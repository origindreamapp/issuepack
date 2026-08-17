import { constants, type Dirent } from "node:fs";
import { randomBytes } from "node:crypto";
import {
  access,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import {
  countFindings,
  fingerprintValue,
  mergeCounts,
  redactText,
  type RedactionCounts,
} from "./redact.js";
import { NAME, VERSION } from "./version.js";

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_FILE_COUNT = 5_000;
const MAX_TOTAL_BYTES = 100 * 1024 * 1024;
const BUNDLE_MANIFEST_PROBE_BYTES = 64 * 1024;
const IGNORED_DIRECTORIES = new Set([".git", "node_modules", "dist", "coverage"]);
const INCOMPLETE_MARKER = ".issuepack-incomplete";

export interface SkippedEntry {
  path: string;
  reason: string;
}

export interface FileReport {
  path: string;
  bytesIn: number;
  bytesOut: number;
  redactions: RedactionCounts;
  pathRedactions: RedactionCounts;
}

export interface ScanReport {
  inputName: string;
  filesScanned: number;
  bytesScanned: number;
  redactions: RedactionCounts;
  files: Array<Pick<FileReport, "path" | "bytesIn" | "redactions">>;
  skipped: SkippedEntry[];
}

export interface BundleManifest {
  schemaVersion: 2;
  generatedAt: string;
  tool: {
    name: string;
    version: string;
  };
  input: {
    name: string;
    type: "file" | "directory";
  };
  limits: {
    maxFileBytes: number;
    maxFiles: number;
    maxTotalBytes: number;
  };
  pathPolicy: {
    mode: "anonymize" | "redact-known";
    warning: string;
  };
  totals: {
    filesWritten: number;
    bytesIn: number;
    bytesOut: number;
    redactions: RedactionCounts;
    pathRedactions: RedactionCounts;
  };
  files: FileReport[];
  skipped: SkippedEntry[];
  warning: string;
}

export interface BundleResult {
  outputPath: string;
  manifest: BundleManifest;
}

export interface BundleOptions {
  outputDir?: string;
  anonymizePaths?: boolean;
}

interface CollectedPath {
  absolutePath: string;
  relativePath: string;
}

interface CollectionResult {
  paths: CollectedPath[];
  skipped: SkippedEntry[];
  inputType: "file" | "directory";
}

function portablePath(value: string): string {
  return value.split(sep).join("/");
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function isGeneratedIssuePackBundle(
  directory: string,
  entries: Dirent[],
): Promise<boolean> {
  const hasManifest = entries.some(
    (entry) => entry.name === "manifest.json" && entry.isFile(),
  );
  const hasReport = entries.some(
    (entry) => entry.name === "REPORT.md" && entry.isFile(),
  );
  const hasFilesDirectory = entries.some(
    (entry) => entry.name === "files" && entry.isDirectory(),
  );
  if (!hasManifest || !hasReport || !hasFilesDirectory) {
    return false;
  }

  const noFollowFlag = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
  let handle;
  try {
    handle = await open(
      join(directory, "manifest.json"),
      constants.O_RDONLY | noFollowFlag,
    );
    const stats = await handle.stat();
    if (!stats.isFile()) {
      return false;
    }

    const buffer = Buffer.alloc(
      Math.min(stats.size, BUNDLE_MANIFEST_PROBE_BYTES),
    );
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const manifestPrefix = decodeText(buffer.subarray(0, bytesRead));
    return (
      manifestPrefix !== undefined &&
      /"schemaVersion"\s*:\s*2\b/.test(manifestPrefix) &&
      /"tool"\s*:\s*\{\s*"name"\s*:\s*"IssuePack"/s.test(manifestPrefix)
    );
  } catch {
    return false;
  } finally {
    await handle?.close();
  }
}

async function collectInput(inputPath: string): Promise<CollectionResult> {
  const inputStats = await lstat(inputPath);
  const paths: CollectedPath[] = [];
  const skipped: SkippedEntry[] = [];
  let collectionTruncated = false;

  if (inputStats.isSymbolicLink()) {
    throw new Error("Input cannot be a symbolic link.");
  }

  if (inputStats.isFile()) {
    paths.push({
      absolutePath: inputPath,
      relativePath: basename(inputPath),
    });
    return { paths, skipped, inputType: "file" };
  }

  if (!inputStats.isDirectory()) {
    throw new Error("Input must be a regular file or directory.");
  }

  async function walk(directory: string): Promise<void> {
    if (collectionTruncated) {
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    if (
      directory !== inputPath &&
      (await isGeneratedIssuePackBundle(directory, entries))
    ) {
      skipped.push({
        path: `${portablePath(relative(inputPath, directory))}/`,
        reason: "generated IssuePack bundle",
      });
      return;
    }

    for (const entry of entries) {
      if (paths.length >= MAX_FILE_COUNT) {
        skipped.push({
          path: portablePath(relative(inputPath, directory)),
          reason: `file limit of ${MAX_FILE_COUNT} reached; remaining entries omitted`,
        });
        collectionTruncated = true;
        return;
      }
      const absolutePath = join(directory, entry.name);
      const relativePath = portablePath(relative(inputPath, absolutePath));

      if (entry.isSymbolicLink()) {
        skipped.push({ path: relativePath, reason: "symbolic link" });
        continue;
      }

      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith("issuepack-")) {
          skipped.push({ path: `${relativePath}/`, reason: "ignored directory" });
          continue;
        }
        await walk(absolutePath);
        if (collectionTruncated) {
          return;
        }
        continue;
      }

      if (entry.isFile()) {
        paths.push({ absolutePath, relativePath });
      }
    }
  }

  await walk(inputPath);
  return { paths, skipped, inputType: "directory" };
}

function portableSegment(value: string): string {
  const sanitized = value
    .replace(/[<>:"`\\|?*\u0000-\u001f]/g, "_")
    .replace(/[. ]+$/g, "_");
  return sanitized || "unnamed";
}

function protectedPlaceholder(value: string): string {
  return value.replace(
    /\[REDACTED:([A-Z_]+):([a-f0-9]{12})\]/g,
    (_match, kind: string, digest: string) =>
      `redacted-${kind.toLowerCase().replaceAll("_", "-")}-${digest}`,
  );
}

function safeExtension(segment: string): string {
  const extension = extname(segment);
  return /^\.[A-Za-z0-9]{1,12}$/.test(extension) ? extension : "";
}

function protectRelativePath(
  value: string,
  salt: string,
  anonymizePaths: boolean,
  finalSegmentIsFile: boolean,
): { path: string; redactions: RedactionCounts } {
  const trailingSlash = value.endsWith("/");
  const rawSegments = value.replace(/\/$/, "").split("/").filter(Boolean);
  let redactions: RedactionCounts = {};
  const protectedSegments = rawSegments.map((segment, index) => {
    const isLast = index === rawSegments.length - 1;
    if (anonymizePaths) {
      const isFile = isLast && finalSegmentIsFile;
      const extension = isFile ? safeExtension(segment) : "";
      const prefix = isFile ? "file" : "dir";
      return `${prefix}-${fingerprintValue(segment, salt)}${extension}`;
    }

    const isFile = isLast && finalSegmentIsFile;
    const extension = isFile ? safeExtension(segment) : "";
    const redactionTarget = extension
      ? segment.slice(0, -extension.length)
      : segment;
    const result = redactText(redactionTarget, { fingerprintSalt: salt });
    redactions = mergeCounts(redactions, countFindings(result.findings));
    return `${portableSegment(protectedPlaceholder(result.text))}${extension}`;
  });

  const protectedPath = protectedSegments.join("/") || "input";
  return {
    path: trailingSlash ? `${protectedPath}/` : protectedPath,
    redactions,
  };
}

function uniqueProtectedPath(
  protectedPath: string,
  sourcePath: string,
  salt: string,
  seen: Set<string>,
): string {
  const collisionKey = protectedPath.toLowerCase();
  if (!seen.has(collisionKey)) {
    seen.add(collisionKey);
    return protectedPath;
  }

  const extension = safeExtension(protectedPath);
  const stem = extension ? protectedPath.slice(0, -extension.length) : protectedPath;
  const candidate = `${stem}-${fingerprintValue(sourcePath, salt)}${extension}`;
  seen.add(candidate.toLowerCase());
  return candidate;
}

function decodeText(buffer: Buffer): string | undefined {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  if (sample.includes(0)) {
    return undefined;
  }

  let controlBytes = 0;
  for (const byte of sample) {
    if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
      controlBytes += 1;
    }
  }
  if (sample.length > 0 && controlBytes / sample.length > 0.01) {
    return undefined;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    return undefined;
  }
}

async function readTextEntry(
  entry: CollectedPath,
): Promise<{ text: string; bytes: number } | { skipped: SkippedEntry }> {
  const fileStats = await lstat(entry.absolutePath);
  if (!fileStats.isFile()) {
    return { skipped: { path: entry.relativePath, reason: "not a regular file" } };
  }
  if (fileStats.size > MAX_FILE_BYTES) {
    return {
      skipped: {
        path: entry.relativePath,
        reason: `larger than ${MAX_FILE_BYTES} bytes`,
      },
    };
  }

  const noFollowFlag = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
  let handle;
  try {
    handle = await open(entry.absolutePath, constants.O_RDONLY | noFollowFlag);
    const openedStats = await handle.stat();
    if (!openedStats.isFile()) {
      return { skipped: { path: entry.relativePath, reason: "not a regular file" } };
    }
    if (openedStats.size !== fileStats.size || openedStats.size > MAX_FILE_BYTES) {
      return { skipped: { path: entry.relativePath, reason: "file changed while reading" } };
    }

    const buffer = await handle.readFile();
    if (buffer.length !== openedStats.size) {
      return { skipped: { path: entry.relativePath, reason: "file changed while reading" } };
    }
    const text = decodeText(buffer);
    if (text === undefined) {
      return {
        skipped: { path: entry.relativePath, reason: "binary or non-UTF-8 file" },
      };
    }

    return { text, bytes: buffer.length };
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ELOOP" || error.code === "EMLINK")
    ) {
      return { skipped: { path: entry.relativePath, reason: "symbolic link" } };
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

function buildReport(manifest: BundleManifest): string {
  const redactionRows = Object.entries(
    mergeCounts(manifest.totals.redactions, manifest.totals.pathRedactions),
  )
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([kind, count]) => `| ${kind} | ${count} |`);

  const skippedRows = manifest.skipped.length
    ? manifest.skipped.map(
        (entry) => `- \`${entry.path.replaceAll("`", "'")}\`: ${entry.reason}`,
      )
    : ["- None"];

  return [
    "# IssuePack Diagnostic Bundle",
    "",
    `Generated by ${manifest.tool.name} v${manifest.tool.version} at ${manifest.generatedAt}.`,
    "",
    "> Redaction is best-effort. Review this bundle manually before sharing it.",
    "",
    "## Summary",
    "",
    `- Input: \`${manifest.input.name}\` (${manifest.input.type})`,
    `- Files written: ${manifest.totals.filesWritten}`,
    `- Files skipped: ${manifest.skipped.length}`,
    `- Bytes processed: ${manifest.totals.bytesIn}`,
    `- Path mode: ${manifest.pathPolicy.mode}`,
    `- Path redactions: ${Object.values(manifest.totals.pathRedactions).reduce((sum, count) => sum + (count ?? 0), 0)}`,
    "",
    "## Redactions",
    "",
    "| Kind | Count |",
    "| --- | ---: |",
    ...(redactionRows.length ? redactionRows : ["| None | 0 |"]),
    "",
    "## Skipped Entries",
    "",
    ...skippedRows,
    "",
    "## Before Sharing",
    "",
    manifest.pathPolicy.warning,
    "",
    "Open the files in this bundle and verify that no confidential or personal data remains.",
    "",
  ].join("\n");
}

export async function scanPath(input: string): Promise<ScanReport> {
  const inputPath = resolve(input);
  if (!(await pathExists(inputPath))) {
    throw new Error(`Input does not exist: ${input}`);
  }

  const collection = await collectInput(inputPath);
  const skipped = [...collection.skipped];
  const files: ScanReport["files"] = [];
  let bytesScanned = 0;
  let totalRedactions: RedactionCounts = {};

  for (const entry of collection.paths) {
    const readResult = await readTextEntry(entry);
    if ("skipped" in readResult) {
      skipped.push(readResult.skipped);
      continue;
    }
    if (bytesScanned + readResult.bytes > MAX_TOTAL_BYTES) {
      skipped.push({
        path: entry.relativePath,
        reason: `total byte limit of ${MAX_TOTAL_BYTES} reached`,
      });
      continue;
    }

    const result = redactText(readResult.text);
    const counts = countFindings(result.findings);
    bytesScanned += readResult.bytes;
    totalRedactions = mergeCounts(totalRedactions, counts);
    files.push({ path: entry.relativePath, bytesIn: readResult.bytes, redactions: counts });
  }

  return {
    inputName: basename(inputPath),
    filesScanned: files.length,
    bytesScanned,
    redactions: totalRedactions,
    files,
    skipped,
  };
}

export async function createBundle(
  input: string,
  options: BundleOptions = {},
): Promise<BundleResult> {
  const inputPath = resolve(input);
  if (!(await pathExists(inputPath))) {
    throw new Error(`Input does not exist: ${input}`);
  }

  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const outputPath = resolve(options.outputDir ?? `issuepack-${stamp}`);
  if (await pathExists(outputPath)) {
    throw new Error(`Output already exists: ${outputPath}`);
  }
  if (outputPath === inputPath) {
    throw new Error("Output directory cannot be the input path.");
  }

  const collection = await collectInput(inputPath);
  const anonymizePaths = options.anonymizePaths ?? false;
  const files: FileReport[] = [];
  const skipped: SkippedEntry[] = [];
  const fingerprintSalt = randomBytes(32).toString("hex");
  const seenProtectedPaths = new Set<string>();
  let totalRedactions: RedactionCounts = {};
  let totalPathRedactions: RedactionCounts = {};
  let totalBytesIn = 0;
  let totalBytesOut = 0;
  const inputName = protectRelativePath(
    basename(inputPath),
    fingerprintSalt,
    anonymizePaths,
    collection.inputType === "file",
  );
  totalPathRedactions = mergeCounts(totalPathRedactions, inputName.redactions);

  const addSkipped = (entry: SkippedEntry): void => {
    const protectedEntry = protectRelativePath(
      entry.path,
      fingerprintSalt,
      anonymizePaths,
      !entry.path.endsWith("/"),
    );
    totalPathRedactions = mergeCounts(
      totalPathRedactions,
      protectedEntry.redactions,
    );
    skipped.push({ path: protectedEntry.path, reason: entry.reason });
  };

  for (const entry of collection.skipped) {
    addSkipped(entry);
  }

  const outputParent = dirname(outputPath);
  const tempPath = join(
    outputParent,
    `issuepack-tmp-${basename(outputPath)}-${randomBytes(6).toString("hex")}`,
  );
  let outputReserved = false;

  await mkdir(outputParent, { recursive: true });
  await mkdir(tempPath);

  try {
    await mkdir(join(tempPath, "files"));

    for (const entry of collection.paths) {
      const readResult = await readTextEntry(entry);
      if ("skipped" in readResult) {
        addSkipped(readResult.skipped);
        continue;
      }
      if (totalBytesIn + readResult.bytes > MAX_TOTAL_BYTES) {
        addSkipped({
          path: entry.relativePath,
          reason: `total byte limit of ${MAX_TOTAL_BYTES} reached`,
        });
        continue;
      }

      const result = redactText(readResult.text, { fingerprintSalt });
      const counts = countFindings(result.findings);
      const protectedEntry = protectRelativePath(
        entry.relativePath,
        fingerprintSalt,
        anonymizePaths,
        true,
      );
      const protectedPath = uniqueProtectedPath(
        protectedEntry.path,
        entry.relativePath,
        fingerprintSalt,
        seenProtectedPaths,
      );
      const destination = join(tempPath, "files", protectedPath);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, result.text, "utf8");

      const bytesOut = Buffer.byteLength(result.text, "utf8");
      totalBytesIn += readResult.bytes;
      totalBytesOut += bytesOut;
      totalRedactions = mergeCounts(totalRedactions, counts);
      totalPathRedactions = mergeCounts(
        totalPathRedactions,
        protectedEntry.redactions,
      );
      files.push({
        path: portablePath(protectedPath),
        bytesIn: readResult.bytes,
        bytesOut,
        redactions: counts,
        pathRedactions: protectedEntry.redactions,
      });
    }

    const manifest: BundleManifest = {
      schemaVersion: 2,
      generatedAt: new Date().toISOString(),
      tool: { name: NAME, version: VERSION },
      input: { name: inputName.path, type: collection.inputType },
      limits: {
        maxFileBytes: MAX_FILE_BYTES,
        maxFiles: MAX_FILE_COUNT,
        maxTotalBytes: MAX_TOTAL_BYTES,
      },
      pathPolicy: {
        mode: anonymizePaths ? "anonymize" : "redact-known",
        warning: anonymizePaths
          ? "All input path segments were replaced with salted fingerprints."
          : "Known sensitive patterns in path names were redacted, but custom names may remain sensitive. Review filenames before sharing.",
      },
      totals: {
        filesWritten: files.length,
        bytesIn: totalBytesIn,
        bytesOut: totalBytesOut,
        redactions: totalRedactions,
        pathRedactions: totalPathRedactions,
      },
      files,
      skipped,
      warning: "Redaction is best-effort. Review the bundle manually before sharing it.",
    };

    await writeFile(
      join(tempPath, "manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    );
    await writeFile(join(tempPath, "REPORT.md"), buildReport(manifest), "utf8");

    await mkdir(outputPath);
    outputReserved = true;
    await writeFile(
      join(outputPath, INCOMPLETE_MARKER),
      "IssuePack did not finish creating this bundle. Delete it and retry.\n",
      "utf8",
    );
    await rename(join(tempPath, "files"), join(outputPath, "files"));
    await rename(join(tempPath, "manifest.json"), join(outputPath, "manifest.json"));
    await rename(join(tempPath, "REPORT.md"), join(outputPath, "REPORT.md"));
    await rm(tempPath, { recursive: true, force: true });
    await rm(join(outputPath, INCOMPLETE_MARKER), { force: true });

    return { outputPath, manifest };
  } catch (error) {
    await rm(tempPath, { recursive: true, force: true });
    if (outputReserved) {
      await rm(outputPath, { recursive: true, force: true });
    }
    throw error;
  }
}
