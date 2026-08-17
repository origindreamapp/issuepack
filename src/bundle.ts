import { constants } from "node:fs";
import { randomBytes } from "node:crypto";
import {
  access,
  lstat,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import {
  countFindings,
  mergeCounts,
  redactText,
  type RedactionCounts,
} from "./redact.js";
import { NAME, VERSION } from "./version.js";

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const IGNORED_DIRECTORIES = new Set([".git", "node_modules", "dist", "coverage"]);

export interface SkippedEntry {
  path: string;
  reason: string;
}

export interface FileReport {
  path: string;
  bytesIn: number;
  bytesOut: number;
  redactions: RedactionCounts;
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
  schemaVersion: 1;
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
  };
  totals: {
    filesWritten: number;
    bytesIn: number;
    bytesOut: number;
    redactions: RedactionCounts;
  };
  files: FileReport[];
  skipped: SkippedEntry[];
  warning: string;
}

export interface BundleResult {
  outputPath: string;
  manifest: BundleManifest;
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

async function collectInput(inputPath: string): Promise<CollectionResult> {
  const inputStats = await stat(inputPath);
  const paths: CollectedPath[] = [];
  const skipped: SkippedEntry[] = [];

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
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
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

  const buffer = await readFile(entry.absolutePath);
  const text = decodeText(buffer);
  if (text === undefined) {
    return { skipped: { path: entry.relativePath, reason: "binary or non-UTF-8 file" } };
  }

  return { text, bytes: buffer.length };
}

function buildReport(manifest: BundleManifest): string {
  const redactionRows = Object.entries(manifest.totals.redactions)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([kind, count]) => `| ${kind} | ${count} |`);

  const skippedRows = manifest.skipped.length
    ? manifest.skipped.map((entry) => `- \`${entry.path}\`: ${entry.reason}`)
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
  options: { outputDir?: string } = {},
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
  const files: FileReport[] = [];
  const skipped = [...collection.skipped];
  const fingerprintSalt = randomBytes(32).toString("hex");
  let totalRedactions: RedactionCounts = {};
  let totalBytesIn = 0;
  let totalBytesOut = 0;

  await mkdir(join(outputPath, "files"), { recursive: true });

  for (const entry of collection.paths) {
    const readResult = await readTextEntry(entry);
    if ("skipped" in readResult) {
      skipped.push(readResult.skipped);
      continue;
    }

    const result = redactText(readResult.text, { fingerprintSalt });
    const counts = countFindings(result.findings);
    const destination = join(outputPath, "files", entry.relativePath);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, result.text, "utf8");

    const bytesOut = Buffer.byteLength(result.text, "utf8");
    totalBytesIn += readResult.bytes;
    totalBytesOut += bytesOut;
    totalRedactions = mergeCounts(totalRedactions, counts);
    files.push({
      path: entry.relativePath,
      bytesIn: readResult.bytes,
      bytesOut,
      redactions: counts,
    });
  }

  const manifest: BundleManifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    tool: { name: NAME, version: VERSION },
    input: { name: basename(inputPath), type: collection.inputType },
    limits: { maxFileBytes: MAX_FILE_BYTES },
    totals: {
      filesWritten: files.length,
      bytesIn: totalBytesIn,
      bytesOut: totalBytesOut,
      redactions: totalRedactions,
    },
    files,
    skipped,
    warning: "Redaction is best-effort. Review the bundle manually before sharing it.",
  };

  await writeFile(
    join(outputPath, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  await writeFile(join(outputPath, "REPORT.md"), buildReport(manifest), "utf8");

  return { outputPath, manifest };
}
