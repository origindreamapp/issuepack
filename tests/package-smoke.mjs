import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  access,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repositoryRoot = process.cwd();
const npmCli = process.env.npm_execpath;

assert.ok(npmCli, "npm_execpath is required to run the package smoke test");

const executionOptions = {
  cwd: repositoryRoot,
  encoding: "utf8",
  maxBuffer: 2 * 1024 * 1024,
  windowsHide: true,
};

async function runNpm(args) {
  return execFileAsync(process.execPath, [npmCli, ...args], executionOptions);
}

async function runCli(cliPath, args, expectedCode = 0) {
  try {
    const result = await execFileAsync(
      process.execPath,
      [cliPath, ...args],
      executionOptions,
    );
    assert.equal(expectedCode, 0, `Expected exit code ${expectedCode}`);
    return result;
  } catch (error) {
    assert.equal(error?.code, expectedCode);
    return {
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? ""),
    };
  }
}

function totalFindings(report) {
  return Object.values(report.redactions).reduce(
    (total, count) => total + count,
    0,
  );
}

const temporaryRoot = await mkdtemp(join(tmpdir(), "issuepack-package-smoke-"));

try {
  const packageJson = JSON.parse(
    await readFile(join(repositoryRoot, "package.json"), "utf8"),
  );
  const { stdout: packOutput } = await runNpm([
    "pack",
    "--json",
    "--ignore-scripts",
    "--pack-destination",
    temporaryRoot,
  ]);
  const [packResult] = JSON.parse(packOutput);
  assert.equal(packResult.version, packageJson.version);
  assert.ok(packResult.entryCount > 0);

  const tarballPath = join(temporaryRoot, packResult.filename);
  const installPrefix = join(temporaryRoot, "install");
  await runNpm([
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--prefix",
    installPrefix,
    tarballPath,
  ]);

  const installedPackage = join(
    installPrefix,
    "node_modules",
    packageJson.name,
  );
  const cliPath = join(installedPackage, "dist", "cli.js");
  const binShim = join(
    installPrefix,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "issuepack.cmd" : "issuepack",
  );
  await access(cliPath);
  await access(binShim);

  const { stdout: versionOutput } = await runCli(cliPath, ["--version"]);
  assert.equal(versionOutput.trim(), packageJson.version);

  const inputDirectory = join(temporaryRoot, "input");
  const inputPath = join(inputDirectory, "service.log");
  const outputDirectory = join(temporaryRoot, "bundle");
  const original = [
    "status=failed",
    "owner=consumer@example.com",
    "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    "github=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    "",
  ].join("\n");
  await mkdir(inputDirectory);
  await writeFile(inputPath, original, "utf8");

  const scanResult = await runCli(
    cliPath,
    ["scan", inputDirectory, "--json"],
    2,
  );
  const scanReport = JSON.parse(scanResult.stdout);
  assert.equal(scanReport.filesScanned, 1);
  assert.equal(totalFindings(scanReport), 3);

  await runCli(cliPath, [
    "bundle",
    inputDirectory,
    "--out",
    outputDirectory,
    "--anonymize-paths",
    "--json",
  ]);
  const manifest = JSON.parse(
    await readFile(join(outputDirectory, "manifest.json"), "utf8"),
  );
  assert.equal(manifest.totals.filesWritten, 1);
  assert.equal(totalFindings({ redactions: manifest.totals.redactions }), 3);

  const outputPath = join(
    outputDirectory,
    "files",
    ...manifest.files[0].path.split("/"),
  );
  const sanitized = await readFile(outputPath, "utf8");
  assert.doesNotMatch(sanitized, /consumer@example\.com|sk-proj-|ghp_/);
  assert.equal((sanitized.match(/\[REDACTED:/g) ?? []).length, 3);

  const rescanResult = await runCli(
    cliPath,
    ["scan", outputDirectory, "--json"],
  );
  const rescanReport = JSON.parse(rescanResult.stdout);
  assert.equal(totalFindings(rescanReport), 0);
  assert.equal(await readFile(inputPath, "utf8"), original);

  console.log(
    `Package smoke passed for ${packageJson.name}@${packageJson.version} (${packResult.entryCount} files).`,
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
