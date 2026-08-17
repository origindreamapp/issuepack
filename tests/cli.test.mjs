import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);

test("prints its version", async () => {
  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    ["dist/cli.js", "--version"],
    { cwd: process.cwd() },
  );

  assert.equal(stdout.trim(), "0.2.0");
  assert.equal(stderr, "");
});

test("prints help with the safety warning", async () => {
  const { stdout } = await execFileAsync(process.execPath, ["dist/cli.js", "--help"], {
    cwd: process.cwd(),
  });

  assert.match(stdout, /without modifying source files/i);
  assert.match(stdout, /issuepack bundle/);
  assert.match(stdout, /--anonymize-paths/);
});

test("runs the bundle command end to end", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-cli-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "diagnostic.log");
  const output = join(root, "bundle");
  await writeFile(input, "token=synthetic-secret-value\n", "utf8");

  const { stdout } = await execFileAsync(
    process.execPath,
    ["dist/cli.js", "bundle", input, "--out", output, "--json"],
    { cwd: process.cwd() },
  );

  const response = JSON.parse(stdout);
  const sanitized = await readFile(join(output, "files", "diagnostic.log"), "utf8");
  assert.equal(response.totals.filesWritten, 1);
  assert.match(sanitized, /\[REDACTED:CREDENTIAL:[a-f0-9]{12}\]/);
  assert.doesNotMatch(sanitized, /synthetic-secret-value/);
});

test("supports full path anonymization from the CLI", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-cli-anonymous-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "customer-project");
  const output = join(root, "bundle");
  await mkdir(input);
  await writeFile(join(input, "customer.log"), "status=ok\n", "utf8");

  const { stdout } = await execFileAsync(
    process.execPath,
    [
      "dist/cli.js",
      "bundle",
      input,
      "--out",
      output,
      "--anonymize-paths",
      "--json",
    ],
    { cwd: process.cwd() },
  );

  const response = JSON.parse(stdout);
  const manifest = JSON.parse(await readFile(join(output, "manifest.json"), "utf8"));
  assert.equal(response.pathPolicy.mode, "anonymize");
  assert.match(manifest.files[0].path, /^file-[a-f0-9]{12}\.log$/);
  assert.doesNotMatch(JSON.stringify(manifest), /customer-project|customer\.log/);
});

test("scan output identifies files without printing matched values", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-cli-scan-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "service.log");
  await writeFile(input, "owner=person@example.com\n", "utf8");

  await assert.rejects(
    execFileAsync(process.execPath, ["dist/cli.js", "scan", input], {
      cwd: process.cwd(),
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stdout, /service\.log/);
      assert.match(error.stdout, /EMAIL: 1/);
      assert.doesNotMatch(error.stdout, /person@example\.com/);
      return true;
    },
  );
});

test("rejects unknown commands before parsing their arguments", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, ["dist/cli.js", "unknown"], {
      cwd: process.cwd(),
    }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /Unknown command: unknown/);
      return true;
    },
  );
});
