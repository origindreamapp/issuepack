import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

  assert.equal(stdout.trim(), "0.1.0");
  assert.equal(stderr, "");
});

test("prints help with the safety warning", async () => {
  const { stdout } = await execFileAsync(process.execPath, ["dist/cli.js", "--help"], {
    cwd: process.cwd(),
  });

  assert.match(stdout, /without modifying source files/i);
  assert.match(stdout, /issuepack bundle/);
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
  assert.match(sanitized, /\[REDACTED:CREDENTIAL:[a-f0-9]{10}\]/);
  assert.doesNotMatch(sanitized, /synthetic-secret-value/);
});
