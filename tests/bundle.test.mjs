import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createBundle, scanPath } from "../dist/index.js";

test("creates a sanitized bundle without modifying its input", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));

  const input = join(root, "diagnostics");
  const output = join(root, "bundle");
  await mkdir(join(input, "logs"), { recursive: true });
  await mkdir(join(input, "node_modules", "ignored"), { recursive: true });

  const sensitive = "user=dev@example.com\ntoken=top-secret-token\nip=10.0.0.8\n";
  await writeFile(join(input, "logs", "app.log"), sensitive, "utf8");
  await writeFile(
    join(input, "notes.txt"),
    "42 tests passed\nowner=dev@example.com\n",
    "utf8",
  );
  await writeFile(join(input, "binary.bin"), Buffer.from([0, 1, 2, 3]));
  await writeFile(join(input, "node_modules", "ignored", "secret.txt"), "token=hidden");

  const before = await readFile(join(input, "logs", "app.log"));
  const result = await createBundle(input, { outputDir: output });
  const after = await readFile(join(input, "logs", "app.log"));
  const sanitized = await readFile(join(output, "files", "logs", "app.log"), "utf8");
  const sanitizedNotes = await readFile(join(output, "files", "notes.txt"), "utf8");
  const manifestText = await readFile(join(output, "manifest.json"), "utf8");

  assert.deepEqual(after, before);
  assert.doesNotMatch(sanitized, /dev@example\.com|top-secret-token|10\.0\.0\.8/);
  assert.equal(result.manifest.totals.filesWritten, 2);
  assert.equal(result.manifest.totals.redactions.EMAIL, 2);
  assert.equal(result.manifest.totals.redactions.CREDENTIAL, 1);
  assert.equal(result.manifest.totals.redactions.IP_ADDRESS, 1);
  assert.ok(result.manifest.skipped.some((entry) => entry.path === "binary.bin"));
  assert.ok(result.manifest.skipped.some((entry) => entry.path === "node_modules/"));
  assert.doesNotMatch(manifestText, new RegExp(root.replaceAll("\\", "\\\\")));
  assert.equal(
    sanitized.match(/\[REDACTED:EMAIL:[a-f0-9]{10}\]/)?.[0],
    sanitizedNotes.match(/\[REDACTED:EMAIL:[a-f0-9]{10}\]/)?.[0],
  );
});

test("scan reports findings and writes no files", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-scan-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "sample.log");
  await writeFile(input, "contact=person@example.com\n", "utf8");

  const report = await scanPath(input);

  assert.equal(report.filesScanned, 1);
  assert.equal(report.redactions.EMAIL, 1);
  assert.deepEqual(await readFile(input, "utf8"), "contact=person@example.com\n");
});

test("refuses to overwrite an existing output directory", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-existing-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "sample.log");
  const output = join(root, "existing");
  await writeFile(input, "clean\n", "utf8");
  await mkdir(output);

  await assert.rejects(
    createBundle(input, { outputDir: output }),
    /Output already exists/,
  );
});
