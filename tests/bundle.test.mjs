import assert from "node:assert/strict";
import {
  access,
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
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
    sanitized.match(/\[REDACTED:EMAIL:[a-f0-9]{12}\]/)?.[0],
    sanitizedNotes.match(/\[REDACTED:EMAIL:[a-f0-9]{12}\]/)?.[0],
  );
  await assert.rejects(readFile(join(output, ".issuepack-incomplete")), /ENOENT/);
});

test("redacts known sensitive values in written and skipped paths", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-paths-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "diagnostics");
  const output = join(root, "bundle");
  await mkdir(input);
  await writeFile(join(input, "owner@example.com.log"), "clean\n", "utf8");
  await writeFile(join(input, "report`name.log"), "clean\n", "utf8");
  await writeFile(join(input, "skipped@example.com.bin"), Buffer.from([0, 1, 2]));

  const result = await createBundle(input, { outputDir: output });
  const manifest = await readFile(join(output, "manifest.json"), "utf8");

  assert.equal(result.manifest.pathPolicy.mode, "redact-known");
  assert.equal(result.manifest.totals.pathRedactions.EMAIL, 2);
  assert.match(result.manifest.files[0].path, /^redacted-email-[a-f0-9]{12}\.log$/);
  assert.ok(result.manifest.files.some((entry) => entry.path === "report_name.log"));
  assert.doesNotMatch(manifest, /owner@example\.com|skipped@example\.com/);
  assert.doesNotMatch(manifest, /report`name/);
});

test("can anonymize every input path segment", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-anonymous-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "customer-acme");
  const output = join(root, "bundle");
  await mkdir(join(input, "production"), { recursive: true });
  await writeFile(join(input, "production", "server.log"), "status=ok\n", "utf8");

  const result = await createBundle(input, {
    outputDir: output,
    anonymizePaths: true,
  });
  const manifest = await readFile(join(output, "manifest.json"), "utf8");

  assert.equal(result.manifest.pathPolicy.mode, "anonymize");
  assert.match(result.manifest.input.name, /^dir-[a-f0-9]{12}$/);
  assert.match(
    result.manifest.files[0].path,
    /^dir-[a-f0-9]{12}\/file-[a-f0-9]{12}\.log$/,
  );
  assert.doesNotMatch(manifest, /customer-acme|production|server\.log/);
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

test("skips generated IssuePack bundles nested under the input", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-nested-bundle-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, "diagnostics");
  const nestedBundle = join(input, ".shared-bundle");
  const secondBundle = join(root, "second-bundle");
  const lookalike = join(input, "lookalike");
  await mkdir(input);
  await writeFile(join(input, "app.log"), "status=ok\n", "utf8");
  await createBundle(input, { outputDir: nestedBundle });

  await mkdir(join(lookalike, "files"), { recursive: true });
  await writeFile(
    join(lookalike, "manifest.json"),
    '{"schemaVersion":2,"tool":{"name":"Other"}}\n',
    "utf8",
  );
  await writeFile(join(lookalike, "REPORT.md"), "not IssuePack\n", "utf8");
  await writeFile(join(lookalike, "files", "payload.log"), "clean\n", "utf8");

  const report = await scanPath(input);
  const second = await createBundle(input, { outputDir: secondBundle });
  const direct = await scanPath(nestedBundle);

  assert.equal(report.filesScanned, 4);
  assert.equal(second.manifest.totals.filesWritten, 4);
  assert.equal(direct.filesScanned, 3);
  assert.ok(
    report.skipped.some(
      (entry) =>
        entry.path === ".shared-bundle/" &&
        entry.reason === "generated IssuePack bundle",
    ),
  );
  assert.ok(report.files.some((entry) => entry.path === "lookalike/REPORT.md"));
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

test("refuses a symbolic link as the direct input", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "issuepack-symlink-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const target = join(root, "target.log");
  const link = join(root, "linked.log");
  await writeFile(target, "token=synthetic-value\n", "utf8");

  try {
    await symlink(target, link, "file");
  } catch (error) {
    if (error && ["EPERM", "EACCES"].includes(error.code)) {
      context.skip("Symbolic links are not permitted in this environment.");
      return;
    }
    throw error;
  }

  await assert.rejects(scanPath(link), /Input cannot be a symbolic link/);
});

test("cleans staged output after a handled read failure", async (context) => {
  if (process.platform === "win32") {
    context.skip("Windows does not enforce POSIX read mode bits.");
    return;
  }

  const root = await mkdtemp(join(tmpdir(), "issuepack-cleanup-"));
  const input = join(root, "input");
  const output = join(root, "bundle");
  const unreadable = join(input, "unreadable.log");
  await mkdir(input);
  await writeFile(unreadable, "token=synthetic-value\n", "utf8");
  await chmod(unreadable, 0o000);
  context.after(async () => {
    await chmod(unreadable, 0o600).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  });

  await assert.rejects(createBundle(input, { outputDir: output }), /EACCES/);
  await assert.rejects(access(output), /ENOENT/);
  assert.deepEqual(
    (await readdir(root)).filter((entry) => entry.startsWith("issuepack-tmp-")),
    [],
  );
});
