#!/usr/bin/env node

import { createBundle, scanPath } from "./bundle.js";
import { NAME, VERSION } from "./version.js";

const usage = `
${NAME} v${VERSION}

Create privacy-safe diagnostic bundles without modifying source files.

Usage:
  issuepack scan <path> [--json]
  issuepack bundle <path> [--out <directory>] [--anonymize-paths] [--json]
  issuepack --help
  issuepack --version

Commands:
  scan     Report potential sensitive values. Writes nothing.
  bundle   Write sanitized UTF-8 text files, REPORT.md, and manifest.json.

Exit codes:
  0  Success; scan found no sensitive values
  1  Usage or runtime error
  2  Scan found potential sensitive values
`.trim();

interface ParsedOptions {
  input?: string;
  outputDir?: string;
  anonymizePaths: boolean;
  json: boolean;
}

function parseOptions(args: string[]): ParsedOptions {
  const options: ParsedOptions = { anonymizePaths: false, json: false };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      throw new Error("Missing command-line argument.");
    }
    if (argument === "--json") {
      options.json = true;
      continue;
    }
    if (argument === "--anonymize-paths") {
      options.anonymizePaths = true;
      continue;
    }
    if (argument === "--out" || argument === "-o") {
      const value = args[index + 1];
      if (!value) {
        throw new Error(`${argument} requires a directory.`);
      }
      options.outputDir = value;
      index += 1;
      continue;
    }
    if (argument?.startsWith("-")) {
      throw new Error(`Unknown option: ${argument}`);
    }
    if (options.input) {
      throw new Error("Only one input path is supported in v0.1.");
    }
    options.input = argument;
  }

  return options;
}

function countTotal(redactions: Record<string, number | undefined>): number {
  let total = 0;
  for (const count of Object.values(redactions)) {
    total += count ?? 0;
  }
  return total;
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);

  if (!command || command === "--help" || command === "-h" || command === "help") {
    console.log(usage);
    return;
  }
  if (command === "--version" || command === "-v") {
    console.log(VERSION);
    return;
  }
  if (command !== "scan" && command !== "bundle") {
    throw new Error(`Unknown command: ${command}`);
  }

  const options = parseOptions(args);
  if (!options.input) {
    throw new Error(`${command} requires an input path.`);
  }

  if (command === "scan") {
    if (options.outputDir) {
      throw new Error("--out is only valid with the bundle command.");
    }
    if (options.anonymizePaths) {
      throw new Error("--anonymize-paths is only valid with the bundle command.");
    }
    const report = await scanPath(options.input);
    const total = countTotal(report.redactions);

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`Scanned ${report.filesScanned} file(s), ${report.bytesScanned} byte(s).`);
      console.log(`Potential sensitive values: ${total}.`);
      for (const [kind, count] of Object.entries(report.redactions).sort()) {
        console.log(`  ${kind}: ${count}`);
      }
      for (const file of report.files.filter(
        (entry) => countTotal(entry.redactions) > 0,
      )) {
        console.log(`  ${file.path}`);
        for (const [kind, count] of Object.entries(file.redactions).sort()) {
          console.log(`    ${kind}: ${count}`);
        }
      }
      if (report.skipped.length) {
        console.log(`Skipped entries: ${report.skipped.length}.`);
      }
    }

    if (total > 0) {
      process.exitCode = 2;
    }
    return;
  }

  if (command === "bundle") {
    const result = await createBundle(options.input, {
      ...(options.outputDir ? { outputDir: options.outputDir } : {}),
      anonymizePaths: options.anonymizePaths,
    });
    if (options.json) {
      console.log(
        JSON.stringify(
          {
            outputPath: result.outputPath,
            pathPolicy: result.manifest.pathPolicy,
            totals: result.manifest.totals,
          },
          null,
          2,
        ),
      );
    } else {
      console.log(`Bundle created: ${result.outputPath}`);
      console.log(`Files written: ${result.manifest.totals.filesWritten}`);
      console.log(
        `Content redactions: ${countTotal(result.manifest.totals.redactions)}`,
      );
      console.log(
        `Path redactions: ${countTotal(result.manifest.totals.pathRedactions)}`,
      );
      console.log(`Path mode: ${result.manifest.pathPolicy.mode}`);
      console.log("Review REPORT.md and every output file before sharing.");
    }
    return;
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`issuepack: ${message}`);
  process.exitCode = 1;
});
