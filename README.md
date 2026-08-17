# IssuePack

[![CI](https://github.com/origindreamapp/issuepack/actions/workflows/ci.yml/badge.svg)](https://github.com/origindreamapp/issuepack/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/origindreamapp/issuepack)](https://github.com/origindreamapp/issuepack/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

IssuePack creates privacy-safe diagnostic bundles for GitHub issues, support requests, and coding agents. It runs locally, never modifies source files, and has zero runtime dependencies.

> IssuePack uses best-effort pattern matching. Always review a generated bundle before sharing it.

## Why

Logs and configuration files are useful for reproducing bugs, but they often contain API keys, session headers, email addresses, usernames, local paths, and network identifiers. IssuePack keeps the diagnostic structure while replacing likely sensitive values with stable fingerprints.

Within one bundle, the same value becomes the same salted placeholder:

```text
user@example.com -> [REDACTED:EMAIL:b4c9a28932]
```

This preserves correlation across files without including the original value.

## Install

IssuePack requires Node.js 20 or newer. The npm package has not been published yet. Until it is available, install from source:

```bash
git clone https://github.com/origindreamapp/issuepack.git
cd issuepack
npm ci
npm run build
npm link
```

Then verify the CLI:

```bash
issuepack --version
issuepack --help
```

## Usage

Scan a file or directory without writing anything:

```bash
issuepack scan ./diagnostics
```

`scan` exits with code `0` when no potential sensitive values are found, `2` when findings are present, and `1` for usage or runtime errors.

Create a sanitized bundle directory:

```bash
issuepack bundle ./diagnostics --out ./issuepack-output
```

Known sensitive patterns in file and directory names are redacted by default. For the strongest path privacy, replace every path segment with a salted fingerprint while retaining safe file extensions:

```bash
issuepack bundle ./diagnostics --out ./issuepack-output --anonymize-paths
```

Machine-readable output is available with `--json`:

```bash
issuepack scan ./diagnostics --json
issuepack bundle ./diagnostics --out ./issuepack-output --json
```

`scan --json` contains local relative paths and is intended for local automation. Do not publish scan output without reviewing those paths.

The bundle contains:

```text
issuepack-output/
|-- files/          Sanitized UTF-8 text files
|-- manifest.json   Schema v2 counts, path policy, limits, and skipped entries
`-- REPORT.md       Human-readable review checklist
```

Binary files, symbolic links, files larger than 5 MiB, and common generated directories are skipped. A run processes at most 5,000 files and 100 MiB. Absolute input paths are never written to the manifest.

Bundle output is staged before it is moved into the requested destination. If an interrupted run leaves `.issuepack-incomplete`, delete that output directory and run the command again.

## Detected Data

IssuePack currently detects:

- OpenAI, Anthropic, GitHub, GitLab, AWS, Google, Slack, Hugging Face, npm, and SendGrid credentials
- Authorization, cookie, and generic credential assignments
- Private keys, JWTs, and authenticated URLs
- Email addresses and home-directory usernames
- IPv4 and MAC addresses

Detection is intentionally conservative, but no regex-based tool can guarantee complete redaction. Custom identifiers, secrets split across lines, encoded payloads, images, archives, and proprietary credential formats may not be detected.

## Safety Model

- Source files are read-only.
- Existing output directories are never overwritten.
- Symbolic links are not followed.
- Processing is local; IssuePack performs no network requests.
- Placeholders use a random per-bundle HMAC key, so values remain correlatable inside a bundle without creating a stable identifier across bundles.
- Known sensitive filename patterns are redacted in written, skipped, and manifest paths.
- `--anonymize-paths` hides every input path segment when names themselves are confidential.
- Generated bundles must be reviewed manually before upload or publication.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and handling missed redactions.

The detailed trust boundaries and unsupported data classes are documented in [docs/threat-model.md](docs/threat-model.md). The generated manifest contract is documented in [docs/manifest-v2.md](docs/manifest-v2.md).

## Library API

```js
import { createBundle, scanPath } from "issuepack-cli";

const scan = await scanPath("./diagnostics");
const bundle = await createBundle("./diagnostics", {
  outputDir: "./issuepack-output",
  anonymizePaths: true,
});
```

The JavaScript API follows the same read-only input and no-overwrite guarantees as the CLI.

## Development

```bash
npm install
npm run check
```

The project uses TypeScript and Node's built-in test runner. Runtime code depends only on Node.js standard-library modules.

## Roadmap

- Configurable include and exclude rules
- Framework-specific diagnostic collectors
- Archive output with integrity checks
- A documented redaction-rule plugin interface

## License

[MIT](LICENSE)
