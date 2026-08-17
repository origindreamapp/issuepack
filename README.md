# IssuePack

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

IssuePack requires Node.js 20 or newer. The npm package has not been released yet; the command below will apply after the first release.

```bash
npm install --global issuepack-cli
```

During local development:

```bash
npm install
npm run build
node dist/cli.js --help
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

Machine-readable output is available with `--json`:

```bash
issuepack scan ./diagnostics --json
issuepack bundle ./diagnostics --out ./issuepack-output --json
```

The bundle contains:

```text
issuepack-output/
|-- files/          Sanitized UTF-8 text files
|-- manifest.json   Counts, file list, limits, and skipped entries
`-- REPORT.md       Human-readable review checklist
```

Binary files, symbolic links, files larger than 5 MiB, and common generated directories are skipped. Absolute input paths are not written to the manifest.

## Detected Data

IssuePack currently detects common API credentials, authorization and cookie headers, private keys, JWTs, credential assignments, authenticated URLs, email addresses, home-directory usernames, IPv4 addresses, and MAC addresses.

Detection is intentionally conservative, but no regex-based tool can guarantee complete redaction. Custom identifiers, secrets split across lines, encoded payloads, images, archives, and proprietary credential formats may not be detected.

## Safety Model

- Source files are read-only.
- Existing output directories are never overwritten.
- Symbolic links are not followed.
- Processing is local; IssuePack performs no network requests.
- Placeholders use a random per-bundle salt, so values remain correlatable inside a bundle without creating a stable identifier across bundles.
- Generated bundles must be reviewed manually before upload or publication.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and handling missed redactions.

## Development

```bash
npm install
npm run check
```

The project uses TypeScript and Node's built-in test runner. Runtime code depends only on Node.js standard-library modules.

## Roadmap

- Configurable collectors for common runtimes
- Archive output after the directory format stabilizes
- Optional screenshot metadata and OCR-assisted review
- Optional maintainer-side issue summaries from already-sanitized bundles

## License

[MIT](LICENSE)
