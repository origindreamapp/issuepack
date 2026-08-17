# Contributing

Thanks for helping make diagnostic sharing safer.

## Development

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Run `npm run check` before opening a pull request.

Keep changes focused. New redaction rules must include tests for detection, false positives, stable placeholders, and idempotence. Test values must be synthetic and must never contain real credentials or personal data.

Changes to bundle paths or `manifest.json` must include Windows-safe path tests and an entry in [CHANGELOG.md](CHANGELOG.md). The runtime must remain dependency-free.

## Issues

For missed redactions, do not post the original sensitive value. Use a synthetic value with the same shape or follow the private reporting process in [SECURITY.md](SECURITY.md).
