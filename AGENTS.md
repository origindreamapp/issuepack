# Repository Instructions

## Scope

IssuePack creates sanitized copies of diagnostic text. Keep the runtime dependency-free and preserve support for Node.js 20 or newer.

## Safety Invariants

- Never modify, delete, or overwrite an input file.
- Never follow symbolic links while collecting a bundle.
- Never include absolute source paths in generated reports or manifests.
- Never use real credentials, private logs, or personal data in tests or documentation.
- Treat redaction as best-effort and keep the manual-review warning visible.
- Keep fingerprints salted per bundle so low-entropy values are not stable across runs.

## Verification

Run `npm run check` before submitting changes. Every new redaction rule needs tests for detection, a representative non-match, stable replacement inside one bundle, and idempotence where applicable.
