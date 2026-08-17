# Manifest Schema v2

Every bundle includes `manifest.json`. Schema version 2 separates content redactions from path redactions and records how paths were handled.

## Top-Level Fields

- `schemaVersion`: Always `2` for this contract.
- `generatedAt`: UTC creation timestamp.
- `tool`: IssuePack name and version.
- `input`: Pattern-redacted or anonymized input name plus input type.
- `limits`: Per-file, file-count, and total-byte limits used for the run.
- `pathPolicy`: `redact-known` or `anonymize`, with a review warning.
- `totals`: File and byte counts plus content and path redaction counts.
- `files`: Sanitized relative output paths, byte counts, and per-file redactions.
- `skipped`: Sanitized paths and reasons for entries that were not processed.
- `warning`: The mandatory manual-review notice.

## Privacy Properties

The manifest never includes an absolute input path. Written, skipped, and input-name paths use the same per-bundle path policy. HMAC salts are not written to the manifest, so placeholders cannot be correlated across bundles.

Custom path names can remain visible in `redact-known` mode. Use `anonymize` mode when every source path should be hidden.

## Compatibility

Consumers must reject unknown major schema versions rather than guessing. IssuePack is pre-1.0, so manifest changes are recorded in `CHANGELOG.md` and may accompany a minor package release.
