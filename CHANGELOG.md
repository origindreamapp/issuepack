# Changelog

All notable changes to IssuePack will be documented here.

## [Unreleased]

## [0.2.0] - 2026-08-17

### Added

- Optional full path anonymization with `--anonymize-paths`.
- Detection for Anthropic, GitLab, Hugging Face, npm, and SendGrid tokens.
- Per-file findings in human-readable scan output.
- File-count and total-byte processing limits.

### Changed

- Bundle creation now stages output and cleans up handled failures.
- Known sensitive patterns in input names, file paths, and skipped paths are redacted.
- Bundle manifests use schema version 2 and report path handling separately.
- Redaction fingerprints use 12-character salted HMAC digests.
- Nested generated IssuePack bundles are skipped so prior output does not pollute later scans or bundles.

## [0.1.0] - 2026-08-17

### Added

- Local scan and bundle commands.
- Stable redaction fingerprints for common credentials and personal identifiers.
- Read-only input handling, symbolic-link protection, file-size limits, and overwrite prevention.
- JSON manifest and Markdown review report.
