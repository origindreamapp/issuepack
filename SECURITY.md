# Security Policy

## Reporting a Vulnerability

Do not open a public issue containing a real secret, private log, credential, or unredacted diagnostic bundle.

Until private vulnerability reporting is configured for the GitHub repository, report only a minimal description without sensitive samples. Repository maintainers will provide a private follow-up channel.

## Redaction Limitations

IssuePack is a best-effort review aid, not a data-loss-prevention guarantee. Users must inspect every generated file and filename before sharing it. Default path handling only redacts known patterns; use `--anonymize-paths` when all path names are confidential.

If IssuePack misses a sensitive value, rotate or revoke that value before doing anything else, then report the pattern using synthetic test data. If an interrupted run leaves `.issuepack-incomplete`, treat that directory as unsafe to share, delete it, and retry.

## Supported Versions

Security fixes are applied to the latest released version. Pre-1.0 manifest schemas may change between minor releases and are documented in [CHANGELOG.md](CHANGELOG.md).
