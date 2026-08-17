# Security Policy

## Reporting a Vulnerability

Do not open a public issue containing a real secret, private log, credential, or unredacted diagnostic bundle.

Until private vulnerability reporting is configured for the GitHub repository, report only a minimal description without sensitive samples. Repository maintainers will provide a private follow-up channel.

## Redaction Limitations

IssuePack is a best-effort review aid, not a data-loss-prevention guarantee. Users must inspect every generated file before sharing it. If IssuePack misses a sensitive value, rotate or revoke that value before doing anything else, then report the pattern using synthetic test data.

## Supported Versions

Security fixes are applied to the latest released version.
