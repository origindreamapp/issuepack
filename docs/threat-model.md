# Threat Model

IssuePack reduces accidental disclosure when a developer needs to share diagnostic text. It is a review aid, not a data-loss-prevention system.

## Trust Boundaries

- Input files are untrusted and are opened read-only.
- Symbolic links are skipped rather than followed.
- Processing happens in the local Node.js process without network requests.
- Existing output paths are never reused or overwritten.
- A generated bundle is still untrusted until a person reviews every output file and filename.

## Protected Data

IssuePack uses explicit patterns for common credentials, session headers, private keys, authenticated URLs, email addresses, user names in home-directory paths, and network identifiers. Repeated values receive the same salted HMAC placeholder inside one bundle and a different placeholder in another bundle.

Known sensitive patterns in path names are redacted. `--anonymize-paths` replaces every path segment with a salted fingerprint when names themselves are confidential.

## Out of Scope

IssuePack does not inspect binary files, images, archives, encrypted data, proprietary encodings, or non-UTF-8 text. It may miss custom identifiers, secrets split across lines, encoded payloads, novel credential formats, and sensitive business context that does not match a known pattern.

IssuePack does not revoke exposed credentials or decide whether a bundle is safe to publish. Rotate a leaked credential first, then report a missed pattern using synthetic data.

## Failure Handling

Bundle content is staged before it is moved into the requested destination. Handled errors remove staged and reserved output. A process or machine failure can still leave an output directory containing `.issuepack-incomplete`; that directory must be deleted and must not be shared.
