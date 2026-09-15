# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Versions below 1.0.0 are git tags and are not published to npm.

## [Unreleased]

### Added

- **feat(pem): RFC 7468 decoding and encoding** — `decodePem` reads every block of a text in `strict` mode (exact boundary lines, 64-character base64 lines, no headers) or `lax` mode (whitespace, any line length, RFC 1421 headers, each deviation reported once); both modes ignore explanatory text around blocks, and refuse labels outside the grammar, mismatched END labels, unterminated blocks and non-canonical base64. An optional `label` refuses any other block, so a private key is never read as a certificate. `encodePem` writes the strict form. The PEM layer never imports the ASN.1 layer.
- **feat(asn1): strict X.690 decoder, value readers, OID codec and DER encoders** — `decodeAsn1` and `decodeAsn1Sequence` decode iteratively (nesting is the `maxDepth` limit, never the call stack), strict DER by default and BER with `encodingRules: 'ber'`; every node is frozen and keeps zero-copy views of its exact bytes. Under DER, indefinite and non-minimal lengths, non-minimal or overflowing high tags, constructed strings, wrong primitive/constructed forms, stray end-of-contents markers and trailing bytes are refused with a stable code; under BER each tolerated construct is reported once. Readers for BOOLEAN, INTEGER (bigint and safe number), NULL, BIT STRING, OCTET STRING (BER segments joined under `maxBerSegments`), eight character string types and both time types (impossible dates refused, never rolled over; years 0000–9999 exact). `encodeOid`, `decodeOid`, `isValidOid` and `readObjectIdentifier` with exact arcs of any size. DER encoders that refuse what DER cannot represent, `encodeSetOf` with X.690 §11.6 ordering, and `encodeAsn1Node`, which re-encodes a DER-decoded tree byte for byte. A length encoded as `84 80 00 00 01` — negative under pdfnative's signed shift — is a `PKI_ASN1_TRUNCATED` or `PKI_ASN1_LENGTH_OVERFLOW` here.
- **feat(core): errors, limits and diagnostics** — the `PkiError` family (`PkiEncodingError`, `PkiCertificateError`, `PkiLimitError`) with a stable `code` from typed unions, registered in `docs/data/errors.json`; eleven CWE-tagged `PkiLimits` with `DEFAULT_PKI_LIMITS`, mirrored in `docs/data/limits.json` and SECURITY.md; the single diagnostics channel (`strict`, `onDiagnostic`, once-per-code `console.warn`) with one payload factory per code, registered in `docs/data/diagnostics.json`; strict UTF-8, UCS-2, UCS-4 and ASCII-subset text codecs; canonical base64. `verify:docs` gains `error-parity` (including the message prefix of every throw site), `diagnostics-parity` and `limits-parity`.

- **chore: bootstrap** — build (tsup ESM + CJS + declarations, a single entry point with `browser`, `import` and `require` conditions), three strict tsconfigs, ESLint 9, vitest 4 with coverage thresholds, the quality gate (`scripts/gate.ts`), the documentation and governance verifier (`scripts/verify-docs.ts` with one module per rule family and a perturbation test per rule), the architecture test that enforces the layer table and the syntactic conventions from the syntax tree, hardened CI on Linux and Windows, CodeQL, Scorecard, Dependency Review, weekly audit, an inert pre-1.0 publish workflow, rulesets, the human-in-the-loop AI governance policy, the Claude Code guard hook and generated rules, and the contributor documentation.

## [0.0.1] – 2026-09-15

Name reservation on npm. The package contains no code.
