---
description: "Audit pkinative for standards conformance, untrusted-input hardening, cross-runtime portability and the zero-dependency contract."
agent: "agent"
---
# Compliance Audit

Perform a comprehensive compliance audit of pkinative. Report findings with
severity (critical/warning/info), the clause or rule each one violates, the
reproduction command, and a recommended fix. Do not fix anything in the same
pass.

## Audit Areas

### 1. ITU-T X.690 (BER/DER)
- Tags: high-tag-number form minimal, no leading `0x80` continuation octet
- Lengths: definite form under DER, minimal long form, no `0xFF`, at most four length octets
- Primitive vs constructed form matches the universal type (SEQUENCE/SET constructed, INTEGER primitive…)
- BOOLEAN `0xFF` for TRUE under DER; INTEGER minimal two's complement; BIT STRING unused bits 0–7 and zero padding
- SET OF sorted (§11.6); DEFAULT values not encoded (§11.5)
- Trailing data after the outermost TLV refused unless explicitly allowed

### 2. RFC 5280 certificate profile
- `signatureAlgorithm` equals `tbsCertificate.signature`
- Version rules (extensions only in v3, unique identifiers only in v2/v3)
- Validity encoding: UTCTime through 2049, GeneralizedTime from 2050, `Z` required, seconds present
- Serial number positive and at most 20 octets
- Extensions: no duplicates, critical flag honoured, unknown critical extensions reported
- Every standard extension decoded to the ASN.1 module of RFC 5280 Appendix A

### 3. RFC 7468 PEM
- Strict mode: exact label, 64-column base64, no headers, matching end label
- Lax mode: whitespace tolerance documented and diagnosed, never silent

### 4. Untrusted-input hardening
- Every loop over input consults a named limit (`src/core/pki-limits.ts`) with a CWE, a fuzzing test and a SECURITY.md row
- Iterative decoding: hostile nesting ends in `PKI_LIMIT_EXCEEDED`, never a `RangeError`
- Every failure is a `PkiError` subclass with a stable `code`; no `TypeError` escapes on malformed input
- No prototype pollution vectors (no object keys taken from input)

### 5. Cryptographic scope
- No secret-dependent arithmetic in `src/` (no modular exponentiation, no scalar multiplication, no key generation)
- Hashing limited to public data (fingerprints)
- Web Crypto the only signing and verification backend (from 0.3)

### 6. Cross-platform
- No Node.js-specific API in `src/` (no `Buffer`, no `node:` imports, no `process`)
- ESM + CJS dual exports working correctly (`npm run check:package`)
- Identical decoding results on Node, browsers, Deno, Bun and Workers

### 7. Zero-dependency verification
- No `dependencies` in package.json
- No dynamic `require()` or `import()` in `src/`
- `npm ls --omit=dev --all` lists nothing but pkinative
