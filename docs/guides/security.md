# Security model

> **Every certificate, PEM text and DER blob pkinative reads is treated as attacker-controlled.** This guide explains what that means in practice: strict decoding, bounded resources, typed failures, and a hard line around cryptography.

## Refuse ambiguity

A signature covers bytes. If two parsers can read the same bytes as two different values, an attacker can have one of them verify what the other one displays (CWE-436). DER exists to rule that out, and pkinative decodes it the way X.690 §10–11 defines it: indefinite lengths, non-minimal lengths and tags, constructed strings, BOOLEAN values other than `0x00` and `0xFF`, non-minimal INTEGERs, non-zero BIT STRING padding and trailing bytes are all refused with a stable code.

BER is accepted only when the caller asks for it with `encodingRules: 'ber'` — as real CMS needs — and every tolerated construct is reported once as a diagnostic. `encodeAsn1Node` refuses to re-encode a BER-only tree as if it were DER.

One exception is deliberate: a DEFAULT value encoded explicitly (`cA FALSE`, `critical FALSE`, version v1) reads the same in every parser, and Go, OpenSSL and BoringSSL accept it; pkinative reads it with the `PKI_DIAG_DEFAULT_ENCODED` diagnostic, and `strict: true` refuses it.

## Bound every resource

Every loop over input consults a named limit. The decoder is iterative, so nesting depth is a limit and never a call-stack overflow. Every declared length is checked against the remaining input before anything is allocated.

| Limit | Default | CWE | Guards |
|---|---|---|---|
| `maxInputBytes` | 64 MiB | CWE-400 | The size of one DER input, or the length of one PEM text |
| `maxDepth` | 64 | CWE-674 | The nesting depth of constructed values |
| `maxNodes` | 200 000 | CWE-770 | The values decoded from one input |
| `maxIntegerBytes` | 8 192 | CWE-407 | The content length of one INTEGER converted to a bigint |
| `maxOidBytes` | 256 | CWE-400 | The content length of one OBJECT IDENTIFIER |
| `maxBerSegments` | 10 000 | CWE-400 | The segments joined from one BER constructed string |
| `maxPemBlocks` | 10 000 | CWE-400 | The blocks read from one PEM text |
| `maxExtensions` | 256 | CWE-400 | The extensions of one certificate |
| `maxGeneralNames` | 10 000 | CWE-400 | The GeneralName entries of one field |
| `maxNameAttributes` | 1 024 | CWE-400 | The attributes of one distinguished name |
| `maxPolicies` | 1 024 | CWE-400 | The policies or policy mappings of one extension |
| `maxChainLength` | 10 | CWE-400 | The certificates in one path, the leaf and the anchor included |
| `maxPolicyNodes` | 4 096 | CWE-770 | The live nodes of the RFC 5280 `valid_policy_tree` |
| `maxRevokedCertificates` | 1 000 000 | CWE-400 | The entries walked in one CRL — walked lazily, never decoded into nodes |
| `maxOcspResponses` | 256 | CWE-400 | The `SingleResponse` entries of one OCSP response |
| `maxPathsExplored` | 1 000 | CWE-400 | The candidate paths explored while building one — the denial-of-service bound of §6 |
| `maxSignerInfos` | 64 | CWE-400 | The signers of one SignedData, each costing a signature verification |
| `maxCmsAttributes` | 256 | CWE-400 | The attributes in one signed or unsigned attribute set |
| `maxCmsBagEntries` | 1 024 | CWE-400 | The certificates and revocation entries one SignedData carries |
| `maxKdfIterations` | 10 000 000 | CWE-400 | The PBKDF2 iteration count honoured — declared by the file, run by the host |
| `maxPkcs12Bags` | 4 096 | CWE-400 | The SafeBags read from one PKCS#12, across every SafeContents |

Exceeding a limit throws `PkiLimitError` with code `PKI_LIMIT_EXCEEDED` and the `limit`, `configured` and `observed` values. Override per call with `options.limits`; `DEFAULT_PKI_LIMITS` holds the defaults.

## Fail in one way

A structural failure throws a `PkiError` subclass — `PkiEncodingError` for X.690, OID and PEM syntax, `PkiCertificateError` for the RFC 5280 structure, `PkiLimitError` for a limit — with a stable `code`. A conformance concern is a diagnostic. The two never mix: a diagnostic never hides a structural failure, and a thrown error never carries a merely pedantic concern. Any other exception escaping on malformed input — a `TypeError`, a `RangeError` — is a bug, and the fuzzing suites plus the conformance gate check that none does across every truncation, every single-octet mutation and 30 361 unique x509-limbo certificates.

Decoded names and OIDs are kept in arrays and `Map`s, never as plain object keys, so a crafted `__proto__` cannot reach an object prototype (CWE-1321). `formatDistinguishedName` escapes control characters, so a crafted name cannot drive the terminal that prints it.

## Cryptography pkinative does not own

pkinative never implements secret-dependent cryptography in TypeScript: no signing, no key generation, no RSA modular exponentiation, no elliptic-curve scalar multiplication. Verification and creation, from 0.3, go through Web Crypto, whose implementations run in constant time in the host. The SHA-1, SHA-256, SHA-384 and SHA-512 code exists for synchronous fingerprints of public data only and is not exported as general-purpose hashing.

This is a deliberate departure from the code pkinative grew out of: pdfnative's pure-JavaScript RSA and ECDSA use `BigInt` arithmetic that is not constant-time, and are not ported.

## No reach outside the engine

`src/` has no filesystem, network, process or dynamic-import access, no `eval` and no `Function`, and no module-level side effects — all enforced from the syntax tree by the architecture test. The package is tree-shakeable, and `npm run verify:bundle` proves that a certificate parser bundle carries no PEM code, no hash and no OID name registry.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting, never in an issue — see [SECURITY.md](../../SECURITY.md) for scope and response times.
