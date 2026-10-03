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
| `maxExtensions` | 256 | CWE-400 | The extensions of one certificate; of one certification request, its attributes, their values and the extensions it requests |
| `maxGeneralNames` | 10 000 | CWE-400 | The GeneralName entries of one field |
| `maxNameAttributes` | 1 024 | CWE-400 | The attributes of one distinguished name |
| `maxPolicies` | 1 024 | CWE-400 | The policies or policy mappings of one extension |
| `maxChainLength` | 10 | CWE-400 | The certificates in one path, the leaf and the anchor included |
| `maxPolicyNodes` | 4 096 | CWE-770 | The live nodes of the RFC 5280 `valid_policy_tree` |
| `maxRevokedCertificates` | 1 000 000 | CWE-400 | The entries walked in one CRL — walked lazily, never decoded into nodes |
| `maxOcspSingleResponses` | 256 | CWE-400 | The `SingleResponse` entries of one OCSP response |
| `maxPathsExplored` | 1 000 | CWE-400 | The candidate paths explored while building one — the denial-of-service bound of §6 |
| `maxSignerInfos` | 64 | CWE-400 | The signers of one SignedData, each costing a signature verification |
| `maxAttributes` | 256 | CWE-400 | The attributes in one attribute set — a CMS signer's, a PKCS#8 key's, a PKCS#12 bag's |
| `maxCmsCertificatesAndCrls` | 1 024 | CWE-400 | The certificates and revocation entries one SignedData carries |
| `maxKdfIterations` | 10 000 000 | CWE-400 | The PBKDF2 iteration count honoured in one derivation — declared by the file, run by the host |
| `maxPkcs12Bags` | 4 096 | CWE-400 | The SafeBags read from one PKCS#12, across every SafeContents |
| `maxPkcs12KdfIterations` | 10 000 000 | CWE-400 | The PBKDF2 iterations one PKCS#12 costs in total — its MAC, every encrypted SafeContents and every shrouded key |

Exceeding a limit throws `PkiLimitError` with code `PKI_LIMIT_EXCEEDED` and the `limit`, `configured` and `observed` values. Override per call with `options.limits`; `DEFAULT_PKI_LIMITS` holds the defaults.

## Fail in one way

A structural failure throws a `PkiError` subclass — `PkiEncodingError` for X.690, OID and PEM syntax, `PkiCertificateError` for the RFC 5280 structure, `PkiLimitError` for a limit — with a stable `code`. A conformance concern is a diagnostic. The two never mix: a diagnostic never hides a structural failure, and a thrown error never carries a merely pedantic concern. Any other exception escaping on malformed input — a `TypeError`, a `RangeError` — is a bug, and the fuzzing suites plus the conformance gate check that none does across every truncation, every single-octet mutation and 30 361 unique x509-limbo certificates.

Decoded names and OIDs are kept in arrays and `Map`s, never as plain object keys, so a crafted `__proto__` cannot reach an object prototype (CWE-1321). `formatDistinguishedName` escapes control characters, so a crafted name cannot drive the terminal that prints it.

## Cryptography pkinative does not own

pkinative never implements secret-dependent cryptography in TypeScript: no signing arithmetic, no key generation, no RSA modular exponentiation, no elliptic-curve scalar multiplication. Every signature it verifies and every signature it creates — on a certificate, a certification request or a CMS SignedData — is one Web Crypto call with the caller's key, and so is every password-based derivation, MAC and decryption of a PKCS#8 or PKCS#12 container; the arithmetic runs in the host's native implementation, not in JavaScript `BigInt`s. `src/crypto/webcrypto.ts` is the only module that names those operations, and it refuses `generateKey`, `exportKey`, `deriveBits`, `encrypt` and `wrapKey` for good. The SHA-1, SHA-256, SHA-384 and SHA-512 code exists for synchronous fingerprints of public data only and is not exported as general-purpose hashing.

The consequence is a split worth knowing: the **structure** around a signature is pkinative's to check — the DER of an ECDSA signature, the algorithm named inside and outside the signed bytes, the key's curve — and the **arithmetic** is the host's, RSA padding, Ed25519 canonicity and the ECDSA scalar range included. The CVE-class corpus below says which side stops each known attack.

This is a deliberate departure from the code pkinative grew out of: pdfnative's pure-JavaScript RSA and ECDSA use `BigInt` arithmetic that is not constant-time, and are not ported. The reasoning behind each permanent refusal — a Web Crypto operation, a legacy PKCS#12 scheme, an algorithm Web Crypto lacks — is recorded in the [architecture decision records](../adr/README.md).

## No reach outside the engine

`src/` has no filesystem, network, process or dynamic-import access, no `eval` and no `Function`, and no module-level side effects — all enforced from the syntax tree by the architecture test. The package is tree-shakeable, and `npm run verify:bundle` proves that a certificate parser bundle carries no PEM code, no hash and no OID name registry.

## CVE classes

Every published vulnerability of a PKI library whose class pkinative could share is replayed against the engine on every gate run: `tests/security/cve-classes.test.ts` rebuilds each one from synthetic input — raw DER, keys generated in the test, forgeries computed with public arithmetic — and asserts the refusal, the code or the verdict. `docs/data/cve-classes.json` records, for each identifier, the library it hit, the class, the CWE, whether it applies, why, and the test that proves it; the `cve-class-parity` rule of `npm run verify:docs` fails the build when the registry, the tests and this table disagree.

**Applies** is `no` when pkinative has the code path and refuses the attack, `n.a.` when the class cannot exist here (no DSA, no padding parser, no memory-unsafe code), and `yes` when the audit found it. **Stopped by** is honest about delegation: where it says the host's Web Crypto, pkinative hands the bytes over unchanged and the test proves the host refuses them — a host that stopped refusing would turn the suite red.

| Identifier | Library | Class | Applies | Stopped by |
|---|---|---|---|---|
| CVE-2020-0601 | Windows CryptoAPI (crypt32.dll) | CurveBall: an ECC certificate carrying a trusted root's public point under explicit curve parameters with an attacker-chosen generator is trusted as that root | no | pkinative |
| CVE-2024-42461, GHSA-49q7-c7j4-3p7m | elliptic (npm) 5.2.1–6.5.6 | BER-encoded ECDSA signatures accepted (signature malleability) | no | pkinative |
| CVE-2020-14966 | jsrsasign (npm) ≤ 8.0.18 | ECDSA signature malleability through unchecked sequence lengths and appended zero octets | no | pkinative |
| CVE-2024-42460, GHSA-977x-g7h5-7qgw | elliptic (npm) 2.0.0–6.5.6 | ECDSA r and s not checked for a redundant leading octet or a negative value | no | pkinative |
| CVE-2020-13822 | elliptic (npm) 6.5.2 | ECDSA malleability through integer overflow (r + n, s + n) | no | pkinative, then the host |
| CVE-2022-21449 | Oracle Java SE 17.0.2 and 18 | ECDSA signature with r = s = 0 accepted | no | the host's Web Crypto |
| CVE-2022-24771 | node-forge (npm) < 1.3.0 | RSA PKCS#1 v1.5 verification lenient about the DigestInfo algorithm structure | n.a. | the host's Web Crypto |
| CVE-2022-24773 | node-forge (npm) < 1.3.0 | RSA PKCS#1 v1.5 verification does not check the DigestInfo ASN.1 structure | n.a. | the host's Web Crypto |
| CVE-2026-33894, GHSA-ppp5-5v6c-4jwp | node-forge (npm) < 1.4.0 | RSA PKCS#1 v1.5 signature forgery through an extra ASN.1 field in the DigestInfo | n.a. | the host's Web Crypto |
| CVE-2022-24772 | node-forge (npm) < 1.3.0 | RSA PKCS#1 v1.5 verification ignores trailing garbage after the DigestInfo | n.a. | the host's Web Crypto |
| CVE-2021-30246 | jsrsasign (npm) ≤ 10.1.13 | some invalid RSA PKCS#1 v1.5 signatures (malformed encoded message) recognised as valid | n.a. | the host's Web Crypto |
| CVE-2006-4339 | OpenSSL before 0.9.7k, and 0.9.8 before 0.9.8c | Bleichenbacher forgery of PKCS#1 v1.5 signatures under an e = 3 key, computed without the private key | n.a. | the host's Web Crypto |
| CVE-2020-14968, GHSA-q3gh-5r98-j4h3 | jsrsasign (npm) 3.0.0–8.0.15 | RSA signature with prepended zero octets accepted | no | the host's Web Crypto |
| CVE-2026-4598 | jsrsasign (npm) < 11.1.1 | infinite loop in modular inversion on a zero or negative input | no | pkinative |
| CVE-2026-4602 | jsrsasign (npm) < 11.1.1 | negative exponents mishandled, breaking signature verification | no | pkinative |
| CVE-2026-4603 | jsrsasign (npm) < 11.1.1 | division by zero in RSA public-key operations on a zero modulus | no | pkinative |
| CVE-2024-42459, GHSA-f7q4-pwc6-w24p | elliptic (npm) 4.0.0–6.5.6 | EdDSA signature length not checked, so zero octets can be appended or removed | no | the host's Web Crypto |
| CVE-2026-33895, GHSA-q67f-28xg-22rw | node-forge (npm) < 1.4.0 | Ed25519 signature with S ≥ L (non-canonical) accepted | no | the host's Web Crypto |
| CVE-2024-48949, GHSA-434g-2637-qmqr | elliptic (npm) < 6.5.6 | EdDSA verify omits the S < n range check | no | the host's Web Crypto |
| CVE-2024-24783 | Go crypto/x509 | Certificate.Verify panics on a certificate with an unknown public-key algorithm in the chain | no | pkinative |
| CVE-2024-29857 | Bouncy Castle (Java) < 1.78 | explicit F2m curve parameters cause excessive CPU when a certificate is imported | no | pkinative |
| CVE-2023-0217 | OpenSSL 3.0 | NULL dereference checking a malformed DSA public key (EVP_PKEY_public_check) | n.a. | by construction |
| CVE-2026-4599 | jsrsasign (npm) 7.0.0 to before 11.1.1 | biased random scalar generation (DSA/ECDSA signing) leaks the private key | n.a. | by construction |
| CVE-2026-4600 | jsrsasign (npm) < 11.1.1 | DSA domain parameters not validated before verification | n.a. | by construction |
| CVE-2026-4601 | jsrsasign (npm) < 11.1.1 | DSA signing does not retry when r or s is zero, leaking the private key | n.a. | by construction |
| CVE-2025-66031, GHSA-554w-wpv2-vw27 | node-forge (npm) < 1.3.2 | unbounded recursion in ASN.1 decoding | no | pkinative |
| CVE-2025-66030, GHSA-65ch-62r8-g69g | node-forge (npm) < 1.3.2 | OID arc truncated to 32 bits, so a crafted OID reads as another (OID spoofing) | no | pkinative |
| CVE-2023-2650 | OpenSSL 1.0.2, 1.1.1, 3.0 and 3.1 | very slow translation of a crafted OID with huge arcs (OBJ_obj2txt) | no | pkinative |
| CVE-2025-12816, GHSA-5gfm-wpxj-wjgq | node-forge (npm) < 1.3.2 | ASN.1 schema validation desynchronised by optional fields (interpretation conflict) | no | pkinative |
| CVE-2023-33202 | Bouncy Castle (Java) < 1.73 | denial of service in the PEM parser on crafted input | no | pkinative |
| CVE-2024-0727 | OpenSSL 1.0.2, 1.1.1, 3.0, 3.1 and 3.2 | NULL dereference on a PKCS#12 whose ContentInfo content is absent | no | pkinative |
| CVE-2023-0216 | OpenSSL 3.0 | invalid pointer dereference loading malformed PKCS#7 data (d2i_PKCS7) | no | pkinative |
| CVE-2022-36083 | jose (npm) | attacker-chosen PBKDF2 iteration count (the JWE p2c header) costs the receiver unbounded CPU | yes | pkinative |
| CVE-2026-33896, GHSA-2328-f5f3-gj25 | node-forge (npm) ≤ 1.3.3 | an intermediate without basicConstraints or keyUsage accepted as a CA | no | pkinative |
| CVE-2023-0286 | OpenSSL 1.0.2, 1.1.1 and 3.0 | type confusion on x400Address in GeneralName comparison | n.a. | by construction |
| CVE-2022-3602 | OpenSSL 3.0 | buffer overrun decoding a punycode email address in name-constraint checking | n.a. | by construction |
| CVE-2022-3786 | OpenSSL 3.0 | buffer overrun (variable length) decoding a punycode email address in name-constraint checking | n.a. | by construction |
| CVE-2024-45341 | Go crypto/x509 | a URI with an IPv6 zone identifier wrongly satisfies a URI name constraint | no | pkinative |
| CVE-2025-61727 | Go crypto/x509 | an excluded subdomain constraint does not restrict a wildcard dNSName | no | pkinative |
| CVE-2023-0464 | OpenSSL 1.0.2, 1.1.1, 3.0 and 3.1 | exponential growth of the policy tree on crafted policy mappings (denial of service) | no | pkinative |
| CVE-2023-0465 | OpenSSL 1.0.2, 1.1.1, 3.0 and 3.1 | invalid certificate policies in a leaf silently ignored | no | pkinative |
| CVE-2009-2408 | Mozilla NSS < 3.12.3 | a NUL character in the commonName matches the name before it | no | pkinative |
| CVE-2021-42574 | Unicode Bidirectional Algorithm | bidirectional control characters reorder rendered text | no | pkinative |

CVE-2022-36083 is the one that applied: a PKCS#12 with no MAC could make `openPkcs12` run one ten-million-iteration PBKDF2 per entry. `maxPkcs12KdfIterations` bounds the work of a whole file and refuses it at parse, before anything is derived.

Coverage-guided fuzzing complements the replays: ClusterFuzzLite runs eight targets in `fuzz/` — the X.690 decoder, X.509, PEM and OIDs, CMS SignedData, CRLs, OCSP responses, RFC 3161 timestamps, and PKCS#12 with PKCS#8 — each seeded with a real structure of its grammar and each executed against `src/` on every gate run by `tests/fuzzing/targets.test.ts`.

## Reporting a vulnerability

Report privately, never in an issue: through [GitHub's private vulnerability reporting](https://github.com/Nizoka/pkinative/security/advisories/new), or by email to [security@pkinative.dev](mailto:security@pkinative.dev). See [SECURITY.md](../../SECURITY.md) for scope and response times.
