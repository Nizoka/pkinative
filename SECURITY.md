# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public issue for security vulnerabilities.**

Report privately, through either channel:

1. **[GitHub private vulnerability reporting](https://github.com/Nizoka/pkinative/security/advisories/new)** — preferred: the report, the discussion, the fix in a temporary private fork and the advisory all stay in one place.
2. **E-mail to [security@pkinative.dev](mailto:security@pkinative.dev)** — when you cannot or would rather not use GitHub. Mail is not encrypted: send the description and a way to reproduce, and we will invite you to a private advisory for anything more sensitive.

Please include the version (or commit), the function called with its options, the input that triggers the problem (or how to build it), what you expected and what happened. A certificate or a DER blob attached as base64 or PEM is the most useful reproduction.

What counts as a vulnerability here: an input that makes pkinative accept an encoding the standard forbids in a way that could change a security decision (a parser differential), a verdict that accepts what the standard rejects, an input that exhausts memory or CPU despite the configured limits, an exception other than a `PkiError` subclass escaping on malformed input, or any secret-dependent behaviour.

The handling steps, their timelines, the advisory and the credit are in [Disclosure Policy](#disclosure-policy). The same contacts are published for machines at `https://pkinative.dev/.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)).

## Supported Versions

| Version | Supported |
|---------|-----------|
| the latest 1.x minor on npm | ✅ fixes land in its next patch or in the next minor |
| any older 1.x minor | ❌ upgrade to the latest minor: under the compatibility promise below it breaks nothing |
| 0.x (git tags only, never on npm) | ❌ |
| npm `0.0.1` (name reservation, deprecated) | ❌ contains no code |

### Supported runtimes and compilers

Decided in [ADR 0017](docs/adr/0017-runtime-and-toolchain-support.md); `contracts.support` in `docs/assets/ecosystem.json` is the same policy for a program to read.

| | 1.x | What a minor may change |
|---|---|---|
| Node.js | Every line in Active or Maintenance LTS: Node.js 22 and Node.js 24 at 1.0.0, both run by CI, each from its patched floor (below) | Drop a line after its end of life (Node 22: 2027-04-30), announced one minor ahead; raise the floor of a line to the release that fixes a vulnerability in a Web Crypto operation pkinative calls |
| TypeScript (consumers) | TypeScript 5.0 and later, under `moduleResolution` `node16`/`nodenext`, `bundler` and `node10` | Raise the floor, never to a release younger than two years |
| ECMAScript | ES2020 syntax and library, plus two host APIs: Web Crypto (`globalThis.crypto.subtle`, for signatures, keys, PKCS#12 and asynchronous digests) and `TextDecoder` | Nothing: raising it is major |
| Browsers (secure context), Deno, Bun, Cloudflare Workers | Targeted: the build has no Node-only import or global, checked statically. **No gate executes it there**, and no version floor is promised | — |

`engines.node` is `^22.22.2 || ^24.14.1 || >=25.8.2`. **Run the latest security release of your Node.js line.** pkinative checks a PKCS#12 MAC with the host's Web Crypto: before 22.22.2, 24.14.1 and 25.8.2, Node compared that MAC in variable time ([CVE-2026-21713](https://nodejs.org/en/blog/vulnerability/march-2026-security-releases)), which is why those releases are the floor. npm warns, and refuses only under `engine-strict`, when a runtime is outside the range.

## Compatibility promise

From 1.0.0, pkinative promises three things for the whole major line. Each is recorded in a committed snapshot, held by a rule of `npm run verify:docs` that fails the build, and decided in an architecture decision record; the snapshots are taken, and the gate runs, under the default options (DER, `strict: false`, the default limits). What the promise says beyond them — option defaults, verdicts, returned unions, report fields, other options, the wire form, entry points — is decided in [ADR 0016](docs/adr/0016-one-entry-point-for-1-x.md), [ADR 0017](docs/adr/0017-runtime-and-toolchain-support.md) and [ADR 0018](docs/adr/0018-what-the-1-x-promise-covers-beyond-its-snapshots.md), and summarised below.

| Leg | What is promised | Snapshot | Held by | Decided in |
|---|---|---|---|---|
| The export surface | Every export of the package keeps its name, its kind and a compatible signature, and every `PkiReasonCode` keeps its name: the reason vocabulary is grow-only. | `docs/assets/api.frozen.json` | `api-surface-frozen` | [ADR 0012](docs/adr/0012-frozen-error-vocabulary.md), [ADR 0013](docs/adr/0013-renames-before-the-freeze.md) |
| The error vocabulary | Every `PkiErrorCode` keeps its name and its `PkiError` class — frozen since 0.8.0. | `docs/data/errors.frozen.json` | `error-codes-frozen` | [ADR 0012](docs/adr/0012-frozen-error-vocabulary.md) |
| The decision surface | A corpus certificate pkinative refuses stays refused, with the same code; a new refusal is a recorded fix; and every corpus certificate decoded with `decodeAsn1` and re-encoded with `encodeAsn1Node` comes back byte for byte. | `docs/data/refusals.frozen.json` | `refusal-baseline-frozen`, and conformance L1 and L2 | [ADR 0014](docs/adr/0014-the-decision-surface-contract.md) |

The corpus is x509-limbo, pinned by commit and SHA-256: the snapshot lists every certificate of it that `parseCertificate` refuses, by the SHA-256 of its DER, with the code it is refused with. Conformance L1 ([docs/guides/conformance.md](docs/guides/conformance.md#the-levels)) holds the engine to that list on every run, and L2 re-encodes every certificate of the corpus, the refused ones included. When the corpus is re-pinned, a certificate it brings and pkinative refuses is promised from the re-pin; one the new corpus expects to be accepted is fixed in the engine first, in its own commit; and a promised certificate the corpus drops is retired from verification only on an accepted record ([ADR 0014](docs/adr/0014-the-decision-surface-contract.md), [ADR 0018](docs/adr/0018-what-the-1-x-promise-covers-beyond-its-snapshots.md)).

### What a 1.x release may change

| Change | Semver |
|---|---|
| An export removed, renamed or given an incompatible signature; a reason code removed or renamed | major |
| An error code removed, renamed or moved to another class | major |
| A refused corpus certificate lifted (it now parses), or refused with another code | major |
| An option's default value changed, in either direction — the defaults are listed in `docs/data/defaults.json`, held to the source by `option-defaults-parity` | major |
| A limit default lowered — a new refusal, recorded like the next row | minor |
| A default added to an option that had none (`openPkcs12`'s `rsaAlgorithm`, `importPrivateKey`'s `algorithm` for an RSA key) | minor |
| A corpus certificate that parsed now refused — only as a security or conformance fix, listed by SHA-256 under `### Decision surface` in the release note | minor |
| A path, revocation, CMS, timestamp, PKCS#12 or signature verdict, or the reasons returned with it, corrected toward the standard — never silently: the reviewed conformance baselines of L6, L7 and L8 move in the same change where they hold the case, and the release note says so | minor |
| A capability added: an outcome that meant "cannot decide" — `PKI_REASON_SIGNATURE_NOT_CHECKED`, a `PKI_REASON_PKCS12_*_UNSUPPORTED` or `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` reason, a key import refused as unsupported — becomes a decision | minor |
| A returned union gains a member, or an input reported as `'unknown'` is reported as a known kind | minor |
| A new export, optional parameter or member, error code, reason code or diagnostic code | minor |
| A subpath export added beside `.` | minor ([ADR 0016](docs/adr/0016-one-entry-point-for-1-x.md)) |
| A subpath export removed or renamed; `.` made incomplete | major |
| A Node.js line dropped after its end of life; the TypeScript floor raised within its two-year window | minor ([ADR 0017](docs/adr/0017-runtime-and-toolchain-support.md)) |
| A field added to a `docs/data` registry; a field removed or renamed | minor; major |
| A refusal the doctrine makes permanent lifted — PBES1, the RFC 7292 Appendix B MAC and Appendix C ciphers, a key operation `KEY_OPERATION_POLICY` refuses | never, in any version |
| A decoded certificate that no longer re-encodes byte for byte | never — a defect, fixed in a patch |

Security fixes stay possible within 1.x because every one found so far made pkinative refuse more: 0.9.0 closed two paths it accepted and RFC 5280 rejects. A fix that would change the code of an existing refusal waits for 2.0, and so does a refusal later found to be wrong: a caller can rely on a refused certificate staying refused.

### Options

**Defaults.** Every default pkinative chooses on a caller's behalf — `requireRevocation: false`, `allowWildcards: true`, `restrictIssuers: true`, `allowSha1: false`, the 60-second `futureTolerance` of OCSP, the SHA-1 of `computeKeyIdentifier`, and every other — is in [`docs/data/defaults.json`](docs/data/defaults.json) with the source line that implements it, and is frozen for 1.x unless its row says `lowerable` (the limits), `addable` (an option with no default yet, [ADR 0015](docs/adr/0015-no-default-rsa-scheme.md)) or `not-promised` (the diagnostic sink).

**Non-default options.** Every option keeps its name, its type, its meaning — the check it switches on or off — and its default. What it accepts when set is not snapshotted: which BER constructs `encodingRules: 'ber'` accepts, which inputs `strict: true` refuses, what parses beyond the default limits, what `mode: 'lax'` tolerates, and the verdicts reached under a relaxing or tightening flag may change in a minor, by the rows above, never silently.

### Reading a report

**Unions are open.** Keep a default branch in every `switch` over a returned `kind`, status or code, and branch on the positive member — `valid === true`, `status === 'valid'` — never on the absence of a known failure.

**Fields.** `code`, the error class, `errorCode` and `limit` are promised. A `path` keeps its grammar: it starts at a member of the input the operation took, or at `path` for the certification path a report describes, and descends with `.member` and `[index]`; a minor may make it more precise. The rest is for a human or a measurement, listed below.

**The wire form.** Results hold `bigint` and `Uint8Array` values, so `JSON.stringify` refuses them; no JSON form is promised. The convention reserved for one — and for the satellites — is a `bigint` as its decimal string and bytes as lowercase hexadecimal. The registries under `docs/data/` and `docs/assets/api.json` are machine contracts that only grow; they are not in the npm package, and the copy for version X.Y.Z is the one at the git tag `vX.Y.Z`.

### What is not promised

- **Diagnostics.** A diagnostic code is never renamed or removed, but its severity and wording may change in a minor — so under `strict: true`, which turns diagnostics into `PKI_STRICT_DIAGNOSTIC`, a certificate may become refused in a minor.
- **Message wording.** The code and the class are the contract; the sentence after `pkinative: `, a reason's `message` and the clause its `standard` cites are for a human, and a cited clause may become more precise.
- **The exact `path` and `offset`** of an error or a reason, beyond the grammar above: they move when a check moves.
- **Order and counts.** The order of `reasons` (treat them as a set), the counts a report carries (`explored`, `signatureVerifications`) and the order of properties in a returned object.
- **Limit default values.** A default may be lowered in a minor when an attack makes it dangerous; that is a new refusal like any other, recorded the same way. Raising a limit is the caller's act, for trusted input. The limit names are frozen.
- **Verdicts**, beyond what the table above says: path, revocation, CMS, timestamp, PKCS#12 and signature verdicts are recorded, not frozen.
- **A JSON form of results**, as above.
- **Runtimes no gate executes.** Browsers, Deno, Bun and Cloudflare Workers are targeted, not tested ([Supported runtimes and compilers](#supported-runtimes-and-compilers)).
- **Conformance scores.** They are measurements, and they move when a corpus is re-pinned.
- **Bundle sizes and performance.** They are measurements, and they move when a budget is reviewed.

### Machine-readable form

`docs/assets/ecosystem.json` → `contracts.compatibility` names each leg with its snapshot, its rules, its conformance levels and its records, then each policy of ADR 0016 to 0018 with its records and the registry or conformance level that holds it, and lists what is not promised, entry for entry with the section above; `contracts.support` states the runtime and compiler floors. The `contracts-shape` rule holds that block to the files, the rules, the records and this section, both ways: a snapshot or a frozen-surface rule that no leg names fails too. The snapshots move only through their generators — `scripts/build-api-frozen.ts`, `scripts/build-errors-frozen.ts` and `scripts/build-refusals-frozen.ts` — which `scripts/release-prepare.ts` runs at every release from 1.0.0, so that what a 1.x release adds becomes part of the promise.

## Security Model

pkinative is a pure TypeScript library with **zero runtime dependencies**. Every certificate, PEM file and DER blob it reads is treated as attacker-controlled.

### Cryptographic Implementation Scope

pkinative **never implements secret-dependent cryptography in TypeScript**. There is no signing, no key generation, no RSA modular exponentiation and no elliptic-curve scalar multiplication in `src/`. Arithmetic cannot be recognised from a syntax tree, so it is kept out by review — but *naming* a Web Crypto key operation can be, and is, per module. The architecture test (`tests/tools/architecture.test.ts`) fails the build when any file outside the list below names one, in a call or in a type, and the `key-operation-parity` rule of `npm run verify:docs` holds this table to `KEY_OPERATION_POLICY` in `scripts/lib/architecture.ts`.

| Operation | Allowed in | Since |
|---|---|---|
| `importKey` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.3.0 |
| `verify` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.3.0 |
| `sign` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.3.0 |
| `generateKey` | nowhere | never |
| `exportKey` | nowhere | never |
| `deriveBits` | nowhere | never |
| `encrypt` | nowhere | never |
| `wrapKey` | nowhere | never |
| `deriveKey` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.8.0 |
| `unwrapKey` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.8.0 |
| `decrypt` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.8.0 |

**"Nowhere / never" is a promise, not a backlog.** pkinative creates, exports, wraps and derives no raw key material in any version. `exportKey` being refused is why the certificate builder takes a SubjectPublicKeyInfo in DER rather than a `CryptoKey`: one line in the caller's code, in exchange for a guarantee a test can check. `deriveBits` stays refused although 0.8 opens `deriveKey`, because the first hands back an `ArrayBuffer` nothing can zeroise and the second returns a non-extractable handle; for the same reason an encrypted private key is opened with `unwrapKey`, which yields a signing key, and never with `decrypt`, which would yield its plaintext. `decrypt` opens a PKCS#12 SafeContents; when its writer nested an *unencrypted* keyBag inside one, that key is plaintext by definition once the SafeContents is opened, and `openPkcs12` wipes those bytes as soon as Web Crypto has imported them — a best effort, stated as one.

`globalThis.crypto` has one door too: only `src/crypto/webcrypto.ts` and `src/hash/fingerprint.ts` may reach it, so everything pkinative asks of a host is readable in two files.

- Signature verification and certificate creation go through Web Crypto (`crypto.subtle`), whose implementations run in constant time in the host. Keys are imported from `spki` — the public half — with `extractable: false` and the single usage `['verify']`.
- Hashing (SHA-1, SHA-256, SHA-384, SHA-512) is implemented in TypeScript for synchronous fingerprints of **public** data only; these functions are not exported as general-purpose hashes.
- The DER ↔ P1363 ECDSA signature converter (`src/crypto/crypto-signature.ts`) is TypeScript, and legal: a signature is public, there is no key in it, and it performs no arithmetic beyond copying bytes.
- This is a deliberate departure from pdfnative's pure-TypeScript RSA and ECDSA, whose `BigInt` arithmetic is not constant-time; that code is not, and will not be, ported.

#### Password-based encryption

An encrypted private key or a PKCS#12 file is opened only where every step is one Web Crypto call; every other scheme is recognised and refused by name, so the error says what the file holds. The `pkcs12-policy-parity` rule of `npm run verify:docs` holds this table to `HMAC_OIDS`, `AES_CBC_OIDS` and `REFUSED_PBE_SCHEMES` in `src/core/key-oids.ts`, both ways.

| Scheme | OID | pkinative |
|---|---|---|
| PBES2 (RFC 8018 §6.2) | `1.2.840.113549.1.5.13` | opens |
| PBKDF2 (RFC 8018 §5.2) | `1.2.840.113549.1.5.12` | opens |
| PBKDF2 PRF / PBMAC1 MAC: HMAC-SHA-1 | `1.2.840.113549.2.7` | opens |
| PBKDF2 PRF / PBMAC1 MAC: HMAC-SHA-256 | `1.2.840.113549.2.9` | opens |
| PBKDF2 PRF / PBMAC1 MAC: HMAC-SHA-384 | `1.2.840.113549.2.10` | opens |
| PBKDF2 PRF / PBMAC1 MAC: HMAC-SHA-512 | `1.2.840.113549.2.11` | opens |
| AES-128-CBC | `2.16.840.1.101.3.4.1.2` | opens |
| AES-192-CBC | `2.16.840.1.101.3.4.1.22` | opens |
| AES-256-CBC | `2.16.840.1.101.3.4.1.42` | opens |
| PBMAC1, the PKCS#12 MAC of RFC 9579 | `1.2.840.113549.1.5.14` | opens |
| `pbeWithSHAAnd128BitRC4` (RFC 7292 Appendix C) | `1.2.840.113549.1.12.1.1` | refuses |
| `pbeWithSHAAnd40BitRC4` (RFC 7292 Appendix C) | `1.2.840.113549.1.12.1.2` | refuses |
| `pbeWithSHAAnd3-KeyTripleDES-CBC` (RFC 7292 Appendix C) | `1.2.840.113549.1.12.1.3` | refuses |
| `pbeWithSHAAnd2-KeyTripleDES-CBC` (RFC 7292 Appendix C) | `1.2.840.113549.1.12.1.4` | refuses |
| `pbeWithSHAAnd128BitRC2-CBC` (RFC 7292 Appendix C) | `1.2.840.113549.1.12.1.5` | refuses |
| `pbeWithSHAAnd40BitRC2-CBC` (RFC 7292 Appendix C) | `1.2.840.113549.1.12.1.6` | refuses |
| `pbeWithMD2AndDES-CBC` (PBES1, RFC 8018 §6.1) | `1.2.840.113549.1.5.1` | refuses |
| `pbeWithMD5AndDES-CBC` (PBES1, RFC 8018 §6.1) | `1.2.840.113549.1.5.3` | refuses |
| `pbeWithMD2AndRC2-CBC` (PBES1, RFC 8018 §6.1) | `1.2.840.113549.1.5.4` | refuses |
| `pbeWithMD5AndRC2-CBC` (PBES1, RFC 8018 §6.1) | `1.2.840.113549.1.5.6` | refuses |
| `pbeWithSHA1AndDES-CBC` (PBES1, RFC 8018 §6.1) | `1.2.840.113549.1.5.10` | refuses |
| `pbeWithSHA1AndRC2-CBC` (PBES1, RFC 8018 §6.1) | `1.2.840.113549.1.5.11` | refuses |
| RFC 7292 Appendix B MAC | — | refuses |

The refusals are a consequence of the scope above, not a backlog. The RFC 7292 Appendix B key derivation, behind both the Appendix C ciphers and the legacy PKCS#12 MAC, is iterated hashing with byte arithmetic over the password — secret-dependent code that Web Crypto does not offer and that pkinative would have to write in TypeScript; PBES1 adds DES, RC2 and MD2 besides. A legacy file converts in two commands, verified against OpenSSL 4.0.0: `openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12`.

### Parser Safety

- DER is strict by default (X.690 §10–11); BER is an explicit option.
- The decoder is iterative: nesting depth is a limit, never a call-stack overflow.
- Every declared length is checked against the remaining input and the limits before anything is allocated.
- Structural failures throw a `PkiError` subclass with a stable code; conformance concerns are diagnostics; the two never mix.

### Resource Limits

Every loop over untrusted input consults one of these named bounds (`PkiLimits`). Each is configurable per call through `options.limits`; exceeding one throws `PkiLimitError` with code `PKI_LIMIT_EXCEEDED` and the `limit`, `configured` and `observed` fields. Raise a limit only for trusted input. The table is held to `src/core/pki-limits.ts` and `docs/data/limits.json` by `npm run verify:docs`. The names are frozen at 1.0 — they are the members of the `PkiLimits` signature that `api-surface-frozen` holds in `docs/assets/api.frozen.json`; the defaults are not, and may be lowered in a minor release (see [Compatibility promise](#compatibility-promise)).

| Limit | Default | CWE | Guards |
|---|---|---|---|
| `maxInputBytes` | 64 MiB | CWE-400 | The size of one DER input, or the length of one PEM text. |
| `maxDepth` | 64 | CWE-674 | The nesting depth of constructed values; the decoder is iterative, so hostile nesting stops here instead of in the call stack. |
| `maxNodes` | 200 000 | CWE-770 | The number of values decoded from one input. |
| `maxIntegerBytes` | 8 192 | CWE-407 | The content length of one INTEGER converted to a bigint. |
| `maxOidBytes` | 256 | CWE-400 | The content length of one OBJECT IDENTIFIER. |
| `maxBerSegments` | 10 000 | CWE-400 | The segments joined from one BER constructed string. |
| `maxPemBlocks` | 10 000 | CWE-400 | The blocks read from one PEM text. |
| `maxExtensions` | 256 | CWE-400 | The extensions of one certificate. |
| `maxGeneralNames` | 10 000 | CWE-400 | The GeneralName entries of one field. |
| `maxNameAttributes` | 1 024 | CWE-400 | The attributes of one distinguished name. |
| `maxPolicies` | 1 024 | CWE-400 | The policies or policy mappings of one extension. |
| `maxChainLength` | 10 | CWE-400 | The certificates one certification path may hold. Path building is exponential in the candidate set, so this is a bound on the walk and not a statement about real hierarchies. |
| `maxPolicyNodes` | 4 096 | CWE-770 | The live nodes of the RFC 5280 valid_policy_tree. The tree grows multiplicatively with each certificate, and it is the part of section 6 that actually explodes — x509-limbo has cases written for it. |
| `maxRevokedCertificates` | 1 000 000 | CWE-400 | The entries walked in one CRL `revokedCertificates` list. The list is walked with a lazy TLV cursor rather than decoded into nodes: at three nodes per entry, `maxNodes` would refuse any CRL past roughly 65 000 entries, and real CRLs are larger than that. |
| `maxOcspSingleResponses` | 256 | CWE-400 | The `SingleResponse` entries of one OCSP response. A client asks about one certificate, so a responder returning hundreds is not answering the question. |
| `maxPathsExplored` | 1 000 | CWE-400 | The candidate paths explored while building one. Path building is exponential in the candidate set, not linear in the chain length: cross-signed hierarchies give a verifier several plausible issuers at each step, and this is THE denial-of-service bound of RFC 5280 section 6 rather than `maxChainLength`. The signatures `verifyCertificateChain` verifies up front are the (subject, issuer) pairs whose names chain from the leaf: at most the square of the certificates it is given, so for a SignedData at most (`maxCmsCertificatesAndCrls` + anchors)² per signer chain, and each is one host operation whose key size the host bounds (16 384-bit RSA in OpenSSL and BoringSSL). |
| `maxSignerInfos` | 64 | CWE-400 | The signers of one SignedData. Each costs a signature verification and, when a trust store is supplied, a path search — so a message carrying thousands of signers is a way to make a verifier do thousands of both. A PDF signature has one; a detached S/MIME message rarely more than two. |
| `maxAttributes` | 256 | CWE-400 | The attributes in one attribute set — a CMS signer's signed or unsigned set, and since 0.8 a PKCS#8 key's or a PKCS#12 bag's, which share the X.501 `Attributes` syntax. Real writers use fewer than ten; the bound stops a file from making the per-attribute rules walk an arbitrarily long list. |
| `maxCmsCertificatesAndCrls` | 1 024 | CWE-400 | The certificates and revocation entries one SignedData carries. The bag is a claim by whoever assembled the message, and the signer search walks it; 1 024 leaves room for a `.p7b` bundle of a whole trust store. |
| `maxKdfIterations` | 10 000 000 | CWE-400 | The PBKDF2 iteration count honoured in one derivation. The file declares the count and the host runs it, so a PKCS#12 declaring 2³¹ iterations would otherwise freeze the reader inside Web Crypto, where no JavaScript bound can reach. Ten million is about ten seconds of SHA-256 on current hardware — above anything a real writer uses. What a whole file costs is `maxPkcs12KdfIterations`. |
| `maxPkcs12Bags` | 4 096 | CWE-400 | The SafeBags read from one PKCS#12, across every SafeContents. Each certificate bag is parsed and each key bag may cost a decryption; 4 096 holds a whole trust store exported as one file. |
| `maxPkcs12KdfIterations` | 10 000 000 | CWE-400 | The PBKDF2 iterations one PKCS#12 costs in total — its PBMAC1 MAC, every encrypted SafeContents and every shrouded key together, counted before each derivation runs. A file declares one count per derivation and may declare thousands of derivations, so `maxKdfIterations` alone bounds a file at thousands of ten-second derivations (the CVE-2022-36083 class). The default keeps one untrusted file at about ten seconds of SHA-256 however it is built, and sits far above what real writers declare: a few derivations per file, at 2 048 iterations each by default for OpenSSL 3, 10 000 for Java's keytool, and 600 000 in the GnuTLS files the 1.0 audit measured — 1 200 000 in total, the costliest of 48. |

### Verification of the Parser

- Every truncation point and every single-octet mutation of the test certificates ends in a certificate or a `PkiError` (`tests/fuzzing/`); seeded suites cover length encodings, nesting, tags, integers, times, strings, BER forms and PEM.
- The conformance gate ([docs/guides/conformance.md](docs/guides/conformance.md)) runs the built package over 30 361 unique x509-limbo certificates and 1 530 Wycheproof ECDSA vectors, pinned by commit and SHA-256, and holds every answer to OpenSSL.
- A certificate is refused only where every x509-limbo case using it expects failure; any other refusal, and any exception that is not a `PkiError`, fails the gate.
- `tests/security/cve-classes.test.ts` replays the class of each of the 43 published vulnerabilities of comparable PKI libraries listed in `docs/data/cve-classes.json` — every identifier checked against NVD or the GitHub Advisory Database — and says for each who stops it: pkinative, or the host's Web Crypto. `cve-class-parity` holds the registry, the tests and the table in [docs/guides/security.md](docs/guides/security.md) together.
- Coverage-guided fuzzing runs through ClusterFuzzLite (`.clusterfuzzlite/`, `.github/workflows/fuzz.yml`) over eight targets — the X.690 decoder in both rule sets; the RFC 5280 parser with and without extension decoding; PEM together with the OID codec, which also asserts that `encodeOid(decodeOid(x))` returns the input byte for byte; CMS SignedData; CRLs; OCSP responses; RFC 3161 tokens, responses and `TSTInfo`; and PKCS#12 with PKCS#8. It is **not** a required status check: the seeded suites are the blocking half, and this one explores. Jazzer.js is installed inside the build image and never in `package.json`, so the zero-dependency promise is unaffected. The same eight target files are executed against `src/` by `tests/fuzzing/targets.test.ts` on every gate run, including an assertion that a target still rethrows what is not a `PkiError` — a target that swallowed everything would search for a week and report nothing.

> What `tests/fuzzing/targets.test.ts` proves on every gate run is that the targets load, run and propagate. The container wiring is proven only by a completed run of the `fuzz` workflow, on a pull request, on its weekly schedule or by hand; its run history on GitHub, not this file, is the record. Where that history shows no completed run, treat the coverage-guided half as unproven.

### Code Safety

- No `eval()`, `Function()`, dynamic `import()` or dynamic code execution — enforced from the syntax tree
- No filesystem, network or process access in the engine
- Tree-shakeable (`sideEffects: false`) — no module-level side effects
- Hardened workflows — every action pinned to a commit SHA, `persist-credentials: false` on every checkout, `step-security/harden-runner` on every job, `npm ci --ignore-scripts` (also `ignore-scripts=true` in `.npmrc`), CodeQL over the TypeScript and over the workflows themselves, zizmor and actionlint on every change, OpenSSF Scorecard, Dependency Review and a weekly `npm audit`
- Release path — see [Release integrity](#release-integrity)

## In place of an external audit

There is no external security audit at 1.0 ([ADR 0010](docs/adr/0010-no-external-security-audit-at-1-0.md)). What stands in its place runs on every release or every change, where an audit is a snapshot of one moment — and none of it is independent of the project the way an audit is:

- **An adversarial release audit** before every release: two independent auditors (claims against code; docs and machine surfaces), an adversarial verifier that re-derives every finding, a docs-autonomy pass and a GO/NO-GO ledger — [CONTRIBUTING.md §Release](CONTRIBUTING.md#release), step 5, and `.claude/skills/release-audit/`. It is run by agents under the maintainer's direction.
- **The conformance gate, L0 to L8**, over third-party corpora pinned by commit and SHA-256 — x509-limbo, Wycheproof and NIST PKITS — plus an interoperability matrix against implementations written by other people ([docs/guides/conformance.md](docs/guides/conformance.md)). It runs on every change and in the publish gate of every release. The corpora judge conformance, not the absence of vulnerabilities.
- **100 % coverage on all four axes** (`vitest.config.ts`), every unreachable branch a counted, justified exception held by `coverage-ignore-budget`; and **mutation testing** (`npm run mutate`), run by hand on the files a change touches when it changes a security decision — not a gate step, because it takes minutes per file; every survivor is killed by a test or argued equivalent in `scripts/data/mutation-equivalents.json`.
- **Seeded adversarial suites** and coverage-guided fuzzing — see [Verification of the Parser](#verification-of-the-parser).
- **CodeQL** (TypeScript and the GitHub Actions workflows) on every push and pull request to `main`, and weekly; **zizmor** and **actionlint** on every change; **OpenSSF Scorecard** on every push to `main`, and weekly; **Dependency Review** on every pull request, as a required check.

If you need an audit for procurement, open an issue: it will be scoped, and ROADMAP.md will say when it happens.

## Release integrity

**Every release is built from its tag by a workflow, never on a maintainer's machine.** The tag rules ([.github/rulesets/tags.json](.github/rulesets/tags.json)) forbid deleting, moving or updating a `v*` tag, with no bypass — the repository owner included — so a version names one commit forever. The release workflow fails when the tag it runs on and the version in `package.json` disagree.

**Below 1.0.0** a version is a git tag and nothing else: a source snapshot of a milestone, with its release note in `release-notes/`, never released on GitHub or npm, and with no tarball to install or verify.

**From 1.0.0** `.github/workflows/publish.yml` publishes to npm when the maintainer pushes the `vX.Y.Z` tag, in four jobs ([ADR 0019](docs/adr/0019-release-integrity-slsa-build-l2.md)):

1. **guard** refuses a ref that is not a tag, a tag that disagrees with `package.json` and any version below 1.0.0 — before any approval is asked, with no token and nothing installed.
2. **build** holds no publishing permission. It installs the dev toolchain from the lockfile with `--ignore-scripts`, runs the full publish gate (the install smoke test of its own build included), packs the tarball once and hands it on with its SHA-256 and SHA-512 digests.
3. **publish** is the only job that can mint the npm token: it waits for the protected `npm-publish` environment, checks out `.nvmrc` and nothing else, runs no repository script, checks the tarball against both digests and its own version, and uploads that exact file through npm Trusted Publishing (OIDC, no long-lived token) with `--provenance`, using an npm client pinned by the SHA-512 of its registry tarball. The registry therefore carries a signed provenance statement tying the tarball to this repository, the workflow and the commit.
4. **attest**, holding the release-write and attestation permissions the publishing job never has, fetches the tarball back from the registry (`npm pack pkinative@X.Y.Z`), checks it against the build job's digests and the registry's integrity, runs `npm audit signatures` on a fresh install of it, writes the SBOMs from the lockfile, attests them with Sigstore build provenance and attaches them, with the Sigstore bundle, to the **draft** GitHub Release — which the maintainer publishes afterwards, so a repository with release immutability on holds the assets unchanged from then on.

The attested tarball is the byte stream npm serves, not a rebuild, and npm's provenance and the GitHub attestation cover the same bytes. No release job restores a dependency cache: every `setup-node` step disables the automatic npm cache explicitly. Every release job runs `harden-runner` with egress blocked to the hosts it needs.

This is **SLSA Build L2** — a hosted build platform that generates and signs the provenance — and not L3: the provenance is produced by a job of the project's own workflow rather than by an isolated reusable one. [ADR 0019](docs/adr/0019-release-integrity-slsa-build-l2.md) says what L3 would take.

The SBOMs: `pkinative-X.Y.Z.cdx.json` (CycloneDX 1.5) and `pkinative-X.Y.Z.spdx.json` (SPDX 2.3) describe the runtime dependency set, and are **empty by design** — pkinative has no runtime dependency, and the empty SBOM is the evidence. `pkinative-X.Y.Z.toolchain.cdx.json` records the dev packages that built `dist/`.

> **None of this has run yet.** At the time of writing the GitHub repository has no pushed history, so no workflow — CI, conformance, CodeQL, Scorecard or publish — has executed. Everything above is what the files say and what `tests/tools/workflows.test.ts`, zizmor and actionlint check locally; the first release tag is the publish workflow's first run, and this note stands until it has succeeded.

To verify:

```sh
# A release tarball and its SBOMs, downloaded from the GitHub release
gh attestation verify pkinative-X.Y.Z.tgz --repo Nizoka/pkinative
gh attestation verify pkinative-X.Y.Z.cdx.json --repo Nizoka/pkinative

# The same, against the Sigstore bundle attached to the release
gh attestation verify pkinative-X.Y.Z.tgz --repo Nizoka/pkinative --bundle pkinative-X.Y.Z.sigstore.json

# An immutable release, and a local file against its asset
gh release verify vX.Y.Z --repo Nizoka/pkinative
gh release verify-asset vX.Y.Z pkinative-X.Y.Z.tgz --repo Nizoka/pkinative

# The registry signatures and provenance of what npm installed
npm audit signatures
```

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). The process below is structured after ISO/IEC 29147:2018, on receiving vulnerability reports and publishing remediation information, and ISO/IEC 30111:2019, on handling them from receipt to post-release; it claims no conformity to either.

| Step | What happens | Target |
|---|---|---|
| Receipt | The report is acknowledged, by the channel it came in on. | 48 hours |
| Verification | The report is reproduced or refuted, its severity assessed with CVSS, and the reporter told the outcome and the planned dates. A report that is not a vulnerability is answered with the reason, and may become a public issue with the reporter's agreement. | 7 days |
| Remediation | The fix and its regression test are developed in the advisory's temporary private fork; the reporter is invited to review it. | Critical 7 days, High 14 days, Medium 30 days, Low the next minor or 90 days |
| Release | The fix ships as a patch or minor of the latest 1.x line ([Supported Versions](#supported-versions)), with a `### Security` entry in its release note. | with the fix |
| Advisory | A GitHub Security Advisory is published when the fixed version is on npm, with a CVE identifier requested through GitHub, a CVE Numbering Authority, the affected and fixed versions, the severity, a workaround where one exists, and the credit. | the day of the release |
| Post-release | The root cause is reviewed. When it is a class of defect, a rule, a test or a named limit is added so that the class cannot return unnoticed, and the next release note says which. | the next minor |

**Disclosure date.** A vulnerability is disclosed when its fix is released, and no later than **90 days** after the report. If no fix is ready by then, the advisory is published with the mitigations known, unless the reporter agrees to a later date. If the vulnerability is being exploited, or is already public, the advisory may be published earlier, with mitigations.

**Credit.** The reporter is credited in the advisory, with GitHub's credit types, and in the release note — under the name or handle they choose, or not at all if they prefer.

We ask that you:

1. Report vulnerabilities privately (see [Reporting a Vulnerability](#reporting-a-vulnerability))
2. Allow the time above for a fix before public disclosure
3. Do not exploit the vulnerability beyond what is necessary to demonstrate it, and do not access, modify or keep data that is not yours
