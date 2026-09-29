# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public issue for security vulnerabilities.**

To report a security vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/Nizoka/pkinative/security/advisories/new).

We will acknowledge receipt within 48 hours and target a fix within 7 days for Critical severity and within 14 days for High severity.

What counts as a vulnerability here: an input that makes pkinative accept an encoding the standard forbids in a way that could change a security decision (a parser differential), an input that exhausts memory or CPU despite the configured limits, an exception other than a `PkiError` subclass escaping on malformed input, or any secret-dependent behaviour.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest tag and its release tarball) | ✅ (pre-1.0: fixes land in the next tag) |
| npm `0.0.1` (name reservation, when published) | ❌ contains no code |

## Compatibility promise

From 1.0.0, pkinative promises three things for the whole major line. Each is recorded in a committed snapshot, held by a rule of `npm run verify:docs` that fails the build, and decided in an architecture decision record; the promise is made for the default options (DER, `strict: false`, the default limits).

| Leg | What is promised | Snapshot | Held by | Decided in |
|---|---|---|---|---|
| The export surface | Every export of the package keeps its name, its kind and a compatible signature, and every `PkiReasonCode` stays. | `docs/assets/api.frozen.json` | `api-surface-frozen` | [ADR 0012](docs/adr/0012-frozen-error-vocabulary.md), [ADR 0013](docs/adr/0013-renames-before-the-freeze.md) |
| The error vocabulary | Every `PkiErrorCode` keeps its name and its `PkiError` class — frozen since 0.8.0. | `docs/data/errors.frozen.json` | `error-codes-frozen` | [ADR 0012](docs/adr/0012-frozen-error-vocabulary.md) |
| The decision surface | A corpus certificate pkinative refuses stays refused, with the same code; a new refusal is a recorded fix; and every corpus certificate decoded with `decodeAsn1` and re-encoded with `encodeAsn1Node` comes back byte for byte. | `docs/data/refusals.frozen.json` | `refusal-baseline-frozen`, and conformance L1 and L2 | [ADR 0014](docs/adr/0014-the-decision-surface-contract.md) |

The corpus is x509-limbo, pinned by commit and SHA-256: the snapshot lists every certificate of it that `parseCertificate` refuses, by the SHA-256 of its DER, with the code it is refused with. Conformance L1 ([docs/guides/conformance.md](docs/guides/conformance.md#the-levels)) holds the engine to that list on every run, and L2 re-encodes every certificate of the corpus, the refused ones included.

### What a 1.x release may change

| Change | Semver |
|---|---|
| An export removed, renamed or given an incompatible signature; a reason code removed or renamed | major |
| An error code removed, renamed or moved to another class | major |
| A refused corpus certificate lifted (it now parses), or refused with another code | major |
| A corpus certificate that parsed now refused — only as a security or conformance fix, listed by SHA-256 under `### Decision surface` in the release note | minor |
| A path, revocation or CMS verdict, or the reasons returned with it, changed — never silently: the reviewed conformance baselines of L6, L7 and L8 move in the same change, and the release note says so | minor |
| A new export, optional parameter or member, error code, reason code or diagnostic code | minor |
| A decoded certificate that no longer re-encodes byte for byte | never — a defect, fixed in a patch |

Security fixes stay possible within 1.x because every one found so far made pkinative refuse more: 0.9.0 closed two paths it accepted and RFC 5280 rejects. A fix that would change the code of an existing refusal waits for 2.0, and so does a refusal later found to be wrong: a caller can rely on a refused certificate staying refused.

### What is not promised

- **Diagnostics.** A diagnostic code is never renamed or removed, but its severity and wording may change in a minor — so under `strict: true`, which turns diagnostics into `PKI_STRICT_DIAGNOSTIC`, a certificate may become refused in a minor.
- **Error message wording.** The code and the class are the contract; the sentence after `pkinative: ` is for a human.
- **Limit default values.** A default may be lowered in a minor when an attack makes it dangerous; that is a new refusal like any other, recorded the same way. Raising a limit is the caller's act, for trusted input. The limit names are frozen.
- **Path, revocation and CMS verdicts**, beyond what the table above says: they are recorded, not frozen.
- **Conformance scores, bundle sizes and performance.** They are measurements, and they move when a corpus is re-pinned or a budget is reviewed.

### Machine-readable form

`docs/assets/ecosystem.json` → `contracts.compatibility` names each leg with its snapshot, its rules, its conformance levels and its records, and lists what is not promised. The `contracts-shape` rule holds that block to the files, the rules, the records and this section, both ways: a snapshot or a frozen-surface rule that no leg names fails too. The snapshots move only through their generators — `scripts/build-api-frozen.ts`, `scripts/build-errors-frozen.ts` and `scripts/build-refusals-frozen.ts` — which `scripts/release-prepare.ts` runs at every release from 1.0.0, so that what a 1.x release adds becomes part of the promise.

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

- Signature verification (0.3) and certificate creation go through Web Crypto (`crypto.subtle`), whose implementations run in constant time in the host. Keys are imported from `spki` — the public half — with `extractable: false` and the single usage `['verify']`.
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

Every loop over untrusted input consults one of these named bounds (`PkiLimits`). Each is configurable per call through `options.limits`; exceeding one throws `PkiLimitError` with code `PKI_LIMIT_EXCEEDED` and the `limit`, `configured` and `observed` fields. Raise a limit only for trusted input. The table is held to `src/core/pki-limits.ts` and `docs/data/limits.json` by `npm run verify:docs`. The names are frozen at 1.0; the defaults are not, and may be lowered in a minor release (see [Compatibility promise](#compatibility-promise)).

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
| `maxPathsExplored` | 1 000 | CWE-400 | The candidate paths explored while building one. Path building is exponential in the candidate set, not linear in the chain length: cross-signed hierarchies give a verifier several plausible issuers at each step, and this is THE denial-of-service bound of RFC 5280 section 6 rather than `maxChainLength`. |
| `maxSignerInfos` | 64 | CWE-400 | The signers of one SignedData. Each costs a signature verification and, when a trust store is supplied, a path search — so a message carrying thousands of signers is a way to make a verifier do thousands of both. A PDF signature has one; a detached S/MIME message rarely more than two. |
| `maxAttributes` | 256 | CWE-400 | The attributes in one attribute set — a CMS signer's signed or unsigned set, and since 0.8 a PKCS#8 key's or a PKCS#12 bag's, which share the X.501 `Attributes` syntax. Real writers use fewer than ten; the bound stops a file from making the per-attribute rules walk an arbitrarily long list. |
| `maxCmsCertificatesAndCrls` | 1 024 | CWE-400 | The certificates and revocation entries one SignedData carries. The bag is a claim by whoever assembled the message, and the signer search walks it; 1 024 leaves room for a `.p7b` bundle of a whole trust store. |
| `maxKdfIterations` | 10 000 000 | CWE-400 | The PBKDF2 iteration count honoured. The file declares the count and the host runs it, so a PKCS#12 declaring 2³¹ iterations would otherwise freeze the reader inside Web Crypto, where no JavaScript bound can reach. Ten million is about ten seconds of SHA-256 on current hardware — above anything a real writer uses, below a hang. |
| `maxPkcs12Bags` | 4 096 | CWE-400 | The SafeBags read from one PKCS#12, across every SafeContents. Each certificate bag is parsed and each key bag may cost a decryption; 4 096 holds a whole trust store exported as one file. |

### Verification of the Parser

- Every truncation point and every single-octet mutation of the test certificates ends in a certificate or a `PkiError` (`tests/fuzzing/`); seeded suites cover length encodings, nesting, tags, integers, times, strings, BER forms and PEM.
- The conformance gate ([docs/guides/conformance.md](docs/guides/conformance.md)) runs the built package over 30 361 unique x509-limbo certificates and 1 530 Wycheproof ECDSA vectors, pinned by commit and SHA-256, and holds every answer to OpenSSL.
- A certificate is refused only where every x509-limbo case using it expects failure; any other refusal, and any exception that is not a `PkiError`, fails the gate.
- Coverage-guided fuzzing runs through ClusterFuzzLite (`.clusterfuzzlite/`, `.github/workflows/fuzz.yml`) over three targets — the X.690 decoder in both rule sets, the RFC 5280 parser with and without extension decoding, and PEM together with the OID codec, which also asserts that `encodeOid(decodeOid(x))` returns the input byte for byte. It is **not** a required status check: the seeded suites are the blocking half, and this one explores. Jazzer.js is installed inside the build image and never in `package.json`, so the zero-dependency promise is unaffected. The same three target files are executed against `src/` by `tests/fuzzing/targets.test.ts` on every gate run, including an assertion that a target still rethrows what is not a `PkiError` — a target that swallowed everything would search for a week and report nothing.

> The ClusterFuzzLite workflow has **not yet executed**: this repository has no pushed history at the time of writing. What is proven locally is that the targets load, run and propagate correctly; what is unproven is the container wiring. The first scheduled run is the evidence, and this note stands until then.

### Code Safety

- No `eval()`, `Function()`, dynamic `import()` or dynamic code execution — enforced from the syntax tree
- No filesystem, network or process access in the engine
- Tree-shakeable (`sideEffects: false`) — no module-level side effects
- Hardened workflows — every action pinned to a commit SHA, `persist-credentials: false` on every checkout, `step-security/harden-runner` on every job, `npm ci --ignore-scripts` (also `ignore-scripts=true` in `.npmrc`), CodeQL, OpenSSF Scorecard, Dependency Review and a weekly `npm audit`
- Release path — see [Release integrity](#release-integrity)

## In place of an external audit

There is no external security audit at 1.0 ([ADR 0010](docs/adr/0010-no-external-security-audit-at-1-0.md)). What stands in its place runs on every release or every change, where an audit is a snapshot of one moment — and none of it is independent of the project the way an audit is:

- **An adversarial release audit** before every release: two independent auditors (claims against code; docs and machine surfaces), an adversarial verifier that re-derives every finding, a docs-autonomy pass and a GO/NO-GO ledger — [CONTRIBUTING.md §Release](CONTRIBUTING.md#release), step 5, and `.claude/skills/release-audit/`. It is run by agents under the maintainer's direction.
- **The conformance gate, L0 to L8**, over third-party corpora pinned by commit and SHA-256 — x509-limbo, Wycheproof and NIST PKITS — plus an interoperability matrix against implementations written by other people ([docs/guides/conformance.md](docs/guides/conformance.md)). It runs on every change and in the publish gate of every release. The corpora judge conformance, not the absence of vulnerabilities.
- **100 % coverage on all four axes** (`vitest.config.ts`), every unreachable branch a counted, justified exception held by `coverage-ignore-budget`; and **mutation testing** (`npm run mutate`), run by hand on the files a change touches when it changes a security decision — not a gate step, because it takes minutes per file; every survivor is killed by a test or argued equivalent in `scripts/data/mutation-equivalents.json`.
- **Seeded adversarial suites** and coverage-guided fuzzing — see [Verification of the Parser](#verification-of-the-parser).
- **CodeQL** on every push and pull request to `main` that touches code, and weekly; **OpenSSF Scorecard** on every push to `main`, and weekly; **Dependency Review** on every pull request.

If you need an audit for procurement, open an issue: it will be scoped, and ROADMAP.md will say when it happens.

## Release integrity

**Every release is built from its tag by a workflow, never on a maintainer's machine.** The tag rules ([.github/rulesets/tags.json](.github/rulesets/tags.json)) forbid deleting, moving or updating a `v*` tag, with no bypass — the repository owner included — so a version names one commit forever. Both release workflows fail when the tag they run on and the version in `package.json` disagree.

**Below 1.0.0** a version is a git tag with a GitHub release, never an npm release. When the maintainer publishes the GitHub release, `.github/workflows/release-assets.yml` checks out the tag, installs with `npm ci --ignore-scripts`, fetches the pinned corpora and runs the full publish gate (`npx tsx scripts/gate.ts --publish --require-all`, conformance included). It then writes a CycloneDX SBOM of the runtime dependencies (`npm sbom --omit dev`), packs the tarball and proves it installs and loads as ESM and CJS (`scripts/smoke-install.ts`), attests both files with Sigstore build provenance (`actions/attest-build-provenance`), and attaches `pkinative-X.Y.Z.tgz` and `pkinative-X.Y.Z.cdx.json` to the release.

**From 1.0.0** `.github/workflows/publish.yml` publishes to npm. It refuses any version below 1.0.0; waits for the protected `npm-publish` environment, whose approval gates the OIDC token; publishes through npm Trusted Publishing (OIDC, no long-lived token) with an exactly pinned npm client, after the same publish gate — which runs the install smoke test on its own build; and runs `npm publish --provenance`, so the registry carries a signed provenance statement tying the tarball to this repository, the workflow and the commit. A second job builds the same commit again, writes the SBOM, packs, attests both files with Sigstore build provenance and attaches them to the GitHub release. That attested tarball is a second build of the commit, not the byte stream npm received: the npm tarball is covered by npm's provenance, the release assets by the GitHub attestation.

To verify:

```sh
# A release tarball and its SBOM, downloaded from the GitHub release
gh attestation verify pkinative-X.Y.Z.tgz --repo Nizoka/pkinative
gh attestation verify pkinative-X.Y.Z.cdx.json --repo Nizoka/pkinative

# From 1.0.0: the registry signatures and provenance of what npm installed
npm audit signatures
```

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We ask that you:

1. Report vulnerabilities privately (see above)
2. Allow reasonable time for a fix before public disclosure
3. Do not exploit the vulnerability beyond what is necessary to demonstrate it
