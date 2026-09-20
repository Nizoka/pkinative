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
| `deriveKey` | nowhere | 0.8.0 |
| `unwrapKey` | nowhere | 0.8.0 |
| `decrypt` | nowhere | 0.8.0 |

**"Nowhere / never" is a promise, not a backlog.** pkinative creates, exports, wraps and derives no raw key material in any version. `exportKey` being refused is why the certificate builder takes a SubjectPublicKeyInfo in DER rather than a `CryptoKey`: one line in the caller's code, in exchange for a guarantee a test can check. `deriveBits` stays refused even when 0.8 opens `deriveKey`, because the first hands back an `ArrayBuffer` nothing can zeroise and the second returns a non-extractable handle.

`globalThis.crypto` has one door too: only `src/crypto/webcrypto.ts` and `src/hash/fingerprint.ts` may reach it, so everything pkinative asks of a host is readable in two files.

- Signature verification (0.3) and certificate creation go through Web Crypto (`crypto.subtle`), whose implementations run in constant time in the host. Keys are imported from `spki` — the public half — with `extractable: false` and the single usage `['verify']`.
- Hashing (SHA-1, SHA-256, SHA-384, SHA-512) is implemented in TypeScript for synchronous fingerprints of **public** data only; these functions are not exported as general-purpose hashes.
- The DER ↔ P1363 ECDSA signature converter (`src/crypto/crypto-signature.ts`) is TypeScript, and legal: a signature is public, there is no key in it, and it performs no arithmetic beyond copying bytes.
- This is a deliberate departure from pdfnative's pure-TypeScript RSA and ECDSA, whose `BigInt` arithmetic is not constant-time; that code is not, and will not be, ported.

### Parser Safety

- DER is strict by default (X.690 §10–11); BER is an explicit option.
- The decoder is iterative: nesting depth is a limit, never a call-stack overflow.
- Every declared length is checked against the remaining input and the limits before anything is allocated.
- Structural failures throw a `PkiError` subclass with a stable code; conformance concerns are diagnostics; the two never mix.

### Resource Limits

Every loop over untrusted input consults one of these named bounds (`PkiLimits`). Each is configurable per call through `options.limits`; exceeding one throws `PkiLimitError` with code `PKI_LIMIT_EXCEEDED` and the `limit`, `configured` and `observed` fields. Raise a limit only for trusted input. The table is held to `src/core/pki-limits.ts` and `docs/data/limits.json` by `npm run verify:docs`.

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

### Verification of the Parser

- Every truncation point and every single-octet mutation of the test certificates ends in a certificate or a `PkiError` (`tests/fuzzing/`); seeded suites cover length encodings, nesting, tags, integers, times, strings, BER forms and PEM.
- The conformance gate ([docs/guides/conformance.md](docs/guides/conformance.md)) runs the built package over 30 361 unique x509-limbo certificates and 1 530 Wycheproof ECDSA vectors, pinned by commit and SHA-256, and holds every answer to OpenSSL.
- A certificate is refused only where every x509-limbo case using it expects failure; any other refusal, and any exception that is not a `PkiError`, fails the gate.

### Code Safety

- No `eval()`, `Function()`, dynamic `import()` or dynamic code execution — enforced from the syntax tree
- No filesystem, network or process access in the engine
- Tree-shakeable (`sideEffects: false`) — no module-level side effects
- Hardened workflows — every action pinned to a commit SHA, `persist-credentials: false` on every checkout, `step-security/harden-runner` on every job, `npm ci --ignore-scripts` (also `ignore-scripts=true` in `.npmrc`), CodeQL, OpenSSF Scorecard, Dependency Review and a weekly `npm audit`
- Release path — `.github/workflows/publish.yml` publishes only from the protected `npm-publish` environment with npm Trusted Publishing (OIDC, no long-lived token), an exactly pinned npm client, `npm publish --provenance` and an attested CycloneDX SBOM; it refuses any pre-1.0 version

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We ask that you:

1. Report vulnerabilities privately (see above)
2. Allow reasonable time for a fix before public disclosure
3. Do not exploit the vulnerability beyond what is necessary to demonstrate it
