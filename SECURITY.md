# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public issue for security vulnerabilities.**

To report a security vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/Nizoka/pkinative/security/advisories/new).

We will acknowledge receipt within 48 hours and target a fix within 7 days for Critical severity and within 14 days for High severity.

What counts as a vulnerability here: an input that makes pkinative accept an encoding the standard forbids in a way that could change a security decision (a parser differential), an input that exhausts memory or CPU despite the configured limits, an exception other than a `PkiError` subclass escaping on malformed input, or any secret-dependent behaviour.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest tag) | ✅ (pre-1.0: fixes land in the next tag) |
| npm `0.0.1` | ❌ name reservation, contains no code |

## Security Model

pkinative is a pure TypeScript library with **zero runtime dependencies**. Every certificate, PEM file and DER blob it reads is treated as attacker-controlled.

### Cryptographic Implementation Scope

pkinative **never implements secret-dependent cryptography in TypeScript**. There is no signing, no key generation, no RSA modular exponentiation and no elliptic-curve scalar multiplication in `src/`, and the architecture test fails the build if a module reaches for one.

- Signature verification and certificate creation (from 0.3) go through Web Crypto (`crypto.subtle`), whose implementations run in constant time in the host.
- Hashing (SHA-1, SHA-256, SHA-384, SHA-512) is implemented in TypeScript for synchronous fingerprints of **public** data only; these functions are not exported as general-purpose hashes.
- This is a deliberate departure from pdfnative's pure-TypeScript RSA and ECDSA, whose `BigInt` arithmetic is not constant-time; that code is not, and will not be, ported.

### Parser Safety

- DER is strict by default (X.690 §10–11); BER is an explicit option.
- The decoder is iterative: nesting depth is a limit, never a call-stack overflow.
- Every declared length is checked against the remaining input and the limits before anything is allocated.
- Structural failures throw a `PkiError` subclass with a stable code; conformance concerns are diagnostics; the two never mix.

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
