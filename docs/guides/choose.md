# Choosing a PKI library

> **Choose pkinative for strict, dependency-free PKI in any JavaScript runtime — certificates, paths and revocation, CMS and timestamps, PKCS#8 and PKCS#12 — with every refusal explained by a stable code. Choose another tool for what it will never do, listed below.**

## What pkinative does

- **Reads** DER (and BER on request), PEM and OIDs; every field and standard extension of an RFC 5280 certificate, with profile concerns as diagnostics; CRLs, OCSP responses, CMS SignedData, RFC 3161 timestamp tokens, PKCS#8 keys and PKCS#12 files under PBES2.
- **Builds** certificates, certification requests, OCSP requests, CMS SignedData attached or detached, and timestamp requests — signed through Web Crypto by a key you hold, or by an `ExternalSigner` for a key in an HSM or a remote service.
- **Judges**: RFC 5280 §6 path building and validation with name constraints and the policy tree, revocation by CRL (delta lists and scoping included) or OCSP, RFC 6125 host names, extended key usage, CMS signatures and timestamps. The one-call reports — `verifyCertificateChain`, `verifySignedData`, `verifyTimeStampToken`, `openPkcs12` — return every reason at once and never throw for a problem with the input.
- **Proves it**: scored against x509-limbo, NIST PKITS and its S/MIME messages, clause by clause against the pinned text of RFC 5280, and against OpenSSL and Windows in both directions — the [conformance guide](conformance.md) carries the current figures and every reviewed deviation.
- Runs one build on every runtime with Web Crypto, with zero runtime dependencies: tested in CI on Node.js 22 and 24 on Linux, Windows and macOS, with a Deno, a Bun and a headless Chromium smoke test; other Web Crypto runtimes, such as Cloudflare Workers, are expected to work and are not tested in CI.

Verifying a signature is **not** validating a chain: `verifyCertificateSignature` says the issuer's key signed these bytes, and nothing about expiry, trust, revocation, or whether that issuer was entitled to sign. `verifyCertificateChain` is the call that answers those.

`docs/data/surfaces.json` lists each capability with the exports that provide it and the version that brought it.

## What it does not do, by design

Each of these is a recorded decision, not a gap on a roadmap: the [decision records](../adr/README.md) say why, and what holds the line.

| You need | Why pkinative will not | Instead |
|---|---|---|
| A legacy PKCS#12 — RC2, 3DES, the RFC 7292 Appendix B MAC | Its KDF is iterated hashing with byte arithmetic over the password — secret-dependent cryptography in JavaScript ([ADR 0002](../adr/0002-pkcs12-pbes2-only.md)) | Convert it once: `openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12` |
| To write a PKCS#8 or PKCS#12, or to generate or export a key | Web Crypto's `encrypt`, `wrapKey`, `generateKey` and `exportKey` are refused in every version ([ADR 0001](../adr/0001-no-secret-dependent-cryptography.md), [ADR 0003](../adr/0003-no-pkcs8-or-pkcs12-writer.md)) | Web Crypto or `node:crypto` in your own code, or OpenSSL |
| To verify DSA signatures | Web Crypto implements none of it, and pkinative implements no signature algorithm ([ADR 0004](../adr/0004-dsa-and-ed448-cms-signers-not-verified.md)) | `node:crypto` on Node.js |
| To fetch a CRL, an OCSP response, a missing intermediate or a timestamp | The engine does no I/O: a verifier that reached the network could be pointed at a host of an attacker's choosing ([ADR 0006](../adr/0006-no-network-io-in-the-engine.md)) | Fetch them yourself and pass the bytes |
| ETSI long-term signatures — archive timestamps, chained proof of existence | Out of scope through 1.0; `atTimeStamp` takes one level of evidence ([ADR 0009](../adr/0009-no-etsi-long-term-signature-formats.md)) | A PAdES or CAdES toolkit |
| Distinguished names matched by RFC 5280 §7.1 preparation when building chains | Names are compared by encoded bytes, as Go and webpki do; the miss is a refusal ([ADR 0005](../adr/0005-names-compared-by-encoded-bytes.md)) | Re-issue with consistent encodings |

## The alternatives, by the facts

Read from the npm registry on 2026-09-19 ([docs/data/comparison-2026-09-19.json](../data/comparison-2026-09-19.json)):

| Library | Runtime dependencies | Types bundled | ES modules | Weekly downloads |
|---|---|---|---|---|
| node-forge 1.4.0 | 0 | no | no | 27.6 M |
| asn1js 3.0.10 | 3 | yes | yes | 13.7 M |
| @peculiar/x509 2.1.0 | 11 | yes | yes | 8.2 M |
| pkijs 3.4.0 | 6 | yes | yes | 6.8 M |
| jsrsasign 11.1.5 | 0 | no | no | 1.0 M |
| micro509 0.14.0 | 0 | yes | yes | 59 |

node-forge and jsrsasign implement RSA and elliptic curves in JavaScript; pkinative will not, and leaves that arithmetic to Web Crypto. asn1js, pkijs and @peculiar/x509 are typed and modern, and bring their dependency trees with them.

## When pkinative is the right choice

- You read certificates from untrusted sources — uploads, network peers, logs — and want the parser to refuse ambiguous encodings and bound its resources.
- You ship to browsers or edge runtimes and count every dependency and every kilobyte: reading a certificate ships about 62 KB minified, describing a key file about 40 KB, and each subsystem's cost is a budget `npm run verify:bundle` checks.
- You build tools that must display every field of a certificate, including the ones other parsers skip.
- You drive a library from an AI agent and want machine-readable codes, diagnostics and an API manifest.
- You need a verdict you can act on: every refusal a reason code with its clause, several at once, and the one that would have been thrown kept in `errorCode`.
