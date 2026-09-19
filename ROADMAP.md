# Roadmap

pkinative grows in milestones, each one a git tag with its own release note. Versions below 1.0.0 are never published to npm; the name is reserved by an empty 0.0.1, and 1.0.0 is the first npm release. Every milestone ships under the same gate, the same limits discipline and the same conformance corpora.

## 0.1.x — M1: Read-only foundation *(0.1.0)*

- [x] **Errors, limits and diagnostics** — the `PkiError` family with stable codes, CWE-tagged `PkiLimits`, the single diagnostics sink with `onDiagnostic` and `strict`
- [x] **ASN.1** — iterative X.690 decoder, strict DER by default and BER on request; value readers (BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, every string type, UTCTime and GeneralizedTime); hardened encoders
- [x] **PEM** — RFC 7468 strict and lax parsing, encoding
- [x] **OIDs** — dotted-string codec and a tree-shaken name registry
- [x] **Fingerprints** — SHA-1/256/384/512 over certificate DER, synchronous and Web Crypto-backed
- [x] **X.509** — complete RFC 5280 certificate parsing: every standard extension, every GeneralName form, full distinguished names with RFC 4514 rendering, every public-key algorithm's parameters
- [x] **Conformance gate** — x509-limbo and Wycheproof pinned by commit and checksum, an engine-independent DER walker, a differential against `node:crypto` and the openssl CLI
- [x] **Documentation** — guides, `llms.txt`, a generated API manifest, executable recipes, the pkinative.dev landing page

## 0.3.x — M2: Creation through Web Crypto

- [ ] Certificate signing requests and certificates built from typed descriptions, signed by a Web Crypto key
- [ ] Signature verification of a certificate against its issuer through Web Crypto (RSA PKCS#1 v1.5 and PSS, ECDSA P-256/384/521, Ed25519)
- [ ] Continuous fuzzing (ClusterFuzzLite with Jazzer.js)

## 0.5.x — M3: Path validation and revocation

- [ ] RFC 5280 §6 path building and validation: name constraints, policies, key usage, path length
- [ ] CRL parsing and verification; OCSP request building, response parsing and verification (RFC 6960)
- [ ] x509-limbo scored on SUCCESS / FAILURE, NIST PKITS

## 0.7.x — M4: CMS and timestamps

- [ ] CMS SignedData (RFC 5652) parsing, building and verification; RFC 3161 timestamp tokens
- [ ] pdfnative's PAdES and LTV signature stack migrates onto pkinative

## 0.9.x — M5: Keys and the frozen contract

- [ ] PKCS#8 and PKCS#12 reading (legacy algorithms read-only)
- [ ] The error-code vocabulary frozen under semantic versioning
- [ ] One-call verification reports that never throw for input problems

## 1.0.0 — M6: Audit and publication

- [ ] External security audit
- [ ] First npm publication with provenance
- [ ] Satellites: `pkinative-cli` and `pkinative-mcp`

## How to Influence the Roadmap

- **Open an issue** describing the use case and the standard that defines it.
- **Report a conformance case** with the conformance template — the corpus grows from real certificates.
- **Sponsor** development through [GitHub Sponsors](https://github.com/sponsors/Nizoka).
- **Contribute** — see [CONTRIBUTING.md](CONTRIBUTING.md).
