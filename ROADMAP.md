# Roadmap

pkinative grows in milestones, each one a git tag with its own release note. Versions below 1.0.0 are never published to npm: each is a git tag whose GitHub release carries an attested tarball, and 1.0.0 is the first npm release. Every milestone ships under the same gate, the same limits discipline and the same conformance corpora.

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

- [x] Certificate signing requests and certificates built from typed descriptions, signed by a Web Crypto key
- [x] Signature verification of a certificate against its issuer through Web Crypto (RSA PKCS#1 v1.5 and PSS, ECDSA P-256/384/521, Ed25519 and Ed448)
- [x] Continuous fuzzing (ClusterFuzzLite with Jazzer.js), non-blocking by construction — it is not one of the contexts the ruleset requires

`generateKey` and `exportKey` stay refused in `src/` here and in every later version, so the key never belongs to pkinative: a builder takes a SubjectPublicKeyInfo in DER and a private key only as an opaque handle it passes straight to `subtle.sign`. Neither `crypto` nor `build` imports `x509`, and `verify-bundle` weighs both claims on the built artefact rather than asserting them in a diagram.

## 0.4.x — M2b: Interoperability, clauses and a performance trend

- [ ] A foreign-tool interop matrix, both directions, blocking on Linux, Windows and macOS: OpenSSL, GnuTLS, `certutil`, `keytool`, macOS `security` and Python `cryptography` read what pkinative writes, and read what pkinative read
- [ ] Conformance level L5 — RFC 5280 §4 checked clause by clause, by an engine-independent parser, with every clause exercised by a corpus certificate and every verdict tied to a diagnostic or a reviewed waiver
- [ ] An output-byte baseline for created artefacts, each entry recording the release its hash came from
- [x] `bench.yml` — a weekly performance trend, explicitly non-blocking and never a required check, held to `bench/RESULTS.md` by `bench-parity`

The write direction of the matrix is impossible before 0.3 creates anything, and the clause checker is what turns a conformance gate from a regression detector into an authority. Both must exist **before** path validation, not after: 0.5 is where a wrong answer becomes expensive.

## 0.5.x — M3: Path validation and revocation

- [ ] RFC 5280 §6 path building and validation: name constraints, policies, key usage, path length
- [ ] CRL parsing and verification; OCSP request building, response parsing and verification (RFC 6960)
- [ ] x509-limbo scored on SUCCESS / FAILURE, NIST PKITS

## 0.7.x — M4: CMS and timestamps

- [ ] CMS SignedData (RFC 5652) parsing, building and verification; RFC 3161 timestamp tokens

Consuming pkinative from pdfnative's PAdES and LTV stack is pdfnative's milestone, not this one. A cross-repository commitment must never gate a release here.

## 0.8.x — M5: Keys, and the vocabulary frozen

- [ ] PKCS#8 reading, and PKCS#12 reading **under PBES2 only** — PBKDF2 and AES through Web Crypto. RFC 7292 Appendix B, RC2 and 3DES are refused by a named code that names `openssl pkcs12 -legacy` as the conversion: that KDF is iterated SHA-1 over a password, and implementing it would be the secret-dependent cryptography this library exists without. The refusal is a policy, stated in SECURITY.md, not a gap
- [ ] One-call verification reports that never throw for input problems
- [ ] **The error-code vocabulary frozen under semantic versioning.** PKCS#12 is the last subsystem that introduces codes, so this is the first version at which the vocabulary is complete — and freezing a whole band before the release that depends on it is what gives 0.9 something to prove

## 0.9.x — M5b: The freeze, rehearsed

- [ ] Zero new exports, zero new codes, zero new engine behaviour. The band exists to prove the freeze holds: propose here every rename you will ever want, because after 0.8 a rename is semver-major
- [ ] A coverage pass over whatever the year left unproven, and an ADR for anything that will not ship
- [ ] Clause completeness promoted to blocking in `conformance.yml`

## 1.0.0 — M6: The freeze and the first publication

- [ ] **The three-part compatibility promise**, written in SECURITY.md and machine-readable in `ecosystem.json → contracts`: the export surface, the error vocabulary, and the *decision surface* — which certificate pkinative refuses, with which code, plus `encode(decode(der)) === der`. Each held by a rule, not by a sentence
- [ ] First npm publication with provenance, through Trusted Publishing
- [ ] Adds no engine behaviour over 0.9: 1.0.0 is the freeze itself

There is **no external security audit** at 1.0, and the line that once promised one has been removed rather than left to be broken. Neither pdfnative nor zipnative shipped 1.0 with one; what stands in its place is named in SECURITY.md — the three-agent adversarial release review, the L0–L5 conformance gate over third-party corpora, 100 % branch coverage, the seeded adversarial suites, and CodeQL, Scorecard and dependency review on every change. If you need an audit for procurement, open an issue: it will be scoped, and it will be said here when it happens.

`pkinative-cli` and `pkinative-mcp` come **after** 1.0.0, as separate repositories and separate npm packages pinning `pkinative ^1.0.0` — the order both elders used. The machine-readable contracts they will consume are named in the 1.0.0 release note.

## How to Influence the Roadmap

- **Open an issue** describing the use case and the standard that defines it.
- **Report a conformance case** with the conformance template — the corpus grows from real certificates.
- **Sponsor** development through [GitHub Sponsors](https://github.com/sponsors/Nizoka).
- **Contribute** — see [CONTRIBUTING.md](CONTRIBUTING.md).
