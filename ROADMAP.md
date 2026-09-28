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

- [ ] A foreign-tool interop matrix, both directions, blocking on Linux, Windows and macOS — **partly landed**: `openssl` and Windows CryptoAPI run today and are blocking on all three; GnuTLS `certtool`, Windows `certutil`, `keytool`, macOS `security` and Python `cryptography` are declared in `scripts/lib/interop.ts` with the reason each is pending, and `--require-all` goes on in the commit that lands the last one
- [x] Conformance level L5 — RFC 5280 §4 checked clause by clause, by an engine-independent parser, with every clause exercised by a corpus certificate and every verdict tied to a diagnostic or a reviewed waiver (19 clauses; §6 doubles the table in 0.5, and the completeness assertion becomes blocking in 0.9)
- [x] An output-byte baseline for created artefacts, each entry recording the release its hash came from (`scripts/verify-samples.ts`, `scripts/data/output-bytes.json`, gate step `verify:samples`)
- [x] `bench.yml` — a weekly performance trend, explicitly non-blocking and never a required check, held to `bench/RESULTS.md` by `bench-parity`

- [x] An `interop_report.md` issue template — the write direction has a different burden of proof from a conformance report, because when another tool refuses what pkinative wrote the bytes are ours

The write direction of the matrix is impossible before 0.3 creates anything, and the clause checker is what turns a conformance gate from a regression detector into an authority. Both must exist **before** path validation, not after: 0.5 is where a wrong answer becomes expensive.

## 0.5.x — M3: Path validation and revocation

<!-- Landed so far in this band: PkiReasonCode (the third vocabulary), RFC 5280
     §6 in full including name constraints and the policy tree, path building,
     CRLs, OCSP, RFC 6125 server-name matching, and the x509-limbo score as
     conformance level L6 — which is what found the last ten name-constraint
     defects, the unjudged trust anchor and the SHA-1 signatures that were being
     verified as evidence. -->


- [x] `PkiReasonCode` — the third vocabulary, landed **before** the code that needs it: primitives return and throw, compositions report, and exactly one layer converts
- [x] RFC 5280 §6 validity window, issuer chaining, signature verdicts, `basicConstraints`, `keyUsage`, path length, loop detection and the trust anchor — synchronous, pure, never throwing for a validation issue
- [x] RFC 5280 §6 name constraints — per-form permitted and excluded subtrees, intersecting down the path, over dNSName, rfc822Name, URI, iPAddress and directoryName, on both the subject and the SAN
- [x] RFC 5280 §6 the policy tree — `valid_policy_tree` as flat levels with children by index and nothing ever removed, the three counters, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy`, and the §6.1.5 (g) success condition
- [x] Path *building*: a depth-first search with backtracking over candidate issuers, bounded by `maxPathsExplored` — which is THE denial-of-service bound of section 6, because building is exponential in the candidate set and only linear in the chain length
- [x] CRL parsing — the revocation list is walked with a lazy TLV cursor rather than decoded into nodes, so a list of millions costs constant memory
- [x] CRL signature verification and the revocation decision — synchronous, taking a precomputed signature verdict, and keeping "unknown" apart from "not revoked"
- [x] OCSP request building, response parsing and signature verification (RFC 6960) — good, revoked and unknown stay three states
- [x] An OCSP status decision returning PkiReason, reporting all four of RFC 6960 section 3.2 client responsibilities and keeping a substituted answer apart from an unknown one
- [x] RFC 6125 server identity matching — a separate question from §6, which has no notion of the name you asked for, and the one whose absence turns a valid certificate for somebody else into an accepted one
- [x] x509-limbo scored on SUCCESS / FAILURE as conformance level L6 — every case built, name-matched and revocation-checked the way a caller would, with a reviewed deviation baseline in which every disagreement carries a written reason, a subset pinned on its `PkiReasonCode` rather than on the boolean, and two canaries against a scorer that stopped deciding anything
- [x] Extended key usage as its own exported check, beside `checkServerName` — not a §6 input (RFC 5280 §4.2.1.12 leaves the purpose decision to the application), including the rule no sentence of the RFC states and every Web PKI validator applies: a CA own extKeyUsage restricts what it may issue for
- [ ] `createCertificate` able to emit `subjectKeyIdentifier` and `authorityKeyIdentifier`, so their absence can be diagnosed without everything this library builds tripping its own reader
- [ ] NIST PKITS

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
