# Roadmap

pkinative grows in milestones, each one a git tag with its own release note. Versions below 1.0.0 are never published: each is a git tag — a source snapshot with its release note in `release-notes/` — with no GitHub release and nothing on npm, and 1.0.0 is the first release, on npm and on GitHub. Every milestone ships under the same gate, the same limits discipline and the same conformance corpora.

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

- [ ] A foreign-tool interop matrix — foreign tools read what pkinative writes, and five of them write what it reads — blocking on Linux, Windows and macOS — **ten tools run**: `openssl` on all three platforms; Windows CryptoAPI and .NET (`dotnet`) on Windows; GnuTLS `certtool`, Go `crypto/x509`, pyca `cryptography`, `zlint` and `pkilint` on Linux, where the conformance workflow installs them pinned; the JDK's `keytool` and `gpgsm` on Linux too, required there since the workflow installs gpgsm and the image ships a JDK. They read certificates, CSRs, CMS SignedData, OCSP and timestamp requests in every signature family the API writes, both linters lint every certificate created, and pkinative verifies the CMS, timestamps, OCSP responses and CRLs that OpenSSL, GnuTLS, gpgsm, .NET and CryptoAPI write. `--require-all` is on, per platform (`REQUIRED_TOOLS`), in the workflow and the release gate. Windows `certutil`, macOS `security`, and .NET on Linux and macOS are declared in `scripts/lib/interop.ts` with the reason each is pending
- [x] Conformance level L4 confronts three implementation lineages, none sharing code with OpenSSL or each other: Windows CryptoAPI on Windows, Go `crypto/x509` (all six fields, `tbsFp256` included) and pyca `cryptography` (five) on Linux
- [x] Conformance level L5 — RFC 5280 §4 checked clause by clause, by an engine-independent parser, with every clause exercised by a corpus certificate and every verdict tied to a diagnostic or a reviewed waiver (19 clauses; §6 doubles the table in 0.5, and the completeness assertion becomes blocking in 0.9)
- [x] An output-byte baseline for created artefacts, each entry recording the release its hash came from (`scripts/verify-samples.ts`, `scripts/data/output-bytes.json`, gate step `verify:samples`)
- [x] `bench.yml` — a weekly performance trend, explicitly non-blocking and never a required check, held to `bench/RESULTS.md` by `bench-parity`

- [x] An `interop_report.md` issue template — the write direction has a different burden of proof from a conformance report, because when another tool refuses what pkinative wrote the bytes are ours

The write direction of the matrix is impossible before 0.3 creates anything, and the clause checker is what turns a conformance gate from a regression detector into an authority. Both must exist **before** path validation, not after: 0.5 is where a wrong answer becomes expensive.

## 0.5.x — M3: Path validation and revocation

<!-- Landed so far in this band: PkiReasonCode (the third vocabulary), RFC 5280
     §6 in full including name constraints and the policy tree, path building,
     CRLs with their §5.2.4 and §5.2.5 scoping, OCSP, RFC 6125 server-name
     matching, extended key usage, the one-call verify layer, and the two scored
     corpora — x509-limbo as L6, which found the last ten name-constraint
     defects, the unjudged trust anchor and the SHA-1 signatures that were being
     verified as evidence; NIST PKITS as L7, which found the whole of CRL
     scoping and the revoked CRL signer this library used to believe.

     Nothing open. What follows is the release itself: release-notes/v0.5.0.md,
     the version bump, and the publish profile. -->

**The band is complete.** All 18 items are landed; what remains is the release
preparation described in CONTRIBUTING.md §Release.


- [x] `PkiReasonCode` — the third vocabulary, landed **before** the code that needs it: primitives return and throw, compositions report, and exactly one layer converts
- [x] RFC 5280 §6 validity window, issuer chaining, signature verdicts, `basicConstraints`, `keyUsage`, path length, loop detection and the trust anchor — synchronous, pure, never throwing for a validation issue
- [x] RFC 5280 §6 name constraints — per-form permitted and excluded subtrees, intersecting down the path, over dNSName, rfc822Name, URI, iPAddress and directoryName, on both the subject and the SAN
- [x] RFC 5280 §6 the policy tree — `valid_policy_tree` as flat levels with children by index and nothing ever removed, the three counters, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy`, and the §6.1.5 (g) success condition
- [x] Path *building*: a depth-first search with backtracking over candidate issuers, bounded by `maxPathsExplored` — which is THE denial-of-service bound of section 6, because building is exponential in the candidate set and only linear in the chain length
- [x] CRL parsing — the revocation list is walked with a lazy TLV cursor rather than decoded into nodes, so a list of millions costs constant memory
- [x] CRL signature verification and the revocation decision — synchronous, taking a precomputed signature verdict, and keeping "unknown" apart from "not revoked"
- [x] OCSP request building, response parsing and signature verification (RFC 6960) — good, revoked and unknown stay three states
- [x] An OCSP status decision returning PkiReason, reporting all four of RFC 6960 section 3.2 client responsibilities and keeping a substituted answer apart from an unknown one
- [x] One call that asks every question — signatures in parallel, then the path with the purpose inside the search, the host name, and revocation by CRL or OCSP including the RFC 6960 §4.2.2.2 delegated-responder rule — in a `verify` layer that is the only place in `src/` that turns a `PkiError` into a reason
- [x] RFC 6125 server identity matching — a separate question from §6, which has no notion of the name you asked for, and the one whose absence turns a valid certificate for somebody else into an accepted one
- [x] x509-limbo scored on SUCCESS / FAILURE as conformance level L6 — every case built, name-matched and revocation-checked the way a caller would, with a reviewed deviation baseline in which every disagreement carries a written reason, a subset pinned on its `PkiReasonCode` rather than on the boolean, and two canaries against a scorer that stopped deciding anything
- [x] Extended key usage as its own exported check, beside `checkServerName` — not a §6 input (RFC 5280 §4.2.1.12 leaves the purpose decision to the application), including the rule no sentence of the RFC states and every Web PKI validator applies: a CA own extKeyUsage restricts what it may issue for
- [x] `computeKeyIdentifier` (RFC 5280 §4.2.1.2 method 1, the same value as an OCSP `issuerKeyHash`), so the builder can write both key identifiers — and their absence is diagnosed without everything this library builds tripping its own reader
- [x] NIST PKITS as conformance level L7 — a second corpus written by different people from a different reading, pinned twice (the archive digest and a per-file list of the extraction), with expectations taken from NIST own file-name convention rather than from its PDF, and the 20 policy tests skipped because the archive states no user-initial-policy-set
- [x] RFC 5280 §5.2.5 `issuingDistributionPoint`, §6.3.3 (b) distribution-point matching and indirect CRLs reached through `cRLDistributionPoints` — what a list declares itself to be about, so that a serial's absence from it means what the CA said it means and not more; with the §5.3.3 `certificateIssuer` running state, without which a serial on an indirect list is not an identity
- [x] RFC 5280 §5.2.4 delta CRLs — a delta read together with the base whose `cRLNumber` reaches its `BaseCRLNumber` and stops short of its own, the delta answering first and the base only where it is silent, including the `removeFromCRL` reason that only a delta may carry and that withdraws what the base still records. A delta handed over alone still answers nothing: on its own it reports every certificate absent from it as unrevoked
- [x] Who may sign a CRL, in three parts — the `authorityKeyIdentifier` the list names, so a CA holding several keys can say which one revokes; and, for a key the CA delegated the job to, that its own certificate is still in date and not itself revoked. Without the last one, withdrawing a compromised CRL-signing key means nothing: whoever holds it keeps publishing *"nothing is revoked"*. Bounded by rank rather than by a depth counter — a delegated signer is judged only by a list the path itself vouches for, and a path certificate is judged by §6

## 0.7.x — M4: CMS and timestamps

<!-- Landed so far in this band: the cms layer (SignedData and TSTInfo parsing,
     the attribute checks), the CMS signature at the Web Crypto boundary, the
     SignedData builder with external signers and the unsigned-attribute
     splice, the two one-call verdicts in verify/, and the NIST PKITS S/MIME
     messages as L8. Open: the release. -->

- [x] CMS SignedData parsing (RFC 5652 §5) — every signer, the certificate and revocation bags including RFC 5940 OCSP responses, and the signed attributes exposed as the SET they were signed under (`0x31`), not the `[0]` they were transmitted under; a degenerate SignedData with no signers parses, because a `.p7b` certificate bag is one
- [x] The attributes a signature commits to, decoded where they are recognised — `contentType`, `messageDigest`, `signingTime`, ESS `signingCertificate` and `signingCertificateV2` (RFC 2634, RFC 5035), `CMSAlgorithmProtection` (RFC 6211) — and exposed only when the attribute appears exactly once with one value, so an ambiguous message is never read as the first of its two answers
- [x] The CMS signature through Web Crypto, with the digest and signature algorithms held consistent (RFC 8933, RFC 4056, RFC 5753, RFC 8419): MD5 refused, `rsaEncryption` read as PKCS#1 v1.5 over the digest the signer declared, Ed25519 only over SHA-512
- [x] SignedData creation — attached or detached, the signed attributes a verifier checks written by default (including `CMSAlgorithmProtection` and ESS `signingCertificateV2`), a `Signer` that is either a Web Crypto key or an `ExternalSigner` for an HSM or a remote service, and `addUnsignedAttribute` / `addTimeStampToken` that splice into a signer without disturbing a single signed byte
- [x] RFC 3161 — `createTimeStampRequest`, `parseTimeStampResponse`, `parseTimeStampToken`, `parseTstInfo`; a TSTInfo is DER always, whatever the enclosing message was
- [x] `verifySignedData` — every signer checked, `intact` kept apart from `valid` (what needs no trust store against what does), the chain judged at the signing instant or, with `atTimeStamp`, at the earliest instant a verified timestamp proves
- [x] `verifyTimeStampToken` — against the request, the data or the imprint; the TSA must hold a critical extKeyUsage of `timeStamping` alone (RFC 3161 §2.3), and its chain is judged at `at` and never at `genTime`, because a TSA whose key leaked can write any `genTime` it likes
- [x] The 224 NIST PKITS S/MIME messages as conformance level L8 — each verified whole by `verifySignedData` with L7's anchor, lists and instant and only the certificates it carries, linked to its test through its own `SignerIdentifier` rather than a table of names, and held to two claims: the CMS layer finds every message intact (221, the three DSA signatures reviewed), and every verdict equals the L7 verdict on its signer's path, refused for a reason that path is refused for

**Known limitations, stated rather than discovered.** `parseSignedData` decodes the whole tree, so a very large `.p7b` meets `maxNodes` before `maxCmsCertificatesAndCrls`. The RFC 4056 §3 check that RSASSA-PSS parameters in a certificate's SubjectPublicKeyInfo agree with the signer's was not made in 0.7; it is since 1.0.0, under RFC 4055 §1.2 and §3.3. When both ESS attributes are present, only `signingCertificateV2` is checked. ETSI long-term formats (B-LTA archive timestamps, proof of existence chained over several timestamps) are not implemented: `atTimeStamp` takes one level of evidence. And a chain that reaches no trust anchor also reports the top certificate's signature as `PKI_REASON_SIGNATURE_NOT_CHECKED` — deliberately, since without the issuer there is no key to check it with.

Consuming pkinative from pdfnative's PAdES and LTV stack is pdfnative's milestone, not this one. A cross-repository commitment must never gate a release here.

## 0.8.x — M5: Keys, and the vocabulary frozen

<!-- Decided at the start of the band, each against a detail of the original
     plan that turned out to be wrong:
     - The password is UTF-8 (RFC 9579, OpenSSL) or octets as given — not the
       BMPString of RFC 7292 Appendix B, which belongs to the KDF refused here.
     - Most PKCS#12 MACs cannot be verified: even OpenSSL 3 files encrypted
       with AES and PBKDF2 key their MAC with Appendix B. Only RFC 9579 PBMAC1
       (OpenSSL 3.4+, -pbmac1_pbkdf2) is checked; anything else is reported as
       unverified, and the one-call reader fails closed unless told otherwise.
     - A private key is unwrapped straight into a non-extractable CryptoKey,
       so its algorithm must be known before decryption: from the certificate
       sharing its localKeyId, or named by the caller.
     - The conversion command was run against OpenSSL 4.0.0 before it was
       written into a remedy; the one-line pipe first drafted does not work. -->

- [x] The Web Crypto door opens `deriveKey`, `unwrapKey` and `decrypt` — each returning a handle or public bytes, never key material — in its own reviewed commit
- [x] The `keys` layer, PBES2 with PBKDF2 and AES-CBC bounded by `maxKdfIterations` before the host runs an iteration, every refused scheme described by name, and the PKCS#8 structure readers, which describe a key without exposing its secret
- [x] PKCS#8 reading (`importPrivateKey`, `decryptPrivateKey`) and PKCS#12 reading (`parsePkcs12`, `verifyPkcs12Mac`, `openSafeContents`) **under PBES2 only** — PBKDF2 and AES-CBC through Web Crypto, every encrypted key unwrapped into a non-extractable `CryptoKey` without its plaintext ever existing in JavaScript (an unencrypted keyBag a writer nests inside an encrypted SafeContents is plaintext by definition, and is wiped once imported). RFC 7292 Appendix B, RC2 and 3DES are refused by a named code whose remedy is a conversion run against OpenSSL 4.0.0: that KDF is iterated hashing with byte arithmetic over a password, and implementing it would be the secret-dependent cryptography this library exists without. The refusal is a policy, stated in SECURITY.md and held to the code by `pkcs12-policy-parity`, not a gap
- [x] One-call reports that never throw for input problems — `openPkcs12` joins the three, and all four decide misuse before their first catch, so a bad argument throws its documented code and bad bytes become a reason. A seeded fuzzer drives the reports with structural mutations and tiny limits; it found a CRL entry that escaped as a throw from all three, and the opposite leak, misuse swallowed into a reason
- [x] **The error-code vocabulary frozen under semantic versioning.** `docs/data/errors.frozen.json` holds the 57 codes at 0.8.0, and `error-codes-frozen` fails on a removal, a rename or a class move; `error-parity` now also decides every throw site's code from the syntax tree, following a code passed through a typed helper to every caller. Diagnostic codes are additions-only — never renamed or removed — while a diagnostic's severity and wording may change: a diagnostic is advice

**Known limitations, stated rather than discovered.** Most PKCS#12 files' integrity cannot be checked here: only an RFC 9579 PBMAC1 MAC can, and `openPkcs12` fails closed on the rest unless told otherwise. `id-RSASSA-PSS` private keys are refused by every current runtime's Web Crypto and end in `PKI_CRYPTO_KEY_UNSUPPORTED`. A key in a PKCS#12 is matched to its certificate by `localKeyId` only. pkinative writes neither PKCS#8 nor PKCS#12, in any version: encrypting or wrapping a key is refused by `KEY_OPERATION_POLICY`.

## 0.9.x — M5b: The freeze, rehearsed

<!-- What each item was taken to mean, decided at the start of the band:
     - "Zero new exports, codes, behaviour" is made executable rather than
       promised: the export surface is snapshotted at 0.8.0 and, in the
       rehearsal phase, ANY change to it fails, as does a code whose `since` is
       0.9.x. The same rules then carry 1.0's semver semantics, having bitten a
       whole band first.
     - "Coverage pass": line coverage has been 100 % since 0.2, so what the
       year left unproven is whether a test would notice the code being wrong.
       That is mutation testing, run in-house on the security-critical modules.
     - "Clause completeness": the L5 runner already fails on an unexercised
       clause. What was never checked is the table against the RFC itself —
       that every quote is verbatim and every normative sentence of §4.1–§4.2 is
       either a clause or a reviewed exclusion. RFC 5280 is pinned as a corpus
       for it. §6 is judged by the scored corpora L6–L8, not by a second clause
       table: the 0.4 release note promised that table "at 0.5", 0.5 scored whole
       corpora instead, and an ADR says so. -->

- [x] Zero new exports, zero new codes, zero new engine behaviour — made executable rather than promised: the surface is snapshotted at 0.8.0 and `api-surface-frozen` fails on any change in the rehearsal phase, as it will on any incompatible one from 1.0. The band did not reach zero to the letter, and says where: no error or reason code was added; the rename set added one exported type, `MatchDnsNameOptions`, which the rule that every option type be exported requires; one diagnostic was added, `PKI_DIAG_CRL_EXTENSION_MALFORMED` (diagnostic codes are additions-only and outside the freeze); and the engine changed in exactly three places, all fixes — an rfc822Name constraint now reaches a subject emailAddress when there is no subjectAltName, an excluded directoryName now matches after §7.1 preparation, and a dropped CRL extension is diagnosed instead of vanishing. The first two closed paths pkinative accepted and RFC 5280 rejects; the first is why NIST's `InvalidDNandRFC822nameConstraintsTest29` was a deviation from 0.5 to 0.8
- [x] The rename set, landed once and without aliases: three limit names, one reason code, four functions, the fields and the types that broke "function name plus `Input`, `Options` or `Report`" — [ADR 0013](docs/adr/0013-renames-before-the-freeze.md), moved into the frozen snapshot with `build-api-frozen.ts --rebaseline`; no error code and no diagnostic code changed
- [x] A coverage pass over whatever the year left unproven, and an ADR for anything that will not ship — line coverage was already 100 %, so the pass is mutation testing, run in-house (`npm run mutate`): the eight security-critical modules at 100 % mutation score after 19 tests its survivors asked for, eight equivalent mutants each justified in `scripts/data/mutation-equivalents.json`. Thirteen decision records in `docs/adr/`, held to their index by `adr-index`
- [x] Clause completeness promoted to blocking in `conformance.yml` — against the RFC itself: RFC 5280 is pinned as a corpus, every quote must be verbatim, and each of the 182 requirement sentences of §4.1–§4.2 is a clause or a reviewed exclusion. Building it found four quotes the RFC does not contain, one of them invented, and 37 requirements decidable from one certificate that pkinative does not yet diagnose — recorded, for a later band

## 1.0.0 — M6: The freeze and the first publication

- [x] **The three-part compatibility promise**, written in SECURITY.md and machine-readable in `ecosystem.json → contracts`: the export surface, the error vocabulary, and the *decision surface* — which certificate pkinative refuses, with which code, plus `encode(decode(der)) === der`. Each held by a rule, not by a sentence: `api-surface-frozen`, `error-codes-frozen` and `refusal-baseline-frozen`, with `contracts-shape` holding the promise to its snapshots, rules and ADRs ([ADR 0014](docs/adr/0014-the-decision-surface-contract.md))
- [ ] First npm publication with provenance, through Trusted Publishing — the path is ready and tested (a tag-only guard before the approval prompt, the tarball checked file by file, the registry's own bytes attested); the publication is the maintainer's act
- [x] Adds no feature over 0.9: 1.0.0 is the freeze itself. What changed under `src/` is a default *removed* — `openPkcs12` no longer guesses an RSA key's scheme ([ADR 0015](docs/adr/0015-no-default-rsa-scheme.md)) — and the fixes of the pre-publication audit below, each a defect that would have been frozen otherwise
- [x] **A pre-publication audit**, nine independent auditors each checked by an adversarial verifier: 98 findings confirmed and fixed or decided before the first publication. Under `src/`: the PBKDF2 work of a whole PKCS#12 bounded by `maxPkcs12KdfIterations` ([ADR 0020](docs/adr/0020-a-kdf-budget-per-pkcs12.md)); `PKI_REASON_REVOKED` only from authenticated, applicable evidence; URI hosts read by the RFC 3986 grammar and SmtpUTF8Mailbox held to rfc822Name constraints; the commonName fallback held to dNSName constraints; name attributes written in the RFC 5280 Appendix A string type; RSASSA-PSS identifiers with explicit NULL, and id-RSASSA-PSS keys held to RFC 4055; `subjectDirectoryAttributes` decoded; `instanceof` across the ESM and CJS builds ([ADR 0021](docs/adr/0021-error-identity-across-builds.md)). Around it: the cross-validation made permanent (eight foreign implementations and two linters, both directions, `--require-all`; L4 with three lineages), a CVE-class corpus of 43 published vulnerabilities, coverage-guided fuzzing over eight targets, the release path split so the job that builds cannot publish ([ADR 0019](docs/adr/0019-release-integrity-slsa-build-l2.md)), and the decisions 1.0 could not leave open — one entry point ([ADR 0016](docs/adr/0016-one-entry-point-for-1-x.md)), the runtime and toolchain policy ([ADR 0017](docs/adr/0017-runtime-and-toolchain-support.md)), and what the promise covers beyond its snapshots ([ADR 0018](docs/adr/0018-what-the-1-x-promise-covers-beyond-its-snapshots.md)); a [standards guide](docs/guides/standards.md) records each ISO/IEC, ITU-T and IETF standard with its evidence; REUSE 3.3 compliance (`REUSE.toml`) and a weekly OSV-Scanner pass over the lockfile.

There is **no external security audit** at 1.0, and the line that once promised one has been removed rather than left to be broken. Neither pdfnative nor zipnative shipped 1.0 with one; what stands in its place is named in SECURITY.md §In place of an external audit — the adversarial release audit (two independent auditors and a verifier that re-derives every finding), the L0–L8 conformance gate over third-party corpora and the pinned text of RFC 5280, 100 % coverage on all four axes and mutation testing, the seeded adversarial suites, and CodeQL, Scorecard and Dependency Review, each on the trigger SECURITY.md names. If you need an audit for procurement, open an issue: it will be scoped, and it will be said here when it happens.

## 1.1.x — next, additive by construction

Everything here is a semver-minor addition under the 1.x promise; none of it was pulled into 1.0, because each would have widened the frozen surface without a rehearsal.

- [ ] The 36 RFC 5280 §4 requirements decidable from one certificate and not yet diagnosed (`scripts/data/rfc5280-requirements.json`, `not-diagnosed`)
- [ ] An id-RSASSA-PSS key verified by re-wrapping its SubjectPublicKeyInfo as rsaEncryption at the Web Crypto door, now that the RFC 4055 restrictions are enforced first; and a PKCS#12 key under an id-RSASSA-PSS certificate
- [ ] A PKCS#10 reader: parse and verify a certification request
- [ ] Signatures verified lazily, only for the edges the path search tries, so a hostile bag of same-name certificates no longer costs a verification per pair
- [ ] An OCSP delegated responder's certificate checked at the response's `producedAt` as well as at the validation instant
- [ ] Ed448 CMS signers ([ADR 0004](docs/adr/0004-dsa-and-ed448-cms-signers-not-verified.md)), once a host verifies Ed448 everywhere the build runs
- [ ] The surface classifier taught that a union widened inside an interface member is compatible, as ADR 0018's open unions require
- [ ] The guides' code blocks type-checked against `lib: DOM`, and an accessibility run (axe or Lighthouse) in the docs workflow
- [ ] `schemaVersion` in the machine registries of `docs/data/`, if a consumer needs more than the immutable tag ([ADR 0018](docs/adr/0018-what-the-1-x-promise-covers-beyond-its-snapshots.md))
- [ ] Node.js 26 joins the tested lines when it enters LTS (2026-10-28), in the CI matrix, `contracts.support` and SECURITY.md together

`pkinative-cli` and `pkinative-mcp` come **after** 1.0.0, as separate repositories and separate npm packages pinning `pkinative ^1.0.0` — the order both elders used. The machine-readable contracts they will consume are named in the 1.0.0 release note.

## How to Influence the Roadmap

- **Open an issue** describing the use case and the standard that defines it.
- **Report a conformance case** with the conformance template — the corpus grows from real certificates.
- **Sponsor** development through [GitHub Sponsors](https://github.com/sponsors/Nizoka).
- **Contribute** — see [CONTRIBUTING.md](CONTRIBUTING.md).
