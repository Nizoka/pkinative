# Conformance

> **pkinative is held to corpora it did not write and to parsers it does not share code with.** A blocking gate runs the built package over x509-limbo and Wycheproof, pinned by commit and SHA-256, and checks every answer against OpenSSL.

## The corpora

| Corpus | What it holds | Pinned at |
|---|---|---|
| [x509-limbo](https://github.com/C2SP/x509-limbo) | 9 793 x509-limbo test cases of certificate validation, from RFC 5280, the CA/Browser Forum, webpki, BetterTLS and pathological inputs | commit `118721335e67` |
| [Project Wycheproof](https://github.com/C2SP/wycheproof) | 1 530 Wycheproof ECDSA vectors on P-256, P-384 and P-521, including deliberately mis-encoded signatures | commit `3fa63dd0344a` |

`npm run conformance:fetch` downloads them into `test-output/corpora/` and refuses any file whose SHA-256 differs from `.github/checksums/`; nothing is committed. `scripts/lib/corpora.ts` holds the pins, and the verify-docs rule `corpus-pin-parity` keeps the checksums, `THIRD-PARTY-NOTICES.md` and `docs/assets/ecosystem.json` in step with them.

## The levels

`scripts/validate-certs.ts` runs the package from `dist/` — what users get, not the sources:

- **L0 — pins and canaries.** The files match their SHA-256, and the case counts match the values declared in `ecosystem.json`, so a silently changed corpus fails loudly.
- **L1 — parse or refuse by the rules.** Every one of the 30 361 unique x509-limbo certificates parses, or throws a `PkiError`. A refusal is allowed only when every limbo case using that certificate expects failure, and only as recorded in the reviewed baseline `scripts/data/limbo-refusals.json`: 565 certificates refused — unknown GeneralName tags, malformed name forms, iPAddress lengths, empty subtree lists, a name-constraints extension that constrains nothing, an empty extended key usage, two truncated extension values (subjectAltName, authorityInfoAccess), an issuer RSA key that is not an RSAPublicKey, a duplicated extension, an emoji in a DNS name, and two denial-of-service certificates stopped by `maxNameAttributes`. A baseline entry that starts to parse is an `UNEXPECTED-PASS`; any other exception fails the gate.
- **L2 — byte identity.** Every certificate re-encodes byte for byte from its decoded tree, and the boundaries of `tbsCertificate` and `signatureValue` agree with `scripts/lib/raw-der.ts`, a walker written separately that never imports `src/`.
- **L3 — OpenSSL.** Every parsed certificate agrees with `node:crypto.X509Certificate` on serial number, validity, CA flag and SHA-256 fingerprint, and a sample of 200 agrees with the `openssl` command-line tool — two builds, the one inside Node and the system one. What is cross-checked is the values the tool reads, never its acceptance policy: a disagreement on a serial or a fingerprint always fails, while a non-reference implementation refusing a certificate (LibreSSL on macOS) is reported as not applicable, and fails only if it reads too few to be a cross-check at all.
- **L4 — other implementations.** There is no veraPDF for the PKI: no single reference a parser can be held to. The honest equivalent is confrontation, so a sample of the corpus is read again by implementations written by other people, in other languages, and the readings must agree. What is compared is never rendered text — every implementation prints a distinguished name its own way — but SHA-256 of exact DER slices: `subjectFp256` and `issuerFp256` over the encoded subject and issuer, `spkiKeyFp256` over the public key octets, `tbsFp256` over the signed bytes, plus the exact identifiers `keyAlgOid` and `version`. Each validator declares in its output which of those it can supply, so a tool that cannot reach a field says so instead of being special-cased.

  Three guards make agreement mean something. A **positive canary** every implementation reads is submitted first, so one that rejects everything is unmasked (`VACUOUS`). **Negative canaries** — a truncated certificate, no bytes at all, octets that are not ASN.1, a length that runs past the input — are submitted last, so one that accepts everything is unmasked (`XPASS`). A **footer** states how many certificates were read, so one that stops halfway and exits 0 is caught by the contract rather than by a guess. Neither canary verdict can be waived.

  A real difference between two implementations is recorded in `scripts/data/validator-disagreements.json` with the reason it is accepted, the way refusals are recorded in `limbo-refusals.json` — never silenced, never a permanent red. Today that file is empty. Every toolchain the matrix uses is already on the runner: nothing is downloaded, vendored, cached or checksum-pinned, so the gate adds no supply-chain surface of its own. A validator that does not exist on a platform is reported as not applicable, never as a pass.
- **L5 — RFC 5280, clause by clause.** L1 to L4 are all **differential**: they prove agreement, not correctness. If pkinative, OpenSSL and `node:crypto` were wrong in the same way, L3 would be green. And a red L1 says *"certificate `ab3f…` was refused and the baseline says otherwise"* — a regression detector, not an authority.

  L5 makes the claim that is missing, and it is a claim about **attribution**. `scripts/lib/clauses.ts` holds 19 clauses of RFC 5280 §4.1 and §4.2, each quoting the normative sentence it enforces and naming the `PkiDiagnosticCode` that must report it. `scripts/validators/rfc5280-clauses.ts` decides each one from the raw bytes through `raw-der.ts`, without importing `src/` — two readings that shared a decoder could not disagree. The runner then fails on a violation pkinative is **silent** about, and, for a clause that claims to decide every case its diagnostic covers, on a diagnostic with **no violation behind it**: the two readings disagree, and one of them is wrong.

  Today a red run says a certificate changed behaviour. L5 says: *"RFC 5280 §4.2.1.9 is violated by 14 certificates of the corpus; pkinative diagnoses 13 and is silent on one."*

  A clause nothing triggers proves nothing, so every clause must be exercised by at least one corpus certificate — or carry a reviewed waiver saying why the corpus cannot reach it and naming the suite that does. Two do: x509-limbo holds no certificate with a unique identifier, and none with a multi-valued relative distinguished name, because neither bears on path validation. `tests/conformance/clauses.test.ts` builds a violating and a conforming certificate for **every** clause, which is also the only thing that could catch an evaluator that always answers "pass". §6 doubles this table and arrives with 0.5; the completeness assertion becomes blocking at 0.9.
- **L6 — path validation, scored.** L1 to L5 judge certificates. L6 judges **chains**, which is the other half of what this library is for and the only half a boolean can be wrong about silently. Every x509-limbo case is built, name-matched and revocation-checked the way a caller would, and pkinative's verdict must match the one the corpus writes down: **9 150 of 9 200 agree, 99.46 %**, with 20 skipped and the rest refused at L1.

  Three things make that a claim rather than a statistic.

  **Reason codes, not the boolean.** A validator that rejects every chain scores well against a corpus that is mostly FAILURE, so 28 cases are pinned on their `PkiReasonCode` — *rejected for the wrong reason* is a defect no pass/fail count can see. CVE-2025-61727 is pinned on `PKI_REASON_NAME_EXCLUDED`, not merely on "refused".

  **Canaries.** One case that must succeed and one that must fail. A harness whose trust store silently stopped being passed through would still score in the high nineties; the positive canary is the only thing that notices.

  **Every deviation carries a sentence someone wrote.** The 50 disagreements are each either a defect or a decision, and only prose tells them apart — so `--update-baseline` records the id it measured and **never** fills in the reason, and an empty one fails the gate. `tests/conformance/limbo-score.test.ts` holds that discipline in the fast gate, where the corpus is not needed: the one thing a reviewer cannot catch by reading a diff is an empty string. What the deviations are, in short: CA/Browser Forum policy the RFC does not state (key sizes, a `commonName` that no `subjectAltName` repeats, webpki's extended-key-usage pedantry), profile sentences addressed to the issuing CA that pkinative reports as diagnostics instead of refusing, two readings x509-limbo itself calls ambiguous, and two gaps where this runner translates the corpus's vocabulary into pkinative's and the translation is what falls short.
- **Wycheproof.** Every ECDSA signature is decoded as a strict `Ecdsa-Sig-Value`: every valid vector must decode, and every vector flagged `BerEncodedSignature`, `InvalidEncoding` or `InvalidTypesInSignature` must be refused.

## The write direction

Everything above points one way: bytes someone else produced, read by pkinative. From 0.3 the arrow also points outward, and that direction has **no corpus** — nobody publishes a set of certificates a library is supposed to have written. The only oracle available is the tools themselves.

`npm run interop` (`scripts/run-interop.ts`) hands every artefact of the sample catalogue to each foreign tool it can find, and requires agreement on facts that have exactly one right answer: the serial number as an integer, the subject common name, the DNS names, whether the chain verifies, and whether the PKCS#10 request's self-signature checks out. The artefacts are the same ones `verify:samples` freezes by hash, so the bytes a baseline blesses are the bytes OpenSSL is asked to read — two catalogues would each be green about something the other never saw.

Three details decide whether the result means anything:

- **A tool that refuses an artefact is a finding about pkinative.** This is the opposite of the read direction, where a foreign acceptance policy stricter than ours is not our defect. Here the bytes are ours.
- **A tool this runner cannot parse is a defect in the runner, never evidence about the certificate.** The two are separate states because conflating them is how a gate ends up red in one language and green in another: Windows `certutil` reads the artefacts perfectly and prints *"Numéro de série"* on a French system, and a runner with two states reported a good certificate as refused.
- **Each tool declares which fields it can supply**, exactly as the L4 validators do, and a tool that compares nothing fails as vacuous. Windows CryptoAPI supplies the serial and the subject — both API values, identical in every locale — and does not supply DNS names, because reaching them from Windows PowerShell 5.1 means `X509Extension.Format()`, whose output is translated.

Today `openssl` and Windows CryptoAPI run, on all three platforms, blocking: the matrix runs inside the `conformance` job, whose three contexts the ruleset already requires. GnuTLS `certtool`, Windows `certutil`, `keytool`, macOS `security` and Python `cryptography` are declared in `scripts/lib/interop.ts` with the reason each is pending, and `interop-matrix-declared` holds that list to ROADMAP.md in both directions so a gap cannot quietly disappear. `--require-all`, which turns a missing tool into a failure, goes on in the commit that lands the last of them.

## What is not claimed yet

NIST PKITS is not run. It is the other standard corpus for path validation, its expectations live in a PDF rather than in machine-readable form, and transcribing ~200 of them by hand is work that has not been done — so nothing here rests on it.

**And the score is a measurement, not a promise.** It moves when the corpus is re-pinned, which is why the 1.0 freeze will not name it: what gets frozen is the *decision surface* — which certificate pkinative refuses and with which code — because that is a property of this library rather than of somebody else's test suite. The deviations file is where the two meet, and it is meant to shrink: the five key-identifier entries in it today say, in so many words, that `createCertificate` has to be able to emit `subjectKeyIdentifier` and `authorityKeyIdentifier` before their absence can be diagnosed — or everything this library builds would trip its own reader.

## Where it runs

`.github/workflows/conformance.yml` runs the gate on every push to `main` and every pull request into it, weekly, and on demand, on Linux, Windows and macOS — three required checks, `conformance`, `conformance-windows` and `conformance-macos`. Three platforms is not redundancy: the command-line tool the L3 level cross-checks against differs by runner (OpenSSL, the Git for Windows build, LibreSSL), and so do line endings, path separators and the default shell. The release gate (`npx tsx scripts/gate.ts --publish --require-all`) runs it too. Locally:

```bash
npm run build
npm run conformance:fetch
npx tsx scripts/validate-certs.ts --require-all
```

## Fixtures

Six public certificates are committed as known-answer fixtures, each with its source, retrieval date and SHA-256 in `tests/fixtures/PROVENANCE.md`: ISRG Root X1 and X2, Let's Encrypt E7 and R12, the letsencrypt.org end-entity certificate, and the RFC 8410 §10.2 example. Their expected values were read with OpenSSL, and every one is also run through the `node:crypto` differential.
