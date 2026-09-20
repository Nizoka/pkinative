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
- **L1 — parse or refuse by the rules.** Every one of the 30 361 unique x509-limbo certificates parses, or throws a `PkiError`. A refusal is allowed only when every limbo case using that certificate expects failure, and only as recorded in the reviewed baseline `scripts/data/limbo-refusals.json`: 564 certificates refused — unknown GeneralName tags, malformed name forms, iPAddress lengths, empty subtree lists, an empty extended key usage, two truncated extension values (subjectAltName, authorityInfoAccess), an issuer RSA key that is not an RSAPublicKey, a duplicated extension, an emoji in a DNS name, and two denial-of-service certificates stopped by `maxNameAttributes`. A baseline entry that starts to parse is an `UNEXPECTED-PASS`; any other exception fails the gate.
- **L2 — byte identity.** Every certificate re-encodes byte for byte from its decoded tree, and the boundaries of `tbsCertificate` and `signatureValue` agree with `scripts/lib/raw-der.ts`, a walker written separately that never imports `src/`.
- **L3 — OpenSSL.** Every parsed certificate agrees with `node:crypto.X509Certificate` on serial number, validity, CA flag and SHA-256 fingerprint, and a sample of 200 agrees with the `openssl` command-line tool — two builds, the one inside Node and the system one. What is cross-checked is the values the tool reads, never its acceptance policy: a disagreement on a serial or a fingerprint always fails, while a non-reference implementation refusing a certificate (LibreSSL on macOS) is reported as not applicable, and fails only if it reads too few to be a cross-check at all.
- **L4 — other implementations.** There is no veraPDF for the PKI: no single reference a parser can be held to. The honest equivalent is confrontation, so a sample of the corpus is read again by implementations written by other people, in other languages, and the readings must agree. What is compared is never rendered text — every implementation prints a distinguished name its own way — but SHA-256 of exact DER slices: `subjectFp256` and `issuerFp256` over the encoded subject and issuer, `spkiKeyFp256` over the public key octets, `tbsFp256` over the signed bytes, plus the exact identifiers `keyAlgOid` and `version`. Each validator declares in its output which of those it can supply, so a tool that cannot reach a field says so instead of being special-cased.

  Three guards make agreement mean something. A **positive canary** every implementation reads is submitted first, so one that rejects everything is unmasked (`VACUOUS`). **Negative canaries** — a truncated certificate, no bytes at all, octets that are not ASN.1, a length that runs past the input — are submitted last, so one that accepts everything is unmasked (`XPASS`). A **footer** states how many certificates were read, so one that stops halfway and exits 0 is caught by the contract rather than by a guess. Neither canary verdict can be waived.

  A real difference between two implementations is recorded in `scripts/data/validator-disagreements.json` with the reason it is accepted, the way refusals are recorded in `limbo-refusals.json` — never silenced, never a permanent red. Today that file is empty. Every toolchain the matrix uses is already on the runner: nothing is downloaded, vendored, cached or checksum-pinned, so the gate adds no supply-chain surface of its own. A validator that does not exist on a platform is reported as not applicable, never as a pass.
- **Wycheproof.** Every ECDSA signature is decoded as a strict `Ecdsa-Sig-Value`: every valid vector must decode, and every vector flagged `BerEncodedSignature`, `InvalidEncoding` or `InvalidTypesInSignature` must be refused.

## What is not claimed yet

x509-limbo also scores path validation — whether a chain should be accepted. pkinative 0.1 does not validate paths, so no SUCCESS/FAILURE score is claimed before 0.5; the gate checks only what 0.1 does: parsing, refusing and re-encoding.

## Where it runs

`.github/workflows/conformance.yml` runs the gate on every push to `main` and every pull request into it, weekly, and on demand, on Linux, Windows and macOS — three required checks, `conformance`, `conformance-windows` and `conformance-macos`. Three platforms is not redundancy: the command-line tool the L3 level cross-checks against differs by runner (OpenSSL, the Git for Windows build, LibreSSL), and so do line endings, path separators and the default shell. The release gate (`npx tsx scripts/gate.ts --publish --require-all`) runs it too. Locally:

```bash
npm run build
npm run conformance:fetch
npx tsx scripts/validate-certs.ts --require-all
```

## Fixtures

Six public certificates are committed as known-answer fixtures, each with its source, retrieval date and SHA-256 in `tests/fixtures/PROVENANCE.md`: ISRG Root X1 and X2, Let's Encrypt E7 and R12, the letsencrypt.org end-entity certificate, and the RFC 8410 §10.2 example. Their expected values were read with OpenSSL, and every one is also run through the `node:crypto` differential.
