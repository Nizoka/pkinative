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
- **L1 — parse or refuse by the rules.** Every one of the 30 361 unique x509-limbo certificates parses, or throws a `PkiError`. A refusal is allowed only when every limbo case using that certificate expects failure, and only as recorded in the reviewed baseline `scripts/data/limbo-refusals.json`: 564 certificates refused — unknown GeneralName tags, malformed name forms, iPAddress lengths, empty subtree lists, an empty extended key usage, a duplicated extension, an emoji in a DNS name, and two denial-of-service certificates stopped by `maxNameAttributes`. A baseline entry that starts to parse is an `UNEXPECTED-PASS`; any other exception fails the gate.
- **L2 — byte identity.** Every certificate re-encodes byte for byte from its decoded tree, and the boundaries of `tbsCertificate` and `signatureValue` agree with `scripts/lib/raw-der.ts`, a walker written separately that never imports `src/`.
- **L3 — OpenSSL.** Every parsed certificate agrees with `node:crypto.X509Certificate` on serial number, validity, CA flag and SHA-256 fingerprint, and a sample of 200 agrees with the `openssl` command-line tool — two OpenSSL builds, the one inside Node and the system one. `--require-all` turns a missing tool into a failure.
- **Wycheproof.** Every ECDSA signature is decoded as a strict `Ecdsa-Sig-Value`: every valid vector must decode, and every vector flagged `BerEncodedSignature`, `InvalidEncoding` or `InvalidTypesInSignature` must be refused.

## What is not claimed yet

x509-limbo also scores path validation — whether a chain should be accepted. pkinative 0.1 does not validate paths, so no SUCCESS/FAILURE score is claimed before 0.5; the gate checks only what 0.1 does: parsing, refusing and re-encoding.

## Where it runs

`.github/workflows/conformance.yml` runs the gate on every push and pull request as the required `conformance` check, and weekly on the pinned corpora; the release gate (`npx tsx scripts/gate.ts --publish --require-all`) runs it too. Locally:

```bash
npm run build
npm run conformance:fetch
npx tsx scripts/validate-certs.ts --require-all
```

## Fixtures

Six public certificates are committed as known-answer fixtures, each with its source, retrieval date and SHA-256 in `tests/fixtures/PROVENANCE.md`: ISRG Root X1 and X2, Let's Encrypt E7 and R12, the letsencrypt.org end-entity certificate, and the RFC 8410 §10.2 example. Their expected values were read with OpenSSL, and every one is also run through the `node:crypto` differential.
