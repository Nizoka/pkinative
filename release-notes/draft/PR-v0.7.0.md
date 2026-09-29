# release: v0.7.0 — sign it, stamp it, and prove it

> **Branch:** `chore/release-v0.7.0` → `main`
> **Type:** Minor release (additive; one reporting change in `verifyCertificateChain`, described below)
> **Milestone:** M4 — CMS and timestamps

## Summary

pkinative could already decide whether to believe a certificate; this release decides whether to believe a **signed message**. RFC 5652 CMS SignedData is parsed, built and verified, and RFC 3161 timestamps are requested, read, verified and attached — the format under S/MIME, code signing and PAdES, and the evidence that lets a signature outlive its certificate. `verifySignedData` keeps `intact` (the message is what its signer signed) apart from `valid` (and somebody you trust signed it), and with `atTimeStamp` judges a signer at the earliest instant a verified timestamp proves, while the TSA's own chain is judged at `at`, never at the `genTime` it wrote itself.

Zero runtime dependencies. No export removed or renamed. A new conformance level, L8, verifies the 224 NIST PKITS S/MIME messages whole and holds each verdict to the L7 verdict on its signer's path; it found one reporting defect, fixed here.

Counts: **253** public exports (152 types, 101 values) · **52** error codes · **38** diagnostic codes · **36** reason codes · **19** named limits · **56** verify-docs rules · **15** bundle probes · **2 816** tests · **100 %** statements, branches, functions and lines.

## Changes

### Engine surface

A new layer, `cms`, registered in `LAYERS` with its edges (`cms → types, core, asn1, hash, x509, build`); `build` gained `hash` and `verify` gained `cms`, in their own reviewed commit.

- `src/cms/` — `parseSignedData`, `parseTstInfo`, `parseTimeStampToken`, `parseTimeStampResponse`, `createTimeStampRequest`, and the attribute checks every signer is held to. `src/core/cms-oids.ts` holds the object identifiers both `cms` and `build` need.
- `src/crypto/cms-verify.ts` — `verifySignerInfoSignature`, with the digest/signature consistency rules of RFC 8933, 4056, 5753 and 8419.
- `src/build/build-signed-data.ts` — `createSignedData`, `addUnsignedAttribute`, `addTimeStampToken`. Every signing entry point now takes a `Signer` (`SigningKey | ExternalSigner`).
- `src/verify/` — `verifySignedData` and `verifyTimeStampToken` (which takes the token or the whole `TimeStampResp`). The rethrow that keeps a programming error from becoming a verdict is shared as `_pkiError`, so the three verify modules hold one coverage exemption between them.
- `src/types/` — `PkiCmsError` and its four codes, `cms-types.ts`, `tsp-types.ts`, `ExternalSigner` and `Signer`; four CMS diagnostics, eleven CMS/TSP reasons, three limits.
- Fixed: `verifyCertificateChain` read a CRL or OCSP response passed twice twice; `requireRevocation` did not reach the timestamps `verifySignedData` checks; the OCSP reader refused a response carrying a recognised extension.

### Tooling (scripts/)

- `scripts/validate-certs.ts` and `scripts/lib/pkits-smime.ts` — the L8 scorer, with `scripts/data/pkits-smime-score.json` as its reviewed baseline; `runPkitsScorer` now returns its per-test verdicts, and the runner's default level is 8, so `npm run conformance`, the publish gate and `conformance.yml` run it unchanged.
- `scripts/lib/corpora.ts` — the PKITS extraction now includes `smime/`, and `.github/checksums/pkits-*.sha256` lists the 802 extracted files.
- `scripts/verify-bundle.ts` — four CMS probes, and the package budget raised in the commit that measured it.

### CI and repository (.github/, root)

No workflow changed. The PKITS per-file checksum list grew with the S/MIME messages.

### Agent layer (.claude/, AGENTS.md, governance)

`AGENTS.md` records the `cms` layer, its edges and the rule that neither `path` nor `cms` imports `crypto`.

### Tests and conformance

2 816 tests across 79 files, 100 % on all four axes, with three justified `v8 ignore` comments counted in `declared.coverageIgnores` — the same three as 0.5.0. New suites under `tests/cms/`, `tests/verify/verify-signed-data.test.ts` and `verify-timestamp.test.ts` (built on a small Web Crypto test PKI in `tests/verify/_cms-pki.ts`), `tests/crypto/cms-verify.test.ts`, `tests/build/build-signed-data.test.ts`, `tests/fuzzing/cms.test.ts`, and `tests/conformance/pkits-smime.test.ts`, which holds the L8 baseline's discipline in the fast gate without the corpus.

### Documentation

`docs/guides/use-cases.md` gained "Sign a message, and verify one the whole way" and "Prove when it was signed"; `docs/guides/errors.md` the CMS codes, diagnostics and reasons; `docs/guides/conformance.md` L8. Three recipes run on every test pass: `recipes/sign-message.ts`, `recipes/external-signer.ts`, `recipes/timestamp.ts`. `llms.txt` and the agent brief now describe what the library does rather than what 0.1 and 0.3 did.

## Independent audit

`/release-audit release-notes/v0.7.0.md v0.5.0` — **PENDING**

This PR is not ready to merge until the ledger is attached here with a fix commit for every confirmed blocker and major.

## Validation (what actually ran, on Windows 11 Pro 10.0.26200, Node 22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 14 passed, 0 skipped in 968.2 s` |
| `npm run test:coverage` | 2 816 tests across 79 files; statements 100 % (5 119/5 119), branches 100 % (3 808/3 808), functions 100 % (646/646), lines 100 % (4 406/4 406) |
| `npm run verify:bundle` | 15 probes, largest `{ * }` 226.1 KB against a 236 KB budget |
| `npx tsx scripts/verify-docs.ts` | 56 rules, 0 errors, 0 warnings |
| `npx tsx scripts/validate-certs.ts --require-all` | L1 29 796 parsed / 565 refused · L2 30 361 re-encoded byte for byte · L3 `node:crypto` 29 796/29 796 and OpenSSL 4.0.0 202/202 · L4 Windows CryptoAPI 202/202 · L5 19 clauses, 17 exercised, every violation attributed · L6 9 156/9 208 (99.44 %) · L7 194/203 (95.57 %) · **L8 221/224 intact, 204/204 equal to L7, 195/204 agree with NIST (95.59 %)** · Wycheproof 1 530 ECDSA vectors |
| `npm run interop` | OpenSSL 4.0.0 (11 checks) and Windows CryptoAPI (6 checks) agree on every artefact; windows-certutil, java-keytool and python-cryptography declared and not implemented |
| `npm run check:package` | attw + publint clean (inside the publish gate) |
| `npm run smoke:install` | ESM and CJS load from the packed tarball (inside the publish gate) |
| `npm pack --dry-run` | 12 files, 960.3 kB packed, 3.9 MB unpacked |
| `npm ls --omit=dev --all` | `pkinative@0.7.0` alone — zero runtime dependencies |

## Backward compatibility

Every public export of v0.5.0 keeps its name. The signing parameter of `createCertificate` and `createCertificationRequest` widened from `SigningKey` to `Signer`, which includes it, so existing calls compile unchanged.

One report reads differently: `verifyCertificateChain` reads each distinct CRL and OCSP response once, so a caller that passed the same list twice sees one `PKI_REASON_REVOKED` where it used to see two. No refusal became an acceptance. Below 1.0 a minor release may still change the API, and the error vocabulary does not freeze until 0.8.0 — both stated in the release note's Downstream integration notes.

## Out of scope (tracked in ROADMAP.md)

- `parseSignedData` decodes the whole tree, so a very large `.p7b` meets `maxNodes` before `maxCmsBagEntries`.
- The RFC 4056 §3 agreement between RSASSA-PSS parameters in a certificate and the signer's.
- The v1 ESS `signingCertificate` when v2 is also present.
- ETSI long-term formats — B-LTA archive timestamps, chained proof of existence.
- DSA and Ed448 signers: Web Crypto implements neither DSA nor SHAKE256.
- ClusterFuzzLite has still never executed.

## Human-in-the-loop — steps for the maintainer

0. **v0.5.0 first.** This branch stacks on the prepared, untagged 0.5.0 release (`87b9ff6`); its audit, merge and tag come before this one, and the audit above compares against `v0.5.0`.
1. Squash-merge to `main` with the title `release: v0.7.0 — sign it, stamp it, and prove it`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.7.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.7.0 — sign it, stamp it, and prove it`, body = `release-notes/v0.7.0.md`).
   Below 1.0.0 expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. The `conformance` job now fetches PKITS `smime/` as well; nothing to configure. The bootstrap of `main` and the ruleset import (B0–B8) are still outstanding and are not part of this release.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — **PENDING, so this PR is not ready to merge.**
