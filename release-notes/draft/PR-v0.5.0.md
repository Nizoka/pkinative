# release: v0.5.0 — decide a chain, and say why

> **Branch:** `chore/release-v0.5.0` → `main`
> **Type:** Minor release (additive, fully backward-compatible with v0.4.0)
> **Milestone:** M3 — Path validation and revocation

## Summary

Until now pkinative **read** certificates: it told you what a certificate said, never whether to believe it. This release adds the judgement — RFC 5280 §6 path validation with name constraints and the policy tree, path building, CRLs with their §5.2.4 and §5.2.5 scoping, RFC 6960 OCSP, RFC 6125 host matching, extended key usage, and one call that asks every question in the right order. It also adds the vocabulary that makes those answers usable: a `PkiReasonCode` is **returned** in a report, never thrown and never emitted, because a verification produces several reasons at once and an exception carries one. That registry was shipped *before* the code that needed it, so nothing was ever built on `try/catch` and migrated afterwards.

Zero runtime dependencies. No export removed or renamed; no parsing behaviour changed. Two new corpora are scored rather than merely parsed, and both baselines record a written reason for every disagreement.

Counts: **215** public exports (126 types, 89 values) · **48** error codes · **34** diagnostic codes · **25** reason codes · **16** named limits · **56** verify-docs rules · **11** bundle probes · **2 145** tests · **100 %** statements, branches, functions and lines.

## Changes

### Engine surface

New layers `path`, `revocation` and `verify`, registered in `LAYERS` in the commit of their first file.

- `src/types/pki-reasons.ts`, `src/core/pki-reasons.ts` — the third vocabulary. `PKI_REASON_INPUT_MALFORMED` carries in `errorCode` the `PkiErrorCode` that would have been thrown, which is how a report promises never to throw for bad input without duplicating 48 encoding codes.
- `src/path/` — `validateCertificatePath` (§6, synchronous and never throwing for a validation issue), `buildCertificatePath`, `checkServerName` (RFC 6125), `checkExtendedKeyUsage` (§4.2.1.12).
- `src/revocation/` — `parseCertificateList` and `findRevocation` (walked with a lazy TLV cursor, never decoded into nodes), `checkRevocation` with §5.2.4 deltas / §5.2.5 scope / §5.3.3 indirect lists, and the RFC 6960 quartet `createOcspRequest`, `encodeCertId`, `parseOcspResponse`, `checkOcspStatus`.
- `src/crypto/` — `verifyCrlSignature`, `verifyOcspSignature`.
- `src/hash/key-identifier.ts` — `computeKeyIdentifier` (§4.2.1.2 method 1, byte for byte RFC 6960's `issuerKeyHash`).
- `src/verify/verify-chain.ts` — `verifyCertificateChain`, the only place in `src/` allowed to catch a `PkiError`.
- Six new profile diagnostics on `x509/`, each measured against the corpus before it was added.

Nothing was removed. `SignatureResult` gained an optional `issuer`; `CertificateList` gained `issuingDistributionPoint` and `baseCrlNumber`.

### Tooling (scripts/)

- `scripts/lib/limbo-score.ts` and the L6 scorer in `scripts/validate-certs.ts` — x509-limbo scored on SUCCESS / FAILURE, with `scripts/data/limbo-score.json` as the reviewed baseline.
- `scripts/lib/pkits.ts`, `scripts/lib/zip.ts` and the L7 scorer — NIST PKITS, with `scripts/data/pkits-score.json`. The ZIP reader is about a hundred lines over `node:zlib`: the central directory is the truth, every offset is bounds-checked, `..` and absolute paths are refused, Zip64 is refused rather than half-read.
- `scripts/lib/corpora.ts` gained an archive source with a second pin (`.github/checksums/pkits-*.sha256`).
- `scripts/verify-bundle.ts` — three new leaf probes and the budgets raised in the commits that measured them.

### CI and repository (.github/, root)

No workflow changed. The PKITS per-file checksum list was added under `.github/checksums/`.

### Agent layer (.claude/, AGENTS.md, governance)

`AGENTS.md` and `.github/copilot-instructions.md` record the `verify` layer and its edges; `.claude/rules/*.md` were regenerated from the instruction files.

### Tests and conformance

2 145 tests, 100 % on all four axes with three justified `v8 ignore` comments counted in `declared.coverageIgnores`. New suites under `tests/path/`, `tests/revocation/`, `tests/verify/` and `tests/conformance/limbo-score.test.ts`, which holds both score baselines' discipline in the fast gate without needing either corpus.

### Documentation

`docs/guides/conformance.md` gained L6 and L7; `docs/guides/use-cases.md` gained the revocation decision, CRL scope, delta CRLs and who may sign a list. `docs/data/reasons.json` is the new machine-readable registry.

## Independent audit

`/release-audit release-notes/v0.5.0.md v0.4.0` — **PENDING**

This PR is not ready to merge until the ledger is attached here with a fix commit for every confirmed blocker and major.

## Validation (what actually ran, on Windows 11 Pro 10.0.26200, Node 22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 14 passed, 0 skipped in 1225.8 s` |
| `npm run test:coverage` | 2 145 tests across 66 files; statements 100 % (3 953/3 953), branches 100 % (2 850/2 850), functions 100 % (497/497), lines 100 % (3 372/3 372) |
| `npm run verify:bundle` | 11 probes, largest `{ * }` 168.9 KB against a 172 KB budget |
| `npx tsx scripts/verify-docs.ts` | 56 rules, 0 errors, 0 warnings |
| `npx tsx scripts/validate-certs.ts --require-all` | L1 29 796 parsed / 565 refused · L2 30 361 re-encoded byte for byte · L3 `node:crypto` 29 796/29 796 and OpenSSL 4.0.0 202/202 · L4 Windows CryptoAPI 202/202 · L5 19 clauses, 17 exercised, every violation attributed · **L6 9 156/9 208 (99.44 %)** · **L7 194/203 (95.57 %)** · Wycheproof 1 530 ECDSA vectors |
| `npm run check:package` | attw + publint clean (inside the publish gate) |
| `npm run smoke:install` | ESM and CJS load from the packed tarball (inside the publish gate) |
| `npm pack --dry-run` | 12 files, 734.6 kB packed, 3.0 MB unpacked |
| `npm ls --omit=dev --all` | `pkinative@0.5.0` alone — zero runtime dependencies |

## Backward compatibility

Every public export of v0.4.0 keeps its name and its signature. Nothing throws where it used to return and nothing returns where it used to throw.

One thing to know rather than to migrate: `PkiReason` is a **returned** value. Nothing in the new surface throws for a validation issue, so a `try/catch` around `verifyCertificateChain` catches nothing but a programming error. Below 1.0 a minor release may still change the API, and the error vocabulary does not freeze until 0.8.0 — both are stated in the release note's Downstream integration notes.

## Out of scope (tracked in ROADMAP.md)

- The 20 PKITS §4.8 certificate-policy tests, skipped until a reviewed transcription of their `user-initial-policy-set` expectations exists. A runner that guessed would be scoring its own guess.
- RFC 5280 §7.1 name comparison by LDAP string preparation. pkinative compares encoded bytes, as Go's `crypto/x509` and webpki do; six PKITS tests turn on that, and the direction of the miss is refusal.
- DSA — Web Crypto implements none of it, and pkinative implements no signature algorithm itself.
- `ValidSelfIssuedinhibitAnyPolicyTest9`, recorded as a *suspected defect* in §6.1.5's policy wrap-up rather than an absent feature. It is the one deviation in either baseline that has not been explained.
- ClusterFuzzLite has still never executed.

## Human-in-the-loop — steps for the maintainer

1. Squash-merge to `main` with the title `release: v0.5.0 — decide a chain, and say why`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.5.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.5.0 — decide a chain, and say why`, body = `release-notes/v0.5.0.md`).
   Below 1.0.0 expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. Nothing version-specific. The bootstrap of `main` and the ruleset import (B0–B8) are still outstanding and are not part of this release.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — **PENDING, so this PR is not ready to merge.**
