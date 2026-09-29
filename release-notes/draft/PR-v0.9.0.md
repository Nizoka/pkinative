# release: v0.9.0 — the freeze, rehearsed

> **Branch:** `chore/release-v0.9.0` → `main`
> **Type:** Minor release (breaking below 1.0: a rename set with no aliases — ADR 0013)
> **Milestone:** M5b — The freeze, rehearsed

## Summary

The release that proves 1.0 can promise what it will promise. The public surface is snapshotted, and `api-surface-frozen` fails on any change to it in this phase and on any incompatible one from 1.0; the snapshot moves only on an accepted ADR, and the error vocabulary ratchets. Every name that freezes at 1.0 was audited and the regrettable ones renamed now (ADR 0013). RFC 5280 is pinned as a corpus and every L5 quote must be verbatim; four were not, one invented. Mutation testing brings the security-critical modules to 100 %. And the work found two paths pkinative accepted and RFC 5280 rejects — one of them the real cause of a NIST deviation misattributed since 0.5.0 — both fixed.

Zero runtime dependencies. No error code and no diagnostic code renamed; one reason code renamed; one exported type added. NIST PKITS 194 → 195/203.

Counts: **282** public exports (171 types, 111 values) · **57** error codes (frozen) · **40** diagnostic codes · **42** reason codes · **21** named limits · **61** verify-docs rules · **18** bundle probes · **3 387** tests · **100 %** statements, branches, functions and lines.

## Changes

### Engine surface

- The rename set across `src/` — limits, report and input fields, four functions, one reason code, the `*Input`/`*Options`/`*Report` types; `MatchDnsNameOptions` added. ADR 0013.
- `src/path/path-validate.ts` — an `rfc822Name` constraint applied to the subject `emailAddress` when there is no subjectAltName (RFC 5280 §4.2.1.10).
- `src/path/path-name-constraints.ts` — an excluded `directoryName` also matches after §7.1 preparation; permitted subtrees stay byte-exact.
- `src/revocation/crl-parse.ts` — a dropped CRL extension is diagnosed (`PKI_DIAG_CRL_EXTENSION_MALFORMED`); `src/core/pki-error-guard.ts` — the one guard every catch passes through.

### Tooling (scripts/)

- `build-api-frozen.ts` (`--rebaseline`, `--ratchet`, `--major`), `lib/api-surface.ts`, `build-errors-frozen.ts --ratchet`, `check-npm-drift.ts`; rules `api-surface-frozen`, `release-era-prose`, `adr-index`; `count-tokens` and `clause-table-complete` extended.
- `lib/rfc-requirements.ts` and `data/rfc5280-requirements.json` — L5 completeness against the pinned RFC; six new clauses.
- `mutate.ts`, `lib/mutation.ts`, `data/mutation-equivalents.json`.
- `release-prepare.ts` — ratchets both snapshots from 1.0.0, and moves three more sentences that quote the minor.
- `verify-bundle.ts` — two path budgets measured after the name-constraint fixes.

### CI and repository (.github/, root)

`docs.yml`'s weekly `npm-drift` job runs `check-npm-drift.ts` anonymously. The RFC 5280 checksum joins `.github/checksums/`. No other workflow changed.

### Agent layer (.claude/, AGENTS.md, governance)

`AGENTS.md` and the instruction files state the catch rule as it holds (only `verify/` converts a `PkiError` into a reason), the freeze and the rebaseline path; diagnostic codes additions-only. `.claude/rules/` regenerated.

### Tests and conformance

3 387 tests across 92 files, 100 % on all four axes, the same three justified `v8 ignore` comments. New: `tests/tools/api-frozen.test.ts`, `errors-frozen.test.ts`, `npm-drift.test.ts`, `mutation.test.ts`; `tests/conformance/rfc-requirements.test.ts`; the 19 mutation-killing tests; name-constraint tests in `tests/path/`.

### Documentation

Thirteen ADRs in `docs/adr/`. `docs/guides/choose.md` rewritten from what ships. `docs/guides/conformance.md` — L5 completeness, the new PKITS figures, Test29's real cause. Corrected in the 0.5.0 and 0.7.0 notes, the changelog and the 0.5.0 PR body: the claim that no deviation accepts what a standards body rejects, and the attribution of Test29.

## Independent audit

`/release-audit release-notes/v0.9.0.md v0.8.0` — **PENDING**

This PR is not ready to merge until the ledger is attached here with a fix commit for every confirmed blocker and major.

## Validation (what actually ran, on Windows 11 Pro 10.0.26200, Node 22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 14 passed, 0 skipped in 1079.1 s` |
| `npm run test:coverage` | 3 387 tests across 92 files; statements 100 % (5 770/5 770), branches 100 % (4 254/4 254), functions 100 % (724/724), lines 100 % (5 005/5 005) |
| `npm run verify:bundle` | 18 probes, largest `{ * }` 261.8 KB against a 272 KB budget |
| `npx tsx scripts/verify-docs.ts` | 61 rules, 0 errors, 0 warnings |
| `npx tsx scripts/validate-certs.ts --require-all` | L5 25 clauses; 182 requirement sentences, 21 clauses, 161 excluded, every quote verbatim · L6 9 156/9 208 (99.44 %) · L7 195/203 (96.06 %) · L8 221/224 intact, 196/204 agree, 204/204 equal to L7 · Wycheproof 1 530 ECDSA vectors |
| `npm run interop` | OpenSSL 4.0.0 and Windows CryptoAPI agree in both directions; 45 and 18 read-direction key-container checks |
| `npm run check:package` | attw + publint clean (inside the publish gate) |
| `npm run smoke:install` | ESM and CJS load from the packed tarball (inside the publish gate) |
| `npm pack --dry-run` | 12 files, 1.1 MB packed, 4.5 MB unpacked |
| `npm run mutate` | not run in the gate; the pass recorded in the release note ran on the eight default modules before the rename set, about 43 minutes |

The publish gate ran on `b4817fb`, the commit before the bump; the bump changes versions, install URLs and three sentences quoting the minor.

## Backward compatibility

**Breaking for 0.8.0 callers, by design and below 1.0:** the rename set has no aliases, because 0.9 is the last band where a rename costs a minor and an alias kept into 1.0 would freeze both names. TypeScript flags every place; JavaScript should search for the old names in ADR 0013. Error codes (frozen at 0.8.0) and diagnostic codes are unchanged. Two verdicts change, both refusals of paths RFC 5280 rejects.

## Out of scope (tracked in ROADMAP.md)

- The 37 RFC 5280 §4 requirements recorded as `not-diagnosed`.
- A full, unsampled mutation run of `path-validate.ts` and `asn1-decode.ts`.
- ClusterFuzzLite has still never executed.

## Human-in-the-loop — steps for the maintainer

0. **v0.5.0, v0.7.0 and v0.8.0 first.** This branch stacks on them; their audits, merges and tags come before this one, and the audit above compares against `v0.8.0`.
1. Squash-merge to `main` with the title `release: v0.9.0 — the freeze, rehearsed`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.9.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.9.0 — the freeze, rehearsed`, body = `release-notes/v0.9.0.md`).
   Below 1.0.0 expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. **Configure Trusted Publishing** for `pkinative` on npmjs.com, bound to `.github/workflows/publish.yml` and the `npm-publish` environment — the plan's step for this band, and the one thing 1.0 needs from npm. The bootstrap of `main` and the ruleset import (B0–B8) are still outstanding.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — **PENDING, so this PR is not ready to merge.**
