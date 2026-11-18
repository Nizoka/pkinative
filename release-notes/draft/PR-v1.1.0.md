# release: v1.1.0 — <headline>

> **Branch:** `chore/release-v1.1.0` → `main`
> **Type:** <Minor | Patch> release (<additive, fully backward-compatible with vA.B.C | breaking: …>)
> **Milestone:** <the ROADMAP.md band this closes, or "none">

## Summary

<!-- One paragraph: what the release is about, the compatibility statement
     (zero runtime dependencies, breaking changes or none, exports added or
     removed, error codes added), and the conformance figures.

     Counts: N public exports · N error codes · N diagnostic codes · N named
     limits · N verify-docs rules · N bundle probes · N tests · N % statements. -->

## Changes

### Engine surface

<!-- New, changed or removed exports. "none" if the engine did not move. -->

### Tooling (scripts/)

### CI and repository (.github/, root)

### Agent layer (.claude/, AGENTS.md, governance)

### Tests and conformance

### Documentation

## Independent audit

`/release-audit release-notes/v1.1.0.md vA.B.C` — <PENDING | GO | NO-GO>

<!-- When run: the ledger summary — how many auditors, how many findings
     confirmed / downgraded / rejected / duplicated, and the fix commit for
     every confirmed blocker and major. -->

## Validation (what actually ran, on <OS>, Node <version>)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | <the gate's own summary line> |
| `npm run test:coverage` | <N tests across M files; statements / branches / functions / lines> |
| `npm run verify:bundle` | <N probes, largest X KB against budget Y KB> |
| `npx tsx scripts/verify-docs.ts` | <N rules, 0 errors> |
| `npx tsx scripts/validate-certs.ts --require-all` | <L0–L8 verdicts, corpus counts> |
| `npm run check:package` | <attw + publint> |
| `npm run smoke:install` | <ESM and CJS load from the packed tarball> |
| `npm pack --dry-run` | <file count, packed size> |
| `npm ls --omit=dev --all` | <pkinative alone> |

## Backward compatibility

<!-- Every public export keeps its signature, or the exact list of what moved
     and the one-line migration for each. Below 1.0 a minor may change the
     API; say so here and in the release note's Downstream integration notes. -->

## Out of scope (tracked in ROADMAP.md)

## Human-in-the-loop — steps for the maintainer

1. Squash-merge to `main` with the title `release: v1.1.0 — <headline>`.
2. Wait for the twelve required checks: `ci (22)`, `ci (24)`, `ci (26)`, `windows`, `macos`, `compat-previous`, `runtimes`, `workflow lint`, `conformance`, `conformance-windows`, `conformance-macos`, `dependency-review`.
3. Tag `v1.1.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v1.1.0 — <headline>`, body = `release-notes/v1.1.0.md`).
   Expect `publish.yml` to pass its `guard` job, wait for the `npm-publish` reviewer, then publish and attest; afterwards `npm view pkinative version` names 1.1.0 and `npm run check:npm-drift` is clean.
5. <Anything version-specific: a ruleset re-import, an npm name reservation, a social image upload.>

## Self-review checklist

- [ ] Every count above was produced by a command on this branch, not typed from memory.
- [ ] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [ ] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [ ] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
