# Release pull-request template

The body of the release pull request. `scripts/release-prepare.ts` copies the
fenced block below into `release-notes/draft/PR-vX.Y.Z.md` and resolves
`X.Y.Z` and `YYYY-MM-DD`; you fill the rest and the maintainer pastes the
result into the GitHub pull request verbatim.

**The per-version bodies are committed.** They are the auditable record of
what each release claimed and what was actually run — the one place a reader
can check, a year later, whether the numbers in a release note came from a
command or from somebody's memory. A git-ignored scratch file at the
repository root cannot serve that purpose, which is why this convention
replaced one.

**Keep the section order.** The release audit (`/release-audit`) reads
*Independent audit* and *Validation* by name.

**Every figure here comes from a command you ran on the release branch** —
the gate's own summary, `npm run test:coverage`, `npx tsx
scripts/verify-docs.ts`, `npx tsx scripts/verify-bundle.ts`, the conformance
runner. A command that was not run is marked `not run`, never guessed, and a
number typed from memory is the failure this instruction exists to prevent.

---

```markdown
# release: vX.Y.Z — <headline>

> **Branch:** `chore/release-vX.Y.Z` → `main`
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

`/release-audit release-notes/vX.Y.Z.md vA.B.C` — <PENDING | GO | NO-GO>

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

1. Squash-merge to `main` with the title `release: vX.Y.Z — <headline>`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `vX.Y.Z` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `vX.Y.Z — <headline>`, body = `release-notes/vX.Y.Z.md`).
   Expect `publish.yml` to pass its `guard` job, wait for the `npm-publish` reviewer, then publish and attest; afterwards `npm view pkinative version` names X.Y.Z and `npm run check:npm-drift` is clean.
5. <Anything version-specific: a ruleset re-import, an npm name reservation, a social image upload.>

## Self-review checklist

- [ ] Every count above was produced by a command on this branch, not typed from memory.
- [ ] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [ ] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [ ] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
```
