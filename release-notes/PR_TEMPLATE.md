# Release pull-request template

The body of the release pull request. Copy it into `RELEASE_PR_v{{version}}.md`
at the repository root (git-ignored — the per-version scratch file is never
committed; this template is), replace `{{version}}`, `{{date}}` and
`{{headline}}`, and fill every section from the facts of the branch. The
Verification section is a record of what actually ran, not a promise:
paste the numbers the gate printed, and mark anything not yet run as PENDING.

---

# release: v{{version}} — {{headline}}

## Summary

<!-- One paragraph: what the release is about, the compatibility statement
     (zero runtime dependencies, breaking changes or none, exports added /
     removed, error codes added), and the conformance figures. -->

## What's in it

| Area | Change |
|---|---|
| <!-- e.g. ASN.1 --> | <!-- the public surface, one row per workstream --> |
| Issues | <!-- #NN closed, with the one-line fix --> |
| Conformance | <!-- corpus pins, counts, expectation changes --> |
| Docs | <!-- guides, registries, recipes added or updated --> |

## Deferred

<!-- What was scoped out and why, so the next release starts from a decision
     rather than a rediscovery. Delete the section if nothing was deferred. -->

- ...

## Docs & registries

- Release note `release-notes/v{{version}}.md` and the `CHANGELOG.md` entry `## [{{version}}] – {{date}}`.
- Manifest `docs/assets/ecosystem.json`: version {{version}}, `verifiedOn` {{date}}, counts updated.
- <!-- errors.json, diagnostics.json, limits.json, guides, recipes -->

## Verification

The release gate is `npx tsx scripts/gate.ts --publish --require-all`. Each line names the individual gate and what it reported on the release commit:

- [ ] `npm run typecheck:all` — clean (src + tests + scripts).
- [ ] `npm run lint` — clean.
- [ ] `npm run test:coverage` — N tests across M files; statements / branches / functions / lines against the thresholds in vitest.config.ts.
- [ ] `npm run build` and `npm run check:package` — ESM, CJS, declarations; attw and publint clean.
- [ ] `npm run verify:bundle` — every probe within budget.
- [ ] Conformance — N limbo certificates, N Wycheproof vectors; every expectation met.
- [ ] `npm run verify:docs` — all rules passed.
- [ ] `npm ls --omit=dev --all` — pkinative alone.

## Merge checklist

- [ ] CI green (`ci (22)`, `ci (24)`, `windows`).
- [ ] `release-notes/v{{version}}.md` reviewed; release date adjusted if the tag is not cut on {{date}}.
- [ ] Squash-merge to `main` with the title `release: v{{version}} — {{headline}}`.
- [ ] The maintainer tags `v{{version}}` on the merge commit and publishes the GitHub Release (title `v{{version}} — {{headline}}`, body = the release note).
