<!--
Thank you for contributing to pkinative. Describe the change, then walk the
checklist. The items mirror CONTRIBUTING.md §Pull Request Checklist word for
word; keep the two in step when you change either.
-->

## What and why

<!-- One paragraph: what changes, why, and which issue it closes (`Closes #…`). -->

## Checklist

- [ ] `npm run gate` passes — the CI profile in one command (`npm run gate:fast` for a quick loop while iterating)
- [ ] All tests pass (`npm run test`)
- [ ] Type check passes (`npm run typecheck:all`)
- [ ] Lint passes (`npm run lint`)
- [ ] New code has tests, and every new error code, diagnostic or limit is raised by at least one of them
- [ ] Every ```ts fence of README.md and `docs/guides/*.md` compiles (`npm run check:guides`, a gate step): a fence may use the inputs named in `GUIDE_INPUTS` (`scripts/check-guides.ts`) — the bytes, certificates and keys the prose around it names — and nothing else undeclared; a new input is a reviewed line in that table
- [ ] No `any` types introduced
- [ ] No new runtime dependencies added
- [ ] Every new loop over untrusted bytes consults a named limit, with its CWE, a fuzzing test and a SECURITY.md row (see [Security](../CONTRIBUTING.md#security))
- [ ] If decoding or parsing behaviour changed: the conformance gate passes and every expectation change is explained in the commit (see [Conformance](../CONTRIBUTING.md#conformance))
- [ ] If docs/, README or llms files changed: `npm run verify:docs` passes
- [ ] CHANGELOG.md updated if user-facing changes
- [ ] For releases: follow [Release](../CONTRIBUTING.md#release) — `release-notes/vX.Y.Z.md` written, and `npx tsx scripts/gate.ts --publish --require-all` passes locally

<!--
Runtime changes also need a ROADMAP.md entry and a line in the next
release-notes/vX.Y.Z.md; a public-API addition, removal or behaviour shift is
described there under "Downstream integration notes" (AGENTS.md §Releasing).
-->
