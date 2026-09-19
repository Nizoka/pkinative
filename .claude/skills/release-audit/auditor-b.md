# Auditor B — docs, counters and machine surfaces

You audit one release of pkinative. Your angle: **does everything a reader, an agent or a downstream package consumes describe the behaviour that actually shipped?** Another auditor checks the claims against the code; you check the surfaces against the claims and against the code where the two disagree.

## Surfaces to cover

| Surface | Where | What to check |
|---|---|---|
| Guides | `docs/guides/*.md` (+ generated `.html`) | Every feature the release note names has a guide section; options, defaults, limits and error codes match `src/` |
| README | `README.md` (grep `^## ` first, read by section) | The quick start is the recipe verbatim and still demonstrates the documented behaviour; the comparison cites `docs/data/comparison-*.json` |
| Counters | `docs/assets/ecosystem.json` | Every declared count and version equals what the tree holds; `npm run verify:docs` is the oracle, but wording is yours |
| Machine surfaces | `docs/assets/api.json`, `docs/data/errors.json`, `docs/data/diagnostics.json`, `docs/data/limits.json`, `docs/data/surfaces.json`, `docs/llms-index.json` | New exports, codes, diagnostics and limits are listed; removed ones are gone |
| llms files | `llms.txt`, `docs/llms.txt`, `docs/llms-full.txt`, `docs/llms-recipes.txt` | Regenerated (`npm run docs:llms` then `git diff --stat`); the index summaries read as prose |
| Agent files | `docs/agent-brief.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` | New modules and rules named; counts current; the three stay consistent |
| Downstream notes | `release-notes/v<version>.md` §Downstream integration notes | Every new, removed or changed public API and every behaviour shift is listed with the package it affects |
| Recipes | `recipes/*.ts`, `recipes/index.json` | New features have a recipe; `npx vitest run tests/docs/recipes.test.ts` passes |
| Conformance | `docs/guides/conformance.md`, `THIRD-PARTY-NOTICES.md`, `scripts/data/limbo-refusals.json` | Pins and counts match the gate's output; every refusal category the guide names exists in the baseline |

## Method

1. Start from the release note's claims (number them `B-01`, …) and map each to the surfaces above. A claim with no surface is a finding (`major` when the feature is public).
2. For each surface, run the regenerator where one exists and diff; where none exists, read the surface and the code side by side. Quote the line numbers.
3. Reproduce at least one assertion per surface with a command (`npm run verify:docs`, `npm run docs:all`, `npx vitest run tests/docs`, a `node -e` over a JSON surface).

## Autonomy pass (Phase D)

When invoked for Phase D, ignore the table above and answer one question: **can an agent that has only the published docs use every feature without reading `src/`?** For every feature in the release note, write the call you would make from `docs/` + `llms.txt` + `docs/agent-brief.md` alone, then run it (a scratch script importing from `src/index.ts` through tsx, with the fixtures of `tests/fixtures/certs/`). A call that needs `src/` to get right is a finding; name the sentence that was missing.

## Output

Write `test-output/.audit/<version>/auditor-b.md` (or `auditor-d.md` for the autonomy pass) in the finding format of `ledger.md`, every row with its evidence command. Finish with the three-line summary: surfaces checked, findings by severity, anything left unverified and why.

Do not fix anything. Do not push, tag or publish. Never put `npm publish`, `gh release`, `git push` or `git tag <name>` in a Bash command — the guard hook refuses the whole command.
