@AGENTS.md

# Claude Code addendum

Everything in AGENTS.md applies. This file adds only what is specific to Claude Code sessions in this repository.

## Token discipline

- Run tests through `npm run gate:fast` or `npx vitest run <file>` (the dot reporter is configured); never paste a full test run into context.
- Never Read `coverage/`, `dist/`, `test-output/`, `node_modules/`, `package-lock.json`, `docs/llms-full.txt`, `docs/llms-index.json`.
  The deny list in `.claude/settings.json` applies to Read and, at best effort, to Grep/Glob — prefer `docs/assets/api.json` lookups over searching them.
- Find an export's module by grepping `docs/assets/api.json` (each export lists its `module`); find internal symbols with Grep `^export function <name>` in `src/`.
- Read README.md and ROADMAP.md by section: `grep -n "^## "` first, then a line range. CHANGELOG.md: only the top entry.
- `.github/instructions/*.md` are the per-area rules: open the ONE matching the area you touch (table in AGENTS.md §Where is what), not all of them.
- In plan mode, summarise gate output; do not paste logs.
- Conformance corpora are downloaded into `test-output/corpora/` — never read them whole; query them with the conformance runner.
- Never push, never open PRs/issues/releases (HITL policy, hook-enforced). No `Co-Authored-By` trailers (`attribution.commit` is `""`).

## Gate

- `npm run gate:fast` — typecheck:all, lint, test, verify:docs. Run before proposing a commit.
- `npm run gate` — the CI profile (default).
- `npx tsx scripts/gate.ts --publish --require-all` — everything. Release branches only.
- `--only <step>` for one step, `--json` for machine output; logs in `test-output/.gate/<step>.log` — open only the failing step's log.
- When the gate exceeds the Bash timeout, run it in the background; read the result with `--json` and open only the failing step's log.

## Where to look first

1. `docs/assets/api.json` — the public surface and the module of every export.
2. AGENTS.md §Where is what — the path → purpose → instruction-file table.
3. `docs/assets/ecosystem.json` — every count and version; `npm run verify:docs` enforces it.
4. `docs/data/errors.json` — every error code, when it is raised, its remedy, standard and CWE.

## Hooks and permissions in force

- `.claude/hooks/guard.mjs` (PreToolUse on Bash) denies `npm publish`/`unpublish`/`deprecate`/`dist-tag`/`version <bump>`, `gh pr|issue create|edit|close|comment` (+ `pr merge`),
  `gh release`, writing `gh api`, any `git push`, `git tag <name>` and `git add --renormalize` — in the whole command, every `&&`/`;`/`|` segment, `$( )`/backticks and
  `sh -c`/`pwsh -Command`/`node -e`/`npx -c` payloads (a quoted string holding one is refused too — write such strings with Edit, never via echo/heredoc).
  Those are submitted by the maintainer (.github/AGENT_RULES.md §5) — prepare, then stop. `tests/tools/guard.test.ts` is the rule table's contract.
- `permissions.deny` in `.claude/settings.json` blocks Read on the generated bulk files listed above and a subset of the GitHub write commands (the guard hook enforces the full list).
  `permissions.allow` pre-approves `npm run`, `npx vitest`, `npx tsx scripts/*`, `npx tsc`, `npx eslint`, `node -e` and read-only git.

## Plan mode

Plans name the files, the commands and the expected gate outcome; keep gate output to its ≤ 20-line summary.

## Rules

- `.claude/rules/*.md` are generated from `.github/instructions/*.instructions.md` by `npm run agents:rules` (scoped by `paths:` = the source `applyTo`).
  Never edit a rule: edit the instruction file, then regenerate (`verify:docs` rule `claude-rules-sync` fails on drift).

## Release

Follow CONTRIBUTING.md §Release: prepare everything (version, changelog, release note, manifest, the publish gate) and stop before tagging or pushing.
