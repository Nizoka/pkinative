@AGENTS.md

# Claude Code addendum

Everything in AGENTS.md applies. This file adds only what is specific to Claude Code sessions in this repository.

## Token discipline

- Run tests through `npm run gate:fast` or `npx vitest run <file>` (dot reporter); never paste a test run or a gate log into context — the gate summary is ≤ 20 lines, and `test-output/.gate/<step>.log` is opened only for the failing step.
- Never Read `coverage/`, `dist/`, `test-output/`, `node_modules/`, `package-lock.json`, `docs/llms-full.txt`, `docs/llms-index.json`, `docs/llms-recipes.txt`, `docs/playground/pkinative.js`,
  `docs/assets/api.frozen.json`, `docs/data/refusals.frozen.json`, `scripts/data/limbo-refusals.json`, `scripts/data/limbo-score.json` — generated: regenerate them.
  `.claude/settings.json` denies Read on them (Grep/Glob at best effort).
- Large registries (`docs/assets/api.json`, `scripts/data/mutation-equivalents.json`, the requirement inventories) are queried with `node -e`, not opened.
- Read README.md, ROADMAP.md, SECURITY.md by section (`grep -n "^## "`, then a line range); CHANGELOG.md: only the top entry.
- Open the ONE `.github/instructions/*.md` for the area you touch (AGENTS.md §Where is what); the matching `.claude/rules/*.md` loads itself when you read a file in scope.
- Conformance corpora live in `test-output/corpora/` — never read them; query them with `scripts/validate-certs.ts` (after `npm run build`: the runner loads `dist/`).
- After any change under `src/`: `npm run mutate -- --files <changed files>` — 100 % killed; a survivor is a new test or an argued entry in `scripts/data/mutation-equivalents.json`, never ignored.
- When a command exceeds the shell timeout, run it in the background and read only its summary (`--json` for the gate).

## Hooks and permissions in force

- `.claude/hooks/guard.mjs` (PreToolUse on **Bash and PowerShell**) denies `npm publish`/`unpublish`/`deprecate`/`dist-tag`/`version <bump>`, `gh pr|issue create|edit|close|comment` (+ `pr merge`),
  `gh release`, writing `gh api`, any `git push`, `git tag <name>` and `git add --renormalize` — in the whole command, every `&&`/`;`/`|` segment, `$( )`/backticks and
  `sh -c`/`pwsh -Command`/`node -e`/`npx -c` payloads (a quoted string holding one is refused too — write such strings with Edit, never via echo/heredoc).
  Those are the maintainer's acts (.github/AGENT_RULES.md §5) — prepare, then stop. `tests/tools/guard.test.ts` is the rule table's contract.
  No `Co-Authored-By` trailers (`attribution.commit` is `""`).
- `permissions.deny` in `.claude/settings.json` blocks Read on the files above and a subset of the GitHub write commands, **once per shell tool** —
  a family denied for one shell and allowed for another is not denied.
  `permissions.allow` pre-approves `npm run`, `npx vitest`, `npx tsx scripts/*`, `npx tsc`, `npx eslint`, `node -e` and read-only git, likewise per tool.
  `GUARDED_SHELL_TOOLS` (`scripts/lib/agent-config.ts`) is the list; `agent-config-parity` fails on a tool missing either half.

## Rules and plans

- `.claude/rules/*.md` are generated from `.github/instructions/*.instructions.md` by `npm run agents:rules` (scoped by `paths:` = the source `applyTo`).
  Never edit a rule: edit the instruction file, then regenerate (`claude-rules-sync` fails on drift).
- Plans name the files, the commands and the expected gate outcome, and summarise gate output.
- Parallel work: one worktree per lot (`git worktree add -b <branch> D:\Github\pkinative-<x> HEAD`, junctions `node_modules` and `dist` —
  shared `dist` means no build or conformance run inside a worktree); unlink every junction before `git worktree remove`.
