@AGENTS.md

# Claude Code addendum

Everything in AGENTS.md applies; this file holds only what is specific to Claude Code sessions in this repository.

- Run tests through `npm run gate:fast` or `npx vitest run <file>` (dot reporter); never paste a run into context. A failing gate step prints the last 12 lines of its log;
  a command past the shell timeout runs in the background (`--json` for the gate).
- Never Read `coverage/`, `dist/`, `test-output/`, `node_modules/`, `package-lock.json`, `docs/llms-full.txt`, `docs/llms-index.json` or the other generated files
  `permissions.deny` lists: regenerate them, or query them with `node -e`, as the large registries (`api.json`, `mutation-equivalents.json`, the requirement inventories).
- Read README.md, ROADMAP.md, SECURITY.md by section (`grep -n "^## "`, then a line range); CHANGELOG.md: only the top entry.
- Area rules `.claude/rules/*.md` load themselves when you read a file in their `paths`; do not open `.github/instructions/` (the same text),
  and never edit a rule: edit the instruction file, then `npm run agents:rules`.
- Conformance corpora are queried with `scripts/validate-certs.ts`, after `npm run build` (the runner loads `dist/`).
- `.claude/hooks/guard.mjs` (PreToolUse on `Bash|PowerShell`) denies the maintainer's acts — publishing, pushing, tagging, `gh` writes — in every segment
  and quoted payload of a command (.github/AGENT_RULES.md §5): prepare, then stop. A commit message that names one goes in a file (`git commit -F`). No `Co-Authored-By` trailer.
- Plans name the files, the commands and the expected gate outcome, and summarise gate output.
- Parallel work: one worktree per lot (`git worktree add -b <branch> D:\Github\pkinative-<x> HEAD`, junctions `node_modules` and `dist` —
  shared `dist` means no build or conformance run inside a worktree); unlink every junction before `git worktree remove`.
