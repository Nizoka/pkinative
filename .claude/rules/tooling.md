---
paths:
  - "scripts/**"
  - ".github/**"
---
<!-- GENERATED from .github/instructions/tooling.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# Tooling rules (scripts/, .github/)

## The gate and its steps
- `scripts/gate.ts` `STEPS` is the list; a step has a profile (`fast`, `ci`, `publish`), a log in `test-output/.gate/<step>.log` and a ≤ 20-line summary. Adding a step: add it to `STEPS`, to the profile table in AGENTS.md and CLAUDE.md, and to `docs/assets/ecosystem.json` if a count quotes it.
- Scripts are pure Node + tsx, zero dependencies, `node:` imports allowed here (never under `src/`); `scripts/lib/` holds what two scripts share.

## verify-docs rules
- A rule lives in `scripts/verify-docs/rules/<area>.ts` with `id`, `summary`, and a `run` that returns `error(file, message)` items; it is registered in the area's list. Every rule has a **perturbation test** in `tests/docs/verify-docs.test.ts` that breaks the thing it holds and asserts the rule fails — a rule without one is not a rule.
- Rules read registries (`docs/data/*.json`, `docs/assets/ecosystem.json`) and sources; they never read `dist/` or `coverage/`. Counts live once, in `ecosystem.json`.
- Parity rules come in pairs: both directions (`error-parity`, `diagnostics-parity`), source ↔ generated (`claude-rules-sync`, `api-json-fresh`), text ↔ code (`layer-parity`, `bench-parity`, `export-exercised`).

## Runners
- Conformance: `scripts/validate-certs.ts` loads `dist/index.js` — `npm run build` first. Corpora are pinned in `scripts/lib/corpora.ts` (commit + SHA-256), downloaded to `test-output/corpora/`, never committed, never read whole. Baselines (`scripts/data/limbo-*.json`) change only through `--update-baseline`, every changed entry reviewed.
- Mutation: `scripts/mutate.ts` (`--files a,b`), sandbox under `test-output/mutation/`; equivalents in `scripts/data/mutation-equivalents.json` keyed `<file>:<line>:<column>:<operator>` — ids drift when lines move; re-anchor them, never delete them silently.
- Frozen snapshots: `scripts/build-{api,errors,refusals}-frozen.ts` — `--ratchet` in a stable phase, `--major` only for a new X.0.0, never hand-edited.

## .github/
- Workflows pin every action by SHA (Dependabot owns bumps — never edit a pin by hand), least-privilege `permissions:`, harden-runner where network egress is known. `tests/tools/workflows.test.ts` holds the shape; zizmor and actionlint run in the audit workflow.
- The release path is split: the job that builds cannot publish (ADR 0019). `publish.yml` refuses pre-1.0 tags.
- Governance: `.github/AGENT_RULES.md` (prose) and `.github/ai-governance.json` (machine-readable) say the same thing; `governance-sources` holds the always-loaded sources under 16 KiB.

## Claude Code configuration
- `.claude/settings.json`: every `permissions.allow`/`deny` shell entry exists for **each** tool in `GUARDED_SHELL_TOOLS` (`scripts/lib/agent-config.ts`); `agent-config-parity` fails otherwise. `.claude/hooks/guard.mjs` is tested by `tests/tools/guard.test.ts` — a new denied family is a row there first.
- `.claude/rules/*.md` are generated (`npm run agents:rules`) from `.github/instructions/*.instructions.md`; each instruction file has `applyTo`, so no rule loads unconditionally (`claude-rules-budget`).
