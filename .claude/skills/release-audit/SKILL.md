---
name: release-audit
description: Pre-release audit of pkinative — two parallel auditors (claims vs code; docs, counters and machine surfaces), an adversarial verifier, a docs-autonomy pass and a GO/NO-GO ledger under test-output/.audit/<version>/. Run by the maintainer before every release; never invoked by the model on its own.
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Bash(npm run *), Bash(npx tsx scripts/*), Bash(npx vitest *), Bash(git diff*), Bash(git log*), Bash(git show*), Agent
argument-hint: [release-notes/vX.Y.Z.md] [previous-tag]
---

# Release audit

Audit the release described by `$0` (default: the newest `release-notes/v*.md`) against everything that changed since `$1` (default: the previous `v*` tag from `git tag -l`, or the root commit for the first release). The audit produces findings, never fixes: every fix goes through the normal edit → gate loop afterwards, and the ledger records what was fixed.

Read `ledger.md` first for the ledger and verdict formats. Each phase below hands a template to the agents it spawns; the agents return findings, you file them.

## Ledger location

`test-output/.audit/<version>/` — `test-output/` is git-ignored (check `.gitignore` covers it before writing), so nothing here is ever committed. One Markdown file per report: auditor-a, auditor-b, verifier-1, auditor-d, verifier-2, then the ledger and the verdict (formats in `ledger.md`).

## Phase A and B — two auditors, in parallel

Spawn both with the Agent tool in the same message (distinct angles; neither sees the other's report):

- **Auditor A — claims vs code.** Template: `auditor-a.md`. Every claim in the release note and the top CHANGELOG entry is checked against `src/`, `tests/`, the recipes and the conformance gate; at least one assertion per claim is *reproduced with a command* (a test, a recipe, the conformance run), not inferred from reading.
- **Auditor B — docs and machine surfaces.** Template: `auditor-b.md`. Guides, the README quick start, `docs/assets/ecosystem.json` counters, `docs/data/*.json`, `docs/assets/api.json`, `llms.txt`, `docs/agent-brief.md`, downstream integration notes — every surface an agent or a downstream package reads — compared with the behaviour that actually shipped.

Both write their report in the finding format of `ledger.md` (id, severity, claim, evidence command, observed, expected).

## Phase C — adversarial verifier

Spawn one verifier (template: `verifier.md`) with both reports. It re-derives every finding from scratch — re-runs the evidence command, reads the cited lines — and stamps each one `CONFIRMED | DOWNGRADED | REJECTED | DUPLICATE` with a one-line justification. Auditors have about 10 % false findings; the verifier exists to keep them out of the ledger. A finding the verifier cannot reproduce is `REJECTED`, not "probably fine".

## Phase D — docs autonomy pass, then verify

**The mechanical half is `npm run gate`; do not re-derive it.** Whether every name is written down, every option field named, every extension kind listed, every interface member described, every export demonstrated by a recipe that runs and every machine surface in step with the package is decided on every run by `export-named`, `member-tsdoc`, `option-fields-named`, `extension-kinds-complete`, `surfaces-parity`, `install-url-version` and the `tests/docs/recipes.test.ts` assertions. Re-deriving them costs tokens and, worse, fills the report with findings the gate already proved green — which trains the reader to skim. Cite the rule ids instead.

Spawn Auditor D (template: `auditor-b.md`, section "Autonomy pass") for the four things no rule can decide:

1. **Is the sentence true?** `count-tokens` proves a number matches its source; nothing proves "results are frozen and hold views of the input" is still true of the code. Pick claims, not names, and reproduce each with a command.
2. **Is the advice still the best advice?** "Compose `decodePem` and `parseCertificate`" becomes incomplete, without becoming false, the day signature verification lands.
3. **Is the ordering right?** An agent reading `llms-full.txt` top to bottom meets the security model before the quick start, or the reverse. Token budget, ordering and lede quality are judgement.
4. **Cross-surface coherence.** `error-parity` proves the *codes* match between `docs/data/errors.json` and the throw sites; it cannot read the remedy text, or tell whether the guide's remedy and the thrown message say the same thing.

Then a second verifier pass (template: `verifier.md`) over its findings.

## Phase E — GO / NO-GO

Merge the confirmed findings into the ledger, then write the verdict file (both formats are in `ledger.md`):

- **GO** — no CONFIRMED finding of severity `blocker`; every `major` has a fix commit or an explicit maintainer waiver in the ledger.
- **NO-GO** — otherwise. List the blockers first, each with its evidence command, so the fix loop starts from the ledger, not from memory.

Report the verdict, the counts per severity and per stamp, and the ledger path. Do not push, tag, open a PR or publish: the maintainer takes over from `GO`.

## Known blind spots

Add a check for each of these to the auditor briefs; they are where audits of the native family missed something.

- Machine surfaces lag behind prose: `docs/data/errors.json`, `docs/data/diagnostics.json`, `docs/data/surfaces.json`, `docs/llms-index.json` and `docs/agent-brief.md` are updated after the guides, and sometimes not at all.
- Recipes drift from behaviour changes: a recipe that still runs is not a recipe that still demonstrates the documented behaviour.
- Regex-driven `verify:docs` rules are blind to wording: they prove counts, versions, links and presence, never that a sentence is true. That blindness is the whole remaining brief of Phase D — everything the rules *can* decide, they now decide on every run.
- The conformance baseline can hide a regression: a refusal moved to another code is caught, but a certificate that should never have been refused needs a human reading of `scripts/data/limbo-refusals.json` against the limbo case descriptions.
- CI assumptions live outside the repo: trusted publishing needs npm >= 11.5.1 on the runner; a green local gate proves nothing about the publish job.
- Auditors have ~10 % false findings — never file an unverified finding, and never let a `REJECTED` one reach the verdict.
- Publish-related strings in a Bash command trip the guard hook (`.claude/hooks/guard.mjs`): anything containing `npm publish`, `gh release`, `git push` or `git tag <name>` inside a segment, a `$( )`, or an interpreter payload is refused. Write such strings into files with Edit or Write, never through `echo` or a heredoc.
