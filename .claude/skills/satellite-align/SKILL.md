---
name: satellite-align
description: Align pkinative.dev and the repository docs on a pkinative-cli / pkinative-mcp release — facts, mechanical edits and worklist from npm run satellites:sync, at most six writers that never read a satellite, one reviewer for behavioural claims only. Run by the maintainer after a satellite release; never invoked by the model on its own.
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Edit, Write, Bash(npm run *), Bash(npx tsx scripts/*), Bash(npx vitest *), Bash(git diff*), Bash(git log*), Bash(git show*), Bash(git status*), PowerShell(npm run *), PowerShell(npx tsx scripts/*), PowerShell(npx vitest *), PowerShell(git diff*), PowerShell(git status*), Agent
argument-hint: cli=<version> mcp=<version>
---

# Satellite alignment

Align pkinative.dev and the repository docs on the satellite versions given as `cli=` and `mcp=` (either or both; an omitted package keeps the version the manifest records). The pass is mechanical wherever `verify:docs` can hold the fact, and written by agents only where prose must change: the facts sheet replaces exploration, the worklist replaces planning, the rules replace the counting audit.

## 0. Preconditions

- The satellite checkouts sit beside this repository (`../pkinative-cli`, `../pkinative-mcp`) at the released tags; another location is passed with `--cli` and `--mcp`. pkinative-cli needs its dependencies installed for the capture (its own `npm ci`, run by the maintainer); pkinative-mcp needs nothing.
- `git status` is clean here and the work happens on a `docs/<topic>` branch, never on `main`.
- Nothing in this skill pushes, tags, publishes or opens a pull request (`.claude/hooks/guard.mjs` refuses those anyway), and nothing is written in a satellite checkout.

## 1. Facts, mechanical edits, worklist — one command

```bash
npm run satellites:sync -- --expect cli=<v> mcp=<v> --capture --apply --worklist
```

It reads each satellite — `<satellite>/docs/assets/surface.json` when the package ships the contract of `surface-contract.md`, else what the package commits plus one capture — and writes the facts and the worklist under `test-output/.satellites/`. `--apply` runs every row of `SATELLITE_EDITS` (`scripts/satellite-sync.ts`): `packages.<name>` of `docs/assets/ecosystem.json` (version, release day, pin, counts, inventories), `docs/assets/versions.js`, the badges, the JSON-LD and `docs/data/cli-surface.json`. A row that finds nothing to rewrite fails the run and nothing is written: fix the row, never the file by hand. A row marked "kept" names a field the surface could not establish; it is listed under "Unverified" in the facts.

Exit 2 means a checkout is not at the version given: stop and tell the maintainer. Never edit a satellite, never install in one.

## 2. Read through `--show`, never with Read

`test-output/` is denied to the Read tool. Every unit is printed by the script, 15 000 characters at most:

```bash
npx tsx scripts/satellite-sync.ts --show facts      # versions, pins, counts, deltas, unverified
npx tsx scripts/satellite-sync.ts --show worklist   # which batches have work
npx tsx scripts/satellite-sync.ts --show B1         # one batch: findings, blind spots, delta
npx tsx scripts/satellite-sync.ts --show cli        # one package with its command lines and flags (mcp: tools and inputs)
```

The coordinator reads `facts` and `worklist`, and `B0` if it has work. It does not read a satellite's `src/`, README, release note or CHANGELOG: a fact missing from the facts is a gap in `scripts/lib/satellite-surface.ts`, fixed there with its test, not looked up by hand.

## 3. Writers — at most six, one batch each, none when there is nothing to write

Spawn one Agent per batch the worklist lists, in one message, each with `writer.md` and the two unit names it reads (it runs `--show` itself; do not paste the units into the brief):

| Batch | Files | Facts unit |
|---|---|---|
| B1 | `docs/guides/cli.md` | `cli` |
| B2 | `docs/guides/mcp.md` | `mcp` |
| B3 | `docs/data/surfaces.json`, `docs/guides/choose.md` | `cli`, `mcp` |
| B4 | `docs/guides/use-cases*.md`, `docs/assets/use-case-*.svg` | `cli`, `mcp` |
| B5 | `README.md`, `llms.txt`, `docs/index.html`, `docs/agent-brief.md`, `docs/guides/errors.md` and the root files `COUNT_SOURCES` reads | `facts` |
| B6 | `docs/playgrounds/{cli,mcp}.{html,js}`, `docs/data/playgrounds.json` | `cli`, `mcp` |

B0 is everything else and is the coordinator's: generated files are regenerated in step 4, never edited. A finding on a generated `docs/guides/*.html` is listed under the batch of its Markdown source, which is the file the writer edits. A patch release with an empty delta and an empty worklist needs no writer and no reviewer: go to step 4.

## 4. Regenerate, then the gate

`npm run docs:all`, then `npm run verify:docs`; repeat after every late edit until it reports no error. `npm run verify:diagrams` only when an SVG changed. Then `npm run satellites:sync -- --capture --apply --dry-run` must report unchanged rows only, and one `npm run gate:fast` must pass. Open `test-output/.gate/<step>.log` for a failing step only.

## 5. Review — one agent, behavioural claims only

Spawn one Agent with `reviewer.md` and the base ref of the pass. Counts, names, versions, release days and pins are held by `satellite-manifest`, `satellite-counts`, `satellite-stamps`, `cli-surface-parity`, `mcp-surface-parity` and `versions-widget`, and are out of its scope; it checks every changed sentence that states a behaviour and lists what it could not verify.

## 6. Pull-request body

Fill `pr-template.md` into `.github/drafts/pr-docs-satellites-<cli>-<mcp>.md` (git-ignored; the maintainer opens the pull request): counts before and after from the facts, the delta of each package, the batches written, the reviewer's table, and every unverified marker under "Explicitly not claimed". Commit as `docs(satellites): pkinative-cli <v>, pkinative-mcp <v>`; do not push.

## Token targets — proposed, not measured

About 600 k subagent tokens for a minor release of both packages (six writers and one reviewer, each reading two units and its own files). Under 30 k, with zero writers, for a patch release with an empty delta. Record what a real pass costs in the pull-request body, so these figures become measurements.

## Known blind spots

- The rules hold counts, names, versions and pins, never that a sentence is true: a sentence copied from a satellite's release note can be wrong. The reviewer's trigger words exist for that.
- Degraded mode cannot see the CLI's flag defaults, its configuration keys, its limit flags or the server's transports, and takes the release day from the tag: each is under "Unverified" until the satellites ship the contract of `surface-contract.md`.
- Social images (`docs/assets/og-image.svg`, `docs/assets/social-preview.svg`) carry engine facts only: a satellite pass never changes them.
- `docs/assets/ecosystem.json` loads no rule of its own on purpose: it is written by the script, and a hand edit there is what `satellite-manifest` exists to catch.
