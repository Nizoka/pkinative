---
description: "Use when editing what the site says about pkinative-cli or pkinative-mcp (their guides, the use cases, the surface matrix, the two playgrounds, cli-surface.json, versions.js) — after a satellite release or while documenting one. Covers where a satellite fact comes from, the rules that hold it, and the alignment pass."
applyTo: "docs/guides/cli.md,docs/guides/mcp.md,docs/guides/choose.md,docs/guides/use-cases*.md,docs/playgrounds/cli.*,docs/playgrounds/mcp.*,docs/data/surfaces.json,docs/data/cli-surface.json,docs/assets/versions.js"
---
# Satellite alignment

pkinative-cli and pkinative-mcp are separate repositories that release on their own cadence; pkinative.dev documents them. This file says where their facts come from and which rules hold them.

## Source of truth
- A satellite's surface is its `docs/assets/surface.json` when the package ships one (`.claude/skills/satellite-align/surface-contract.md`), otherwise what `npm run satellites:sync -- --capture` derives from the checkout beside this repository. Read it with `npx tsx scripts/satellite-sync.ts --show <facts|cli|mcp>` — `test-output/` is not readable, and no satellite source, README, CHANGELOG or release note is quoted for a fact: pkinative-mcp's CHANGELOG dates 1.0.0 four days before it shipped.
- Versions, release days, pins, counts and inventories live once, in `packages.<name>` of `docs/assets/ecosystem.json`, and are written by `npm run satellites:sync -- --apply`, never by hand; so are `docs/data/cli-surface.json` (a projection of the CLI's own manifest), the `versions.js` FALLBACK rows, the badges and the JSON-LD versions.
- An engine behaviour is proven by `src/` of this repository, cited by file and line. A satellite behaviour is written only when the facts state it (a constraint, a ledger entry); otherwise it is marked `<!-- unverified: … -->`.

## Rules that hold these files
- `satellite-manifest`: `packages.<name>` agrees with itself and with `docs/data/cli-surface.json`.
- `satellite-counts`: every count quoted in prose — tools, prompts, wrapper codes, commands, invocations, error classes, subcommands, schema subjects, groups, environment variables — on a line that says which satellite it counts.
- `satellite-stamps`: every `pkinative-cli X.Y.Z` / `pkinative-mcp X.Y.Z` (also `@X.Y.Z`, the tarball name, "at the vX.Y.Z tag"), "released on <date>" and `pkinative ^X.Y.Z`, in the prose, the playground scripts, the use-case diagrams and `docs/data/surfaces.json`.
- `cli-surface-parity`, `mcp-surface-parity`: the guides and the playgrounds document exactly the commands, flags, error classes, tools, prompts and variables recorded. `surfaces-shape`: every command line and every tool belongs to a capability of `docs/data/surfaces.json`.
- `versions-widget`, `jsonld-version`: the fallback table, the badges and the schema.org nodes.

## Conventions
- A sentence that is history keeps its numbers with `<!-- verify-docs:allow <rule> (historical: …) -->` on the same line or the line above; a floor is written "since pkinative-mcp X.Y.Z" and needs no marker.
- A pin is written `pkinative ^X.Y.Z`; on a line that names one satellite it is that satellite's, anywhere else it speaks for both.
- `docs/guides/*.html` are generated: edit the Markdown, then `npm run docs:guides`. `docs/assets/ecosystem.json` is deliberately outside this file's scope — it is the script's.
- The social images carry engine facts only; a satellite pass never changes them.

A full pass is the maintainer-invoked skill `/satellite-align cli=<v> mcp=<v>` (`.claude/skills/satellite-align/SKILL.md`); CONTRIBUTING.md §Release step 12 is the same pass by hand.
