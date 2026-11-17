# docs(satellites): pkinative-cli {{cli.version}}, pkinative-mcp {{mcp.version}}

> Local draft of the pull-request body, written to `.github/drafts/pr-docs-satellites-<cli>-<mcp>.md` (git-ignored). The maintainer opens the pull request.

## Summary

Documentation-only pass aligning pkinative.dev and the repository docs on pkinative-cli **{{cli.version}}** (released {{cli.releasedOn}}, pins `{{cli.pin}}`) and pkinative-mcp **{{mcp.version}}** (released {{mcp.releasedOn}}, pins `{{mcp.pin}}`). No runtime change: nothing under `src/`.

## Mechanical edits (`npm run satellites:sync -- --apply`)

{{apply.lines}}

## Counts before → after

| Package | Counter | Before | After |
|---|---|---|---|
{{counts.rows}}

## What changed in each package (delta)

{{delta.bullets}}

## Written changes by batch

{{batches.summary}}

## Review

{{review.table}}

## Explicitly not claimed

{{unverified.list}}

## Verification

- `npm run verify:docs` — {{verify.summary}}.
- `npm run satellites:sync -- --capture --apply --dry-run` — {{dryrun.summary}} (unchanged rows only).
- `npm run gate:fast` — {{gate.summary}}.
- The social images are unchanged: a satellite pass carries no engine fact.

## Cost

Subagent tokens: {{tokens.writers}} for {{writers.count}} writer(s), {{tokens.reviewer}} for the reviewer. The skill's targets are proposals until a pass like this one measures them.

## After the merge

- Deploy pkinative.dev, then `npm run check:npm-drift` once: the registry's `latest` against the manifest.
- Satellite-side follow-ups: {{followups}}
