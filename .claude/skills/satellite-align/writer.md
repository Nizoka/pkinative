# Writer brief — satellite alignment

You update one batch of pkinative's documentation after a pkinative-cli or pkinative-mcp release. The coordinator gives you this brief, your batch (`B1`…`B6`) and the facts units to read. That is your whole input.

## Inputs

Run these yourself; each prints at most 15 000 characters. `test-output/` cannot be opened with Read.

```bash
npx tsx scripts/satellite-sync.ts --show B<n>      # your batch: verify:docs findings, blind spots, the surface delta
npx tsx scripts/satellite-sync.ts --show cli       # or mcp, or facts — the unit(s) the coordinator named
```

- Facts: versions, release days, pins, counts, lists, command lines with their flags, tools with their inputs, deltas, constraints, ledger entries. Every number, name and date you write comes from the facts; never compute, infer or remember one.
- Batch: each finding names a file, a line, the rule and the expected value.

## Method

1. Edit only the files of your batch. A finding on a generated `docs/guides/<name>.html` is fixed in `docs/guides/<name>.md`; never edit the HTML, never run a generator.
2. Fix every line of the batch, then search the same file for the stale value it names and fix the siblings the rule did not reach.
3. Each delta entry — an added command line, flag, tool, tool input, variable, error class, wrapper code — becomes its section, row or sentence where the file documents that kind of thing, in the voice of the neighbouring entries. A removed entry is deleted, not kept as history.
4. A sentence that is history keeps its numbers and carries `<!-- verify-docs:allow <rule> (historical: …) -->` on the same line or the line above — never below. A floor is written "since pkinative-mcp X.Y.Z" and needs no marker.
5. English only; keep the file's line endings (LF) and the house style of the surrounding text. No emoji.
6. A fact you need and do not have: write `<!-- unverified: <what> -->` beside the sentence and list it in your report. Do not open any path outside this repository, do not read a satellite's source, README or release note, and do not run `verify:docs` (the coordinator does).
7. A sentence that states a behaviour — "refuses", "defaults to", "never", "always", "only" — is written only when the facts, a constraint or a ledger entry states it; otherwise mark it unverified. A flag default is never in degraded-mode facts: do not write one.

## Output

The files you changed, the unverified markers you left, nothing else. No commit.
