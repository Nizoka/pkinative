# Reviewer brief — behavioural claims only

You review the diff of a satellite-alignment pass in pkinative and fix what is wrong, in place. Counts, names, versions, release days and pins are out of scope: `verify:docs` holds them (`satellite-manifest`, `satellite-counts`, `satellite-stamps`, `cli-surface-parity`, `mcp-surface-parity`, `versions-widget`). Your scope is every changed sentence that states a behaviour.

## Inputs

- `git diff <base>` of the pass (the coordinator gives the base ref), limited to the documentation: `README.md`, `llms.txt`, `docs/`, the root documents.
- The facts, through the script — `npx tsx scripts/satellite-sync.ts --show cli` and `--show mcp` (15 000 characters each at most; `test-output/` cannot be opened with Read): deltas, constraints, ledger entries, and what is unverified.
- The engine source under `src/` of this repository: the only evidence for an engine behaviour, cited as `src/<file>:<line>`. A satellite's README, release note or CHANGELOG is not evidence, and you do not open a satellite.

## Method

1. Collect every changed sentence containing a trigger word: `never`, `always`, `only`, `default`, `defaults to`, `refuses`, `refused`, `throws`, `rejects`, `silently`, `mutually exclusive`, `never both`, `requires`, `unchanged`, `byte-identical`, `deterministic`, `offline`, `no network`.
2. For each, find the evidence: an engine source line, a constraint or a ledger entry of the facts, a delta line. Record it.
3. Supported: leave it. Contradicted: rewrite it to what the evidence supports, on every surface that repeats it (search the phrase across `docs/`, `README.md`, `llms.txt`). Unsupported: append `<!-- unverified: <claim> -->` and keep it in your list.
4. Known traps: a schema that admits a value does not mean the engine accepts it; a satellite that carries a `PKI_*` code verbatim says nothing about when the engine raises it — read the throw site; "offline" and "no network" are claims about the satellite, supported only by a ledger entry or a constraint; a flag default is never in degraded-mode facts.
5. Do not touch a count, a name, a version, a date or a pin, even one that looks wrong: report it to the coordinator instead.

## Output

A table `claim | file:line | evidence | action (kept / rewritten / unverified)`, then the list of unverified claims. No commit; never push, tag or publish.
