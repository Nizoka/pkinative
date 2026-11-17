---
status: accepted
date: 2026-11-17
since: 1.1.0
---

# What a satellite may implement around the engine, what the engine reserves, and what a satellite must prove

## Context and Problem Statement

Two packages are built on `pkinative ^1.0.0`: `pkinative-cli` and `pkinative-mcp`. Since 1.0 the engine's documentation *describes* them — [the choose guide](../guides/choose.md) says that no surface generates or exports a key, that only the CLI and the MCP sandbox write files, that a satellite adds no PKI decision — and those sentences are a description of the two releases that exist, not a rule a change is held to.

The rulings live in each satellite instead: pkinative-cli in its ADR 0004 (*Offline, and pkinative's refusals are the CLI's*), which lists its uses of `node:crypto`; pkinative-mcp in rule 7 of its `.github/AGENT_RULES.md` (*Anti-goals stay out*). Two repositories, two wordings. The next release of either, or a third satellite, would rule again — and a capability the engine refuses by decision ([ADR 0001](0001-no-secret-dependent-cryptography.md), [ADR 0006](0006-no-network-io-in-the-engine.md), [ADR 0015](0015-no-default-rsa-scheme.md)) could come back one layer up, under the same name, with none of the engine's evidence behind it.

Where is the one rule written, and what does it say?

## Decision Drivers

- A refusal of the engine is a decision with a record. A package that carries the engine's name and fills the gap undoes the decision without amending the record.
- A `PKI_*`, `PKI_REASON_*` or `PKI_DIAG_*` code must mean the same thing on every surface, or a caller that moves from the library to the CLI reads a different verdict from the same bytes.
- A satellite needs room: argv, configuration, a protocol, files and randomness are its job, and the engine does none of them.
- The rule must be checkable by the satellite's own gate, not by a reviewer's memory.

## Considered Options

1. **Keep the rulings in each satellite.** Nothing to write; each repository stays self-contained.
2. **One rule in the engine, as an ADR**, which the satellites cite and which supersedes their own wordings by reference.
3. **Enforce the rule in the engine's gate**, by reading the satellites' sources.

## Decision Outcome

Chosen option: **2**. The engine is the only place every satellite depends on, so it is the only place one rule can live. Option 1 is the situation that produced two wordings. Option 3 would make the engine's gate depend on checkouts it does not own; the engine states the rule and each satellite proves it in its own gate.

A satellite is a package that depends on `pkinative` and presents its capabilities through another surface — a command line, a protocol, a component library.

### A satellite may

- parse argv, configuration and its protocol (the Model Context Protocol), and render reports — tables, JSON Schemas, projections such as `--summary`, `--fields` or a verbosity level;
- read and write files and streams **inside its own trust boundary**: the paths a CLI user names, the sandbox an MCP server is given;
- draw from the host CSPRNG the values the engine does not draw: a serial number when the caller names none, an OCSP or time-stamp nonce, a temporary file name;
- derive, through host cryptography, the **public** half of a key the user already holds, to name the subject key of a certificate or a request;
- hash public bytes it returns or stores;
- carry presentation tables — RFC 4514 short names, algorithm names — that label or classify without deciding anything.

### A satellite may not

- generate or export a key, or write a PKCS#8 or a PKCS#12;
- open a socket in the path that produces a verdict — no CRL, OCSP, AIA or time-stamp fetch that the verdict then depends on;
- re-implement an ASN.1, X.509, CMS, OCSP, CRL or RFC 3161 decision: a structure is read by the engine's reader and judged by the engine's verb, and a satellite adds no reason, no diagnostic and no refusal of its own to them;
- relax a parse outside the engine's own options — BER where the engine was asked for DER, a lenient PEM, a limit raised past what the caller set;
- give RSA a default scheme, or accept SHA-1 without the consent flag the engine defines;
- let a configuration file change an input, a trust anchor, the time a verdict is given for, a limit or an output path — those come from the invocation;
- rename, renumber or reword an engine code: the `PKI_*` code is carried verbatim.

### A satellite must prove

- **Reach.** Every runtime export of the engine version it pins is reached by its surface, or is listed with the reason it is not — a matrix held by a test. A minor of the engine that adds an export leaves the satellite's matrix incomplete until its own next release, and the engine's release note says so under *Downstream integration notes*.
- **Follow-through.** Every bullet of the engine's CHANGELOG between two pinned versions is mapped to a test or to a typed waiver.
- **Wire form.** Reports are serialised in the form [ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md) records, and the registries the satellite vendors — errors, reasons, diagnostics, limits — are the engine's at the pinned tag.
- **Boundary.** A code the satellite defines names only what the satellite owns: validation of its own input, its sandbox, its caps, its output. It never stands for an engine verdict.

### Consequences

- Good: one sentence to cite. pkinative-cli's ADR 0004 and pkinative-mcp's rule 7 become applications of this record; where their wording and this one differ, this one decides.
- Good: a capability the engine refuses cannot return through a satellite without an ADR here that amends the refusal first.
- Good: the descriptive sentences of the choose guide now describe a rule, and say so.
- Bad: the engine cannot enforce it. A satellite that breaks the rule is found by its own gate, by a release audit, or by a reader — which is why the three proofs are tests in the satellite and not prose here.
- Neutral: a satellite may still be *narrower* than the engine. Exposing less is always allowed; the reach matrix only asks that what is left out be named.

### Confirmation

- In the engine: `surfaces-shape` holds `docs/data/surfaces.json`, where a capability names the command and the tool that reach it, and `satellite-manifest` and the two `*-surface-parity` rules hold the site to the satellites' published inventories. Every engine release note carries **Downstream integration notes**, which name the exports, codes and registries a satellite must follow.
- In each satellite: the reach matrix, the CHANGELOG follow-through and the wire form are tests of its own gate; its record of this rule cites this ADR by number.
- In a release audit of either side: a capability on the "may not" list found in a satellite is a finding, whatever its tests say.

## More Information

- [ADR 0001](0001-no-secret-dependent-cryptography.md), [ADR 0006](0006-no-network-io-in-the-engine.md), [ADR 0015](0015-no-default-rsa-scheme.md) — the refusals a satellite inherits.
- [ADR 0012](0012-frozen-error-vocabulary.md) and [ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md) — the vocabularies and the wire form a satellite consumes.
- [docs/guides/choose.md](../guides/choose.md) §Choosing your surface — what the two published satellites do under this rule.
- `docs/data/surfaces.json` — the capability × surface matrix the site shows, held by `surfaces-shape`.
