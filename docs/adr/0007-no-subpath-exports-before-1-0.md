---
status: accepted
date: 2026-09-29
since: 0.3.0
---

# One entry point until 1.0; subpath exports are decided at 1.0, for the whole partition at once

## Context and Problem Statement

pkinative has one entry point, `src/index.ts`, published as the single `.` export of `package.json`. Tree-shaking keeps a consumer's bundle to what it imports, but the declaration file is loaded whole: `dist/index.d.ts` is the fastest-growing artefact the package ships. Subpath exports (`pkinative/x509`, `pkinative/cms`, …) would split it. The question is when, and how, to decide.

At 0.3.0 the plan wrote down a trigger: revisit subpath exports at 1.0 if `dist/index.d.ts` passes 200 000 bytes ([CHANGELOG.md, 0.3.0](../../CHANGELOG.md)). It measured 182 552 bytes after the 0.5.0 verify layer, passed the trigger at 0.7.0, and measured 294 325 bytes at 0.8.0 (the `$comment` of `declared.bundle` in [`docs/assets/ecosystem.json`](../assets/ecosystem.json)).

## Decision Drivers

- A subpath is a public contract: once published it freezes a module split.
- The partition was not complete until 0.8.0 added the `keys` layer; a subpath added earlier would have frozen a split before `keys/` existed.
- The bundle cost of a single entry point is already measured and bounded by tree-shaking, per import.

## Considered Options

1. Add subpaths one at a time, as each layer grows.
2. Keep one entry point through the 0.x line, and decide at 1.0 for the whole partition at once.

## Decision Outcome

Chosen option: 2. When the trigger fired at 0.7.0, the decision stayed where the plan put it — at 1.0, for the whole partition — rather than being taken piecemeal ([release-notes/v0.7.0.md](../../release-notes/v0.7.0.md)). At 0.8.0 the partition the 1.0 decision will weigh is complete. This record defers the decision; it does not take it.

### Consequences

- Good, because no module split is frozen before the last layer exists, and the one decision is taken with the whole surface in view.
- Good, because bundle size does not depend on it: `scripts/verify-bundle.ts` proves per import that, for instance, reading a certificate ships no Web Crypto bridge and verifying a signature ships no parser.
- Bad, because every TypeScript consumer loads the full declaration file, which grew from 182 552 to 294 325 bytes between the 0.5.0 measurement above and 0.8.0.

### Confirmation

- `declared.typeSurface` in `docs/assets/ecosystem.json` (170 exported types and 111 values at 0.8.0), held to `docs/assets/api.json` by `type-surface-parity`, so the surface cannot grow unnoticed.
- The byte budget of `dist/index.d.ts` in `declared.bundle`, enforced by the `bundle-check` gate step; raising it is a reviewed diff.
- The `mustNotContain` markers of `scripts/verify-bundle.ts`, which are never relaxed.

## More Information

- [`docs/assets/ecosystem.json`](../assets/ecosystem.json) — the measurement history in `declared.bundle`, and the trigger in `declared.typeSurface`.
- [release-notes/v0.7.0.md §Downstream integration notes](../../release-notes/v0.7.0.md) — the trigger passed.
