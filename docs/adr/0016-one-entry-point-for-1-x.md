---
status: accepted
date: 2026-10-01
since: 1.0.0
---

# One entry point for 1.x: no subpath export at 1.0; a later minor may add one, never remove it

## Context and Problem Statement

[ADR 0007](0007-no-subpath-exports-before-1-0.md) kept a single entry point through the 0.x line and put the decision on subpath exports (`pkinative/x509`, `pkinative/cms`, …) at 1.0, for the whole module partition at once. It deferred the decision without taking it. This record takes it, because 1.0.0 is the release from which the `exports` map of `package.json` becomes part of the compatibility promise ([SECURITY.md §Compatibility promise](../../SECURITY.md#compatibility-promise)).

The trigger written down at 0.3.0 was 200 000 bytes of `dist/index.d.ts`. On the 1.0.0 tree, built with `npm run build`, the file measures **307 592 bytes**: 154 % of the trigger, and 99.2 % of the 310 000-byte budget that `declared.bundle` in [`docs/assets/ecosystem.json`](../assets/ecosystem.json) sets and the `bundle-check` gate step enforces. Its growth was 182 552 bytes at 0.5.0, 258 879 at 0.7.0, 294 325 at 0.8.0, 296 510 on the 1.0.0 release commit, and 307 592 once the pre-publication audit had landed its fixes (two exports, five diagnostics, the subjectDirectoryAttributes decoder, the error brand): the 0.9 band and the freeze itself added almost nothing.

The same file was then measured as a TypeScript consumer loads it. A one-file consumer importing `pkinative`, compiled by TypeScript 5.9.3 with `skipLibCheck: false` and the ES2020 and DOM libraries, loads 5 671 lines of definitions against 49 324 lines of the standard library, and checks in 1.3 to 2.1 seconds under `moduleResolution: bundler` and `node16`. The declaration file is about a tenth of what the compiler reads for a browser-targeting project.

## Decision Drivers

- **A subpath can be added in a minor and removed only in a major.** Adding `pkinative/x509` breaks no caller; removing or renaming it breaks every import of it.
- **The partition is complete.** 0.8.0 added `keys/`, the last layer; the layering of [AGENTS.md §Architecture](../../AGENTS.md) is what a split would follow.
- **Bundle size does not depend on it.** `scripts/verify-bundle.ts` proves per import that tree-shaking keeps a consumer's bundle to what it imports; a subpath would not make any bundle smaller.
- **Error identity.** `instanceof PkiError` is the documented catch ([docs/guides/errors.md](../guides/errors.md)). Separate entry files, each with its own copy of the `PkiError` classes, would make an error thrown through one subpath fail `instanceof` against the class imported from another.
- **The cost of the single entry is measured, and modest.** The declaration file is read whole, but it is a small part of a TypeScript program's load, as measured above.

## Considered Options

1. Publish subpath exports at 1.0, one per layer, with `.` kept as the complete entry.
2. Keep the single `.` entry for 1.x, and allow a later minor to add subpaths additively.
3. Keep the single `.` entry for the whole of 1.x, and refuse subpaths until 2.0.

## Decision Outcome

Chosen option: 2. Option 1 freezes a module split for the whole major line, one subpath per layer at once, to save a cost the measurement shows is a tenth of a consumer's type load; a split chosen wrong at 1.0 stays wrong until 2.0. Option 3 forbids an additive change that could later be justified, which semver does not require.

What holds for 1.x:

- **`.` stays the complete entry point for the whole major line.** Every export reachable through a subpath is also exported from `.`. `./package.json` stays exported.
- **A subpath export may be added in a minor**, under three conditions: it is recorded in its own ADR that supersedes this one for the partition it adds; the subpaths share one runtime chunk with `.` (tsup `splitting: true`, or an equivalent), so that each `PkiError` class has one identity whatever entry imported it; and `api-surface-frozen` and `check:package` cover the new entry before it ships.
- **A subpath, once published, is removed or renamed only in a major.** Deep imports of files under `dist/` are not a contract: the `exports` map refuses them.

**The next review trigger** is the 310 000-byte budget of `dist/index.d.ts` in `declared.bundle`. A change that needs that budget raised reopens this decision in the same diff: either the raise is argued against the measurement above, repeated on the new tree, or a subpath partition is proposed in a new ADR.

### Consequences

- Good, because no module split is frozen at 1.0, and the one decision that cannot be undone in 1.x — removing a subpath — cannot arise.
- Good, because the error classes keep one identity per build, and a caller's `instanceof PkiError` works whatever they imported.
- Good, because adding subpaths stays possible in a minor if the declaration file becomes a measured problem.
- Bad, because every TypeScript consumer keeps loading the whole declaration file, 307 592 bytes at 1.0.0.
- Bad, because the budget will have to be argued again, rather than raised, the next time a subsystem lands.

### Confirmation

- `tests/tools/workflows.test.ts` holds `package.json` to exactly two exports, `.` and `./package.json`; a subpath added without changing that test fails the suite.
- The `bundle-check` gate step holds `dist/index.d.ts` to its 310 000-byte budget in `declared.bundle`; raising it is a reviewed diff, and this record says what the review must contain.
- `declared.typeSurface` in `docs/assets/ecosystem.json` (171 exported types and 111 values at 1.0.0), held to `docs/assets/api.json` by `type-surface-parity`.
- `docs/assets/ecosystem.json` → `contracts.compatibility.policies.entry-points` states the decision for a program to read, and `contracts-shape` holds it to this record and to SECURITY.md.

## More Information

- [ADR 0007](0007-no-subpath-exports-before-1-0.md), which this record supersedes.
- [`tsup.config.ts`](../../tsup.config.ts) — the single entry, `splitting: false` today.
- Measurement: `npm run build`, then the size of `dist/index.d.ts`; and a consumer compiled with `tsc --extendedDiagnostics`, `skipLibCheck: false`, `lib: ["es2020", "dom"]`, at TypeScript 5.9.3.
