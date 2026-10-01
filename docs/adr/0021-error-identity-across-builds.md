---
status: accepted
date: 2026-10-01
since: 1.0.0
---

# Error identity across builds: a shared brand answers `instanceof`, and the dual package stays

## Context and Problem Statement

`package.json` sends `import` to `dist/index.js` and `require` to `dist/index.cjs`. An application whose dependencies load pkinative both ways — one through ES modules, another through CommonJS — holds two copies of every class, and an error thrown by one copy failed `instanceof` against the class imported from the other. The errors guide teaches `error instanceof PkiError` ([docs/guides/errors.md](../guides/errors.md)), so the documented catch silently missed the other copy's errors; the same holds across realms (an iframe, a worker, a `vm` context). The pre-publication audit of 1.0.0 recorded it (I-02), and once published the behaviour could not be changed without breaking someone, in either direction.

## Decision Drivers

- The documented way to branch on an error must hold whatever loaded the package; a contract that depends on the caller's bundler is not one.
- Dropping the CommonJS build, or raising the Node.js floor to the first release that loads an ES module through require without a flag, would remove the hazard but change who can install 1.x — a decision about the support policy ([ADR 0017](0017-runtime-and-toolchain-support.md)), not about errors.
- The classes are the only classes in `src/` (AGENTS.md), and their declared shape is frozen with the export surface: whatever answers `instanceof` must not change what the `.d.ts` says.
- No module-level side effect (`sideEffects: false`), and the zero-dependency rule.

## Considered Options

1. Ship ES modules only, or require a Node.js release that loads ES modules through require, so there is one copy.
2. Keep the dual package and document the hazard: tell callers to branch on `error.code`.
3. Keep the dual package and make `instanceof` recognise an error from any copy: every error carries a brand under `Symbol.for('pkinative.PkiError')` naming its family, and each class answers `Symbol.hasInstance` from it.

## Decision Outcome

Chosen option: 3. Every `PkiError` is marked, non-enumerably, with its family name under a symbol every copy and every realm of one agent shares; each class installs `Symbol.hasInstance` from a static block, accepting its own instances as before and, failing that, an `Error` whose brand names its family (`PkiError` accepts every family, so an error class a newer copy adds is still a `PkiError` to an older one). The static block leaves the declared shape of each class untouched, so `instanceof` keeps narrowing through the constructor type and the export surface does not move. A caller's own subclass keeps the ordinary `instanceof`. Branching on `error.code` remains the most robust test and needs none of this.

### Consequences

- Good: `error instanceof PkiError`, and `instanceof` any subclass, works for an error from the ESM build beside the CJS build, and across realms.
- Good: nothing changes for a caller who loads one copy; the CommonJS build stays for everyone who needs it.
- Bad: esbuild lowers the static blocks at the ES2020 target, so the error classes no longer tree-shake: about 1.3 KB on every bundle probe, recorded with the budgets of `scripts/verify-bundle.ts`.
- Bad: an object that forges the brand passes `instanceof`. The brand is a debugging and routing aid, not a security boundary; nothing in pkinative decides trust from `instanceof`.
- Not changed: module-level state is still duplicated across the two copies, but pkinative keeps none that matters to a verdict — limits and options are per call.

### Confirmation

- `tests/tools/dual-package.test.ts` loads `dist/index.js` and `dist/index.cjs` in one process and asserts `instanceof` both ways, with the subclass preserved; the gate requires the build (`GATE_REQUIRE_ARTIFACTS`).
- `api-surface-frozen` holds the declared shape of every error class.

## More Information

- Node.js documentation, "Dual package hazard" (packages, conditional exports).
- MDN, `Symbol.hasInstance` and `Symbol.for`.
- The same hazard exists in pdfnative and zipnative; the family note is drafted for pdfnative's maintainer.
