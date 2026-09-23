# release: v0.2.0 — hardened, held to three platforms, and runnable on its own site

> **Branch:** `chore/release-v0.2.0` → `main`
> **Type:** Minor release (additive, fully backward-compatible with v0.1.0)
> **Milestone:** M1b — hardening and site (ROADMAP.md)

## Summary

v0.2.0 adds no public export and changes no decoded value: the engine of v0.1.0 is the engine of v0.2.0, and every one of the 127 exports keeps its signature. What changed is the proof around it. Coverage is 100 % on all four axes by construction; the conformance gate gained a level that confronts pkinative with an implementation written by other people; CI verifies Linux, Windows and macOS; the built package is probed as an artefact rather than trusted as a syntax tree; and the site is now the third copy of the family charter, with two playgrounds that run the published build on bytes the reader chooses.

Counts: 127 public exports · 44 error codes · 26 diagnostic codes · 11 named limits · 49 verify-docs rules · 6 bundle probes · 1198 tests · 100.0 % statements.

## Changes

### Engine surface

None. No export added, removed or re-signed; `docs/assets/api.json` is byte-identical apart from the version it records. One behaviour is stricter, and it can only affect a caller that was already receiving nonsense: `formatDistinguishedName` throws `PKI_INVALID_INPUT` for an `rdns` that is not an array of attributes, where it previously returned a string of commas.

### Tooling (scripts/)

- `scripts/lib/bundle-probe.ts` and the `bundle-check` gate step decide on the artefact rather than the syntax tree: no `node:` specifier, no package, `console` reached exactly once, no fixture marker, no embedded PEM, both declaration files naming every export, every shipped file inside a declared byte budget.
- `scripts/build-playground.ts` copies `dist/index.js` byte for byte into `docs/playground/`, and writes the three derived hashes into the manifest itself rather than printing them to be transcribed.
- `scripts/build-sitemap.ts` derives `docs/sitemap.xml` from the canonical URL each page declares.
- `scripts/release-prepare.ts` gains the six install-URL rewrites it was missing. Before them every release failed `install-url-version` — a rule inside `verify:docs`, a step of every gate profile — and was patched by hand under release pressure.
- `scripts/lib/validators.ts` and `scripts/validators/windows-cryptoapi.ps1` add conformance level L4.

### CI and repository (.github/, root)

- `ci.yml` and `conformance.yml` each become one matrix job whose `name:` decides the status-check name, so the four contexts the ruleset already required keep exactly the names they had, and `macos`, `conformance-windows` and `conformance-macos` are purely additive. Renaming a required check is what leaves every pull request waiting on a context that never reports again.
- `ruleset-parity` now derives check names the way GitHub does, `include:` entries included.
- `CONTRIBUTING.md` §Branch protection corrected from four required checks to seven — it had not followed `main.json` since the three-OS matrix landed.

### Agent layer (.claude/, AGENTS.md, governance)

- `agent-autonomy` becomes a gate step rather than a question asked at review time.
- Coverage thresholds move to 100/100/100/100 with no per-path override, and `coverage-ignore-budget` counts the two justified `v8 ignore`s.

### Tests and conformance

- **Level L4 — cross-implementation confrontation.** There is no veraPDF for the PKI, so the gate confronts instead: 202 sampled x509-limbo certificates are read again by Microsoft CryptoAPI through .NET `X509Certificate2`, and the readings must agree on SHA-256 of exact DER slices — never on anything either side renders. 202 of 202 agree on all five fields. A positive canary unmasks a validator that rejects everything, four structurally broken canaries unmask one that accepts anything, and a footer unmasks one that stops halfway; none of the three can be waived.
- 100 % branch coverage by construction: of 63 uncovered branches, 60 were `?? fallback` expressions that `noUncheckedIndexedAccess` forces after a bound the code has already proved, and they are gone with the code that created them.

### Documentation

- `style.css` 118 → 704 lines, `guide.css` 21 → 298; 115 classes against zipnative's 120. The mark becomes the family tile with a key, and both social cards adopt the family grammar.
- Two playgrounds (certificate inspector, ASN.1 tree) on a byte-for-byte copy of the published build, held fresh in two layers.
- A sixth guide, `use-cases`, with two inline SVG diagrams drawn entirely in design tokens.

## Independent audit

`/release-audit release-notes/v0.2.0.md v0.1.0` — **PENDING**

The audit is a maintainer step (CONTRIBUTING §Release step 5). This pull request is not ready to merge until this section carries a GO verdict and a fix commit for every confirmed blocker and major.

## Validation (what actually ran, on Windows 11, Node 22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 12 passed, 0 skipped in 193.9 s` — every step green, conformance included |
| `npm run gate` (CI profile) | `gate: 11 passed, 0 skipped in 146.5 s` |
| `npm run test:coverage` | 1198 tests, 100.0 % statements (thresholds 100/100/100/100, no per-path override) |
| `npx tsx scripts/verify-docs.ts` | 49 rules, 0 errors, 0 warnings |
| `npx vitest run tests/docs/verify-docs.test.ts` | 60 tests — one perturbation row per rule, exact set equality both ways |
| `npx tsx scripts/gate.ts --publish --only conformance` | `PASS conformance 41.0s` — L0–L4 over the pinned corpora |
| `npm run check:package` | green inside the gate (attw `--profile node16` + publint) |
| `npm run smoke:install` | green inside the gate — ESM and CJS load from the packed tarball |
| `npm pack --dry-run` | **not run** — `check:package` packs the tarball inside the gate; the standalone dry run is a `publish.yml` step |
| `npm ls --omit=dev --all` | **not run** — `dependencies` is absent from `package.json` and `bundle-check` refuses any bare specifier in `dist/` |

## Backward compatibility

Every public export keeps its signature. 127 exports, 44 error codes, 26 diagnostic codes, 11 limits — all unchanged. The registries move their freeze statement from 0.9.0 to 0.8.0, but nothing in either registry changed.

The one behaviour shift is named under *Engine surface* and in the release note's **Downstream integration notes**.

## Out of scope (tracked in ROADMAP.md)

- Signature verification through Web Crypto and certificate creation — 0.3.
- The foreign-tool interop matrix and the clause-by-clause RFC 5280 checker — 0.4.
- Path validation, CRL and OCSP — 0.5.

## Human-in-the-loop — steps for the maintainer

1. Squash-merge to `main` with the title `release: v0.2.0 — hardened, held to three platforms, and runnable on its own site`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.2.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.2.0 — hardened, held to three platforms, and runnable on its own site`, body = `release-notes/v0.2.0.md`).
   Expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. Re-import `.github/rulesets/main.json`: it now requires `macos`, `conformance-windows` and `conformance-macos`, which the repository settings do not yet know about.
6. Upload `docs/assets/social-preview.png` by hand in Settings → General → Social preview.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
