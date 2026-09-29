# release: v1.0.0 — the freeze, promised

> **Branch:** `chore/release-v1.0.0` → `main`, the first push of the repository (see the steps below: it is pushed, not squash-merged)
> **Type:** Major release, the first one. It is breaking from 0.9.0 in exactly one place: `openPkcs12` has no default RSA scheme ([ADR 0015](../../docs/adr/0015-no-default-rsa-scheme.md)).
> **Milestone:** ROADMAP.md §1.0.0 — M6: The freeze and the first publication

## Summary

This is pkinative's first release, on npm with provenance and on GitHub with an attested tarball. Versions 0.1 to 0.9 are tagged but never released.

- **The three-part compatibility promise**, each part held by a committed snapshot and a rule that fails the build ([SECURITY.md §Compatibility promise](../../SECURITY.md#compatibility-promise), `ecosystem.json → contracts.compatibility`):
  - the export surface;
  - the error vocabulary;
  - the decision surface: 565 promised refusals, and byte-for-byte re-encoding.
- **The publication path, hardened:**
  - it runs from a tag only;
  - it refuses a pre-1.0 version before any approval is asked;
  - it restores no dependency cache;
  - it attests the bytes the registry serves.
- **One engine change: no default RSA scheme** in `openPkcs12` (ADR 0015).
- **Compatibility:** zero runtime dependencies. No export added or removed; one reason code added.

Counts: 282 public exports · 57 error codes (frozen since 0.8.0) · 43 reason codes · 40 diagnostic codes · 64 verify-docs rules · 18 bundle probes · 3 452 tests · 100 % statements, branches, functions and lines.

Conformance, unchanged from 0.9.0:

| Level | Result |
|---|---|
| L5 | 25 clauses |
| L6 | 9 156/9 208 |
| L7 | 195/203 |
| L8 | 221/224 and 196/204 |
| Interop | OpenSSL 4.0.0 and Windows, both directions |

## Changes

### Engine surface

- `openPkcs12`: an RSA key whose certificate is `rsaEncryption` is opened only with `options.rsaAlgorithm`. Without it, the report returns the new reason `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` (RFC 8017 §8), and the file's certificates, CRLs and other keys are still reported.
- `api.frozen.json` moved on ADR 0015 (`--rebaseline`, the second use after ADR 0013), then rebased as `stable` at 1.0.0.
- Mutation testing of `verify-pkcs12.ts`: 100 % (35 killed, 0 survivors, 1 documented equivalent).

### Tooling (scripts/)

- `build-refusals-frozen.ts` and `scripts/lib/refusals-frozen.ts`, with `--ratchet`, `--major` and `--repin`.
- `release-prepare.ts`:
  - rebases or ratchets all three snapshots;
  - swaps the reviewed `PRE_1_0_PROSE` table at 1.0.0;
  - all of it is planned as a pure function.
- New rules: `refusal-baseline-frozen`, `contracts-shape` and `package-files-parity`. `build-errors-frozen.ts` may refresh the `$comment` under the freeze.
- Conformance L1 reads the frozen refusal snapshot directly.

### CI and repository (.github/, root)

- `publish.yml`:
  - a `guard` job with no environment: tag only, tag equals `package.json`, 1.0.0 or later;
  - no `cache: npm`;
  - `attest` fetches the tarball back with `npm pack pkinative@VERSION`;
  - npm@11.19.1 is pinned, checked against the registry.
- `release-assets.yml` is retired.
- `docs/data/package-files.json` lists the twelve files of the tarball.

### Agent layer (.claude/, AGENTS.md, governance)

- The fast gate profile names `verify:samples` in AGENTS.md, CLAUDE.md and copilot-instructions.md.

### Tests and conformance

- The freeze suites run their rehearsal cases on the 0.9 tree rebuilt in memory, and their stable cases on the live tree.
- The release-prepare suite plans 1.0.1 and 1.1.0.
- The workflow suite holds the three `publish.yml` changes.

### Documentation

- Install:
  - `npm install pkinative` everywhere;
  - the stable-era prose applied by the bump;
  - the social card and preview re-rasterised with headless Edge (the stale "0.1 reads, 0.3 verifies" is gone).
- SECURITY.md restructured:
  - Compatibility promise;
  - In place of an external audit;
  - Release integrity;
  - supported versions: the latest 1.x minor.
- ADR 0014 (the decision surface) and ADR 0015 (no default RSA scheme).
- CONTRIBUTING §Release step 11: the one-time npm settings after the first publication.

## Independent audit

`/release-audit release-notes/v1.0.0.md v0.9.0` — PENDING

## Validation (what actually ran, on Windows 11, Node v22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 14 passed, 0 skipped in 1065.6 s` |
| `npm run test:coverage` | 3 452 tests; 100.0 % statements, and the 100 % threshold on all four axes held |
| `npm run verify:bundle` | 18 probes within budget; `*` 262.2 KB of 272 KB, `openPkcs12` 95.1 KB of 104 KB |
| `npx tsx scripts/verify-docs.ts` | 64 rules, 0 errors, 0 warnings |
| conformance (publish gate step) | PASS: L0–L8 against the pinned corpora, 565 refusals held code for code |
| `npm run check:package` | PASS (attw, publint, the tarball file by file) |
| `npm run smoke:install` | PASS: ESM and CJS load from the packed tarball |
| `npm pack --dry-run` | 12 files, 1.1 MB packed, 4.5 MB unpacked |
| `npm ls --omit=dev --all` | `pkinative@1.0.0` alone (empty) |
| `npx tsx scripts/mutate.ts --files src/verify/verify-pkcs12.ts` | 89 mutants: 35 killed, 53 refused by the compiler, 1 equivalent; 100.0 % |

## Backward compatibility

Every export keeps its signature (282, as in 0.9.0). One behaviour change:

- Callers of `openPkcs12` who open RSA containers pass `rsaAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }`, which is the former default.

From here, semver applies to all three parts of the promise.

## Out of scope (tracked in ROADMAP.md)

- `pkinative-cli` and `pkinative-mcp`, after 1.0.0.
- The 37 RFC 5280 §4 requirements not yet diagnosed.
- Taking an `id-RSASSA-PSS` certificate's scheme from its parameters in `openPkcs12`.

## Human-in-the-loop — steps for the maintainer

This is the first push to an empty repository, so the steps differ from the template. `main` must carry the whole linear history, not a squash, so that each 0.x tag lands on an ancestor of `main`.

1. Create the `npm-publish` environment, with yourself as required reviewer: Settings → Environments.
2. Set up and push `main`:
   - `git remote add origin https://github.com/Nizoka/pkinative.git`
   - `git ls-remote --heads origin`: this must print nothing.
   - `git branch -f main chore/release-v1.0.0`, then `git push -u origin main`.
   - Nothing protects `main` yet; that is by design.
3. Import the rulesets: `.github/rulesets/main.json`, then `.github/rulesets/tags.json` (Settings → Rules → Rulesets → Import).
4. Wait for the seven required checks plus CodeQL and Scorecard to go green on `main`.
5. Tag the 0.x line: annotated tags, pushed, with **no GitHub Release**. A tag starts no workflow.

   | Tag | Commit |
   |---|---|
   | `v0.1.0` | `f271a88` |
   | `v0.2.0` | `adeb55f` |
   | `v0.3.0` | `de7a7c2` |
   | `v0.4.0` | `0c63bf5` |
   | `v0.5.0` | `87b9ff6` |
   | `v0.7.0` | `448713c` |
   | `v0.8.0` | `cd9e629` |
   | `v0.9.0` | `353f36e` |

   **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
6. Configure Trusted Publishing on npmjs.com for `pkinative`, bound to `.github/workflows/publish.yml` and the `npm-publish` environment.
7. Tag `v1.0.0` on the tip of `main`, push it, and publish the GitHub Release: title `v1.0.0 — the freeze, promised`, body = `release-notes/v1.0.0.md`.
8. What to expect from `publish.yml`:
   - `guard` passes;
   - `publish` waits for your approval, then runs the publish gate and publishes with provenance;
   - `attest` attaches the registry's tarball and the SBOM.
9. Check the result:
   - `npm view pkinative version` shows `1.0.0`;
   - `npm audit signatures`;
   - `gh attestation verify pkinative-1.0.0.tgz --repo Nizoka/pkinative`;
   - `npm run check:npm-drift`.
10. CONTRIBUTING §Release step 11:
    - require 2FA and disallow tokens on the package;
    - deprecate the `0.0.1` reservation;
    - upload `docs/assets/social-preview.png` in Settings → General → Social preview.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files (plus the two re-rasterised images), nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above — PENDING: this PR is not ready to merge until it is.
