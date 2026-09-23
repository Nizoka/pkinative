# release: v0.1.0 — read-only PKI foundation

> **Branch:** `chore/release-v0.1.0` → `main`
> **Type:** Minor release (the first; no prior version to be compatible with)
> **Milestone:** M1 — read-only foundation (ROADMAP.md)

<!-- This body predates release-notes/PR_TEMPLATE.md. Its content is preserved
     exactly as it was written on 2026-09-19; only the section names were
     brought to the template so the release audit can read them, and the
     "generated with" footer was removed — the self-review checklist of every
     later release forbids one. -->

## Summary

The first milestone (M1) of pkinative: a zero-dependency TypeScript toolkit that reads public-key infrastructure data — strict ASN.1 DER (BER on request), RFC 7468 PEM, object identifiers and complete RFC 5280 X.509 certificates. Zero runtime dependencies (`npm ls --omit=dev --all` lists pkinative alone), 127 public exports, every error code and diagnostic registered, no breaking change possible (first release). Conformance: all 30 361 unique x509-limbo certificates parse or are refused only where every limbo case using them expects failure (564 refusals, each in the reviewed baseline), all 1 530 Wycheproof ECDSA vectors decode strictly, and every parsed certificate agrees with OpenSSL. 0.1.0 is a git tag; nothing is published to npm before 1.0.0.

## What's in it

| Area | Change |
|---|---|
| Core | `PkiError` family with stable codes, eleven CWE-tagged `PkiLimits`, the diagnostics channel (`onDiagnostic`, `strict`), strict text and base64 codecs |
| ASN.1 | Iterative X.690 decoder (DER strict, BER on request), readers for every universal type, DER encoders, byte-identical `encodeAsn1Node`, OID codec |
| PEM | RFC 7468 strict and lax decoding with a required `label`, encoding |
| Fingerprints | SHA-1/256/384/512 over public data, synchronous and Web Crypto; pdfnative's SHA-256 bit-length defect fixed (reported to pdfnative as a local draft) |
| OIDs | `getOidName` and `OID_REGISTRY`, 300+ names with their defining standards |
| X.509 | `parseCertificate`, `getExtension`, `decodeExtensionValue`, `formatDistinguishedName`: every RFC 5280 field and standard extension; RSA, RSASSA-PSS, EC, Ed25519/448, X25519/448 and ML-DSA keys checked |
| Conformance | `scripts/validate-certs.ts` (L0 pins and canaries, L1 parse-or-refuse with a reviewed baseline, L2 byte identity against an independent DER walker, L3 node:crypto and openssl CLI, Wycheproof), `conformance.yml` as a required check |
| Build | `verify:bundle` tree-shaking probes, `docs/assets/api.json`, benchmarks with run context |
| Docs | README, five guides rendered to static pages, llms files, agent brief, five executable recipes, landing page, release note |
| Distribution | `release-assets.yml` attests every pre-1.0 release tarball (Sigstore provenance + CycloneDX SBOM) and attaches it; `npm run smoke:install` proves the packed package installs and loads as ESM and CJS |
| Tooling | `scripts/release-prepare.ts`, the `release-audit` skill, 36 verify-docs rules each with a perturbation test |

## Deferred

- `parsePemCertificates` — dropped by design: `x509` never imports `pem` (as Go separates `encoding/pem` and `crypto/x509`); callers compose `decodePem` and `parseCertificate` (`recipes/pem-bundle.ts`).
- A PNG Open Graph image (audit B-36, minor, waived) — the landing page ships an SVG one; rasterising it needs a renderer the repository does not carry. Export `docs/assets/og-image.svg` and point `og:image` and `twitter:image` at the PNG when convenient.
- A runtime smoke matrix for browsers, Deno, Bun and Workers (audit B-38, note, waived) — the claim holds by construction (no `node:` import, no `process`, no `Buffer`, enforced by the architecture test) and the tarball is smoke-tested on Node; a real matrix is a 0.3 item.
- Continuous fuzzing (ClusterFuzzLite + Jazzer.js) — 0.3, as planned; the seeded suites and the conformance gate cover 0.1.

## Docs & registries

- Release note `release-notes/v0.1.0.md` and the `CHANGELOG.md` entry `## [0.1.0] – 2026-09-19`.
- Manifest `docs/assets/ecosystem.json`: version 0.1.0, `verifiedOn` 2026-09-19, corpus pins and canaries.
- `docs/data/errors.json`, `diagnostics.json`, `limits.json`, `surfaces.json`, `comparison-2026-09-19.json`; `docs/assets/api.json`; `tests/fixtures/PROVENANCE.md`; `THIRD-PARTY-NOTICES.md`.

## Validation (what actually ran, on Windows 11, Node 22.17.0)

The release gate is `npx tsx scripts/gate.ts --publish --require-all`, run on the head of this branch (f271a88) on 2026-09-19 (Node.js 22.17.0, Windows 11):

- [x] `npm run typecheck:all` — clean (src + tests + scripts).
- [x] `npm run lint` — clean.
- [x] `npm run test:coverage` — 1117 tests; 100.0 % statements (thresholds 95 % global, 98 % on the ASN.1 and PEM parsers).
- [x] `npm run build` and `npm run check:package` — ESM, CJS, declarations; attw and publint clean.
- [x] `npm run verify:bundle` — 6 probes within budget, no forbidden marker retained.
- [x] `npm run smoke:install` — the packed tarball installs into an empty project and loads as ESM and CJS, with all 43 runtime exports.
- [x] Conformance — 30 361 limbo certificates (29 797 parsed, 564 refused as the baseline records), 30 361 byte-identical re-encodings, 29 797 node:crypto agreements, 202 openssl CLI agreements, 1 530 Wycheproof vectors; every expectation met.
- [x] `npm run verify:docs` — 36 rules passed.
- [x] `npm ls --omit=dev --all` — pkinative alone.
- [x] Release audit (`.claude/skills/release-audit`) — **GO**. Two auditors, an adversarial verifier, a docs-autonomy pass and a second verifier: 31 confirmed findings, 1 blocker (the documented git install produced a package with no code), 8 major, all fixed in aeca269 and f271a88; 2 waived (B-36 minor, B-38 note, both under Deferred). Ledger and verdict: the session scratchpad (`.claude/settings.json` denies writes under `test-output/`), `ledger.md` and `verdict.md`.

## Human-in-the-loop — steps for the maintainer

- [ ] CI green (`ci (22)`, `ci (24)`, `windows`, `conformance`).
- [ ] `release-notes/v0.1.0.md` reviewed; release date adjusted if the tag is not cut on 2026-09-19.
- [ ] Import `.github/rulesets/main.json` again: it now requires the `conformance` check.
- [ ] Squash-merge to `main` with the title `release: v0.1.0 — read-only PKI foundation`.
- [ ] The maintainer tags `v0.1.0` on the merge commit and publishes the GitHub Release (title `v0.1.0 — read-only PKI foundation`, body = the release note). `publish.yml` refuses a pre-1.0 version by design.
- [ ] Separately, when convenient: publish the npm name placeholder `pkinative@0.0.1` from a scratch folder, then configure Trusted Publishing for 1.0.0.


## Independent audit

`/release-audit release-notes/v0.1.0.md` (no previous tag) — **GO**.

Two auditors, an adversarial verifier, a docs-autonomy pass and a second verifier: 31 confirmed findings — 1 blocker (the documented git install produced a package with no code), 8 major, the rest minor — all fixed in `aeca269` and `f271a88`; 2 waived (B-36 minor, B-38 note, both recorded under Deferred).

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [x] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major.
