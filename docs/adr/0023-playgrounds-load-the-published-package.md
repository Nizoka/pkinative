---
status: accepted
date: 2026-10-17
since: 1.0.0
---

# Playgrounds load the published package from a CDN, pinned to the documented version; the local engine copy is retired

## Context and Problem Statement

Until 1.0.0 pkinative was not on npm, so the playgrounds could not do what the pdfnative and zipnative playgrounds do — import the published package from a CDN. They ran a committed byte-for-byte copy of `dist/index.js` (`docs/playground/pkinative.js`, 543 kB), held to the build by a `playground-freshness` rule, a `docs:playground-fresh` gate step and a `declared.playgroundBundle` block of hashes in `docs/assets/ecosystem.json`. pkinative 1.0.0 is published, and its two satellites — pkinative-cli and pkinative-mcp — are too. The copy now answers a question that no longer exists, at the cost of half a megabyte in every clone, a generated file agents must be told not to read, and three pieces of tooling whose only job is to keep it honest. The site also moved its playgrounds from `/playground/` to `/playgrounds/`, the path both siblings use.

## Decision Drivers

- What a playground runs must be what a reader installs: a demonstration of bytes nobody can `npm install` demonstrates nothing.
- Family parity: one loader pattern across pdfnative, zipnative and pkinative, so a fix found on one site applies to the others.
- Untrusted input: a playground is fed hostile bytes on purpose, so the engine it runs must be the hardened release, not a development build.
- Supply chain: a third-party script must be pinned. Subresource Integrity covers `<script src>` and stylesheets, not a dynamic module import, and esm.sh serves a build that varies with the requesting browser, so no single hash could pin it.
- Published URLs stay served: pkinative.dev has been public since 2026-10-04.

## Considered Options

1. Keep the committed copy and its freshness tooling.
2. Import the published package from a CDN, pinned to an exact version: esm.sh first, jsDelivr's `+esm` build second, each verified by a capability probe; no local fallback.
3. Self-host a copy of the published tarball's `dist/index.js` at the pinned version, fetched at deploy time.

## Decision Outcome

Chosen option: 2, the pattern pdfnative and zipnative already ship. `docs/playgrounds/load-engine.js` declares `const VERSION`, imports `https://esm.sh/pkinative@${VERSION}` and falls back to `https://cdn.jsdelivr.net/npm/pkinative@${VERSION}/+esm`; a build that does not export `parseCertificate` and `decodeAsn1` is refused, and an unreachable CDN is reported on the page, never papered over. Every playground names the CDN and version that served it in its footer. The `cdn-pin` rule holds `VERSION` to `packages.pkinative.version` of the manifest, refuses a local engine import or any other remote import in a playground script, and refuses the retired bundle and its manifest block; `scripts/release-prepare.ts` moves the pin on every release. The sample certificates stay first-party (`docs/playgrounds/samples.js`, generated from the test fixtures by `scripts/build-playground-samples.ts` and checked by the `docs:playground-samples-fresh` gate step). The three `/playground/` URLs remain as `noindex` redirect stubs, held to their targets by the `redirect-stubs` rule.

### Consequences

- Good, because the playgrounds run the npm release at its exact version (the CDN's ES-module build of its tarball), as the siblings' do, and the repository loses 543 kB of generated code and the tooling that policed it.
- Good, because a version bump is one line, moved by the release script and refused by `cdn-pin` if forgotten.
- Bad, because an export under `[Unreleased]` cannot be demonstrated until it ships, and the playgrounds depend on two CDNs being reachable; the failure is loud, not silent.
- Bad, because the engine import carries no integrity hash. It is pinned to an exact version on two independent CDNs serving npm's immutable tarball; `cdn-sri` keeps requiring SRI on every `<script src>` and stylesheet.

### Confirmation

`cdn-pin` and `redirect-stubs` in `npm run verify:docs`, each with a perturbation in `tests/docs/verify-docs.test.ts`; the release rehearsal in `tests/tools/release-prepare.test.ts` asserts the pin moves with the manifest. The documentation workflow's accessibility job allows `esm.sh:443` and `cdn.jsdelivr.net:443`, the two hosts the loader may reach.

## More Information

Option 3 was rejected: a deploy-time fetch adds a build step to a site that has none, and reproduces the copy this record retires. pdfnative's and zipnative's loaders are the reference implementations; zipnative made the same move in its `docs/ecosystem-1.0` branch.
