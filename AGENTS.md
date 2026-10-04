# AGENTS.md

Editor-agnostic guidance for AI coding agents. Detail: [.github/copilot-instructions.md](.github/copilot-instructions.md) + [.github/instructions/](.github/instructions/) (one file per area, table below).
Claude Code loads [CLAUDE.md](CLAUDE.md), which imports this file.

## Mission and constraints

pkinative is a zero-runtime-dependency TypeScript toolkit for PKI data — X.690 DER/BER, RFC 7468 PEM, OIDs, RFC 5280 certificates, paths and revocation, CMS and timestamps, PKCS#8/#12 —
third library of the *native* family ([pdfnative](https://github.com/Nizoka/pdfnative), [zipnative](https://github.com/Nizoka/zipnative)).

- **Zero deps.** Never add a runtime dependency; a dev dependency needs a written justification in the pull request that adds it.
- **No secret-dependent cryptography.** No key generation, no arithmetic on secrets, no signature algorithm in TypeScript: signing and verification are one Web Crypto call with the caller's key;
  hashing covers public data only.
- **No classes, no module-level side effects.** Closure factories; the only classes are the `PkiError` family (`src/types/pki-errors.ts`).
- **TypeScript strict** + `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`; no `any`; ESM-first; `.js` import extensions; one entry point, `src/index.ts`.
- **Untrusted input everywhere.** Every loop over input bytes consults a named, CWE-tagged limit (`src/core/pki-limits.ts`); the decoder is iterative; DER is strict by default.
- **Throw or diagnose, never both.** Structural failures throw a `PkiError` subclass (stable `code`, message `pkinative: …` naming the remedy).
  Conformance concerns go through `src/core/pki-diagnostics.ts`, the only module that may `console.warn` (`onDiagnostic` redirects; `strict: true` refuses `warning` diagnostics, still reports `info`).
- **No I/O in the engine.** No `node:` imports, `process`, filesystem, network, `eval`, dynamic `import()` — `tests/tools/architecture.test.ts` decides from the syntax tree.
- **Human-in-the-loop.** Agents draft and verify; the maintainer pushes, tags, opens PRs/issues and publishes.
- **English everywhere**; another language only as demonstrated content marked `demo-language: <tag> (reason)`.

## The gate

`scripts/gate.ts` (`STEPS` is the list); logs in `test-output/.gate/<step>.log`, summary ≤ 20 lines.

| Profile | Command | Runs |
|---|---|---|
| Fast — before every commit | `npm run gate:fast` | typecheck:all, lint, test, verify:samples, verify:docs, check:guides |
| CI — the default | `npm run gate` | the CI profile |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | everything |

`--only <step>`, `--json`. One suite: `npx vitest run tests/<path>.test.ts`.
After a change under `src/`: `npm run mutate -- --files <files>` → 100 % killed (a survivor is a test or an argued entry in `scripts/data/mutation-equivalents.json`).
Conformance L0–L8: `npm run build`, then `npx tsx scripts/validate-certs.ts` (it loads `dist/`).

## Where is what

| Path | Purpose | Read first (`.github/instructions/`) |
|---|---|---|
| `src/types/` | `PkiError` family, code unions, public types | `api-design` |
| `src/core/` | Limits, diagnostics sink, bytes/text/base64 | `security` |
| `src/asn1/`, `src/pem/`, `src/oid/` | X.690 decoder and readers, time, OID codec, encoders; RFC 7468; OID names | `pki-core` |
| `src/hash/` | Hashes over public data, fingerprints | `performance` |
| `src/x509/` | RFC 5280 certificates and requests: envelope, names, SPKI, every extension | `pki-core` |
| `src/crypto/`, `src/keys/` | The Web Crypto door, algorithm tables, DER ↔ P1363; PKCS#8/#12 | `security` |
| `src/build/`, `src/cms/` | Structural encoders, signed certificates and CSRs; RFC 5652 and RFC 3161 | `pki-core` |
| `src/path/`, `src/revocation/`, `src/verify/` | §6 paths, §5 revocation, OCSP; `verify/` composes them and alone turns a `PkiError` into a reason | `decision` |
| `src/index.ts` | The single entry point, ten numbered sections | `api-design` |
| `tests/` | Suites mirroring `src/`, plus fuzzing, security, property, performance, conformance, tools, docs | `testing` |
| `scripts/`, `.github/` | Gate, verify-docs rules, generators, conformance and mutation runners; workflows, governance | `tooling` |
| `docs/` | pkinative.dev: guides, `data/` registries, llms files, `assets/ecosystem.json` | `api-design` |

## Architecture

Layering enforced from `LAYERS` in `scripts/lib/architecture.ts` (`layer-parity` holds this diagram to it):

```
types  → (nothing)
core   → types
hash   → types, core
asn1   → types, core
pem    → types, core
oid    → (nothing)
x509   → types, core, asn1
crypto → types, core, asn1
build  → types, core, asn1, hash, crypto
path   → types, core, x509
revocation → types, core, asn1, hash, x509, build
cms    → types, core, asn1, hash, x509, build
keys   → types, core, asn1, crypto
verify → types, core, asn1, hash, x509, crypto, path, revocation, cms, keys
```

`src/index.ts` imports every layer; nothing imports it. **No reverse edges**; a new edge changes `LAYERS` and this diagram first, in its own commit.
`x509` never imports `oid`, `pem` never `asn1`, `crypto`/`build` never `x509`, `path`/`cms` never `crypto` (verdicts arrive precomputed), `keys` never `x509`.
**Web Crypto has one door**, `src/crypto/webcrypto.ts`: the only module naming `importKey`, `verify`, `sign`, `deriveKey`, `unwrapKey`, `decrypt`;
`KEY_OPERATION_POLICY` refuses `generateKey`, `exportKey`, `deriveBits`, `encrypt`, `wrapKey` forever.

## Conventions

- `verbNoun` functions, `PascalCase` types, `UPPER_SNAKE` constants, `_prefixed` internals; `fn(data, options?)`; explicit return types;
  TSDoc `@param`/`@returns`/`@throws` on every export (`docs/assets/api.json` is generated from it).
- Codes `PKI_<SUBJECT>_<CONDITION>` in `docs/data/errors.json` (frozen vocabulary), `PKI_DIAG_…` in `docs/data/diagnostics.json` (additions-only),
  `PKI_REASON_…` in `docs/data/reasons.json`; `verify:docs` checks each both ways.
- Decoded values `readonly`, zero-copy `Uint8Array` views; times `epochMilliseconds`; `bigint` only for INTEGERs and oversized arcs;
  `isBytes` (`src/core/bytes.ts`) never `instanceof Uint8Array`; a catch binds its error and passes through `_pkiError`.
- Module header `/** pkinative — Title\n ===\n … */`, dividers `// ── Name ──`, `/*#__PURE__*/` on module-level constants.
- **Find a symbol:** public → grep `docs/assets/api.json` for `"name":"<Export>"` (lists its `module`); internal → grep `^export function <name>` in `src/`.

## Never touch / regenerate instead

- `release-notes/v*.md` of tagged versions; `tests/fixtures/**` (foreign provenance); SHA pins in `.github/workflows/*.yml` (Dependabot); `package-lock.json` (npm);
  `dist/`, `coverage/`, `test-output/`, `node_modules/`.
- Generated: `docs/assets/api.json` + llms files + playground (`npm run docs:*`); `docs/assets/api.frozen.json`, `docs/data/{errors,refusals}.frozen.json` (`scripts/build-*-frozen.ts --ratchet`);
  `scripts/data/limbo-*.json` (`validate-certs.ts --update-baseline`, review each entry); `scripts/data/output-bytes.json` (`verify-samples.ts --update-baseline`); `.claude/rules/*.md` (`npm run agents:rules`).

## Counts, versions, traceability

`docs/assets/ecosystem.json` is the source of every count, version and contract quoted in the docs (`verify:docs` enforces).
Coverage: 100 % on four axes in `vitest.config.ts`, no override; an unreachable branch is removed or carries a justified `v8 ignore`.
`scripts/data/rfc*-requirements.json` (5280, 5652, 3161, 6960, 7292, 7468) give every MUST/SHOULD sentence a status naming its test or a closed-list exclusion reason.

## Releasing and governance

CONTRIBUTING.md §Release; Conventional Commits; every runtime change gets a ROADMAP.md entry and a line in the next `release-notes/vX.Y.Z.md`, downstream-visible ones under **Downstream integration notes**.
No version below 1.0.0 was ever tagged or released; `publish.yml` refuses one all the same.
Human-in-the-loop, enforced: agents never push, tag, open PRs/issues/releases, publish, or add `Co-Authored-By`.
Protocol [.github/AGENT_RULES.md](.github/AGENT_RULES.md), policy [.github/ai-governance.json](.github/ai-governance.json); issue drafts in `.github/drafts/` (`npm run verify:issue`); security findings follow SECURITY.md.
