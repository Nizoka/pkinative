# AGENTS.md

Condensed, editor-agnostic guidance for AI coding agents (Cursor, Aider, Claude Code, Copilot, Continue, Zed, Cline, Windsurf, Goose, Gemini CLI, …).
Canonical detail: [.github/copilot-instructions.md](.github/copilot-instructions.md) + [.github/instructions/](.github/instructions/). Claude Code loads [CLAUDE.md](CLAUDE.md), which imports this file. Keep the three consistent.

## Mission and constraints

pkinative is a zero-runtime-dependency TypeScript toolkit for public-key infrastructure data: ITU-T X.690 DER/BER, RFC 7468 PEM, object identifiers and RFC 5280 X.509 certificates.
Third library of the *native* family, under the doctrine of [pdfnative](https://github.com/Nizoka/pdfnative) and [zipnative](https://github.com/Nizoka/zipnative).

- **Zero deps.** Never add a runtime dependency. Dev deps need a written justification.
- **No secret-dependent cryptography.** No signing, key generation or arithmetic on secret material in TypeScript — Web Crypto only (from 0.3). Hashing covers public data.
- **No classes, no module-level side effects.** Closure factories return interfaces; the only classes are the `PkiError` family in `src/types/pki-errors.ts`. `sideEffects: false` is probed.
- **TypeScript strict** plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`. No `any`; ESM-first; `.js` import extensions; one entry point, `src/index.ts`.
- **Untrusted input everywhere.** Every loop over input bytes consults a named, CWE-tagged limit (`src/core/pki-limits.ts`); the decoder is iterative; DER is strict by default.
- **Throw or diagnose, never both.** Structural failures throw a `PkiError` subclass with a stable `code` and a message that starts with `pkinative: ` and names the remedy.
  Conformance concerns go through `src/core/pki-diagnostics.ts`, the only module that may call `console.warn` (`onDiagnostic` redirects, `strict` escalates).
- **No I/O in the engine.** No `node:` imports, no `process`, no filesystem, no network, no `eval`, no dynamic `import()` — decided from the syntax tree by `tests/tools/architecture.test.ts`.
- **Human-in-the-loop.** Agents draft and verify; the maintainer pushes, opens PRs/issues and publishes (see Governance).
- **English everywhere.** Code, comments, messages, tests, docs and release notes; another language only as demonstrated content marked `demo-language: <tag> (reason)`.

## The gate

`npm run gate` is THE quality gate (`scripts/gate.ts`; the step list is its `STEPS` table). Logs land in `test-output/.gate/<step>.log`; the summary is at most 20 lines.

| Profile | Command | Runs |
|---|---|---|
| Fast — before every commit | `npm run gate:fast` | typecheck:all, lint, test, verify:docs |
| CI — the default | `npm run gate` | the CI profile |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | everything |

`npx tsx scripts/gate.ts --only <step>` runs one step, `--json` emits machine-readable output. One suite: `npx vitest run tests/<path>.test.ts` (dot reporter).

## Where is what

| Path | Purpose | Read first |
|---|---|---|
| `src/types/` | Error classes and their code unions, public types | `.github/instructions/api-design.instructions.md` |
| `src/core/` | Named limits, the diagnostics sink, byte, text and base64 helpers | `.github/instructions/security.instructions.md` |
| `src/asn1/` | X.690 decoder (iterative, DER or BER), value readers, time, OID codec, encoders | `.github/instructions/pki-core.instructions.md` |
| `src/pem/` | RFC 7468 decode and encode | `.github/instructions/pki-core.instructions.md` |
| `src/oid/` | OID name registry — data that only `getOidName` pulls in | `.github/instructions/pki-core.instructions.md` |
| `src/hash/` | SHA-1/256/384/512 over public data, certificate fingerprints | `.github/instructions/performance.instructions.md` |
| `src/x509/` | RFC 5280 certificates: envelope, names, general names, SPKI, every standard extension | `.github/instructions/pki-core.instructions.md` |
| `tests/` | Vitest suites mirroring `src/`, plus fuzzing, property, conformance, tools and docs suites | `.github/instructions/testing.instructions.md` |
| `scripts/` | The gate, verify-docs (engine + `verify-docs/rules/`), generators, the conformance runner | this file |
| `docs/` | pkinative.dev sources: guides, data registries, llms files, `assets/ecosystem.json` | `.github/instructions/api-design.instructions.md` |

## Architecture

Strict layering, enforced from `LAYERS` in `scripts/lib/architecture.ts`; `verify:docs` rule `layer-parity` holds this diagram to it:

```
types  → (nothing)
core   → types
hash   → types, core
asn1   → types, core
pem    → types, core
oid    → (nothing)
x509   → types, core, asn1
crypto → types, core, asn1
```

`src/index.ts` imports every layer; nothing imports it. **Sanctioned reverse edges: none.** A new layer or edge changes `LAYERS` and this diagram first, in its own reviewed commit.
`x509` never imports `oid` (the registry stays out of the parser's bundle), `pem` never imports `asn1` (PEM is an envelope), and **`crypto` never imports `x509`**: the verifier consumes parsed data, so verification ships no parser.
**Web Crypto has one door.** Only `src/crypto/webcrypto.ts` may name `importKey`, `verify` or `sign`; `KEY_OPERATION_POLICY` refuses `generateKey`, `exportKey`, `deriveBits`, `encrypt` and `wrapKey` in every version.

## Conventions

- `verbNoun` functions, `PascalCase` types, `UPPER_SNAKE` constants, `_prefixed` internals; options object last: `fn(data, options?)`; explicit return types on every export.
- Error codes `PKI_<SUBJECT>_<CONDITION>` in `docs/data/errors.json`; diagnostic codes `PKI_DIAG_<SUBJECT>_<CONDITION>` in `docs/data/diagnostics.json`; both checked both ways by `verify:docs`.
- Decoded values are `readonly`, with zero-copy `Uint8Array` views of the input; times are `epochMilliseconds`; `bigint` only for INTEGER values and oversized OID arcs.
- Every public export has TSDoc with `@param`, `@returns` and `@throws`; `docs/assets/api.json` is generated from it.
- Module header `/** pkinative — Title\n ===\n … */`, section dividers `// ── Name ──`, `/*#__PURE__*/` on module-level constant construction.

## Finding a symbol

- Public export → grep `docs/assets/api.json` for `"name":"<Export>"`; every entry lists its `module`.
- Internal symbol → grep `^export function <name>` (or `^export const <name>`) in `src/`.
- README.md and ROADMAP.md are long: `grep -n "^## "` first, then read a line range. CHANGELOG.md: the top entry only.

## Never touch

- `release-notes/v*.md` of already-tagged versions (read-only history).
- `dist/`, `coverage/`, `test-output/`, `node_modules/`, `package-lock.json` (npm owns it), and every generated file below: regenerate, never hand-edit.
- `tests/fixtures/**` committed certificates (foreign provenance — regenerating them locally destroys the point) and the SHA pins in `.github/workflows/*.yml` (Dependabot owns bumps).

## Generated files

| File | Regenerate with |
|---|---|
| `.claude/rules/*.md` | `npm run agents:rules` (from `.github/instructions/*.instructions.md`) |
| `docs/assets/api.json` | `npm run docs:api` (from the TSDoc of every export of `src/index.ts`) |
| `scripts/data/limbo-refusals.json` | `npx tsx scripts/validate-certs.ts --update-baseline` — then review every changed entry |
| `dist/`, `coverage/`, `test-output/` | `npm run build`, `npm run test:coverage`, `npm run gate` |

## Counts and versions

`docs/assets/ecosystem.json` is the source of every count, version, milestone and contract quoted in the docs; run `npm run verify:docs` after touching any of them.
Coverage thresholds live once, in `vitest.config.ts`: 100 % on all four axes, no per-path override. An unreachable branch is removed by construction, or carries a justified `v8 ignore` that `declared.coverageIgnores` counts.

## Releasing

Follow CONTRIBUTING.md §Release; Conventional Commits (`feat(scope):`, `fix(scope):`, `docs:`, `chore:`); every runtime change gets a ROADMAP.md entry and a line in the next `release-notes/vX.Y.Z.md`.
Downstream-impacting changes (new public APIs, removed APIs, behaviour shifts, new error codes) must be documented in the **Downstream integration notes** section of the relevant release note.
Pre-1.0 versions are git tags, never npm releases; `publish.yml` refuses them.

## Governance

Human-in-the-loop, enforced: agents never push, never open PRs/issues/releases, never publish, and never add `Co-Authored-By` trailers.
Protocol: [.github/AGENT_RULES.md](.github/AGENT_RULES.md); machine-readable policy: [.github/ai-governance.json](.github/ai-governance.json).
Issue drafts go to `.github/drafts/` and are validated with `npm run verify:issue` before a human submits them. Security findings follow [SECURITY.md](SECURITY.md), never a public draft.

## Ecosystem

- [pdfnative](https://github.com/Nizoka/pdfnative) — the mother project; its PAdES/LTV signature stack is the origin of pkinative and will consume it from the 0.7 milestone.
- [zipnative](https://github.com/Nizoka/zipnative) — the sibling whose error vocabulary, limits and conformance-gate patterns pkinative inherits.

See also: [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md).
