# pkinative — Copilot Instructions

Keep the three agent entry points consistent: this file (canonical detail), [AGENTS.md](../AGENTS.md) (condensed, editor-agnostic)
and [CLAUDE.md](../CLAUDE.md) (Claude Code addendum). Per-area rules live in [instructions/](instructions/) and are loaded by path.

## Overview

pkinative is a zero-runtime-dependency, pure-TypeScript toolkit for public-key infrastructure data.
It decodes and encodes ITU-T X.690 DER (BER on request), reads and writes RFC 7468 PEM, converts object identifiers,
and parses RFC 5280 X.509 certificates with every standard extension. On that foundation it verifies signatures,
builds and validates RFC 5280 §6 paths with CRL and OCSP revocation, checks host names and key purposes, reads, builds
and verifies CMS SignedData and RFC 3161 timestamps, opens PKCS#8 keys and PKCS#12 files under PBES2, and creates
certificates and certification requests. One build runs on every runtime with Web Crypto: CI tests Node.js 22 and 24
on Linux, Windows and macOS, with Deno, Bun and headless Chromium smoke tests.

It is the third library of the *native* family ([pdfnative](https://github.com/Nizoka/pdfnative), [zipnative](https://github.com/Nizoka/zipnative))
and follows the same doctrine: one quality gate, secure-by-default parsing of hostile input, stable machine-readable error codes,
a conformance gate against external corpora, and a human-in-the-loop AI governance policy.

It **never implements secret-dependent cryptography**. Every signature is created and verified through Web Crypto with the
caller's key, and `src/crypto/webcrypto.ts` is the only module that names a Web Crypto operation; hashing is limited to public data.

## Architecture

| Path | Purpose | Instruction file |
|---|---|---|
| `src/types/` | `PkiError` family and code unions, public types | `api-design.instructions.md` |
| `src/core/` | Named limits (`pki-limits.ts`), diagnostics sink (`pki-diagnostics.ts`), bytes, text, base64 | `security.instructions.md` |
| `src/asn1/` | Iterative X.690 decoder, value readers, time, OID codec, encoders | `pki-core.instructions.md` |
| `src/pem/` | RFC 7468 strict and lax PEM | `pki-core.instructions.md` |
| `src/oid/` | OID name registry — data only `getOidName` pulls in | `pki-core.instructions.md` |
| `src/hash/` | SHA-1/256/384/512 over public data, fingerprints | `performance.instructions.md` |
| `src/x509/` | Certificate envelope, names, general names, SPKI, every standard extension | `pki-core.instructions.md` |
| `src/crypto/` | The Web Crypto boundary, algorithm tables, DER ↔ P1363, signature verification | `security.instructions.md` |
| `src/build/` | Structural encoders; certificates and CSRs signed through Web Crypto | `pki-core.instructions.md` |
| `src/path/` | RFC 5280 §6 path building and validation, host names, key purposes | `pki-core.instructions.md` |
| `src/revocation/` | RFC 5280 §5 CRLs and RFC 6960 OCSP | `pki-core.instructions.md` |
| `src/cms/` | RFC 5652 SignedData and RFC 3161 timestamps | `pki-core.instructions.md` |
| `src/keys/` | PKCS#8 and PKCS#12 under PBES2 | `security.instructions.md` |
| `src/verify/` | The one-call reports; the only layer that turns a `PkiError` into a reason | `pki-core.instructions.md` |
| `src/index.ts` | The single public entry point | `api-design.instructions.md` |
| `tests/` | Unit, fuzzing, property, conformance, tools, docs | `testing.instructions.md` |

The dependency rules, which `LAYERS` in `scripts/lib/architecture.ts` defines and the `copilot-layer-parity` rule holds this block to:

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

`src/index.ts` imports every layer; nothing imports it. There is no sanctioned reverse edge.
`x509` never imports `oid`, `pem` never imports `asn1`, neither `crypto` nor `build` imports `x509`; `path` and `cms` never import `crypto`
(verdicts arrive precomputed); `keys` never imports `x509` (certificate bags leave as DER).
`tests/tools/architecture.test.ts` enforces the table, and also refuses `node:` imports, bare specifiers,
dynamic `import()`, `class` outside `src/types/pki-errors.ts`, `console` outside `src/core/pki-diagnostics.ts`,
and host globals (`process`, `Buffer`, `fetch`, `eval`, `Function`).

## Code Style

- TypeScript `strict` plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noPropertyAccessFromIndexSignature` (library tsconfig)
- No `any` — use `unknown` with narrowing; no non-null assertions in `src/`
- ESM-first; every internal import ends in `.js`; `import type` for types
- `const` over `let`, never `var`; `for` loops in hot paths
- Closure factories returning `readonly` interfaces — no classes except errors
- No module-level side effects; `/*#__PURE__*/` on module-level constant construction
- Module header `/** pkinative — Title\n ===\n description */`; section dividers `// ── Name ──`
- English everywhere; another language only as demonstrated content marked `demo-language: <tag> (reason)`

## Build & Test

```bash
npm ci                     # install (dev dependencies only)
npm run gate:fast          # typecheck:all, lint, test, verify:samples, verify:docs — before every commit
npm run gate               # the CI profile
npm run test:coverage      # vitest with the coverage thresholds of vitest.config.ts
npm run build              # tsup → dist/ (ESM + CJS + declarations)
npm run check:package      # build + attw + publint + the pinned tarball file list
npm run verify:docs        # documentation and governance rules
npm run agents:rules       # regenerate .claude/rules/ from .github/instructions/
```

## Quality Standards

- Zero TypeScript errors, zero ESLint errors
- Coverage: 100 % statements, branches, functions and lines, with no per-path override; an unreachable branch carries a justified `v8 ignore` counted by `declared.coverageIgnores`
- Every error code and diagnostic raised by at least one test; every limit tripped by a fuzzing test
- Zero runtime dependencies — `npm ls --omit=dev --all` lists pkinative alone
- The conformance gate, L0 to L8, passes on the pinned x509-limbo, Wycheproof and NIST PKITS corpora and the pinned text of RFC 5280

## Conventions

### PKI invariants
- DER is the default and is strict: indefinite lengths, non-minimal lengths and tags, constructed strings, non-canonical BOOLEAN and INTEGER, non-zero BIT STRING padding and trailing data all throw
- BER is an explicit option (`encodingRules: 'ber'`) and raises a diagnostic when it accepts a BER-only construct
- Every decoded node keeps its absolute offset and a zero-copy view of its exact bytes, so signed bytes are never re-serialised
- UTCTime maps 50–99 to 1950–1999 and 00–49 to 2000–2049; under DER `Z` and seconds are required (BER accepts their absence with a diagnostic); out-of-range fields throw
- `x509/` parses and nothing more: verification lives in `crypto/`, creation in `build/`, paths in `path/`, revocation in `revocation/`, and `verify/` composes them into reports
- Verifying one signature is not validating a chain: `verifyCertificateSignature` checks one key, `verifyCertificateChain` judges trust, validity, revocation, name and purpose

### API
- `verbNoun` functions (`decodeAsn1`, `parseCertificate`), `PascalCase` types, `UPPER_SNAKE` constants
- `fn(data, options?)`; explicit return types; outputs declare every key (`T | undefined`)
- Every public export has TSDoc with `@param`, `@returns`, `@throws`
- Times are `epochMilliseconds`; `bigint` only for INTEGER values and oversized OID arcs

### Error handling
- Structural failures THROW; conformance concerns DIAGNOSE; never both for one condition; compositions REPORT reasons
- Every thrown value is a `PkiError` subclass with a stable `code` (`PKI_<SUBJECT>_<CONDITION>`) and a message that starts with `pkinative: ` and names the remedy
- Every code is registered in `docs/data/errors.json` with `since`, `raisedWhen`, `remedy`, `standard` and `cwe`, and named in `docs/guides/errors.md`
- Codes are frozen: removal, renaming or a class move is semver-major, addition is semver-minor (`docs/data/errors.frozen.json`, rule `error-codes-frozen`)
- The public surface is frozen for the 1.x line (`docs/assets/api.frozen.json`, rule `api-surface-frozen`): a removal or an incompatible signature
  is semver-major; a new export or a new optional parameter or member is semver-minor, and `scripts/release-prepare.ts --ratchet` records it.
  The decision surface is frozen too (`docs/data/refusals.frozen.json`, rule `refusal-baseline-frozen`, ADR 0014).
  Diagnostic codes are additions-only; their severity and wording may change

### Security
- Every loop over input consults a named limit (`PkiLimits`) with a CWE tag, a default, a fuzzing test and a SECURITY.md row
- Validate before allocating; the decoder is iterative, so nesting ends in `PKI_LIMIT_EXCEEDED`, never a `RangeError`
- No object keys taken from input (prototype pollution)
- No secret-dependent arithmetic, no key generation or export, no signing in TypeScript; `KEY_OPERATION_POLICY` refuses `generateKey`, `exportKey`, `deriveBits`, `encrypt`, `wrapKey`

### Performance
- Zero-copy `subarray` views, never `slice`, in decoding paths
- No per-node closures or intermediate arrays; allocation proportional to input and bounded by the limits

### Workflow
- Conventional Commits; one concern per commit; the fast gate before every commit
- Runtime changes get a ROADMAP.md entry and a release-note line; API or behaviour shifts go under Downstream integration notes
- Agents draft, humans submit: no push, no PR, no issue, no release, no publication by an agent (`.github/AGENT_RULES.md`)
