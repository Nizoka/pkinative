---
paths:
  - "tests/**"
---
<!-- GENERATED from .github/instructions/testing.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# Testing Standards

## Framework
- **vitest** — native ESM, fast watch mode, built-in coverage
- Run: `npm run test` (single run), `npm run test:watch` (watch), `npm run test:coverage`
- Config: `vitest.config.ts` (unit + fuzzing + property + conformance + tools + docs); `TZ=UTC`, `pool: 'forks'`, no shuffle
- **Typecheck tests**: `npm run typecheck:tests` — uses `tsconfig.test.json` (includes `src/` + `tests/` + `recipes/`)
- Tests may import `node:*` modules (they run on Node); `src/` never does

## Test Organization
```
tests/
├── core/           # errors, limits, diagnostics, bytes, text, base64
├── asn1/           # decoder, value readers, time, OID codec, encoders
├── pem/            # RFC 7468 strict and lax
├── hash/           # SHA-1/256/384/512 known answers, fingerprints
├── oid/            # registry integrity
├── x509/           # certificate envelope, names, general names, SPKI, every extension
├── fuzzing/        # one file per adversarial class, seeded, fixed budgets
├── security/       # CVE-class replays, one test per published class, held to docs/data/cve-classes.json
├── property/       # seeded round-trip properties (encode → decode → encode)
├── conformance/    # offline differential against node:crypto
├── tools/          # guard hook, workflows, agent config, architecture, verify-issue
├── docs/           # verify-docs rules, recipes, fixture budget
├── helpers/        # raw DER builder, PRNG, certificate templates — NEVER import src/
└── fixtures/       # public certificates only, with PROVENANCE.md
```

## Test Patterns
- Name: `describe('functionName', () => { it('should ...', () => { ... }) })`
- One assertion per concept — split complex verifications into separate `it()` blocks
- Use `describe.each` / `it.each` for tables of vectors
- No `any` in test code — type test inputs properly
- **Assert the error code, never the message text**: `expect(() => f(x)).toThrow(expect.objectContaining({ code: 'PKI_ASN1_TRUNCATED' }))`, plus `instanceof` the class
- Diagnostics: assert the code through `onDiagnostic` (and the throw under `strict`), never the `console.warn` text; every code asserted must exist in the registry

## Known-Answer Vectors
- Cite the source in the test name or a comment: `X.690 §8.19.5`, `RFC 7468 §5.1`, `FIPS 180-4`, `RFC 8410 §10.2`
- Hash vectors cover the padding boundaries (55, 56, 64, 111, 112 bytes) and the empty input

## Adversarial Inputs (tests/fuzzing/)
- One file per class: length encoding, nesting depth, node count, high tag numbers, integers, bit strings, OID arcs, time rollover, string types, BER indefinite forms, PEM, truncation, byte flips, duplicate extensions
- Seeded and deterministic (`tests/helpers/prng.ts`); print the seed in the failure message
- Every iteration must end in a returned value or a thrown `PkiError` subclass — any other exception (`TypeError`, `RangeError`) fails the suite
- Every named limit in `src/core/pki-limits.ts` has a test that trips it and asserts `PKI_LIMIT_EXCEEDED` with the right `limit`

## Locking tests for fixes
- A fix's locking test asserts the **decoded structure or the exact error code** the fix changes — never only "does not throw"
- Parser fixes get a **synthetic input built in the test** with `tests/helpers/raw-der-builder.ts` (independent of the engine), not a committed binary

## Test Data and Fixtures
- Committed binaries are allowed ONLY when their provenance is foreign (a public CA root, an RFC example); each is listed in `tests/fixtures/PROVENANCE.md` with its source and licence
- Hostile inputs are generated, never committed: "never commit what our own code can build"
- The fixture tree has a byte budget enforced by `tests/docs/fixture-budget.test.ts`
- Downloaded conformance corpora live in `test-output/corpora/` (git-ignored), pinned by commit and SHA-256

## Anti-Patterns
- Tests that depend on execution order
- Shared mutable state between tests (use `beforeEach` for fresh state)
- Using the library's own encoder as the only oracle for its decoder
- Snapshot tests of binary output (fragile — assert structure)
- "Does not throw" as the only assertion of a fix
