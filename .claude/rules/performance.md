---
paths:
  - "src/asn1/**"
  - "src/pem/**"
  - "src/hash/**"
  - "src/core/bytes.ts"
  - "src/core/text.ts"
  - "src/core/base64.ts"
---
<!-- GENERATED from .github/instructions/performance.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# Performance Engineering Standards

## Hot Path Identification
- **TLV header decoding** — called once per node; a CA bundle holds hundreds of certificates of hundreds of nodes each
- **Base64 decoding** in PEM — called per character
- **String decoding** (UTF-8, UCS-2, UCS-4, PrintableString validation) — called per attribute value
- **Hashing** — called per fingerprint, over the whole certificate

## Zero-Copy Patterns
- Nodes expose `subarray` views of the input — never `slice` in the decoder
- One `DataView` or direct index reads over the input; no intermediate arrays per node
- The decoder is iterative with an explicit stack — no recursion, no closures allocated per node
- Prefer `for` loops over `.map()/.filter()/.reduce()` in decoding paths
- Avoid spread operator `...` in hot loops (creates new arrays)

## Memory Bounds
- Allocation is proportional to the input and bounded by the named limits (`maxInputBytes`, `maxNodes`, `maxDepth`) — validate before allocating
- Concatenation of BER constructed segments allocates once, after the total length is known and checked
- No caches that grow with untrusted input

## Benchmarking Rules
- Benchmark before AND after any change to a hot path (`npm run bench`)
- Test with realistic data: a public CA bundle, certificates with large SAN lists
- Record the run context (Node version, platform, command) in `bench/RESULTS.md` — numbers without context are not evidence
- Run multiple iterations to account for JIT warmup

## Size Optimization
- Tree-shaking: `sideEffects: false` — no module-level side effects; `/*#__PURE__*/` on module-level constant construction
- The OID name registry is data that only `getOidName` pulls in; the certificate parser never imports it
- `npm run verify:bundle` holds every probe to its byte budget and its forbidden markers
