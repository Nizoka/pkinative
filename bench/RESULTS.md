# Benchmark results

Numbers with no run context are not evidence: every table below says where, when and how it was measured. Re-run with `npm run bench` before and after any change to a hot path (performance.instructions.md) and add a dated section; never overwrite one.

## 2026-09-19 — 0.1.0 development tree

- **Command:** `npm run bench` (`vitest bench --run`, vitest 4.1.11, default tinybench warm-up and iterations)
- **Runtime:** Node.js v22.17.0, win32 x64
- **Machine:** Intel Core i7-4510U @ 2.00 GHz, 4 logical cores, laptop on mains power, other applications open
- **Inputs:** the public certificates of `tests/fixtures/` (PROVENANCE.md) — ISRG Root X1 (1 391 bytes, RSA 4096), the letsencrypt.org leaf (1 098 bytes, ten extensions), and a PEM bundle of all six fixtures

| Benchmark | ops/s | mean (ms) | p99 (ms) | rme |
|---|---:|---:|---:|---:|
| `decodeAsn1` — ISRG Root X1 | 14 178 | 0.071 | 0.298 | ±23.1 % |
| `decodeAsn1` — letsencrypt.org leaf | 22 361 | 0.045 | 0.149 | ±8.9 % |
| `parseCertificate` — ISRG Root X1 | 5 245 | 0.191 | 0.770 | ±3.2 % |
| `parseCertificate` — leaf, ten extensions decoded | 5 895 | 0.170 | 0.742 | ±3.1 % |
| `parseCertificate` — leaf, `decodeExtensions: false` | 11 720 | 0.085 | 0.232 | ±1.4 % |
| `decodePem` — six-certificate bundle | 7 208 | 0.139 | 0.496 | ±2.6 % |
| `computeFingerprint` SHA-256 — leaf | 51 974 | 0.019 | 0.105 | ±1.9 % |

Reading: parsing a real end-entity certificate with every extension decoded takes about 0.17 ms on a 2014 laptop CPU; half of it is extension decoding, which `decodeExtensions: false` skips for tools that only need the envelope. The high relative error of the first `decodeAsn1` row is JIT warm-up on the first benchmark of the run, not a property of the decoder.
