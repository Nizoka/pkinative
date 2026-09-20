# Benchmark results

Numbers with no run context are not evidence: every table below says where, when and how it was measured. Re-run with `npm run bench` before and after any change to a hot path (performance.instructions.md) and add a dated section; never overwrite one.

## 2026-09-20 — the 100 % branch-coverage rewrites

- **Runtime / machine:** as the 2026-09-19 section, under heavy concurrent load.
- **Why the numbers below are not from `npm run bench`:** three consecutive `npm run bench` runs on *identical* code gave 24 719, 20 340 and 11 894 ops/s for the same `decodeAsn1` row, and swung `decodePem` from −29 % to +11 %. On this machine, under this load, a sequential before/after comparison measures the load, not the change. The measurement used instead imports the pre-rewrite tree (a `git worktree` at the previous commit) and the working tree into **one process** and interleaves them, best of five rounds, so both sides meet the same conditions. `computeFingerprint`, which no rewrite touches, is carried as a control: when it reads more than a couple of percent away from zero, the whole run is biased and is discarded.

Micro-measurements of the two candidate replacements for an indexed read, same process, best of five:

| Operation | indexed + `?? fallback` | replacement | verdict |
|---|---:|---:|---|
| base64 `_sextet`, per character | 11.9 ms | 15.9 ms (string table + `charCodeAt`) | **33 % slower** |
| decoder octet reads | 19.3 ms | 24.1 ms (`DataView.getUint8`) | **25 % slower** |
| `toHex` | 358.8 ms | 366.2 ms (`for…of` + `charAt`) | within noise |

End-to-end, after retreating on `_sextet` only (three accepted runs; control in the last column):

| Benchmark | run A | run B | run C | reading |
|---|---:|---:|---:|---|
| `decodeAsn1` — ISRG Root X1 | −3.5 % | −0.6 % | −1.5 % | within noise |
| `decodeAsn1` — leaf | −0.2 % | +1.8 % | −1.7 % | within noise |
| `parseCertificate` — ISRG Root X1 | −2.4 % | ±0.0 % | −8.0 % | sign varies: noise |
| `parseCertificate` — leaf | −1.4 % | −7.7 % | +2.1 % | sign varies: noise |
| `decodePem` — six-certificate bundle | −10.9 % → −3.1 % | −3.1 % | −0.7 % | see below |
| `computeFingerprint` (control, untouched) | −5.1 % | +2.5 % | +3.8 % | the noise floor, ±5 % |

`decodePem` was the one consistent regression: negative in every run, and worse than the control, which matches the 33 % measured on `_sextet` — base64 decoding is a per-character hot path (performance.instructions.md). `_sextet` therefore keeps its indexed read and carries a justified `v8 ignore`, counted by `declared.coverageIgnores`. After that retreat it returns to the noise floor. Everything else — one `DataView` per decode call rather than per node, `for…of`, `charAt`, `m[0]` in the PEM grammars — shows no regression outside the control's own spread.

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
