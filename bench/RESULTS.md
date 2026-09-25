# Benchmark results

Numbers with no run context are not evidence: every table below says where, when and how it was measured. Re-run with `npm run bench` before and after any change to a hot path (performance.instructions.md) and add a dated section; never overwrite one.

## 2026-09-25 — 0.3.0, the creation paths measured for the first time

- **Command:** `npm run bench` (`vitest bench --run`, vitest 4.1.11, default tinybench warm-up and iterations)
- **Runtime:** Node.js v22.17.0, win32 x64
- **Machine:** Intel Core i7-4510U @ 2.00 GHz, 4 logical cores, laptop on mains power, otherwise idle
- **Inputs:** as the 2026-09-19 section, plus a two-RDN name, a three-extension list and one ECDSA P-256 key generated once for the whole file

| Benchmark | ops/s | mean (ms) | p99 (ms) | rme |
|---|---:|---:|---:|---:|
| `decodeAsn1` — ISRG Root X1 | 24 386 | 0.041 | 0.113 | ±12.6 % |
| `decodeAsn1` — letsencrypt.org leaf | 24 820 | 0.040 | 0.138 | ±1.3 % |
| `parseCertificate` — ISRG Root X1 | 5 555 | 0.180 | 0.541 | ±2.7 % |
| `parseCertificate` — leaf, ten extensions decoded | 6 706 | 0.149 | 0.433 | ±2.7 % |
| `parseCertificate` — leaf, `decodeExtensions: false` | 11 876 | 0.084 | 0.250 | ±1.3 % |
| `decodePem` — six-certificate bundle | 8 080 | 0.124 | 0.284 | ±1.1 % |
| `computeFingerprint` SHA-256 — leaf | 64 579 | 0.016 | 0.062 | ±0.8 % |
| `encodeDistinguishedName` — two RDNs | 73 302 | 0.014 | 0.033 | ±0.9 % |
| `encodeExtensions` — three extensions | 49 675 | 0.020 | 0.049 | ±1.9 % |
| `createCertificate` — v3, three extensions | 2 888 | 0.346 | 0.741 | ±1.5 % |

**Read the last row for what it is.** An ECDSA P-256 signature dominates `createCertificate`: pkinative's own share is the two rows above it, which together account for roughly 0.034 ms of the 0.346 ms. The row is here to catch an encoder that starts allocating per byte, not to quote as pkinative's signing speed — that number belongs to whatever implements Web Crypto on your runtime, and would move if you changed nothing in this library.

**The parsing rows are not comparable with the 2026-09-19 section**, even though the code is unchanged in behaviour: that run was on a loaded machine and this one on an idle one, and the difference (`decodeAsn1` reads 72 % faster) is the load, not the library. It is recorded rather than quietly overwritten because a table that only keeps the flattering run is not a record. The two sections that *can* be compared are 2026-09-19 and 2026-09-20, which were taken under the same conditions on purpose.

The first `decodeAsn1` row again carries a high relative error. That is JIT warm-up on the first benchmark of the run, as in every section here, and not a property of the decoder.

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
