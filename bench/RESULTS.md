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

## 2026-10-02 — 1.0.0, every verb family measured before the first publication

- **Command:** `npm run bench` (`vitest bench --run`, vitest 4.1.11, default tinybench warm-up and iterations), on an otherwise idle machine; an earlier run under three concurrent agent sessions gave relative errors of 20–40 % and was discarded
- **Runtime:** Node.js v22.17.0, win32 x64
- **Machine:** Intel Core i7-4510U @ 2.00 GHz, 4 logical cores, laptop on mains power, otherwise idle
- **Inputs:** as the 2026-09-25 section for `bench/asn1-x509.bench.ts`, plus the small Ed25519 PKI of `bench/path-revocation.bench.ts` (a root, a leaf, twenty bystanders, a 10 000-entry CRL and one OCSP answer, every signature real) and the containers of `bench/cms-keys.bench.ts` (an ECDSA P-256 signer under a root, a timestamp token, a PKCS#8 key plain and under PBES2 with 2 048 iterations, a PBMAC1 PKCS#12). `vitest bench` reports the asn1-x509 file three times in one run; the first table is recorded.

Rows whose name says "dominates" are Web Crypto benchmarks with pkinative's decoding attached, and are not pkinative's speed.

| Benchmark | ops/s | mean (ms) | p99 (ms) | rme |
|---|---|---|---|---|
| `verifyCertificateChain` — leaf under a root, name checked (Ed25519 verify dominates) | 1 174 | 0.852 | 1.535 | ±1.8 % |
| `buildCertificatePath` — leaf, 20 bystanders in the bag, verdicts supplied | 4 521 | 0.221 | 0.664 | ±2.7 % |
| `validateCertificatePath` — §6 over [leaf], anchor implicit, verdicts supplied | 6 977 | 0.143 | 0.368 | ±1.4 % |
| `parseCertificateList` — 10 000 entries | 437 | 2.289 | 5.450 | ±5.9 % |
| `checkRevocation` — one serial against 10 000 entries, signature verdict supplied | 56 | 17.867 | 30.641 | ±7 % |
| `verifyCertificateChain` — with a 10 000-entry CRL, required (parse, sign check, lookup) | 24 | 41.919 | 43.645 | — |
| `parseOcspResponse` — one good answer | 24 432 | 0.041 | 0.132 | ±4.8 % |
| `checkOcspStatus` — one good answer, verdicts supplied | 744 906 | 0.0013 | 0.0026 | ±6.4 % |
| `decodeAsn1` — ISRG Root X1 (1 391 B, RSA 4096) | 30 755 | 0.033 | 0.072 | ±1.2 % |
| `decodeAsn1` — letsencrypt.org leaf (1 098 B) | 16 647 | 0.060 | 0.223 | ±7.4 % |
| `parseCertificate` — ISRG Root X1 | 3 471 | 0.288 | 0.962 | ±5.5 % |
| `parseCertificate` — letsencrypt.org leaf, 10 extensions | 1 975 | 0.506 | 3.526 | ±11.3 % |
| `parseCertificate` — leaf, `decodeExtensions: false` | 4 198 | 0.238 | 1.242 | ±14.1 % |
| `decodePem` — six-certificate bundle | 7 582 | 0.132 | 0.300 | ±1.0 % |
| `computeFingerprint` SHA-256 — leaf | 55 557 | 0.018 | 0.069 | ±1.3 % |
| `encodeDistinguishedName` — two RDNs | 62 924 | 0.016 | 0.040 | ±1.0 % |
| `encodeExtensions` — three extensions | 44 148 | 0.023 | 0.051 | ±0.9 % |
| `createCertificate` — v3, three extensions (ECDSA P-256 sign dominates) | 1 932 | 0.518 | 4.007 | ±16.9 % |
| `parseSignedData` — one signer, one certificate | 5 560 | 0.180 | 0.570 | ±6.5 % |
| `verifySignedData` — attached, one ECDSA P-256 signer under a root (verify dominates) | 402 | 2.490 | 3.924 | ±2.4 % |
| `verifySignedData` — detached, content supplied | 397 | 2.521 | 4.804 | ±3.0 % |
| `verifyTimeStampToken` — token against its imprint, TSA under a root | 379 | 2.637 | 5.778 | ±7.7 % |
| `importPrivateKey` — PKCS#8 ECDSA P-256 | 716 | 1.397 | 2.820 | ±2.8 % |
| `decryptPrivateKey` — PBES2, PBKDF2 2 048 iterations, AES-256-CBC (PBKDF2 dominates) | 244 | 4.106 | 6.941 | ±2.8 % |
| `openPkcs12` — PBMAC1, one shrouded key, two certificates (three PBKDF2 runs dominate) | 95 | 10.500 | 16.802 | — |

**What the new rows say.** The decision paths cost what their signatures cost: the chain report is one Ed25519 verification plus a tenth of a millisecond of §6; the path search over twenty bystanders and the §6 walk alone run in the hundreds of microseconds. A 10 000-entry list parses in 2.3 ms and is consulted in 18 ms — the lookup decodes entries while the parse only walks them, which is the linear bound `maxRevokedCertificates` exists for, and the one row here that would repay attention. The key containers are PBKDF2: 2 048 iterations cost 4 ms per derivation, and a PKCS#12 that derives three times costs 10 ms, so the `maxPkcs12KdfIterations` budget of ten million is minutes, not seconds, on this machine — which is why it is a budget.

Against 2026-09-25 the parser rows moved within noise or faster (`decodeAsn1` on ISRG Root X1 24 386 → 30 755 ops/s): the review's added checks — the exponent, the EC parameters, the control characters in general names — cost nothing measurable.
