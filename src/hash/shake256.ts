/**
 * pkinative — SHAKE256 (FIPS 202 §6.2)
 * ====================================
 * The one extendable-output function pkinative computes, and the only
 * digest of an Ed448 CMS signer: RFC 8419 §3.1 makes `id-shake256` with a
 * 512-bit output the `digestAlgorithm` of such a signer, and Web Crypto
 * offers no SHAKE. Like the FIPS 180-4 hashes beside it, this covers
 * **public data only** (ADR 0001) — the content and the signed attributes
 * of a message anyone may read; no secret ever passes through here.
 *
 * Keccak-f[1600] is written over 32-bit lane halves — lane `i` is
 * `s[2i]` (low word) and `s[2i + 1]` (high word), little-endian as FIPS 202
 * §B.1 lays the state out in bytes — so the hot loop allocates nothing and
 * uses no BigInt. The rate is 1088 bits (136 octets), the padding is
 * `0x1F … 0x80` (the SHAKE domain separator `1111` and pad10*1 together),
 * and the squeeze reads as many 136-octet blocks as the caller's output
 * length needs.
 *
 * @module hash/shake256
 */

import { assertBytes } from '../core/bytes.js';
import { PkiError } from '../types/pki-errors.js';

// ── Keccak-f[1600] tables ────────────────────────────────────────────

/** The high words of the 24 round constants of ι (FIPS 202 §3.2.5). */
const RC_HI = /*#__PURE__*/ new Uint32Array([
    0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000,
    0x80000000, 0x80000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
]);

/** The low words of the same 24 round constants. */
const RC_LO = /*#__PURE__*/ new Uint32Array([
    0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
    0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
    0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
]);

/**
 * The ρ rotation of lane `x + 5y` (FIPS 202 §3.2.2, Table 2, reduced mod 64)
 * as two tables over 32-bit halves: a rotation by `n` is a swap of the two
 * halves when `n ≥ 32` (`RHO_SWAP`), then a rotation by `n mod 32`
 * (`RHO_SHIFT`). The offsets are 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10,
 * 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14; none is exactly 32.
 */
const RHO_SHIFT = /*#__PURE__*/ new Uint8Array([0, 1, 30, 28, 27, 4, 12, 6, 23, 20, 3, 10, 11, 25, 7, 9, 13, 15, 21, 8, 18, 2, 29, 24, 14]);
const RHO_SWAP = /*#__PURE__*/ new Uint8Array([0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0]);

/** Where π sends lane `x + 5y`: to lane `y + 5·((2x + 3y) mod 5)` (FIPS 202 §3.2.3). */
const PI = /*#__PURE__*/ new Uint8Array([0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4]);

/**
 * The five columns `x`, and the five rows as lane offsets `5y` — iterated by
 * value, so the loops below have data for bounds rather than comparisons an
 * off-by-one could silently widen into the typed arrays' dropped stores.
 */
const COLUMNS = /*#__PURE__*/ new Uint8Array([0, 1, 2, 3, 4]);
const ROWS = /*#__PURE__*/ new Uint8Array([0, 5, 10, 15, 20]);

/** The rate of SHAKE256 in octets: 1600 − 2·256 bits (FIPS 202 §6.2). */
const RATE = 136;
/** The SHAKE domain separator with the first pad bit: `1111` then `1` (FIPS 202 §6.2 and §5.1). */
const SHAKE_PAD = 0x1f;

// ── The permutation ──────────────────────────────────────────────────

/**
 * Keccak-p[1600, 24] in place over `s`, with `c` (10 words) and `b` (50
 * words) as scratch — passed in so one call of {@link shake256} allocates
 * them once, and the module keeps no state between calls.
 */
function keccakF(s: Uint32Array, c: Uint32Array, b: Uint32Array): void {
    for (let round = 0; round < 24; round++) {
        // θ: the parity of each column, then each lane absorbs the parities
        // of the column to its left and, rotated by one bit, to its right.
        for (const x of COLUMNS) {
            const i = 2 * x;
            c[i] = (s[i] as number) ^ (s[i + 10] as number) ^ (s[i + 20] as number) ^ (s[i + 30] as number) ^ (s[i + 40] as number);
            c[i + 1] = (s[i + 1] as number) ^ (s[i + 11] as number) ^ (s[i + 21] as number) ^ (s[i + 31] as number) ^ (s[i + 41] as number);
        }
        for (const x of COLUMNS) {
            const left = 2 * ((x + 4) % 5);
            const right = 2 * ((x + 1) % 5);
            const rightLo = c[right] as number;
            const rightHi = c[right + 1] as number;
            const dLo = (c[left] as number) ^ ((rightLo << 1) | (rightHi >>> 31));
            const dHi = (c[left + 1] as number) ^ ((rightHi << 1) | (rightLo >>> 31));
            for (const y of ROWS) {
                const i = 2 * (x + y);
                s[i] = (s[i] as number) ^ dLo;
                s[i + 1] = (s[i + 1] as number) ^ dHi;
            }
        }

        // ρ and π: rotate each lane by its offset and move it to its new place.
        for (const lane of PI.keys()) {
            const swap = (RHO_SWAP[lane] as number) === 1;
            const lo = (swap ? s[2 * lane + 1] : s[2 * lane]) as number;
            const hi = (swap ? s[2 * lane] : s[2 * lane + 1]) as number;
            const m = RHO_SHIFT[lane] as number;
            const target = 2 * (PI[lane] as number);
            // A shift by 0 must not reach `>>> 32`, which JavaScript reads as `>>> 0`.
            b[target] = m === 0 ? lo : (lo << m) | (hi >>> (32 - m));
            b[target + 1] = m === 0 ? hi : (hi << m) | (lo >>> (32 - m));
        }

        // χ: each lane is combined with the two to its right in its row.
        for (const y of ROWS) {
            for (const x of COLUMNS) {
                const i = 2 * (y + x);
                const next = 2 * (y + ((x + 1) % 5));
                const after = 2 * (y + ((x + 2) % 5));
                s[i] = (b[i] as number) ^ (~(b[next] as number) & (b[after] as number));
                s[i + 1] = (b[i + 1] as number) ^ (~(b[next + 1] as number) & (b[after + 1] as number));
            }
        }

        // ι: the round constant into lane (0, 0).
        s[0] = (s[0] as number) ^ (RC_LO[round] as number);
        s[1] = (s[1] as number) ^ (RC_HI[round] as number);
    }
}

// ── The sponge ───────────────────────────────────────────────────────

/** The most octets one call squeezes: 1 MiB, far past any digest and short of the host's allocation limit. */
const MAX_OUTPUT_OCTETS = 1_048_576;

/**
 * SHAKE256 of public data, with the output length the caller names.
 *
 * The one digest an Ed448 CMS signer uses: RFC 8419 §3.1 names
 * `id-shake256` with a 512-bit output (64 octets) as the `digestAlgorithm`,
 * and `verifySignedData` computes the content digest of such a signer here.
 * It is exposed so a caller can compute the same `messageDigest` value
 * for a detached content — the `contentDigest` of `verifySignedData` — or
 * check one against a tool's. Like the fingerprint digests it hashes public
 * data only; pkinative never hashes secret material in TypeScript.
 *
 * ```ts
 * import { shake256 } from 'pkinative';
 *
 * const digest = shake256(content, 64); // what an Ed448 signer's messageDigest holds
 * ```
 *
 * @param input The octets to hash.
 * @param outputLength How many octets to produce — 64 for an Ed448 CMS signer. The caller's
 *   number, not a bound on input: the output buffer is this size, and a large value costs the
 *   memory and the time of squeezing it (about 136 octets per Keccak permutation).
 * @returns `outputLength` octets of SHAKE256 output.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `input` is not a Uint8Array;
 *   `PKI_INVALID_OPTION` when `outputLength` is not an integer from 0 to
 *   1 048 576 — a digest, not a stream: past a mebibyte the host's allocation
 *   would fail with a RangeError, and every thrown value here is a PkiError.
 */
export function shake256(input: Uint8Array, outputLength: number): Uint8Array {
    const bytes = assertBytes(input, 'shake256 input');
    if (!Number.isInteger(outputLength) || outputLength < 0 || outputLength > MAX_OUTPUT_OCTETS) {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: shake256 outputLength must be an integer number of octets from 0 to ${String(MAX_OUTPUT_OCTETS)}, got ${String(outputLength)} — an Ed448 CMS signer uses 64, and a digest is not a stream`);
    }

    // Pad: the message, the domain separator with the first pad bit, zeros,
    // and the last pad bit in the final octet of the last block — which is
    // the separator's own octet when the message fills a block but one.
    const total = Math.ceil((bytes.length + 1) / RATE) * RATE;
    const padded = new Uint8Array(total);
    padded.set(bytes);
    padded[bytes.length] = SHAKE_PAD;
    padded[total - 1] = (padded[total - 1] as number) | 0x80;

    const state = new Uint32Array(50);
    const c = new Uint32Array(10);
    const b = new Uint32Array(50);
    const view = new DataView(padded.buffer);

    // Absorb: each block is XORed into the first 34 words of the state, then permuted.
    for (let offset = 0; offset < total; offset += RATE) {
        for (let word = 0; word < RATE / 4; word++) {
            state[word] = (state[word] as number) ^ view.getUint32(offset + word * 4, true);
        }
        keccakF(state, c, b);
    }

    // Squeeze: one block of output per permutation — the state as absorbed
    // for the first, permuted once more for each block after it — and the
    // last block cut to the length asked for.
    const out = new Uint8Array(outputLength);
    const block = new Uint8Array(RATE);
    const blockView = new DataView(block.buffer);
    const blocks = Math.ceil(outputLength / RATE);
    for (let index = 0; index < blocks; index++) {
        if (index > 0) keccakF(state, c, b);
        for (let word = 0; word < RATE / 4; word++) blockView.setUint32(word * 4, state[word] as number, true);
        const offset = index * RATE;
        out.set(block.subarray(0, Math.min(RATE, outputLength - offset)), offset);
    }
    return out;
}
