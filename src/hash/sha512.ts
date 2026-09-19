/**
 * pkinative — SHA-384 and SHA-512 (FIPS 180-4 §6.4, §6.5)
 * =======================================================
 * 64-bit words are carried as (high, low) pairs of unsigned 32-bit numbers.
 * Unlike pdfnative's implementation (the source of the round constants and
 * initial values), the compression loop allocates nothing: rotations are
 * written out per shift amount and additions go through one scratch pair.
 *
 * @module hash/sha512
 */

import { padMessage } from './hash-shared.js';

const K_HI = /*#__PURE__*/ new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
    0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
]);

const K_LO = /*#__PURE__*/ new Uint32Array([
    0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
    0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
    0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
    0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
    0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
    0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
    0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
    0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
    0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
    0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
]);

/** FIPS 180-4 §5.3.5, as (high, low) pairs. */
const IV_512: readonly number[] = [
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
];

/** FIPS 180-4 §5.3.4, as (high, low) pairs. */
const IV_384: readonly number[] = [
    0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
];

/** out ← (ah:al) + (bh:bl) mod 2^64; every operand an unsigned 32-bit number. */
function add(out: Uint32Array, ah: number, al: number, bh: number, bl: number): void {
    const low = (al + bl) >>> 0;
    out[0] = (ah + bh + (low < al ? 1 : 0)) >>> 0;
    out[1] = low;
}

function core(input: Uint8Array, iv: readonly number[], outputLength: 48 | 64): Uint8Array {
    const padded = padMessage(input, 128, 16);
    const view = new DataView(padded.buffer);
    const state = Uint32Array.from(iv);
    const wh = new Uint32Array(80);
    const wl = new Uint32Array(80);
    const t = new Uint32Array(2);
    /** state[i], state[i + 1] += (high, low) modulo 2^64 — per word, allocating nothing. */
    const fold = (i: number, high: number, low: number): void => {
        add(t, state[i] as number, state[i + 1] as number, high, low);
        state[i] = t[0] as number;
        state[i + 1] = t[1] as number;
    };

    for (let offset = 0; offset < padded.length; offset += 128) {
        for (let j = 0; j < 16; j++) {
            wh[j] = view.getUint32(offset + j * 8, false);
            wl[j] = view.getUint32(offset + j * 8 + 4, false);
        }
        for (let j = 16; j < 80; j++) {
            // σ0(W[j−15]) = ROTR¹ ⊕ ROTR⁸ ⊕ SHR⁷
            const xh = wh[j - 15] as number;
            const xl = wl[j - 15] as number;
            const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
            const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
            // σ1(W[j−2]) = ROTR¹⁹ ⊕ ROTR⁶¹ ⊕ SHR⁶
            const yh = wh[j - 2] as number;
            const yl = wl[j - 2] as number;
            const s1h = ((yh >>> 19) | (yl << 13)) ^ ((yl >>> 29) | (yh << 3)) ^ (yh >>> 6);
            const s1l = ((yl >>> 19) | (yh << 13)) ^ ((yh >>> 29) | (yl << 3)) ^ ((yl >>> 6) | (yh << 26));
            add(t, wh[j - 16] as number, wl[j - 16] as number, s0h >>> 0, s0l >>> 0);
            add(t, t[0] as number, t[1] as number, wh[j - 7] as number, wl[j - 7] as number);
            add(t, t[0] as number, t[1] as number, s1h >>> 0, s1l >>> 0);
            wh[j] = t[0] as number;
            wl[j] = t[1] as number;
        }

        let aH = state[0] as number, aL = state[1] as number;
        let bH = state[2] as number, bL = state[3] as number;
        let cH = state[4] as number, cL = state[5] as number;
        let dH = state[6] as number, dL = state[7] as number;
        let eH = state[8] as number, eL = state[9] as number;
        let fH = state[10] as number, fL = state[11] as number;
        let gH = state[12] as number, gL = state[13] as number;
        let hH = state[14] as number, hL = state[15] as number;

        for (let j = 0; j < 80; j++) {
            // Σ1(e) = ROTR¹⁴ ⊕ ROTR¹⁸ ⊕ ROTR⁴¹
            const sigma1H = ((eH >>> 14) | (eL << 18)) ^ ((eH >>> 18) | (eL << 14)) ^ ((eL >>> 9) | (eH << 23));
            const sigma1L = ((eL >>> 14) | (eH << 18)) ^ ((eL >>> 18) | (eH << 14)) ^ ((eH >>> 9) | (eL << 23));
            const choiceH = (eH & fH) ^ (~eH & gH);
            const choiceL = (eL & fL) ^ (~eL & gL);
            add(t, hH, hL, sigma1H >>> 0, sigma1L >>> 0);
            add(t, t[0] as number, t[1] as number, choiceH >>> 0, choiceL >>> 0);
            add(t, t[0] as number, t[1] as number, K_HI[j] as number, K_LO[j] as number);
            add(t, t[0] as number, t[1] as number, wh[j] as number, wl[j] as number);
            const temp1H = t[0] as number;
            const temp1L = t[1] as number;
            // Σ0(a) = ROTR²⁸ ⊕ ROTR³⁴ ⊕ ROTR³⁹
            const sigma0H = ((aH >>> 28) | (aL << 4)) ^ ((aL >>> 2) | (aH << 30)) ^ ((aL >>> 7) | (aH << 25));
            const sigma0L = ((aL >>> 28) | (aH << 4)) ^ ((aH >>> 2) | (aL << 30)) ^ ((aH >>> 7) | (aL << 25));
            const majorityH = (aH & bH) ^ (aH & cH) ^ (bH & cH);
            const majorityL = (aL & bL) ^ (aL & cL) ^ (bL & cL);
            add(t, sigma0H >>> 0, sigma0L >>> 0, majorityH >>> 0, majorityL >>> 0);
            const temp2H = t[0] as number;
            const temp2L = t[1] as number;

            hH = gH; hL = gL;
            gH = fH; gL = fL;
            fH = eH; fL = eL;
            add(t, dH, dL, temp1H, temp1L);
            eH = t[0] as number; eL = t[1] as number;
            dH = cH; dL = cL;
            cH = bH; cL = bL;
            bH = aH; bL = aL;
            add(t, temp1H, temp1L, temp2H, temp2L);
            aH = t[0] as number; aL = t[1] as number;
        }

        fold(0, aH, aL);
        fold(2, bH, bL);
        fold(4, cH, cL);
        fold(6, dH, dL);
        fold(8, eH, eL);
        fold(10, fH, fL);
        fold(12, gH, gL);
        fold(14, hH, hL);
    }

    const out = new Uint8Array(64);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) outView.setUint32(i * 4, state[i] as number, false);
    return outputLength === 64 ? out : out.slice(0, 48);
}

/**
 * SHA-512 digest of public data.
 *
 * @internal Exposed publicly only through `computeFingerprint`.
 */
export function sha512(input: Uint8Array): Uint8Array {
    return core(input, IV_512, 64);
}

/**
 * SHA-384 digest of public data.
 *
 * @internal Exposed publicly only through `computeFingerprint`.
 */
export function sha384(input: Uint8Array): Uint8Array {
    return core(input, IV_384, 48);
}
