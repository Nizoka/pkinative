/**
 * pkinative — SHA-1 (FIPS 180-4 §6.1)
 * ===================================
 * SHA-1 is broken for collision resistance and is never a security digest in
 * pkinative. It exists because certificate fingerprints are still displayed
 * in SHA-1 by browsers and tools, and because PKIX identifiers (OCSP CertID,
 * the key identifier method of RFC 5280 §4.2.1.2) are specified over it.
 *
 * @module hash/sha1
 */

import { padMessage } from './hash-shared.js';

function rotl(x: number, n: number): number {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * SHA-1 digest of public data.
 *
 * @internal Exposed publicly only through `computeFingerprint`.
 */
export function sha1(input: Uint8Array): Uint8Array {
    const padded = padMessage(input, 64, 8);
    const view = new DataView(padded.buffer);
    const w = new Uint32Array(80);
    let h0 = 0x67452301;
    let h1 = 0xefcdab89;
    let h2 = 0x98badcfe;
    let h3 = 0x10325476;
    let h4 = 0xc3d2e1f0;

    for (let offset = 0; offset < padded.length; offset += 64) {
        for (let j = 0; j < 16; j++) w[j] = view.getUint32(offset + j * 4, false);
        for (let j = 16; j < 80; j++) {
            w[j] = rotl((w[j - 3] as number) ^ (w[j - 8] as number) ^ (w[j - 14] as number) ^ (w[j - 16] as number), 1);
        }
        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;
        for (let j = 0; j < 80; j++) {
            let f: number;
            let k: number;
            if (j < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            } else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            const temp = (rotl(a, 5) + f + e + k + (w[j] as number)) >>> 0;
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }

    const out = new Uint8Array(20);
    const outView = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((word, i) => outView.setUint32(i * 4, word, false));
    return out;
}
