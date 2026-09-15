/**
 * pkinative — FIPS 180-4 message padding
 * ======================================
 * The one padding routine the three hash modules share (FIPS 180-4 §5.1):
 * the message, a 0x80 octet, zeros, and the message length in bits as a
 * big-endian integer in the last 8 (SHA-1, SHA-256) or 16 (SHA-384, SHA-512)
 * octets of the final block.
 *
 * One definition on purpose. pdfnative carried three: its SHA-1 and SHA-512
 * wrote the high word of the bit length, its SHA-256 did not, so every input
 * of 2^29 octets (512 MiB) or more hashed to a wrong digest. `writeBitLength`
 * is exact for every array length an engine can allocate.
 *
 * These hashes cover public data only (fingerprints): pkinative never hashes
 * secret material in TypeScript.
 *
 * @module hash/hash-shared
 */

/** 2^29: the octet count whose bit length no longer fits in 32 bits. */
const HIGH_WORD_UNIT = 0x20000000;

/**
 * Write `byteLength × 8` as a 64-bit big-endian integer into the 8 octets
 * that end at `end`. For a 128-bit length field the 8 octets before them stay
 * zero, which is exact for any length below 2^61 octets.
 *
 * @internal
 */
export function writeBitLength(target: Uint8Array, end: number, byteLength: number): void {
    const view = new DataView(target.buffer, target.byteOffset, target.byteLength);
    view.setUint32(end - 8, Math.floor(byteLength / HIGH_WORD_UNIT), false);
    view.setUint32(end - 4, (byteLength % HIGH_WORD_UNIT) * 8, false);
}

/**
 * The padded message: a copy of `input` followed by FIPS 180-4 §5.1 padding,
 * a whole number of `blockSize` blocks long.
 *
 * @internal
 */
export function padMessage(input: Uint8Array, blockSize: 64 | 128, lengthOctets: 8 | 16): Uint8Array {
    const total = Math.ceil((input.length + 1 + lengthOctets) / blockSize) * blockSize;
    const padded = new Uint8Array(total);
    padded.set(input);
    padded[input.length] = 0x80;
    writeBitLength(padded, total, input.length);
    return padded;
}
