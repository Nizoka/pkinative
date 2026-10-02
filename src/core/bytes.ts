/**
 * pkinative — Byte helpers
 * ========================
 * The handful of byte operations every layer shares. Nothing here copies
 * unless the operation is a copy by definition (`concatBytes`).
 *
 * @module core/bytes
 */

import { PkiError } from '../types/pki-errors.js';

/**
 * Accept a `Uint8Array` from any realm (a Worker, an iframe, Node's `Buffer`
 * subclass) and refuse everything else before any byte is read.
 *
 * @throws {PkiError} `PKI_INVALID_INPUT` when the value is not a Uint8Array.
 */
/**
 * Whether `value` is a `Uint8Array` from **any** realm. `instanceof` is bound
 * to one realm's constructor, so a buffer made in a `vm` context, an iframe
 * or a worker fails it while being exactly what the function was given to
 * read; the view check and the brand are what the bytes themselves say.
 *
 * @param value Anything a caller passed.
 * @returns True when `value` is a `Uint8Array`, whichever realm created it.
 */
export function isBytes(value: unknown): value is Uint8Array {
    return ArrayBuffer.isView(value) && Object.prototype.toString.call(value) === '[object Uint8Array]';
}

export function assertBytes(input: unknown, what: string): Uint8Array {
    if (isBytes(input)) {
        return input;
    }
    throw new PkiError('PKI_INVALID_INPUT',
        `pkinative: ${what} must be a Uint8Array, got ${input === null ? 'null' : typeof input} — decode PEM text with decodePem() first`);
}

/**
 * A `DataView` over exactly the bytes of `data`.
 *
 * `noUncheckedIndexedAccess` widens `data[i]` to `number | undefined`, and the
 * `?? 0` that narrows it back turns a bound the caller has already proved into
 * a silent default: an out-of-range read becomes a plausible zero octet, which
 * is a wrong value rather than a failure. `getUint8` returns a `number`, and
 * throws a `RangeError` if a bound is ever wrong — which the fuzzing suites
 * turn into a test failure. Hold one view per input, never one per node.
 */
export function byteView(data: Uint8Array): DataView {
    return new DataView(data.buffer, data.byteOffset, data.byteLength);
}

/**
 * Lexicographic octet-string order; a prefix sorts first (X.690 §11.6).
 *
 * §11.6 pads the shorter encoding with trailing zero octets before comparing.
 * Comparing the common prefix and then the lengths gives the same order,
 * because a zero octet compares below every octet the longer encoding can hold
 * in that position.
 */
export function compareOctets(a: Uint8Array, b: Uint8Array): number {
    const av = byteView(a);
    const bv = byteView(b);
    const min = Math.min(a.length, b.length);
    for (let i = 0; i < min; i++) {
        const diff = av.getUint8(i) - bv.getUint8(i);
        if (diff !== 0) return diff;
    }
    return a.length - b.length;
}

const HEX_DIGITS = '0123456789abcdef';

/** Lowercase hexadecimal, with an optional separator between octets. */
export function toHex(bytes: Uint8Array, separator = ''): string {
    const parts: string[] = [];
    // for…of yields a number and charAt a string, so neither needs the `?? ''`
    // that an indexed read would: two unreachable branches fewer.
    for (const b of bytes) parts.push(HEX_DIGITS.charAt(b >> 4) + HEX_DIGITS.charAt(b & 15));
    return parts.join(separator);
}

/** Byte-wise equality of two arrays (not constant-time: public data only). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/** One new array holding every part in order. */
export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
    let length = 0;
    for (const part of parts) length += part.length;
    const out = new Uint8Array(length);
    let at = 0;
    for (const part of parts) {
        out.set(part, at);
        at += part.length;
    }
    return out;
}
