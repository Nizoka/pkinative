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
export function assertBytes(input: unknown, what: string): Uint8Array {
    if (ArrayBuffer.isView(input) && Object.prototype.toString.call(input) === '[object Uint8Array]') {
        return input as Uint8Array;
    }
    throw new PkiError('PKI_INVALID_INPUT',
        `pkinative: ${what} must be a Uint8Array, got ${input === null ? 'null' : typeof input} — decode PEM text with decodePem() first`);
}

const HEX_DIGITS = '0123456789abcdef';

/** Lowercase hexadecimal, with an optional separator between octets. */
export function toHex(bytes: Uint8Array, separator = ''): string {
    const parts: string[] = [];
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i] ?? 0;
        parts.push(`${HEX_DIGITS[b >> 4] ?? ''}${HEX_DIGITS[b & 15] ?? ''}`);
    }
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
