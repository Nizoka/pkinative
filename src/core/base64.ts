/**
 * pkinative — Canonical base64
 * ============================
 * RFC 4648 §4 base64 with the standard alphabet and mandatory padding. The
 * decoder is strict on purpose: it refuses a character outside the alphabet,
 * padding anywhere but the end, a length that is not a multiple of four, and
 * non-zero padding bits (RFC 4648 §3.5) — two texts for one byte string is a
 * parser differential. Whitespace handling belongs to the PEM layer, which
 * knows the line structure.
 *
 * @module core/base64
 */

import { byteView } from './bytes.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function _reverseTable(): Int16Array {
    const table = new Int16Array(128).fill(-1);
    for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i;
    return table;
}

const REVERSE: Int16Array = /*#__PURE__*/ _reverseTable();

function _sextet(text: string, index: number): number {
    const c = text.charCodeAt(index);
    /* v8 ignore next -- unreachable: `c < 128` is the bound of a 128-entry table, so the read always yields a number. The `?? -1` exists only because noUncheckedIndexedAccess cannot see that. Measured alternatives that erase the branch — a string table read with charCodeAt, and a DataView — cost 33 % and 25 % on this per-character path, and decodePem is where that shows (performance.instructions.md, hot paths). */
    return c < 128 ? REVERSE[c] ?? -1 : -1;
}

/**
 * Decode canonical, padded base64. Returns null for any deviation.
 */
export function decodeBase64(text: string): Uint8Array | null {
    if (text.length % 4 !== 0) return null;
    if (text.length === 0) return new Uint8Array(0);
    let padding = 0;
    if (text.charCodeAt(text.length - 1) === 0x3d) padding = text.charCodeAt(text.length - 2) === 0x3d ? 2 : 1;
    const out = new Uint8Array((text.length / 4) * 3 - padding);
    let at = 0;
    for (let i = 0; i < text.length; i += 4) {
        const last = i + 4 === text.length;
        const a = _sextet(text, i);
        const b = _sextet(text, i + 1);
        const c = last && padding === 2 ? 0 : _sextet(text, i + 2);
        const d = last && padding >= 1 ? 0 : _sextet(text, i + 3);
        if (a < 0 || b < 0 || c < 0 || d < 0) return null;
        if (last && padding === 2 && (b & 0x0f) !== 0) return null; // non-zero padding bits
        if (last && padding === 1 && (c & 0x03) !== 0) return null;
        const triple = (a << 18) | (b << 12) | (c << 6) | d;
        out[at++] = (triple >> 16) & 0xff;
        if (!(last && padding === 2)) out[at++] = (triple >> 8) & 0xff;
        if (!(last && padding >= 1)) out[at++] = triple & 0xff;
    }
    return out;
}

/** Encode bytes as canonical, padded base64 (one line, no whitespace). */
export function encodeBase64(bytes: Uint8Array): string {
    const parts: string[] = [];
    const view = byteView(bytes);
    for (let i = 0; i < bytes.length; i += 3) {
        // `remaining` replaces the `=== undefined` tests one for one: the same
        // two branches, without the three indexed reads that could not fail.
        const remaining = bytes.length - i;
        const b0 = view.getUint8(i);
        const b1 = remaining > 1 ? view.getUint8(i + 1) : 0;
        const b2 = remaining > 2 ? view.getUint8(i + 2) : 0;
        const triple = (b0 << 16) | (b1 << 8) | b2;
        parts.push(
            ALPHABET.charAt((triple >> 18) & 63),
            ALPHABET.charAt((triple >> 12) & 63),
            remaining > 1 ? ALPHABET.charAt((triple >> 6) & 63) : '=',
            remaining > 2 ? ALPHABET.charAt(triple & 63) : '=',
        );
    }
    return parts.join('');
}
