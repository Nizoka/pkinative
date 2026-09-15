/**
 * pkinative — Strict text codecs
 * ==============================
 * The character decoders behind every ASN.1 string type, written out rather
 * than delegated to `TextDecoder`: the ES2020 baseline does not guarantee it,
 * its non-fatal mode silently substitutes U+FFFD, and a certificate name that
 * decodes differently in two implementations is a parser differential.
 *
 * Every decoder returns `null` for bytes outside its encoding, and the
 * caller turns that into `PKI_ASN1_STRING_INVALID` with the offset it knows.
 *
 * @module core/text
 */

/** Code units are turned into strings in chunks, far below any engine's argument limit. */
const CHUNK = 4096;

function _fromCodeUnits(units: readonly number[]): string {
    let out = '';
    for (let i = 0; i < units.length; i += CHUNK) {
        out += String.fromCharCode(...units.slice(i, i + CHUNK));
    }
    return out;
}

function _pushCodePoint(units: number[], cp: number): void {
    if (cp > 0xffff) {
        const v = cp - 0x10000;
        units.push(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
    } else {
        units.push(cp);
    }
}

/**
 * Strict UTF-8 (RFC 3629): refuses overlong forms, surrogates, code points
 * above U+10FFFF, stray continuation bytes and truncated sequences.
 */
export function decodeUtf8(bytes: Uint8Array): string | null {
    const units: number[] = [];
    let i = 0;
    while (i < bytes.length) {
        const b0 = bytes[i] ?? 0;
        if (b0 < 0x80) {
            units.push(b0);
            i += 1;
            continue;
        }
        let need: number;
        let cp: number;
        let lower = 0x80;
        let upper = 0xbf;
        if (b0 >= 0xc2 && b0 <= 0xdf) {
            need = 1; cp = b0 & 0x1f;
        } else if (b0 >= 0xe0 && b0 <= 0xef) {
            need = 2; cp = b0 & 0x0f;
            if (b0 === 0xe0) lower = 0xa0;       // overlong
            if (b0 === 0xed) upper = 0x9f;       // surrogates
        } else if (b0 >= 0xf0 && b0 <= 0xf4) {
            need = 3; cp = b0 & 0x07;
            if (b0 === 0xf0) lower = 0x90;       // overlong
            if (b0 === 0xf4) upper = 0x8f;       // above U+10FFFF
        } else {
            return null;
        }
        for (let k = 1; k <= need; k++) {
            const b = bytes[i + k];
            if (b === undefined) return null;
            const lo = k === 1 ? lower : 0x80;
            const hi = k === 1 ? upper : 0xbf;
            if (b < lo || b > hi) return null;
            cp = (cp << 6) | (b & 0x3f);
        }
        _pushCodePoint(units, cp);
        i += need + 1;
    }
    return _fromCodeUnits(units);
}

/** BMPString (UCS-2, big-endian): an even number of octets, no surrogate code units. */
export function decodeUcs2Be(bytes: Uint8Array): string | null {
    if (bytes.length % 2 !== 0) return null;
    const units: number[] = [];
    for (let i = 0; i < bytes.length; i += 2) {
        const unit = ((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0);
        if (unit >= 0xd800 && unit <= 0xdfff) return null;
        units.push(unit);
    }
    return _fromCodeUnits(units);
}

/** UniversalString (UCS-4, big-endian): a multiple of four octets, scalar values only. */
export function decodeUcs4Be(bytes: Uint8Array): string | null {
    if (bytes.length % 4 !== 0) return null;
    const units: number[] = [];
    for (let i = 0; i < bytes.length; i += 4) {
        const cp = (((bytes[i] ?? 0) << 24) | ((bytes[i + 1] ?? 0) << 16) | ((bytes[i + 2] ?? 0) << 8) | (bytes[i + 3] ?? 0)) >>> 0;
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
        _pushCodePoint(units, cp);
    }
    return _fromCodeUnits(units);
}

/** ISO 8859-1: every octet is the code point of the same value. Never fails. */
export function decodeLatin1(bytes: Uint8Array): string {
    const units: number[] = [];
    for (let i = 0; i < bytes.length; i++) units.push(bytes[i] ?? 0);
    return _fromCodeUnits(units);
}

/** Single-octet text whose every octet satisfies `allowed`; null at the first octet that does not. */
export function decodeAsciiSubset(bytes: Uint8Array, allowed: (octet: number) => boolean): string | null {
    const units: number[] = [];
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i] ?? 0;
        if (!allowed(b)) return null;
        units.push(b);
    }
    return _fromCodeUnits(units);
}

/** The first octet of `bytes` that fails `allowed`, or -1. */
export function firstOctetOutside(bytes: Uint8Array, allowed: (octet: number) => boolean): number {
    for (let i = 0; i < bytes.length; i++) {
        if (!allowed(bytes[i] ?? 0)) return i;
    }
    return -1;
}

/** PrintableString alphabet (X.680 §41.4): A–Z a–z 0–9 space ' ( ) + , - . / : = ? */
export function isPrintableOctet(b: number): boolean {
    return (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39)
        || b === 0x20 || b === 0x27 || b === 0x28 || b === 0x29 || b === 0x2b || b === 0x2c
        || b === 0x2d || b === 0x2e || b === 0x2f || b === 0x3a || b === 0x3d || b === 0x3f;
}

/** IA5String: the 7-bit International Alphabet No. 5 (ASCII, controls included). */
export function isIa5Octet(b: number): boolean {
    return b < 0x80;
}

/** VisibleString: printing ASCII from space to tilde. */
export function isVisibleOctet(b: number): boolean {
    return b >= 0x20 && b <= 0x7e;
}

/** NumericString: digits and space. */
export function isNumericOctet(b: number): boolean {
    return (b >= 0x30 && b <= 0x39) || b === 0x20;
}

/** UTF-8 encoding of a well-formed string; null when it contains a lone surrogate. */
export function encodeUtf8(text: string): Uint8Array | null {
    const out: number[] = [];
    for (let i = 0; i < text.length; i++) {
        let cp = text.charCodeAt(i);
        if (cp >= 0xd800 && cp <= 0xdbff) {
            const low = text.charCodeAt(i + 1);
            if (!(low >= 0xdc00 && low <= 0xdfff)) return null;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            i++;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) {
            return null;
        }
        if (cp < 0x80) out.push(cp);
        else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
        else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
        else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
    return Uint8Array.from(out);
}
