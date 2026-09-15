/**
 * pkinative — DER encoders
 * ========================
 * Encoders that emit DER only, and refuse arguments DER cannot represent
 * instead of truncating them. pdfnative's encoders (the seed of these) wrote
 * lengths without range checks, truncated character codes to one octet and
 * produced wrong UTCTime text outside 1950–2049; each of those is now
 * `PKI_ASN1_VALUE_OUT_OF_RANGE`. `encodeSetOf` keeps pdfnative's X.690 §11.6
 * ordering.
 *
 * @module asn1/asn1-encode
 */

import { assertBytes, concatBytes } from '../core/bytes.js';
import { encodeUtf8, isIa5Octet, isNumericOctet, isPrintableOctet, isVisibleOctet } from '../core/text.js';
import type { Asn1Node, Asn1StringType, TagClass } from '../types/asn1-types.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import { encodeOid } from './asn1-oid.js';
import { assertNode } from './asn1-read.js';
import {
    STRING_TAGS,
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_CLASSES,
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_SET,
    TAG_UTC_TIME,
    isStringTag,
    tagLabel,
} from './asn1-tags.js';

// ── Tag, length, value ───────────────────────────────────────────────

function encodeLength(length: number): number[] {
    if (length < 0x80) return [length];
    const octets: number[] = [];
    let rest = length;
    while (rest > 0) {
        octets.unshift(rest % 256);
        rest = Math.floor(rest / 256);
    }
    return [0x80 | octets.length, ...octets];
}

/**
 * Encode one tag-length-value in DER: the shortest identifier and length forms.
 *
 * @param tagClass    The class of the tag.
 * @param tagNumber   The tag number, 0 to 2^31 − 1 (0 is refused in the universal class).
 * @param constructed Whether the content is a concatenation of encodings.
 * @param content     The content octets.
 * @returns The encoding.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for an unknown class, a tag number out of range or universal tag 0.
 */
export function encodeTlv(tagClass: TagClass, tagNumber: number, constructed: boolean, content: Uint8Array): Uint8Array {
    const bytes = assertBytes(content, 'encodeTlv content');
    const classIndex = TAG_CLASSES.indexOf(tagClass);
    if (classIndex < 0) {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE', `pkinative: tagClass must be one of ${TAG_CLASSES.join(', ')}, got ${String(tagClass)}`);
    }
    if (!Number.isInteger(tagNumber) || tagNumber < 0 || tagNumber > 0x7fffffff || (tagClass === 'universal' && tagNumber === 0)) {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE',
            `pkinative: tag number ${String(tagNumber)} is outside 0 to 2^31 − 1, or is the reserved universal tag 0 — pass a valid tag number`);
    }
    const leading = (classIndex << 6) | (constructed ? 0x20 : 0);
    const identifier: number[] = [];
    if (tagNumber < 31) {
        identifier.push(leading | tagNumber);
    } else {
        const digits: number[] = [];
        let rest = tagNumber;
        do {
            digits.push(rest % 128);
            rest = Math.floor(rest / 128);
        } while (rest > 0);
        identifier.push(leading | 0x1f);
        for (let i = digits.length - 1; i >= 0; i--) identifier.push((digits[i] ?? 0) | (i > 0 ? 0x80 : 0));
    }
    const header = [...identifier, ...encodeLength(bytes.length)];
    const out = new Uint8Array(header.length + bytes.length);
    out.set(header, 0);
    out.set(bytes, header.length);
    return out;
}

// ── Constructed types ────────────────────────────────────────────────

function childrenContent(children: readonly Uint8Array[], what: string): Uint8Array {
    if (!Array.isArray(children)) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} expects an array of encodings, got ${typeof children}`);
    }
    return concatBytes(children.map((c) => assertBytes(c, `${what} child`)));
}

/**
 * Encode a SEQUENCE from its encoded components, in the order given.
 *
 * @param children The DER encodings of the components.
 * @returns The SEQUENCE encoding.
 */
export function encodeSequence(children: readonly Uint8Array[]): Uint8Array {
    return encodeTlv('universal', TAG_SEQUENCE, true, childrenContent(children, 'encodeSequence'));
}

/**
 * Encode a SET whose component order the schema fixes (SET, not SET OF).
 *
 * @param children The DER encodings of the components, in schema order.
 * @returns The SET encoding.
 */
export function encodeSet(children: readonly Uint8Array[]): Uint8Array {
    return encodeTlv('universal', TAG_SET, true, childrenContent(children, 'encodeSet'));
}

/** Lexicographic octet-string order; a prefix sorts first (X.690 §11.6). */
function compareOctets(a: Uint8Array, b: Uint8Array): number {
    const min = Math.min(a.length, b.length);
    for (let i = 0; i < min; i++) {
        const diff = (a[i] ?? 0) - (b[i] ?? 0);
        if (diff !== 0) return diff;
    }
    return a.length - b.length;
}

/**
 * Encode a SET OF with the canonical DER ordering: the component encodings
 * sorted as octet strings (X.690 §11.6).
 *
 * @param children The DER encodings of the components, in any order.
 * @returns The SET OF encoding.
 */
export function encodeSetOf(children: readonly Uint8Array[]): Uint8Array {
    childrenContent(children, 'encodeSetOf');
    return encodeTlv('universal', TAG_SET, true, concatBytes([...children].sort(compareOctets)));
}

// ── Primitive types ──────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

/**
 * Encode an INTEGER in minimal two's complement form.
 *
 * @param value A bigint, or a safe-integer number.
 * @returns The INTEGER encoding.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for a number that is not a safe integer.
 */
export function encodeInteger(value: bigint | number): Uint8Array {
    let v: bigint;
    if (typeof value === 'bigint') {
        v = value;
    } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
        v = BigInt(value);
    } else {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE', `pkinative: encodeInteger expects a bigint or a safe integer, got ${String(value)}`);
    }
    let hex: string;
    if (v >= 0n) {
        hex = v.toString(16);
        if (hex.length % 2 === 1) hex = `0${hex}`;
        if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = `00${hex}`;
    } else {
        let octets = 1;
        while (v < -(1n << BigInt(octets * 8 - 1))) octets++;
        hex = ((1n << BigInt(octets * 8)) + v).toString(16).padStart(octets * 2, '0');
    }
    return encodeTlv('universal', TAG_INTEGER, false, hexToBytes(hex));
}

/**
 * Encode a BOOLEAN (TRUE as 0xFF, as DER requires).
 *
 * @param value The boolean.
 * @returns The BOOLEAN encoding.
 */
export function encodeBoolean(value: boolean): Uint8Array {
    return encodeTlv('universal', TAG_BOOLEAN, false, Uint8Array.of(value ? 0xff : 0x00));
}

/**
 * Encode a NULL.
 *
 * @returns The two octets 05 00.
 */
export function encodeNull(): Uint8Array {
    return encodeTlv('universal', TAG_NULL, false, new Uint8Array(0));
}

/**
 * Encode a BIT STRING.
 *
 * @param bytes      The octets.
 * @param unusedBits Unused bits in the last octet, 0 to 7; they must be zero.
 * @returns The BIT STRING encoding.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for an invalid count, unused bits on an empty string, or non-zero padding bits.
 */
export function encodeBitString(bytes: Uint8Array, unusedBits = 0): Uint8Array {
    const data = assertBytes(bytes, 'encodeBitString bytes');
    if (!Number.isInteger(unusedBits) || unusedBits < 0 || unusedBits > 7 || (data.length === 0 && unusedBits !== 0)) {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE',
            `pkinative: unusedBits must be 0 to 7, and 0 for an empty BIT STRING, got ${String(unusedBits)}`);
    }
    if (unusedBits > 0 && ((data[data.length - 1] ?? 0) & ((1 << unusedBits) - 1)) !== 0) {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE',
            `pkinative: the ${unusedBits} unused bits of the last octet must be zero in DER (X.690 §11.2.1) — clear them before encoding`);
    }
    const content = new Uint8Array(data.length + 1);
    content[0] = unusedBits;
    content.set(data, 1);
    return encodeTlv('universal', TAG_BIT_STRING, false, content);
}

/**
 * Encode an OCTET STRING.
 *
 * @param bytes The octets.
 * @returns The OCTET STRING encoding.
 */
export function encodeOctetString(bytes: Uint8Array): Uint8Array {
    return encodeTlv('universal', TAG_OCTET_STRING, false, assertBytes(bytes, 'encodeOctetString bytes'));
}

/**
 * Encode an OBJECT IDENTIFIER from dotted decimal.
 *
 * @param oid A dotted-decimal OID.
 * @returns The OBJECT IDENTIFIER encoding.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed OID.
 */
export function encodeObjectIdentifier(oid: string): Uint8Array {
    return encodeTlv('universal', TAG_OID, false, encodeOid(oid));
}

function outOfRange(type: Asn1StringType, index: number): PkiEncodingError {
    return new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE',
        `pkinative: the character at index ${index} cannot be encoded as ${tagLabel('universal', STRING_TAGS[type])} — choose a string type whose character set contains it`);
}

/**
 * Encode a character string, refusing any character outside the type.
 *
 * @param type  The string type.
 * @param value The text.
 * @returns The string encoding.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for a character the type cannot hold (or a lone surrogate).
 * @throws {PkiError} `PKI_INVALID_OPTION` for an unknown type; `PKI_INVALID_INPUT` when the value is not a string.
 */
export function encodeString(type: Asn1StringType, value: string): Uint8Array {
    if (typeof value !== 'string') {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: encodeString expects a string value, got ${typeof value}`);
    }
    let content: Uint8Array;
    switch (type) {
        case 'utf8': {
            const encoded = encodeUtf8(value);
            if (encoded === null) throw outOfRange(type, [...value].findIndex((c) => c.length === 1 && c.charCodeAt(0) >= 0xd800 && c.charCodeAt(0) <= 0xdfff));
            content = encoded;
            break;
        }
        case 'printable':
        case 'ia5':
        case 'visible':
        case 'numeric': {
            const allowed = type === 'printable' ? isPrintableOctet : type === 'ia5' ? isIa5Octet : type === 'visible' ? isVisibleOctet : isNumericOctet;
            content = new Uint8Array(value.length);
            for (let i = 0; i < value.length; i++) {
                const code = value.charCodeAt(i);
                if (code > 0x7f || !allowed(code)) throw outOfRange(type, i);
                content[i] = code;
            }
            break;
        }
        case 'teletex':
            content = new Uint8Array(value.length);
            for (let i = 0; i < value.length; i++) {
                const code = value.charCodeAt(i);
                if (code > 0xff) throw outOfRange(type, i);
                content[i] = code;
            }
            break;
        case 'bmp':
            content = new Uint8Array(value.length * 2);
            for (let i = 0; i < value.length; i++) {
                const code = value.charCodeAt(i);
                if (code >= 0xd800 && code <= 0xdfff) throw outOfRange(type, i);
                content[i * 2] = code >> 8;
                content[i * 2 + 1] = code & 0xff;
            }
            break;
        case 'universal': {
            const points: number[] = [];
            let index = 0;
            for (const ch of value) {
                const code = ch.codePointAt(0) ?? 0;
                if (code >= 0xd800 && code <= 0xdfff) throw outOfRange(type, index);
                points.push(code >>> 24, (code >> 16) & 0xff, (code >> 8) & 0xff, code & 0xff);
                index += ch.length;
            }
            content = Uint8Array.from(points);
            break;
        }
        default:
            throw new PkiError('PKI_INVALID_OPTION', `pkinative: string type must be one of ${Object.keys(STRING_TAGS).join(', ')}, got ${String(type)}`);
    }
    return encodeTlv('universal', STRING_TAGS[type], false, content);
}

// ── Time ─────────────────────────────────────────────────────────────

function pad(value: number, width: number): string {
    return String(value).padStart(width, '0');
}

/**
 * Encode an instant as a UTCTime or a GeneralizedTime in its DER form.
 *
 * @param epochMilliseconds The instant, in milliseconds since 1970-01-01T00:00:00Z.
 * @param type `'rfc5280'` (default) picks UTCTime for 1950–2049 and GeneralizedTime otherwise, with whole seconds;
 *             `'UTCTime'` requires 1950–2049 and whole seconds; `'GeneralizedTime'` writes a fraction when needed.
 * @returns The time encoding.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for a year outside 0000–9999, a UTCTime outside 1950–2049, or a fraction the type forbids.
 * @throws {PkiError} `PKI_INVALID_OPTION` for an unknown type.
 */
export function encodeTime(epochMilliseconds: number, type: 'UTCTime' | 'GeneralizedTime' | 'rfc5280' = 'rfc5280'): Uint8Array {
    if (type !== 'UTCTime' && type !== 'GeneralizedTime' && type !== 'rfc5280') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: time type must be 'UTCTime', 'GeneralizedTime' or 'rfc5280', got ${String(type)}`);
    }
    const date = new Date(typeof epochMilliseconds === 'number' ? epochMilliseconds : NaN);
    const year = date.getUTCFullYear();
    if (Number.isNaN(date.getTime()) || year < 0 || year > 9999) {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE', `pkinative: ${String(epochMilliseconds)} is not an instant in the years 0000 to 9999`);
    }
    const millisecond = date.getUTCMilliseconds();
    const resolved = type === 'rfc5280' ? (year >= 1950 && year <= 2049 ? 'UTCTime' : 'GeneralizedTime') : type;
    if (millisecond !== 0 && type !== 'GeneralizedTime') {
        throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE',
            `pkinative: ${date.toISOString()} has a fraction of a second, which ${type === 'rfc5280' ? 'RFC 5280 forbids in certificates' : 'UTCTime cannot hold'} — round to whole seconds`);
    }
    const clock = `${pad(date.getUTCMonth() + 1, 2)}${pad(date.getUTCDate(), 2)}${pad(date.getUTCHours(), 2)}${pad(date.getUTCMinutes(), 2)}${pad(date.getUTCSeconds(), 2)}`;
    let text: string;
    if (resolved === 'UTCTime') {
        if (year < 1950 || year > 2049) {
            throw new PkiEncodingError('PKI_ASN1_VALUE_OUT_OF_RANGE', `pkinative: UTCTime covers 1950 to 2049 only; ${year} needs GeneralizedTime`);
        }
        text = `${pad(year % 100, 2)}${clock}Z`;
    } else {
        const fraction = millisecond === 0 ? '' : `.${pad(millisecond, 3).replace(/0+$/, '')}`;
        text = `${pad(year, 4)}${clock}${fraction}Z`;
    }
    const content = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) content[i] = text.charCodeAt(i);
    return encodeTlv('universal', resolved === 'UTCTime' ? TAG_UTC_TIME : TAG_GENERALIZED_TIME, false, content);
}

// ── Re-encoding ──────────────────────────────────────────────────────

/**
 * Re-encode a decoded node tree in DER. For a tree decoded under DER the
 * result is byte-identical to the input it came from. Iterative, like the decoder.
 *
 * @param node A node returned by decodeAsn1.
 * @returns The DER encoding of the tree.
 * @throws {PkiError} `PKI_API_MISUSE` for an indefinite-length node or a constructed string, which have no DER form.
 */
export function encodeAsn1Node(node: Asn1Node): Uint8Array {
    const root = assertNode(node, 'encodeAsn1Node');
    const stack: Array<{ readonly node: Asn1Node; next: number; readonly parts: Uint8Array[] }> = [{ node: root, next: 0, parts: [] }];
    let result: Uint8Array = new Uint8Array(0);
    while (stack.length > 0) {
        const top = stack[stack.length - 1] as { readonly node: Asn1Node; next: number; readonly parts: Uint8Array[] };
        const current = top.node;
        if (current.indefinite) {
            throw new PkiError('PKI_API_MISUSE',
                `pkinative: the value at offset ${current.offset} was decoded from the BER indefinite length form, which has no DER re-encoding — decode the original as DER, or keep its bytes`);
        }
        let encoded: Uint8Array;
        if (!current.constructed) {
            encoded = encodeTlv(current.tagClass, current.tagNumber, false, current.content);
        } else {
            if (current.tagClass === 'universal' && isStringTag(current.tagNumber)) {
                throw new PkiError('PKI_API_MISUSE',
                    `pkinative: the ${tagLabel(current.tagClass, current.tagNumber)} at offset ${current.offset} is a constructed string, which has no DER form — read it with the string reader and encode the result`);
            }
            if (top.next < current.children.length) {
                stack.push({ node: current.children[top.next] as Asn1Node, next: 0, parts: [] });
                top.next++;
                continue;
            }
            encoded = encodeTlv(current.tagClass, current.tagNumber, true, concatBytes(top.parts));
        }
        stack.pop();
        const parent = stack[stack.length - 1];
        if (parent === undefined) result = encoded;
        else parent.parts.push(encoded);
    }
    return result;
}
