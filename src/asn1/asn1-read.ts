/**
 * pkinative — ASN.1 value readers
 * ===============================
 * Typed readers over decoded nodes: BOOLEAN, INTEGER, NULL, BIT STRING,
 * OCTET STRING and the character string types.
 *
 * A reader accepts its universal tag, or any non-universal tag — an
 * implicitly tagged value, whose type only the schema knows. A universal tag
 * of another type is `PKI_ASN1_UNEXPECTED_TAG`. Strictness follows the
 * encoding rules of the call: under DER the canonical forms of X.690 §11 are
 * required; under BER the tolerated deviations are reported once as
 * diagnostics.
 *
 * Every public reader has an internal `_read*` twin that takes the operation
 * context, so a structure parser reads a whole certificate under one context.
 *
 * @module asn1/asn1-read
 */

import { concatBytes } from '../core/bytes.js';
import { printableStringCharsetDiagnostic, teletexAsLatin1Diagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import {
    decodeAsciiSubset,
    decodeLatin1,
    decodeUcs2Be,
    decodeUcs4Be,
    decodeUtf8,
    firstOctetOutside,
    isIa5Octet,
    isNumericOctet,
    isPrintableOctet,
    isVisibleOctet,
} from '../core/text.js';
import type { Asn1Node, Asn1String, Asn1StringType, BitString, ReadStringOptions } from '../types/asn1-types.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import { createAsn1Context, noteBer, type Asn1Context } from './asn1-context.js';
import {
    STRING_TAGS,
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_INTEGER,
    TAG_NULL,
    TAG_OCTET_STRING,
    stringTypeOfTag,
    tagLabel,
} from './asn1-tags.js';

// ── Shared checks ────────────────────────────────────────────────────

/**
 * Refuse something that is not a decoded node before any field is read.
 *
 * @internal
 */
export function assertNode(node: unknown, reader: string): Asn1Node {
    const candidate = node as Partial<Asn1Node> | null;
    if (typeof node !== 'object' || candidate === null || !(candidate.content instanceof Uint8Array)
        || !Array.isArray(candidate.children) || typeof candidate.tagNumber !== 'number') {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${reader} expects a node returned by decodeAsn1, got ${node === null ? 'null' : typeof node}`);
    }
    return node as Asn1Node;
}

/**
 * A universal tag must be the expected one; a non-universal tag is an implicit tag and passes.
 *
 * @internal
 */
export function expectUniversal(node: Asn1Node, tagNumber: number): void {
    if (node.tagClass === 'universal' && node.tagNumber !== tagNumber) {
        throw new PkiEncodingError('PKI_ASN1_UNEXPECTED_TAG',
            `pkinative: expected ${tagLabel('universal', tagNumber)} at offset ${node.offset}, found ${tagLabel(node.tagClass, node.tagNumber)} — check that the input is the structure this reader expects`, node.offset);
    }
}

function expectPrimitive(node: Asn1Node, what: string): void {
    if (node.constructed) {
        throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_FORM_INVALID',
            `pkinative: the ${what} at offset ${node.offset} is constructed, but X.690 encodes it in primitive form only`, node.offset);
    }
}

/**
 * The content of a string-like value: its content octets when primitive, the
 * concatenation of its segments when constructed (BER only). Segments must
 * carry `segmentTag` (X.690 §8.6.4, §8.7.3, §8.23.6).
 *
 * @internal
 */
export function stringContent(node: Asn1Node, ctx: Asn1Context, segmentTag: number, what: string): Uint8Array {
    if (!node.constructed) return node.content;
    if (ctx.rules === 'der') {
        throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN',
            `pkinative: the ${what} at offset ${node.offset} is in constructed form, which DER forbids (X.690 §10.2) — decode with encodingRules: 'ber' if the input is BER`, node.offset);
    }
    noteBer(ctx, 'constructed string', node.offset);
    const segments: Uint8Array[] = [];
    const stack: Asn1Node[] = [...node.children].reverse();
    while (stack.length > 0) {
        const segment = stack.pop() as Asn1Node;
        if (segment.tagClass !== 'universal' || segment.tagNumber !== segmentTag) {
            throw new PkiEncodingError('PKI_ASN1_UNEXPECTED_TAG',
                `pkinative: a segment of the constructed ${what} at offset ${node.offset} is ${tagLabel(segment.tagClass, segment.tagNumber)}, not ${tagLabel('universal', segmentTag)} (X.690 §8.7.3)`, segment.offset);
        }
        if (segment.constructed) {
            for (let i = segment.children.length - 1; i >= 0; i--) stack.push(segment.children[i] as Asn1Node);
            continue;
        }
        segments.push(segment.content);
        enforceLimit(ctx.limits, 'maxBerSegments', segments.length, `the segments of the constructed ${what}`);
    }
    return concatBytes(segments);
}

// ── BOOLEAN ──────────────────────────────────────────────────────────

/** @internal */
export function _readBoolean(node: Asn1Node, ctx: Asn1Context): boolean {
    expectUniversal(node, TAG_BOOLEAN);
    expectPrimitive(node, 'BOOLEAN');
    if (node.contentLength !== 1) {
        throw new PkiEncodingError('PKI_ASN1_BOOLEAN_INVALID',
            `pkinative: the BOOLEAN at offset ${node.offset} has ${node.contentLength} content octets; X.690 §8.2.1 requires exactly one`, node.offset);
    }
    const value = node.content[0] ?? 0;
    if (value !== 0x00 && value !== 0xff) {
        if (ctx.rules === 'der') {
            throw new PkiEncodingError('PKI_ASN1_BOOLEAN_INVALID',
                `pkinative: the BOOLEAN at offset ${node.offset} encodes TRUE as 0x${value.toString(16).padStart(2, '0')}; DER requires 0xFF (X.690 §11.1)`, node.offset);
        }
        noteBer(ctx, 'non-canonical BOOLEAN', node.offset);
    }
    return value !== 0;
}

/**
 * Read a BOOLEAN.
 *
 * @param node    A BOOLEAN node, or an implicitly tagged one.
 * @param options Encoding rules and diagnostics (DER requires TRUE as 0xFF).
 * @returns The boolean value.
 * @throws {PkiEncodingError} `PKI_ASN1_UNEXPECTED_TAG`, `PKI_ASN1_CONSTRUCTED_FORM_INVALID` or `PKI_ASN1_BOOLEAN_INVALID`.
 */
export function readBoolean(node: Asn1Node, options?: PkiParseOptions): boolean {
    return _readBoolean(assertNode(node, 'readBoolean'), createAsn1Context(options));
}

// ── INTEGER ──────────────────────────────────────────────────────────

/** @internal */
export function _readInteger(node: Asn1Node, ctx: Asn1Context): bigint {
    expectUniversal(node, TAG_INTEGER);
    expectPrimitive(node, 'INTEGER');
    const content = node.content;
    if (content.length === 0) {
        throw new PkiEncodingError('PKI_ASN1_INTEGER_INVALID',
            `pkinative: the INTEGER at offset ${node.offset} has no content octet (X.690 §8.3.1)`, node.offset);
    }
    enforceLimit(ctx.limits, 'maxIntegerBytes', content.length, 'the INTEGER content length');
    const first = content[0] ?? 0;
    if (content.length > 1) {
        const second = content[1] ?? 0;
        if ((first === 0x00 && (second & 0x80) === 0) || (first === 0xff && (second & 0x80) !== 0)) {
            throw new PkiEncodingError('PKI_ASN1_INTEGER_INVALID',
                `pkinative: the INTEGER at offset ${node.offset} is not in minimal two's complement form (X.690 §8.3.2) — the encoder is broken`, node.offset);
        }
    }
    let hex = '';
    for (let i = 0; i < content.length; i++) hex += (content[i] ?? 0).toString(16).padStart(2, '0');
    let value = BigInt(`0x${hex}`);
    if ((first & 0x80) !== 0) value -= 1n << BigInt(content.length * 8);
    return value;
}

/**
 * Read an INTEGER of any size.
 *
 * @param node    An INTEGER node, or an implicitly tagged one.
 * @param options Limits (`maxIntegerBytes`) and diagnostics.
 * @returns The value as a bigint.
 * @throws {PkiEncodingError} `PKI_ASN1_UNEXPECTED_TAG`, `PKI_ASN1_CONSTRUCTED_FORM_INVALID` or `PKI_ASN1_INTEGER_INVALID`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond `maxIntegerBytes`.
 */
export function readInteger(node: Asn1Node, options?: PkiParseOptions): bigint {
    return _readInteger(assertNode(node, 'readInteger'), createAsn1Context(options));
}

/** @internal */
export function _readSmallInteger(node: Asn1Node, ctx: Asn1Context): number {
    const value = _readInteger(node, ctx);
    if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < -BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new PkiEncodingError('PKI_ASN1_INTEGER_UNREPRESENTABLE',
            `pkinative: the INTEGER at offset ${node.offset} is outside ±(2^53 − 1) — read it with readInteger to get a bigint`, node.offset);
    }
    return Number(value);
}

/**
 * Read an INTEGER that must fit in a JavaScript number.
 *
 * @param node An INTEGER node, or an implicitly tagged one.
 * @returns The value as a number.
 * @throws {PkiEncodingError} `PKI_ASN1_INTEGER_UNREPRESENTABLE` outside ±(2^53 − 1), and the errors of readInteger.
 */
export function readSmallInteger(node: Asn1Node): number {
    return _readSmallInteger(assertNode(node, 'readSmallInteger'), createAsn1Context(undefined));
}

// ── NULL ─────────────────────────────────────────────────────────────

/**
 * Read a NULL.
 *
 * @param node A NULL node, or an implicitly tagged one.
 * @returns null.
 * @throws {PkiEncodingError} `PKI_ASN1_UNEXPECTED_TAG`, `PKI_ASN1_CONSTRUCTED_FORM_INVALID` or `PKI_ASN1_NULL_INVALID`.
 */
export function readNull(node: Asn1Node): null {
    const checked = assertNode(node, 'readNull');
    expectUniversal(checked, TAG_NULL);
    expectPrimitive(checked, 'NULL');
    if (checked.contentLength !== 0) {
        throw new PkiEncodingError('PKI_ASN1_NULL_INVALID',
            `pkinative: the NULL at offset ${checked.offset} has ${checked.contentLength} content octets; X.690 §8.8.2 requires none`, checked.offset);
    }
    return null;
}

// ── BIT STRING ───────────────────────────────────────────────────────

function bitStringFromContent(content: Uint8Array, offset: number, ctx: Asn1Context): BitString {
    if (content.length === 0) {
        throw new PkiEncodingError('PKI_ASN1_BIT_STRING_INVALID',
            `pkinative: the BIT STRING at offset ${offset} has no initial octet; X.690 §8.6.2.2 requires the unused-bits count`, offset);
    }
    const unusedBits = content[0] ?? 0;
    if (unusedBits > 7) {
        throw new PkiEncodingError('PKI_ASN1_BIT_STRING_INVALID',
            `pkinative: the BIT STRING at offset ${offset} declares ${unusedBits} unused bits; X.690 §8.6.2.2 allows 0 to 7`, offset);
    }
    if (content.length === 1 && unusedBits !== 0) {
        throw new PkiEncodingError('PKI_ASN1_BIT_STRING_INVALID',
            `pkinative: the empty BIT STRING at offset ${offset} declares ${unusedBits} unused bits; X.690 §8.6.2.3 requires 0`, offset);
    }
    if (unusedBits !== 0 && ((content[content.length - 1] ?? 0) & ((1 << unusedBits) - 1)) !== 0) {
        if (ctx.rules === 'der') {
            throw new PkiEncodingError('PKI_ASN1_BIT_STRING_INVALID',
                `pkinative: the BIT STRING at offset ${offset} has non-zero unused bits; DER requires them to be zero (X.690 §11.2.1)`, offset);
        }
        noteBer(ctx, 'non-zero BIT STRING padding', offset);
    }
    return Object.freeze({ bytes: content.subarray(1), unusedBits });
}

/** @internal */
export function _readBitString(node: Asn1Node, ctx: Asn1Context): BitString {
    expectUniversal(node, TAG_BIT_STRING);
    if (!node.constructed) return bitStringFromContent(node.content, node.offset, ctx);
    if (ctx.rules === 'der') {
        throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN',
            `pkinative: the BIT STRING at offset ${node.offset} is in constructed form, which DER forbids (X.690 §10.2) — decode with encodingRules: 'ber' if the input is BER`, node.offset);
    }
    noteBer(ctx, 'constructed string', node.offset);
    const parts: Uint8Array[] = [];
    let unusedBits = 0;
    const stack: Asn1Node[] = [...node.children].reverse();
    while (stack.length > 0) {
        const segment = stack.pop() as Asn1Node;
        if (segment.tagClass !== 'universal' || segment.tagNumber !== TAG_BIT_STRING) {
            throw new PkiEncodingError('PKI_ASN1_UNEXPECTED_TAG',
                `pkinative: a segment of the constructed BIT STRING at offset ${node.offset} is ${tagLabel(segment.tagClass, segment.tagNumber)}, not BIT STRING (X.690 §8.6.4)`, segment.offset);
        }
        if (segment.constructed) {
            for (let i = segment.children.length - 1; i >= 0; i--) stack.push(segment.children[i] as Asn1Node);
            continue;
        }
        if (unusedBits !== 0) {
            throw new PkiEncodingError('PKI_ASN1_BIT_STRING_INVALID',
                `pkinative: a segment before the last one of the BIT STRING at offset ${node.offset} declares unused bits; X.690 §8.6.4 allows them only in the last segment`, segment.offset);
        }
        const piece = bitStringFromContent(segment.content, segment.offset, ctx);
        parts.push(piece.bytes);
        unusedBits = piece.unusedBits;
        enforceLimit(ctx.limits, 'maxBerSegments', parts.length, 'the segments of the constructed BIT STRING');
    }
    return Object.freeze({ bytes: concatBytes(parts), unusedBits });
}

/**
 * Read a BIT STRING.
 *
 * @param node    A BIT STRING node (constructed only under BER), or an implicitly tagged one.
 * @param options Encoding rules (DER requires zero padding bits), limits and diagnostics.
 * @returns The octets (a zero-copy view when primitive) and the unused-bits count.
 * @throws {PkiEncodingError} `PKI_ASN1_BIT_STRING_INVALID`, `PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN` or `PKI_ASN1_UNEXPECTED_TAG`.
 */
export function readBitString(node: Asn1Node, options?: PkiParseOptions): BitString {
    return _readBitString(assertNode(node, 'readBitString'), createAsn1Context(options));
}

// ── OCTET STRING ─────────────────────────────────────────────────────

/** @internal */
export function _readOctetString(node: Asn1Node, ctx: Asn1Context): Uint8Array {
    expectUniversal(node, TAG_OCTET_STRING);
    return stringContent(node, ctx, TAG_OCTET_STRING, 'OCTET STRING');
}

/**
 * Read an OCTET STRING.
 *
 * @param node    An OCTET STRING node (constructed only under BER), or an implicitly tagged one.
 * @param options Encoding rules, limits (`maxBerSegments`) and diagnostics.
 * @returns The octets: a zero-copy view when primitive, a joined copy when segmented.
 * @throws {PkiEncodingError} `PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN` or `PKI_ASN1_UNEXPECTED_TAG`.
 */
export function readOctetString(node: Asn1Node, options?: PkiParseOptions): Uint8Array {
    return _readOctetString(assertNode(node, 'readOctetString'), createAsn1Context(options));
}

// ── Character strings ────────────────────────────────────────────────

function invalidString(node: Asn1Node, type: Asn1StringType, why: string): PkiEncodingError {
    return new PkiEncodingError('PKI_ASN1_STRING_INVALID',
        `pkinative: the ${tagLabel('universal', STRING_TAGS[type])} at offset ${node.offset} ${why} — the issuer encoded it wrongly`, node.offset);
}

/** @internal */
export function _readString(node: Asn1Node, ctx: Asn1Context, implicitType: Asn1StringType | undefined, path: string): Asn1String {
    let type: Asn1StringType | undefined;
    if (node.tagClass === 'universal') {
        type = stringTypeOfTag(node.tagNumber);
        if (type === undefined) {
            throw new PkiEncodingError('PKI_ASN1_UNEXPECTED_TAG',
                `pkinative: expected a character string at offset ${node.offset}, found ${tagLabel(node.tagClass, node.tagNumber)}`, node.offset);
        }
    } else {
        type = implicitType;
        if (type === undefined) {
            throw new PkiError('PKI_API_MISUSE',
                `pkinative: the value at offset ${node.offset} carries the implicit tag ${tagLabel(node.tagClass, node.tagNumber)}; pass stringType to say which string type it is`);
        }
    }
    const raw = stringContent(node, ctx, TAG_OCTET_STRING, tagLabel('universal', STRING_TAGS[type]));
    let value: string | null;
    switch (type) {
        case 'utf8':
            value = decodeUtf8(raw);
            if (value === null) throw invalidString(node, type, 'is not well-formed UTF-8 (RFC 3629)');
            break;
        case 'bmp':
            value = decodeUcs2Be(raw);
            if (value === null) throw invalidString(node, type, 'has an odd length or a surrogate code unit, which UCS-2 does not allow');
            break;
        case 'universal':
            value = decodeUcs4Be(raw);
            if (value === null) throw invalidString(node, type, 'has a length that is not a multiple of four or a value outside the Unicode scalar range');
            break;
        case 'teletex':
            value = decodeLatin1(raw);
            ctx.emitter.emit(teletexAsLatin1Diagnostic(path, node.offset));
            break;
        case 'printable': {
            value = decodeAsciiSubset(raw, isIa5Octet);
            if (value === null) throw invalidString(node, type, 'contains an octet above 0x7F');
            const outside = firstOctetOutside(raw, isPrintableOctet);
            if (outside >= 0) ctx.emitter.emit(printableStringCharsetDiagnostic(path, String.fromCharCode(raw[outside] ?? 0), node.offset));
            break;
        }
        case 'ia5':
            value = decodeAsciiSubset(raw, isIa5Octet);
            if (value === null) throw invalidString(node, type, 'contains an octet above 0x7F');
            break;
        case 'visible':
            value = decodeAsciiSubset(raw, isVisibleOctet);
            if (value === null) throw invalidString(node, type, 'contains an octet outside printing ASCII');
            break;
        case 'numeric':
            value = decodeAsciiSubset(raw, isNumericOctet);
            if (value === null) throw invalidString(node, type, 'contains an octet other than a digit or a space');
            break;
    }
    return Object.freeze({ stringType: type, value, raw });
}

/**
 * Read a character string: UTF8String, NumericString, PrintableString,
 * TeletexString (as ISO 8859-1, with a diagnostic), IA5String, VisibleString,
 * UniversalString or BMPString.
 *
 * @param node    A string node, or an implicitly tagged one together with `stringType`.
 * @param options Encoding rules, limits, diagnostics, and the type of an implicit tag.
 * @returns The type, the decoded text and the original octets.
 * @throws {PkiEncodingError} `PKI_ASN1_STRING_INVALID`, `PKI_ASN1_UNEXPECTED_TAG` or `PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN`.
 * @throws {PkiError} `PKI_API_MISUSE` for an implicit tag without `stringType`; `PKI_INVALID_OPTION` for an unknown `stringType`.
 */
export function readString(node: Asn1Node, options?: ReadStringOptions): Asn1String {
    const checked = assertNode(node, 'readString');
    const ctx = createAsn1Context(options);
    const implicitType = options?.stringType;
    if (implicitType !== undefined && !(implicitType in STRING_TAGS)) {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: stringType must be one of ${Object.keys(STRING_TAGS).join(', ')}, got ${String(implicitType)}`);
    }
    return _readString(checked, ctx, implicitType, '');
}
