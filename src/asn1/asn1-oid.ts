/**
 * pkinative — OBJECT IDENTIFIER and RELATIVE-OID codec
 * ====================================================
 * X.690 §8.19 and §8.20: content octets ↔ dotted decimal. Arcs of any size
 * are exact — `2.25.<UUID>` arcs exceed 2^53 and switch to bigint
 * arithmetic — and the encoder always emits the minimal base-128 form the
 * decoder demands. A RELATIVE-OID is the same subidentifier encoding without
 * the first-two-arcs packing of §8.19.4: one arc per subidentifier, at least
 * one arc, no X.660 tree to hold the first two to.
 *
 * @module asn1/asn1-oid
 */

import { assertBytes } from '../core/bytes.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import { createAsn1Context, type Asn1Context } from './asn1-context.js';
import { assertNode, expectUniversal } from './asn1-read.js';
import { TAG_OID, TAG_RELATIVE_OID } from './asn1-tags.js';

/** Above this, one more base-128 digit could leave the exact integer range of a number. */
const EXACT_LIMIT = 0x3fffffffffff;

// ── Decoding ─────────────────────────────────────────────────────────

/**
 * The subidentifiers of an OBJECT IDENTIFIER or a RELATIVE-OID, as arcs.
 * `relative` decides whether the first subidentifier packs two arcs
 * (X.690 §8.19.4) or is one arc like every other (§8.20.2).
 */
function decodeArcs(content: Uint8Array, offset: number, ctx: Asn1Context, relative: boolean): string {
    const what = relative ? 'RELATIVE-OID' : 'OBJECT IDENTIFIER';
    const section = relative ? '8.20.2' : '8.19.2';
    if (content.length === 0) {
        throw new PkiEncodingError('PKI_OID_INVALID',
            `pkinative: the ${what} at offset ${offset} has no content octet (X.690 §${section})`, offset);
    }
    enforceLimit(ctx.limits, 'maxOidBytes', content.length, `the ${what} content length`);
    const arcs: string[] = [];
    let value = 0;
    let big: bigint | null = null;
    let inArc = false;
    for (const octet of content) {
        if (!inArc && octet === 0x80) {
            throw new PkiEncodingError('PKI_OID_INVALID',
                `pkinative: a subidentifier of the ${what} at offset ${offset} starts with 0x80, a non-minimal form X.690 §${section} forbids`, offset);
        }
        inArc = true;
        if (big === null && value > EXACT_LIMIT) big = BigInt(value);
        if (big === null) value = value * 128 + (octet & 0x7f);
        else big = big * 128n + BigInt(octet & 0x7f);
        if ((octet & 0x80) !== 0) continue;
        if (arcs.length === 0 && !relative) {
            // The first subidentifier packs the first two arcs (X.690 §8.19.4).
            if (big === null) {
                if (value < 40) arcs.push('0', String(value));
                else if (value < 80) arcs.push('1', String(value - 40));
                else arcs.push('2', String(value - 80));
            } else {
                arcs.push('2', String(big - 80n));
            }
        } else {
            arcs.push(big === null ? String(value) : String(big));
        }
        value = 0;
        big = null;
        inArc = false;
    }
    if (inArc) {
        throw new PkiEncodingError('PKI_OID_INVALID',
            `pkinative: the ${what} at offset ${offset} ends inside a subidentifier — the input is truncated or corrupt`, offset);
    }
    return arcs.join('.');
}

/** @internal */
export function _decodeOid(content: Uint8Array, offset: number, ctx: Asn1Context): string {
    return decodeArcs(content, offset, ctx, false);
}

/**
 * Decode the content octets of an OBJECT IDENTIFIER to dotted decimal.
 *
 * @param content The content octets (not the tag and length).
 * @param options Limits (`maxOidBytes`).
 * @returns The dotted-decimal OID, e.g. `1.2.840.113549.1.1.11`.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for empty, non-minimal or truncated content.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond `maxOidBytes`.
 */
export function decodeOid(content: Uint8Array, options?: PkiParseOptions): string {
    return _decodeOid(assertBytes(content, 'decodeOid content'), 0, createAsn1Context(options));
}

function expectPrimitiveIdentifier(node: Asn1Node, what: string): void {
    if (node.constructed) {
        throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_FORM_INVALID',
            `pkinative: the ${what} at offset ${node.offset} is constructed, but X.690 encodes it in primitive form only`, node.offset);
    }
}

/** @internal */
export function _readObjectIdentifier(node: Asn1Node, ctx: Asn1Context): string {
    expectUniversal(node, TAG_OID);
    expectPrimitiveIdentifier(node, 'OBJECT IDENTIFIER');
    return decodeArcs(node.content, node.offset, ctx, false);
}

/**
 * Read an OBJECT IDENTIFIER node.
 *
 * @param node    An OBJECT IDENTIFIER node, or an implicitly tagged one.
 * @param options Limits (`maxOidBytes`).
 * @returns The dotted-decimal OID.
 * @throws {PkiEncodingError} `PKI_OID_INVALID`, `PKI_ASN1_UNEXPECTED_TAG` or `PKI_ASN1_CONSTRUCTED_FORM_INVALID`.
 */
export function readObjectIdentifier(node: Asn1Node, options?: PkiParseOptions): string {
    return _readObjectIdentifier(assertNode(node, 'readObjectIdentifier'), createAsn1Context(options));
}

/** @internal */
export function _readRelativeOid(node: Asn1Node, ctx: Asn1Context): string {
    expectUniversal(node, TAG_RELATIVE_OID);
    expectPrimitiveIdentifier(node, 'RELATIVE-OID');
    return decodeArcs(node.content, node.offset, ctx, true);
}

/**
 * Read a RELATIVE-OID node (X.690 §8.20): universal tag 13, the subidentifier
 * encoding of an OBJECT IDENTIFIER without the first-two-arcs packing, so
 * `0D 04 C2 7B 03 02` reads as `8571.3.2` (the §8.20.2 example).
 *
 * @param node    A RELATIVE-OID node, or an implicitly tagged one.
 * @param options Limits (`maxOidBytes`).
 * @returns The arcs in dotted decimal, e.g. `8571.3.2`.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for empty, non-minimal or truncated content; `PKI_ASN1_UNEXPECTED_TAG` or `PKI_ASN1_CONSTRUCTED_FORM_INVALID`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond `maxOidBytes`.
 */
export function readRelativeOid(node: Asn1Node, options?: PkiParseOptions): string {
    return _readRelativeOid(assertNode(node, 'readRelativeOid'), createAsn1Context(options));
}

// ── Encoding ─────────────────────────────────────────────────────────

/**
 * X.660: two or more arcs, no leading zeros, and — under the 0 and 1 trees —
 * a second arc of 0 to 39, which the alternation states outright rather than
 * leaving to a `BigInt` comparison the grammar then has to be trusted about.
 */
const DOTTED = /^(?:[01]\.(?:[0-9]|[123][0-9])|2\.(?:0|[1-9][0-9]*))(?:\.(?:0|[1-9][0-9]*))*$/;

/** X.680 §33: one or more arcs, each a non-negative integer without leading zeros. */
const RELATIVE_DOTTED = /^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*$/;

/**
 * Whether a string is a dotted-decimal OID X.660 allows: at least two arcs,
 * the first 0, 1 or 2, the second at most 39 under 0 and 1, no leading zeros.
 *
 * @param oid The candidate string.
 * @returns True when `encodeOid` accepts it; false for anything else, a non-string included.
 * @throws Never.
 */
export function isValidOid(oid: string): boolean {
    return typeof oid === 'string' && DOTTED.test(oid);
}

/** The minimal base-128 encoding of subidentifiers, in order (X.690 §8.19.2, §8.20.2). */
function encodeSubidentifiers(subidentifiers: readonly bigint[]): Uint8Array {
    const out: number[] = [];
    for (const sub of subidentifiers) {
        // Most significant digit first, so the emitting loop reads them in
        // order and the continuation bit is a countdown, not an index.
        const digits: number[] = [];
        let rest = sub;
        do {
            digits.unshift(Number(rest & 0x7fn));
            rest >>= 7n;
        } while (rest > 0n);
        let remaining = digits.length;
        for (const digit of digits) {
            remaining--;
            out.push(digit | (remaining > 0 ? 0x80 : 0));
        }
    }
    return Uint8Array.from(out);
}

/** The string shown in a refusal: cut so that a hostile argument cannot fill the message. */
function shown(oid: string): string {
    return oid.length > 64 ? `${oid.slice(0, 61)}…` : oid;
}

/**
 * Encode a dotted-decimal OID as content octets (without tag and length).
 *
 * @param oid A dotted-decimal OID, e.g. `2.5.29.17`.
 * @returns The minimal base-128 content octets.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` when `isValidOid` rejects the string.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the argument is not a string.
 */
export function encodeOid(oid: string): Uint8Array {
    if (typeof oid !== 'string') {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: encodeOid expects a dotted-decimal string, got ${typeof oid}`);
    }
    if (!isValidOid(oid)) {
        throw new PkiEncodingError('PKI_OID_INVALID',
            `pkinative: "${shown(oid)}" is not a dotted-decimal OID — use two or more decimal arcs without leading zeros, a first arc of 0, 1 or 2, and a second arc of at most 39 under 0 and 1`);
    }
    // X.690 §8.19.4: the first two arcs share one subidentifier. Accumulated
    // rather than indexed, because an indexed read of a split() result is
    // `string | undefined` and its fallback is a branch the grammar above
    // has already made unreachable.
    const subidentifiers: bigint[] = [];
    let head: bigint | null = null;
    for (const arc of oid.split('.')) {
        const value = BigInt(arc);
        if (head === null) head = value * 40n;
        else if (subidentifiers.length === 0) subidentifiers.push(head + value);
        else subidentifiers.push(value);
    }
    return encodeSubidentifiers(subidentifiers);
}

/**
 * Encode the arcs of a RELATIVE-OID as content octets (without tag and
 * length): one subidentifier per arc (X.690 §8.20.2).
 *
 * @internal
 */
export function _encodeRelativeOid(oid: string): Uint8Array {
    if (typeof oid !== 'string') {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: encodeRelativeOid expects a dotted-decimal string, got ${typeof oid}`);
    }
    if (!RELATIVE_DOTTED.test(oid)) {
        throw new PkiEncodingError('PKI_OID_INVALID',
            `pkinative: "${shown(oid)}" is not a dotted-decimal RELATIVE-OID — use one or more decimal arcs without leading zeros, separated by dots`);
    }
    return encodeSubidentifiers(oid.split('.').map((arc) => BigInt(arc)));
}
