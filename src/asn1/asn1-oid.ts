/**
 * pkinative — OBJECT IDENTIFIER codec
 * ===================================
 * X.690 §8.19: content octets ↔ dotted decimal. Arcs of any size are exact —
 * `2.25.<UUID>` arcs exceed 2^53 and switch to bigint arithmetic — and the
 * encoder always emits the minimal base-128 form the decoder demands.
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
import { TAG_OID } from './asn1-tags.js';

/** Above this, one more base-128 digit could leave the exact integer range of a number. */
const EXACT_LIMIT = 0x3fffffffffff;

/** @internal */
export function _decodeOid(content: Uint8Array, offset: number, ctx: Asn1Context): string {
    if (content.length === 0) {
        throw new PkiEncodingError('PKI_OID_INVALID',
            `pkinative: the OBJECT IDENTIFIER at offset ${offset} has no content octet (X.690 §8.19.2)`, offset);
    }
    enforceLimit(ctx.limits, 'maxOidBytes', content.length, 'the OBJECT IDENTIFIER content length');
    const arcs: string[] = [];
    let value = 0;
    let big: bigint | null = null;
    let inArc = false;
    for (const octet of content) {
        if (!inArc && octet === 0x80) {
            throw new PkiEncodingError('PKI_OID_INVALID',
                `pkinative: a subidentifier of the OBJECT IDENTIFIER at offset ${offset} starts with 0x80, a non-minimal form X.690 §8.19.2 forbids`, offset);
        }
        inArc = true;
        if (big === null && value > EXACT_LIMIT) big = BigInt(value);
        if (big === null) value = value * 128 + (octet & 0x7f);
        else big = big * 128n + BigInt(octet & 0x7f);
        if ((octet & 0x80) !== 0) continue;
        if (arcs.length === 0) {
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
            `pkinative: the OBJECT IDENTIFIER at offset ${offset} ends inside a subidentifier — the input is truncated or corrupt`, offset);
    }
    return arcs.join('.');
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

/** @internal */
export function _readObjectIdentifier(node: Asn1Node, ctx: Asn1Context): string {
    expectUniversal(node, TAG_OID);
    if (node.constructed) {
        throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_FORM_INVALID',
            `pkinative: the OBJECT IDENTIFIER at offset ${node.offset} is constructed, but X.690 encodes it in primitive form only`, node.offset);
    }
    return _decodeOid(node.content, node.offset, ctx);
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

/**
 * X.660: two or more arcs, no leading zeros, and — under the 0 and 1 trees —
 * a second arc of 0 to 39, which the alternation states outright rather than
 * leaving to a `BigInt` comparison the grammar then has to be trusted about.
 */
const DOTTED = /^(?:[01]\.(?:[0-9]|[123][0-9])|2\.(?:0|[1-9][0-9]*))(?:\.(?:0|[1-9][0-9]*))*$/;

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
            `pkinative: "${oid.length > 64 ? `${oid.slice(0, 61)}…` : oid}" is not a dotted-decimal OID — use two or more decimal arcs without leading zeros, a first arc of 0, 1 or 2, and a second arc of at most 39 under 0 and 1`);
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
