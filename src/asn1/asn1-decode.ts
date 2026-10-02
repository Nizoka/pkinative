/**
 * pkinative — ASN.1 decoder
 * =========================
 * An ITU-T X.690 decoder that is strict DER by default and BER on request.
 *
 * It is iterative: constructed values are opened on an explicit stack, so
 * nesting depth is the named limit `maxDepth` and never the JavaScript call
 * stack. Every length is checked against the enclosing value before a child
 * is read, every value counts against `maxNodes`, and the input size against
 * `maxInputBytes` before the first byte.
 *
 * Under DER it refuses, with a stable code, every form X.690 §10–11 forbids:
 * indefinite lengths, non-minimal lengths, constructed strings — the
 * ambiguities that let two parsers read one signed byte string differently.
 * Every node keeps a zero-copy view of its exact bytes, so signed content is
 * never re-serialised to be verified.
 *
 * pdfnative's decoder, which this replaces, read lengths with a signed 32-bit
 * shift (`84 80 00 00 01` became a negative length that passed its bounds
 * check), recursed without limit and ignored trailing bytes.
 *
 * @module asn1/asn1-decode
 */

import { assertBytes, byteView } from '../core/bytes.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, DecodeAsn1Options, TagClass } from '../types/asn1-types.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import { createAsn1Context, noteBer, type Asn1Context } from './asn1-context.js';
import { isConstructedOnly, isPrimitiveOnly, isStringTag, tagClassOf, tagLabel } from './asn1-tags.js';

interface Header {
    readonly tagClass: TagClass;
    readonly tagNumber: number;
    readonly constructed: boolean;
    readonly headerLength: number;
    /** null for the indefinite form. */
    readonly length: number | null;
}

interface Frame {
    readonly tagClass: TagClass;
    readonly tagNumber: number;
    readonly offset: number;
    readonly headerLength: number;
    readonly contentStart: number;
    /** null for the indefinite form: the end is the end-of-contents marker. */
    readonly contentEnd: number | null;
    /**
     * The offset no child may cross: `contentEnd` for the definite form; for the
     * indefinite form, the bound of the enclosing value, or the end of the input.
     */
    readonly bound: number;
    /** Whether `bound` is the end of the input rather than the end of an enclosing value. */
    readonly boundIsInput: boolean;
    readonly children: Asn1Node[];
}

function where(endIsInput: boolean): string {
    return endIsInput ? 'input' : 'enclosing value';
}

function readHeader(view: DataView, offset: number, end: number, endIsInput: boolean, ctx: Asn1Context): Header {
    if (offset >= end) {
        throw new PkiEncodingError('PKI_ASN1_TRUNCATED',
            `pkinative: expected an identifier octet at offset ${offset}, but the ${where(endIsInput)} ends there — the input is incomplete`, offset);
    }
    const first = view.getUint8(offset);
    const tagClass = tagClassOf(first);
    const constructed = (first & 0x20) !== 0;
    let tagNumber = first & 0x1f;
    let at = offset + 1;

    if (tagNumber === 0x1f) {
        tagNumber = 0;
        for (let index = 0; ; index++) {
            if (at >= end) {
                throw new PkiEncodingError('PKI_ASN1_TRUNCATED',
                    `pkinative: the high-tag-number identifier at offset ${offset} runs past the end of the ${where(endIsInput)} — the input is incomplete`, offset);
            }
            const octet = view.getUint8(at);
            if (index === 0 && octet === 0x80) {
                throw new PkiEncodingError('PKI_ASN1_TAG_INVALID',
                    `pkinative: the high-tag-number identifier at offset ${offset} starts with 0x80, a non-minimal form X.690 §8.1.2.4.2 forbids`, offset);
            }
            tagNumber = tagNumber * 128 + (octet & 0x7f);
            if (tagNumber > 0x7fffffff) {
                throw new PkiEncodingError('PKI_ASN1_TAG_INVALID',
                    `pkinative: the tag number at offset ${offset} exceeds 2^31 − 1 — the input is corrupt or crafted`, offset);
            }
            at++;
            if ((octet & 0x80) === 0) break;
        }
        if (tagNumber < 31) {
            throw new PkiEncodingError('PKI_ASN1_TAG_INVALID',
                `pkinative: tag number ${tagNumber} at offset ${offset} uses the high-tag-number form, which X.690 §8.1.2.2 reserves for numbers of 31 and above`, offset);
        }
    }

    if (at >= end) {
        throw new PkiEncodingError('PKI_ASN1_TRUNCATED',
            `pkinative: expected a length octet at offset ${at}, but the ${where(endIsInput)} ends there — the input is incomplete`, offset);
    }
    const lengthOctet = view.getUint8(at);
    at++;
    if (lengthOctet < 0x80) {
        return { tagClass, tagNumber, constructed, headerLength: at - offset, length: lengthOctet };
    }
    const label = tagLabel(tagClass, tagNumber);
    if (lengthOctet === 0x80) {
        if (!constructed) {
            throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_FORM_INVALID',
                `pkinative: the primitive ${label} at offset ${offset} uses the indefinite length form, which X.690 §8.1.3.2 allows only for constructed values`, offset);
        }
        if (ctx.rules === 'der') {
            throw new PkiEncodingError('PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN',
                `pkinative: the ${label} at offset ${offset} uses the indefinite length form, which DER forbids — decode with encodingRules: 'ber' if the input is BER`, offset);
        }
        noteBer(ctx, 'indefinite length', offset);
        return { tagClass, tagNumber, constructed, headerLength: at - offset, length: null };
    }
    if (lengthOctet === 0xff) {
        throw new PkiEncodingError('PKI_ASN1_LENGTH_INVALID',
            `pkinative: the length octet 0xFF at offset ${at - 1} is reserved by X.690 §8.1.3.5 — the input is corrupt or not ASN.1`, offset);
    }
    const count = lengthOctet & 0x7f;
    const lengthStart = at;
    let length = 0;
    for (let i = 0; i < count; i++) {
        if (at >= end) {
            throw new PkiEncodingError('PKI_ASN1_TRUNCATED',
                `pkinative: the ${count}-octet length of the ${label} at offset ${offset} runs past the end of the ${where(endIsInput)} — the input is incomplete`, offset);
        }
        length = length * 256 + view.getUint8(at);
        at++;
    }
    const minimal = count === 1 ? length >= 0x80 : view.getUint8(lengthStart) !== 0;
    if (!minimal) {
        if (ctx.rules === 'der') {
            throw new PkiEncodingError('PKI_ASN1_LENGTH_NON_MINIMAL',
                `pkinative: the length of the ${label} at offset ${offset} is not in its shortest form, which DER requires (X.690 §10.1) — decode with encodingRules: 'ber' if the producer emits BER`, offset);
        }
        noteBer(ctx, 'non-minimal length', offset);
    }
    return { tagClass, tagNumber, constructed, headerLength: at - offset, length };
}

function makeNode(
    data: Uint8Array, tagClass: TagClass, tagNumber: number, constructed: boolean, offset: number,
    headerLength: number, contentStart: number, contentEnd: number, end: number, indefinite: boolean, children: Asn1Node[],
): Asn1Node {
    return Object.freeze({
        tagClass,
        tagNumber,
        constructed,
        offset,
        headerLength,
        contentLength: contentEnd - contentStart,
        indefinite,
        bytes: data.subarray(offset, end),
        content: data.subarray(contentStart, contentEnd),
        children: Object.freeze(children) as readonly Asn1Node[],
    });
}

/**
 * Decode one value starting at `start`, iteratively. The value may end before
 * `data.length`; the caller decides what trailing bytes mean.
 *
 * @internal Shared by the public decoders and the structure parsers.
 */
export function decodeValueAt(data: Uint8Array, start: number, ctx: Asn1Context): Asn1Node {
    return decodeValueIn(byteView(data), data, start, ctx);
}

/**
 * The body of `decodeValueAt`, taking the view as a parameter so that a caller
 * decoding many values back to back — `decodeAsn1Sequence` over a bundle —
 * allocates one view for the whole input rather than one per value.
 */
function decodeValueIn(view: DataView, data: Uint8Array, start: number, ctx: Asn1Context): Asn1Node {
    const frames: Frame[] = [];
    let pos = start;
    for (;;) {
        const top = frames[frames.length - 1];
        if (top !== undefined) {
            let closed: Asn1Node | null = null;
            if (top.contentEnd !== null && pos === top.contentEnd) {
                closed = makeNode(data, top.tagClass, top.tagNumber, true, top.offset, top.headerLength, top.contentStart, pos, pos, false, top.children);
            } else if (top.contentEnd === null && pos + 1 < top.bound && data[pos] === 0 && data[pos + 1] === 0) {
                closed = makeNode(data, top.tagClass, top.tagNumber, true, top.offset, top.headerLength, top.contentStart, pos, pos + 2, true, top.children);
                pos += 2;
            } else if (top.contentEnd === null && !top.boundIsInput && pos + 2 > top.bound) {
                throw new PkiEncodingError('PKI_ASN1_LENGTH_OVERFLOW',
                    `pkinative: the indefinite-length ${tagLabel(top.tagClass, top.tagNumber)} at offset ${top.offset} has no end-of-contents marker before its enclosing value ends at offset ${top.bound} — the input is corrupt or crafted`, top.offset);
            } else if (top.contentEnd === null && pos >= data.length) {
                throw new PkiEncodingError('PKI_ASN1_TRUNCATED',
                    `pkinative: the indefinite-length ${tagLabel(top.tagClass, top.tagNumber)} at offset ${top.offset} has no end-of-contents marker — the input is incomplete`, top.offset);
            }
            if (closed !== null) {
                frames.pop();
                const parent = frames[frames.length - 1];
                if (parent === undefined) return closed;
                parent.children.push(closed);
                continue;
            }
        }

        const end = top === undefined ? data.length : top.bound;
        const endIsInput = top === undefined || top.boundIsInput;
        const header = readHeader(view, pos, end, endIsInput, ctx);
        const label = tagLabel(header.tagClass, header.tagNumber);

        if (header.tagClass === 'universal' && header.tagNumber === 0) {
            throw new PkiEncodingError('PKI_ASN1_EOC_UNEXPECTED',
                `pkinative: an end-of-contents marker at offset ${pos} ${top?.contentEnd === null ? 'is not the two octets 0x00 0x00' : 'appears outside an indefinite-length value'} (X.690 §8.1.5) — the input is corrupt`, pos);
        }

        ctx.nodes++;
        enforceLimit(ctx.limits, 'maxNodes', ctx.nodes, 'the number of ASN.1 values');

        if (header.tagClass === 'universal') {
            if (header.constructed && isPrimitiveOnly(header.tagNumber)) {
                throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_FORM_INVALID',
                    `pkinative: the ${label} at offset ${pos} is constructed, but X.690 encodes it in primitive form only — the input is corrupt`, pos);
            }
            if (!header.constructed && isConstructedOnly(header.tagNumber)) {
                throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_FORM_INVALID',
                    `pkinative: the ${label} at offset ${pos} is primitive, but X.690 encodes it in constructed form only — the input is corrupt`, pos);
            }
            if (header.constructed && isStringTag(header.tagNumber)) {
                if (ctx.rules === 'der') {
                    throw new PkiEncodingError('PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN',
                        `pkinative: the ${label} at offset ${pos} is in constructed form, which DER forbids (X.690 §10.2) — decode with encodingRules: 'ber' if the input is BER`, pos);
                }
                noteBer(ctx, 'constructed string', pos);
            }
        }

        const contentStart = pos + header.headerLength;
        if (header.length === null) {
            enforceLimit(ctx.limits, 'maxDepth', frames.length + 1, 'the nesting depth');
            frames.push({ tagClass: header.tagClass, tagNumber: header.tagNumber, offset: pos, headerLength: header.headerLength, contentStart, contentEnd: null, bound: end, boundIsInput: endIsInput, children: [] });
            pos = contentStart;
            continue;
        }
        const contentEnd = contentStart + header.length;
        if (contentEnd > end) {
            if (endIsInput) {
                throw new PkiEncodingError('PKI_ASN1_TRUNCATED',
                    `pkinative: the ${label} at offset ${pos} declares ${header.length} content octets but only ${end - contentStart} remain in the input — the input is incomplete`, pos);
            }
            throw new PkiEncodingError('PKI_ASN1_LENGTH_OVERFLOW',
                `pkinative: the ${label} at offset ${pos} declares ${header.length} content octets, which overruns its enclosing value by ${contentEnd - end} — the input is corrupt or crafted`, pos);
        }
        if (header.constructed) {
            enforceLimit(ctx.limits, 'maxDepth', frames.length + 1, 'the nesting depth');
            frames.push({ tagClass: header.tagClass, tagNumber: header.tagNumber, offset: pos, headerLength: header.headerLength, contentStart, contentEnd, bound: contentEnd, boundIsInput: false, children: [] });
            pos = contentStart;
            continue;
        }
        const node = makeNode(data, header.tagClass, header.tagNumber, false, pos, header.headerLength, contentStart, contentEnd, contentEnd, false, []);
        pos = contentEnd;
        const parent = frames[frames.length - 1];
        if (parent === undefined) return node;
        parent.children.push(node);
    }
}

/**
 * Decode exactly one value from `data` under an existing context.
 *
 * @internal Shared with the structure parsers, which reuse one context per operation.
 */
export function decodeWithContext(data: Uint8Array, ctx: Asn1Context, allowTrailingData: boolean): Asn1Node {
    enforceLimit(ctx.limits, 'maxInputBytes', data.length, 'the input size');
    const node = decodeValueAt(data, 0, ctx);
    const end = node.bytes.length;
    if (end !== data.length && !allowTrailingData) {
        throw new PkiEncodingError('PKI_ASN1_TRAILING_DATA',
            `pkinative: ${data.length - end} byte(s) follow the outermost value at offset ${end} — pass exactly one DER object, split concatenated objects with decodeAsn1Sequence, or set allowTrailingData`, end);
    }
    return node;
}

/**
 * Decode one ASN.1 value — strict DER by default, BER with `encodingRules: 'ber'`.
 *
 * @param data    The encoded value. Nodes are zero-copy views of it.
 * @param options Encoding rules, limits, diagnostics, and whether bytes may follow the value.
 * @returns The root node, with every descendant decoded.
 * @throws {PkiEncodingError} For every X.690 violation (`PKI_ASN1_*`), including `PKI_ASN1_TRAILING_DATA`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` when the input exceeds `maxInputBytes`, `maxDepth` or `maxNodes`.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument.
 */
export function decodeAsn1(data: Uint8Array, options?: DecodeAsn1Options): Asn1Node {
    const bytes = assertBytes(data, 'decodeAsn1 input');
    const ctx = createAsn1Context(options);
    const allow = options?.allowTrailingData;
    if (allow !== undefined && typeof allow !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: allowTrailingData must be a boolean, got ${typeof allow}`);
    }
    return decodeWithContext(bytes, ctx, allow === true);
}

/**
 * Decode a concatenation of ASN.1 values placed back to back (an empty input
 * yields no value). All values share one node budget.
 *
 * @param data    The concatenated encodings.
 * @param options Encoding rules, limits and diagnostics.
 * @returns Every value, in input order.
 * @throws {PkiEncodingError} For every X.690 violation.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` when the input exceeds `maxInputBytes`, `maxDepth` or `maxNodes`.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument.
 */
export function decodeAsn1Sequence(data: Uint8Array, options?: DecodeAsn1Options): readonly Asn1Node[] {
    const bytes = assertBytes(data, 'decodeAsn1Sequence input');
    const ctx = createAsn1Context(options);
    enforceLimit(ctx.limits, 'maxInputBytes', bytes.length, 'the input size');
    const out: Asn1Node[] = [];
    const view = byteView(bytes);
    let pos = 0;
    while (pos < bytes.length) {
        const node = decodeValueIn(view, bytes, pos, ctx);
        out.push(node);
        pos = node.offset + node.bytes.length;
    }
    return Object.freeze(out);
}
