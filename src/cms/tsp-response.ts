/**
 * pkinative — RFC 3161 responses and tokens
 * =========================================
 * What comes back from a timestamp authority: a status, and — only when the
 * request was granted — a token, which is a CMS SignedData whose content is a
 * TSTInfo.
 *
 * Parsing a token proves nothing about it. The TSA's signature, its right to
 * stamp, and whether the token answers your request or stamps your data are
 * all decided by `verifyTimeStampToken`. What this module does refuse is the
 * shape RFC 3161 forbids: a granted response without a token, a declined one
 * with a token, a status or failure code the RFC does not define — §2.4.2 says
 * a compliant client "MUST generate an error if values it does not understand
 * are present", and a status this reader does not know is one it cannot tell
 * apart from a grant.
 *
 * @module cms/tsp-response
 */

import { assertBytes } from '../core/bytes.js';
import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readBitString, _readInteger, _readString } from '../asn1/asn1-read.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiCmsError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { TimeStampFailure, TimeStampResponse, TimeStampStatus, TimeStampToken } from '../types/tsp-types.js';
import { parseSignedData } from './cms-signed-data.js';
import { OID_TST_INFO } from '../core/cms-oids.js';
import { _tspError, parseTstInfo } from './tsp-tst-info.js';

/** RFC 3161 §2.4.2 `PKIStatus`, by value. */
const STATUSES: readonly TimeStampStatus[] = /*#__PURE__*/ Object.freeze([
    'granted', 'grantedWithMods', 'rejection', 'waiting', 'revocationWarning', 'revocationNotification',
]);

/** RFC 3161 §2.4.2 `PKIFailureInfo`, by bit number — sparse, as the RFC numbers it. */
const FAILURES: ReadonlyMap<number, TimeStampFailure> = /*#__PURE__*/ new Map([
    [0, 'badAlg'],
    [2, 'badRequest'],
    [5, 'badDataFormat'],
    [14, 'timeNotAvailable'],
    [15, 'unacceptedPolicy'],
    [16, 'unacceptedExtension'],
    [17, 'addInfoNotAvailable'],
    [25, 'systemFailure'],
]);

/**
 * Parse a `TimeStampToken` — the token itself, as it is embedded in a signature
 * or a PDF document timestamp.
 *
 * ```ts
 * const token = parseTimeStampToken(tokenDer);
 * console.log(new Date(token.tstInfo.genTime.epochMilliseconds).toISOString());
 * ```
 *
 * The time it carries is what the TSA **claims** until `verifyTimeStampToken`
 * has checked who signed it and what it stamps.
 *
 * @param der     The token: a ContentInfo whose content is a SignedData over a TSTInfo.
 * @param options Encoding rules, limits and diagnostics, as `parseSignedData`
 *   takes them. The TSTInfo inside is always read as DER.
 * @returns The SignedData envelope and the TSTInfo it carries.
 * @throws {PkiCmsError} `PKI_CMS_CONTENT_TYPE_UNEXPECTED` when the SignedData
 *   carries something other than a TSTInfo; `PKI_CMS_STRUCTURE_INVALID` when
 *   the TSTInfo is detached or malformed; everything `parseSignedData` and
 *   `parseTstInfo` throw.
 * @throws {PkiEncodingError} For any encoding violation.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past any limit.
 */
export function parseTimeStampToken(der: Uint8Array, options?: PkiParseOptions): TimeStampToken {
    const signedData = parseSignedData(der, options);
    if (signedData.contentType !== OID_TST_INFO) {
        throw new PkiCmsError('PKI_CMS_CONTENT_TYPE_UNEXPECTED',
            `pkinative: this SignedData carries ${signedData.contentType}, not a TSTInfo (${OID_TST_INFO}) — it is a signed message, not a timestamp token; read it with parseSignedData`,
            'content.encapContentInfo.eContentType', 0);
    }
    const content = signedData.content;
    if (content === undefined) {
        // A detached TSTInfo is meaningless: the token IS the assertion, and one
        // that does not carry it asserts nothing anybody could check.
        throw new PkiCmsError('PKI_CMS_STRUCTURE_INVALID',
            'pkinative: this timestamp token carries no TSTInfo — its eContent is absent, and RFC 3161 §2.4.2 requires the token to hold what the TSA asserts',
            'content.encapContentInfo.eContent', 0);
    }
    return Object.freeze({ signedData, tstInfo: parseTstInfo(content, options) });
}

/**
 * Parse a `TimeStampResp` — what a TSA answers to a `TimeStampReq`.
 *
 * ```ts
 * const response = parseTimeStampResponse(new Uint8Array(await reply.arrayBuffer()));
 * if (response.token === undefined) throw new Error(`the TSA declined: ${response.status} ${response.failInfo.join(', ')}`);
 * ```
 *
 * `tokenDer` is the exact token, to embed as `id-aa-signatureTimeStampToken`
 * or as a PDF document timestamp. A declined response has no token and is not
 * an error to parse: it is an answer, and `failInfo` says why.
 *
 * @param der     The response, as the TSA sent it.
 * @param options Encoding rules, limits and diagnostics.
 * @returns The parsed response, with zero-copy views of `der`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array.
 * @throws {PkiCmsError} `PKI_CMS_STRUCTURE_INVALID` when the response is
 *   malformed, carries a status or failure code RFC 3161 does not define, or
 *   has a token where its status forbids one or none where it requires one;
 *   everything `parseTimeStampToken` throws.
 * @throws {PkiEncodingError} For any encoding violation.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past any limit.
 */
export function parseTimeStampResponse(der: Uint8Array, options?: PkiParseOptions): TimeStampResponse {
    const bytes = assertBytes(der, 'parseTimeStampResponse input');
    const ctx = createAsn1Context(options);
    const root = decodeWithContext(bytes, ctx, false);
    const path = 'TimeStampResp';
    if (root.tagClass !== 'universal' || root.tagNumber !== 16 || root.children.length < 1 || root.children.length > 2) {
        throw _tspError(path, root.offset, 'is not a SEQUENCE of a status and, optionally, a token');
    }
    const [statusNode, tokenNode] = root.children as [Asn1Node, Asn1Node | undefined];
    const { status, statusStrings, failInfo } = readStatusInfo(statusNode, ctx, `${path}.status`);

    const granted = status === 'granted' || status === 'grantedWithMods';
    if (granted && tokenNode === undefined) {
        throw _tspError(path, root.offset, `says ${status} and carries no token; RFC 3161 §2.4.2 requires one`);
    }
    if (!granted && tokenNode !== undefined) {
        throw _tspError(path, tokenNode.offset, `says ${status} and still carries a token; RFC 3161 §2.4.2 forbids one`);
    }

    let tokenDer: Uint8Array | undefined;
    let token: TimeStampToken | undefined;
    if (tokenNode !== undefined) {
        tokenDer = der.subarray(tokenNode.offset, tokenNode.offset + tokenNode.headerLength + tokenNode.contentLength);
        token = parseTimeStampToken(tokenDer, options);
    }
    return Object.freeze({
        der: der.subarray(root.offset, root.offset + root.headerLength + root.contentLength),
        status,
        statusStrings,
        failInfo,
        tokenDer,
        token,
        diagnostics: ctx.emitter.diagnostics,
    });
}

/** `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL, failInfo PKIFailureInfo OPTIONAL }`. */
function readStatusInfo(node: Asn1Node, ctx: Asn1Context, path: string): {
    readonly status: TimeStampStatus;
    readonly statusStrings: readonly string[];
    readonly failInfo: readonly TimeStampFailure[];
} {
    if (node.tagClass !== 'universal' || node.tagNumber !== 16) throw _tspError(path, node.offset, 'is not a PKIStatusInfo SEQUENCE');
    const [statusNode, ...rest] = node.children;
    if (statusNode?.tagClass !== 'universal' || statusNode.tagNumber !== 2) throw _tspError(`${path}.status`, node.offset, 'is missing or not an INTEGER');
    const value = _readInteger(statusNode, ctx);
    const status = value >= 0n && value < BigInt(STATUSES.length) ? STATUSES[Number(value)] : undefined;
    if (status === undefined) {
        throw _tspError(`${path}.status`, statusNode.offset, `is ${String(value)}, which RFC 3161 §2.4.2 does not define — a status this reader does not know is one it cannot tell apart from a grant`);
    }

    let statusStrings: readonly string[] = [];
    let failInfo: readonly TimeStampFailure[] = [];
    let last = -1;
    for (const field of rest) {
        // 0 = statusString (SEQUENCE OF UTF8String), 1 = failInfo (BIT STRING).
        const slot = field.tagClass === 'universal' && field.tagNumber === 16 ? 0
            : field.tagClass === 'universal' && field.tagNumber === 3 ? 1 : -1;
        if (slot <= last) throw _tspError(path, field.offset, 'holds a field PKIStatusInfo does not define, or holds its fields twice or out of order');
        last = slot;
        if (slot === 0) statusStrings = readFreeText(field, ctx, `${path}.statusString`);
        else failInfo = readFailInfo(field, ctx, `${path}.failInfo`);
    }
    return { status, statusStrings, failInfo };
}

/** `PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String` (RFC 4210 §5.1.1). */
function readFreeText(node: Asn1Node, ctx: Asn1Context, path: string): readonly string[] {
    if (node.children.length === 0) throw _tspError(path, node.offset, 'is empty; PKIFreeText holds at least one string');
    return Object.freeze(node.children.map((child, index) => {
        if (child.tagClass !== 'universal' || child.tagNumber !== 12) {
            throw _tspError(`${path}[${String(index)}]`, child.offset, 'is not a UTF8String, the only string type PKIFreeText allows');
        }
        return _readString(child, ctx, undefined, `${path}[${String(index)}]`).value;
    }));
}

/**
 * `PKIFailureInfo ::= BIT STRING` with eight named bits, numbered sparsely.
 *
 * A bit RFC 3161 does not name is refused rather than ignored: §2.4.2 requires
 * the client to fail on values it does not understand, and dropping one would
 * report a failure without the reason the TSA actually gave.
 */
function readFailInfo(node: Asn1Node, ctx: Asn1Context, path: string): readonly TimeStampFailure[] {
    const bits = _readBitString(node, ctx);
    const total = bits.bytes.length * 8 - bits.unusedBits;
    const out: TimeStampFailure[] = [];
    for (let bit = 0; bit < total; bit += 1) {
        if (((bits.bytes[bit >> 3] as number) & (0x80 >> (bit & 7))) === 0) continue;
        const name = FAILURES.get(bit);
        if (name === undefined) throw _tspError(path, node.offset, `sets bit ${String(bit)}, which RFC 3161 §2.4.2 does not name`);
        out.push(name);
    }
    return Object.freeze(out);
}
