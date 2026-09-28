/**
 * pkinative — RFC 3161 TSTInfo
 * ============================
 * What a timestamp authority asserts: that a hash existed at a time, under a
 * policy, with a serial of its own.
 *
 * Read **as DER whatever the caller asked for**. RFC 3161 §2.4.2 says the
 * eContent "SHALL be the DER-encoded value of TSTInfo", and the reason is not
 * pedantry: the TSA signed those exact bytes, and a reader that tolerated a BER
 * variant would be reading something other than what was signed.
 *
 * The TSTInfo is small and has no unbounded list in it, so it is decoded into
 * a tree the ordinary way rather than walked with the cursor the revocation
 * lists need. The sub-structures RFC 3161 borrows from RFC 5280 — the
 * `AlgorithmIdentifier`, the `GeneralName`, the `Extensions` — are read by the
 * certificate readers, and a failure inside one is reported as a `PkiCmsError`
 * naming the TSTInfo field, as the SignedData parser reports it: a caller of
 * `parseTimeStampToken` catches one class, not two.
 *
 * @module cms/tsp-tst-info
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier, readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBoolean, _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import { _readTime } from '../asn1/asn1-time.js';
import { toHex } from '../core/bytes.js';
import { defaultEncodedDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiCmsError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { MessageImprint, TimeStampAccuracy, TstInfo } from '../types/tsp-types.js';
import type { Extension, SerialNumber } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _decodeExtension } from '../x509/x509-extensions.js';
import { _viaX509 } from './cms-attributes.js';
import { _readGeneralName } from '../x509/x509-general-name.js';

/** The digest lengths a `messageImprint` is checked against; any other digest is accepted unmeasured. */
const DIGEST_BYTES: ReadonlyMap<string, number> = /*#__PURE__*/ new Map([
    ['1.3.14.3.2.26', 20],
    ['2.16.840.1.101.3.4.2.1', 32],
    ['2.16.840.1.101.3.4.2.2', 48],
    ['2.16.840.1.101.3.4.2.3', 64],
]);

/** @internal */
export function _tspError(path: string, offset: number, why: string): PkiCmsError {
    return new PkiCmsError('PKI_CMS_STRUCTURE_INVALID', `pkinative: ${path} ${why} — the input is not an RFC 3161 structure`, path, offset);
}

/**
 * `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`.
 *
 * The length of the hash is checked against the algorithm when pkinative knows
 * the algorithm. RFC 3161 §2.4.1 makes that the TSA's first check too, and a
 * 20-octet "SHA-256" imprint is a request nobody could have meant — accepting
 * it would let a truncated hash be stamped as if it were the full one.
 *
 * @internal
 */
export function _readMessageImprint(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): MessageImprint {
    if (node === undefined || node.tagClass !== 'universal' || node.tagNumber !== 16 || node.children.length !== 2) {
        throw _tspError(path, node?.offset ?? parentOffset, 'is not a MessageImprint: a SEQUENCE of a hash algorithm and a hash');
    }
    const hashAlgorithm = _viaX509(`${path}.hashAlgorithm`, node.offset, () =>
        _readAlgorithmIdentifier(node.children[0], ctx, `${path}.hashAlgorithm`, 'PKI_X509_STRUCTURE_INVALID', node.offset));
    const hashedMessage = _readOctetString(node.children[1] as Asn1Node, ctx);
    const expected = DIGEST_BYTES.get(hashAlgorithm.oid);
    if (expected !== undefined && hashedMessage.length !== expected) {
        throw _tspError(`${path}.hashedMessage`, node.offset,
            `is ${String(hashedMessage.length)} octets, and a ${hashAlgorithm.oid} digest is ${String(expected)}`);
    }
    return Object.freeze({ hashAlgorithm, hashedMessage });
}

/** @internal */
export function _serialOf(node: Asn1Node, ctx: Asn1Context): SerialNumber {
    return Object.freeze({ bytes: node.content, hex: toHex(node.content), value: _readInteger(node, ctx) }) as SerialNumber;
}

/**
 * Parse a DER `TSTInfo` — the `eContent` of a timestamp token.
 *
 * ```ts
 * const info = parseTstInfo(token.signedData.content);
 * console.log(new Date(info.genTime.epochMilliseconds).toISOString(), info.policy);
 * ```
 *
 * This reads what the TSA **asserts**. Nothing here checks that the TSA signed
 * it, that the imprint is the hash of your data, or that the TSA was entitled
 * to stamp anything — `verifyTimeStampToken` decides those, and the assertion
 * means nothing until it has.
 *
 * `genTime` keeps a fractional second when the TSA wrote one: RFC 3161 allows
 * it, unlike the RFC 5280 certificate profile, so no diagnostic is raised for it
 * here. `epochMilliseconds` is truncated to the millisecond; `genTime.text`
 * keeps every digit the TSA wrote.
 *
 * @param der     The DER of one TSTInfo.
 * @param options Limits and diagnostics. `encodingRules` is ignored: a TSTInfo
 *   is always DER.
 * @returns The parsed TSTInfo, with zero-copy views of `der`.
 * @throws {PkiCmsError} `PKI_CMS_STRUCTURE_INVALID` when the value is not a
 *   TSTInfo — including a malformed `AlgorithmIdentifier`, `GeneralName` or
 *   recognised extension inside it — or `PKI_CMS_VERSION_UNSUPPORTED` for a
 *   version other than 1.
 * @throws {PkiEncodingError} For any DER violation.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxExtensions` or the decoder's limits.
 */
export function parseTstInfo(der: Uint8Array, options?: PkiParseOptions): TstInfo {
    const ctx = createAsn1Context({ ...options, encodingRules: 'der' });
    const root = decodeWithContext(der, ctx, false);
    const path = 'TSTInfo';
    if (root.tagClass !== 'universal' || root.tagNumber !== 16) throw _tspError(path, root.offset, 'is not a SEQUENCE');

    const fields = root.children;
    let at = 0;
    const take = (what: string): Asn1Node => {
        const field = fields[at];
        if (field === undefined) throw _tspError(`${path}.${what}`, root.offset, 'is missing');
        at += 1;
        return field;
    };

    const versionNode = take('version');
    if (versionNode.tagClass !== 'universal' || versionNode.tagNumber !== 2) throw _tspError(`${path}.version`, versionNode.offset, 'is not an INTEGER');
    const version = _readInteger(versionNode, ctx);
    if (version !== 1n) {
        throw new PkiCmsError('PKI_CMS_VERSION_UNSUPPORTED',
            `pkinative: ${path}.version is ${String(version)}; RFC 3161 §2.4.2 defines only version 1, so this token promises a syntax this reader cannot know`,
            `${path}.version`, versionNode.offset);
    }
    const policy = _readObjectIdentifier(take('policy'), ctx);
    const messageImprint = _readMessageImprint(take('messageImprint'), ctx, `${path}.messageImprint`, root.offset);
    const serialNode = take('serialNumber');
    if (serialNode.tagClass !== 'universal' || serialNode.tagNumber !== 2) throw _tspError(`${path}.serialNumber`, serialNode.offset, 'is not an INTEGER');
    const serialNumber = _serialOf(serialNode, ctx);
    const genTimeNode = take('genTime');
    if (genTimeNode.tagClass !== 'universal' || genTimeNode.tagNumber !== 24) {
        throw _tspError(`${path}.genTime`, genTimeNode.offset, 'is not a GeneralizedTime; RFC 3161 §2.4.2 allows no other time type');
    }
    const genTime = _readTime(genTimeNode, ctx, undefined);

    // The optional tail, each field identified by its tag, in the order the
    // module fixes. A field out of order is a field that is not there, and
    // what is left over at the end is reported as the thing it is: not a
    // TSTInfo field at all.
    let accuracy: TimeStampAccuracy | undefined;
    let ordering = false;
    let nonce: bigint | undefined;
    let tsa: TstInfo['tsa'];
    let extensions: readonly Extension[] = [];
    const next = (): Asn1Node | undefined => fields[at];

    let field = next();
    if (field?.tagClass === 'universal' && field.tagNumber === 16) {
        accuracy = readAccuracy(field, ctx, `${path}.accuracy`);
        at += 1;
        field = next();
    }
    if (field?.tagClass === 'universal' && field.tagNumber === 1) {
        ordering = _readBoolean(field, ctx);
        // ordering is BOOLEAN DEFAULT FALSE: X.690 §11.5 requires the default
        // to be absent, so an encoded FALSE is a producer's slip worth naming.
        if (!ordering) ctx.emitter.emit(defaultEncodedDiagnostic(`${path}.ordering`, 'FALSE', field.offset));
        at += 1;
        field = next();
    }
    if (field?.tagClass === 'universal' && field.tagNumber === 2) {
        nonce = _readInteger(field, ctx);
        at += 1;
        field = next();
    }
    if (field?.tagClass === 'context' && field.tagNumber === 0) {
        // tsa [0] GeneralName: EXPLICIT despite the module's IMPLICIT TAGS,
        // because GeneralName is an untagged CHOICE (X.680 §31.2.7). Reading it
        // as implicit would take the [0] for the GeneralName's own otherName tag.
        const inner = field.constructed && field.children.length === 1 ? field.children[0] as Asn1Node : undefined;
        if (inner === undefined) throw _tspError(`${path}.tsa`, field.offset, 'is not one GeneralName under an explicit [0] tag');
        tsa = _viaX509(`${path}.tsa`, field.offset, () => _readGeneralName(inner, ctx, `${path}.tsa`, false));
        at += 1;
        field = next();
    }
    if (field?.tagClass === 'context' && field.tagNumber === 1) {
        extensions = readExtensions(der, field, ctx, `${path}.extensions`);
        at += 1;
        field = next();
    }
    if (field !== undefined) {
        throw _tspError(`${path}[${String(at)}]`, field.offset, 'is not a field TSTInfo defines, or not in the order RFC 3161 §2.4.2 fixes');
    }

    return Object.freeze({
        version: 1,
        policy,
        messageImprint,
        serialNumber,
        genTime,
        accuracy,
        ordering,
        nonce,
        tsa,
        extensions,
        der: der.subarray(root.offset, root.offset + root.headerLength + root.contentLength),
    });
}

/**
 * `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER (1..999)
 * OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }`.
 *
 * The 1..999 range is part of the type, so a `millis` of 0 or 1000 is refused
 * rather than read: a TSA claiming a thousand milliseconds of accuracy has
 * written a second in the wrong field, and silently adding it up would widen
 * the window a caller trusts.
 */
function readAccuracy(node: Asn1Node, ctx: Asn1Context, path: string): TimeStampAccuracy {
    let seconds = 0;
    let millis = 0;
    let micros = 0;
    let last = -1;
    for (const child of node.children) {
        // 0 = seconds (universal INTEGER), 1 = millis [0], 2 = micros [1].
        const slot = child.tagClass === 'universal' && child.tagNumber === 2 ? 0
            : child.tagClass === 'context' && child.tagNumber <= 1 && !child.constructed ? child.tagNumber + 1
                : -1;
        if (slot <= last) throw _tspError(path, child.offset, 'holds a field Accuracy does not define, or holds its fields twice or out of order');
        last = slot;
        const value = readSmallNonNegative(child, ctx, path);
        if (slot === 0) {
            seconds = value;
            continue;
        }
        if (value < 1 || value > 999) {
            throw _tspError(`${path}.${slot === 1 ? 'millis' : 'micros'}`, child.offset, `is ${String(value)}, outside the 1..999 the type allows`);
        }
        if (slot === 1) millis = value;
        else micros = value;
    }
    return Object.freeze({ seconds, millis, micros });
}

/** An INTEGER, possibly implicitly tagged, that must fit a JavaScript number and not be negative. */
function readSmallNonNegative(node: Asn1Node, ctx: Asn1Context, path: string): number {
    const value = _readInteger(node, ctx);
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw _tspError(path, node.offset, `holds ${String(value)}, which is not a non-negative count a clock can mean`);
    }
    return Number(value);
}

/**
 * `extensions [1] IMPLICIT Extensions` — the `[1]` replaces the SEQUENCE tag,
 * so its children are the `Extension` values themselves.
 *
 * Each value is decoded in place from a view that ends where its extnValue
 * ends, which is what lets the extension reader tell a value with trailing
 * octets from a well-formed one — the detail that, got wrong, once made the
 * CRL parser refuse every list carrying a recognised extension.
 */
function readExtensions(der: Uint8Array, field: Asn1Node, ctx: Asn1Context, path: string): readonly Extension[] {
    const out: Extension[] = [];
    for (const [index, entry] of field.children.entries()) {
        const where = `${path}[${String(index)}]`;
        enforceLimit(ctx.limits, 'maxExtensions', index + 1, where);
        const oidNode = entry.children[0];
        const valueNode = entry.children[entry.children.length - 1];
        if (entry.tagClass !== 'universal' || entry.tagNumber !== 16 || entry.children.length < 2 || entry.children.length > 3
            || oidNode === undefined || valueNode === undefined) {
            throw _tspError(where, entry.offset, 'is not an Extension');
        }
        const criticalNode = entry.children.length === 3 ? entry.children[1] as Asn1Node : undefined;
        const start = valueNode.offset + valueNode.headerLength;
        out.push(_viaX509(where, entry.offset, () => _decodeExtension(
            der.subarray(0, start + valueNode.contentLength),
            start,
            readObjectIdentifier(oidNode),
            criticalNode !== undefined && _readBoolean(criticalNode, ctx),
            valueNode.content,
            ctx,
            where,
        )));
    }
    return Object.freeze(out);
}
