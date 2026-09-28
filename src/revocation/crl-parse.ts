/**
 * pkinative — RFC 5280 §5 certificate revocation lists
 * ====================================================
 * A `CertificateList`, parsed — and its `revokedCertificates` deliberately
 * **not** parsed.
 *
 * That last part is the whole design. At three ASN.1 nodes per entry, decoding
 * the list into a tree hits `maxNodes` (200 000) at roughly 65 000 entries,
 * while `maxInputBytes` (64 MiB) would allow millions. Real CRLs sit in
 * between. So the envelope is decoded normally — it is small and every field
 * matters — and the list is **walked** with `asn1/asn1-cursor.ts`, one header
 * at a time, in constant memory, bounded by `maxRevokedCertificates`.
 *
 * The consequence for the API is that there is no `revokedCertificates` array
 * to read. There is {@link findRevocation}, which answers the question a
 * caller actually has, and `entryCount`, counted by walking. An array would
 * either cap the library below real sizes or allocate hundreds of megabytes to
 * answer one yes-or-no.
 *
 * @module revocation/crl-parse
 */

import { walkChildren, readTlvHeader, type TlvHeader } from '../asn1/asn1-cursor.js';
import { decodeValueAt } from '../asn1/asn1-decode.js';
import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { _readTime } from '../asn1/asn1-time.js';
import { readInteger } from '../asn1/asn1-read.js';
import { readObjectIdentifier } from '../asn1/asn1-oid.js';
import { toHex } from '../core/bytes.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, PkiTime } from '../types/asn1-types.js';
import type { CertificateList, CrlReason, RevokedCertificate } from '../types/crl-types.js';
import { PkiCertificateError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { Extension, SerialNumber } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _decodeExtension } from '../x509/x509-extensions.js';
import { _readName } from '../x509/x509-name.js';
import {
    OID_CERTIFICATE_ISSUER,
    OID_ISSUING_DISTRIBUTION_POINT,
    _entryCertificateIssuer,
    _findIssuingDistributionPoint,
} from './crl-scope.js';

const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';

/** RFC 5280 §5.3.1. Index 7 is unassigned, so the table has a hole rather than a shift. */
const REASONS: Readonly<Record<number, CrlReason>> = Object.freeze({
    0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise', 3: 'affiliationChanged',
    4: 'superseded', 5: 'cessationOfOperation', 6: 'certificateHold',
    8: 'removeFromCRL', 9: 'privilegeWithdrawn', 10: 'aACompromise',
});

const OID_CRL_NUMBER = '2.5.29.20';
const OID_DELTA_CRL_INDICATOR = '2.5.29.27';
const OID_CRL_REASON = '2.5.29.21';
const OID_INVALIDITY_DATE = '2.5.29.24';

/**
 * The §5.2 and §5.3 extensions this module reads itself.
 *
 * They are kept raw rather than handed to `_decodeExtension`, for one reason:
 * that decoder knows the certificate profile, and every one of these OIDs is
 * unknown to it. Three of them — `deltaCRLIndicator`, `issuingDistributionPoint`
 * and `certificateIssuer` — MUST be critical, so passing them through would put
 * `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION` on every correctly formed CRL, for
 * extensions this library not only recognises but acts on.
 */
const CRL_OWN_EXTENSIONS: ReadonlySet<string> = new Set([
    OID_CRL_NUMBER,
    OID_DELTA_CRL_INDICATOR,
    OID_CRL_REASON,
    OID_INVALIDITY_DATE,
    OID_ISSUING_DISTRIBUTION_POINT,
    OID_CERTIFICATE_ISSUER,
]);

function crlError(path: string, offset: number, why: string): PkiCertificateError {
    return new PkiCertificateError(STRUCTURE, `pkinative: ${path} ${why} — the input is not an RFC 5280 CertificateList`, path, offset);
}

/** Decode one small sub-value of the CRL, the normal way, under the node budget. */
function decodeAt(der: Uint8Array, header: TlvHeader, ctx: Asn1Context): Asn1Node {
    return decodeValueAt(der, header.offset, ctx);
}

/** The universal tag numbers of the two time types, for a field that is either. */
const isTime = (header: TlvHeader): boolean => header.tagClass === 'universal' && (header.tagNumber === 23 || header.tagNumber === 24);

interface Envelope {
    readonly tbs: TlvHeader;
    readonly fields: readonly TlvHeader[];
    /** The `revokedCertificates` SEQUENCE, when the CRL has one. */
    readonly revoked: TlvHeader | undefined;
    readonly extensionsField: TlvHeader | undefined;
    readonly version: 1 | 2;
    /**
     * Where `signature` is in `fields`.
     *
     * Carried rather than derived from `version`, because the version field is
     * OPTIONAL **and** may be written as 0: a CRL that spells v1 out has the
     * field at index 0 and the signature at index 1, while a CRL that omits it
     * has the signature at index 0. Inferring this from the version value is
     * wrong for exactly that case, and it was wrong here until a test built it.
     */
    readonly signatureIndex: number;
    readonly thisUpdateAt: TlvHeader;
    readonly nextUpdateAt: TlvHeader | undefined;
}

/**
 * Locate the `tbsCertList` fields positionally, with the cursor.
 *
 * RFC 5280 §5.1 makes `version`, `nextUpdate`, `revokedCertificates` and
 * `crlExtensions` all optional, and three of the four are distinguished only by
 * their tag — which is why this is a walk with tag tests rather than a fixed
 * index into a decoded array.
 */
function locate(der: Uint8Array, outer: TlvHeader): Envelope {
    const parts = [...walkChildren(der, outer, 'CertificateList')];
    const tbs = parts[0];
    if (parts.length !== 3 || tbs === undefined) {
        throw crlError('CertificateList', outer.offset, `holds ${String(parts.length)} values where RFC 5280 §5.1 defines exactly three`);
    }
    const fields = [...walkChildren(der, tbs, 'tbsCertList')];
    let at = 0;
    const take = (what: string): TlvHeader => {
        const field = fields[at];
        if (field === undefined) throw crlError(`tbsCertList.${what}`, tbs.offset, 'is missing');
        at += 1;
        return field;
    };

    // version is an INTEGER and signature is a SEQUENCE, so one tag test
    // decides whether the optional field is there.
    const first = fields[0];
    let version: 1 | 2 = 1;
    if (first !== undefined && first.tagClass === 'universal' && first.tagNumber === 2) {
        const encoded = der[first.contentStart];
        if (first.length !== 1 || (encoded !== 0 && encoded !== 1)) {
            throw crlError('tbsCertList.version', first.offset, 'is not v1 (0) or v2 (1)');
        }
        version = encoded === 1 ? 2 : 1;
        at += 1;
    }
    const signatureIndex = at;
    take('signature');
    take('issuer');
    const thisUpdateAt = take('thisUpdate');
    if (!isTime(thisUpdateAt)) throw crlError('tbsCertList.thisUpdate', thisUpdateAt.offset, 'is not a UTCTime or a GeneralizedTime');

    let nextUpdateAt: TlvHeader | undefined;
    const maybeNext = fields[at];
    if (maybeNext !== undefined && isTime(maybeNext)) {
        nextUpdateAt = maybeNext;
        at += 1;
    }

    let revoked: TlvHeader | undefined;
    const maybeRevoked = fields[at];
    if (maybeRevoked !== undefined && maybeRevoked.tagClass === 'universal' && maybeRevoked.tagNumber === 16) {
        revoked = maybeRevoked;
        at += 1;
    }

    let extensionsField: TlvHeader | undefined;
    const maybeExtensions = fields[at];
    if (maybeExtensions !== undefined && maybeExtensions.tagClass === 'context' && maybeExtensions.tagNumber === 0) {
        extensionsField = maybeExtensions;
        at += 1;
    }
    if (at !== fields.length) {
        throw crlError('tbsCertList', tbs.offset, `has ${String(fields.length - at)} field(s) after crlExtensions, where RFC 5280 §5.1 defines none`);
    }
    return { tbs, fields, revoked, extensionsField, version, signatureIndex, thisUpdateAt, nextUpdateAt };
}

/** Count the entries by walking, which is also the cheapest validation of the list's shape. */
function countEntries(der: Uint8Array, revoked: TlvHeader | undefined, ctx: Asn1Context): number {
    if (revoked === undefined) return 0;
    let count = 0;
    for (const entry of walkChildren(der, revoked, 'tbsCertList.revokedCertificates')) {
        if (!entry.constructed || entry.tagClass !== 'universal' || entry.tagNumber !== 16) {
            throw crlError(`tbsCertList.revokedCertificates[${String(count)}]`, entry.offset, 'is not a SEQUENCE');
        }
        count += 1;
        enforceLimit(ctx.limits, 'maxRevokedCertificates', count, `tbsCertList.revokedCertificates[${String(count)}]`);
    }
    return count;
}

/**
 * Parse an RFC 5280 CertificateList.
 *
 * ```ts
 * import { findRevocation, parseCertificateList } from 'pkinative';
 *
 * const crl = parseCertificateList(der);
 * const entry = findRevocation(crl, certificate.serialNumber);
 * if (entry !== undefined) console.log('revoked', entry.reason, new Date(entry.revocationDate.epochMilliseconds));
 * ```
 *
 * The result carries `entryCount` but **no array of entries**: see the module
 * comment. Ask with {@link findRevocation}.
 *
 * `issuingDistributionPoint` (§5.2.5) is decoded here because it decides what
 * the list may be believed about, and a value that cannot be read leaves that
 * unknown — so a malformed one refuses the whole list rather than leaving it
 * looking unrestricted, which is the one way to get this wrong that matters.
 *
 * @param der     The complete CertificateList.
 * @param options Encoding rules, limits, diagnostics — the same options every
 *   other entry point takes.
 * @returns The parsed CRL, with zero-copy views of `der`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` when the bytes are
 *   not an RFC 5280 CertificateList, or `PKI_X509_EXTENSION_MALFORMED` when
 *   `issuingDistributionPoint` is not one.
 * @throws {PkiEncodingError} For any DER violation in the envelope or the walk.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxRevokedCertificates`.
 */
export function parseCertificateList(der: Uint8Array, options?: PkiParseOptions): CertificateList {
    const ctx = createAsn1Context(options);
    const outer = readTlvHeader(der, 0, 'CertificateList');
    if (!outer.constructed || outer.tagClass !== 'universal' || outer.tagNumber !== 16) {
        throw crlError('CertificateList', 0, 'is not a SEQUENCE');
    }
    const env = locate(der, outer);
    const fields = env.fields;

    const tbsSignatureAlgorithm = _readAlgorithmIdentifier(decodeAt(der, fields[env.signatureIndex] as TlvHeader, ctx), ctx, 'tbsCertList.signature', STRUCTURE, env.tbs.offset);
    const issuer = _readName(decodeAt(der, fields[env.signatureIndex + 1] as TlvHeader, ctx), ctx, 'tbsCertList.issuer', env.tbs.offset);
    const thisUpdate = _readTime(decodeAt(der, env.thisUpdateAt, ctx), ctx, undefined);
    const nextUpdate = env.nextUpdateAt === undefined ? undefined : _readTime(decodeAt(der, env.nextUpdateAt, ctx), ctx, undefined);

    const parts = [...walkChildren(der, outer, 'CertificateList')];
    const signatureAlgorithm = _readAlgorithmIdentifier(decodeAt(der, parts[1] as TlvHeader, ctx), ctx, 'signatureAlgorithm', STRUCTURE, outer.offset);
    const signatureNode = decodeAt(der, parts[2] as TlvHeader, ctx);
    if (signatureNode.tagClass !== 'universal' || signatureNode.tagNumber !== 3) {
        throw crlError('signatureValue', (parts[2] as TlvHeader).offset, 'is not a BIT STRING');
    }
    const unusedBits = signatureNode.content[0] ?? 0;
    const signatureValue = { bytes: signatureNode.content.subarray(1), unusedBits };

    const extensions = readExtensions(der, env.extensionsField, ctx, 'tbsCertList.crlExtensions');
    let crlNumber: bigint | undefined;
    let isDelta = false;
    for (const extension of extensions) {
        if (extension.oid === OID_CRL_NUMBER) crlNumber = readIntegerValue(extension, ctx);
        if (extension.oid === OID_DELTA_CRL_INDICATOR) isDelta = true;
    }

    return Object.freeze({
        der: der.subarray(outer.offset, outer.end),
        tbsDer: der.subarray(env.tbs.offset, env.tbs.end),
        version: env.version,
        signatureAlgorithm,
        tbsSignatureAlgorithm,
        signatureValue: Object.freeze(signatureValue),
        issuer,
        thisUpdate,
        nextUpdate,
        extensions,
        crlNumber,
        isDelta,
        issuingDistributionPoint: _findIssuingDistributionPoint(extensions, ctx),
        entryCount: countEntries(der, env.revoked, ctx),
        diagnostics: ctx.emitter.diagnostics,
    });
}

/** Decode an `Extensions` field, or return an empty list when it is absent. */
function readExtensions(der: Uint8Array, field: TlvHeader | undefined, ctx: Asn1Context, path: string): readonly Extension[] {
    if (field === undefined) return [];
    const wrapper = field.tagClass === 'context' ? [...walkChildren(der, field, path)][0] : field;
    if (wrapper === undefined) return [];
    const out: Extension[] = [];
    let index = 0;
    for (const entry of walkChildren(der, wrapper, path)) {
        const where = `${path}[${String(index)}]`;
        enforceLimit(ctx.limits, 'maxExtensions', index + 1, where);
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
        // extnValue OCTET STRING }. Two fields or three, decided by the count:
        // the same shape the certificate parser reads, read the same way.
        const node = decodeAt(der, entry, ctx);
        const oidNode = node.children[0];
        const criticalNode = node.children.length === 3 ? node.children[1] : undefined;
        const valueNode = node.children[node.children.length - 1];
        if (oidNode === undefined || valueNode === undefined || node.children.length < 2) {
            throw crlError(where, entry.offset, 'is not an Extension');
        }
        // `_decodeExtension` decodes the value **in place**, from a buffer that
        // ends where the value ends: that is how it can tell a value with
        // trailing octets inside its extnValue from a well-formed one. So it
        // takes the offset of the extnValue's *content* and a view trimmed to
        // its end — exactly what the certificate parser hands it. Passing the
        // Extension SEQUENCE's own offset and the whole CRL instead made every
        // recognised extension look like garbage followed by the rest of the
        // file, which refused every CRL carrying one.
        const start = valueNode.offset + valueNode.headerLength;
        const oid = readObjectIdentifier(oidNode);
        const critical = criticalNode !== undefined && criticalNode.content[0] !== 0x00;
        if (CRL_OWN_EXTENSIONS.has(oid)) {
            const own: Extension = { kind: 'unknown', oid, critical, valueDer: valueNode.content };
            out.push(Object.freeze(own));
        } else {
            out.push(_decodeExtension(
                der.subarray(0, start + valueNode.contentLength),
                start,
                oid,
                critical,
                valueNode.content,
                ctx,
                where,
            ));
        }
        index += 1;
    }
    return Object.freeze(out);
}

/** The INTEGER inside an extension whose value is one, e.g. `cRLNumber`. */
function readIntegerValue(extension: Extension, ctx: Asn1Context): bigint | undefined {
    try {
        return readInteger(decodeValueAt(extension.valueDer, 0, ctx));
    } catch {
        // A malformed cRLNumber is a conformance problem, not a reason to
        // refuse the whole list: the revocation answers do not depend on it.
        return undefined;
    }
}

/** What {@link findRevocation} takes beyond the ordinary parse options. */
export interface FindRevocationOptions extends PkiParseOptions {
    /**
     * The encoded `issuer` of the certificate being asked about.
     *
     * It decides nothing on an ordinary CRL, where every entry is about the
     * list's own issuer. On an indirect CRL it is what makes the answer
     * correct: without it the walk answers for the CRL issuer, and a serial
     * matching some *other* CA's entry would be read as this certificate's
     * revocation.
     */
    readonly issuerDer?: Uint8Array | undefined;
}

/**
 * Look one serial number up in the revocation list.
 *
 * The list is walked, not indexed, and the walk stops at the first match. For
 * a caller checking many certificates against one CRL that is O(n·m); the
 * alternative is a map keyed by serial, which is the caller's decision to make
 * because it is the caller who knows how many serials they have and how much
 * memory they will spend on them. What this library must not do is allocate
 * that map behind their back for a single lookup.
 *
 * Serials are compared **by their content octets**, never by `value`: two
 * serials that differ only in a leading zero octet are two different serials
 * to a CA, and comparing the `bigint` would make them one.
 *
 * On an **indirect** CRL — one whose `issuingDistributionPoint` asserts
 * `indirectCRL` — a serial is not enough: the list holds entries for several
 * CAs, and two CAs issue the same serial all the time. Pass `issuerDer` and the
 * walk honours the running `certificateIssuer` state of §5.3.3, so an entry
 * counts only when it is about a certificate of *that* CA. Without it the walk
 * answers for the CRL's own issuer, which is the §5.3.3 default.
 *
 * @param der     The same bytes `parseCertificateList` was given.
 * @param serial  The certificate's serial number.
 * @param options The same options, plus `issuerDer`; the limits apply to the walk.
 * @returns The entry, or undefined when the serial is not listed.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` for a malformed entry.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxRevokedCertificates`.
 */
export function findRevocation(der: Uint8Array, serial: Uint8Array, options?: FindRevocationOptions): RevokedCertificate | undefined {
    const ctx = createAsn1Context(options);
    const outer = readTlvHeader(der, 0, 'CertificateList');
    const env = locate(der, outer);
    if (env.revoked === undefined) return undefined;

    // An indirect CRL (§5.2.5) holds entries for more than one CA, so a serial
    // alone no longer identifies a certificate: two CAs can, and do, issue the
    // same serial. Which CA an entry is about is carried by the running
    // `certificateIssuer` state of §5.3.3 — an entry inherits the last one
    // named before it, and the CRL's own issuer before the first.
    //
    // That state costs an extension decode per entry, so it is only tracked
    // when the list says it needs it. On the ordinary direct CRL the walk below
    // is byte-for-byte the one that was here before.
    const crlExtensions = readExtensions(der, env.extensionsField, ctx, 'tbsCertList.crlExtensions');
    const indirect = _findIssuingDistributionPoint(crlExtensions, ctx)?.indirectCRL === true;
    const issuerField = env.fields[env.signatureIndex + 1] as TlvHeader;
    const crlIssuerDer = der.subarray(issuerField.offset, issuerField.end);
    const wantedIssuer = indirect ? options?.issuerDer ?? crlIssuerDer : undefined;
    let entryIssuer = crlIssuerDer;

    let index = 0;
    for (const entry of walkChildren(der, env.revoked, 'tbsCertList.revokedCertificates')) {
        enforceLimit(ctx.limits, 'maxRevokedCertificates', index + 1, `tbsCertList.revokedCertificates[${String(index)}]`);
        const path = `tbsCertList.revokedCertificates[${String(index)}]`;
        const parts = [...walkChildren(der, entry, path)];
        const serialField = parts[0];
        const dateField = parts[1];
        if (serialField === undefined || dateField === undefined) {
            throw crlError(path, entry.offset, 'holds fewer than the two fields RFC 5280 §5.1.2.6 requires');
        }
        index += 1;
        // The cheap test first, on bytes, before decoding anything: a CRL with
        // a million entries is a million comparisons and at most one decode.
        const content = der.subarray(serialField.contentStart, serialField.end);
        const hit = sameBytes(content, serial);
        if (!hit && wantedIssuer === undefined) continue;

        const extensions = readExtensions(der, parts[2], ctx, `${path}.crlEntryExtensions`);
        if (wantedIssuer !== undefined) {
            // Read before the match is decided, and on every entry: the state
            // this entry sets is the state the *next* one inherits, so skipping
            // it for a non-matching serial would mis-attribute everything after
            // it — the one bug an indirect CRL walk can have.
            entryIssuer = _entryCertificateIssuer(extensions, ctx, `${path}.crlEntryExtensions.certificateIssuer`) ?? entryIssuer;
            if (!hit || !sameBytes(entryIssuer, wantedIssuer)) continue;
        }

        const revocationDate = _readTime(decodeAt(der, dateField, ctx), ctx, undefined);
        return Object.freeze({
            serialNumber: Object.freeze({ bytes: content, hex: toHex(content), value: readInteger(decodeAt(der, serialField, ctx)) }) as SerialNumber,
            revocationDate,
            extensions,
            reason: readReason(extensions, ctx),
            invalidityDate: readInvalidityDate(extensions, ctx),
        });
    }
    return undefined;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
    return true;
}

/** `cRLReason`, or undefined when absent or not a value RFC 5280 assigns. */
function readReason(extensions: readonly Extension[], ctx: Asn1Context): CrlReason | undefined {
    const extension = extensions.find((e) => e.oid === OID_CRL_REASON);
    if (extension === undefined) return undefined;
    try {
        const node = decodeValueAt(extension.valueDer, 0, ctx);
        // ENUMERATED is tag 10, and `readInteger` accepts only tag 2 — so the
        // content is read here rather than through it. An INTEGER in this
        // field is a common encoder bug and is read anyway: refusing would
        // hide the revocation, and a hidden revocation is the worse failure.
        if (node.tagClass !== 'universal' || (node.tagNumber !== 10 && node.tagNumber !== 2)) return undefined;
        if (node.content.length !== 1) return undefined;
        return REASONS[node.content[0] as number];
    } catch {
        return undefined;
    }
}

/** `invalidityDate` in epoch milliseconds, or undefined. */
function readInvalidityDate(extensions: readonly Extension[], ctx: Asn1Context): number | undefined {
    const extension = extensions.find((e) => e.oid === OID_INVALIDITY_DATE);
    if (extension === undefined) return undefined;
    try {
        const time: PkiTime = _readTime(decodeValueAt(extension.valueDer, 0, ctx), ctx, undefined);
        return time.epochMilliseconds;
    } catch {
        return undefined;
    }
}
