/**
 * pkinative — X.509 certificate
 * =============================
 * RFC 5280 §4.1: the Certificate envelope and every TBSCertificate field.
 * A structural violation of the ASN.1 module throws `PkiCertificateError`;
 * a profile violation real issuers commit is a diagnostic, recorded on
 * `certificate.diagnostics`. Recognised extensions are decoded
 * (x509-extensions.ts) unless `decodeExtensions: false` keeps them raw.
 *
 * Parsing reads; it does not verify the signature and does not validate a
 * chain.
 *
 * @module x509/x509-certificate
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readBoolean, _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import {
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_UTC_TIME,
    tagLabel,
} from '../asn1/asn1-tags.js';
import { _readTime } from '../asn1/asn1-time.js';
import { assertBytes, bytesEqual, toHex } from '../core/bytes.js';
import {
    akiMissingDiagnostic,
    commonNameNotInSanDiagnostic,
    defaultEncodedDiagnostic,
    emptyIssuerDiagnostic,
    emptySubjectSanNotCriticalDiagnostic,
    extensionsRequireV3Diagnostic,
    keyCertSignWithoutCaDiagnostic,
    nameConstraintsInEndEntityDiagnostic,
    generalizedTimeBefore2050Diagnostic,
    generalizedTimeFractionDiagnostic,
    serialNotPositiveDiagnostic,
    serialTooLongDiagnostic,
    skiMissingDiagnostic,
    signatureAlgorithmMismatchDiagnostic,
    uniqueIdRequiresV2Diagnostic,
    validityInvertedDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, BitString, PkiTime } from '../types/asn1-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { Certificate, DistinguishedName, Extension, ParseCertificateOptions, RawExtension, SerialNumber, Validity } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from './x509-algorithm.js';
import { _decodeExtension } from './x509-extensions.js';
import { certificateError, expectUniversalField } from './x509-fields.js';
import { _readName } from './x509-name.js';
import { _readSubjectPublicKeyInfo } from './x509-spki.js';

const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';
const OID_SUBJECT_ALT_NAME = '2.5.29.17';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_NAME_CONSTRAINTS = '2.5.29.30';
const OID_SUBJECT_KEY_IDENTIFIER = '2.5.29.14';
const OID_AUTHORITY_KEY_IDENTIFIER = '2.5.29.35';
const OID_COMMON_NAME = '2.5.4.3';

/**
 * Whether a `commonName` is the kind of string a relying party could try to
 * match against a host or an address.
 *
 * Deliberately generous on the left and strict on the right: a dotted label
 * sequence or a bracketed or colon-bearing address qualifies, and anything with
 * a space, a slash or an equals sign — the shape of an organisational name —
 * does not. Being generous is the safe direction here, because the diagnostic
 * only ever reports.
 */
function looksLikeHost(value: string): boolean {
    if (value === '' || /[\s/=,]/.test(value)) return false;
    return value.includes(':') || /^\*?[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+\.?$/.test(value);
}
/**
 * Profile checks that need the **whole certificate**, not one extension.
 *
 * Each of these is a sentence RFC 5280 or the CA/Browser Forum addresses to the
 * issuing CA, so each is a diagnostic and none refuses the certificate: a
 * verifier that rejected them would be stricter than the standards ask of a
 * verifier while changing no decision it takes. `strict: true` escalates them
 * for a caller who wants the stricter reading, which is where that choice
 * belongs. Every one of them is a case x509-limbo scores, and the reason each
 * stays a diagnostic is written beside it in `scripts/data/limbo-score.json`.
 */

function emitProfileDiagnostics(
    ctx: Asn1Context,
    version: 1 | 2 | 3,
    subject: DistinguishedName,
    issuer: DistinguishedName,
    extensions: readonly Extension[],
): void {
    const find = (oid: string): Extension | undefined => extensions.find((e) => e.oid === oid);
    const basicConstraints = find(OID_BASIC_CONSTRAINTS);
    const isCa = basicConstraints?.kind === 'basicConstraints' && basicConstraints.cA;

    // The key identifiers, each under the condition RFC 5280 actually sets, and
    // each measured before it was added: absent from 0.7 % and 1.3 % of
    // x509-limbo's certificates, which is a signal rather than chatter.
    //
    // §4.2.1.1 exempts a certificate that names nobody above it — a self-signed
    // root has no authority to identify — and equal encoded names is how that is
    // visible without a key operation. §4.2.1.2 requires the subject identifier
    // of **CA certificates**; for an end entity it is a SHOULD, and reporting a
    // SHOULD on the commonest shape in existence would be chatter.
    //
    // Neither is a verdict: the field is an opaque hint a path builder uses to
    // order its candidates, and `buildCertificatePath` works by name, so a
    // missing one costs exploration and not correctness.
    // …and only of a v3 certificate. A v1 or v2 certificate has nowhere to put
    // an extension — RFC 5280 §4.1.2.1 ties the field to the version — so
    // reporting one as missing would be reporting the format rather than a
    // choice the issuer made.
    if (version === 3) {
        if (!bytesEqual(subject.der, issuer.der) && find(OID_AUTHORITY_KEY_IDENTIFIER) === undefined) {
            ctx.emitter.emit(akiMissingDiagnostic());
        }
        if (isCa && find(OID_SUBJECT_KEY_IDENTIFIER) === undefined) ctx.emitter.emit(skiMissingDiagnostic());
    }
    if (!isCa && find(OID_NAME_CONSTRAINTS) !== undefined) ctx.emitter.emit(nameConstraintsInEndEntityDiagnostic());

    const keyUsage = find(OID_KEY_USAGE);
    if (!isCa && keyUsage?.kind === 'keyUsage' && keyUsage.usages.includes('keyCertSign')) {
        ctx.emitter.emit(keyCertSignWithoutCaDiagnostic());
    }

    // CA/Browser Forum BR 7.1.4.3: a commonName, when present, repeats a SAN
    // value. Only checked when the certificate has a SAN at all — a certificate
    // with none is the older shape the fallback in `checkServerName` is for, and
    // its own diagnostic already covers the empty-subject case.
    //
    // And only for a commonName that **could be matched as a host**: the
    // security question is whether a name a lenient relying party might accept
    // is sitting here without the issuer having put it in the SAN, and
    // `CN=Example CA` is not such a name. Reporting it would be reporting the
    // ordinary shape of every organisational subject, which is how a diagnostic
    // channel gets ignored.
    const san = find(OID_SUBJECT_ALT_NAME);
    if (san?.kind !== 'subjectAltName') return;
    const named = new Set<string>();
    for (const name of san.names) {
        if (name.kind === 'dNSName') named.add(name.value.toLowerCase());
        else if (name.kind === 'iPAddress') named.add(name.address.toLowerCase());
    }
    if (named.size === 0) return;
    for (const rdn of subject.rdns) {
        for (const attribute of rdn) {
            if (attribute.type !== OID_COMMON_NAME || attribute.value === undefined) continue;
            const common = attribute.value.value;
            if (!looksLikeHost(common) || named.has(common.toLowerCase())) continue;
            ctx.emitter.emit(commonNameNotInSanDiagnostic(common));
        }
    }
}
const NO_EXTENSIONS: readonly Extension[] = /*#__PURE__*/ Object.freeze([]);

// ── TBSCertificate fields ────────────────────────────────────────────

function readVersion(field: Asn1Node, ctx: Asn1Context): 1 | 2 | 3 {
    const path = 'tbsCertificate.version';
    if (!field.constructed || field.children.length !== 1) {
        throw certificateError(STRUCTURE, path, field.offset, 'is not one INTEGER under the explicit [0] tag');
    }
    const node = expectUniversalField(field.children[0], TAG_INTEGER, path, STRUCTURE, field.offset);
    const value = _readInteger(node, ctx);
    if (value !== 0n && value !== 1n && value !== 2n) {
        throw certificateError('PKI_X509_VERSION_INVALID', path, node.offset, `is ${String(value)}; RFC 5280 defines v1 (0), v2 (1) and v3 (2)`);
    }
    if (value === 0n) ctx.emitter.emit(defaultEncodedDiagnostic(path, 'v1', field.offset));
    return (Number(value) + 1) as 1 | 2 | 3;
}

function readValidityTime(node: Asn1Node, ctx: Asn1Context, path: string): PkiTime {
    if (node.tagClass !== 'universal' || (node.tagNumber !== TAG_UTC_TIME && node.tagNumber !== TAG_GENERALIZED_TIME)) {
        throw certificateError('PKI_X509_VALIDITY_INVALID', path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; a certificate time is a UTCTime or a GeneralizedTime`);
    }
    const time = _readTime(node, ctx, undefined);
    if (time.type === 'GeneralizedTime') {
        if (Number(time.text.slice(0, 4)) < 2050) ctx.emitter.emit(generalizedTimeBefore2050Diagnostic(path, time.text, node.offset));
        if (/[.,]/.test(time.text)) ctx.emitter.emit(generalizedTimeFractionDiagnostic(path, time.text, node.offset));
    }
    return time;
}

function readValidity(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): Validity {
    const path = 'tbsCertificate.validity';
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, 'PKI_X509_VALIDITY_INVALID', parentOffset);
    if (seq.children.length !== 2) {
        throw certificateError('PKI_X509_VALIDITY_INVALID', path, seq.offset, `holds ${seq.children.length} values; Validity is notBefore and notAfter`);
    }
    const notBefore = readValidityTime(seq.children[0] as Asn1Node, ctx, `${path}.notBefore`);
    const notAfter = readValidityTime(seq.children[1] as Asn1Node, ctx, `${path}.notAfter`);
    if (notBefore.epochMilliseconds > notAfter.epochMilliseconds) ctx.emitter.emit(validityInvertedDiagnostic(notBefore.text, notAfter.text));
    const validity: Validity = { notBefore, notAfter };
    return Object.freeze(validity);
}

function readExtensions(field: Asn1Node, ctx: Asn1Context, input: Uint8Array, decode: boolean): readonly Extension[] {
    const path = 'tbsCertificate.extensions';
    if (!field.constructed || field.children.length !== 1) {
        throw certificateError(STRUCTURE, path, field.offset, 'is not one SEQUENCE under the explicit [3] tag');
    }
    const seq = expectUniversalField(field.children[0], TAG_SEQUENCE, path, STRUCTURE, field.offset);
    if (seq.children.length === 0) {
        throw certificateError('PKI_X509_EXTENSIONS_EMPTY', path, seq.offset, 'is present but holds no extension; RFC 5280 requires at least one');
    }
    enforceLimit(ctx.limits, 'maxExtensions', seq.children.length, 'the extensions of the certificate');
    const seen = new Set<string>();
    const extensions: Extension[] = [];
    for (let i = 0; i < seq.children.length; i++) {
        const extPath = `${path}[${i}]`;
        const ext = expectUniversalField(seq.children[i], TAG_SEQUENCE, extPath, STRUCTURE, seq.offset);
        if (ext.children.length < 2 || ext.children.length > 3) {
            throw certificateError(STRUCTURE, extPath, ext.offset, `holds ${ext.children.length} values; an Extension is extnID, an optional critical flag and extnValue`);
        }
        const oid = _readObjectIdentifier(expectUniversalField(ext.children[0], TAG_OID, `${extPath}.extnID`, STRUCTURE, ext.offset), ctx);
        let critical = false;
        if (ext.children.length === 3) {
            const flag = expectUniversalField(ext.children[1], TAG_BOOLEAN, `${extPath}.critical`, STRUCTURE, ext.offset);
            critical = _readBoolean(flag, ctx);
            if (!critical) ctx.emitter.emit(defaultEncodedDiagnostic(`${extPath}.critical`, 'FALSE', flag.offset));
        }
        const valueNode = expectUniversalField(ext.children[ext.children.length - 1], TAG_OCTET_STRING, `${extPath}.extnValue`, STRUCTURE, ext.offset);
        const valueDer = _readOctetString(valueNode, ctx);
        if (seen.has(oid)) {
            throw certificateError('PKI_X509_EXTENSION_DUPLICATE', extPath, ext.offset, `repeats the extension ${oid}; RFC 5280 §4.2 allows each extension once`);
        }
        seen.add(oid);
        if (!decode) {
            const extension: RawExtension = { kind: 'raw', oid, critical, valueDer };
            extensions.push(Object.freeze(extension));
        } else if (valueNode.constructed) {
            // A BER segmented extnValue was joined into a copy: decode the copy. Offsets
            // inside it count from the joined content (documented in x509-extensions.ts).
            extensions.push(_decodeExtension(valueDer, 0, oid, critical, valueDer, ctx, extPath));
        } else {
            const start = valueNode.offset + valueNode.headerLength;
            extensions.push(_decodeExtension(input.subarray(0, start + valueNode.contentLength), start, oid, critical, valueDer, ctx, extPath));
        }
    }
    return Object.freeze(extensions);
}

// ── Certificate ──────────────────────────────────────────────────────

/**
 * Parse a DER-encoded X.509 certificate (RFC 5280 §4.1). Parsing checks the
 * structure and records profile concerns as diagnostics; it does not verify
 * the signature and does not validate a chain.
 *
 * @param der     The certificate encoding. The result holds zero-copy views of it: do not mutate it while you use the result.
 * @param options Encoding rules (`'der'` by default), limits, `strict`, `onDiagnostic` and `decodeExtensions` (default `true`).
 * @returns The frozen certificate, with every diagnostic of the parse on `diagnostics`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID`, `PKI_X509_VERSION_INVALID`, `PKI_X509_NAME_INVALID`,
 *   `PKI_X509_VALIDITY_INVALID`, `PKI_X509_SPKI_INVALID`, `PKI_X509_UNIQUE_ID_INVALID`, `PKI_X509_EXTENSIONS_EMPTY`,
 *   `PKI_X509_EXTENSION_DUPLICATE`, `PKI_X509_EXTENSION_MALFORMED` or `PKI_X509_GENERAL_NAME_INVALID`
 *   when the DER is not an RFC 5280 certificate.
 * @throws {PkiEncodingError} For every X.690 violation (`PKI_ASN1_*`, `PKI_OID_INVALID`).
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond a configured limit.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument; `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function parseCertificate(der: Uint8Array, options?: ParseCertificateOptions): Certificate {
    const bytes = assertBytes(der, 'parseCertificate input');
    const ctx = createAsn1Context(options);
    const decode = options?.decodeExtensions ?? true;
    if (typeof decode !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: decodeExtensions must be a boolean, got ${typeof decode}`);
    }
    const cert = expectUniversalField(decodeWithContext(bytes, ctx, false), TAG_SEQUENCE, 'certificate', STRUCTURE, 0);
    if (cert.children.length !== 3) {
        throw certificateError(STRUCTURE, 'certificate', cert.offset, `holds ${cert.children.length} values; a Certificate is tbsCertificate, signatureAlgorithm and signatureValue`);
    }
    const tbs = expectUniversalField(cert.children[0], TAG_SEQUENCE, 'tbsCertificate', STRUCTURE, cert.offset);
    const fields = tbs.children;
    let index = 0;

    let version: 1 | 2 | 3 = 1;
    const first = fields[0];
    if (first !== undefined && first.tagClass === 'context' && first.tagNumber === 0) {
        version = readVersion(first, ctx);
        index = 1;
    }

    const serialNode = expectUniversalField(fields[index++], TAG_INTEGER, 'tbsCertificate.serialNumber', STRUCTURE, tbs.offset);
    const serialValue = _readInteger(serialNode, ctx);
    if (serialNode.contentLength > 20) ctx.emitter.emit(serialTooLongDiagnostic(serialNode.contentLength, serialNode.offset));
    if (serialValue <= 0n) ctx.emitter.emit(serialNotPositiveDiagnostic(serialNode.offset));

    const tbsSignatureAlgorithm = _readAlgorithmIdentifier(fields[index++], ctx, 'tbsCertificate.signature', STRUCTURE, tbs.offset);
    const issuer = _readName(fields[index++], ctx, 'tbsCertificate.issuer', tbs.offset);
    if (issuer.rdns.length === 0) ctx.emitter.emit(emptyIssuerDiagnostic());
    const validity = readValidity(fields[index++], ctx, tbs.offset);
    const subject = _readName(fields[index++], ctx, 'tbsCertificate.subject', tbs.offset);
    const subjectPublicKeyInfo = _readSubjectPublicKeyInfo(fields[index++], ctx, 'tbsCertificate.subjectPublicKeyInfo', tbs.offset);

    let issuerUniqueId: BitString | undefined;
    let subjectUniqueId: BitString | undefined;
    let extensions = NO_EXTENSIONS;
    let extensionsPresent = false;
    let rank = 0;
    for (; index < fields.length; index++) {
        const field = fields[index] as Asn1Node;
        const tag = field.tagClass === 'context' ? field.tagNumber : -1;
        if (tag !== 1 && tag !== 2 && tag !== 3) {
            throw certificateError(STRUCTURE, `tbsCertificate[${index}]`, field.offset,
                `is ${tagLabel(field.tagClass, field.tagNumber)}, where only issuerUniqueID [1], subjectUniqueID [2] or extensions [3] may follow the public key`);
        }
        const path = tag === 1 ? 'tbsCertificate.issuerUniqueID' : tag === 2 ? 'tbsCertificate.subjectUniqueID' : 'tbsCertificate.extensions';
        if (tag <= rank) {
            throw certificateError(tag === 3 ? STRUCTURE : 'PKI_X509_UNIQUE_ID_INVALID', path, field.offset,
                'appears twice or out of order; TBSCertificate orders issuerUniqueID, subjectUniqueID, then extensions');
        }
        rank = tag;
        if (tag === 3) {
            extensions = readExtensions(field, ctx, bytes, decode);
            extensionsPresent = true;
            continue;
        }
        if (field.constructed && ctx.rules === 'der') {
            throw certificateError('PKI_X509_UNIQUE_ID_INVALID', path, field.offset, 'is constructed; a unique identifier is a primitive BIT STRING under its implicit tag');
        }
        const id = _readBitString(field, ctx);
        if (tag === 1) issuerUniqueId = id;
        else subjectUniqueId = id;
    }
    if ((issuerUniqueId !== undefined || subjectUniqueId !== undefined) && version === 1) ctx.emitter.emit(uniqueIdRequiresV2Diagnostic(version));
    if (extensionsPresent && version !== 3) ctx.emitter.emit(extensionsRequireV3Diagnostic(version));
    if (subject.rdns.length === 0 && extensions.find((e) => e.oid === OID_SUBJECT_ALT_NAME)?.critical !== true) {
        ctx.emitter.emit(emptySubjectSanNotCriticalDiagnostic());
    }
    emitProfileDiagnostics(ctx, version, subject, issuer, extensions);

    const signatureAlgorithm = _readAlgorithmIdentifier(cert.children[1], ctx, 'signatureAlgorithm', STRUCTURE, cert.offset);
    if (!bytesEqual(signatureAlgorithm.der, tbsSignatureAlgorithm.der)) {
        ctx.emitter.emit(signatureAlgorithmMismatchDiagnostic(signatureAlgorithm.oid, tbsSignatureAlgorithm.oid));
    }
    const signatureValue = _readBitString(expectUniversalField(cert.children[2], TAG_BIT_STRING, 'signatureValue', STRUCTURE, cert.offset), ctx);

    const serialNumber: SerialNumber = { bytes: serialNode.content, hex: toHex(serialNode.content), value: serialValue };
    const certificate: Certificate = {
        der: cert.bytes,
        tbsDer: tbs.bytes,
        version,
        serialNumber: Object.freeze(serialNumber),
        signatureAlgorithm,
        tbsSignatureAlgorithm,
        signatureValue,
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
        issuerUniqueId,
        subjectUniqueId,
        extensions,
        diagnostics: Object.freeze([...ctx.emitter.diagnostics]),
    };
    return Object.freeze(certificate);
}
