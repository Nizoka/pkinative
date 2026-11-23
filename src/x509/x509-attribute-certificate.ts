/**
 * pkinative — Attribute certificate
 * =================================
 * RFC 5755 §4.1: the AttributeCertificate envelope and every
 * AttributeCertificateInfo field — the holder and issuer references, the
 * validity period, the attributes (x509-ac-attributes.ts) and the extensions,
 * the three only an AC carries among them (x509-ext-attribute-certificate.ts).
 * A structural violation of the ASN.1 module throws `PkiCertificateError`; a
 * violation of the §4.2–§4.4 profile the module admits is a diagnostic on
 * `ac.diagnostics`.
 *
 * Parsing reads; it does not verify the signature
 * (`verifyAttributeCertificateSignature` does) and does not validate the AC:
 * RFC 5755 §5 is the caller's composition (ADR 0028).
 *
 * @module x509/x509-attribute-certificate
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readEnumerated, _readInteger } from '../asn1/asn1-read.js';
import { TAG_BIT_STRING, TAG_ENUMERATED, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_OID, TAG_SEQUENCE, tagLabel } from '../asn1/asn1-tags.js';
import { _readTime } from '../asn1/asn1-time.js';
import { assertBytes, bytesEqual, toHex } from '../core/bytes.js';
import {
    acExtensionCriticalityDiagnostic,
    acHolderEmptyDiagnostic,
    acHolderMultipleDiagnostic,
    acIssuerNotProfiledDiagnostic,
    acIssuerV1FormDiagnostic,
    generalizedTimeFractionDiagnostic,
    serialNotPositiveDiagnostic,
    serialTooLongDiagnostic,
    signatureAlgorithmMismatchDiagnostic,
    uniqueIdPresentDiagnostic,
    validityInvertedDiagnostic,
} from '../core/pki-diagnostics.js';
import type { Asn1Node, BitString, PkiTime } from '../types/asn1-types.js';
import type {
    AttributeCertificate,
    AttributeCertificateExtension,
    AttributeCertificateHolder,
    AttributeCertificateIssuer,
    DigestedObjectType,
    IssuerSerial,
    ObjectDigestInfo,
} from '../types/attribute-certificate-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { DistinguishedName, GeneralName, ParseCertificateOptions, SerialNumber, Validity } from '../types/x509-types.js';
import { _readAcAttributes, _readAcGeneralNames } from './x509-ac-attributes.js';
import { _readAlgorithmIdentifier } from './x509-algorithm.js';
import { _readExtensionSequence } from './x509-certificate.js';
import { AC_EXTENSION_DECODERS } from './x509-ext-attribute-certificate.js';
import { certificateError, expectUniversalField } from './x509-fields.js';
import { _readGeneralNameList } from './x509-general-name.js';

const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';
const VALIDITY = 'PKI_X509_VALIDITY_INVALID';
const OID_CRL_DISTRIBUTION_POINTS = '2.5.29.31';
const DIGESTED_OBJECT_TYPES: readonly DigestedObjectType[] = /*#__PURE__*/ Object.freeze<DigestedObjectType[]>(['publicKey', 'publicKeyCert', 'otherObjectTypes']);
const NO_EXTENSIONS: readonly AttributeCertificateExtension[] = /*#__PURE__*/ Object.freeze([]);
const HOLDER_OPTIONS: readonly string[] = /*#__PURE__*/ Object.freeze(['baseCertificateID', 'entityName', 'objectDigestInfo']);

/**
 * Implicitly tagged optional fields `[0]` to `[maxTag]`, each at most once and
 * in increasing order, indexed by tag number.
 */
function taggedFields(children: readonly Asn1Node[], maxTag: number, path: string): Array<Asn1Node | undefined> {
    const fields: Array<Asn1Node | undefined> = [];
    let last = -1;
    for (const child of children) {
        if (child.tagClass !== 'context' || child.tagNumber > maxTag || child.tagNumber <= last) {
            throw certificateError(STRUCTURE, path, child.offset, `holds ${tagLabel(child.tagClass, child.tagNumber)} where only [0] to [${String(maxTag)}], once each and in order, may appear`);
        }
        fields[child.tagNumber] = child;
        last = child.tagNumber;
    }
    return fields;
}

// ── IssuerSerial and ObjectDigestInfo ────────────────────────────────

function readSerial(node: Asn1Node, ctx: Asn1Context): SerialNumber {
    const serial: SerialNumber = { bytes: node.content, hex: toHex(node.content), value: _readInteger(node, ctx) };
    return Object.freeze(serial);
}

/** IssuerSerial (RFC 5755 §4.1), as a SEQUENCE or under its implicit tag. */
function readIssuerSerial(node: Asn1Node, ctx: Asn1Context, path: string): IssuerSerial {
    const children = node.children;
    // Fewer than two components leaves issuer or serial missing, which the field checks below refuse.
    if (children.length > 3) {
        throw certificateError(STRUCTURE, path, node.offset, `holds ${String(children.length)} values; IssuerSerial is issuer, serial and an optional issuerUID`);
    }
    const issuerNode = expectUniversalField(children[0], TAG_SEQUENCE, `${path}.issuer`, STRUCTURE, node.offset);
    const issuer = _readAcGeneralNames(issuerNode, ctx, `${path}.issuer`);
    const serial = readSerial(expectUniversalField(children[1], TAG_INTEGER, `${path}.serial`, STRUCTURE, node.offset), ctx);
    const uidNode = children[2];
    const issuerUid = uidNode === undefined ? undefined : _readBitString(expectUniversalField(uidNode, TAG_BIT_STRING, `${path}.issuerUID`, STRUCTURE, node.offset), ctx);
    const value: IssuerSerial = { issuer, serial, issuerUid, der: node.bytes };
    return Object.freeze(value);
}

/** ObjectDigestInfo (RFC 5755 §4.1), under its implicit tag. */
function readObjectDigestInfo(node: Asn1Node, ctx: Asn1Context, path: string): ObjectDigestInfo {
    const children = node.children;
    // Fewer than three cannot hold both an AlgorithmIdentifier and a BIT STRING after the type: the field checks below refuse them.
    if (children.length > 4) {
        throw certificateError(STRUCTURE, path, node.offset, `holds ${String(children.length)} values; ObjectDigestInfo is digestedObjectType, an optional otherObjectTypeID, digestAlgorithm and objectDigest`);
    }
    const typeNode = expectUniversalField(children[0], TAG_ENUMERATED, `${path}.digestedObjectType`, STRUCTURE, node.offset);
    const type = _readEnumerated(typeNode, ctx);
    if (type < 0n || type > 2n) {
        throw certificateError(STRUCTURE, `${path}.digestedObjectType`, typeNode.offset, `is ${String(type)}; it is publicKey (0), publicKeyCert (1) or otherObjectTypes (2)`);
    }
    const other = children.length === 4;
    const otherObjectTypeId = other ? _readObjectIdentifier(expectUniversalField(children[1], TAG_OID, `${path}.otherObjectTypeID`, STRUCTURE, node.offset), ctx) : undefined;
    const digestAlgorithm = _readAlgorithmIdentifier(children[other ? 2 : 1], ctx, `${path}.digestAlgorithm`, STRUCTURE, node.offset);
    const objectDigest = _readBitString(expectUniversalField(children[children.length - 1], TAG_BIT_STRING, `${path}.objectDigest`, STRUCTURE, node.offset), ctx);
    const value: ObjectDigestInfo = {
        digestedObjectType: DIGESTED_OBJECT_TYPES[Number(type)] as DigestedObjectType,
        otherObjectTypeId,
        digestAlgorithm,
        objectDigest,
        der: node.bytes,
    };
    return Object.freeze(value);
}

// ── Holder and issuer ────────────────────────────────────────────────

function readHolder(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): AttributeCertificateHolder {
    const path = 'acinfo.holder';
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, STRUCTURE, parentOffset);
    const fields = taggedFields(seq.children, 2, path);
    const [baseNode, nameNode, digestNode] = fields;
    const holder: AttributeCertificateHolder = {
        baseCertificateId: baseNode === undefined ? undefined : readIssuerSerial(baseNode, ctx, `${path}.baseCertificateID`),
        entityName: nameNode === undefined ? undefined : _readAcGeneralNames(nameNode, ctx, `${path}.entityName`),
        objectDigestInfo: digestNode === undefined ? undefined : readObjectDigestInfo(digestNode, ctx, `${path}.objectDigestInfo`),
        der: seq.bytes,
    };
    const present = HOLDER_OPTIONS.filter((_, i) => fields[i] !== undefined);
    // §4.2.2: none binds the attributes to anybody; more than one is
    // "a potential for confusion", and the RFC RECOMMENDS one.
    if (present.length === 0) ctx.emitter.emit(acHolderEmptyDiagnostic(seq.offset));
    if (present.length > 1) ctx.emitter.emit(acHolderMultipleDiagnostic(present, seq.offset));
    return Object.freeze(holder);
}

/** The one non-empty directoryName §4.2.3 requires, or `undefined`. */
function profiledName(names: readonly GeneralName[] | undefined): DistinguishedName | undefined {
    const only = names?.length === 1 ? names[0] : undefined;
    return only?.kind === 'directoryName' && only.name.rdns.length > 0 ? only.name : undefined;
}

function readIssuer(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): AttributeCertificateIssuer {
    const path = 'acinfo.issuer';
    if (node === undefined) throw certificateError(STRUCTURE, path, parentOffset, 'is missing; expected AttCertIssuer');
    if (node.tagClass === 'universal' && node.tagNumber === TAG_SEQUENCE) {
        // v1Form: bare GeneralNames, which §4.2.3 forbids — read, and said.
        ctx.emitter.emit(acIssuerV1FormDiagnostic(node.offset));
        const issuerName = _readGeneralNameList(node, ctx, `${path}.v1Form`, false);
        const issuer: AttributeCertificateIssuer = {
            form: 'v1Form', issuerName, name: profiledName(issuerName), baseCertificateId: undefined, objectDigestInfo: undefined, der: node.bytes,
        };
        return Object.freeze(issuer);
    }
    if (node.tagClass !== 'context' || node.tagNumber !== 0 || !node.constructed) {
        throw certificateError(STRUCTURE, path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; AttCertIssuer is v2Form [0] (or the v1Form GeneralNames SEQUENCE)`);
    }
    const first = node.children[0];
    const named = first !== undefined && first.tagClass === 'universal' && first.tagNumber === TAG_SEQUENCE;
    const issuerName = named ? _readGeneralNameList(first, ctx, `${path}.issuerName`, false) : undefined;
    const [baseNode, digestNode] = taggedFields(node.children.slice(named ? 1 : 0), 1, path);
    const issuer: AttributeCertificateIssuer = {
        form: 'v2Form',
        issuerName,
        name: profiledName(issuerName),
        baseCertificateId: baseNode === undefined ? undefined : readIssuerSerial(baseNode, ctx, `${path}.baseCertificateID`),
        objectDigestInfo: digestNode === undefined ? undefined : readObjectDigestInfo(digestNode, ctx, `${path}.objectDigestInfo`),
        der: node.bytes,
    };
    const problems: string[] = [];
    if (issuer.name === undefined) problems.push('does not name exactly one non-empty directoryName');
    if (baseNode !== undefined) problems.push('carries baseCertificateID');
    if (digestNode !== undefined) problems.push('carries objectDigestInfo');
    if (problems.length > 0) ctx.emitter.emit(acIssuerNotProfiledDiagnostic(problems.join(' and '), node.offset));
    return Object.freeze(issuer);
}

// ── Version and validity ─────────────────────────────────────────────

function readVersion(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): 2 {
    const path = 'acinfo.version';
    if (node !== undefined && node.tagClass === 'context') {
        throw certificateError('PKI_X509_VERSION_INVALID', path, node.offset, 'is absent: the structure is a v1 attribute certificate of X.509 (1997), and RFC 5755 §4.2.1 defines v2 only');
    }
    const field = expectUniversalField(node, TAG_INTEGER, path, STRUCTURE, parentOffset);
    const value = _readInteger(field, ctx);
    if (value !== 1n) throw certificateError('PKI_X509_VERSION_INVALID', path, field.offset, `is ${String(value)}; RFC 5755 §4.2.1 requires v2 (1)`);
    return 2;
}

function readAcTime(node: Asn1Node, ctx: Asn1Context, path: string): PkiTime {
    if (node.tagClass !== 'universal' || node.tagNumber !== TAG_GENERALIZED_TIME) {
        throw certificateError(VALIDITY, path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; an attribute certificate time is a GeneralizedTime (RFC 5755 §4.1)`);
    }
    const time = _readTime(node, ctx, undefined);
    // §4.2.6: "GeneralizedTime values MUST NOT include fractional seconds."
    if (/[.,]/.test(time.text)) ctx.emitter.emit(generalizedTimeFractionDiagnostic(path, time.text, node.offset));
    return time;
}

function readValidity(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): Validity {
    const path = 'acinfo.attrCertValidityPeriod';
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, VALIDITY, parentOffset);
    if (seq.children.length !== 2) {
        throw certificateError(VALIDITY, path, seq.offset, `holds ${String(seq.children.length)} values; AttCertValidityPeriod is notBeforeTime and notAfterTime`);
    }
    const notBefore = readAcTime(seq.children[0] as Asn1Node, ctx, `${path}.notBeforeTime`);
    const notAfter = readAcTime(seq.children[1] as Asn1Node, ctx, `${path}.notAfterTime`);
    if (notBefore.epochMilliseconds > notAfter.epochMilliseconds) ctx.emitter.emit(validityInvertedDiagnostic(notBefore.text, notAfter.text, path));
    const validity: Validity = { notBefore, notAfter };
    return Object.freeze(validity);
}

// ── AttributeCertificate ─────────────────────────────────────────────

/**
 * Parse a DER-encoded attribute certificate (RFC 5755 §4.1). Parsing checks
 * the structure and records the profile concerns of §4.2–§4.4 as diagnostics;
 * it does not verify the signature and does not validate the AC — holder
 * binding, targeting, revocation and the issuer's path are RFC 5755 §5, and
 * the caller's composition (ADR 0028).
 *
 * The six attributes of §4.4 are decoded, any other is kept with its values'
 * DER as `kind: 'unknown'`; the extensions are read as a certificate's are,
 * plus auditIdentity, targetInformation and noRevAvail, which only an AC
 * carries.
 *
 * @param der     The attribute certificate encoding. The result holds zero-copy views of it: do not mutate it while you use the result.
 * @param options Encoding rules (`'der'` by default), limits, `strict`, `onDiagnostic` and `decodeExtensions` (default `true`).
 * @returns The frozen attribute certificate, with every diagnostic of the parse on `diagnostics`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID`, `PKI_X509_VERSION_INVALID` (a version other than v2, a v1 AC included),
 *   `PKI_X509_VALIDITY_INVALID` (a UTCTime among them), `PKI_X509_NAME_INVALID`, `PKI_X509_GENERAL_NAME_INVALID`,
 *   `PKI_X509_ATTRIBUTE_MALFORMED`, `PKI_X509_EXTENSIONS_EMPTY`, `PKI_X509_EXTENSION_DUPLICATE` or `PKI_X509_EXTENSION_MALFORMED`
 *   when the DER is not an RFC 5755 attribute certificate.
 * @throws {PkiEncodingError} For every X.690 violation (`PKI_ASN1_*`, `PKI_OID_INVALID`).
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond a configured limit (`maxInputBytes`, `maxAttributes`, `maxGeneralNames`, `maxExtensions`, …).
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument; `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function parseAttributeCertificate(der: Uint8Array, options?: ParseCertificateOptions): AttributeCertificate {
    const bytes = assertBytes(der, 'parseAttributeCertificate input');
    const ctx = createAsn1Context(options);
    const decode = options?.decodeExtensions === undefined ? true : options.decodeExtensions;
    if (typeof decode !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: decodeExtensions must be a boolean, got ${typeof decode}`);
    }
    const ac = expectUniversalField(decodeWithContext(bytes, ctx, false), TAG_SEQUENCE, 'attributeCertificate', STRUCTURE, 0);
    if (ac.children.length !== 3) {
        throw certificateError(STRUCTURE, 'attributeCertificate', ac.offset, `holds ${String(ac.children.length)} values; an AttributeCertificate is acinfo, signatureAlgorithm and signatureValue`);
    }
    const info = expectUniversalField(ac.children[0], TAG_SEQUENCE, 'acinfo', STRUCTURE, ac.offset);
    const fields = info.children;

    const version = readVersion(fields[0], ctx, info.offset);
    const holder = readHolder(fields[1], ctx, info.offset);
    const issuer = readIssuer(fields[2], ctx, info.offset);
    const tbsSignatureAlgorithm = _readAlgorithmIdentifier(fields[3], ctx, 'acinfo.signature', STRUCTURE, info.offset);
    const serialNode = expectUniversalField(fields[4], TAG_INTEGER, 'acinfo.serialNumber', STRUCTURE, info.offset);
    const serialNumber = readSerial(serialNode, ctx);
    // §4.2.5: positive, and at most 20 octets — the rules of RFC 5280 §4.1.2.2.
    if (serialNode.contentLength > 20) ctx.emitter.emit(serialTooLongDiagnostic(serialNode.contentLength, serialNode.offset, 'acinfo.serialNumber'));
    if (serialNumber.value <= 0n) ctx.emitter.emit(serialNotPositiveDiagnostic(serialNode.offset, 'acinfo.serialNumber'));
    const validity = readValidity(fields[5], ctx, info.offset);
    const attributes = _readAcAttributes(fields[6], ctx, info.offset);

    let index = 7;
    let issuerUniqueId: BitString | undefined;
    const uidNode = fields[index];
    if (uidNode !== undefined && uidNode.tagClass === 'universal' && uidNode.tagNumber === TAG_BIT_STRING) {
        issuerUniqueId = _readBitString(uidNode, ctx);
        // §4.2.8: only where the issuer's PKC has one, which RFC 5280 §4.1.2.8 forbids a conforming CA to issue.
        ctx.emitter.emit(uniqueIdPresentDiagnostic('acinfo.issuerUniqueID'));
        index++;
    }
    let extensions = NO_EXTENSIONS;
    const extensionsNode = fields[index];
    if (extensionsNode !== undefined) {
        const seq = expectUniversalField(extensionsNode, TAG_SEQUENCE, 'acinfo.extensions', STRUCTURE, info.offset);
        extensions = _readExtensionSequence(seq, ctx, bytes, decode, 'acinfo.extensions', 'the extensions of the attribute certificate', AC_EXTENSION_DECODERS);
        // §4.3.5 makes non-critical a MUST where RFC 5280 §4.2.1.13 says SHOULD
        // (an info there): the AC's own rule is the warning.
        const crlDp = extensions.findIndex((e) => e.oid === OID_CRL_DISTRIBUTION_POINTS && e.critical);
        if (crlDp >= 0) ctx.emitter.emit(acExtensionCriticalityDiagnostic('crlDistributionPoints', 'non-critical', `acinfo.extensions[${String(crlDp)}]`));
        index++;
    }
    const extra = fields[index];
    if (extra !== undefined) {
        throw certificateError(STRUCTURE, `acinfo[${String(index)}]`, extra.offset, `is ${tagLabel(extra.tagClass, extra.tagNumber)}, where nothing may follow the extensions`);
    }

    const signatureAlgorithm = _readAlgorithmIdentifier(ac.children[1], ctx, 'signatureAlgorithm', STRUCTURE, ac.offset);
    if (!bytesEqual(signatureAlgorithm.der, tbsSignatureAlgorithm.der)) {
        ctx.emitter.emit(signatureAlgorithmMismatchDiagnostic(signatureAlgorithm.oid, tbsSignatureAlgorithm.oid, 'acinfo.signature'));
    }
    const signatureValue = _readBitString(expectUniversalField(ac.children[2], TAG_BIT_STRING, 'signatureValue', STRUCTURE, ac.offset), ctx);

    const certificate: AttributeCertificate = {
        der: ac.bytes,
        tbsDer: info.bytes,
        version,
        holder,
        issuer,
        tbsSignatureAlgorithm,
        signatureAlgorithm,
        signatureValue,
        serialNumber,
        validity,
        attributes,
        issuerUniqueId,
        extensions,
        diagnostics: Object.freeze([...ctx.emitter.diagnostics]),
    };
    return Object.freeze(certificate);
}
