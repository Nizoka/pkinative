/**
 * pkinative — Identifier and name extensions
 * ==========================================
 * subjectKeyIdentifier, authorityKeyIdentifier, subjectAltName,
 * issuerAltName, subjectDirectoryAttributes (RFC 5280 §4.2.1), the
 * Certificate Transparency SCT list (RFC 6962 §3.3) and id-pkix-ocsp-nocheck
 * (RFC 6960 §4.2.2.2.1).
 *
 * @module x509/x509-ext-identifiers
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import { TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET } from '../asn1/asn1-tags.js';
import { toHex } from '../core/bytes.js';
import {
    akiCriticalDiagnostic,
    akiIssuerSerialUnpairedDiagnostic,
    altNameGeneralNameEmptyDiagnostic,
    altNameUriHostInvalidDiagnostic,
    altNameUriInvalidDiagnostic,
    altNameUriSchemeMissingDiagnostic,
    issuerAltNameCriticalDiagnostic,
    sanEmptyDiagnostic,
    skiCriticalDiagnostic,
    subjectDirectoryAttributesCriticalDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import { isFqdnOrIpHost, isUri, uriAuthorityHost, uriScheme } from '../core/uri.js';
import type {
    AuthorityKeyIdentifierExtension,
    DirectoryAttribute,
    GeneralName,
    IssuerAltNameExtension,
    OcspNoCheckExtension,
    SerialNumber,
    SignedCertificateTimestampListExtension,
    SubjectAltNameExtension,
    SubjectDirectoryAttributesExtension,
    SubjectKeyIdentifierExtension,
} from '../types/x509-types.js';
import { MALFORMED, baseOf, contextFields, expectNonEmpty, expectSequence, malformed, type ExtensionInput } from './x509-ext-shared.js';
import { expectUniversalField } from './x509-fields.js';
import { _readGeneralNameList, _readGeneralNames } from './x509-general-name.js';

/** @internal */
export function decodeSubjectKeyIdentifier(input: ExtensionInput): SubjectKeyIdentifierExtension {
    const { node, ctx, path } = input;
    const keyIdentifier = _readOctetString(expectUniversalField(node, TAG_OCTET_STRING, path, MALFORMED, node.offset), ctx);
    if (input.critical) ctx.emitter.emit(skiCriticalDiagnostic());
    const extension: SubjectKeyIdentifierExtension = { ...baseOf(input), kind: 'subjectKeyIdentifier', keyIdentifier };
    return Object.freeze(extension);
}

/** @internal */
export function decodeAuthorityKeyIdentifier(input: ExtensionInput): AuthorityKeyIdentifierExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    const [keyNode, issuerNode, serialNode] = contextFields(seq.children, 2, path);
    let authorityCertSerialNumber: SerialNumber | undefined;
    if (serialNode !== undefined) {
        const serial: SerialNumber = { bytes: serialNode.content, hex: toHex(serialNode.content), value: _readInteger(serialNode, ctx) };
        authorityCertSerialNumber = Object.freeze(serial);
    }
    const extension: AuthorityKeyIdentifierExtension = {
        ...baseOf(input),
        kind: 'authorityKeyIdentifier',
        keyIdentifier: keyNode === undefined ? undefined : _readOctetString(keyNode, ctx),
        authorityCertIssuer: issuerNode === undefined ? undefined : _readGeneralNameList(issuerNode, ctx, `${path}.authorityCertIssuer`, false),
        authorityCertSerialNumber,
    };
    if ((issuerNode === undefined) !== (serialNode === undefined)) ctx.emitter.emit(akiIssuerSerialUnpairedDiagnostic());
    if (input.critical) ctx.emitter.emit(akiCriticalDiagnostic());
    return Object.freeze(extension);
}

/** Whether a GeneralName holds nothing: an empty string, a Name without an RDN, an empty x400Address or ediPartyName. */
function isEmptyName(name: GeneralName): boolean {
    switch (name.kind) {
        case 'rfc822Name':
        case 'dNSName':
        case 'uniformResourceIdentifier':
            return name.value === '';
        case 'directoryName':
            return name.name.rdns.length === 0;
        case 'x400Address':
        case 'ediPartyName':
            return name.value.contentLength === 0;
        default:
            // An otherName has a type-id, an iPAddress 4 or 16 octets and a
            // registeredID an arc: the decoder has refused any of them empty.
            return false;
    }
}

/**
 * RFC 5280 §4.2.1.6 on the content of each name — and §4.2.1.7, which encodes
 * issuer alternative names *"as in 4.2.1.6"*. A URI is judged by the RFC 3986
 * grammar of core/uri.ts, the one name constraints read its host with; it is
 * kept and compared literally whatever the verdict.
 */
function emitAltNameDiagnostics(names: readonly GeneralName[], ctx: Asn1Context, extension: string): void {
    for (let i = 0; i < names.length; i++) {
        const name = names[i] as GeneralName;
        const at = `tbsCertificate.extensions.${extension}[${String(i)}]`;
        if (isEmptyName(name)) ctx.emitter.emit(altNameGeneralNameEmptyDiagnostic(name.kind, at));
        if (name.kind !== 'uniformResourceIdentifier') continue;
        const uri = name.value;
        if (!isUri(uri)) ctx.emitter.emit(altNameUriInvalidDiagnostic(uri, at));
        const scheme = uriScheme(uri);
        if (scheme === null || scheme.specific === '') ctx.emitter.emit(altNameUriSchemeMissingDiagnostic(uri, at));
        const host = uriAuthorityHost(uri);
        if (host !== null && !isFqdnOrIpHost(host)) ctx.emitter.emit(altNameUriHostInvalidDiagnostic(uri, at));
    }
}

/** @internal */
export function decodeSubjectAltName(input: ExtensionInput): SubjectAltNameExtension {
    const names = _readGeneralNames(input.node, input.ctx, input.path, false);
    if (names.length === 0) input.ctx.emitter.emit(sanEmptyDiagnostic(input.path));
    emitAltNameDiagnostics(names, input.ctx, 'subjectAltName');
    const extension: SubjectAltNameExtension = { ...baseOf(input), kind: 'subjectAltName', names };
    return Object.freeze(extension);
}

/** @internal */
export function decodeIssuerAltName(input: ExtensionInput): IssuerAltNameExtension {
    const names = _readGeneralNames(input.node, input.ctx, input.path, false);
    if (names.length === 0) input.ctx.emitter.emit(sanEmptyDiagnostic(input.path));
    emitAltNameDiagnostics(names, input.ctx, 'issuerAltName');
    if (input.critical) input.ctx.emitter.emit(issuerAltNameCriticalDiagnostic());
    const extension: IssuerAltNameExtension = { ...baseOf(input), kind: 'issuerAltName', names };
    return Object.freeze(extension);
}

/** @internal */
export function decodeSignedCertificateTimestampList(input: ExtensionInput): SignedCertificateTimestampListExtension {
    const { node, ctx, path } = input;
    const list = _readOctetString(expectUniversalField(node, TAG_OCTET_STRING, path, MALFORMED, node.offset), ctx);
    const extension: SignedCertificateTimestampListExtension = { ...baseOf(input), kind: 'signedCertificateTimestampList', list };
    return Object.freeze(extension);
}

/** @internal */
export function decodeOcspNoCheck(input: ExtensionInput): OcspNoCheckExtension {
    const { node, path } = input;
    const value = expectUniversalField(node, TAG_NULL, path, MALFORMED, node.offset);
    if (value.contentLength !== 0) throw malformed(path, value.offset, `is a NULL with ${value.contentLength} content octets; X.690 §8.8.2 allows none`);
    const extension: OcspNoCheckExtension = { ...baseOf(input), kind: 'ocspNoCheck' };
    return Object.freeze(extension);
}

/**
 * subjectDirectoryAttributes (RFC 5280 §4.2.1.8): `SEQUENCE SIZE (1..MAX) OF
 * Attribute`, each a type and a non-empty SET OF values. The values are
 * attribute-specific — dateOfBirth, placeOfBirth, gender, countryOfCitizenship
 * and countryOfResidence (RFC 3739 §3.2.2) are the usual ones — and are kept
 * as their DER, as every other open-ended value in this library is. Bounded
 * by `maxAttributes`, for the attributes and for the values of each.
 *
 * @internal
 */
export function decodeSubjectDirectoryAttributes(input: ExtensionInput): SubjectDirectoryAttributesExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    expectNonEmpty(seq, path, 'attribute');
    enforceLimit(ctx.limits, 'maxAttributes', seq.children.length, `the attributes of ${path}`);
    const attributes: DirectoryAttribute[] = [];
    for (let i = 0; i < seq.children.length; i++) {
        const at = `${path}[${String(i)}]`;
        const attribute = expectUniversalField(seq.children[i], TAG_SEQUENCE, at, MALFORMED, seq.offset);
        if (attribute.children.length !== 2) {
            throw malformed(at, attribute.offset, `holds ${String(attribute.children.length)} values; an Attribute is a type and a SET of values`);
        }
        const oid = _readObjectIdentifier(expectUniversalField(attribute.children[0], TAG_OID, `${at}.type`, MALFORMED, attribute.offset), ctx);
        const values = expectUniversalField(attribute.children[1], TAG_SET, `${at}.values`, MALFORMED, attribute.offset);
        // RFC 5280 Appendix A.1: "at least one value is required".
        if (values.children.length === 0) throw malformed(`${at}.values`, values.offset, 'is empty; an attribute carries at least one value');
        enforceLimit(ctx.limits, 'maxAttributes', values.children.length, `the values of ${at}`);
        attributes.push(Object.freeze({ oid, values: Object.freeze(values.children.map((v) => v.bytes)), der: attribute.bytes }));
    }
    if (input.critical) ctx.emitter.emit(subjectDirectoryAttributesCriticalDiagnostic());
    const extension: SubjectDirectoryAttributesExtension = { ...baseOf(input), kind: 'subjectDirectoryAttributes', attributes: Object.freeze(attributes) };
    return Object.freeze(extension);
}
