/**
 * pkinative — Identifier and name extensions
 * ==========================================
 * subjectKeyIdentifier, authorityKeyIdentifier, subjectAltName,
 * issuerAltName (RFC 5280 §4.2.1), the Certificate Transparency SCT list
 * (RFC 6962 §3.3) and id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1).
 *
 * @module x509/x509-ext-identifiers
 */

import { _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import { TAG_NULL, TAG_OCTET_STRING } from '../asn1/asn1-tags.js';
import { toHex } from '../core/bytes.js';
import { akiIssuerSerialUnpairedDiagnostic, sanEmptyDiagnostic } from '../core/pki-diagnostics.js';
import type {
    AuthorityKeyIdentifierExtension,
    IssuerAltNameExtension,
    OcspNoCheckExtension,
    SerialNumber,
    SignedCertificateTimestampListExtension,
    SubjectAltNameExtension,
    SubjectKeyIdentifierExtension,
} from '../types/x509-types.js';
import { MALFORMED, baseOf, contextFields, expectSequence, malformed, type ExtensionInput } from './x509-ext-shared.js';
import { expectUniversalField } from './x509-fields.js';
import { _readGeneralNameList, _readGeneralNames } from './x509-general-name.js';

/** @internal */
export function decodeSubjectKeyIdentifier(input: ExtensionInput): SubjectKeyIdentifierExtension {
    const { node, ctx, path } = input;
    const keyIdentifier = _readOctetString(expectUniversalField(node, TAG_OCTET_STRING, path, MALFORMED, node.offset), ctx);
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
    return Object.freeze(extension);
}

/** @internal */
export function decodeSubjectAltName(input: ExtensionInput): SubjectAltNameExtension {
    const names = _readGeneralNames(input.node, input.ctx, input.path, false);
    if (names.length === 0) input.ctx.emitter.emit(sanEmptyDiagnostic(input.path));
    const extension: SubjectAltNameExtension = { ...baseOf(input), kind: 'subjectAltName', names };
    return Object.freeze(extension);
}

/** @internal */
export function decodeIssuerAltName(input: ExtensionInput): IssuerAltNameExtension {
    const names = _readGeneralNames(input.node, input.ctx, input.path, false);
    if (names.length === 0) input.ctx.emitter.emit(sanEmptyDiagnostic(input.path));
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
