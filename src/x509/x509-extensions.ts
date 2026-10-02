/**
 * pkinative — Extension dispatcher
 * ================================
 * One decoder per recognised extension OID. The extension value is decoded
 * in place, so every offset stays absolute in the certificate — with one
 * exception: under `encodingRules: 'ber'`, an extnValue in the constructed
 * (segmented) form is joined into a copy and decoded there, and the offsets
 * of the errors and diagnostics inside it count from the first octet of the
 * joined content, not from the certificate. The segment headers between the
 * pieces leave no single shift that would map one onto the other. A recognised
 * extension whose value does not match its ASN.1 definition throws
 * `PKI_X509_EXTENSION_MALFORMED`; an unrecognised one is kept as
 * `kind: 'unknown'`, with a diagnostic when it is critical.
 *
 * @module x509/x509-extensions
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeValueAt } from '../asn1/asn1-decode.js';
import { isValidOid } from '../asn1/asn1-oid.js';
import { assertBytes } from '../core/bytes.js';
import { unknownCriticalExtensionDiagnostic } from '../core/pki-diagnostics.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import type { Certificate, DecodeExtensionValueOptions, DecodedExtensionKind, Extension, UnknownExtension } from '../types/x509-types.js';
import {
    decodeBasicConstraints,
    decodeExtendedKeyUsage,
    decodeInhibitAnyPolicy,
    decodeKeyUsage,
    decodeNameConstraints,
    decodePolicyConstraints,
} from './x509-ext-constraints.js';
import {
    decodeAuthorityInfoAccess,
    decodeCrlDistributionPoints,
    decodeFreshestCrl,
    decodeSubjectInfoAccess,
} from './x509-ext-distribution.js';
import {
    decodeAuthorityKeyIdentifier,
    decodeIssuerAltName,
    decodeOcspNoCheck,
    decodeSignedCertificateTimestampList,
    decodeSubjectAltName,
    decodeSubjectDirectoryAttributes,
    decodeSubjectKeyIdentifier,
} from './x509-ext-identifiers.js';
import { decodeCertificatePolicies, decodePolicyMappings } from './x509-ext-policies.js';
import { malformed, type ExtensionInput } from './x509-ext-shared.js';

type Decoder = (input: ExtensionInput) => Extension;

const DECODERS: ReadonlyMap<string, Decoder> = /*#__PURE__*/ new Map<string, Decoder>([
    ['2.5.29.9', decodeSubjectDirectoryAttributes],
    ['2.5.29.14', decodeSubjectKeyIdentifier],
    ['2.5.29.15', decodeKeyUsage],
    ['2.5.29.17', decodeSubjectAltName],
    ['2.5.29.18', decodeIssuerAltName],
    ['2.5.29.19', decodeBasicConstraints],
    ['2.5.29.30', decodeNameConstraints],
    ['2.5.29.31', decodeCrlDistributionPoints],
    ['2.5.29.32', decodeCertificatePolicies],
    ['2.5.29.33', decodePolicyMappings],
    ['2.5.29.35', decodeAuthorityKeyIdentifier],
    ['2.5.29.36', decodePolicyConstraints],
    ['2.5.29.37', decodeExtendedKeyUsage],
    ['2.5.29.46', decodeFreshestCrl],
    ['2.5.29.54', decodeInhibitAnyPolicy],
    ['1.3.6.1.5.5.7.1.1', decodeAuthorityInfoAccess],
    ['1.3.6.1.5.5.7.1.11', decodeSubjectInfoAccess],
    ['1.3.6.1.4.1.11129.2.4.2', decodeSignedCertificateTimestampList],
    ['1.3.6.1.5.5.7.48.1.5', decodeOcspNoCheck],
]);

/**
 * Decode one extension value. `data` ends where the value ends and `start`
 * is where it begins, so offsets are those of `data`.
 *
 * @internal
 */
export function _decodeExtension(
    data: Uint8Array,
    start: number,
    oid: string,
    critical: boolean,
    valueDer: Uint8Array,
    ctx: Asn1Context,
    path: string,
): Extension {
    const decoder = DECODERS.get(oid);
    if (decoder === undefined) {
        if (critical) ctx.emitter.emit(unknownCriticalExtensionDiagnostic(oid, path));
        const extension: UnknownExtension = { kind: 'unknown', oid, critical, valueDer };
        return Object.freeze(extension);
    }
    try {
        const node = decodeValueAt(data, start, ctx);
        const end = node.offset + node.bytes.length;
        if (end !== data.length) throw malformed(path, end, `has ${data.length - end} octet(s) after the extension value inside extnValue`);
        return decoder({ node, ctx, path, oid, critical, valueDer });
    } catch (error) {
        if (error instanceof PkiEncodingError) {
            /* v8 ignore next -- unreachable: every PkiEncodingError a recognised extension decoder can raise comes from a reader that knows its node offset. The class makes `offset` optional only because the encoders, the PEM layer and decodeExtensionValue's own OID check throw without one, and no decode path reaches any of them. */
            throw malformed(path, error.offset ?? start, `does not match its ASN.1 definition (${error.code})`);
        }
        throw error;
    }
}

/**
 * Decode an extension value on its own — the content of an extnValue — as
 * `parseCertificate` decodes it. Use it after parsing with
 * `decodeExtensions: false`, or on an extension from any other source.
 * Diagnostics go to `onDiagnostic` (or the console) and `strict`.
 *
 * @param oid       The extension OID, e.g. `2.5.29.17`.
 * @param valueDer  The DER encoding of the extension value.
 * @param options   `critical`, encoding rules, limits, `strict` and `onDiagnostic`.
 * @returns The decoded extension, or `kind: 'unknown'` for an OID pkinative does not decode.
 * @throws {PkiCertificateError} `PKI_X509_EXTENSION_MALFORMED`, `PKI_X509_GENERAL_NAME_INVALID` or `PKI_X509_NAME_INVALID`
 *   when the value does not match the definition of its extension.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for an OID string X.660 does not allow.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond a configured limit.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument; `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function decodeExtensionValue(oid: string, valueDer: Uint8Array, options?: DecodeExtensionValueOptions): Extension {
    if (typeof oid !== 'string') throw new PkiError('PKI_INVALID_INPUT', `pkinative: decodeExtensionValue expects the extension OID as a dotted string, got ${typeof oid}`);
    if (!isValidOid(oid)) throw new PkiEncodingError('PKI_OID_INVALID', `pkinative: "${oid.slice(0, 64)}" is not a dotted-decimal OID X.660 allows — pass the extnID, e.g. 2.5.29.17`);
    const bytes = assertBytes(valueDer, 'decodeExtensionValue value');
    const critical = options?.critical ?? false;
    if (typeof critical !== 'boolean') throw new PkiError('PKI_INVALID_OPTION', `pkinative: critical must be a boolean, got ${typeof critical}`);
    return _decodeExtension(bytes, 0, oid, critical, bytes, createAsn1Context(options), 'extnValue');
}

/**
 * The decoded extension of one kind, e.g. `getExtension(cert, 'subjectAltName')?.names`.
 *
 * @param certificate A certificate from `parseCertificate`.
 * @param kind        The extension kind; RFC 5280 allows each extension once per certificate.
 * @returns The extension, or `undefined` when the certificate does not carry it, was parsed with `decodeExtensions: false`,
 *   or `kind` names no decoded extension kind (TypeScript refuses such a kind at compile time).
 * @throws {PkiError} `PKI_INVALID_INPUT` when `certificate` is not a parsed certificate.
 */
export function getExtension<K extends DecodedExtensionKind>(certificate: Certificate, kind: K): Extract<Extension, { readonly kind: K }> | undefined {
    if (typeof certificate !== 'object' || certificate === null || !Array.isArray(certificate.extensions)) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: getExtension expects a certificate returned by parseCertificate, got ${certificate === null ? 'null' : typeof certificate}`);
    }
    for (const extension of certificate.extensions) {
        if (extension.kind === kind) return extension as Extract<Extension, { readonly kind: K }>;
    }
    return undefined;
}
