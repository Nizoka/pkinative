/**
 * pkinative — X.509 field checks
 * ==============================
 * The two helpers every certificate structure reader shares — the certificate,
 * the CRL and the PKCS#10 request among them: the error of a field that is
 * missing or of the wrong type, and the check that raises it. Every
 * `PkiCertificateError` names its path, its offset and a remedy.
 *
 * @module x509/x509-fields
 */

import { tagLabel } from '../asn1/asn1-tags.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiCertificateError, type PkiCertificateErrorCode } from '../types/pki-errors.js';

const REMEDIES: Readonly<Record<PkiCertificateErrorCode, string>> = /*#__PURE__*/ Object.freeze({
    PKI_X509_STRUCTURE_INVALID: 'check that the input is the structure this reader expects: a certificate, a CSR, a CRL and a key are four different ones',
    PKI_X509_VERSION_INVALID: 'the input is not a version RFC 5280 (certificate) or RFC 2986 (request) defines',
    PKI_X509_NAME_INVALID: 'the issuer encoded the name wrongly',
    PKI_X509_VALIDITY_INVALID: 'the issuer encoded the validity period wrongly',
    PKI_X509_SPKI_INVALID: 'the issuer encoded the public key wrongly',
    PKI_X509_UNIQUE_ID_INVALID: 'the issuer encoded the certificate wrongly',
    PKI_X509_EXTENSIONS_EMPTY: 'the issuer encoded the certificate wrongly',
    PKI_X509_EXTENSION_DUPLICATE: 'which instance a verifier reads is undefined, so the certificate is refused',
    PKI_X509_EXTENSION_MALFORMED: 'parse with decodeExtensions: false to keep every extension raw',
    PKI_X509_GENERAL_NAME_INVALID: 'the issuer encoded the name wrongly',
});

/**
 * The error of one certificate field.
 *
 * @internal
 */
export function certificateError(code: PkiCertificateErrorCode, path: string, offset: number, why: string): PkiCertificateError {
    return new PkiCertificateError(code, `pkinative: ${path} at offset ${offset} ${why} — ${REMEDIES[code]}`, path, offset);
}

/**
 * A field that must be present and carry one universal tag. The decoder has
 * already checked the primitive or constructed form of every universal type.
 *
 * @internal
 */
export function expectUniversalField(
    node: Asn1Node | undefined,
    tagNumber: number,
    path: string,
    code: PkiCertificateErrorCode,
    parentOffset: number,
): Asn1Node {
    const expected = tagLabel('universal', tagNumber);
    if (node === undefined) throw certificateError(code, path, parentOffset, `is missing; expected ${expected}`);
    if (node.tagClass !== 'universal' || node.tagNumber !== tagNumber) {
        throw certificateError(code, path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; expected ${expected}`);
    }
    return node;
}
