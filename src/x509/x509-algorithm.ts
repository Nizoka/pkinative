/**
 * pkinative — AlgorithmIdentifier
 * ===============================
 * RFC 5280 §4.1.1.2: an algorithm OID and optional parameters. The
 * parameters stay an undecoded node; only the RSA PKCS #1 v1.5 rule of
 * RFC 3279 §2.2.1 (parameters NULL) is checked here, as a diagnostic.
 *
 * @module x509/x509-algorithm
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { TAG_NULL, TAG_OID, TAG_SEQUENCE } from '../asn1/asn1-tags.js';
import { rsaParametersNotNullDiagnostic } from '../core/pki-diagnostics.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type { PkiCertificateErrorCode } from '../types/pki-errors.js';
import type { AlgorithmIdentifier } from '../types/x509-types.js';
import { certificateError, expectUniversalField } from './x509-fields.js';

/** rsaEncryption and the PKCS #1 v1.5 signature algorithms, whose parameters must be NULL. */
const PKCS1_V15: ReadonlySet<string> = /*#__PURE__*/ new Set([
    '1.2.840.113549.1.1.1',
    '1.2.840.113549.1.1.2',
    '1.2.840.113549.1.1.3',
    '1.2.840.113549.1.1.4',
    '1.2.840.113549.1.1.5',
    '1.2.840.113549.1.1.11',
    '1.2.840.113549.1.1.12',
    '1.2.840.113549.1.1.13',
    '1.2.840.113549.1.1.14',
    '1.2.840.113549.1.1.15',
    '1.2.840.113549.1.1.16',
]);

/**
 * Read an AlgorithmIdentifier; `code` is the error of the structure it sits in.
 *
 * @internal
 */
export function _readAlgorithmIdentifier(
    node: Asn1Node | undefined,
    ctx: Asn1Context,
    path: string,
    code: PkiCertificateErrorCode,
    parentOffset: number,
): AlgorithmIdentifier {
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, code, parentOffset);
    if (seq.children.length > 2) {
        throw certificateError(code, path, seq.offset, `holds ${seq.children.length} values; an AlgorithmIdentifier is an OID and optional parameters`);
    }
    const oid = _readObjectIdentifier(expectUniversalField(seq.children[0], TAG_OID, `${path}.algorithm`, code, seq.offset), ctx);
    const parameters = seq.children[1];
    const isNull = parameters !== undefined && parameters.tagClass === 'universal' && parameters.tagNumber === TAG_NULL && parameters.contentLength === 0;
    if (PKCS1_V15.has(oid) && !isNull) ctx.emitter.emit(rsaParametersNotNullDiagnostic(`${path}.parameters`, seq.offset));
    const algorithm: AlgorithmIdentifier = { oid, parameters, der: seq.bytes };
    return Object.freeze(algorithm);
}
