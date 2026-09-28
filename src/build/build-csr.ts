/**
 * pkinative — certification request creation
 * ==========================================
 * A PKCS#10 `CertificationRequest` (RFC 2986) from a typed description,
 * signed by the key whose public half it carries.
 *
 * A CSR is a proof of possession: the signature is made with the private
 * half of `subjectPublicKey`, and a CA that verifies it learns the requester
 * holds that key. Signing with a different key produces a request that is
 * structurally valid and proves nothing, so the one check worth making here
 * is the one a caller cannot make for themselves — see
 * `createCertificationRequest`.
 *
 * @module build/build-csr
 */

import { encodeImplicit, encodeInteger, encodeSequence, encodeSetOf } from '../asn1/asn1-encode.js';
import { assertBytes } from '../core/bytes.js';
import type { CertificationRequestDescription } from '../types/build-types.js';
import type { Signer } from '../types/crypto-types.js';
import type { CreateOptions } from './build-certificate.js';
import { signAndWrap } from './build-certificate.js';
import { encodeAttribute, encodeDistinguishedName, encodeExtensions } from './build-structures.js';

/** PKCS#9 `extensionRequest` — how a CSR asks for extensions (RFC 2985 §5.4.2). */
const EXTENSION_REQUEST = '1.2.840.113549.1.9.14';

/**
 * Build and sign a PKCS#10 certification request.
 *
 * ```ts
 * import { createCertificationRequest } from 'pkinative';
 *
 * const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
 * const csr = await createCertificationRequest(
 *     { subject: [[{ type: '2.5.4.3', value: 'host.example' }]], subjectPublicKey: spki },
 *     { key: privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
 * );
 * ```
 *
 * The `attributes` field is always present, as RFC 2986 requires — it is
 * `[0] IMPLICIT SET OF`, and an empty SET is not the same as an absent
 * field. Extensions, when given, travel inside the single
 * `extensionRequest` attribute; a CA is free to ignore every one of them,
 * which is why the same extensions still have to be placed by
 * `createCertificate` when the certificate is issued.
 *
 * @param description What the request asks for.
 * @param signer      The key that signs it — the private half of `subjectPublicKey` — as a
 *   `SigningKey` for Web Crypto, or an `ExternalSigner` for a key held elsewhere.
 * @param options     See {@link CreateOptions}.
 * @returns The complete `CertificationRequest`, in DER.
 * @throws {PkiError} `PKI_API_MISUSE` for a duplicated extension, or an `ExternalSigner` that returns other than what `crypto.subtle.sign` would;`PKI_INVALID_INPUT` for a malformed name or a non-`Uint8Array` where DER is expected.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the runtime cannot sign; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` for an algorithm with no RFC 5280 OID; `PKI_CRYPTO_KEY_UNSUPPORTED` when the host refuses the key.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxNameAttributes` or `maxExtensions`.
 */
export async function createCertificationRequest(
    description: CertificationRequestDescription,
    signer: Signer,
    options?: CreateOptions,
): Promise<Uint8Array> {
    const limits = options?.limits === undefined ? undefined : { limits: options.limits };
    const subject = description.subjectDer !== undefined
        ? assertBytes(description.subjectDer, 'subjectDer')
        : encodeDistinguishedName(description.subject, limits);

    const extensions = description.extensions ?? [];
    const attributes = extensions.length === 0
        ? []
        : [encodeAttribute(EXTENSION_REQUEST, [encodeExtensions(extensions, limits)])];

    const info = encodeSequence([
        // version is 0 for a PKCS#10 v1 request, and unlike the certificate's
        // it is not DEFAULT: it is written even when it is zero.
        encodeInteger(0),
        subject,
        assertBytes(description.subjectPublicKey, 'subjectPublicKey'),
        // `attributes [0] IMPLICIT SET OF Attribute` — RFC 2986's module is
        // IMPLICIT TAGS, so [0] *replaces* the SET's tag rather than wrapping
        // it: the content is the sorted attribute encodings directly, and the
        // constructed bit comes from the SET the tag replaced. The field is
        // present even when empty, because an empty SET is not an absent one.
        encodeImplicit(0, encodeSetOf(attributes)),
    ]);

    return signAndWrap(info, signer);
}
