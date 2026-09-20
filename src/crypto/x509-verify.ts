/**
 * pkinative — certificate signature verification
 * ==============================================
 * Does the issuer's key actually sign this certificate's `tbsCertificate`?
 *
 * Notice what this module does **not** import: nothing from `src/x509/`.
 * Everything it needs is already on the parsed structure as data —
 * `tbsDer`, `signatureAlgorithm`, `signatureValue`, and the issuer's
 * `subjectPublicKeyInfo.der`. That is the invariant of the `crypto` layer,
 * stated in AGENTS.md §Architecture and proved on the built artefact by
 * `verify-bundle.ts`: **the verifier consumes parsed data, it does not
 * parse.** A caller who only verifies ships no certificate parser.
 *
 * ## What a `true` here does and does not mean
 *
 * It means: the bytes of `certificate.tbsDer` were signed by the private
 * key matching `issuer.subjectPublicKeyInfo`. That is one link.
 *
 * It does not mean the certificate is valid, trusted, unexpired or
 * unrevoked, and it does not mean `issuer` was entitled to sign it —
 * nothing here reads `basicConstraints`, `keyUsage`, the validity window,
 * or a name. Those are RFC 5280 §6, and they arrive in 0.5. Until then,
 * **verifying a signature is not validating a chain**, and a caller that
 * treats it as one has built an authentication bypass.
 *
 * @module crypto/x509-verify
 */

import { bytesEqual } from '../core/bytes.js';
import { PkiError } from '../types/pki-errors.js';
import type { Certificate } from '../types/x509-types.js';
import { coordinateBytes, resolveAlgorithm } from './crypto-algorithms.js';
import { ecdsaDerToRaw } from './crypto-signature.js';
import { importPublicKey, verifySignature } from './webcrypto.js';

/** Options of {@link verifyCertificateSignature}. */
export interface VerifyCertificateSignatureOptions {
    /**
     * Check that the outer `signatureAlgorithm` equals the inner
     * `tbsCertificate.signature`, as RFC 5280 §4.1.1.2 requires. Default
     * `true`.
     *
     * The two fields are separate encodings of the same algorithm, and only
     * the inner one is signed. A certificate where they disagree is one
     * where an attacker may have rewritten the outer field, so the answer is
     * `false` rather than an error: the signature does not stand up.
     * Setting this to `false` is for a tool that wants to see the mismatch
     * and report it, never for one that wants to accept it.
     */
    readonly requireAlgorithmMatch?: boolean | undefined;
}

/**
 * Verify that `issuer`'s public key signed `certificate`.
 *
 * Returns a boolean; it throws only when the question could not be put —
 * no Web Crypto on this runtime, an algorithm pkinative does not map, a key
 * the host will not import. A malformed signature, an unusable ECDSA
 * encoding and a mismatched algorithm field are all `false`, because they
 * mean the signature does not stand up and failing closed is the safe
 * reading of each.
 *
 * ```ts
 * import { decodePem, parseCertificate, verifyCertificateSignature } from 'pkinative';
 *
 * const [leaf, ca] = decodePem(bundle, { label: 'CERTIFICATE' })
 *     .map((block) => parseCertificate(block.bytes));
 * const signed = await verifyCertificateSignature(leaf, ca);
 * ```
 *
 * @param certificate The certificate whose signature is in question.
 * @param issuer The certificate holding the public key that should have
 *   signed it. Pass `certificate` itself to test a self-signature.
 * @param options See {@link VerifyCertificateSignatureOptions}.
 * @returns Whether the issuer's key signed this certificate's `tbsCertificate`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either argument is not a
 *   parsed certificate.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the runtime has no
 *   Web Crypto; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the signature
 *   algorithm is outside the supported set; `PKI_CRYPTO_KEY_UNSUPPORTED`
 *   when the issuer's key cannot carry this signature or the host refuses
 *   to import it.
 * @throws {PkiEncodingError} When the signature algorithm's parameters are
 *   malformed DER — `parseCertificate` leaves them undecoded, so this is
 *   the first reader to look inside them.
 */
export async function verifyCertificateSignature(
    certificate: Certificate,
    issuer: Certificate,
    options?: VerifyCertificateSignatureOptions,
): Promise<boolean> {
    const subject = assertCertificate(certificate, 'certificate');
    const signer = assertCertificate(issuer, 'issuer');

    // Only tbsCertificate.signature is covered by the signature; the outer
    // field is not. RFC 5280 §4.1.1.2 requires them equal, and comparing
    // the encodings — not the OIDs — also catches parameters that differ.
    if (options?.requireAlgorithmMatch !== false
        && !bytesEqual(subject.signatureAlgorithm.der, subject.tbsSignatureAlgorithm.der)) {
        return false;
    }

    // The unused-bits count of a signature BIT STRING is always zero: a
    // signature is a whole number of octets. Anything else is a rewritten
    // certificate, not a short signature.
    if (subject.signatureValue.unusedBits !== 0) return false;

    // null is a decided "no": this key cannot have produced this kind of
    // signature. Path building in 0.5 walks candidate issuers, so that
    // answer must be a value and not an exception.
    const resolved = resolveAlgorithm(subject.signatureAlgorithm, signer.subjectPublicKeyInfo);
    if (resolved === null) return false;

    let signature = subject.signatureValue.bytes;
    if (resolved.curve !== undefined) {
        const raw = ecdsaDerToRaw(signature, coordinateBytes(resolved.curve));
        if (raw === null) return false;
        signature = raw;
    }

    const key = await importPublicKey(signer.subjectPublicKeyInfo.der, resolved.importParams, subject.signatureAlgorithm.oid);
    return verifySignature(key, resolved.verifyParams, signature, subject.tbsDer);
}

/**
 * Verify that a certificate signed itself — the definition of a root, and
 * the check a trust store's contents deserve before they are trusted.
 *
 * A `true` here says the key in the certificate signed the certificate. It
 * says nothing about whether *you* should trust it: self-signature is what
 * every attacker's root also has.
 *
 * @param certificate The certificate to test.
 * @param options See {@link VerifyCertificateSignatureOptions}.
 * @returns Whether the certificate's own key signed it, and its subject and
 *   issuer names are byte-identical.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the argument is not a parsed certificate.
 * @throws {PkiCryptoError} As {@link verifyCertificateSignature}.
 */
export async function verifySelfSignature(certificate: Certificate, options?: VerifyCertificateSignatureOptions): Promise<boolean> {
    const self = assertCertificate(certificate, 'certificate');
    if (!bytesEqual(self.subject.der, self.issuer.der)) return false;
    return verifyCertificateSignature(self, self, options);
}

function assertCertificate(value: unknown, what: string): Certificate {
    const candidate = value as Partial<Certificate> | null;
    if (typeof value !== 'object' || candidate === null
        || !(candidate.tbsDer instanceof Uint8Array)
        || typeof candidate.signatureAlgorithm !== 'object' || candidate.signatureAlgorithm === null
        || typeof candidate.subjectPublicKeyInfo !== 'object' || candidate.subjectPublicKeyInfo === null) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} must be a certificate from parseCertificate — pass the parsed value, not its DER`);
    }
    return value as Certificate;
}
