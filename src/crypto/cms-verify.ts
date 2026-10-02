/**
 * pkinative — CMS signer signature verification
 * =============================================
 * Does the signer certificate's key actually sign what this `SignerInfo`
 * covers?
 *
 * The primitive under `verifySignedData`, as `verifyOcspSignature` is the
 * primitive under revocation checking. Like the rest of the `crypto` layer it
 * consumes parsed data and parses nothing: the bytes the signature covers are
 * already on the `SignerInfo` as `signedAttributesDer`, with the `0x31` tag
 * RFC 5652 §5.4 signs under rather than the `[0]` tag it is transmitted
 * under. Nothing here re-tags or re-encodes, because every re-derivation of
 * signed bytes is a chance to derive different ones.
 *
 * @module crypto/cms-verify
 */

import { PkiCryptoError, PkiError } from '../types/pki-errors.js';
import type { SignerInfo } from '../types/cms-types.js';
import type { Certificate } from '../types/x509-types.js';
import { _cmsAlgorithmProblem, _importRefusal, coordinateBytes, resolveCmsAlgorithm } from './crypto-algorithms.js';
import { ecdsaDerToRaw } from './crypto-signature.js';
import { importPublicKey, verifySignature } from './webcrypto.js';
import { isBytes } from '../core/bytes.js';

/** Options of {@link verifySignerInfoSignature}. */
export interface VerifySignerInfoSignatureOptions {
    /**
     * The content octets, for a signer **without** signed attributes: such a
     * signer signs the content itself (RFC 5652 §5.4), so nothing else can be
     * checked. Ignored when the signer has signed attributes — those are what
     * the signature covers, and the content is bound to them through
     * `messageDigest`, which this function does not read.
     */
    readonly content?: Uint8Array | undefined;
    /**
     * Treat a SHA-1 signature as evidence. Default **`false`**, and it throws
     * `PKI_CRYPTO_ALGORITHM_REFUSED` rather than returning a boolean — the same
     * policy, for the same reason, as `verifyCertificateSignature`.
     */
    readonly allowSha1?: boolean | undefined;
}

/**
 * Verify that `signer`'s public key signed what `signerInfo` covers — its
 * signed attributes when it has them, the content otherwise.
 *
 * Returns a boolean; it throws only when the question could not be put. A
 * tampered signature, an unusable ECDSA encoding, a key that cannot carry the
 * algorithm, and a `digestAlgorithm` that contradicts the signature algorithm
 * (`ecdsa-with-SHA384` over a SHA-256 digest, MD5 anywhere) are all `false`:
 * an inconsistent SignerInfo does not stand up, and `verifySignedData` names
 * the precise reason by asking the same question.
 *
 * ```ts
 * import { parseCertificate, parseSignedData, verifySignerInfoSignature } from 'pkinative';
 *
 * const signer = parseCertificate(signerDer);
 * for (const signerInfo of parseSignedData(p7s).signerInfos) {
 *     if (!await verifySignerInfoSignature(signerInfo, signer)) return 'not signed by that key';
 * }
 * ```
 *
 * **A `true` here says only that the key signed the bytes.** It does not say
 * that `signer` is the certificate the SignerInfo names — nothing here reads
 * `sid` or the signing-certificate attribute. It does not say the content is
 * the content that was signed — nothing here computes a digest or reads
 * `messageDigest`, so a signer with signed attributes verifies whatever
 * content travels with it. And it does not say the certificate is trusted,
 * current or entitled to sign. `verifySignedData` makes those judgements;
 * treating this boolean as a verdict on a message is how a valid signature
 * over someone else's attributes gets believed.
 *
 * @param signerInfo One entry of a parsed `SignedData`'s `signerInfos`.
 * @param signer The certificate whose key is alleged to have signed.
 * @param options See {@link VerifySignerInfoSignatureOptions}.
 * @returns Whether the signer's key signed `signerInfo.signedAttributesDer`,
 *   or `options.content` when the signer has no signed attributes.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either argument is not parsed;
 *   `PKI_API_MISUSE` when the signer has no signed attributes and no
 *   `content` was given.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the runtime has no
 *   Web Crypto; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` for an algorithm Web Crypto
 *   does not run (DSA, Ed448, SHA-224, an unknown OID);
 *   `PKI_CRYPTO_ALGORITHM_REFUSED` for SHA-1 without `allowSha1`;
 *   `PKI_CRYPTO_KEY_UNSUPPORTED` when the host refuses to import the key —
 *   always for a signer certificate whose key is `id-RSASSA-PSS`, which the
 *   W3C Web Crypto specification does not import (see
 *   `verifyCertificateSignature`). Such a key signing with PKCS#1
 *   v1.5, or under RSASSA-PSS parameters its own exclude, is `false`
 *   (RFC 4055 §1.2 and §3.3, RFC 4056 §3).
 * @throws {PkiEncodingError} When the signature algorithm's parameters are
 *   malformed DER.
 */
export async function verifySignerInfoSignature(
    signerInfo: SignerInfo,
    signer: Certificate,
    options?: VerifySignerInfoSignatureOptions,
): Promise<boolean> {
    const info = assertSignerInfo(signerInfo);
    const certificate = assertCertificate(signer);

    const covered = info.signedAttributesDer ?? options?.content;
    if (covered === undefined) {
        throw new PkiError('PKI_API_MISUSE',
            'pkinative: this signer has no signed attributes, so its signature is over the content itself — pass { content } with the eContent or the detached content');
    }

    // Before resolution, so an inconsistent pair is a `false` even when one
    // half would also be refused: MD5 is a verdict on the signer, not a gap in
    // what this runtime can check.
    if (_cmsAlgorithmProblem(info.digestAlgorithm, info.signatureAlgorithm) !== null) return false;

    const resolved = resolveCmsAlgorithm(info.digestAlgorithm, info.signatureAlgorithm, certificate.subjectPublicKeyInfo);
    if (resolved === null) return false;

    if (resolved.hash === 'SHA-1' && options?.allowSha1 !== true) {
        throw new PkiCryptoError('PKI_CRYPTO_ALGORITHM_REFUSED',
            'pkinative: this signer signed over SHA-1, whose collisions have been practical since 2017, so verifying it would assert something it cannot show — have it re-signed under SHA-256, or pass { allowSha1: true } to examine a historical artefact rather than rely on it',
            info.signatureAlgorithm.oid);
    }

    let signature = info.signature;
    if (resolved.curve !== undefined) {
        const raw = ecdsaDerToRaw(signature, coordinateBytes(resolved.curve));
        if (raw === null) return false;
        signature = raw;
    }

    const key = await importPublicKey(certificate.subjectPublicKeyInfo.der, resolved.importParams, info.signatureAlgorithm.oid, _importRefusal(certificate.subjectPublicKeyInfo));
    return verifySignature(key, resolved.verifyParams, signature, covered);
}

function assertSignerInfo(value: unknown): SignerInfo {
    const candidate = value as Partial<SignerInfo> | null;
    if (typeof value !== 'object' || candidate === null
        || !isBytes(candidate.signature)
        || typeof candidate.digestAlgorithm !== 'object' || candidate.digestAlgorithm === null
        || typeof candidate.signatureAlgorithm !== 'object' || candidate.signatureAlgorithm === null) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: signerInfo must be an entry of parseSignedData().signerInfos — pass the parsed value, not its DER');
    }
    return value as SignerInfo;
}

function assertCertificate(value: unknown): Certificate {
    const candidate = value as Partial<Certificate> | null;
    if (typeof value !== 'object' || candidate === null
        || typeof candidate.subjectPublicKeyInfo !== 'object' || candidate.subjectPublicKeyInfo === null
        || !isBytes(candidate.subjectPublicKeyInfo.der)) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: signer must be a certificate from parseCertificate — pass the parsed value, not its DER');
    }
    return value as Certificate;
}
