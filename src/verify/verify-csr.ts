/**
 * pkinative — the verdict on a certification request
 * ==================================================
 * Did the requester prove possession of the key it asks to have certified?
 *
 * A PKCS#10 request (RFC 2986) is signed with the private half of the very
 * key it carries, so the question has one answer and needs no trust anchor:
 * the signature over `certificationRequestInfo` either verifies under
 * `subjectPKInfo` or it does not. RFC 2986 §4.2 adds the one consistency
 * check a verifier owes — the signature algorithm must be one that key can
 * produce — and that is the whole of it. Nothing here says the subject is
 * entitled to the name it asks for, or that the requested extensions should
 * be granted: those are the CA's decisions, and a CA that took a verified
 * request for an approved one has skipped its own job.
 *
 * Like every report in `verify/`, this one **resolves**: a request that does
 * not parse is `PKI_REASON_INPUT_MALFORMED`, a false signature is
 * `PKI_REASON_SIGNATURE_INVALID`, and a host that cannot put the question —
 * no Web Crypto, an algorithm or key it will not import, SHA-1 — is
 * `PKI_REASON_SIGNATURE_NOT_CHECKED`, which is not a synonym for invalid.
 *
 * @module verify/verify-csr
 */

import { isBytes } from '../core/bytes.js';
import { _pkiError } from '../core/pki-error-guard.js';
import { inputMalformedReason, signatureInvalidReason, signatureNotCheckedReason } from '../core/pki-reasons.js';
import { resolveAlgorithm } from '../crypto/crypto-algorithms.js';
import { verifyCertificateSignature } from '../crypto/x509-verify.js';
import { PkiCryptoError, PkiError } from '../types/pki-errors.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate, CertificationRequest, ParseCertificateOptions } from '../types/x509-types.js';
import { parseCertificationRequest } from '../x509/x509-csr.js';

/** Options of {@link verifyCertificationRequest}: how to read the request, and whether SHA-1 counts. */
export interface VerifyCertificationRequestOptions extends ParseCertificateOptions {
    /**
     * Treat a SHA-1 signature as evidence. Default `false`, in which case it is
     * reported as `PKI_REASON_SIGNATURE_NOT_CHECKED` rather than believed — a
     * chosen-prefix collision has been practical since 2017, so such a
     * signature does not bind the bytes it covers.
     */
    readonly allowSha1?: boolean | undefined;
}

/** The verdict on a certification request, and the request it was about. */
export interface VerifyCertificationRequestReport {
    /** Whether the request's signature verifies under the key the request carries. */
    readonly valid: boolean;
    /** Every reason it does not; empty when `valid`. */
    readonly reasons: readonly PkiReason[];
    /** The request, parsed; `undefined` when the bytes could not be read as one. */
    readonly request: CertificationRequest | undefined;
    /** How many signature verifications this cost: one, or none when the question could not be put. */
    readonly signatureVerifications: number;
}

/** Where every reason about the signature is rooted. */
const PATH = 'certificationRequest';

/**
 * Verify a PKCS#10 certification request: the proof of possession, checked
 * with the key inside the request.
 *
 * ```ts
 * import { verifyCertificationRequest } from 'pkinative';
 *
 * const report = await verifyCertificationRequest(csrDer);
 * if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
 * else console.log('possession proved for', formatDistinguishedName(report.request.subject));
 * ```
 *
 * **It never throws for a verification issue or for malformed input**: bytes
 * that are not a request are `PKI_REASON_INPUT_MALFORMED`, carrying in
 * `errorCode` the `PkiErrorCode` that would have been thrown. A signature
 * algorithm the request's own key cannot produce (RFC 2986 §4.2 — an ECDSA
 * algorithm over an RSA key, PKCS#1 v1.5 under an RSASSA-PSS key) is
 * `PKI_REASON_SIGNATURE_INVALID` at `certificationRequest.signatureAlgorithm`;
 * a signature the key does not verify is the same reason at
 * `certificationRequest.signature`. A `valid` report says the requester holds
 * the key — and nothing about whether a CA should certify it.
 *
 * @param request The request, as the DER bytes or as `parseCertificationRequest` returned it.
 * @param options See {@link VerifyCertificationRequestOptions}; the reading options apply when `request` is DER.
 * @returns The verdict, every reason behind it and the parsed request.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `request` is neither bytes nor a parsed request;
 *   `PKI_INVALID_OPTION` or `PKI_LIMIT_INVALID` for a malformed option.
 */
export async function verifyCertificationRequest(
    request: CertificationRequest | Uint8Array,
    options?: VerifyCertificationRequestOptions,
): Promise<VerifyCertificationRequestReport> {
    if (options !== undefined && (typeof options !== 'object' || options === null)) {
        throw new PkiError('PKI_INVALID_OPTION', 'pkinative: options must be an object — pass { allowSha1, encodingRules, limits, strict, onDiagnostic, decodeExtensions } or omit it');
    }
    const { allowSha1, ...reading } = options ?? {};
    let parsed: CertificationRequest;
    if (isBytes(request)) {
        try {
            // The request's profile concerns are on `request.diagnostics` for a
            // caller who wants them; a verdict does not print them.
            parsed = parseCertificationRequest(request, { ...reading, onDiagnostic: reading.onDiagnostic ?? ((): undefined => undefined) });
        } catch (error) {
            // Misuse is thrown before anything is read: an option the reader
            // refuses is the caller's, not the request's.
            const refused = _pkiError(error);
            if (refused.code === 'PKI_INVALID_OPTION' || refused.code === 'PKI_LIMIT_INVALID') throw refused;
            return { valid: false, reasons: [inputMalformedReason(refused.code, refused.message, PATH)], request: undefined, signatureVerifications: 0 };
        }
    } else {
        parsed = _assertRequest(request);
    }

    // RFC 2986 §4.2: the algorithm must be one the request's own key can have
    // signed under. `null` is that decided "no", and it is the verdict —
    // asking Web Crypto afterwards could only restate it.
    let compatible: boolean;
    try {
        compatible = resolveAlgorithm(parsed.signatureAlgorithm, parsed.subjectPublicKeyInfo) !== null;
    } catch (error) {
        return { valid: false, reasons: [_couldNotAsk(_pkiError(error), `${PATH}.signatureAlgorithm`)], request: parsed, signatureVerifications: 0 };
    }
    if (!compatible) {
        return { valid: false, reasons: [signatureInvalidReason(`${PATH}.signatureAlgorithm`)], request: parsed, signatureVerifications: 0 };
    }

    // The request is its own signer: `verifyCertificateSignature` reads of its
    // first argument the signed bytes, the algorithm and the signature, and of
    // its second the public key — the signed-structure shape a certificate, a
    // CRL and a request share, and the shape its own guard checks. A request
    // names its algorithm once, so the inner-field match is simply not asked.
    const signed = parsed as unknown as Certificate;
    let verified: boolean;
    try {
        verified = await verifyCertificateSignature(signed, signed, { allowSha1: allowSha1 === true });
    } catch (error) {
        return { valid: false, reasons: [_couldNotAsk(_pkiError(error), `${PATH}.signature`)], request: parsed, signatureVerifications: 0 };
    }
    const reasons: PkiReason[] = verified ? [] : [signatureInvalidReason(`${PATH}.signature`)];
    return { valid: reasons.length === 0, reasons, request: parsed, signatureVerifications: 1 };
}

/**
 * The reason for a question the host could not put. A `PkiCryptoError` says
 * nothing about the signature and is `not-checked`; any other `PkiError` from
 * the resolution — malformed algorithm parameters, which `parseCertificationRequest`
 * leaves undecoded — is a fact about the bytes.
 */
function _couldNotAsk(refused: PkiError, path: string): PkiReason {
    return refused instanceof PkiCryptoError
        ? signatureNotCheckedReason(path, refused.code, refused.message)
        : inputMalformedReason(refused.code, refused.message, path);
}

/**
 * Refuse, before anything is read, what is neither bytes nor a request
 * `parseCertificationRequest` made — the one thing this report throws for.
 */
function _assertRequest(value: unknown): CertificationRequest {
    const candidate = value as Partial<CertificationRequest> | null;
    if (typeof value !== 'object' || candidate === null
        || !isBytes(candidate.tbsDer)
        || typeof candidate.signatureAlgorithm !== 'object' || candidate.signatureAlgorithm === null
        || typeof candidate.signatureValue !== 'object' || candidate.signatureValue === null
        || typeof candidate.subjectPublicKeyInfo !== 'object' || candidate.subjectPublicKeyInfo === null) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: request must be the DER of a certification request, or the value parseCertificationRequest returned for it');
    }
    return value as CertificationRequest;
}
