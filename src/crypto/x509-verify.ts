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

import { bytesEqual, isBytes } from '../core/bytes.js';
import { PkiCryptoError, PkiError } from '../types/pki-errors.js';
import type { CertificateList } from '../types/crl-types.js';
import type { OcspBasicResponse } from '../types/ocsp-types.js';
import type { Certificate } from '../types/x509-types.js';
import { _importableSpki, coordinateBytes, resolveAlgorithm } from './crypto-algorithms.js';
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
    /**
     * Treat a SHA-1 signature as evidence. Default **`false`**, and it throws
     * `PKI_CRYPTO_ALGORITHM_REFUSED` rather than returning a boolean.
     *
     * Web Crypto will compute SHA-1 quite happily, which is the problem: a
     * chosen-prefix collision has been practical since 2017 (SHAttered), so a
     * SHA-1 signature does not bind the bytes it covers, and a `true` here would
     * be a false assurance rather than a verdict. `false` would be wrong too —
     * the signature may well be arithmetically correct — so the honest answer is
     * *"this question cannot be put"*, which is what the `PkiCryptoError` family
     * means. The path validator turns it into
     * `PKI_REASON_SIGNATURE_NOT_CHECKED`, so a chain signed over SHA-1 is
     * refused with a reason a reader can act on.
     *
     * Turn it on to examine a historical artefact, never to authenticate with
     * one. A certificate's SHA-1 **fingerprint** is a different thing and is
     * unaffected: that is a digest of public data, not a signature.
     */
    readonly allowSha1?: boolean | undefined;
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
 * **RSASSA-PSS keys.** An issuer key certified under `id-RSASSA-PSS`
 * (RFC 4055) is held to what it was certified for: a PKCS#1 v1.5 signature
 * under it is `false` (§1.2), and so is a PSS signature whose hash differs
 * from the key's parameters or whose salt is shorter (§3.3). A signature that
 * passes those checks is verified: the W3C Web Crypto specification imports
 * an RSA key only under `rsaEncryption`, so the same key bits are handed to
 * the host under that identifier — RFC 4055 §1.2 says the key *is* that RSA
 * key, restricted — with the hash the key's parameters name, or the
 * signature's when the key has none. Certificates, CRLs, OCSP responses and
 * CMS signed by such a key (what `openssl genpkey -algorithm RSA-PSS`, GnuTLS
 * `certtool --key-type=rsa-pss` and `keytool -keyalg RSASSA-PSS` produce)
 * therefore verify on every runtime, as a `rsaEncryption` key signing with
 * RSASSA-PSS — what CAs issuing PSS certificates generally use — always did.
 *
 * **ECDSA signatures are malleable.** `(r, s)` and `(r, n − s)` are both
 * valid for the same message — nothing in the X.509 profiles requires a low
 * `s`, and Web Crypto accepts both — so a third party can turn one
 * ECDSA-signed certificate into a second, byte-different one that verifies
 * just the same. Its DER, and so its fingerprint, is not unique to its
 * `tbsCertificate`: identify an ECDSA-signed certificate by what it signs
 * (`tbsDer`, or issuer and serial), not by its fingerprint, where the
 * difference matters.
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
    return verifySignedStructure(subject, signer, resolveOptions(options));
}

/**
 * Everything both a certificate and a CRL have in common, which is everything
 * this module needs.
 *
 * A `Certificate` and a `CertificateList` are the same *signed structure*:
 * covered bytes, the algorithm named inside them, the algorithm named outside
 * them, and a signature. Writing that shape down once means a CRL cannot end
 * up with a laxer signature check than a certificate — which is how a
 * revocation list gets accepted from someone who did not issue it.
 */
interface SignedStructure {
    readonly tbsDer: Uint8Array;
    readonly signatureAlgorithm: { readonly der: Uint8Array; readonly oid: string; readonly parameters: unknown };
    /**
     * The algorithm named *inside* the covered bytes, where the structure has
     * one. A certificate and a CRL do; an OCSP response does not — RFC 6960
     * §4.2.1 names the algorithm once, outside `tbsResponseData` — so this is
     * optional rather than faked, and the match check is simply skipped where
     * there is nothing to match against.
     */
    readonly tbsSignatureAlgorithm?: { readonly der: Uint8Array } | undefined;
    readonly signatureValue: { readonly bytes: Uint8Array; readonly unusedBits: number };
}

/** The options with their defaults applied, once, so every entry point agrees. */
function resolveOptions(options: VerifyCertificateSignatureOptions | undefined): { requireAlgorithmMatch: boolean; allowSha1: boolean } {
    return { requireAlgorithmMatch: options?.requireAlgorithmMatch !== false, allowSha1: options?.allowSha1 === true };
}

async function verifySignedStructure(
    signed: SignedStructure,
    signer: Certificate,
    options: { readonly requireAlgorithmMatch: boolean; readonly allowSha1: boolean },
): Promise<boolean> {
    // Only the inner `signature` field is covered by the signature; the outer
    // one is not. RFC 5280 §4.1.1.2 and §5.1.1.2 require them equal, and
    // comparing the encodings — not the OIDs — also catches parameters that
    // differ.
    const inner = signed.tbsSignatureAlgorithm;
    if (options.requireAlgorithmMatch && inner !== undefined && !bytesEqual(signed.signatureAlgorithm.der, inner.der)) {
        return false;
    }

    // The unused-bits count of a signature BIT STRING is always zero: a
    // signature is a whole number of octets. Anything else is a rewritten
    // structure, not a short signature.
    if (signed.signatureValue.unusedBits !== 0) return false;

    // null is a decided "no": this key cannot have produced this kind of
    // signature. Path building walks candidate issuers, so that answer must
    // be a value and not an exception.
    const resolved = resolveAlgorithm(signed.signatureAlgorithm as Parameters<typeof resolveAlgorithm>[0], signer.subjectPublicKeyInfo);
    if (resolved === null) return false;

    // SHA-1 throws rather than returning either boolean, because neither is
    // true: the arithmetic may well check out, and it still proves nothing about
    // the bytes. "This question cannot be put" is what PkiCryptoError means, and
    // it is the only honest third answer.
    if (resolved.hash === 'SHA-1' && !options.allowSha1) {
        throw new PkiCryptoError('PKI_CRYPTO_ALGORITHM_REFUSED',
            'pkinative: this signature is over SHA-1, whose collisions have been practical since 2017, so verifying it would assert something it cannot show — get the certificate reissued under SHA-256, or pass { allowSha1: true } to examine a historical artefact rather than rely on it',
            signed.signatureAlgorithm.oid);
    }

    let signature = signed.signatureValue.bytes;
    if (resolved.curve !== undefined) {
        const raw = ecdsaDerToRaw(signature, coordinateBytes(resolved.curve));
        if (raw === null) return false;
        signature = raw;
    }

    const key = await importPublicKey(_importableSpki(signer.subjectPublicKeyInfo), resolved.importParams, signed.signatureAlgorithm.oid);
    return verifySignature(key, resolved.verifyParams, signature, signed.tbsDer);
}

/**
 * Verify that a CA's key signed this revocation list.
 *
 * ```ts
 * const crl = parseCertificateList(der);
 * if (!await verifyCrlSignature(crl, caCertificate)) return 'this list is not from that CA';
 * ```
 *
 * **A `true` here says only that the key signed the bytes.** It does not say
 * the CA was entitled to publish this list, that the list is current, or that
 * it covers the certificate you are asking about — nothing here reads
 * `thisUpdate`, `nextUpdate`, the issuer name or `keyUsage`. `checkRevocation`
 * makes those judgements and reports them; treating this boolean as a
 * revocation answer is how an expired list from the wrong CA gets believed.
 *
 * @param crl    A parsed `CertificateList`.
 * @param issuer The certificate whose key is alleged to have signed it.
 * @param options See {@link VerifyCertificateSignatureOptions}.
 * @returns Whether the issuer's key signed `crl.tbsDer`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either argument is not parsed.
 * @throws {PkiCryptoError} As {@link verifyCertificateSignature}.
 */
export async function verifyCrlSignature(
    crl: CertificateList,
    issuer: Certificate,
    options?: VerifyCertificateSignatureOptions,
): Promise<boolean> {
    if (typeof crl !== 'object' || crl === null || !isBytes(crl.tbsDer)) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: crl must be a CertificateList from parseCertificateList(), not raw bytes');
    }
    const signer = assertCertificate(issuer, 'issuer');
    return verifySignedStructure(crl, signer, resolveOptions(options));
}

/**
 * Verify that a responder's key signed this OCSP response.
 *
 * ```ts
 * const response = parseOcspResponse(bytes);
 * const basic = response.basicResponse;
 * if (basic === undefined) return `the responder declined: ${response.status}`;
 * if (!await verifyOcspSignature(basic, responderCertificate)) return 'not from that responder';
 * ```
 *
 * **Which certificate is `responder`, is the question this function does not
 * answer.** RFC 6960 §4.2.2.2 gives three ways a response may be authorised:
 * the CA signed it itself, a responder the CA delegated to signed it, or the
 * client trusts the responder out of band. `basicResponse.certificates` are
 * certificates the responder *attached* — trusting them because they arrived
 * would let the responder nominate its own authority, which is the whole point
 * of that clause. Choosing the responder certificate, and checking that it is
 * entitled to answer for this CA, is the caller's decision.
 *
 * @param basicResponse The `basicResponse` of a successful `OcspResponse`.
 * @param responder     The certificate whose key is alleged to have signed it.
 * @returns Whether the responder's key signed `basicResponse.tbsDer`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either argument is not parsed.
 * @throws {PkiCryptoError} As {@link verifyCertificateSignature}.
 */
export async function verifyOcspSignature(basicResponse: OcspBasicResponse, responder: Certificate): Promise<boolean> {
    if (typeof basicResponse !== 'object' || basicResponse === null || !isBytes(basicResponse.tbsDer)) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: basicResponse must come from parseOcspResponse(), not raw bytes — and a response whose status is not successful has none');
    }
    const signer = assertCertificate(responder, 'responder');
    // No algorithm-match check: RFC 6960 names the algorithm once, so there is
    // no second field that could disagree with it. SHA-1 is refused here with no
    // opt-in at all: a revocation answer is a live authentication decision, and
    // there is no archival reading of one to make room for.
    return verifySignedStructure(basicResponse, signer, { requireAlgorithmMatch: false, allowSha1: false });
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
        || !isBytes(candidate.tbsDer)
        || typeof candidate.signatureAlgorithm !== 'object' || candidate.signatureAlgorithm === null
        || typeof candidate.subjectPublicKeyInfo !== 'object' || candidate.subjectPublicKeyInfo === null) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} must be a certificate from parseCertificate — pass the parsed value, not its DER`);
    }
    return value as Certificate;
}
