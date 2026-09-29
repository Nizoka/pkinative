/**
 * pkinative — a CMS signed message, judged the whole way
 * ======================================================
 * One call for the question a PDF validator, an S/MIME client and a
 * code-signing check all ask: *is this signed message what its signers signed,
 * and do I trust who they are?*
 *
 * For each signer, in the order that keeps each answer honest: its attributes
 * (they are what bind a signature to a content, a content type, a certificate
 * and its algorithms), its algorithms, the digest of the content — computed
 * here, never taken from the signer — the signature, the certificate it
 * committed to, any RFC 3161 timestamp over the signature, and finally that
 * certificate's chain, judged by `verifyCertificateChain`.
 *
 * **Trust is not optional.** `trustAnchors` is required, as it is for a chain:
 * an empty list is accepted and yields `PKI_REASON_NO_TRUST_ANCHOR`. A verifier
 * that called a message valid without knowing whom its signer answers to would
 * make "anyone with a key" the default signer. A caller who only wants to know
 * whether the message was altered reads each signer's `intact`.
 *
 * It never throws for a verification issue, and never for bad input: a message
 * that cannot be read is `PKI_REASON_INPUT_MALFORMED`. It throws only for API
 * misuse — content given twice, or given for a message that carries its own.
 *
 * @module verify/verify-signed-data
 */

import { parseSignedData } from '../cms/cms-signed-data.js';
import { cmsNoSignersReason, inputMalformedReason } from '../core/pki-reasons.js';
import type { PkiTime } from '../types/asn1-types.js';
import type { SignedData } from '../types/cms-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { EncodingRules, PkiLimits } from '../types/pki-types.js';
import type { Certificate } from '../types/x509-types.js';
import { _assertArguments, _assertCertificates, _pkiError, verifyCertificateChain, type VerifyCertificateChainReport } from './verify-chain.js';
import { _under, _verifySigner } from './verify-signer.js';
import { _parseBag, verifyTimeStampToken, type VerifyTimeStampTokenReport } from './verify-timestamp.js';

/** What to verify a signed message against. */
export interface VerifySignedDataInput {
    /** The DER `ContentInfo`: a `.p7s` or `.p7m` file, or a PDF signature's `/Contents`. */
    readonly signedData: Uint8Array;
    /**
     * The content, when it is detached — as it is for a PDF signature and most
     * S/MIME. Absent content is never treated as empty content.
     */
    readonly content?: Uint8Array | undefined;
    /**
     * The detached content's digest, instead of the content — the PDF case,
     * where the caller hashes the `/ByteRange` and never holds it whole. Used
     * for every signer with signed attributes; a signer without them signed the
     * content itself, and is reported as not checked.
     */
    readonly contentDigest?: Uint8Array | undefined;
    /** Certificates to look for the signers and their issuers among, beyond those the message carries. */
    readonly certificates?: readonly Certificate[] | undefined;
    /** The anchors every signer must chain to. An empty list is accepted and always yields `PKI_REASON_NO_TRUST_ANCHOR`. */
    readonly trustAnchors: readonly Certificate[];
    /** KeyPurposeId OIDs each signer's chain must permit — `KEY_PURPOSES.emailProtection` for S/MIME, for instance. */
    readonly purposes?: readonly string[] | undefined;
    /** CRLs, as DER, added to those the message carries. */
    readonly crls?: readonly Uint8Array[] | undefined;
    /** OCSP responses, as DER, added to those the message carries. */
    readonly ocspResponses?: readonly Uint8Array[] | undefined;
    /** Report `PKI_REASON_REVOCATION_UNKNOWN` when nothing covered a signer's certificate. Off by default, as for a chain. */
    readonly requireRevocation?: boolean | undefined;
    /** The instant to judge the chains at. Now by default. */
    readonly at?: number | undefined;
    /**
     * Judge each signer's chain at the time its own verified RFC 3161 timestamp
     * proves the signature existed by — `genTime` plus the declared accuracy —
     * instead of `at`. This is the long-term-validation question: *was the
     * certificate good when this was signed?* A signer with no valid timestamp
     * is judged at `at`. The signer's own `signingTime` is never used: nothing
     * vouches for it but the signer.
     *
     * **The timestamp's own authority is still judged at `at`.** A timestamp is
     * proof of time only while its TSA is trusted: judging the TSA's chain at
     * the time its own token asserts would let a TSA key compromised after its
     * certificate expired backdate tokens that are then believed. TSA
     * certificates are long-lived for this reason. Proving the timestamps of an
     * expired TSA needs a later archive timestamp (PAdES B-LTA), which is not
     * implemented here.
     */
    readonly atTimeStamp?: boolean | undefined;
    /** Treat SHA-1 signatures as evidence. Off by default. */
    readonly allowSha1?: boolean | undefined;
    /** Require every signer to name its certificate in a signing-certificate attribute, as CAdES and PAdES do. */
    readonly requireSigningCertificate?: boolean | undefined;
    /** Require every signer to protect its algorithms with `CMSAlgorithmProtection` (RFC 6211). */
    readonly requireAlgorithmProtection?: boolean | undefined;
    /** Ignore bytes after the ContentInfo — the zero padding of a PDF `/Contents`. */
    readonly allowTrailingData?: boolean | undefined;
    /** `'ber'` for a message from a PKCS #7 producer that streams with indefinite lengths. DER by default. */
    readonly encodingRules?: EncodingRules | undefined;
    /** Overrides for any subset of `DEFAULT_PKI_LIMITS`. */
    readonly limits?: Partial<PkiLimits> | undefined;
}

/** The verdict on one signer. */
export interface SignerReport {
    /** The signer's position in `signerInfos`, in encoded order. */
    readonly index: number;
    /** Whether this signer is valid: intact, timestamps valid, and chaining to a trusted anchor. */
    readonly valid: boolean;
    /**
     * Whether every check that needs no trust store passed: the attributes say
     * what they must, the algorithms agree, the content hashes to the committed
     * digest, the signature verifies, and the key's certificate is the one the
     * signer named. `true` here with `valid` false means *unaltered, but not by
     * anybody you trust*.
     */
    readonly intact: boolean;
    /** The certificate that signed; `undefined` when none could be established. */
    readonly certificate: Certificate | undefined;
    /** The time the signer **claims** it signed. Nothing vouches for it; see `timeStamps` for a time that is proved. */
    readonly signingTime: PkiTime | undefined;
    /** Each RFC 3161 timestamp over this signer's signature, verified. */
    readonly timeStamps: readonly VerifyTimeStampTokenReport[];
    /** The signer's chain, judged; `undefined` when there was no certificate to judge. */
    readonly chain: VerifyCertificateChainReport | undefined;
    /** Every reason this signer is not valid, with paths under `signerInfos[i]`. */
    readonly reasons: readonly PkiReason[];
}

/** The verdict on a signed message. */
export interface VerifySignedDataReport {
    /** Whether the message has at least one signer and every signer is valid. */
    readonly valid: boolean;
    /** The message, parsed; `undefined` when it could not be read. */
    readonly signedData: SignedData | undefined;
    /** One verdict per signer, in encoded order. */
    readonly signers: readonly SignerReport[];
    /** Every reason, from every signer and from the message itself. */
    readonly reasons: readonly PkiReason[];
    /** How many signature verifications this cost, chains and timestamps included. */
    readonly signatureVerifications: number;
}

/**
 * Verify a CMS SignedData — a PDF signature, an S/MIME message, a `.p7s` —
 * the whole way.
 *
 * ```ts
 * const report = await verifySignedData({ signedData: p7s, content: document, trustAnchors: roots });
 * if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
 * ```
 *
 * A message is valid when it has at least one signer and **every** signer is
 * valid — the strict reading RFC 5652 §5.1 allows, and the right one for a PDF
 * or a timestamp token, which have one. `signers` carries each verdict for a
 * caller whose policy is another.
 *
 * @param input See {@link VerifySignedDataInput}.
 * @returns The verdict, one verdict per signer, and every reason.
 * @throws {PkiError} `PKI_API_MISUSE` when both `content` and `contentDigest`
 *   are given, or either is given for a message that carries its own content;
 *   `PKI_LIMIT_INVALID` for an unknown or non-positive key in `limits`; `PKI_INVALID_INPUT`
 *   when a certificate is not one `parseCertificate` made.
 */
export async function verifySignedData(input: VerifySignedDataInput): Promise<VerifySignedDataReport> {
    if (input.content !== undefined && input.contentDigest !== undefined) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: pass the detached content or its digest, not both — there would be two answers to which bytes were signed');
    }
    // Misuse is decided here, before the parse below converts every refusal
    // into a reason about the message.
    _assertCertificates(input.certificates ?? [], 'certificates');
    _assertCertificates(input.trustAnchors, 'trustAnchors');
    _assertArguments([['signedData', input.signedData], ['content', input.content], ['contentDigest', input.contentDigest]], {
        limits: input.limits ?? {},
        ...(input.encodingRules === undefined ? {} : { encodingRules: input.encodingRules }),
    });
    if (input.allowTrailingData !== undefined && typeof input.allowTrailingData !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: allowTrailingData must be a boolean, got ${typeof input.allowTrailingData}`);
    }
    const quiet = { onDiagnostic: (): undefined => undefined };
    let signedData: SignedData;
    try {
        signedData = parseSignedData(input.signedData, {
            ...quiet,
            limits: input.limits ?? {},
            ...(input.encodingRules === undefined ? {} : { encodingRules: input.encodingRules }),
            ...(input.allowTrailingData === undefined ? {} : { allowTrailingData: input.allowTrailingData }),
        });
    } catch (error) {
        const refused = _pkiError(error);
        return Object.freeze({ valid: false, signedData: undefined, signers: [], reasons: Object.freeze([inputMalformedReason(refused.code, refused.message, 'signedData')]), signatureVerifications: 0 });
    }
    if (signedData.content !== undefined && (input.content !== undefined || input.contentDigest !== undefined)) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: this message carries its own content, so the content or digest passed alongside it is ambiguous — drop it, or verify the message whose content is detached');
    }

    if (signedData.signerInfos.length === 0) {
        // `[].every(valid)` is true, and a verifier written that way calls a
        // certificate bundle a valid signature. It is not one.
        return Object.freeze({ valid: false, signedData, signers: [], reasons: Object.freeze([cmsNoSignersReason('signerInfos')]), signatureVerifications: 0 });
    }

    const reading = { limits: input.limits ?? {} };
    const { candidates, unreadable } = _parseBag(signedData.certificates, input.certificates ?? [], reading);
    const signers: SignerReport[] = [];
    let signatureVerifications = 0;
    for (const [index, signer] of signedData.signerInfos.entries()) {
        const path = `signerInfos[${String(index)}]`;
        const outcome = await _verifySigner({
            signedData,
            candidates,
            unreadable,
            content: signedData.content ?? input.content,
            contentDigest: input.contentDigest,
            allowSha1: input.allowSha1 === true,
            requireSigningCertificate: input.requireSigningCertificate === true,
            requireAlgorithmProtection: input.requireAlgorithmProtection === true,
        }, signer, path);
        signatureVerifications += outcome.signatureVerifications;
        const reasons: PkiReason[] = [...outcome.reasons];

        // A timestamp over this signer's signature proves when it existed — and
        // a present one that does not verify is the message claiming a time it
        // cannot prove, which makes the signer invalid, not merely unstamped.
        const timeStamps: VerifyTimeStampTokenReport[] = [];
        for (const [position, token] of signer.timeStampTokens.entries()) {
            const stamp = await verifyTimeStampToken({
                token,
                data: signer.signature,
                certificates: candidates,
                trustAnchors: input.trustAnchors,
                ...(input.crls === undefined ? {} : { crls: input.crls }),
                ...(input.ocspResponses === undefined ? {} : { ocspResponses: input.ocspResponses }),
                ...(input.requireRevocation === undefined ? {} : { requireRevocation: input.requireRevocation }),
                ...(input.at === undefined ? {} : { at: input.at }),
                ...(input.allowSha1 === undefined ? {} : { allowSha1: input.allowSha1 }),
                ...(input.limits === undefined ? {} : { limits: input.limits }),
            });
            signatureVerifications += stamp.signatureVerifications;
            timeStamps.push(stamp);
            reasons.push(...stamp.reasons.map((reason) => _under(`${path}.unsignedAttrs.timeStampToken[${String(position)}]`, reason)));
        }

        let chain: VerifyCertificateChainReport | undefined;
        const certificate = outcome.certificate;
        if (certificate !== undefined) {
            chain = await verifyCertificateChain({
                leaf: certificate,
                candidates,
                trustAnchors: input.trustAnchors,
                at: _instant(input, timeStamps),
                ...(input.purposes === undefined ? {} : { purposes: input.purposes }),
                crls: [...signedData.crls, ...(input.crls ?? [])],
                ocspResponses: [...signedData.ocspResponses, ...(input.ocspResponses ?? [])],
                ...(input.requireRevocation === undefined ? {} : { requireRevocation: input.requireRevocation }),
                ...(input.allowSha1 === undefined ? {} : { allowSha1: input.allowSha1 }),
                ...(input.limits === undefined ? {} : { limits: input.limits }),
            });
            signatureVerifications += chain.signatureVerifications;
            reasons.push(...chain.reasons.map((reason) => _under(`${path}.chain`, reason)));
        }

        signers.push(Object.freeze({
            index,
            valid: reasons.length === 0,
            intact: outcome.intact,
            certificate,
            signingTime: signer.signingTime,
            timeStamps: Object.freeze(timeStamps),
            chain,
            reasons: Object.freeze(reasons),
        }));
    }

    const reasons = signers.flatMap((signer) => signer.reasons);
    return Object.freeze({
        valid: reasons.length === 0,
        signedData,
        signers: Object.freeze(signers),
        reasons: Object.freeze(reasons),
        signatureVerifications,
    });
}

/**
 * The instant a signer's chain is judged at.
 *
 * With `atTimeStamp`, the earliest `latest` of this signer's **valid**
 * timestamps: each proves the signature existed by then, and the earliest
 * proof is the strongest. `latest` rather than `genTime`, because the true time
 * may be as late as genTime plus the declared accuracy, and a certificate that
 * expired inside that window is not proved to have been valid.
 */
function _instant(input: VerifySignedDataInput, stamps: readonly VerifyTimeStampTokenReport[]): number {
    const proved = stamps.flatMap((stamp) => (stamp.valid && stamp.latest !== undefined ? [stamp.latest] : []));
    if (input.atTimeStamp === true && proved.length > 0) return Math.min(...proved);
    return input.at ?? Date.now();
}
