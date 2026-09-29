/**
 * pkinative — an RFC 3161 timestamp, judged the whole way
 * =======================================================
 * A timestamp token says that **a hash existed at a time**, and it is only
 * worth that once three separate things have been established: that the hash
 * is the one you care about, that a timestamp authority signed it, and that the
 * authority was entitled to. RFC 3161 §2.4.2 lists the client's checks, and
 * this is where they are made — every one of them, in one call, never throwing
 * for a verdict.
 *
 * **It will not run without knowing what was stamped.** A request, the data, or
 * the expected imprint: one of the three is required, because a verifier that
 * checked a token without asking *of what* would confirm that some hash existed
 * at some time, which is true of every token ever issued.
 *
 * The TSA's certificate is judged twice, for two different things. RFC 3161
 * §2.3 asks of it what no other profile asks — an extKeyUsage that is present,
 * critical, and names timestamping alone — and that is checked here directly.
 * Whether it chains to an anchor you trust, is unrevoked, and whose CAs let it
 * stamp at all is `verifyCertificateChain`'s question.
 *
 * @module verify/verify-timestamp
 */

import { OID_KP_TIMESTAMPING } from '../core/cms-oids.js';
import { bytesEqual } from '../core/bytes.js';
import {
    cmsNoSignersReason,
    expiredReason,
    inputMalformedReason,
    notYetValidReason,
    purposeNotPermittedReason,
    tspImprintMismatchReason,
    tspNotGrantedReason,
    tspRequestMismatchReason,
    tspTokenInvalidReason,
} from '../core/pki-reasons.js';
import { _parseTimeStampRequest } from '../cms/tsp-request.js';
import { parseTimeStampResponse, parseTimeStampToken } from '../cms/tsp-response.js';
import { computeFingerprintAsync } from '../hash/fingerprint.js';
import type { PkiTime } from '../types/asn1-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { PkiLimits, PkiParseOptions } from '../types/pki-types.js';
import type { MessageImprint, TimeStampToken } from '../types/tsp-types.js';
import type { Certificate } from '../types/x509-types.js';
import { parseCertificate } from '../x509/x509-certificate.js';
import { getExtension } from '../x509/x509-extensions.js';
import { _assertArguments, _assertCertificates, _pkiError, verifyCertificateChain, type VerifyCertificateChainReport } from './verify-chain.js';
import { _digestName, _under, _verifySigner } from './verify-signer.js';

/** What to verify a timestamp token against. */
export interface VerifyTimeStampTokenInput {
    /**
     * The token: a ContentInfo whose content is a SignedData over a TSTInfo.
     * Give this or `response`, not both.
     */
    readonly token?: Uint8Array | undefined;
    /**
     * The whole `TimeStampResp` the TSA sent back, when you hold that rather
     * than the token inside it. A response that granted nothing is reported
     * as `PKI_REASON_TSP_NOT_GRANTED`, carrying the TSA's status, text and
     * failure codes. Give this or `token`, not both.
     */
    readonly response?: Uint8Array | undefined;
    /**
     * The `TimeStampReq` you sent. The token must stamp the same imprint, echo
     * the same nonce as the same integer, and carry the policy you asked for.
     * This is the strongest of the three ways to say what was stamped: it is
     * the only one that catches a replayed response.
     */
    readonly request?: Uint8Array | undefined;
    /** The data that was stamped. It is hashed with the token's own imprint algorithm. */
    readonly data?: Uint8Array | undefined;
    /** The hash that was stamped, when you hold that rather than the data. */
    readonly imprint?: Uint8Array | undefined;
    /** Certificates to look for the TSA's among, beyond those the token carries — needed when the request set certReq to false. */
    readonly certificates?: readonly Certificate[] | undefined;
    /** The anchors the TSA must chain to. An empty list is accepted and always yields `PKI_REASON_NO_TRUST_ANCHOR`. */
    readonly trustAnchors: readonly Certificate[];
    /** CRLs for the TSA's chain, as DER. */
    readonly crls?: readonly Uint8Array[] | undefined;
    /** OCSP responses for the TSA's certificate, as DER. */
    readonly ocspResponses?: readonly Uint8Array[] | undefined;
    /** Report `PKI_REASON_REVOCATION_UNKNOWN` when nothing covered the TSA's certificate. Off by default, as for a chain. */
    readonly requireRevocation?: boolean | undefined;
    /**
     * The instant to judge the TSA's chain at. Now by default — the ordinary
     * PKIX model. A long-term validation that must accept a token whose TSA
     * certificate has since expired passes the token's `genTime` here, and is
     * deciding, deliberately, to trust the time the token itself asserts.
     */
    readonly at?: number | undefined;
    /** Treat SHA-1 signatures as evidence. Off by default. */
    readonly allowSha1?: boolean | undefined;
    /**
     * Accept a TSA whose extKeyUsage names timestamping but is not critical.
     * RFC 3161 §2.3 requires it critical and some deployed TSAs are not; this
     * is the documented escape for them, off by default.
     */
    readonly allowNonCriticalTimeStampingEku?: boolean | undefined;
    /** Overrides for any subset of `DEFAULT_PKI_LIMITS`. */
    readonly limits?: Partial<PkiLimits> | undefined;
}

/** The verdict on a timestamp token, and what it established. */
export interface VerifyTimeStampTokenReport {
    /** Whether the token is evidence that the expected hash existed at `genTime`. */
    readonly valid: boolean;
    /** The token, parsed; `undefined` when it could not be read. */
    readonly token: TimeStampToken | undefined;
    /** The time the token asserts — established only when `valid`. */
    readonly genTime: PkiTime | undefined;
    /** `genTime` minus the declared accuracy, in epoch milliseconds: the earliest the stamping can have happened. */
    readonly earliest: number | undefined;
    /** `genTime` plus the declared accuracy: the latest. An LTV check asking "before the certificate expired?" wants this one. */
    readonly latest: number | undefined;
    /** The TSA's certificate, when its key verified the token and it is the one the token names. */
    readonly tsaCertificate: Certificate | undefined;
    /** The TSA's chain, judged by `verifyCertificateChain`; `undefined` when there was no certificate to judge. */
    readonly chain: VerifyCertificateChainReport | undefined;
    /** Every reason the token is not evidence of what was asked. */
    readonly reasons: readonly PkiReason[];
    /** How many signature verifications this cost, the TSA's chain included. */
    readonly signatureVerifications: number;
}

/** What a token must stamp, and what else it must echo. */
interface _Expectation {
    /** The expected imprint, or the data to hash with the token's imprint algorithm. */
    readonly imprint: Uint8Array | undefined;
    readonly data: Uint8Array | undefined;
    /** The request's imprint, when there was one: the algorithm must match too. */
    readonly requested: MessageImprint | undefined;
    readonly nonce: bigint | undefined;
    readonly policy: string | undefined;
}

/**
 * Verify an RFC 3161 timestamp token.
 *
 * ```ts
 * const report = await verifyTimeStampToken({ token, request, trustAnchors: tsaRoots });
 * if (report.valid) console.log('existed by', new Date(report.latest ?? 0).toISOString());
 * ```
 *
 * It never throws for a verification issue or for malformed input — a token
 * that cannot be read is `PKI_REASON_INPUT_MALFORMED`. It throws only for API
 * misuse: saying nothing about what was stamped, or a malformed `request`,
 * which is your own bytes.
 *
 * @param input See {@link VerifyTimeStampTokenInput}.
 * @returns The verdict and what it established.
 * @throws {PkiError} `PKI_API_MISUSE` when none of `request`, `data` and
 *   `imprint` is given, or when not exactly one of `token` and `response` is; `PKI_LIMIT_INVALID` for an unknown or non-positive key in `limits`;
 *   `PKI_INVALID_INPUT` when a certificate is not one `parseCertificate` made.
 * @throws {PkiCmsError} When `request` is not a TimeStampReq.
 */
export async function verifyTimeStampToken(input: VerifyTimeStampTokenInput): Promise<VerifyTimeStampTokenReport> {
    // Silent for everything this call reads — the request, the token and the
    // bag: a verdict call reports in its report.
    const reading = { limits: input.limits ?? {}, onDiagnostic: (): undefined => undefined };
    const expectation = _expectation(input, reading);
    const reasons: PkiReason[] = [];

    let token: TimeStampToken;
    try {
        if (input.response === undefined) {
            // _expectation has refused a call carrying neither.
            token = parseTimeStampToken(input.token as Uint8Array, reading);
        } else {
            const response = parseTimeStampResponse(input.response, reading);
            // RFC 3161 §2.4.2: only granted and grantedWithMods carry a token,
            // and the parser has already refused one that claims to without.
            if (response.token === undefined) {
                reasons.push(tspNotGrantedReason('response.status', response.status, response.statusStrings, response.failInfo));
                return _report(reasons, undefined, undefined, undefined, 0);
            }
            token = response.token;
        }
    } catch (error) {
        const refused = _pkiError(error);
        reasons.push(inputMalformedReason(refused.code, refused.message, input.response === undefined ? 'token' : 'response'));
        return _report(reasons, undefined, undefined, undefined, 0);
    }
    const { signedData, tstInfo } = token;

    // ── The token's own shape (RFC 3161 §2.4.2) ──
    const [signer, ...others] = signedData.signerInfos;
    if (signer === undefined) {
        reasons.push(cmsNoSignersReason('token.signerInfos'));
        return _report(reasons, token, undefined, undefined, 0);
    }
    if (others.length > 0) {
        reasons.push(tspTokenInvalidReason('token.signerInfos',
            `the token carries ${String(signedData.signerInfos.length)} signers, and RFC 3161 §2.4.2 allows only the TSA's`));
    }

    // ── What was stamped ──
    reasons.push(...await _imprintReasons(tstInfo.messageImprint, expectation));
    if (expectation.nonce !== undefined && tstInfo.nonce !== expectation.nonce) {
        reasons.push(tspRequestMismatchReason('token.tstInfo.nonce', tstInfo.nonce === undefined
            ? 'the request carried a nonce and the token echoes none'
            : `the request carried the nonce ${String(expectation.nonce)} and the token echoes ${String(tstInfo.nonce)}`));
    }
    if (expectation.policy !== undefined && tstInfo.policy !== expectation.policy) {
        reasons.push(tspRequestMismatchReason('token.tstInfo.policy', `the request asked for the policy ${expectation.policy} and the token was issued under ${tstInfo.policy}`));
    }

    // ── Who signed it (RFC 5652 §5.6, with the binding RFC 5816 makes mandatory) ──
    const { candidates, unreadable } = _parseBag(signedData.certificates, input.certificates ?? [], reading);
    const outcome = await _verifySigner({
        signedData,
        candidates,
        unreadable,
        content: signedData.content,
        contentDigest: undefined,
        allowSha1: input.allowSha1 === true,
        requireSigningCertificate: true,
        requireAlgorithmProtection: false,
    }, signer, 'token.signerInfos[0]');
    reasons.push(...outcome.reasons);
    let signatureVerifications = outcome.signatureVerifications;
    const tsa = outcome.certificate;
    if (tsa === undefined) return _report(reasons, token, undefined, undefined, signatureVerifications);

    // ── Whether that signer may stamp (RFC 3161 §2.3, §2.4.2) ──
    const purpose = _tsaPurposeReason(tsa, input.allowNonCriticalTimeStampingEku === true);
    if (purpose !== null) reasons.push(purpose);
    const genTime = tstInfo.genTime.epochMilliseconds;
    if (genTime < tsa.validity.notBefore.epochMilliseconds) {
        reasons.push(notYetValidReason('token.tsaCertificate', tsa.validity.notBefore.epochMilliseconds, genTime));
    } else if (genTime > tsa.validity.notAfter.epochMilliseconds) {
        reasons.push(expiredReason('token.tsaCertificate', tsa.validity.notAfter.epochMilliseconds, genTime));
    }
    const named = tstInfo.tsa;
    if (named !== undefined && !_holdsName(tsa, named)) {
        reasons.push(tspTokenInvalidReason('token.tstInfo.tsa', 'the token names a TSA that is neither the subject of its signing certificate nor among that certificate\'s subjectAltName'));
    }

    // ── Whether you trust it ──
    const chain = await verifyCertificateChain({
        leaf: tsa,
        candidates,
        trustAnchors: input.trustAnchors,
        at: input.at ?? Date.now(),
        // The purpose goes into the path search only when the certificate itself
        // passed the RFC 3161 test above: otherwise the chain would say again
        // what that test already said, one reason per round trip.
        ...(purpose === null ? { purposes: [OID_KP_TIMESTAMPING] } : {}),
        crls: [...signedData.crls, ...(input.crls ?? [])],
        ocspResponses: [...signedData.ocspResponses, ...(input.ocspResponses ?? [])],
        ...(input.requireRevocation === undefined ? {} : { requireRevocation: input.requireRevocation }),
        ...(input.allowSha1 === undefined ? {} : { allowSha1: input.allowSha1 }),
        ...(input.limits === undefined ? {} : { limits: input.limits }),
    });
    signatureVerifications += chain.signatureVerifications;
    reasons.push(...chain.reasons.map((reason) => _under('token.tsaChain', reason)));
    return _report(reasons, token, tsa, chain, signatureVerifications);
}

/** The report, with the time window filled in only when the token is evidence. */
function _report(reasons: readonly PkiReason[], token: TimeStampToken | undefined, tsa: Certificate | undefined, chain: VerifyCertificateChainReport | undefined, signatureVerifications: number): VerifyTimeStampTokenReport {
    const valid = reasons.length === 0;
    const info = valid ? token?.tstInfo : undefined;
    const accuracy = info?.accuracy;
    const slack = accuracy === undefined ? 0 : accuracy.seconds * 1000 + accuracy.millis + accuracy.micros / 1000;
    return Object.freeze({
        valid,
        token,
        genTime: info?.genTime,
        earliest: info === undefined ? undefined : info.genTime.epochMilliseconds - slack,
        latest: info === undefined ? undefined : info.genTime.epochMilliseconds + slack,
        tsaCertificate: tsa,
        chain,
        reasons: Object.freeze([...reasons]),
        signatureVerifications,
    });
}

/** What the caller said was stamped, resolved once and refused if they said nothing. */
function _expectation(input: VerifyTimeStampTokenInput, reading: PkiParseOptions): _Expectation {
    if ((input.token === undefined) === (input.response === undefined)) {
        throw new PkiError('PKI_API_MISUSE',
            'pkinative: pass the timestamp as exactly one of token (the token alone) or response (the whole TimeStampResp the TSA sent)');
    }
    if (input.request === undefined && input.data === undefined && input.imprint === undefined) {
        throw new PkiError('PKI_API_MISUSE',
            'pkinative: say what was stamped — pass the request you sent, the data, or the expected imprint. A token verified without it proves that some hash existed at some time, which is true of every token ever issued');
    }
    // Misuse is decided here, before the parse in the caller converts every
    // refusal into a reason about the token.
    _assertCertificates(input.certificates ?? [], 'certificates');
    _assertCertificates(input.trustAnchors, 'trustAnchors');
    _assertArguments([
        ['token', input.token], ['response', input.response], ['request', input.request], ['data', input.data], ['imprint', input.imprint],
    ], reading);
    const request = input.request === undefined ? undefined : _parseTimeStampRequest(input.request, reading);
    return {
        imprint: input.imprint,
        data: input.data,
        requested: request?.messageImprint,
        nonce: request?.nonce,
        policy: request?.policy,
    };
}

/**
 * The token's imprint against everything the caller said was stamped. Each
 * given expectation is checked, not just the first: a request and a data that
 * disagree with each other are two statements, and the token has to answer
 * both.
 */
async function _imprintReasons(stamped: MessageImprint, expectation: _Expectation): Promise<PkiReason[]> {
    const out: PkiReason[] = [];
    const where = 'token.tstInfo.messageImprint';
    const requested = expectation.requested;
    if (requested !== undefined
        && (requested.hashAlgorithm.oid !== stamped.hashAlgorithm.oid || !bytesEqual(requested.hashedMessage, stamped.hashedMessage))) {
        out.push(tspImprintMismatchReason(where));
    }
    if (expectation.imprint !== undefined && !bytesEqual(expectation.imprint, stamped.hashedMessage)) {
        out.push(tspImprintMismatchReason(where));
    }
    if (expectation.data !== undefined) {
        // With the token's own imprint algorithm, which RFC 8933 §3.5 lets
        // differ from the one the TSA signed with.
        const name = _digestName(stamped.hashAlgorithm.oid);
        if (name === undefined) {
            out.push(tspTokenInvalidReason(where, `the token stamps a ${stamped.hashAlgorithm.oid} digest, which pkinative does not compute, so what it stamps cannot be established`));
        } else if (!bytesEqual(await computeFingerprintAsync(expectation.data, name), stamped.hashedMessage)) {
            out.push(tspImprintMismatchReason(where));
        }
    }
    // Several expectations that all fail are one fact, said once.
    return out.slice(0, 1);
}

/**
 * RFC 3161 §2.3: the TSA's certificate "MUST contain only one instance of the
 * extended key usage field extension … with KeyPurposeID having value
 * id-kp-timeStamping. This extension MUST be critical."
 *
 * Read strictly: present, critical, and timestamping alone. The sentence is
 * ambiguous between "one extension" and "one purpose", and the stricter
 * reading is the safe one — a certificate that may also sign code or e-mail is
 * one whose key does more than stamp time, and a compromise of it is a
 * compromise of every timestamp it ever made.
 */
function _tsaPurposeReason(certificate: Certificate, allowNonCritical: boolean): PkiReason | null {
    const eku = getExtension(certificate, 'extendedKeyUsage');
    const where = 'token.tsaCertificate.extKeyUsage';
    if (eku === undefined) return purposeNotPermittedReason(where, OID_KP_TIMESTAMPING, null);
    if (!eku.purposes.includes(OID_KP_TIMESTAMPING)) return purposeNotPermittedReason(where, OID_KP_TIMESTAMPING, eku.purposes);
    if (eku.purposes.length > 1) return purposeNotPermittedReason(where, OID_KP_TIMESTAMPING, eku.purposes, 'exclusive');
    if (!eku.critical && !allowNonCritical) return purposeNotPermittedReason(where, OID_KP_TIMESTAMPING, eku.purposes, 'critical');
    return null;
}

/** Whether the TSA's certificate holds the name the TSTInfo gives — as its subject, or among its subjectAltName. */
function _holdsName(certificate: Certificate, name: NonNullable<TimeStampToken['tstInfo']['tsa']>): boolean {
    if (name.kind === 'directoryName' && bytesEqual(name.name.der, certificate.subject.der)) return true;
    return (getExtension(certificate, 'subjectAltName')?.names ?? []).some((alt) => bytesEqual(alt.der, name.der));
}

/**
 * The message's certificates parsed, and the caller's added.
 *
 * A certificate in the message that does not parse is skipped rather than
 * reported: the bag is a claim by whoever assembled the message, may hold
 * unrelated certificates, and one broken stranger must not make the signature
 * unreadable. How many were skipped is said if the signer then goes unfound.
 *
 * @internal
 */
export function _parseBag(ders: readonly Uint8Array[], extra: readonly Certificate[], reading: { readonly limits: Partial<PkiLimits> }): {
    readonly candidates: readonly Certificate[];
    readonly unreadable: number;
} {
    const candidates: Certificate[] = [];
    let unreadable = 0;
    for (const der of ders) {
        try {
            candidates.push(parseCertificate(der, { ...reading, onDiagnostic: (): undefined => undefined }));
        } catch (error) {
            _pkiError(error);
            unreadable += 1;
        }
    }
    return { candidates: [...candidates, ...extra], unreadable };
}
