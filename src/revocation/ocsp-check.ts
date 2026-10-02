/**
 * pkinative — the OCSP status decision
 * ====================================
 * Given a response, the question it was supposed to answer, and an instant:
 * what does it actually establish?
 *
 * Synchronous, pure, never throwing for a status issue — the same contract
 * `checkRevocation` and §6 have. The signature verdict and the *responder
 * authorisation* verdict both arrive precomputed, which is what keeps this
 * function free of Web Crypto and free of policy.
 *
 * ## The checks RFC 6960 §3.2 makes a client responsible for
 *
 * A client must confirm all of these, and this function reports each one it
 * can. The clause's own list, and where each lands:
 *
 *   1. *The certificate identified in the response corresponds to the one in
 *      the request* — `PKI_REASON_REVOCATION_MISMATCH`, the check that stops a
 *      cache or an attacker handing over somebody else's answer.
 *   2. *The signature is valid* — the caller's `signatureVerified`.
 *   3. *The signer is authorised to answer for this CA* — the caller's
 *      `responderAuthorized`. **Not decided here**, because RFC 6960 §4.2.2.2
 *      gives three routes and `basicResponse.certificates` are certificates the
 *      responder *attached*: trusting them because they arrived would let the
 *      responder nominate its own authority.
 *   4. *`thisUpdate` is sufficiently recent* and *`nextUpdate` has not passed*
 *      — `PKI_REASON_REVOCATION_STALE`. An answer with **no** `nextUpdate` is
 *      stale by default, as a CRL without one is: RFC 6960 §4.2.2.1 reads the
 *      absence as *"newer revocation information is available all the time"*,
 *      which says the answer is good at `thisUpdate` and promises nothing
 *      after it. `staleTolerance` is then measured from `thisUpdate`, which
 *      is how a caller holding a response it fetched a moment ago accepts it.
 *      A `revoked` answer is exempt: a revocation, once published, stands.
 *
 * §3.2 asks for these *"prior to accepting a signed response ... as valid"*,
 * so a `revoked` answer becomes `PKI_REASON_REVOKED` only when checks 2 and 3
 * hold. Otherwise anyone who can write a response — an on-path attacker on
 * plain-HTTP OCSP, a key nobody authorised — could have a report say
 * "revoked (reason: keyCompromise)"; the claim is carried instead in a
 * `PKI_REASON_REVOCATION_UNKNOWN`, beside the reasons that already fail it.
 *
 * ## The nonce, and why an absence is not the same as a mismatch
 *
 * A nonce that comes back **different** is always wrong: that response was not
 * produced for this request. A nonce that does not come back **at all** is a
 * policy question — the CA/Browser Forum discourages nonces precisely so
 * responses stay cacheable, and most public responders omit the echo. So a
 * mismatch is always reported and an absence only when `requireNonce` asks,
 * which is the caller choosing whether replay protection or cacheability wins.
 *
 * @module revocation/ocsp-check
 */

import { bytesEqual } from '../core/bytes.js';
import {
    revocationMismatchReason,
    revocationStaleReason,
    revocationUnknownReason,
    revokedReason,
} from '../core/pki-reasons.js';
import type { OcspBasicResponse, OcspResponse, OcspSingleResponse } from '../types/ocsp-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import { _unverifiedRevocation } from './crl-check.js';

/** `id-pkix-ocsp-nonce`, RFC 6960 §4.4.1. */
export const OCSP_NONCE_OID = '1.3.6.1.5.5.7.48.1.2';

/** What to check, and everything needed to judge it. */
export interface CheckOcspStatusInput {
    /** The parsed response. */
    readonly response: OcspResponse;
    /**
     * The `CertID` that was asked about, as `encodeOcspCertId` produced it. Compared
     * to the answer's, field by field — which is RFC 6960 §3.2's first
     * requirement and the one a client that trusts the response order skips.
     */
    readonly expected: {
        readonly issuerNameHash: Uint8Array;
        readonly issuerKeyHash: Uint8Array;
        readonly serialNumber: Uint8Array;
    };
    /** The instant to judge at, in epoch milliseconds. */
    readonly at: number;
    /**
     * Whether the responder's signature verified. `false` means it was checked
     * and failed, `undefined` means it was never checked; both give
     * `PKI_REASON_REVOCATION_UNKNOWN`, with different wording.
     */
    readonly signatureVerified?: boolean | undefined;
    /**
     * Whether the signer is authorised to answer for this CA (RFC 6960
     * §4.2.2.2). **The caller's decision**: the CA signed it itself, the CA
     * delegated to this responder, or the client trusts it out of band. Left
     * `undefined` it is reported as unknown, because a responder nobody
     * authorised is a responder anyone can be.
     */
    readonly responderAuthorized?: boolean | undefined;
    /** The nonce that was sent, if any. A different one coming back is always a mismatch. */
    readonly nonce?: Uint8Array | undefined;
    /**
     * Report a missing nonce echo as a mismatch. `false` by default, because
     * most public responders omit it on purpose so answers stay cacheable —
     * turning it on is choosing replay protection over that.
     */
    readonly requireNonce?: boolean | undefined;
    /**
     * Accept a response whose `nextUpdate` has passed, up to this many
     * milliseconds. Zero by default. For an answer that declares no
     * `nextUpdate`, the tolerance runs from its `thisUpdate` instead — the
     * one instant such an answer vouches for — so the default refuses it.
     */
    readonly staleTolerance?: number | undefined;
    /**
     * Refuse a response whose `thisUpdate` is more than this far in the future.
     * A minute by default: clocks disagree by seconds, not by hours, and a
     * `thisUpdate` well ahead of now is a responder with a broken clock or a
     * response minted for later.
     */
    readonly futureTolerance?: number | undefined;
}

const MINUTE = 60_000;

/**
 * Decide what an OCSP response establishes about one certificate.
 *
 * ```ts
 * const response = parseOcspResponse(bytes);
 * const basic = response.basicResponse;
 * const reasons = checkOcspStatus({
 *     response,
 *     expected: { issuerNameHash, issuerKeyHash, serialNumber: certificate.serialNumber.bytes },
 *     at: Date.now(),
 *     signatureVerified: basic !== undefined && await verifyOcspSignature(basic, responder),
 *     responderAuthorized: yourPolicySaysSo,
 *     nonce,
 * });
 * ```
 *
 * `[]` means the responder said `good`, about this certificate, recently
 * enough, signed by someone you authorised. Everything else is a reason.
 *
 * **Freshness** (RFC 6960 §3.2 (4)): a `thisUpdate` more than
 * `futureTolerance` ahead of `at` is `PKI_REASON_REVOCATION_STALE`, and so
 * is an answer past its `nextUpdate` (plus `staleTolerance`). An answer with
 * no `nextUpdate` is stale once `at` is past `thisUpdate` plus
 * `staleTolerance` — stale by default, as a CRL without one is — unless it
 * says `revoked`.
 *
 * **Contradiction**: a response carrying two answers about this one
 * certificate that disagree on its status is `PKI_REASON_REVOCATION_UNKNOWN`
 * — contradictory answers establish nothing, and taking the first would let
 * the order decide.
 *
 * @param input See {@link CheckOcspStatusInput}.
 * @returns Every reason the answer is not a clean `good`; empty when it is.
 * @throws Never — every negative answer is a reason in the returned list. The
 *   response was already parsed, so there are no bytes left to fail on.
 */
export function checkOcspStatus(input: CheckOcspStatusInput): readonly PkiReason[] {
    const out: PkiReason[] = [];
    const path = 'ocsp';

    // A responder that declined said nothing about any certificate. Reported as
    // unknown with the status named, because `tryLater` and `unauthorized` call
    // for different next moves and a caller needs to know which it got.
    if (input.response.status !== 'successful') {
        out.push(revocationUnknownReason(path, `the responder declined with ${input.response.status}, which says nothing about this certificate`));
        return out;
    }
    const basic = input.response.basicResponse;
    if (basic === undefined) {
        out.push(revocationUnknownReason(path, 'the response carries no body'));
        return out;
    }

    if (input.signatureVerified !== true) {
        out.push(revocationUnknownReason(path, input.signatureVerified === false
            ? 'the responder\'s signature did not verify against the key it was checked with'
            : 'the responder\'s signature was never checked, and an unsigned response is something anyone can produce'));
    }
    if (input.responderAuthorized !== true) {
        out.push(revocationUnknownReason(path, input.responderAuthorized === false
            ? 'the signer is not authorised to answer for this CA (RFC 6960 §4.2.2.2)'
            : 'nothing says the signer is authorised to answer for this CA, and a responder nobody authorised is a responder anyone can be'));
    }

    out.push(...checkNonce(basic, input, path));

    // Find the answer that is about the certificate asked about. Never
    // `responses[0]`: a response may carry several, and taking the first is
    // how a client reads somebody else's status as its own. The responses
    // came out of the parser, bounded by `maxOcspSingleResponses`.
    const answers = basic.responses.filter((single) => matches(single, input.expected));
    const answer = answers[0];
    if (answer === undefined) {
        out.push(revocationMismatchReason(path, describeMismatch(basic, input)));
        return out;
    }
    // Two answers about this one certificate that disagree: `good` then
    // `revoked` is a response that has said both, and believing the first
    // would let the order of the SEQUENCE decide the verdict.
    if (answers.some((other) => other.status.kind !== answer.status.kind)) {
        out.push(revocationUnknownReason(path, 'the response answers more than once about this certificate and the answers disagree on its status, so it establishes nothing'));
        return out;
    }

    out.push(...checkFreshness(answer, input, path));

    if (answer.status.kind === 'revoked') {
        const { revocationTime, reason } = answer.status;
        out.push(input.signatureVerified === true && input.responderAuthorized === true
            ? revokedReason(path, revocationTime.epochMilliseconds, reason)
            : revocationUnknownReason(path, _unverifiedRevocation('response', revocationTime.epochMilliseconds, reason)));
    } else if (answer.status.kind === 'unknown') {
        // The responder's own third state, carried through rather than
        // flattened: it means "I do not know about this certificate", which is
        // not "not revoked" and is often a sign the serial is not this CA's.
        out.push(revocationUnknownReason(path, 'the responder answered unknown, meaning it has no record of this certificate — often a sign the serial does not belong to that CA'));
    }
    return out;
}

/** All three `CertID` fields, compared by bytes. */
function matches(single: OcspSingleResponse, expected: CheckOcspStatusInput['expected']): boolean {
    return bytesEqual(single.certId.issuerNameHash, expected.issuerNameHash)
        && bytesEqual(single.certId.issuerKeyHash, expected.issuerKeyHash)
        && bytesEqual(single.certId.serialNumber.bytes, expected.serialNumber);
}

/** Which field of which answer failed to match, so the report can be acted on. */
function describeMismatch(basic: OcspBasicResponse, input: CheckOcspStatusInput): string {
    if (basic.responses.length === 0) return 'the response carries no answers at all';
    const first = basic.responses[0] as OcspSingleResponse;
    if (!bytesEqual(first.certId.serialNumber.bytes, input.expected.serialNumber)) {
        return `it answers about serial ${first.certId.serialNumber.hex}, and the question was about ${hex(input.expected.serialNumber)}`;
    }
    if (!bytesEqual(first.certId.issuerNameHash, input.expected.issuerNameHash)) {
        return 'the serial matches but the issuer name hash does not, so the answer is about a certificate from another CA';
    }
    return 'the serial matches but the issuer key hash does not, so the answer is about a certificate under another key';
}

function hex(bytes: Uint8Array): string {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
}

/** §4.4.1: a different nonce is always wrong; a missing one is a policy choice. */
function checkNonce(basic: OcspBasicResponse, input: CheckOcspStatusInput, path: string): PkiReason[] {
    const sent = input.nonce;
    if (sent === undefined) return [];
    const echoed = basic.extensions.find((extension) => extension.oid === OCSP_NONCE_OID);
    if (echoed === undefined) {
        return input.requireNonce === true
            ? [revocationMismatchReason(path, 'no nonce came back, and requireNonce was asked for — without an echo this response may be a replay')]
            : [];
    }
    // The extension value is an OCTET STRING whose content is another one, so
    // the nonce sits two layers deep. Comparing at the wrong layer is a nonce
    // check that passes on everything.
    const inner = unwrapOctetString(echoed.valueDer);
    if (inner === null || !bytesEqual(inner, sent)) {
        return [revocationMismatchReason(path, 'the nonce that came back is not the one that was sent')];
    }
    return [];
}

/** The content of an OCTET STRING at the start of `bytes`, or null. */
function unwrapOctetString(bytes: Uint8Array): Uint8Array | null {
    if (bytes.length < 2 || bytes[0] !== 0x04) return null;
    const length = bytes[1] as number;
    // Short form only: a nonce is at most 32 octets (RFC 8954 §2.1), so a
    // long-form length here is not a nonce this code should try to read.
    if (length > 0x7f || 2 + length > bytes.length) return null;
    return bytes.subarray(2, 2 + length);
}

/** §3.2: `thisUpdate` recent enough, `nextUpdate` not passed. */
function checkFreshness(answer: OcspSingleResponse, input: CheckOcspStatusInput, path: string): PkiReason[] {
    const out: PkiReason[] = [];
    const future = input.futureTolerance ?? MINUTE;
    if (answer.thisUpdate.epochMilliseconds > input.at + future) {
        out.push(revocationStaleReason(path, undefined, input.at));
    }
    const nextUpdate = answer.nextUpdate?.epochMilliseconds;
    const tolerance = input.staleTolerance ?? 0;
    if (nextUpdate !== undefined && input.at > nextUpdate + tolerance) {
        out.push(revocationStaleReason(path, nextUpdate, input.at));
    }
    // No `nextUpdate`: RFC 6960 §4.2.2.1 says the responder *"is indicating
    // that newer revocation information is available all the time"* — so this
    // answer vouches for `thisUpdate` and for nothing after it. Read as current
    // forever, a `good` minted five years ago would still clear a certificate
    // today. Stale by default, as a CRL without a nextUpdate is, with the
    // tolerance measured from the one instant it does vouch for. A `revoked`
    // answer is the exception: a revocation, once published, is not withdrawn
    // by time.
    if (nextUpdate === undefined && answer.status.kind !== 'revoked' && input.at > answer.thisUpdate.epochMilliseconds + tolerance) {
        out.push(revocationStaleReason(path, undefined, input.at));
    }
    return out;
}
