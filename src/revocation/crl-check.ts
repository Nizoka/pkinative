/**
 * pkinative — the revocation decision
 * ===================================
 * Given a certificate, a CRL and an instant: is the certificate revoked, and
 * is the list even entitled to say so?
 *
 * Synchronous, pure, and never throwing for a revocation issue — the same
 * contract §6 has, for the same reason. The CRL's signature verdict arrives
 * **precomputed**, exactly as path validation takes signature verdicts, which
 * is what keeps this function free of Web Crypto and free of `await`.
 *
 * ## The four answers, and why they are four
 *
 * `[]` — not revoked, by a list that was entitled to say so and current
 * enough to be believed.
 *
 * `PKI_REASON_REVOKED` — listed. Carries the date, because a signature made
 * before the revocation instant may still be good and the caller deciding
 * that needs the date.
 *
 * `PKI_REASON_REVOCATION_STALE` / `..._WRONG_ISSUER` — the list cannot answer
 * for this certificate. An out-of-date list says what was revoked *then*; a
 * list from another CA says nothing at all.
 *
 * `PKI_REASON_REVOCATION_UNKNOWN` — no evidence either way. This is the answer
 * a soft-fail policy acts on, and it is deliberately **not** the same as "not
 * revoked": a validator that reported silence as a clean bill of health would
 * make the soft-fail decision on the caller's behalf, invisibly.
 *
 * @module revocation/crl-check
 */

import {
    revocationStaleReason,
    revocationUnknownReason,
    revocationWrongIssuerReason,
    revokedReason,
} from '../core/pki-reasons.js';
import { bytesEqual } from '../core/bytes.js';
import type { CertificateList } from '../types/crl-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { Certificate } from '../types/x509-types.js';
import { findRevocation } from './crl-parse.js';

/** What to check, and everything needed to judge it. */
export interface RevocationCheckInput {
    /** The certificate whose status is in question. */
    readonly certificate: Certificate;
    /** The parsed list. */
    readonly crl: CertificateList;
    /** The same bytes `parseCertificateList` was given — the walk needs them. */
    readonly crlDer: Uint8Array;
    /** The instant to judge at, in epoch milliseconds. */
    readonly at: number;
    /**
     * Whether the CRL's signature was verified against a key entitled to sign
     * it. Computed beforehand with `verifyCrlSignature`, which is what keeps
     * this function synchronous.
     *
     * `false` and `undefined` are different: `false` means the signature was
     * checked and failed, `undefined` means it was never checked. Both produce
     * `PKI_REASON_REVOCATION_UNKNOWN`, with different wording — an unsigned
     * list is not evidence, and pretending otherwise lets anyone publish one.
     */
    readonly signatureVerified?: boolean | undefined;
    /**
     * Accept a list whose `nextUpdate` has passed, up to this many
     * milliseconds. Zero by default: an expired list is refused.
     */
    readonly staleTolerance?: number | undefined;
    /** Options for the walk — the limits apply to it. */
    readonly options?: PkiParseOptions | undefined;
}

/**
 * Decide a certificate's revocation status against one CRL.
 *
 * ```ts
 * const crl = parseCertificateList(crlDer);
 * const signatureVerified = await verifyCrlSignature(crl, caCertificate);
 * const reasons = checkRevocation({ certificate, crl, crlDer, at: Date.now(), signatureVerified });
 * if (reasons.length === 0) console.log('not revoked');
 * ```
 *
 * It never throws for a revocation issue. It does throw for malformed CRL bytes
 * reached during the walk, because that is a structural failure and not a
 * verdict — the same line every other entry point draws.
 *
 * Only **one** list is consulted. Choosing which lists cover a certificate,
 * fetching them and combining a delta with its base are the caller's job, and
 * `crl.isDelta` is there so a caller does not mistake a delta for a full list:
 * a delta answers only about what changed, and reading it as complete reports
 * every certificate absent from it as unrevoked.
 *
 * @param input See {@link RevocationCheckInput}.
 * @returns Every reason the answer is not a clean "not revoked", in the order
 *   they were established; empty when the certificate is not revoked.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` for a malformed entry.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxRevokedCertificates`.
 */
export function checkRevocation(input: RevocationCheckInput): readonly PkiReason[] {
    const out: PkiReason[] = [];
    const path = 'crl';

    // Is this list even about this certificate? Encoded names, never rendered
    // ones: two names that print the same and encode differently are two names.
    if (!bytesEqual(input.crl.issuer.der, input.certificate.issuer.der)) {
        out.push(revocationWrongIssuerReason(path));
    }

    if (input.signatureVerified !== true) {
        out.push(revocationUnknownReason(path, input.signatureVerified === false
            ? 'the list\'s signature did not verify against the key it was checked with'
            : 'the list\'s signature was never checked, and an unsigned list is something anyone can publish'));
    }

    // RFC 5280 §5.1.2.5 makes nextUpdate optional but tells CAs to include it.
    // A list without one has nothing asserting it is still current, so it is
    // stale by default rather than current by default.
    const tolerance = input.staleTolerance ?? 0;
    const nextUpdate = input.crl.nextUpdate?.epochMilliseconds;
    if (nextUpdate === undefined || input.at > nextUpdate + tolerance) {
        out.push(revocationStaleReason(path, nextUpdate, input.at));
    }

    // The lookup happens regardless of everything above. A list that is stale
    // or from the wrong CA still tells you something worth reporting when the
    // serial is on it, and hiding that behind an earlier failure would be the
    // one direction of error that matters.
    const entry = findRevocation(input.crlDer, input.certificate.serialNumber.bytes, input.options);
    if (entry !== undefined) {
        out.push(revokedReason(path, entry.revocationDate.epochMilliseconds, entry.reason));
    }
    return out;
}
