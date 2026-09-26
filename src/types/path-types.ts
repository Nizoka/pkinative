/**
 * pkinative — Certification path types
 * ====================================
 * What RFC 5280 §6 takes and what it gives back.
 *
 * The shape of the input is the design decision worth reading: path
 * validation takes **signature results that have already been computed**,
 * never a key and never a Web Crypto handle. Three things follow from that,
 * and all three are the point:
 *
 *   - §6 stays **synchronous**. Putting `subtle.verify` inside it would make
 *     the whole state machine asynchronous, unfuzzable without a host, and
 *     would mix an I/O-shaped failure with a logical one.
 *   - §6 stays **pure**. It reads data and returns a verdict; it reaches
 *     nothing.
 *   - The signatures can be checked **in parallel**, before the walk, which
 *     is what a verifier should do anyway.
 *
 * @module types/path-types
 */

import type { PkiReason } from './pki-reasons.js';
import type { Certificate } from './x509-types.js';
import type { PkiLimits } from './pki-types.js';

/**
 * Whether one certificate's signature was checked against its issuer, and
 * what came of it.
 *
 * `'not-checked'` is a third state and not a synonym for `false`: a runtime
 * without Web Crypto, or one that refuses Ed448, says nothing about whether
 * the signature is good. Collapsing it into `false` would turn "ask me
 * elsewhere" into "this certificate is bad".
 */
export type SignatureVerdict = 'valid' | 'invalid' | 'not-checked';

/** One already-computed signature result, keyed by the certificate it covers. */
export interface SignatureResult {
    /** The certificate whose signature was checked. Matched by `der` identity. */
    readonly certificate: Certificate;
    /** What came of checking it. `not-checked` is not a synonym for `invalid`. */
    readonly verdict: SignatureVerdict;
    /** For `'not-checked'`: the `PkiCryptoError.code` that explains why. */
    readonly errorCode?: string | undefined;
    /** For `'not-checked'`: the error's own message. */
    readonly detail?: string | undefined;
}

/** What to validate, and everything needed to judge it. */
export interface PathValidationInput {
    /**
     * The chain, **leaf first**, as parsed certificates. The trust anchor may
     * be the last element or supplied only in `trustAnchors`; both are
     * accepted, because a server sends the chain both ways in practice.
     */
    readonly certificates: readonly Certificate[];
    /**
     * The certificates the caller trusts a priori. An empty list is accepted
     * and always produces `PKI_REASON_NO_TRUST_ANCHOR`: a chain with no
     * anchor is not valid, and refusing to run would hide that answer behind
     * an exception.
     */
    readonly trustAnchors: readonly Certificate[];
    /** The instant to validate at, in epoch milliseconds. */
    readonly at: number;
    /**
     * Signature verdicts computed beforehand — by `verifyCertificateSignature`,
     * or by whatever the caller trusts. A certificate with no entry is
     * reported as `PKI_REASON_SIGNATURE_NOT_CHECKED`, never assumed valid.
     */
    readonly signatures?: readonly SignatureResult[] | undefined;
    /** Overrides for any subset of `DEFAULT_PKI_LIMITS`. */
    readonly limits?: Partial<PkiLimits> | undefined;
}

/**
 * The verdict, and every reason behind it.
 *
 * `valid` is `true` only when `reasons` is empty. They are not two
 * independent fields: a report that said `valid: true` while listing reasons
 * would be two answers to one question.
 */
export interface PathValidationReport {
    /** True only when `reasons` is empty; the two are one answer, not two. */
    readonly valid: boolean;
    /**
     * Every reason the answer is no, not just the first. A certificate can be
     * expired *and* issued by something that is not a CA, and a caller fixing
     * one at a time is a caller making several round trips to learn what a
     * single report could have told them.
     */
    readonly reasons: readonly PkiReason[];
    /**
     * The path actually walked, leaf first, ending at the trust anchor when
     * one was reached. Shorter than `certificates` when the walk stopped.
     */
    readonly path: readonly Certificate[];
}
