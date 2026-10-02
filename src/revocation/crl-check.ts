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
 * `PKI_REASON_REVOKED` — listed, by a list entitled to say so: this
 * certificate's issuer's, covering it, with a verified signature. Carries the
 * date, because a signature made before the revocation instant may still be
 * good and the caller deciding that needs the date. A listing on any other
 * list is not evidence and never becomes this code.
 *
 * `PKI_REASON_REVOCATION_STALE` / `..._WRONG_ISSUER` / `..._OUT_OF_SCOPE` — the
 * list cannot answer for this certificate. An out-of-date list says what was
 * revoked *then*; a list from another CA says nothing at all; and a list from
 * the right CA whose `issuingDistributionPoint` excludes this certificate says
 * nothing *about this certificate*, which is the one of the three that looks
 * like a clean answer if you do not read §5.2.5.
 *
 * `PKI_REASON_REVOCATION_UNKNOWN` — no evidence either way. This is the answer
 * a soft-fail policy acts on, and it is deliberately **not** the same as "not
 * revoked": a validator that reported silence as a clean bill of health would
 * make the soft-fail decision on the caller's behalf, invisibly.
 *
 * @module revocation/crl-check
 */

import {
    revocationOutOfScopeReason,
    revocationPartialReason,
    revocationStaleReason,
    revocationUnknownReason,
    revocationWrongIssuerReason,
    revokedReason,
    unknownCriticalExtensionReason,
} from '../core/pki-reasons.js';
import type { CertificateList } from '../types/crl-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { PkiDiagnosticHandler, PkiLimits } from '../types/pki-types.js';
import type { Certificate } from '../types/x509-types.js';
import { _unknownCriticalEntryExtension, findRevocation, type FindRevocationOptions } from './crl-parse.js';
import { _crlScopeProblem, _deltaApplies, type CrlScopeProblem } from './crl-scope.js';

/** What to check, and everything needed to judge it. */
export interface CheckRevocationInput {
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
    /**
     * A delta CRL (RFC 5280 §5.2.4) describing the changes since `crl`.
     *
     * Supplied here rather than checked separately because **the order of
     * consultation is the rule**: the delta is asked first and the base only
     * for a serial the delta says nothing about. A caller who asked the two
     * lists independently and merged the answers themselves would have to
     * rediscover that, and would have no way at all to act on the one entry
     * reason that exists only here — `removeFromCRL`, which withdraws a
     * revocation the base still records.
     *
     * A delta that does not apply to this base is ignored, not reported: the
     * pairing rule is `_deltaApplies`, and mismatched lists are the ordinary
     * result of handing over everything you hold.
     */
    readonly delta?: DeltaCrlInput | undefined;
    /** Overrides for any subset of `DEFAULT_PKI_LIMITS`, applied to the walk of the entries. */
    readonly limits?: Partial<PkiLimits> | undefined;
    /**
     * Receive every diagnostic the walk raises — an entry extension that is
     * malformed and dropped — instead of the default once-per-code
     * `console.warn`.
     */
    readonly onDiagnostic?: PkiDiagnosticHandler | undefined;
}

/** One delta CRL, and what is known about it. */
export interface DeltaCrlInput {
    /** The parsed delta. */
    readonly crl: CertificateList;
    /** The same bytes `parseCertificateList` was given. */
    readonly crlDer: Uint8Array;
    /**
     * Whether a key entitled to sign it did. An unverified delta is not applied
     * at all: a delta that anyone can publish could withdraw any revocation on
     * the base with one `removeFromCRL` entry, which is a strictly easier
     * attack than forging the base.
     */
    readonly signatureVerified?: boolean | undefined;
}

/**
 * The supplied delta, when it is one this base may be read with.
 *
 * Every condition is a way of being handed the wrong delta, and each is fatal
 * to the pairing rather than reported: a caller passing everything they hold is
 * the ordinary case. The signature is the one worth naming — an unverified
 * delta could withdraw any revocation on the base with a single
 * `removeFromCRL` entry, which is a strictly easier attack than forging the
 * base, so a delta nobody vouched for is not applied at all.
 */
function _applicableDelta(input: CheckRevocationInput): DeltaCrlInput | undefined {
    const delta = input.delta;
    if (delta === undefined || delta.signatureVerified !== true) return undefined;
    if (!_deltaApplies(input.crl, delta.crl)) return undefined;
    // Same scope, in the only sense that changes this answer: both lists have
    // to be entitled to speak about *this* certificate — and to speak at all,
    // which a delta with an unprocessed critical entry extension may not.
    if (_crlScopeProblem({ certificate: input.certificate, crl: delta.crl, asDelta: true }) !== null) return undefined;
    if (_unknownCriticalEntryExtension(delta.crlDer, _lookup(input)) !== undefined) return undefined;
    return delta;
}

/** The options of every walk over the entries of the lists in `input`. */
function _lookup(input: CheckRevocationInput): FindRevocationOptions {
    return { limits: input.limits, onDiagnostic: input.onDiagnostic, issuerDer: input.certificate.issuer.der };
}

/**
 * The list-level scope of `_crlScopeProblem`, then the entries: a list that
 * would cover the certificate is still unusable when any entry carries a
 * critical extension nothing here processes (RFC 5280 §5.3) — the same
 * `unusable` answer, so every reader of the scope treats the two alike.
 */
function _scope(input: CheckRevocationInput): CrlScopeProblem | null {
    const scope = _crlScopeProblem({ certificate: input.certificate, crl: input.crl });
    if (scope !== null) return scope;
    const oid = _unknownCriticalEntryExtension(input.crlDer, _lookup(input));
    return oid === undefined ? null : { kind: 'unusable', oid };
}

/**
 * What an unauthenticated source claims, worded as a claim: the detail of the
 * `PKI_REASON_REVOCATION_UNKNOWN` that carries a revocation nobody vouched for
 * (RFC 5280 §6.3.3 (g), RFC 6960 §3.2).
 *
 * @internal
 */
export function _unverifiedRevocation(source: 'list' | 'response', at: number, reason: string | undefined): string {
    return `the ${source} says this certificate was revoked on ${new Date(at).toISOString()} (${reason === undefined ? 'no reason given' : `reason: ${reason}`}), `
        + `but the ${source} is not authenticated, so that is a claim and not evidence`;
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
 * Only **one** list is consulted, and whether it is entitled to answer is
 * decided here: RFC 5280 §5.2.5 for what the list declares itself to be about,
 * §6.3.3 (b) for the agreement between the certificate's `cRLDistributionPoints`
 * and the list's own `issuingDistributionPoint`, including the indirect case.
 * A list that would answer and carries a critical extension nothing here
 * processes — on itself (§6.3.3) or on **any** entry (§5.3) — is
 * `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`, and nothing it lists is evidence.
 *
 * A **delta CRL** (§5.2.4) goes in `delta`, beside the complete list it
 * describes the changes since, and the two are read as one answer: the delta
 * first, the base only where the delta is silent. Passing a delta as `crl` is
 * refused instead — on its own it reports every certificate absent from it as
 * unrevoked, which is nearly all of them.
 *
 * Fetching the lists is still the caller's job. This library performs no I/O.
 *
 * @param input See {@link CheckRevocationInput}.
 * @returns Every reason the answer is not a clean "not revoked", in the order
 *   they were established; empty when the certificate is not revoked.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` for a malformed entry.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxRevokedCertificates`.
 */
export function checkRevocation(input: CheckRevocationInput): readonly PkiReason[] {
    const out: PkiReason[] = [];
    const path = 'crl';

    // Is this list even about this certificate? Two questions, and RFC 5280
    // answers them in two places: §6.3.3 (b)(1) asks who may have issued the
    // list — the certificate's own CA, or a cRLIssuer it delegates to — and
    // §5.2.5 asks what the list says it is about. Names are compared encoded,
    // never rendered: two names that print the same and encode differently are
    // two names. A list that would answer is then asked whether any of its
    // entries forbids using it at all (§5.3).
    const scope = _scope(input);
    if (scope?.kind === 'wrong-issuer') out.push(revocationWrongIssuerReason(path));
    if (scope?.kind === 'out-of-scope') out.push(revocationOutOfScopeReason(path, scope.why));
    // The same rule §6.1.3 (f) sets for a certificate, and the same code: a
    // critical extension nothing here recognises — on the list, or on any of
    // its entries — means the object does not mean what this implementation
    // would take it to mean.
    if (scope?.kind === 'unusable') out.push(unknownCriticalExtensionReason(path, scope.oid, 'revocation list'));

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

    // The lookup happens regardless of everything above, so a malformed entry
    // is refused whatever else is wrong with the list. What a listing *means*
    // is decided below: evidence only from a list that may speak.
    const serial = input.certificate.serialNumber.bytes;
    const lookup = _lookup(input);
    const delta = _applicableDelta(input);
    const changed = delta === undefined ? undefined : findRevocation(delta.crlDer, serial, lookup);

    // **The order is §5.2.4.** Where the delta speaks it is the newer truth;
    // where it is silent the base still holds. Nothing merges the two answers,
    // because there is only ever one.
    const entry = changed ?? findRevocation(input.crlDer, serial, lookup);

    // `removeFromCRL` (§5.3.1) is the one entry reason that means the opposite
    // of the list it sits on: only a delta may carry it, and it says the base
    // list's revocation has been withdrawn. So it does two things here, and
    // they are the same thing — it is not reported as a revocation, and because
    // it is the delta's answer the base is never asked. Reporting it would take
    // an un-revocation and answer "revoked (reason: removeFromCRL)", a sentence
    // that is wrong in both halves.
    //
    // **A listing is evidence only from a list entitled to make it.** RFC 5280
    // §6.3.3 consults a list only once (b) its issuer and scope are this
    // certificate's and (g) its signature is valid, and §5.2 forbids using a
    // list with a critical extension nothing here processes. Serial numbers are
    // unique per issuer (§4.1.2.2), so another CA's list naming the same serial
    // says nothing about this certificate, and a list nobody verified is one
    // anyone can write. Such a listing is not `REVOKED`, which a caller rightly
    // reads as "this certificate is revoked"; the reasons above already fail
    // the answer. A list whose only fault is its unverified signature is still
    // this CA's list about this certificate, so its claim is carried, as what
    // it is, in an `UNKNOWN`. A stale list that may speak still proves the
    // revocation: a revocation, once published, is not withdrawn by time.
    if (entry !== undefined && entry.reason !== 'removeFromCRL') {
        const revokedAt = entry.revocationDate.epochMilliseconds;
        if (scope === null && input.signatureVerified === true) out.push(revokedReason(path, revokedAt, entry.reason));
        else if (scope === null) out.push(revocationUnknownReason(path, _unverifiedRevocation('list', revokedAt, entry.reason)));
        return out;
    }

    // RFC 5280 §5.2.5 `onlySomeReasons`: a list that covers two reasons out of
    // nine has ruled out two. Reporting that as "not revoked" is the same
    // mistake as reporting an out-of-scope list that way, one step finer — and
    // it is the step a CA takes when it publishes a separate keyCompromise list
    // it can reissue faster than the rest.
    //
    // It is a **partial** answer and not an absent one, which matters one layer
    // up: §6.3.3 accumulates these into `reasons_mask`, and two lists that each
    // cover half answer completely between them. Only a caller holding both can
    // see that, so this says what it ruled out and leaves the addition to them.
    const covered = input.crl.issuingDistributionPoint?.onlySomeReasons;
    if (covered !== undefined) out.push(revocationPartialReason(path, covered.filter((reason) => reason !== 'unused')));
    return out;
}
