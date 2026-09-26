/**
 * pkinative — Validation reason factories
 * =======================================
 * One factory per `PkiReasonCode`, the mirror of `core/pki-diagnostics.ts`,
 * and for the same purpose: the message that reaches a caller is written
 * once, here, rather than assembled at each call site where it would drift.
 *
 * Unlike a diagnostic, a reason is never emitted, never escalated and never
 * printed. It is **returned**, inside a report the caller reads. Nothing in
 * this module touches `console`, and nothing in it throws — a module whose
 * job is to explain a "no" must not be able to produce one of its own.
 *
 * The messages do not carry the `pkinative: ` prefix. That prefix marks what
 * is thrown, `reason-parity` refuses it here, and keeping it exclusive is
 * what lets a log reader tell an exception from a verdict.
 *
 * @module core/pki-reasons
 */

import type { PkiReason, PkiReasonCode } from '../types/pki-reasons.js';

function _reason(code: PkiReasonCode, standard: string, message: string, path: string, extra?: { errorCode?: string; limit?: string }): PkiReason {
    return Object.freeze({ code, message, standard, path, errorCode: extra?.errorCode, limit: extra?.limit });
}

/**
 * The bytes are not the structure they claim to be.
 *
 * This is the one factory that reaches into the error vocabulary, and it is
 * how a non-throwing report stays honest without a second copy of 47
 * encoding codes: the `PkiErrorCode` that *would* have been thrown travels
 * in `errorCode`, so a caller who wants the detail has it, and a caller who
 * only wants a verdict is not made to catch anything.
 *
 * @param errorCode The `PkiError.code` the parser raised.
 * @param detail    The parser's own message, already specific.
 * @param path      Where in the input, e.g. `path[1]`.
 * @returns The reason.
 */
export function inputMalformedReason(errorCode: string, detail: string, path: string): PkiReason {
    return _reason('PKI_REASON_INPUT_MALFORMED', 'ITU-T X.690',
        `the input could not be read as the structure it claims to be (${errorCode}): ${detail.replace(/^pkinative: /, '')}`,
        path, { errorCode });
}

/** The validation instant is before `notBefore`. */
export function notYetValidReason(path: string, notBefore: number, at: number): PkiReason {
    return _reason('PKI_REASON_NOT_YET_VALID', 'RFC 5280 §6.1.3 (a)(2)',
        `the certificate is not valid until ${new Date(notBefore).toISOString()}, and validation was asked for ${new Date(at).toISOString()}`,
        path);
}

/** The validation instant is after `notAfter`. */
export function expiredReason(path: string, notAfter: number, at: number): PkiReason {
    return _reason('PKI_REASON_EXPIRED', 'RFC 5280 §6.1.3 (a)(2)',
        `the certificate expired on ${new Date(notAfter).toISOString()}, and validation was asked for ${new Date(at).toISOString()}`,
        path);
}

/** A critical extension nothing here recognises. RFC 5280 requires refusal, not tolerance. */
export function unrecognisedCriticalExtensionReason(path: string, oid: string): PkiReason {
    return _reason('PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION', 'RFC 5280 §6.1.3 (f)',
        `the certificate carries the critical extension ${oid}, which this implementation does not recognise; a verifier must refuse rather than ignore it`,
        path);
}

/**
 * A name falls outside what a CA above this certificate permitted.
 *
 * The message names the form and the value, because "a name is not
 * permitted" without saying which name is a report nobody can act on — and
 * the whole point of a name constraint is that one specific name is wrong.
 */
export function nameNotPermittedReason(path: string, form: string, text: string): PkiReason {
    return _reason('PKI_REASON_NAME_NOT_PERMITTED', 'RFC 5280 §6.1.3 (b)',
        `the ${form} "${text}" falls outside the permitted subtrees a CA above this certificate set; a sub-CA cannot issue for names its issuer withheld`,
        path);
}

/** A name falls inside a subtree a CA above this certificate excluded. */
export function nameExcludedReason(path: string, form: string, text: string): PkiReason {
    return _reason('PKI_REASON_NAME_EXCLUDED', 'RFC 5280 §6.1.3 (c)',
        `the ${form} "${text}" falls inside an excluded subtree; an exclusion anywhere on the path wins over every permission`,
        path);
}

/** No supplied candidate has a subject equal to this certificate's issuer. */
export function issuerNotFoundReason(path: string, issuer: string): PkiReason {
    return _reason('PKI_REASON_ISSUER_NOT_FOUND', 'RFC 5280 §6.1',
        `no supplied certificate has the subject ${issuer}, so this certificate has no issuer to check it against`,
        path);
}

/** The issuer's key does not verify this signature. A verdict, not an incident. */
export function signatureInvalidReason(path: string): PkiReason {
    return _reason('PKI_REASON_SIGNATURE_INVALID', 'RFC 5280 §6.1.3 (a)(1)',
        'the issuer\'s public key does not verify this certificate\'s signature',
        path);
}

/**
 * The signature could not be checked at all.
 *
 * Never a verdict about the certificate: a runtime without Web Crypto, or
 * one that refuses Ed448, says nothing about whether the signature is good.
 * Reporting it as `PKI_REASON_SIGNATURE_INVALID` would turn "ask me
 * elsewhere" into "this certificate is bad", which is the single most
 * expensive confusion in this whole vocabulary.
 */
export function signatureNotCheckedReason(path: string, errorCode: string, detail: string): PkiReason {
    return _reason('PKI_REASON_SIGNATURE_NOT_CHECKED', 'RFC 5280 §6.1.3 (a)(1)',
        `the signature could not be checked here (${errorCode}): ${detail.replace(/^pkinative: /, '')} — this says nothing about whether the signature is valid`,
        path, { errorCode });
}

/** The chain does not end at a trust anchor the caller supplied. */
export function noTrustAnchorReason(path: string): PkiReason {
    return _reason('PKI_REASON_NO_TRUST_ANCHOR', 'RFC 5280 §6.1.1 (d)',
        'the chain does not end at any of the trust anchors supplied; a signature that verifies is not a certificate that is trusted',
        path);
}

/** An issuing certificate is not allowed to issue. */
export function notACaReason(path: string, why: 'basicConstraints' | 'keyUsage'): PkiReason {
    return _reason('PKI_REASON_NOT_A_CA', 'RFC 5280 §6.1.4 (k)',
        why === 'basicConstraints'
            ? 'a certificate in the chain issued another without asserting cA in basicConstraints'
            : 'a certificate in the chain issued another without asserting keyCertSign in keyUsage',
        path);
}

/** A `pathLenConstraint`, or the caller's own bound, is exceeded. */
export function pathTooLongReason(path: string, allowed: number): PkiReason {
    return _reason('PKI_REASON_PATH_TOO_LONG', 'RFC 5280 §6.1.4 (l)',
        `the chain is longer than the ${String(allowed)} intermediate certificate(s) a pathLenConstraint in it allows`,
        path);
}

/** The same certificate appears twice. */
export function pathLoopsReason(path: string): PkiReason {
    return _reason('PKI_REASON_PATH_LOOPS', 'RFC 5280 §6.1',
        'the same certificate appears twice in the chain; a path that revisits a certificate is not a path',
        path);
}

/**
 * A named limit stopped the search.
 *
 * Reported rather than thrown, because reaching a bound while judging a
 * chain is an answer about that chain — "I will not spend more than this on
 * you" — and a caller who raised the bound deliberately gets to see which
 * one they would have to raise again.
 */
export function limitExceededReason(path: string, limit: string, configured: number): PkiReason {
    return _reason('PKI_REASON_LIMIT_EXCEEDED', 'CWE-400',
        `validation stopped at the ${limit} limit of ${String(configured)}; raise it only for input you trust`,
        path, { limit });
}
