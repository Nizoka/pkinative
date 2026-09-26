/**
 * pkinative — Validation reasons
 * ==============================
 * The third vocabulary, and the one that decides how every composed
 * operation from 0.5 onwards reports itself.
 *
 * | Vocabulary | The question it answers | How it travels |
 * |---|---|---|
 * | `PkiErrorCode` | "Is this the structure it claims to be, and is the API being used correctly?" — **no** | thrown |
 * | `PkiDiagnosticCode` | "It is that structure, but it deviates from a profile." — about **one object** | emitted |
 * | `PkiReasonCode` | "The input is well formed, and the **judgement** you asked for is *no* — here is why." — about a **relation** | **returned**, in a report |
 *
 * **Why neither existing registry can do this.** A validation produces
 * *several* reasons at once — expired **and** revoked **and** outside a name
 * constraint — where an exception carries one. And the error vocabulary
 * freezes at 0.8: validation reasons, by contrast, grow for as long as the
 * PKI does. On the diagnostics side the severity model is wrong for a
 * verdict, and `strict: true` would turn "this certificate is revoked" into
 * a thrown `PKI_STRICT_DIAGNOSTIC` — exactly what a non-throwing report must
 * never do.
 *
 * **The rule this establishes, and that every later layer follows:**
 *
 * > Primitives return and throw. Compositions report. Exactly one layer
 * > converts — `verify` — and it is the only place in `src/` that catches a
 * > `PkiError`.
 *
 * `PKI_REASON_INPUT_MALFORMED` is what makes that affordable: it carries in
 * its `errorCode` field the `PkiErrorCode` that *would* have been thrown. So
 * "a report never throws for a malformed input" is kept **without copying
 * forty-seven encoding codes into a second registry**. The firm rule is:
 * *the reason registry never duplicates the error registry, it wraps it.*
 *
 * Reason messages deliberately do **not** start with `pkinative: `. That
 * prefix marks what is thrown, and keeping it exclusive is what lets someone
 * reading a log tell an exception from a verdict.
 *
 * @module types/pki-reasons
 */

/**
 * Why a validation said no.
 *
 * Additions are semver-minor and expected: unlike `PkiErrorCode`, this
 * vocabulary is **not** frozen at 0.8, because the set of reasons a chain can
 * be rejected grows with the standards. Removals and renames are major.
 */
export type PkiReasonCode =
    // ── The input, wrapped rather than duplicated ──
    /** The bytes are not the structure they claim to be. `errorCode` carries the `PkiErrorCode` that would have been thrown. */
    | 'PKI_REASON_INPUT_MALFORMED'

    // ── The certificate, on its own ──
    /** The validation instant is before `notBefore`. */
    | 'PKI_REASON_NOT_YET_VALID'
    /** The validation instant is after `notAfter`. */
    | 'PKI_REASON_EXPIRED'
    /** A critical extension no implementation here recognises; RFC 5280 §6.1.3 requires refusal. */
    | 'PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION'
    /** A name in the certificate falls outside the name constraints a CA above it set. */
    | 'PKI_REASON_NAME_NOT_PERMITTED'
    /** A name in the certificate falls inside a subtree a CA above it excluded. */
    | 'PKI_REASON_NAME_EXCLUDED'

    // ── The link to the issuer ──
    /** No candidate issuer was supplied whose subject matches this certificate's issuer. */
    | 'PKI_REASON_ISSUER_NOT_FOUND'
    /** The issuer's key does not verify this certificate's signature. */
    | 'PKI_REASON_SIGNATURE_INVALID'
    /** The signature could not be checked at all — this runtime has no Web Crypto, or refuses the algorithm. Never a verdict about the certificate. */
    | 'PKI_REASON_SIGNATURE_NOT_CHECKED'

    // ── The chain ──
    /** The chain does not end at a supplied trust anchor. */
    | 'PKI_REASON_NO_TRUST_ANCHOR'
    /** An issuing certificate is not a CA, or its keyUsage does not assert keyCertSign. */
    | 'PKI_REASON_NOT_A_CA'
    /** A `pathLenConstraint`, or the caller's own bound, is exceeded. */
    | 'PKI_REASON_PATH_TOO_LONG'
    /** The same certificate appears twice in the path. */
    | 'PKI_REASON_PATH_LOOPS'

    // ── The caller's limits, reached while judging ──
    /** A named `PkiLimits` bound stopped the search. `limit` names it. */
    | 'PKI_REASON_LIMIT_EXCEEDED';

/**
 * One reason a validation said no.
 *
 * Several are reported together whenever several apply: a certificate can be
 * expired *and* outside a name constraint, and a report that stopped at the
 * first would hide the work still to do.
 */
export interface PkiReason {
    /** Which reason this is. Branch on it; the message is for people. */
    readonly code: PkiReasonCode;
    /**
     * What happened and what the caller can do about it. It does **not**
     * begin with `pkinative: ` — that prefix belongs to thrown errors, and a
     * log reader tells the two apart by it.
     */
    readonly message: string;
    /** The clause that decides the case, e.g. `RFC 5280 §6.1.3`. */
    readonly standard: string;
    /** Where in the input, e.g. `path[1].tbsCertificate.validity`. */
    readonly path: string;
    /**
     * For `PKI_REASON_INPUT_MALFORMED` only: the code that would have been
     * thrown. This is how the reason registry wraps the error registry
     * instead of copying it.
     */
    readonly errorCode?: string | undefined;
    /** For `PKI_REASON_LIMIT_EXCEEDED` only: the `PkiLimits` key that stopped the search. */
    readonly limit?: string | undefined;
}
