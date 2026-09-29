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
    /** No name in the certificate matches the host or address the caller asked about. */
    | 'PKI_REASON_NAME_MISMATCH'
    /** A certificate on the path does not permit the purpose the caller needs (RFC 5280 §4.2.1.12). */
    | 'PKI_REASON_PURPOSE_NOT_PERMITTED'
    /** A critical extension no implementation here recognises; RFC 5280 §6.1.3 requires refusal. */
    | 'PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION'
    /** A name in the certificate falls outside the name constraints a CA above it set. */
    | 'PKI_REASON_NAME_NOT_PERMITTED'
    /** A name in the certificate falls inside a subtree a CA above it excluded. */
    | 'PKI_REASON_NAME_EXCLUDED'
    // ── Revocation ──
    /** The certificate is listed in a revocation list that covers it. */
    | 'PKI_REASON_REVOKED'
    /** The revocation list is older than the caller allows, or its nextUpdate has passed. */
    | 'PKI_REASON_REVOCATION_STALE'
    /** The revocation list was not issued by the certificate's issuer. */
    | 'PKI_REASON_REVOCATION_WRONG_ISSUER'
    /** The list comes from the right CA but declares a scope that excludes this certificate. */
    | 'PKI_REASON_REVOCATION_OUT_OF_SCOPE'
    /** The list covers only some revocation reasons, so its silence rules out only those. */
    | 'PKI_REASON_REVOCATION_PARTIAL'
    /** Revocation could not be established at all — no list, or an unverified one. */
    | 'PKI_REASON_REVOCATION_UNKNOWN'
    /** The revocation answer is about a different certificate, or does not echo the nonce that was sent. */
    | 'PKI_REASON_REVOCATION_MISMATCH'

    /** No certificate policy survives the path, and an explicit policy was required. */
    | 'PKI_REASON_NO_VALID_POLICY'
    /** A `policyMappings` extension maps to or from `anyPolicy`, which RFC 5280 forbids. */
    | 'PKI_REASON_POLICY_MAPPING_INVALID'

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

    // ── Signed messages (RFC 5652) ──
    /** The SignedData has no signer, so it signs nothing — a certificate bundle, not a signature. */
    | 'PKI_REASON_CMS_NO_SIGNERS'
    /** No available certificate matches the signer's identifier. */
    | 'PKI_REASON_CMS_SIGNER_NOT_FOUND'
    /** The content is detached and was not supplied, so there is nothing to check the signature against. */
    | 'PKI_REASON_CMS_CONTENT_MISSING'
    /** The content does not hash to the digest the signer committed to in `messageDigest`. */
    | 'PKI_REASON_CMS_DIGEST_MISMATCH'
    /** A signed attribute the syntax requires is missing, repeated, multi-valued, wrongly unsigned, or has the wrong value. */
    | 'PKI_REASON_CMS_ATTRIBUTE_INVALID'
    /** The algorithms the signer names disagree with each other, or one is refused outright. */
    | 'PKI_REASON_CMS_ALGORITHM_MISMATCH'
    /** The signing-certificate attribute commits to a different certificate from the one that verifies. */
    | 'PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH'

    // ── Timestamps (RFC 3161) ──
    /** The timestamp authority declined the request; the response carries no token. */
    | 'PKI_REASON_TSP_NOT_GRANTED'
    /** The token breaks a rule RFC 3161 sets for tokens: more than one signer, the wrong content, a `tsa` name its signer does not hold. */
    | 'PKI_REASON_TSP_TOKEN_INVALID'
    /** The token stamps a different hash from the one the caller holds. */
    | 'PKI_REASON_TSP_IMPRINT_MISMATCH'
    /** The token does not answer the request that was sent: its nonce or its policy differ. */
    | 'PKI_REASON_TSP_REQUEST_MISMATCH'

    // ── PKCS#12 (RFC 7292, RFC 9579) ──
    /** A key or a bag of certificates is encrypted with a scheme pkinative refuses: anything but PBES2 with PBKDF2 and AES-CBC. */
    | 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED'
    /** The container's integrity could not be checked: its MAC uses the RFC 7292 Appendix B KDF, or it has none. */
    | 'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED'
    /** The RFC 9579 MAC does not match: the password is wrong, or the container was altered. */
    | 'PKI_REASON_PKCS12_MAC_MISMATCH'
    /** A key or a bag of certificates would not decrypt under the password. */
    | 'PKI_REASON_PKCS12_DECRYPTION_FAILED'
    /** A key shares its `localKeyId` with no certificate, so what kind of key it is cannot be known before decrypting it. */
    | 'PKI_REASON_PKCS12_KEY_UNMATCHED'
    /** A key is of a kind this runtime or pkinative cannot import. */
    | 'PKI_REASON_PKCS12_KEY_UNSUPPORTED'

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
