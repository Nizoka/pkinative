/**
 * pkinative — the RFC 5280 clause table (conformance level L5)
 * ============================================================
 * L1–L4 are all **differential**: they prove agreement, not correctness. If
 * pkinative, OpenSSL and `node:crypto` were all wrong in the same way, L3
 * would be green. And a red L1 says *"certificate `ab3f…` was refused and the
 * baseline says otherwise"* — a regression detector, not an authority.
 *
 * L5 makes the claim that is missing, and it is a claim about **attribution**:
 * clause by clause, which sentence of RFC 5280 a certificate violates, and
 * whether pkinative says so. Today a red run says a certificate changed
 * behaviour. L5 says: *"RFC 5280 §4.2.1.9 is violated by 14 certificates of
 * the corpus; pkinative diagnoses 13 and is silent on one."*
 *
 * Three properties hold this table honest, and the runner
 * (`scripts/validators/rfc5280-clauses.ts`) asserts all three:
 *
 *   1. **Every clause is applicable to at least one corpus certificate.** A
 *      clause nothing exercises proves nothing, and a checker full of them
 *      produces a number instead of evidence.
 *   2. **Every `fail` is accounted for** — by a matching pkinative diagnostic,
 *      or by a waiver written here with a reason.
 *   3. **Where a clause names a `diagnostic`, pkinative's diagnostic fires
 *      exactly when the clause fails.** This is what ties the checker to the
 *      product instead of leaving it a parallel implementation that drifts.
 *
 * Every entry quotes the normative sentence it enforces. A clause whose
 * `quote` cannot be found in the RFC is a clause someone invented.
 *
 * @module scripts/lib/clauses
 */

/** What a clause decided about one certificate. */
export type Verdict = 'pass' | 'fail' | 'not-applicable';

export interface Clause {
    /** Stable, sortable: `<section>-<what it requires>`. */
    readonly id: string;
    /** The document and section, as it is cited in messages and diagnostics. */
    readonly section: string;
    /** The normative sentence, quoted. Not a paraphrase. */
    readonly quote: string;
    /**
     * The `PkiDiagnosticCode` that must fire exactly when this clause fails,
     * or `null` when pkinative reports the violation another way. A `null`
     * requires a `waiver`.
     */
    readonly diagnostic: string | null;
    /** Why there is no diagnostic. Required when `diagnostic` is null. */
    readonly waiver?: string;
    /**
     * Substrings of the diagnostic's `path` that belong to this clause, when
     * one code is emitted from several places. `PKI_DIAG_DEFAULT_ENCODED`
     * fires for an explicit `version v1`, an explicit `critical FALSE`, an
     * explicit `cA FALSE` and a subtree `minimum 0`; a clause that checks one
     * of them must not claim the others.
     */
    readonly paths?: readonly string[];
    /**
     * `true` when this clause claims to decide **every** case in which its
     * diagnostic (within `paths`) may fire, so the runner may also assert the
     * converse: a diagnostic with no clause failure behind it is a
     * disagreement between the two readings, and one of them is wrong.
     *
     * `false` where the independent checker deliberately covers a subset —
     * named-bit trimming, for instance, is checked on `keyUsage` only, while
     * pkinative checks it wherever a named bit list appears. Claiming
     * exhaustiveness there would make the gate red for a correct diagnostic.
     */
    readonly exhaustive: boolean;
    /**
     * A reviewed statement that the **pinned corpus contains no certificate**
     * this clause applies to, naming the suite that exercises it instead.
     *
     * A clause nothing triggers proves nothing, so the default is that the
     * corpus must exercise it. But x509-limbo is a path-validation corpus: it
     * has no certificate carrying a unique identifier, and none with a
     * multi-valued RDN, because neither matters to the question it was built
     * to ask. Dropping those clauses would shrink the table to whatever one
     * corpus happens to contain; pretending they are exercised would be a
     * lie. Naming the test that does exercise them is the third option, and
     * the only honest one.
     */
    readonly unexercisedBy?: { readonly corpus: string; readonly reason: string; readonly provenBy: string };
}

/**
 * RFC 5280 §4.1 and §4.2, as far as a **reading** library can check without
 * path validation. §6 doubles this table and arrives with 0.5.
 *
 * Deliberately absent, and why:
 *
 * - *"A certificate MUST NOT include more than one instance of a particular
 *   extension"* (§4.2) is **structural** here, not a profile concern:
 *   `parseCertificate` throws `PKI_X509_DUPLICATE_EXTENSION`. A clause whose
 *   violation cannot produce a parsed certificate has nothing to diagnose.
 * - Everything requiring an issuer, a trust anchor or a clock — key usage
 *   consistency across a chain, name constraints, policy trees — is §6.
 */
export const CLAUSES: readonly Clause[] = Object.freeze([
    // ── §4.1 — the envelope ──
    {
        id: '4.1.2.2-serial-positive',
        section: 'RFC 5280 §4.1.2.2',
        quote: 'The serial number MUST be a positive integer assigned by the CA to each certificate.',
        diagnostic: 'PKI_DIAG_SERIAL_NOT_POSITIVE',
        exhaustive: true,
    },
    {
        id: '4.1.2.2-serial-at-most-20-octets',
        section: 'RFC 5280 §4.1.2.2',
        quote: 'Certificate users MUST be able to handle serialNumber values up to 20 octets.',
        diagnostic: 'PKI_DIAG_SERIAL_TOO_LONG',
        exhaustive: true,
    },
    {
        id: '4.1.1.2-signature-algorithm-matches-tbs',
        section: 'RFC 5280 §4.1.1.2',
        quote: 'This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate.',
        diagnostic: 'PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH',
        exhaustive: true,
    },
    {
        id: '4.1.2.1-extensions-require-v3',
        section: 'RFC 5280 §4.1.2.1',
        quote: 'If the certificate contains an issuerUniqueID or a subjectUniqueID then the version MUST be 2 or 3. If the certificate contains extensions, the version MUST be 3.',
        diagnostic: 'PKI_DIAG_EXTENSIONS_REQUIRE_V3',
        exhaustive: true,
    },
    {
        id: '4.1.2.8-unique-id-requires-v2',
        section: 'RFC 5280 §4.1.2.8',
        quote: 'These fields MUST only appear if the version is 2 or 3.',
        diagnostic: 'PKI_DIAG_UNIQUE_ID_REQUIRES_V2',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries an issuerUniqueID or a subjectUniqueID; they were deprecated before the corpus was assembled and play no part in path validation, which is the question x509-limbo was built to ask',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.1.2.5-generalized-time-only-from-2050',
        section: 'RFC 5280 §4.1.2.5',
        quote: 'CAs conforming to this profile MUST always encode certificate validity dates through the year 2049 as UTCTime; certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime.',
        diagnostic: 'PKI_DIAG_GENERALIZED_TIME_BEFORE_2050',
        exhaustive: true,
    },
    {
        id: '4.1.2.5.2-generalized-time-no-fraction',
        section: 'RFC 5280 §4.1.2.5.2',
        quote: 'GeneralizedTime values MUST NOT include fractional seconds.',
        diagnostic: 'PKI_DIAG_GENERALIZED_TIME_FRACTION',
        exhaustive: true,
    },
    {
        id: '4.1.2.4-issuer-not-empty',
        section: 'RFC 5280 §4.1.2.4',
        quote: 'The issuer field MUST contain a non-empty distinguished name (DN).',
        diagnostic: 'PKI_DIAG_EMPTY_ISSUER',
        exhaustive: true,
    },

    // ── §4.2 — the extension envelope ──
    {
        id: '4.2-critical-default-absent',
        section: 'ITU-T X.690 §11.5',
        quote: 'The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.',
        diagnostic: 'PKI_DIAG_DEFAULT_ENCODED',
        exhaustive: true,
    },
    {
        id: '4.2.1.9-path-len-requires-ca',
        section: 'RFC 5280 §4.2.1.9',
        quote: 'CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted and the key usage extension asserts the keyCertSign bit.',
        diagnostic: 'PKI_DIAG_PATHLEN_WITHOUT_CA',
        exhaustive: true,
    },
    {
        id: '4.2.1.3-key-usage-not-empty',
        section: 'RFC 5280 §4.2.1.3',
        quote: 'When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1.',
        diagnostic: 'PKI_DIAG_KEY_USAGE_EMPTY',
        exhaustive: true,
    },
    {
        id: '4.2.1.6-alt-name-not-empty',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'If the subjectAltName extension is present, the sequence MUST contain at least one entry.',
        diagnostic: 'PKI_DIAG_SAN_EMPTY',
        exhaustive: true,
    },
    {
        id: '4.2.1.10-name-constraints-critical',
        section: 'RFC 5280 §4.2.1.10',
        quote: 'Conforming CAs MUST mark this extension as critical.',
        diagnostic: 'PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.11-policy-constraints-not-empty',
        section: 'RFC 5280 §4.2.1.11',
        quote: 'Conforming CAs MUST NOT issue certificates where policy constraints is an empty sequence.',
        diagnostic: 'PKI_DIAG_POLICY_CONSTRAINTS_EMPTY',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-policies-not-duplicated',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'A certificate policy OID MUST NOT appear more than once in a certificate policies extension.',
        diagnostic: 'PKI_DIAG_POLICY_DUPLICATE',
        exhaustive: true,
    },
    {
        id: '4.2.1.1-aki-issuer-and-serial-paired',
        section: 'RFC 5280 §4.2.1.1',
        quote: 'The identification MAY be based on either the key identifier (the subject key identifier in the issuer\'s certificate) or the issuer name and serial number.',
        diagnostic: 'PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED',
        exhaustive: true,
    },

    // ── X.690, where the profile inherits the encoding rules ──
    {
        id: 'x690-11.6-rdn-set-sorted',
        section: 'ITU-T X.690 §11.6',
        quote: 'The encodings of the component values of a set-of value shall appear in ascending order.',
        diagnostic: 'PKI_DIAG_RDN_SET_NOT_SORTED',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a multi-valued relative distinguished name, so no SET OF in a Name has two components to order',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: 'x690-11.2.2-named-bits-trimmed',
        section: 'ITU-T X.690 §11.2.2',
        quote: 'Where ITU-T Rec. X.680 | ISO/IEC 8824-1, 22.7, applies, the bitstring shall have all trailing 0 bits removed before it is encoded.',
        diagnostic: 'PKI_DIAG_NAMED_BITS_TRAILING_ZERO',
        exhaustive: true,
    },
    {
        id: '4.1.2.6-empty-subject-requires-critical-san',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical.',
        diagnostic: 'PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL',
        exhaustive: true,
    },
]);

/** Every clause id, for the completeness rule and the runner's bookkeeping. */
export const CLAUSE_IDS: readonly string[] = CLAUSES.map((c) => c.id);
