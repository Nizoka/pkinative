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
 * `quote` cannot be found in the RFC is a clause someone invented — and since
 * 0.9 that is checked: RFC 5280 is a pinned corpus (scripts/lib/corpora.ts),
 * every quote citing it must be found verbatim, after whitespace
 * normalisation, in the section it cites, and every requirement sentence of
 * §4.1 and §4.2 is accounted for in scripts/data/rfc5280-requirements.json —
 * as one of these clauses, or as an exclusion with its reason
 * (scripts/lib/rfc-requirements.ts). The three X.690 clauses quote
 * Recommendation ITU-T X.690 (02/2021), the edition the pki-core instructions
 * cite. ITU publishes it only as a PDF, whose text extraction is not stable
 * enough to pin, so those quotes were compared by hand with the text of
 * §11.2.2, §11.5 and §11.6 — whole sentences, word order included — and
 * tests/conformance/clauses.test.ts holds them to that reading.
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
 * path validation. §6 is not in this table: it is judged over chains, by the
 * scored corpora of L6, L7 and L8 (docs/adr/0008-section-6-judged-by-scored-corpora.md).
 *
 * Deliberately absent, and why:
 *
 * - *"A certificate MUST NOT include more than one instance of a particular
 *   extension"* (§4.2) is **structural** here, not a profile concern:
 *   `parseCertificate` throws `PKI_X509_EXTENSION_DUPLICATE`. A clause whose
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
        quote: 'Conforming CAs MUST NOT use serialNumber values longer than 20 octets.',
        diagnostic: 'PKI_DIAG_SERIAL_TOO_LONG',
        exhaustive: true,
    },
    {
        id: '4.1.1.2-signature-algorithm-matches-tbs',
        section: 'RFC 5280 §4.1.1.2',
        quote: 'This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate (Section 4.1.2.3).',
        diagnostic: 'PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH',
        exhaustive: true,
    },
    {
        id: '4.1.2.1-extensions-require-v3',
        section: 'RFC 5280 §4.1.2.1',
        quote: 'When extensions are used, as expected in this profile, version MUST be 3 (value is 2).',
        diagnostic: 'PKI_DIAG_EXTENSIONS_REQUIRE_V3',
        exhaustive: true,
    },
    {
        id: '4.1.2.8-unique-id-requires-v2',
        section: 'RFC 5280 §4.1.2.8',
        quote: 'These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).',
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
        quote: 'Conforming CAs MUST mark this extension as critical and SHOULD NOT impose name constraints on the x400Address, ediPartyName, or registeredID name forms.',
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
        quote: 'The encodings of the component values of a set-of value shall appear in ascending order, the encodings being compared as octet strings with the shorter components being padded at their trailing end with 0-octets.',
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
        quote: 'Where Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.7, applies, the bitstring shall have all trailing 0 bits removed before it is encoded.',
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

    // ── Since 0.9: requirements the RFC inventory found diagnosed and unrecorded ──
    // scripts/data/rfc5280-requirements.json accounts for every requirement
    // sentence of §4.1 and §4.2. Reading them against the diagnostics registry
    // found six that pkinative already reported and this table did not hold to
    // an independent reading; each is now a clause like the others.
    {
        id: '4.2.1.9-basic-constraints-critical-in-ca',
        section: 'RFC 5280 §4.2.1.9',
        quote: 'Conforming CAs MUST include this extension in all CA certificates that contain public keys used to validate digital signatures on certificates and MUST mark the extension as critical in such certificates.',
        // The second half is decidable from the bytes — a basicConstraints
        // that asserts cA is the certificate saying it is a CA certificate.
        // The first half is not: a certificate without the extension does not
        // say what its key will be used for.
        diagnostic: 'PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.11-policy-constraints-critical',
        section: 'RFC 5280 §4.2.1.11',
        quote: 'Conforming CAs MUST mark this extension as critical.',
        diagnostic: 'PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.3-key-cert-sign-requires-ca',
        section: 'RFC 5280 §4.2.1.3',
        quote: 'If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted.',
        diagnostic: 'PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA',
        exhaustive: true,
    },
    {
        id: '4.2.1.10-name-constraints-only-in-ca',
        section: 'RFC 5280 §4.2.1.10',
        quote: 'The name constraints extension, which MUST be used only in a CA certificate, indicates a name space within which all subject names in subsequent certificates in a certification path MUST be located.',
        diagnostic: 'PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY',
        exhaustive: true,
    },
    {
        id: '4.2.1.1-aki-key-identifier-present',
        section: 'RFC 5280 §4.2.1.1',
        quote: 'The keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs to facilitate certification path construction.',
        // §4.2.1.1 exempts a self-signed certificate, and equal encoded
        // issuer and subject is how both readings see one without a key
        // operation. A v1 or v2 certificate has no field to carry it in, and
        // is judged by 4.1.2.1 instead. The evaluator reads the sentence — the
        // keyIdentifier *field* — while the diagnostic fires on a missing
        // *extension*; no pinned certificate tells the two apart, and one
        // carrying an authorityKeyIdentifier without a keyIdentifier would
        // turn L5 red as a silent miss, which is what it would be.
        diagnostic: 'PKI_DIAG_AKI_MISSING',
        exhaustive: true,
    },
    {
        id: '4.2.1.2-ski-present-in-ca',
        section: 'RFC 5280 §4.2.1.2',
        quote: 'To facilitate certification path construction, this extension MUST appear in all conforming CA certificates, that is, all certificates including the basic constraints extension (Section 4.2.1.9) where the value of cA is TRUE.',
        diagnostic: 'PKI_DIAG_SKI_MISSING',
        exhaustive: true,
    },

    // ── Since 1.0: the 36 sentences the inventory recorded as not-diagnosed ──
    // Each was decidable from one certificate and unreported; each is now a
    // diagnostic, held here like the others. Two codes answer two sentences
    // each, because each pair states one fact: §4.2.1.4 asks for UTF8String
    // (IA5String allowed) and forbids VisibleString and BMPString, and those
    // two are the only DisplayText types that break either sentence; §4.2.2.1
    // and §4.2.2.2 state the LDAP URI requirement in one identical sentence,
    // and the path of PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE names the
    // extension, which is what `paths` separates.
    {
        id: '4.1.2.8-no-unique-ids',
        section: 'RFC 5280 §4.1.2.8',
        quote: 'CAs conforming to this profile MUST NOT generate certificates with unique identifiers.',
        diagnostic: 'PKI_DIAG_UNIQUE_ID_PRESENT',
        exhaustive: true,
    },
    {
        id: '4.2.1.1-aki-not-critical',
        section: 'RFC 5280 §4.2.1.1',
        quote: 'Conforming CAs MUST mark this extension as non-critical.',
        diagnostic: 'PKI_DIAG_AKI_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.2-ski-in-end-entity',
        section: 'RFC 5280 §4.2.1.2',
        quote: 'To assist applications in identifying the appropriate end entity certificate, this extension SHOULD be included in all end entity certificates.',
        diagnostic: 'PKI_DIAG_SKI_MISSING_END_ENTITY',
        exhaustive: true,
    },
    {
        id: '4.2.1.2-ski-not-critical',
        section: 'RFC 5280 §4.2.1.2',
        quote: 'Conforming CAs MUST mark this extension as non-critical.',
        diagnostic: 'PKI_DIAG_SKI_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.3-key-usage-critical',
        section: 'RFC 5280 §4.2.1.3',
        quote: 'When present, conforming CAs SHOULD mark this extension as critical.',
        diagnostic: 'PKI_DIAG_KEY_USAGE_NOT_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-any-policy-qualifiers',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section.',
        diagnostic: 'PKI_DIAG_ANY_POLICY_QUALIFIER',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-no-notice-ref',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'Conforming CAs SHOULD NOT use the noticeRef option.',
        diagnostic: 'PKI_DIAG_NOTICE_REF_USED',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-explicit-text-utf8',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'Conforming CAs SHOULD use the UTF8String encoding for explicitText, but MAY use IA5String.',
        diagnostic: 'PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-explicit-text-not-visible-or-bmp',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'Conforming CAs MUST NOT encode explicitText as VisibleString or BMPString.',
        diagnostic: 'PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-explicit-text-no-control',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'The explicitText string SHOULD NOT include any control characters (e.g., U+0000 to U+001F and U+007F to U+009F).',
        diagnostic: 'PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER',
        exhaustive: true,
    },
    {
        id: '4.2.1.4-explicit-text-nfc',
        section: 'RFC 5280 §4.2.1.4',
        quote: 'When the UTF8String encoding is used, all character sequences SHOULD be normalized according to Unicode normalization form C (NFC) [NFC].',
        diagnostic: 'PKI_DIAG_EXPLICIT_TEXT_NOT_NFC',
        exhaustive: true,
    },
    {
        id: '4.2.1.5-mapped-policy-asserted',
        section: 'RFC 5280 §4.2.1.5',
        quote: 'Each issuerDomainPolicy named in the policy mappings extension SHOULD also be asserted in a certificate policies extension in the same certificate.',
        diagnostic: 'PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a policyMappings extension; x509-limbo builds its policy cases from certificatePolicies alone, so no issuerDomainPolicy exists to look for',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.1.5-policy-mappings-critical',
        section: 'RFC 5280 §4.2.1.5',
        quote: 'Conforming CAs SHOULD mark this extension as critical.',
        diagnostic: 'PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a policyMappings extension, critical or not; x509-limbo builds its policy cases from certificatePolicies alone',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.1.6-san-not-critical-with-subject',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'When including the subjectAltName extension in a certificate that has a non-empty subject distinguished name, conforming CAs SHOULD mark the subjectAltName extension as non-critical.',
        diagnostic: 'PKI_DIAG_SAN_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.6-uri-absolute',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'The name MUST NOT be a relative URI, and it MUST follow the URI syntax and encoding rules specified in [RFC3986].',
        diagnostic: 'PKI_DIAG_ALT_NAME_URI_INVALID',
        exhaustive: true,
    },
    {
        id: '4.2.1.6-uri-scheme-and-part',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'The name MUST include both a scheme (e.g., "http" or "ftp") and a scheme-specific-part.',
        diagnostic: 'PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING',
        exhaustive: true,
    },
    {
        id: '4.2.1.6-uri-host-fqdn-or-ip',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'URIs that include an authority ([RFC3986], Section 3.2) MUST include a fully qualified domain name or IP address as the host.',
        diagnostic: 'PKI_DIAG_ALT_NAME_URI_HOST_INVALID',
        exhaustive: true,
    },
    {
        id: '4.2.1.6-no-empty-general-name',
        section: 'RFC 5280 §4.2.1.6',
        quote: 'Unlike the subject field, conforming CAs MUST NOT issue certificates with subjectAltNames containing empty GeneralName fields.',
        diagnostic: 'PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY',
        exhaustive: true,
    },
    {
        id: '4.2.1.7-ian-not-critical',
        section: 'RFC 5280 §4.2.1.7',
        quote: 'Where present, conforming CAs SHOULD mark this extension as non-critical.',
        diagnostic: 'PKI_DIAG_ISSUER_ALT_NAME_CRITICAL',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries an issuerAltName extension; path validation never reads one, and x509-limbo was built to ask about path validation',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.1.10-no-min-max',
        section: 'RFC 5280 §4.2.1.10',
        quote: 'Within this profile, the minimum and maximum fields are not used with any name forms, thus, the minimum MUST be zero, and maximum MUST be absent.',
        diagnostic: 'PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX',
        exhaustive: true,
    },
    {
        id: '4.2.1.10-uri-constraint-fqdn',
        section: 'RFC 5280 §4.2.1.10',
        quote: 'The constraint MUST be specified as a fully qualified domain name and MAY specify a host or a domain.',
        diagnostic: 'PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN',
        exhaustive: true,
    },
    {
        id: '4.2.1.12-any-eku-not-critical',
        section: 'RFC 5280 §4.2.1.12',
        quote: 'Conforming CAs SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage KeyPurposeId is present.',
        diagnostic: 'PKI_DIAG_EKU_ANY_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.13-crl-dp-not-critical',
        section: 'RFC 5280 §4.2.1.13',
        quote: 'The extension SHOULD be non-critical, but this profile RECOMMENDS support for this extension by CAs and applications.',
        diagnostic: 'PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.1.13-dp-not-reasons-only',
        section: 'RFC 5280 §4.2.1.13',
        quote: 'While each of these fields is optional, a DistributionPoint MUST NOT consist of only the reasons field; either distributionPoint or cRLIssuer MUST be present.',
        diagnostic: 'PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME',
        exhaustive: true,
    },
    {
        id: '4.2.1.13-ldap-uri-dn-and-attrdesc',
        section: 'RFC 5280 §4.2.1.13',
        quote: 'When the LDAP URI scheme [RFC4516] is used, the URI MUST include a <dn> field containing the distinguished name of the entry holding the CRL, MUST include a single <attrdesc> that contains an appropriate attribute description for the attribute that holds the CRL [RFC4523], and SHOULD include a <host> (e.g., <ldap://ldap.example.com/cn=example%20CA,dc=example,dc=com? certificateRevocationList;binary>).',
        diagnostic: 'PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no cRLDistributionPoints or freshestCRL in the pinned corpus names an ldap:// URI; every distribution point x509-limbo writes is an HTTP URI',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.1.13-http-or-ldap-uri',
        section: 'RFC 5280 §4.2.1.13',
        quote: 'When present, DistributionPointName SHOULD include at least one LDAP or HTTP URI.',
        diagnostic: 'PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI',
        exhaustive: true,
    },
    {
        id: '4.2.1.13-no-relative-name',
        section: 'RFC 5280 §4.2.1.13',
        quote: 'Conforming CAs SHOULD NOT use nameRelativeToCRLIssuer to specify distribution point names.',
        diagnostic: 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME',
        exhaustive: true,
    },
    {
        id: '4.2.1.13-relative-name-one-issuer',
        section: 'RFC 5280 §4.2.1.13',
        quote: 'The DistributionPointName MUST NOT use the nameRelativeToCRLIssuer alternative when cRLIssuer contains more than one distinguished name.',
        diagnostic: 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no distribution point in the pinned corpus is named by nameRelativeToCRLIssuer, so no cRLIssuer stands beside one to be counted',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.1.14-inhibit-any-policy-critical',
        section: 'RFC 5280 §4.2.1.14',
        quote: 'Conforming CAs MUST mark this extension as critical.',
        diagnostic: 'PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries an inhibitAnyPolicy extension; x509-limbo does not exercise anyPolicy inhibition',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.1.15-freshest-crl-not-critical',
        section: 'RFC 5280 §4.2.1.15',
        quote: 'The extension MUST be marked as non-critical by conforming CAs.',
        diagnostic: 'PKI_DIAG_FRESHEST_CRL_CRITICAL',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a freshestCRL extension; x509-limbo scores no revocation, and delta CRLs least of all',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.2.1-aia-not-critical',
        section: 'RFC 5280 §4.2.2.1',
        quote: 'Conforming CAs MUST mark this extension as non-critical.',
        diagnostic: 'PKI_DIAG_AIA_CRITICAL',
        exhaustive: true,
    },
    {
        id: '4.2.2.1-ldap-uri-dn-and-attributes',
        section: 'RFC 5280 §4.2.2.1',
        quote: 'The LDAP URI [RFC4516] MUST include a <dn> field containing the distinguished name of the entry holding the certificates, MUST include an <attributes> field that lists appropriate attribute descriptions for the attributes that hold the DER encoded certificates or cross-certificate pairs [RFC4523], and SHOULD include a <host> (e.g., <ldap://ldap.example.com/cn=CA, dc=example,dc=com?cACertificate;binary,crossCertificatePair;binary>).',
        diagnostic: 'PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE',
        paths: ['authorityInfoAccess'],
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no id-ad-caIssuers location in the pinned corpus is an ldap:// URI; the authorityInfoAccess extensions x509-limbo carries point at HTTP',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.2.1-ca-issuers-http-or-ldap',
        section: 'RFC 5280 §4.2.2.1',
        quote: 'When the id-ad-caIssuers accessMethod is used, at least one instance SHOULD specify an accessLocation that is an HTTP [RFC2616] or LDAP [RFC4516] URI.',
        diagnostic: 'PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI',
        exhaustive: true,
    },
    {
        id: '4.2.2.2-sia-not-critical',
        section: 'RFC 5280 §4.2.2.2',
        quote: 'Conforming CAs MUST mark this extension as non-critical.',
        diagnostic: 'PKI_DIAG_SIA_CRITICAL',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a subjectInfoAccess extension; path validation never reads one',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.2.2-ldap-uri-dn-and-attributes',
        section: 'RFC 5280 §4.2.2.2',
        quote: 'The LDAP URI [RFC4516] MUST include a <dn> field containing the distinguished name of the entry holding the certificates, MUST include an <attributes> field that lists appropriate attribute descriptions for the attributes that hold the DER encoded certificates or cross-certificate pairs [RFC4523], and SHOULD include a <host> (e.g., <ldap://ldap.example.com/cn=CA, dc=example,dc=com?cACertificate;binary,crossCertificatePair;binary>).',
        diagnostic: 'PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE',
        paths: ['subjectInfoAccess'],
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a subjectInfoAccess extension, so no id-ad-caRepository location exists to be an LDAP URI',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
    {
        id: '4.2.2.2-ca-repository-http-or-ldap',
        section: 'RFC 5280 §4.2.2.2',
        quote: 'When the id-ad-caRepository accessMethod is used, at least one instance SHOULD specify an accessLocation that is an HTTP [RFC2616] or LDAP [RFC4516] URI.',
        diagnostic: 'PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI',
        exhaustive: true,
        unexercisedBy: {
            corpus: 'x509-limbo',
            reason: 'no certificate in the pinned corpus carries a subjectInfoAccess extension, so id-ad-caRepository is never listed',
            provenBy: 'tests/conformance/clauses.test.ts',
        },
    },
]);

/** Every clause id, for the completeness rule and the runner's bookkeeping. */
export const CLAUSE_IDS: readonly string[] = CLAUSES.map((c) => c.id);
