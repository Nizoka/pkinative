/**
 * pkinative — RFC 5280 §5 certificate revocation list types
 * =========================================================
 * A parsed `CertificateList`, and what asking it about one certificate
 * returns.
 *
 * **`revokedCertificates` is not a field here, and that is deliberate.** The
 * list is walked on demand with `findRevocation`, never materialised: at three
 * ASN.1 nodes per entry, a decoded tree hits `maxNodes` at roughly 65 000
 * entries, and real CRLs are larger than that. Exposing an array would either
 * cap the library below real-world sizes or allocate hundreds of megabytes for
 * a question that has one answer. `entryCount` is available when a caller
 * genuinely wants the size, and it is counted by walking, not by decoding.
 *
 * @module types/crl-types
 */

import type { BitString, PkiTime } from './asn1-types.js';
import type {
    AlgorithmIdentifier,
    DistinguishedName,
    Extension,
    GeneralName,
    ReasonFlag,
    RelativeDistinguishedName,
    SerialNumber,
} from './x509-types.js';
import type { PkiDiagnostic } from './pki-types.js';

/** One entry of `revokedCertificates` (RFC 5280 §5.1.2.6). */
export interface RevokedCertificate {
    /** The revoked certificate's serial. Compare by `bytes` or `hex`, never by `value`. */
    readonly serialNumber: SerialNumber;
    /** When the CA says the certificate stopped being trustworthy. */
    readonly revocationDate: PkiTime;
    /** `crlEntryExtensions`, decoded; empty when the entry has none. */
    readonly extensions: readonly Extension[];
    /** Reason code from `cRLReason` (RFC 5280 §5.3.1), or undefined when absent. */
    readonly reason: CrlReason | undefined;
    /** `invalidityDate` (RFC 5280 §5.3.2) in epoch milliseconds, or undefined. */
    readonly invalidityDate: number | undefined;
}

/**
 * The `CRLReason` values of RFC 5280 §5.3.1.
 *
 * `7` is not assigned: the enumeration skips it, and a CRL asserting 7 is
 * reporting a reason no standard defines.
 */
export type CrlReason =
    | 'unspecified'
    | 'keyCompromise'
    | 'cACompromise'
    | 'affiliationChanged'
    | 'superseded'
    | 'cessationOfOperation'
    | 'certificateHold'
    | 'removeFromCRL'
    | 'privilegeWithdrawn'
    | 'aACompromise';

/**
 * `issuingDistributionPoint` (RFC 5280 §5.2.5) — what a list declares itself to
 * be about.
 *
 * This is the extension that makes "the serial is not on the list" mean
 * something. Without it a list is assumed to cover every certificate its CA
 * issued; with it the list says *"I only speak for end-entity certificates
 * published at this point"*, and reading a CA certificate's absence from such a
 * list as "not revoked" is how a revoked sub-CA is accepted. RFC 5280 requires
 * it to be critical, for exactly that reason.
 *
 * The four booleans are `DEFAULT FALSE`, so an absent field is `false` here and
 * a caller never has to distinguish absent from false — the standard already
 * decided they are the same thing.
 */
export interface IssuingDistributionPoint {
    /** `distributionPoint` as a `fullName`, or `undefined` when the field names nothing or is relative. */
    readonly fullName: readonly GeneralName[] | undefined;
    /** `distributionPoint` named relative to the CRL issuer; `undefined` when absent. Mutually exclusive with `fullName`. */
    readonly nameRelativeToCRLIssuer: RelativeDistinguishedName | undefined;
    /** The list covers only certificates that are not CAs. */
    readonly onlyContainsUserCerts: boolean;
    /** The list covers only CA certificates. */
    readonly onlyContainsCACerts: boolean;
    /** The revocation reasons this list covers; `undefined` means all of them, which is not the same as an empty list. */
    readonly onlySomeReasons: readonly ReasonFlag[] | undefined;
    /** The list carries entries for CAs other than its own issuer, each named by a `certificateIssuer` entry extension. */
    readonly indirectCRL: boolean;
    /** The list covers only attribute certificates (X.509 §12), which this library does not parse — so it covers nothing here. */
    readonly onlyContainsAttributeCerts: boolean;
}

/** A parsed `CertificateList` (RFC 5280 §5.1). */
export interface CertificateList {
    /** The whole CRL, as a zero-copy view of the input. */
    readonly der: Uint8Array;
    /** The `tbsCertList` bytes the signature covers. */
    readonly tbsDer: Uint8Array;
    /** `1` for v1, `2` for v2 (the encoded INTEGER is 0 or 1). */
    readonly version: 1 | 2;
    /** The algorithm the outer signature was made with. */
    readonly signatureAlgorithm: AlgorithmIdentifier;
    /** `tbsCertList.signature`; RFC 5280 §5.1.1.2 requires it to equal the outer one. */
    readonly tbsSignatureAlgorithm: AlgorithmIdentifier;
    /** The signature over `tbsDer`, as a BIT STRING of whole octets. */
    readonly signatureValue: BitString;
    /** The CA that issued this list. Match it against a certificate's `issuer` by `der`. */
    readonly issuer: DistinguishedName;
    /** When this list was produced. */
    readonly thisUpdate: PkiTime;
    /** Absent in a CRL that promises no successor, which RFC 5280 discourages. */
    readonly nextUpdate: PkiTime | undefined;
    /** `crlExtensions`, decoded; empty when there are none. */
    readonly extensions: readonly Extension[];
    /** `cRLNumber` (RFC 5280 §5.2.3), or undefined when absent. */
    readonly crlNumber: bigint | undefined;
    /** Whether `deltaCRLIndicator` (§5.2.4) is present — a delta CRL is not a full one. */
    readonly isDelta: boolean;
    /** `issuingDistributionPoint` (§5.2.5), or `undefined` when absent — in which case the list covers everything its CA issued. */
    readonly issuingDistributionPoint: IssuingDistributionPoint | undefined;
    /** Entries in `revokedCertificates`, counted by walking rather than decoding. */
    readonly entryCount: number;
    /** Profile concerns found while reading the envelope, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
