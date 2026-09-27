/**
 * pkinative — RFC 6960 OCSP types
 * ===============================
 * What an OCSP request carries, and what a response says.
 *
 * The shape worth reading before the fields is `OcspCertStatus`. RFC 6960
 * gives three: `good`, `revoked` and `unknown` — and `unknown` means *"the
 * responder does not know about this certificate"*, which is not the same as
 * "not revoked" and not the same as an error. Collapsing those three into a
 * boolean is the mistake that turns a responder saying "I have never heard of
 * this serial" into a clean bill of health, and it is why the type is a
 * discriminated union rather than a flag.
 *
 * @module types/ocsp-types
 */

import type { PkiTime } from './asn1-types.js';
import type { CrlReason } from './crl-types.js';
import type { AlgorithmIdentifier, Extension, SerialNumber } from './x509-types.js';
import type { PkiDiagnostic } from './pki-types.js';

/**
 * The `CertID` of RFC 6960 §4.1.1: which certificate a question or an answer
 * is about.
 *
 * The issuer is identified by **hashes of its name and key**, not by its name.
 * That is the protocol's own choice and it has a consequence worth knowing:
 * two CAs sharing a key and a name are indistinguishable here, and a
 * responder's answer therefore binds to `(issuerNameHash, issuerKeyHash,
 * serialNumber)` and to nothing else.
 */
export interface OcspCertId {
    /** The algorithm the two hashes were computed with, usually SHA-1 (RFC 6960 §4.1.1). */
    readonly hashAlgorithm: AlgorithmIdentifier;
    /** Hash of the issuer's encoded `Name` — the DER of the field, not a rendering. */
    readonly issuerNameHash: Uint8Array;
    /** Hash of the issuer's `subjectPublicKey` BIT STRING content, excluding the tag and the unused-bits octet. */
    readonly issuerKeyHash: Uint8Array;
    /** The serial of the certificate being asked about. Compare by `bytes` or `hex`. */
    readonly serialNumber: SerialNumber;
}

/**
 * One certificate's status (RFC 6960 §4.2.1).
 *
 * Three states, never two. `unknown` is the responder saying it cannot answer
 * about this certificate, which is an absence of evidence — the same
 * distinction `PKI_REASON_REVOCATION_UNKNOWN` draws for CRLs.
 */
export type OcspCertStatus =
    | { readonly kind: 'good' }
    | { readonly kind: 'revoked'; readonly revocationTime: PkiTime; readonly reason: CrlReason | undefined }
    | { readonly kind: 'unknown' };

/** One `SingleResponse` (RFC 6960 §4.2.1). */
export interface OcspSingleResponse {
    /** Which certificate this answer is about. */
    readonly certId: OcspCertId;
    /** Good, revoked or unknown — three states, and unknown is not good. */
    readonly status: OcspCertStatus;
    /** When the responder knew this status to be correct. */
    readonly thisUpdate: PkiTime;
    /** When newer information will be available; absent means the responder has no successor to promise. */
    readonly nextUpdate: PkiTime | undefined;
    /** `singleExtensions`, decoded; empty when there are none. */
    readonly extensions: readonly Extension[];
}

/**
 * The `OCSPResponseStatus` of RFC 6960 §4.2.1.
 *
 * Only `successful` carries a `basicResponse`. The other six are the
 * responder declining to answer, and each one is a reason to look elsewhere
 * rather than a statement about the certificate.
 */
export type OcspResponseStatus =
    | 'successful'
    | 'malformedRequest'
    | 'internalError'
    | 'tryLater'
    | 'sigRequired'
    | 'unauthorized';

/** How a responder identified itself (RFC 6960 §4.2.1). */
export type OcspResponderId =
    /** `byName [1]`: the responder's `Name`, as its encoded DER. */
    | { readonly kind: 'byName'; readonly nameDer: Uint8Array }
    /** `byKey [2]`: a SHA-1 hash of the responder's public key. */
    | { readonly kind: 'byKey'; readonly keyHash: Uint8Array };

/** A parsed `BasicOCSPResponse` (RFC 6960 §4.2.1). */
export interface OcspBasicResponse {
    /** The `tbsResponseData` bytes the signature covers. */
    readonly tbsDer: Uint8Array;
    /** How the responder named itself — by name, or by a hash of its key. */
    readonly responderId: OcspResponderId;
    /** When the responder signed this response. */
    readonly producedAt: PkiTime;
    /** One answer per certificate asked about, in the order the responder gave them. */
    readonly responses: readonly OcspSingleResponse[];
    /** The algorithm the responder signed with. RFC 6960 names it once, outside the covered bytes. */
    readonly signatureAlgorithm: AlgorithmIdentifier;
    /** The signature over `tbsDer`, as a BIT STRING of whole octets. */
    readonly signatureValue: { readonly bytes: Uint8Array; readonly unusedBits: number };
    /**
     * Certificates the responder attached to help a client build a path to it.
     * **Attached, not trusted**: a responder can put anything here, and a
     * client that trusted them would let the responder nominate its own
     * authority.
     */
    readonly certificates: readonly Uint8Array[];
    /** `responseExtensions`, decoded; the nonce echo lives here. */
    readonly extensions: readonly Extension[];
}

/** A parsed `OCSPResponse` (RFC 6960 §4.2.1). */
export interface OcspResponse {
    /** The whole response, as a zero-copy view of the input. */
    readonly der: Uint8Array;
    /** `successful`, or one of the six ways a responder declines to answer. */
    readonly status: OcspResponseStatus;
    /** Present only when `status` is `'successful'`; the protocol carries no body otherwise. */
    readonly basicResponse: OcspBasicResponse | undefined;
    /** Profile concerns found while reading, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
