/**
 * pkinative — Attribute certificate types
 * =======================================
 * The decoded shape of an RFC 5755 attribute certificate (AC): the envelope,
 * the holder and issuer references, the attributes of §4.4 and the extensions
 * only an AC carries (§4.3). Every structure is frozen and keeps zero-copy
 * views of the caller's input: the caller must not mutate the bytes while it
 * holds the result (pass `data.slice()` to decouple).
 *
 * A parsed AC is not a valid one: RFC 5755 §5 validation (holder binding,
 * targeting, revocation, the issuer's path) is the caller's composition
 * (ADR 0028).
 *
 * @module types/attribute-certificate-types
 */

import type { BitString } from './asn1-types.js';
import type { PkiDiagnostic } from './pki-types.js';
import type { AlgorithmIdentifier, DistinguishedName, Extension, ExtensionBase, GeneralName, SerialNumber, Validity } from './x509-types.js';

// ── References to certificates and objects ───────────────────────────

/** IssuerSerial (RFC 5755 §4.1): a public-key certificate named by its issuer and serial number. */
export interface IssuerSerial {
    /** The issuer of the referenced certificate, as GeneralNames — RFC 5755 §4.2.2 asks for one directoryName equal to its issuer field. */
    readonly issuer: readonly GeneralName[];
    /** The serial number of the referenced certificate. */
    readonly serial: SerialNumber;
    /** The issuerUniqueID of the referenced certificate, or `undefined` when absent. */
    readonly issuerUid: BitString | undefined;
    /** The IssuerSerial encoding, exactly as encoded (under its implicit tag where it has one). */
    readonly der: Uint8Array;
}

/** What an ObjectDigestInfo digests (RFC 5755 §4.1, §7.3). */
export type DigestedObjectType = 'publicKey' | 'publicKeyCert' | 'otherObjectTypes';

/** ObjectDigestInfo (RFC 5755 §4.1): an object named by its digest. pkinative does not recompute it. */
export interface ObjectDigestInfo {
    /** The kind of object digested. RFC 5755 forbids `otherObjectTypes` in its profile. */
    readonly digestedObjectType: DigestedObjectType;
    /** otherObjectTypeID, or `undefined` when absent. */
    readonly otherObjectTypeId: string | undefined;
    /** The digest algorithm. */
    readonly digestAlgorithm: AlgorithmIdentifier;
    /** The digest. */
    readonly objectDigest: BitString;
    /** The ObjectDigestInfo encoding, exactly as encoded. */
    readonly der: Uint8Array;
}

/**
 * The Holder of an AC (RFC 5755 §4.2.2): up to three references to whom the
 * attributes belong. RFC 5755 recommends exactly one.
 */
export interface AttributeCertificateHolder {
    /** The holder's public-key certificate, by issuer and serial, or `undefined` when absent. */
    readonly baseCertificateId: IssuerSerial | undefined;
    /** The holder's names, or `undefined` when absent. */
    readonly entityName: readonly GeneralName[] | undefined;
    /** A digest of the holder's key or certificate, or `undefined` when absent. */
    readonly objectDigestInfo: ObjectDigestInfo | undefined;
    /** The Holder encoding, exactly as encoded. */
    readonly der: Uint8Array;
}

/**
 * The issuer of an AC (RFC 5755 §4.2.3): `v2Form`, the only form the profile
 * allows, or the `v1Form` of X.509 (1997), read and diagnosed.
 */
export interface AttributeCertificateIssuer {
    /** Which CHOICE of AttCertIssuer was encoded. */
    readonly form: 'v1Form' | 'v2Form';
    /** The issuer's names: the GeneralNames of `v1Form`, or `issuerName` of `v2Form` (`undefined` when that is absent). */
    readonly issuerName: readonly GeneralName[] | undefined;
    /**
     * The issuer's distinguished name when `issuerName` is exactly one non-empty
     * directoryName — the profiled form — and `undefined` otherwise. Compare its
     * `der` with the `subject.der` of a candidate issuer certificate.
     */
    readonly name: DistinguishedName | undefined;
    /** `v2Form.baseCertificateID`, which the profile forbids, or `undefined`. */
    readonly baseCertificateId: IssuerSerial | undefined;
    /** `v2Form.objectDigestInfo`, which the profile forbids, or `undefined`. */
    readonly objectDigestInfo: ObjectDigestInfo | undefined;
    /** The AttCertIssuer encoding, exactly as encoded. */
    readonly der: Uint8Array;
}

// ── Attributes (RFC 5755 §4.4) ───────────────────────────────────────

/** The fields every AC attribute carries (RFC 5755 §4.1). */
export interface AttributeCertificateAttributeBase {
    /** The attribute type, in dotted notation, e.g. `2.5.4.72` (role). */
    readonly oid: string;
    /** Each AttributeValue, as its exact DER, in encoded order — at least one. */
    readonly values: readonly Uint8Array[];
    /** The whole Attribute SEQUENCE, exactly as encoded. */
    readonly der: Uint8Array;
}

/** SvceAuthInfo (RFC 5755 §4.4.1): a service, the holder's identity at it, and optional authentication data. */
export interface ServiceAuthInfo {
    /** The service. */
    readonly service: GeneralName;
    /** The holder's identity at the service. */
    readonly ident: GeneralName;
    /** Service-specific authentication data (often a password: treat as secret), or `undefined` when absent. */
    readonly authInfo: Uint8Array | undefined;
}

/** id-aca-authenticationInfo (RFC 5755 §4.4.1). */
export interface AuthenticationInfoAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'authenticationInfo';
    /** One SvceAuthInfo per value, in encoded order. */
    readonly infos: readonly ServiceAuthInfo[];
}

/** id-aca-accessIdentity (RFC 5755 §4.4.2): the SvceAuthInfo syntax without `authInfo`. */
export interface AccessIdentityAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'accessIdentity';
    /** One SvceAuthInfo per value, in encoded order. */
    readonly identities: readonly ServiceAuthInfo[];
}

/** One value of an IetfAttrSyntax (RFC 5755 §4.4): an OCTET STRING, an OBJECT IDENTIFIER or a UTF8String. */
export type IetfAttrValue =
    | { readonly kind: 'octets'; readonly value: Uint8Array }
    | { readonly kind: 'oid'; readonly value: string }
    | { readonly kind: 'string'; readonly value: string };

/** IetfAttrSyntax (RFC 5755 §4.4): values under an optional policy authority. */
export interface IetfAttrSyntax {
    /** The policyAuthority, or `undefined` when absent. */
    readonly policyAuthority: readonly GeneralName[] | undefined;
    /** The values, in encoded order. */
    readonly values: readonly IetfAttrValue[];
}

/** id-aca-chargingIdentity (RFC 5755 §4.4.3). */
export interface ChargingIdentityAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'chargingIdentity';
    /** One IetfAttrSyntax per value — RFC 5755 allows one. */
    readonly syntaxes: readonly IetfAttrSyntax[];
}

/** id-aca-group (RFC 5755 §4.4.4). */
export interface GroupAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'group';
    /** One IetfAttrSyntax per value — RFC 5755 allows one. */
    readonly syntaxes: readonly IetfAttrSyntax[];
}

/** RoleSyntax (RFC 5755 §4.4.5). */
export interface RoleSyntax {
    /** The roleAuthority, or `undefined` when absent. */
    readonly roleAuthority: readonly GeneralName[] | undefined;
    /** The roleName — RFC 5755 requires a uniformResourceIdentifier. */
    readonly roleName: GeneralName;
}

/** id-at-role (RFC 5755 §4.4.5). */
export interface RoleAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'role';
    /** One RoleSyntax per value, in encoded order. */
    readonly roles: readonly RoleSyntax[];
}

/** The six classes the basic hierarchy of RFC 5755 §4.4.6 reserves, bits 0 to 5 of ClassList. */
export type ClassListName = 'unmarked' | 'unclassified' | 'restricted' | 'confidential' | 'secret' | 'topSecret';

/** SecurityCategory (RFC 5755 §4.4.6): a type and a value defined by the security policy. */
export interface SecurityCategory {
    /** The category type. */
    readonly type: string;
    /** The value under the explicit `[1]` tag, as its exact DER. */
    readonly value: Uint8Array;
}

/** Clearance (RFC 5755 §4.4.6, the X.501 (1997) syntax). */
export interface Clearance {
    /** The security policy the clearance relates to. */
    readonly policyId: string;
    /** The named classes set among bits 0 to 5 — `['unclassified']`, the DEFAULT, when classList is absent. */
    readonly classList: readonly ClassListName[];
    /** The ClassList BIT STRING as encoded, for classes a security policy defines beyond bit 5; `undefined` when absent. */
    readonly classListBits: BitString | undefined;
    /** The security categories, or `undefined` when absent. */
    readonly securityCategories: readonly SecurityCategory[] | undefined;
}

/** id-at-clearance, 2.5.4.55 (RFC 5755 §4.4.6). */
export interface ClearanceAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'clearance';
    /** One Clearance per value, in encoded order. */
    readonly clearances: readonly Clearance[];
}

/**
 * An attribute pkinative does not decode — any type outside RFC 5755 §4.4,
 * the RFC 3281 clearance (2.5.1.5.55) among them. Read `oid` and `values`.
 */
export interface UnknownAttributeCertificateAttribute extends AttributeCertificateAttributeBase {
    /** Discriminant. */
    readonly kind: 'unknown';
}

/** An attribute of an AC, discriminated by `kind`. */
export type AttributeCertificateAttribute =
    | AuthenticationInfoAttribute
    | AccessIdentityAttribute
    | ChargingIdentityAttribute
    | GroupAttribute
    | RoleAttribute
    | ClearanceAttribute
    | UnknownAttributeCertificateAttribute;

// ── Extensions only an AC carries (RFC 5755 §4.3) ────────────────────

/**
 * One Target of targetInformation (RFC 5755 §4.3.2): a named target, a target
 * group, or a targetCert — which RFC 5755 forbids, kept as its DER under its
 * implicit `[2]` tag.
 */
export type AttributeCertificateTarget =
    | { readonly kind: 'targetName'; readonly name: GeneralName }
    | { readonly kind: 'targetGroup'; readonly name: GeneralName }
    | { readonly kind: 'targetCert'; readonly der: Uint8Array };

/** id-ce-targetInformation (RFC 5755 §4.3.2). */
export interface TargetInformationExtension extends ExtensionBase {
    /** Discriminant. */
    readonly kind: 'targetInformation';
    /** Every Target of every Targets element, as one list — what RFC 5755 §4.3.2 tells a reader to do. */
    readonly targets: readonly AttributeCertificateTarget[];
}

/** id-pe-ac-auditIdentity (RFC 5755 §4.3.1). */
export interface AuditIdentityExtension extends ExtensionBase {
    /** Discriminant. */
    readonly kind: 'auditIdentity';
    /** The opaque audit identity. */
    readonly identity: Uint8Array;
}

/** id-ce-noRevAvail (RFC 5755 §4.3.6): no revocation information will be published for this AC. */
export interface NoRevAvailExtension extends ExtensionBase {
    /** Discriminant. The extension carries no value: its presence is the assertion. */
    readonly kind: 'noRevAvail';
}

/** An extension of an AC: any certificate extension, or one of the three only an AC carries. */
export type AttributeCertificateExtension = Extension | TargetInformationExtension | AuditIdentityExtension | NoRevAvailExtension;

// ── The attribute certificate ────────────────────────────────────────

/**
 * A parsed RFC 5755 attribute certificate. Parsing checks structure and
 * records profile concerns; it does not verify the signature
 * (`verifyAttributeCertificateSignature` does) and does not validate the AC.
 */
export interface AttributeCertificate {
    /** The whole AC encoding. */
    readonly der: Uint8Array;
    /** The acinfo encoding — the bytes the signature covers. */
    readonly tbsDer: Uint8Array;
    /** The AC version, decoded from the encoded 1: RFC 5755 defines v2 only. */
    readonly version: 2;
    /** Whom the attributes belong to. */
    readonly holder: AttributeCertificateHolder;
    /** Who issued the AC. */
    readonly issuer: AttributeCertificateIssuer;
    /** acinfo.signature, which must equal `signatureAlgorithm`. */
    readonly tbsSignatureAlgorithm: AlgorithmIdentifier;
    /** The outer signatureAlgorithm. */
    readonly signatureAlgorithm: AlgorithmIdentifier;
    /** The signature over `tbsDer`. */
    readonly signatureValue: BitString;
    /** The issuer-assigned serial; the pair (issuer, serialNumber) identifies an AC. */
    readonly serialNumber: SerialNumber;
    /** attrCertValidityPeriod. Nothing here is compared against the current time; that is the caller's decision. */
    readonly validity: Validity;
    /** Every attribute in encoded order. */
    readonly attributes: readonly AttributeCertificateAttribute[];
    /** issuerUniqueID, or `undefined` when absent. */
    readonly issuerUniqueId: BitString | undefined;
    /** Every extension in encoded order; empty when the field is absent. */
    readonly extensions: readonly AttributeCertificateExtension[];
    /** Every diagnostic the parse recorded, in emission order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
