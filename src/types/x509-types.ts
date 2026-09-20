/**
 * pkinative — X.509 types
 * =======================
 * The decoded shape of an RFC 5280 certificate. Every structure is frozen and
 * keeps zero-copy views of the caller's input, like the ASN.1 nodes it was
 * read from: the caller must not mutate the bytes while it holds the result
 * (pass `data.slice()` to decouple).
 *
 * @module types/x509-types
 */

import type { Asn1Node, Asn1String, BitString, PkiTime } from './asn1-types.js';
import type { PkiDiagnostic, PkiParseOptions } from './pki-types.js';

// ── Algorithms ───────────────────────────────────────────────────────

/** An AlgorithmIdentifier (RFC 5280 §4.1.1.2). */
export interface AlgorithmIdentifier {
    /** The algorithm OID, e.g. `1.2.840.113549.1.1.11`. */
    readonly oid: string;
    /** The parameters, or `undefined` when the field is absent. */
    readonly parameters: Asn1Node | undefined;
    /** The exact encoding of the AlgorithmIdentifier. */
    readonly der: Uint8Array;
}

// ── Names ────────────────────────────────────────────────────────────

/** One attribute of a distinguished name (RFC 5280 §4.1.2.4). */
export interface AttributeTypeAndValue {
    /** The attribute type OID, e.g. `2.5.4.3` (commonName). */
    readonly type: string;
    /** The decoded value when it is a character string; `undefined` for a value of any other ASN.1 type. */
    readonly value: Asn1String | undefined;
    /** The exact encoding of the value: tag, length and content. */
    readonly valueDer: Uint8Array;
}

/** A relative distinguished name: one or more attributes, in encoded order. */
export type RelativeDistinguishedName = readonly AttributeTypeAndValue[];

/** A distinguished name. */
export interface DistinguishedName {
    /** The relative distinguished names in encoded order — the reverse of the RFC 4514 string order. */
    readonly rdns: readonly RelativeDistinguishedName[];
    /** The exact encoding of the Name, the bytes a name comparison by octets uses. */
    readonly der: Uint8Array;
}

// ── General names ────────────────────────────────────────────────────

interface GeneralNameBase {
    /** The exact encoding of the GeneralName, its context tag included. */
    readonly der: Uint8Array;
}

/** `otherName [0]`: a type OID and a value of that type. */
export interface OtherGeneralName extends GeneralNameBase {
    /** Discriminant: switch on it to narrow a `GeneralName` to this alternative. */
    readonly kind: 'otherName';
    /** The OID that says how to read `value`. */
    readonly typeId: string;
    /** The value inside the explicit `[0]` tag. */
    readonly value: Asn1Node;
}

/** `rfc822Name [1]`, `dNSName [2]` and `uniformResourceIdentifier [6]`: ASCII text. */
export interface TextGeneralName extends GeneralNameBase {
    /** Discriminant, which also says which of the three text forms this is. */
    readonly kind: 'rfc822Name' | 'dNSName' | 'uniformResourceIdentifier';
    /** The IA5String text, exactly as encoded: never lowercased, never punycode-decoded, never trimmed. */
    readonly value: string;
}

/** `x400Address [3]` and `ediPartyName [5]`, kept as their tagged node. */
export interface OpaqueGeneralName extends GeneralNameBase {
    /** Discriminant, which also says which of the two undecoded forms this is. */
    readonly kind: 'x400Address' | 'ediPartyName';
    /** The tagged node, undecoded: neither form has a profile RFC 5280 defines. */
    readonly value: Asn1Node;
}

/** `directoryName [4]`. */
export interface DirectoryGeneralName extends GeneralNameBase {
    /** Discriminant: switch on it to narrow a `GeneralName` to this alternative. */
    readonly kind: 'directoryName';
    /** The name, in the same shape as `certificate.subject`. */
    readonly name: DistinguishedName;
}

/** `iPAddress [7]`: an address, and in name constraints its mask. */
export interface IpAddressGeneralName extends GeneralNameBase {
    /** Discriminant: switch on it to narrow a `GeneralName` to this alternative. */
    readonly kind: 'iPAddress';
    /** 4 or 6, decided by the octet count, not by anything the certificate asserts. */
    readonly version: 4 | 6;
    /** Dotted decimal for IPv4, RFC 5952 text for IPv6. */
    readonly address: string;
    /** The mask in the same notation, present only in name constraints. */
    readonly mask: string | undefined;
    /** The octets: 4 or 16, doubled with the mask in name constraints. */
    readonly bytes: Uint8Array;
}

/** `registeredID [8]`. */
export interface RegisteredIdGeneralName extends GeneralNameBase {
    /** Discriminant: switch on it to narrow a `GeneralName` to this alternative. */
    readonly kind: 'registeredID';
    /** The identifier, in dotted notation. */
    readonly oid: string;
}

/** One GeneralName (RFC 5280 §4.2.1.6), discriminated by `kind`. */
export type GeneralName =
    | OtherGeneralName
    | TextGeneralName
    | OpaqueGeneralName
    | DirectoryGeneralName
    | IpAddressGeneralName
    | RegisteredIdGeneralName;

// ── Public keys ──────────────────────────────────────────────────────

interface PublicKeyInfoBase {
    /** The algorithm the key belongs to, with its parameters; `kind` is pkinative's reading of it. */
    readonly algorithm: AlgorithmIdentifier;
    /** The subjectPublicKey BIT STRING. */
    readonly publicKey: BitString;
    /** The exact encoding of the SubjectPublicKeyInfo. */
    readonly der: Uint8Array;
}

/** An RSA or RSASSA-PSS key (RFC 3279 §2.3.1, RFC 4055 §1.2). */
export interface RsaPublicKeyInfo extends PublicKeyInfoBase {
    /** Discriminant: switch on it to narrow a `SubjectPublicKeyInfo` to this alternative. */
    readonly kind: 'rsa' | 'rsa-pss';
    /** The unsigned big-endian modulus, without its sign octet. */
    readonly modulus: Uint8Array;
    /** The bit length of `modulus`, counted from its most significant set bit — the number "RSA 2048" means. */
    readonly modulusBits: number;
    /** The public exponent, usually 65537. */
    readonly publicExponent: bigint;
}

/** The NIST curves RFC 5480 names. */
export type EcCurve = 'P-256' | 'P-384' | 'P-521';

/** An elliptic-curve key (RFC 5480). */
export interface EcPublicKeyInfo extends PublicKeyInfoBase {
    /** Discriminant: switch on it to narrow a `SubjectPublicKeyInfo` to this alternative. */
    readonly kind: 'ec';
    /** The namedCurve OID; `undefined` when the parameters are not a named curve. */
    readonly namedCurve: string | undefined;
    /** The curve name when `namedCurve` is P-256, P-384 or P-521. */
    readonly curve: EcCurve | undefined;
    /** Read from the point's first octet: `0x04` is uncompressed, `0x02` and `0x03` compressed. */
    readonly pointFormat: 'uncompressed' | 'compressed';
    /** The encoded point, format octet included. */
    readonly point: Uint8Array;
}

/** A key whose subjectPublicKey is the raw key octets (RFC 8410, FIPS 204). */
export interface OctetPublicKeyInfo extends PublicKeyInfoBase {
    /** Discriminant, which also names the algorithm; switch on it to narrow a `SubjectPublicKeyInfo`. */
    readonly kind: 'ed25519' | 'ed448' | 'x25519' | 'x448' | 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';
    /** The raw key octets: the subjectPublicKey content, with no structure of its own. */
    readonly key: Uint8Array;
}

/** A key of an algorithm pkinative does not decode. */
export interface UnknownPublicKeyInfo extends PublicKeyInfoBase {
    /** Discriminant: read `algorithm.oid` and `publicKey` to go further. */
    readonly kind: 'unknown';
}

/** A SubjectPublicKeyInfo (RFC 5280 §4.1.2.7), discriminated by `kind`. */
export type SubjectPublicKeyInfo = RsaPublicKeyInfo | EcPublicKeyInfo | OctetPublicKeyInfo | UnknownPublicKeyInfo;

// ── Certificate ──────────────────────────────────────────────────────

/** The validity period (RFC 5280 §4.1.2.5). */
export interface Validity {
    /** The first instant the certificate is valid, inclusive. */
    readonly notBefore: PkiTime;
    /** The last instant the certificate is valid, inclusive; RFC 5280 §4.1.2.5 gives 99991231235959Z the meaning "no well-defined expiry". */
    readonly notAfter: PkiTime;
}

/** The serial number (RFC 5280 §4.1.2.2). */
export interface SerialNumber {
    /** The two's-complement content octets, exactly as encoded. */
    readonly bytes: Uint8Array;
    /** Lowercase hexadecimal of `bytes`. */
    readonly hex: string;
    /** The signed value; negative for a serial whose first octet has the high bit set. Compare serials by `bytes` or `hex`, never by `value`. */
    readonly value: bigint;
}

// ── Extensions ───────────────────────────────────────────────────────

/** The fields every extension carries (RFC 5280 §4.1.2.9). */
export interface ExtensionBase {
    /** The extnID, in dotted notation, e.g. `2.5.29.19` (basicConstraints). */
    readonly oid: string;
    /** Whether the issuer marked the extension critical: a relying party that does not understand a critical extension must reject the certificate. */
    readonly critical: boolean;
    /** The content of extnValue: the DER encoding of the extension value. */
    readonly valueDer: Uint8Array;
}

/** An extension kept as encoded because the parse ran with `decodeExtensions: false`. */
export interface RawExtension extends ExtensionBase {
    readonly kind: 'raw';
}

/** An extension pkinative does not decode. */
export interface UnknownExtension extends ExtensionBase {
    readonly kind: 'unknown';
}

/** basicConstraints (RFC 5280 §4.2.1.9). */
export interface BasicConstraintsExtension extends ExtensionBase {
    readonly kind: 'basicConstraints';
    readonly cA: boolean;
    readonly pathLenConstraint: number | undefined;
}

/** The named bits of KeyUsage, in bit order (RFC 5280 §4.2.1.3). */
export type KeyUsageName =
    | 'digitalSignature'
    | 'nonRepudiation'
    | 'keyEncipherment'
    | 'dataEncipherment'
    | 'keyAgreement'
    | 'keyCertSign'
    | 'cRLSign'
    | 'encipherOnly'
    | 'decipherOnly';

/** keyUsage (RFC 5280 §4.2.1.3). */
export interface KeyUsageExtension extends ExtensionBase {
    readonly kind: 'keyUsage';
    /** The asserted usages, in bit order. */
    readonly usages: readonly KeyUsageName[];
    readonly bits: BitString;
}

/** extKeyUsage (RFC 5280 §4.2.1.12). */
export interface ExtendedKeyUsageExtension extends ExtensionBase {
    readonly kind: 'extendedKeyUsage';
    /** KeyPurposeId OIDs, e.g. `1.3.6.1.5.5.7.3.1` (serverAuth). */
    readonly purposes: readonly string[];
}

/** subjectAltName (RFC 5280 §4.2.1.6). */
export interface SubjectAltNameExtension extends ExtensionBase {
    readonly kind: 'subjectAltName';
    readonly names: readonly GeneralName[];
}

/** issuerAltName (RFC 5280 §4.2.1.7). */
export interface IssuerAltNameExtension extends ExtensionBase {
    readonly kind: 'issuerAltName';
    readonly names: readonly GeneralName[];
}

/** subjectKeyIdentifier (RFC 5280 §4.2.1.2). */
export interface SubjectKeyIdentifierExtension extends ExtensionBase {
    readonly kind: 'subjectKeyIdentifier';
    readonly keyIdentifier: Uint8Array;
}

/** authorityKeyIdentifier (RFC 5280 §4.2.1.1). */
export interface AuthorityKeyIdentifierExtension extends ExtensionBase {
    readonly kind: 'authorityKeyIdentifier';
    readonly keyIdentifier: Uint8Array | undefined;
    readonly authorityCertIssuer: readonly GeneralName[] | undefined;
    readonly authorityCertSerialNumber: SerialNumber | undefined;
}

/** One permitted or excluded subtree of name constraints. */
export interface GeneralSubtree {
    readonly base: GeneralName;
    readonly minimum: number;
    readonly maximum: number | undefined;
}

/** nameConstraints (RFC 5280 §4.2.1.10). */
export interface NameConstraintsExtension extends ExtensionBase {
    readonly kind: 'nameConstraints';
    readonly permittedSubtrees: readonly GeneralSubtree[] | undefined;
    readonly excludedSubtrees: readonly GeneralSubtree[] | undefined;
}

/** A CPS pointer qualifier. */
export interface CpsQualifier {
    readonly kind: 'cps';
    readonly oid: string;
    readonly uri: string;
}

/** The organization and notice numbers of a user notice. */
export interface NoticeReference {
    readonly organization: Asn1String;
    readonly noticeNumbers: readonly bigint[];
}

/** A user notice qualifier. */
export interface UserNoticeQualifier {
    readonly kind: 'userNotice';
    readonly oid: string;
    readonly noticeRef: NoticeReference | undefined;
    readonly explicitText: Asn1String | undefined;
}

/** A qualifier pkinative does not decode. */
export interface UnknownPolicyQualifier {
    readonly kind: 'unknown';
    readonly oid: string;
    readonly qualifier: Asn1Node;
}

/** One policy qualifier, discriminated by `kind`. */
export type PolicyQualifier = CpsQualifier | UserNoticeQualifier | UnknownPolicyQualifier;

/** One entry of certificatePolicies. */
export interface PolicyInformation {
    readonly policyIdentifier: string;
    readonly qualifiers: readonly PolicyQualifier[];
}

/** certificatePolicies (RFC 5280 §4.2.1.4). */
export interface CertificatePoliciesExtension extends ExtensionBase {
    readonly kind: 'certificatePolicies';
    readonly policies: readonly PolicyInformation[];
}

/** One issuer-to-subject policy mapping. */
export interface PolicyMapping {
    readonly issuerDomainPolicy: string;
    readonly subjectDomainPolicy: string;
}

/** policyMappings (RFC 5280 §4.2.1.5). */
export interface PolicyMappingsExtension extends ExtensionBase {
    readonly kind: 'policyMappings';
    readonly mappings: readonly PolicyMapping[];
}

/** policyConstraints (RFC 5280 §4.2.1.11). */
export interface PolicyConstraintsExtension extends ExtensionBase {
    readonly kind: 'policyConstraints';
    readonly requireExplicitPolicy: number | undefined;
    readonly inhibitPolicyMapping: number | undefined;
}

/** inhibitAnyPolicy (RFC 5280 §4.2.1.14). */
export interface InhibitAnyPolicyExtension extends ExtensionBase {
    readonly kind: 'inhibitAnyPolicy';
    readonly skipCerts: number;
}

/** One access method and where to reach it. */
export interface AccessDescription {
    /** e.g. `1.3.6.1.5.5.7.48.1` (ocsp) or `1.3.6.1.5.5.7.48.2` (caIssuers). */
    readonly accessMethod: string;
    readonly accessLocation: GeneralName;
}

/** authorityInfoAccess (RFC 5280 §4.2.2.1). */
export interface AuthorityInfoAccessExtension extends ExtensionBase {
    readonly kind: 'authorityInfoAccess';
    readonly descriptions: readonly AccessDescription[];
}

/** subjectInfoAccess (RFC 5280 §4.2.2.2). */
export interface SubjectInfoAccessExtension extends ExtensionBase {
    readonly kind: 'subjectInfoAccess';
    readonly descriptions: readonly AccessDescription[];
}

/** The named bits of ReasonFlags, in bit order (RFC 5280 §4.2.1.13). */
export type ReasonFlag =
    | 'unused'
    | 'keyCompromise'
    | 'cACompromise'
    | 'affiliationChanged'
    | 'superseded'
    | 'cessationOfOperation'
    | 'certificateHold'
    | 'privilegeWithdrawn'
    | 'aACompromise';

/** One distribution point. */
export interface DistributionPoint {
    readonly fullName: readonly GeneralName[] | undefined;
    readonly nameRelativeToCRLIssuer: RelativeDistinguishedName | undefined;
    readonly reasons: readonly ReasonFlag[] | undefined;
    readonly cRLIssuer: readonly GeneralName[] | undefined;
}

/** cRLDistributionPoints (RFC 5280 §4.2.1.13). */
export interface CrlDistributionPointsExtension extends ExtensionBase {
    readonly kind: 'crlDistributionPoints';
    readonly points: readonly DistributionPoint[];
}

/** freshestCRL (RFC 5280 §4.2.1.15). */
export interface FreshestCrlExtension extends ExtensionBase {
    readonly kind: 'freshestCRL';
    readonly points: readonly DistributionPoint[];
}

/** The Certificate Transparency SCT list (RFC 6962 §3.3), kept in its TLS encoding. */
export interface SignedCertificateTimestampListExtension extends ExtensionBase {
    readonly kind: 'signedCertificateTimestampList';
    /** The SignedCertificateTimestampList, TLS-encoded. */
    readonly list: Uint8Array;
}

/** id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1). */
export interface OcspNoCheckExtension extends ExtensionBase {
    readonly kind: 'ocspNoCheck';
}

/** A certificate extension, discriminated by `kind`. */
export type Extension =
    | BasicConstraintsExtension
    | KeyUsageExtension
    | ExtendedKeyUsageExtension
    | SubjectAltNameExtension
    | IssuerAltNameExtension
    | SubjectKeyIdentifierExtension
    | AuthorityKeyIdentifierExtension
    | NameConstraintsExtension
    | CertificatePoliciesExtension
    | PolicyMappingsExtension
    | PolicyConstraintsExtension
    | InhibitAnyPolicyExtension
    | AuthorityInfoAccessExtension
    | SubjectInfoAccessExtension
    | CrlDistributionPointsExtension
    | FreshestCrlExtension
    | SignedCertificateTimestampListExtension
    | OcspNoCheckExtension
    | UnknownExtension
    | RawExtension;

/** The kinds `getExtension` looks up: every decoded extension, one per certificate. */
export type DecodedExtensionKind = Exclude<Extension['kind'], 'unknown' | 'raw'>;

// ── Options ──────────────────────────────────────────────────────────

/** Options of `parseCertificate`. */
export interface ParseCertificateOptions extends PkiParseOptions {
    /**
     * Decode every recognised extension (default `true`). With `false`, every
     * extension stays `kind: 'raw'` and a malformed one cannot fail the parse;
     * decode the ones you need with `decodeExtensionValue`.
     */
    readonly decodeExtensions?: boolean | undefined;
}

/** Options of `decodeExtensionValue`. */
export interface DecodeExtensionValueOptions extends PkiParseOptions {
    /** The criticality to report on the result and to check against (default `false`). */
    readonly critical?: boolean | undefined;
}

/**
 * A parsed X.509 certificate. Parsing checks structure and records profile
 * concerns; it does not verify the signature or validate a chain.
 */
export interface Certificate {
    /** The whole certificate encoding. */
    readonly der: Uint8Array;
    /** The tbsCertificate encoding — the bytes the signature covers. */
    readonly tbsDer: Uint8Array;
    /** The profile version, already decoded from the encoded 0, 1 or 2; only a v3 certificate may carry extensions. */
    readonly version: 1 | 2 | 3;
    /** The issuer-assigned serial, unique per issuer — the pair (issuer, serialNumber) identifies a certificate. */
    readonly serialNumber: SerialNumber;
    /** The outer signatureAlgorithm. */
    readonly signatureAlgorithm: AlgorithmIdentifier;
    /** tbsCertificate.signature, which RFC 5280 requires to equal `signatureAlgorithm`. */
    readonly tbsSignatureAlgorithm: AlgorithmIdentifier;
    /** The signature over `tbsDer`. pkinative does not verify it: 0.1 parses only. */
    readonly signatureValue: BitString;
    /** Who issued the certificate — matched against the subject of the issuing certificate by encoded bytes. */
    readonly issuer: DistinguishedName;
    /** When the certificate is valid. Nothing here is compared against the current time; that is the caller's decision. */
    readonly validity: Validity;
    /** Who the certificate is about. Empty for a certificate that carries its identity in subjectAltName. */
    readonly subject: DistinguishedName;
    /** The subject's public key, discriminated by `kind`. */
    readonly subjectPublicKeyInfo: SubjectPublicKeyInfo;
    /** issuerUniqueID, or `undefined` when absent. RFC 5280 §4.1.2.8 recommends against issuing it. */
    readonly issuerUniqueId: BitString | undefined;
    /** subjectUniqueID, or `undefined` when absent. RFC 5280 §4.1.2.8 recommends against issuing it. */
    readonly subjectUniqueId: BitString | undefined;
    /** Every extension in encoded order; empty when the field is absent. */
    readonly extensions: readonly Extension[];
    /** Every diagnostic the parse recorded, in emission order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
