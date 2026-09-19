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
import type { PkiDiagnostic } from './pki-types.js';

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
    readonly kind: 'otherName';
    readonly typeId: string;
    /** The value inside the explicit `[0]` tag. */
    readonly value: Asn1Node;
}

/** `rfc822Name [1]`, `dNSName [2]` and `uniformResourceIdentifier [6]`: ASCII text. */
export interface TextGeneralName extends GeneralNameBase {
    readonly kind: 'rfc822Name' | 'dNSName' | 'uniformResourceIdentifier';
    readonly value: string;
}

/** `x400Address [3]` and `ediPartyName [5]`, kept as their tagged node. */
export interface OpaqueGeneralName extends GeneralNameBase {
    readonly kind: 'x400Address' | 'ediPartyName';
    readonly value: Asn1Node;
}

/** `directoryName [4]`. */
export interface DirectoryGeneralName extends GeneralNameBase {
    readonly kind: 'directoryName';
    readonly name: DistinguishedName;
}

/** `iPAddress [7]`: an address, and in name constraints its mask. */
export interface IpAddressGeneralName extends GeneralNameBase {
    readonly kind: 'iPAddress';
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
    readonly kind: 'registeredID';
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
    readonly algorithm: AlgorithmIdentifier;
    /** The subjectPublicKey BIT STRING. */
    readonly publicKey: BitString;
    /** The exact encoding of the SubjectPublicKeyInfo. */
    readonly der: Uint8Array;
}

/** An RSA or RSASSA-PSS key (RFC 3279 §2.3.1, RFC 4055 §1.2). */
export interface RsaPublicKeyInfo extends PublicKeyInfoBase {
    readonly kind: 'rsa' | 'rsa-pss';
    /** The unsigned big-endian modulus, without its sign octet. */
    readonly modulus: Uint8Array;
    readonly modulusBits: number;
    readonly publicExponent: bigint;
}

/** The NIST curves RFC 5480 names. */
export type EcCurve = 'P-256' | 'P-384' | 'P-521';

/** An elliptic-curve key (RFC 5480). */
export interface EcPublicKeyInfo extends PublicKeyInfoBase {
    readonly kind: 'ec';
    /** The namedCurve OID; `undefined` when the parameters are not a named curve. */
    readonly namedCurve: string | undefined;
    /** The curve name when `namedCurve` is P-256, P-384 or P-521. */
    readonly curve: EcCurve | undefined;
    readonly pointFormat: 'uncompressed' | 'compressed';
    /** The encoded point, format octet included. */
    readonly point: Uint8Array;
}

/** A key whose subjectPublicKey is the raw key octets (RFC 8410, FIPS 204). */
export interface OctetPublicKeyInfo extends PublicKeyInfoBase {
    readonly kind: 'ed25519' | 'ed448' | 'x25519' | 'x448' | 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';
    readonly key: Uint8Array;
}

/** A key of an algorithm pkinative does not decode. */
export interface UnknownPublicKeyInfo extends PublicKeyInfoBase {
    readonly kind: 'unknown';
}

/** A SubjectPublicKeyInfo (RFC 5280 §4.1.2.7), discriminated by `kind`. */
export type SubjectPublicKeyInfo = RsaPublicKeyInfo | EcPublicKeyInfo | OctetPublicKeyInfo | UnknownPublicKeyInfo;

// ── Certificate ──────────────────────────────────────────────────────

/** The validity period (RFC 5280 §4.1.2.5). */
export interface Validity {
    readonly notBefore: PkiTime;
    readonly notAfter: PkiTime;
}

/** The serial number (RFC 5280 §4.1.2.2). */
export interface SerialNumber {
    /** The two's-complement content octets, exactly as encoded. */
    readonly bytes: Uint8Array;
    /** Lowercase hexadecimal of `bytes`. */
    readonly hex: string;
    readonly value: bigint;
}

/** An extension kept as encoded (RFC 5280 §4.2). */
export interface RawExtension {
    readonly kind: 'raw';
    readonly oid: string;
    readonly critical: boolean;
    /** The content of extnValue: the DER encoding of the extension value. */
    readonly valueDer: Uint8Array;
}

/** A certificate extension, discriminated by `kind`. */
export type Extension = RawExtension;

/**
 * A parsed X.509 certificate. Parsing checks structure and records profile
 * concerns; it does not verify the signature or validate a chain.
 */
export interface Certificate {
    /** The whole certificate encoding. */
    readonly der: Uint8Array;
    /** The tbsCertificate encoding — the bytes the signature covers. */
    readonly tbsDer: Uint8Array;
    readonly version: 1 | 2 | 3;
    readonly serialNumber: SerialNumber;
    /** The outer signatureAlgorithm. */
    readonly signatureAlgorithm: AlgorithmIdentifier;
    /** tbsCertificate.signature, which RFC 5280 requires to equal `signatureAlgorithm`. */
    readonly tbsSignatureAlgorithm: AlgorithmIdentifier;
    readonly signatureValue: BitString;
    readonly issuer: DistinguishedName;
    readonly validity: Validity;
    readonly subject: DistinguishedName;
    readonly subjectPublicKeyInfo: SubjectPublicKeyInfo;
    readonly issuerUniqueId: BitString | undefined;
    readonly subjectUniqueId: BitString | undefined;
    /** Every extension in encoded order; empty when the field is absent. */
    readonly extensions: readonly Extension[];
    /** Every diagnostic the parse recorded, in emission order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
