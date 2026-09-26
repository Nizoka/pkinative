/**
 * pkinative — Public entry point
 * ==============================
 * The single entry point of the package: everything public is exported from
 * this file, grouped in the category order of
 * `.github/instructions/api-design.instructions.md`. Nothing inside the
 * library imports it (tests/tools/architecture.test.ts).
 *
 * @packageDocumentation
 */

// ── 1. Errors, limits and diagnostics ────────────────────────────────

export { PkiError, PkiEncodingError, PkiCertificateError, PkiLimitError, PkiCryptoError } from './types/pki-errors.js';
export type {
    PkiErrorCode,
    PkiBaseErrorCode,
    PkiEncodingErrorCode,
    PkiCertificateErrorCode,
    PkiLimitErrorCode,
    PkiCryptoErrorCode,
} from './types/pki-errors.js';
export { DEFAULT_PKI_LIMITS } from './core/pki-limits.js';
export type {
    PkiLimits,
    PkiDiagnostic,
    PkiDiagnosticCode,
    PkiDiagnosticSeverity,
    PkiDiagnosticHandler,
    PkiParseOptions,
    EncodingRules,
} from './types/pki-types.js';
// The third vocabulary. A reason is RETURNED in a report, never thrown and
// never emitted; src/types/pki-reasons.ts carries the table of the three and
// says why neither of the other two could do this job.
export type { PkiReason, PkiReasonCode } from './types/pki-reasons.js';

// ── 2. ASN.1 — decoding, value readers, encoders ─────────────────────

export { decodeAsn1, decodeAsn1Sequence } from './asn1/asn1-decode.js';
export {
    readBoolean,
    readInteger,
    readSmallInteger,
    readNull,
    readBitString,
    readOctetString,
    readString,
} from './asn1/asn1-read.js';
export { readTime } from './asn1/asn1-time.js';
export {
    encodeTlv,
    encodeSequence,
    encodeSet,
    encodeSetOf,
    encodeInteger,
    encodeBoolean,
    encodeNull,
    encodeBitString,
    encodeOctetString,
    encodeObjectIdentifier,
    encodeString,
    encodeTime,
    encodeAsn1Node,
    encodeEnumerated,
    encodeExplicit,
    encodeImplicit,
    encodeNamedBits,
} from './asn1/asn1-encode.js';
export type {
    TagClass,
    Asn1Node,
    DecodeAsn1Options,
    BitString,
    Asn1StringType,
    Asn1String,
    TimeType,
    PkiTime,
    ReadStringOptions,
    ReadTimeOptions,
} from './types/asn1-types.js';

// ── 3. OID — codec and registry ──────────────────────────────────────

export { encodeOid, decodeOid, isValidOid, readObjectIdentifier } from './asn1/asn1-oid.js';
export { OID_REGISTRY } from './oid/oid-registry.js';
export type { OidRegistryEntry } from './oid/oid-registry.js';
export { getOidName } from './oid/oid-names.js';

// ── 4. PEM — RFC 7468 ────────────────────────────────────────────────

export { decodePem, encodePem } from './pem/pem.js';
export type { PemBlock, DecodePemOptions } from './types/pem-types.js';

// ── 5. Fingerprints ──────────────────────────────────────────────────

export { computeFingerprint, computeFingerprintAsync, formatFingerprint } from './hash/fingerprint.js';
export type { FingerprintAlgorithm, FormatFingerprintOptions } from './types/hash-types.js';

// ── 6. X.509 — certificate parsing, names, public keys ───────────────

export { parseCertificate } from './x509/x509-certificate.js';
export { formatDistinguishedName } from './x509/x509-name-format.js';
export { getExtension, decodeExtensionValue } from './x509/x509-extensions.js';
export type {
    ParseCertificateOptions,
    DecodeExtensionValueOptions,
    ExtensionBase,
    UnknownExtension,
    BasicConstraintsExtension,
    KeyUsageName,
    KeyUsageExtension,
    ExtendedKeyUsageExtension,
    SubjectAltNameExtension,
    IssuerAltNameExtension,
    SubjectKeyIdentifierExtension,
    AuthorityKeyIdentifierExtension,
    GeneralSubtree,
    NameConstraintsExtension,
    CpsQualifier,
    NoticeReference,
    UserNoticeQualifier,
    UnknownPolicyQualifier,
    PolicyQualifier,
    PolicyInformation,
    CertificatePoliciesExtension,
    PolicyMapping,
    PolicyMappingsExtension,
    PolicyConstraintsExtension,
    InhibitAnyPolicyExtension,
    AccessDescription,
    AuthorityInfoAccessExtension,
    SubjectInfoAccessExtension,
    ReasonFlag,
    DistributionPoint,
    CrlDistributionPointsExtension,
    FreshestCrlExtension,
    SignedCertificateTimestampListExtension,
    OcspNoCheckExtension,
    DecodedExtensionKind,
    AlgorithmIdentifier,
    AttributeTypeAndValue,
    RelativeDistinguishedName,
    DistinguishedName,
    GeneralName,
    OtherGeneralName,
    TextGeneralName,
    OpaqueGeneralName,
    DirectoryGeneralName,
    IpAddressGeneralName,
    RegisteredIdGeneralName,
    EcCurve,
    RsaPublicKeyInfo,
    EcPublicKeyInfo,
    OctetPublicKeyInfo,
    UnknownPublicKeyInfo,
    SubjectPublicKeyInfo,
    Validity,
    SerialNumber,
    RawExtension,
    Extension,
    Certificate,
} from './types/x509-types.js';

// ── 7. Verification through Web Crypto ───────────────────────────────

export { verifyCertificateSignature, verifySelfSignature } from './crypto/x509-verify.js';
export type { VerifyCertificateSignatureOptions } from './crypto/x509-verify.js';
export { canVerify } from './crypto/webcrypto.js';

// ── 8. Building — certificates and requests, signed through Web Crypto ─

export { createCertificate, signatureAlgorithmDer } from './build/build-certificate.js';
export type { CreateOptions } from './build/build-certificate.js';
export { createCertificationRequest } from './build/build-csr.js';
export { canSign } from './crypto/webcrypto.js';
export {
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeValidity,
    KEY_USAGE_BITS,
} from './build/build-structures.js';
export type { GeneralNameDescription } from './build/build-structures.js';
export type {
    CertificateDescription,
    CertificationRequestDescription,
    ExtensionDescription,
    NameAttribute,
    NameDescription,
} from './types/build-types.js';
export type { SignatureAlgorithm, SignatureHash, SigningKey } from './types/crypto-types.js';
