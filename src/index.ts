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

export { PkiError, PkiEncodingError, PkiCertificateError, PkiLimitError, PkiCryptoError, PkiCmsError, PkiKeyError } from './types/pki-errors.js';
export type {
    PkiErrorCode,
    PkiBaseErrorCode,
    PkiEncodingErrorCode,
    PkiCertificateErrorCode,
    PkiLimitErrorCode,
    PkiCryptoErrorCode,
    PkiCmsErrorCode,
    PkiKeyErrorCode,
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

// ── 7. Certification path validation (RFC 5280 section 6) ────────────

export { findRevocation, parseCertificateList } from './revocation/crl-parse.js';
export type { FindRevocationOptions } from './revocation/crl-parse.js';
export { checkRevocation } from './revocation/crl-check.js';
export { createOcspRequest, encodeOcspCertId } from './revocation/ocsp-request.js';
export type { CreateOcspRequestOptions, OcspHashAlgorithm } from './revocation/ocsp-request.js';
export { parseOcspResponse } from './revocation/ocsp-response.js';
export { checkOcspStatus, OCSP_NONCE_OID } from './revocation/ocsp-check.js';
export type { CheckOcspStatusInput } from './revocation/ocsp-check.js';
export type { OcspBasicResponse, OcspCertId, OcspCertStatus, OcspResponderId, OcspResponse, OcspResponseStatus, OcspSingleResponse } from './types/ocsp-types.js';
export type { DeltaCrlInput, CheckRevocationInput } from './revocation/crl-check.js';
export type { CertificateList, CrlReason, IssuingDistributionPoint, RevokedCertificate } from './types/crl-types.js';
export { buildCertificatePath } from './path/path-build.js';
export { checkServerName, matchDnsName } from './path/path-server-name.js';
export type { CheckServerNameOptions, MatchDnsNameOptions, ServerIdentity } from './path/path-server-name.js';
export { ANY_EXTENDED_KEY_USAGE, checkExtendedKeyUsage, KEY_PURPOSES } from './path/path-purpose.js';
export type { CheckExtendedKeyUsageOptions } from './path/path-purpose.js';
export type { BuildCertificatePathInput, BuildCertificatePathReport } from './path/path-build.js';
export { validateCertificatePath } from './path/path-validate.js';
export { verifyCertificateChain } from './verify/verify-chain.js';
export type { VerifyCertificateChainInput, VerifyCertificateChainReport } from './verify/verify-chain.js';
export type { ValidateCertificatePathInput, ValidateCertificatePathReport, SignatureResult, SignatureVerdict } from './types/path-types.js';

// ── 2. ASN.1 — decoding, value readers, encoders ─────────────────────

export { decodeAsn1, decodeAsn1Sequence } from './asn1/asn1-decode.js';
export {
    readBoolean,
    readInteger,
    readSmallInteger,
    readEnumerated,
    readNull,
    readBitString,
    readOctetString,
    readString,
} from './asn1/asn1-read.js';
export { readRelativeOid } from './asn1/asn1-oid.js';
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
    encodeRelativeOid,
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
export { computeKeyIdentifier } from './hash/key-identifier.js';
export { shake256 } from './hash/shake256.js';
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
    DirectoryAttribute,
    SubjectDirectoryAttributesExtension,
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

export { verifyCertificateSignature, verifyCrlSignature, verifyOcspSignature, verifySelfSignature } from './crypto/x509-verify.js';
export type { VerifyCertificateSignatureOptions } from './crypto/x509-verify.js';
export { canVerify } from './crypto/webcrypto.js';

// ── 8. Building — certificates and requests, signed through Web Crypto ─

export { createCertificate, encodeSignatureAlgorithm } from './build/build-certificate.js';
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
    PkiBuildOptions,
} from './types/build-types.js';
export type { ExternalSigner, SignatureAlgorithm, SignatureHash, Signer, SigningKey } from './types/crypto-types.js';

// ── 9. CMS signed messages and RFC 3161 timestamps ───────────────────
// Parsing in cms/, the signature at the Web Crypto boundary in crypto/,
// writing in build/, and the two one-call verdicts in verify/ — the same
// split every other subsystem keeps.

export { parseSignedData } from './cms/cms-signed-data.js';
export type {
    Attribute,
    EssCertId,
    ParseSignedDataOptions,
    SignedData,
    SignerIdentifier,
    SignerInfo,
    SigningCertificateAttribute,
} from './types/cms-types.js';
export { verifySignerInfoSignature } from './crypto/cms-verify.js';
export type { VerifySignerInfoSignatureOptions } from './crypto/cms-verify.js';
export { addTimeStampToken, addUnsignedAttribute, createSignedData } from './build/build-signed-data.js';
export type { CreateSignedDataInput } from './build/build-signed-data.js';
export { parseTstInfo } from './cms/tsp-tst-info.js';
export { parseTimeStampResponse, parseTimeStampToken } from './cms/tsp-response.js';
export { createTimeStampRequest } from './cms/tsp-request.js';
export type { CreateTimeStampRequestOptions, TimeStampHashAlgorithm } from './cms/tsp-request.js';
export type {
    MessageImprint,
    TimeStampAccuracy,
    TimeStampFailure,
    TimeStampResponse,
    TimeStampStatus,
    TimeStampToken,
    TstInfo,
} from './types/tsp-types.js';
export { verifySignedData } from './verify/verify-signed-data.js';
export type { SignerReport, VerifySignedDataInput, VerifySignedDataReport } from './verify/verify-signed-data.js';
export { verifyTimeStampToken } from './verify/verify-timestamp.js';
export type { VerifyTimeStampTokenInput, VerifyTimeStampTokenReport } from './verify/verify-timestamp.js';

// ── 10. Private keys — PKCS#8 and PKCS#12, under PBES2 only ──────────
// Reading in keys/, the password operations at the Web Crypto door, and the
// one call that opens a whole .p12 in verify/. No type here holds a private
// key's bits: a key comes out as a non-extractable SigningKey.

export { parseEncryptedPrivateKeyInfo, parsePrivateKeyInfo } from './keys/key-pkcs8.js';
export { decryptPrivateKey, importPrivateKey } from './keys/key-import.js';
export { openSafeContents, parsePkcs12, verifyPkcs12Mac } from './keys/key-pkcs12.js';
export { canDecrypt } from './crypto/webcrypto.js';
export type {
    DecryptPrivateKeyOptions,
    EncryptedPrivateKeyInfo,
    ImportPrivateKeyOptions,
    PasswordEncryption,
    Pbes2Parameters,
    Pbkdf2Prf,
    Pkcs12,
    Pkcs12Mac,
    Pkcs12MacKind,
    PrivateKeyInfo,
    PrivateKeyKind,
    SafeBag,
    SafeBagKind,
    SafeContentsInfo,
} from './types/key-types.js';
export { openPkcs12 } from './verify/verify-pkcs12.js';
export type { Pkcs12Key, OpenPkcs12Options, OpenPkcs12Report } from './verify/verify-pkcs12.js';
