/**
 * pkinative — RFC 5652 CMS SignedData types
 * =========================================
 * What a SignedData carries, and what one signer inside it says.
 *
 * The shape worth reading before the fields is `SignerInfo.signedAttributesDer`.
 * RFC 5652 §5.4 transmits the signed attributes under an IMPLICIT `[0]` tag and
 * signs them under an explicit `SET OF` tag — the same length and content, one
 * different octet. A verifier that hashed the bytes as they arrive would check
 * every CMS signature against the wrong input, and one that re-encoded the set
 * from decoded attributes would check it against a re-sorted input the signer
 * never saw. So the parser exposes **the exact bytes the signature covers**, the
 * way `Certificate.tbsDer` does, and nothing downstream re-derives them.
 *
 * Certificates and revocation lists are kept as DER. A SignedData is a
 * *container*: the bag it carries is a claim by whoever assembled it, and parsing
 * every entry up front would spend work on certificates nobody asks about and
 * refuse a whole message over one unrelated malformed certificate. The caller —
 * or `verifySignedData` — parses what it uses.
 *
 * @module types/cms-types
 */

import type { PkiTime } from './asn1-types.js';
import type { PkiDiagnostic, PkiParseOptions } from './pki-types.js';
import type { AlgorithmIdentifier, DistinguishedName, GeneralName, SerialNumber } from './x509-types.js';

/** What `parseSignedData` takes beyond the ordinary parse options. */
export interface ParseSignedDataOptions extends PkiParseOptions {
    /**
     * Accept bytes after the `ContentInfo`, and ignore them.
     *
     * For one case, and it is common enough to name: a PDF signature's
     * `/Contents` is a fixed-size placeholder, zero-padded after the DER. Off by
     * default, because anywhere else bytes after the structure are either a
     * second object or an attempt to smuggle one past a reader that stops early.
     * `SignedData.der` never includes them.
     */
    readonly allowTrailingData?: boolean | undefined;
}

/**
 * `SignerIdentifier` (RFC 5652 §5.3): which certificate holds the key that
 * signed. Two alternatives, and they identify differently.
 *
 * `issuerAndSerialNumber` names a certificate; `subjectKeyIdentifier` names a
 * **key**, which several certificates may hold — a rollover or a cross-signature
 * leaves two. Matching the latter therefore finds candidates, not *the*
 * certificate, and the signature settles which one.
 */
export type SignerIdentifier =
    | {
        /** Discriminant: `version` 1 signers use this alternative. */
        readonly kind: 'issuerAndSerialNumber';
        /** The issuer of the signer's certificate. Match it by `der`, never by rendering. */
        readonly issuer: DistinguishedName;
        /** The serial of the signer's certificate. Compare by `bytes` or `hex`. */
        readonly serialNumber: SerialNumber;
    }
    | {
        /** Discriminant: `version` 3 signers use this alternative. */
        readonly kind: 'subjectKeyIdentifier';
        /** The key identifier, as the certificate's `subjectKeyIdentifier` extension would carry it. */
        readonly keyIdentifier: Uint8Array;
    };

/** One `Attribute` (RFC 5652 §5.3): a type and a non-empty set of values. */
export interface Attribute {
    /** The attribute type. */
    readonly oid: string;
    /** Each `AttributeValue`, as its exact DER, in encoded order. */
    readonly values: readonly Uint8Array[];
    /** The whole `Attribute` SEQUENCE, exactly as encoded. */
    readonly der: Uint8Array;
}

/**
 * One `ESSCertID` (RFC 2634 §5.4.1) or `ESSCertIDv2` (RFC 5035 §4): a hash of a
 * certificate the signer commits to having signed with.
 *
 * It is what stops a signature being re-attributed. Without it, anyone who
 * obtains a second certificate for the same key — a rollover, a cross-signature,
 * a CA misissuing one — can present the signature under that certificate
 * instead; the hash binds the signature to one specific certificate.
 */
export interface EssCertId {
    /**
     * The digest `certHash` was computed with, as Web Crypto names it — SHA-1
     * for v1, SHA-256 when a v2 omits it — or the dotted OID when it is a digest
     * pkinative does not compute. An unknown digest is not refused here: it only
     * means the binding cannot be checked, which is the verifier's to say.
     */
    readonly hashAlgorithm: string;
    /** The digest of the whole certificate DER. */
    readonly certHash: Uint8Array;
    /** `issuerSerial`, when the signer included it; `undefined` otherwise. */
    readonly issuerSerial: {
        /** The certificate issuer, as `GeneralNames` — in practice one `directoryName`. */
        readonly issuer: readonly GeneralName[];
        /** The certificate serial. Compare by `bytes` or `hex`. */
        readonly serialNumber: SerialNumber;
    } | undefined;
}

/** `SigningCertificate` (RFC 2634 §5.4) or `SigningCertificateV2` (RFC 5035 §3). */
export interface SigningCertificateAttribute {
    /** `1` for `id-aa-signingCertificate`, `2` for `id-aa-signingCertificateV2`. */
    readonly version: 1 | 2;
    /** The first entry names the signing certificate; any others constrain the path (RFC 5035 §3). */
    readonly certIds: readonly EssCertId[];
}

/** One `SignerInfo` (RFC 5652 §5.3). */
export interface SignerInfo {
    /** `1` when `sid` is `issuerAndSerialNumber`, `3` when it is `subjectKeyIdentifier`. */
    readonly version: 1 | 3;
    /** Which certificate holds the signing key. */
    readonly sid: SignerIdentifier;
    /** The digest over the content, and — when `signedAttributes` are present — over them too. */
    readonly digestAlgorithm: AlgorithmIdentifier;
    /** The signed attributes in encoded order; `undefined` when absent, which is not the same as empty. */
    readonly signedAttributes: readonly Attribute[] | undefined;
    /**
     * The exact bytes the signature covers when `signedAttributes` are present:
     * the transmitted `[0]` value with its tag replaced by the `SET OF` tag
     * `0x31` (RFC 5652 §5.4). `undefined` when there are no signed attributes,
     * in which case the signature is over the content itself.
     */
    readonly signedAttributesDer: Uint8Array | undefined;
    /** The algorithm the signature was made with — often a bare key algorithm such as `rsaEncryption`, the digest being `digestAlgorithm`. */
    readonly signatureAlgorithm: AlgorithmIdentifier;
    /** The signature value, as the OCTET STRING content. ECDSA is DER-encoded here, as in X.509. */
    readonly signature: Uint8Array;
    /** The unsigned attributes in encoded order; `undefined` when absent. */
    readonly unsignedAttributes: readonly Attribute[] | undefined;
    // The six fields below are conveniences over `signedAttributes`, and each
    // is set **only when its attribute appears exactly once, with exactly one
    // value, among the signed attributes**. A field that took "the first one"
    // would hide a second `messageDigest` — which is not a formatting slip but
    // the shape of an attack — so a repeated or multi-valued attribute leaves
    // the field `undefined`, and `verifySignedData`, reading the raw list, says
    // why. A recognised attribute whose value is malformed is refused outright.
    /** `contentType` (§11.1), the one attribute that makes the signed attributes bind to what they sign; `undefined` when absent. */
    readonly contentType: string | undefined;
    /** `messageDigest` (§11.2), the digest of the content the signer committed to; `undefined` when absent. */
    readonly messageDigest: Uint8Array | undefined;
    /** `signingTime` (§11.3) as the signer **claims** it — nothing vouches for it but the signer. `undefined` when absent. */
    readonly signingTime: PkiTime | undefined;
    /** `signingCertificate` or `signingCertificateV2`, whichever is present; `undefined` when neither is. */
    readonly signingCertificate: SigningCertificateAttribute | undefined;
    /**
     * `CMSAlgorithmProtection` (RFC 6211): the signer's **signed** statement of
     * the algorithms it used. `digestAlgorithm` and `signatureAlgorithm` above
     * are not covered by the signature; these are, and a verifier compares the
     * two to refuse an algorithm swapped in after signing. `undefined` when the
     * signer did not include one.
     */
    readonly algorithmProtection: {
        /** The digest the signer says it used. */
        readonly digestAlgorithm: AlgorithmIdentifier;
        /** The signature algorithm the signer says it used; its `der` carries the IMPLICIT `[1]` tag it was read under. */
        readonly signatureAlgorithm: AlgorithmIdentifier;
    } | undefined;
    /**
     * Every `id-aa-signatureTimeStampToken` (RFC 3161 Appendix A) among the
     * unsigned attributes, each a `ContentInfo` DER that `parseTimeStampToken`
     * reads. Empty when there are none.
     */
    readonly timeStampTokens: readonly Uint8Array[];
    /** The whole `SignerInfo`, exactly as encoded. */
    readonly der: Uint8Array;
}

/** A parsed `ContentInfo` whose `contentType` is `id-signedData` (RFC 5652 §3, §5.1). */
export interface SignedData {
    /** The whole `ContentInfo`, as a zero-copy view of the input. */
    readonly der: Uint8Array;
    /** `1`, `3`, `4` or `5`, as §5.1 derives it from what the structure carries. */
    readonly version: 1 | 3 | 4 | 5;
    /** `digestAlgorithms`: every digest any signer used, in encoded order. */
    readonly digestAlgorithms: readonly AlgorithmIdentifier[];
    /** `eContentType` — `id-data` for arbitrary bytes, `id-ct-TSTInfo` for a timestamp token. */
    readonly contentType: string;
    /**
     * The `eContent` octets; `undefined` when the content is **detached**, which
     * is how a PDF signature and most S/MIME signatures are made. A detached
     * signature can only be verified against content, or its digest, that the
     * caller supplies.
     */
    readonly content: Uint8Array | undefined;
    /** Every `certificate` choice of `certificates`, as DER, in encoded order. A claim by whoever assembled the message. */
    readonly certificates: readonly Uint8Array[];
    /** Every `CertificateList` of `crls`, as DER, in encoded order. */
    readonly crls: readonly Uint8Array[];
    /**
     * Every `OCSPResponse` carried as `other` with `id-ri-ocsp-response` in
     * `crls` (RFC 5940), as DER. This is where CAdES and long-term PDF
     * signatures keep the revocation evidence they were validated with.
     */
    readonly ocspResponses: readonly Uint8Array[];
    /**
     * The signers, in encoded order. **Possibly empty**: RFC 5652 §5.1 allows a
     * "degenerate" SignedData with no signer, which is how `.p7b` and `.p7c`
     * certificate bundles ship a chain. Parsing one is ordinary; verifying one
     * proves nothing, and `verifySignedData` says so rather than succeeding.
     */
    readonly signerInfos: readonly SignerInfo[];
    /** Profile concerns found while reading, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
