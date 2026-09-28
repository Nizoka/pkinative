/**
 * pkinative — CMS and TSP object identifiers
 * ==========================================
 * The OIDs RFC 5652, RFC 3161, RFC 2634, RFC 5035 and RFC 6211 name, in one
 * table, so that a parser, a builder and a verifier compare against the same
 * strings and a typo in one of them cannot make it disagree with the others.
 *
 * It lives in `core` because three layers read it — `build` writes these
 * OIDs, `cms` parses them and `verify` decides with them — and `core` is the one
 * layer all three already import. In `cms` it would be out of reach of `build`,
 * which `cms` itself imports, and the builder would have to keep a second copy:
 * exactly the drift the table exists to prevent. It is not the `oid/` name
 * registry either, which is data that only `getOidName` should pull into a
 * bundle.
 *
 * @module core/cms-oids
 */

// ── Content types (RFC 5652 §4–§9, RFC 3161 §2.4.2) ──

/** `id-data`: arbitrary octets. The only content type a SignedData may carry without signed attributes. */
export const OID_DATA = '1.2.840.113549.1.7.1';
/** `id-signedData`. */
export const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
/** `id-envelopedData` — named so that it can be refused by name. */
export const OID_ENVELOPED_DATA = '1.2.840.113549.1.7.3';
/** `id-digestedData` — named so that it can be refused by name. */
export const OID_DIGESTED_DATA = '1.2.840.113549.1.7.5';
/** `id-encryptedData` — named so that it can be refused by name. */
export const OID_ENCRYPTED_DATA = '1.2.840.113549.1.7.6';
/** `id-ct-authData` — named so that it can be refused by name. */
export const OID_AUTH_DATA = '1.2.840.113549.1.9.16.1.2';
/** `id-ct-TSTInfo`: the content of a timestamp token. */
export const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

// ── Attributes (RFC 5652 §11, RFC 2634 §5.4, RFC 5035 §3, RFC 3161 App. A, RFC 6211 §2) ──

/** `id-contentType`: signed only, one value — the attribute that binds the signed attributes to what they sign. */
export const OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
/** `id-messageDigest`: signed only, one value — the signer's commitment to the content. */
export const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
/** `id-signingTime`: signed only, one value — the time the signer **claims**. */
export const OID_ATTR_SIGNING_TIME = '1.2.840.113549.1.9.5';
/** `id-countersignature`: unsigned only. Carried, not verified, in 0.7. */
export const OID_ATTR_COUNTERSIGNATURE = '1.2.840.113549.1.9.6';
/** `id-aa-signingCertificate` (ESSCertID, SHA-1). */
export const OID_ATTR_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12';
/** `id-aa-signingCertificateV2` (ESSCertIDv2, any hash). */
export const OID_ATTR_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47';
/** `id-aa-timeStampToken`: an RFC 3161 token over this signer's signature value, unsigned. */
export const OID_ATTR_TIMESTAMP_TOKEN = '1.2.840.113549.1.9.16.2.14';
/** `id-aa-CMSAlgorithmProtection`: signed only — the signer's own statement of the algorithms it used. */
export const OID_ATTR_ALGORITHM_PROTECTION = '1.2.840.113549.1.9.52';

/** Attributes RFC 5652, RFC 2634, RFC 5035 and RFC 6211 allow **only** among the signed attributes. */
export const SIGNED_ONLY_ATTRIBUTES: ReadonlySet<string> = /*#__PURE__*/ new Set([
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_ATTR_SIGNING_TIME,
    OID_ATTR_SIGNING_CERTIFICATE,
    OID_ATTR_SIGNING_CERTIFICATE_V2,
    OID_ATTR_ALGORITHM_PROTECTION,
]);

// ── Revocation information (RFC 5940) ──

/** `id-ri-ocsp-response`: an `OCSPResponse` carried in a SignedData's `crls` field. */
export const OID_RI_OCSP_RESPONSE = '1.3.6.1.5.5.7.16.2';

// ── Key purposes (RFC 3161 §2.3) ──

/** `id-kp-timeStamping`: the only purpose a TSA certificate may carry, and it must be critical. */
export const OID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
