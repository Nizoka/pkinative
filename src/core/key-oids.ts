/**
 * pkinative — PKCS#8 and PKCS#12 object identifiers
 * =================================================
 * The OIDs RFC 5958, RFC 8018, RFC 7292 and RFC 9579 name, in one table, so
 * that the key readers and the one-call PKCS#12 reader compare against the
 * same strings.
 *
 * It lives in `core` for the reason `cms-oids.ts` does: `keys` parses these
 * OIDs and `verify` decides with them, and `core` is the one layer both
 * import. The refused schemes are listed as carefully as the accepted ones —
 * a scheme pkinative will not open is still named in the error, so a caller
 * learns what they have and not only that it failed.
 *
 * @module core/key-oids
 */

import type { Pbkdf2Prf } from '../types/key-types.js';

// ── PBES2 (RFC 8018) ──

/** `id-PBES2`: the one password-based encryption scheme pkinative opens. */
export const OID_PBES2 = '1.2.840.113549.1.5.13';
/** `id-PBKDF2`: the one key derivation function it runs. */
export const OID_PBKDF2 = '1.2.840.113549.1.5.12';
/** `id-PBMAC1` (RFC 8018 §7.1, profiled for PKCS#12 by RFC 9579): the one MAC it verifies. */
export const OID_PBMAC1 = '1.2.840.113549.1.5.14';

/** PBKDF2's pseudo-random functions and PBMAC1's MACs — the HMACs Web Crypto implements, by OID (RFC 8018 §B.1.2). */
export const HMAC_OIDS: ReadonlyMap<string, Pbkdf2Prf> = /*#__PURE__*/ new Map<string, Pbkdf2Prf>([
    ['1.2.840.113549.2.7', 'SHA-1'],
    ['1.2.840.113549.2.9', 'SHA-256'],
    ['1.2.840.113549.2.10', 'SHA-384'],
    ['1.2.840.113549.2.11', 'SHA-512'],
]);

/** AES-CBC with PKCS#7 padding (RFC 8018 §B.2.5), by OID, with its key size in bits. */
export const AES_CBC_OIDS: ReadonlyMap<string, 128 | 192 | 256> = /*#__PURE__*/ new Map<string, 128 | 192 | 256>([
    ['2.16.840.1.101.3.4.1.2', 128],
    ['2.16.840.1.101.3.4.1.22', 192],
    ['2.16.840.1.101.3.4.1.42', 256],
]);

/**
 * The password-based schemes pkinative recognises and refuses, by OID, with
 * the name an error gives them: RFC 7292 Appendix C, whose key comes from the
 * Appendix B KDF, and the PKCS#5 v1.5 PBES1 schemes (RFC 8018 §6.1).
 */
export const REFUSED_PBE_SCHEMES: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    ['1.2.840.113549.1.12.1.1', 'pbeWithSHAAnd128BitRC4'],
    ['1.2.840.113549.1.12.1.2', 'pbeWithSHAAnd40BitRC4'],
    ['1.2.840.113549.1.12.1.3', 'pbeWithSHAAnd3-KeyTripleDES-CBC'],
    ['1.2.840.113549.1.12.1.4', 'pbeWithSHAAnd2-KeyTripleDES-CBC'],
    ['1.2.840.113549.1.12.1.5', 'pbeWithSHAAnd128BitRC2-CBC'],
    ['1.2.840.113549.1.12.1.6', 'pbeWithSHAAnd40BitRC2-CBC'],
    ['1.2.840.113549.1.5.1', 'pbeWithMD2AndDES-CBC'],
    ['1.2.840.113549.1.5.3', 'pbeWithMD5AndDES-CBC'],
    ['1.2.840.113549.1.5.4', 'pbeWithMD2AndRC2-CBC'],
    ['1.2.840.113549.1.5.6', 'pbeWithMD5AndRC2-CBC'],
    ['1.2.840.113549.1.5.10', 'pbeWithSHA1AndDES-CBC'],
    ['1.2.840.113549.1.5.11', 'pbeWithSHA1AndRC2-CBC'],
]);

// ── PKCS#12 (RFC 7292 §4.2) ──

/** SafeBag types, by OID. */
export const OID_KEY_BAG = '1.2.840.113549.1.12.10.1.1';
export const OID_PKCS8_SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
export const OID_CERT_BAG = '1.2.840.113549.1.12.10.1.3';
export const OID_CRL_BAG = '1.2.840.113549.1.12.10.1.4';
export const OID_SECRET_BAG = '1.2.840.113549.1.12.10.1.5';
export const OID_SAFE_CONTENTS_BAG = '1.2.840.113549.1.12.10.1.6';

/** `x509Certificate` (PKCS#9): a certBag holding DER in an OCTET STRING. */
export const OID_CERT_TYPE_X509 = '1.2.840.113549.1.9.22.1';
/** `x509CRL` (PKCS#9): a crlBag holding DER in an OCTET STRING. */
export const OID_CRL_TYPE_X509 = '1.2.840.113549.1.9.23.1';

/** `friendlyName` (PKCS#9): a BMPString label. */
export const OID_ATTR_FRIENDLY_NAME = '1.2.840.113549.1.9.20';
/** `localKeyId` (PKCS#9): an OCTET STRING tying a key to its certificate. */
export const OID_ATTR_LOCAL_KEY_ID = '1.2.840.113549.1.9.21';

// ── Private key algorithms (RFC 5958 §2) ──

/** `rsaEncryption`: an RSA key usable for PKCS#1 v1.5 or PSS. */
export const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
/** `id-RSASSA-PSS`: an RSA key restricted to PSS (RFC 4055 §1.2). */
export const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
/** `id-ecPublicKey`: an EC key; the curve is in the parameters. */
export const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
/** `id-Ed25519` (RFC 8410). */
export const OID_ED25519 = '1.3.101.112';
/** `id-Ed448` (RFC 8410). */
export const OID_ED448 = '1.3.101.113';

/** The named curves Web Crypto signs with, by OID. */
export const EC_CURVE_OIDS: ReadonlyMap<string, 'P-256' | 'P-384' | 'P-521'> = /*#__PURE__*/ new Map<string, 'P-256' | 'P-384' | 'P-521'>([
    ['1.2.840.10045.3.1.7', 'P-256'],
    ['1.3.132.0.34', 'P-384'],
    ['1.3.132.0.35', 'P-521'],
]);
