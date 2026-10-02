/**
 * pkinative — PKCS#8 and PKCS#12 types
 * ====================================
 * What a private-key file and a PKCS#12 container carry, as far as pkinative
 * reads them.
 *
 * Two shapes are worth reading before the fields. **No type here holds a
 * private key's bits.** A `PrivateKeyInfo` describes a key without exposing
 * its `privateKey` octets, an `EncryptedPrivateKeyInfo` exposes only
 * ciphertext, and the one thing that comes out of decryption is a
 * `SigningKey` — an opaque, non-extractable handle. And **a password-based
 * scheme is always described, even when it is refused**: a PKCS#12 written
 * with RFC 7292 Appendix B, RC2 or 3DES still parses, with `pbes2`
 * `undefined`, so a tool can say exactly why it will not open it.
 *
 * @module types/key-types
 */

import type { BitString } from './asn1-types.js';
import type { Attribute } from './cms-types.js';
import type { SignatureAlgorithm, SignatureHash } from './crypto-types.js';
import type { PkiDiagnostic, PkiParseOptions } from './pki-types.js';
import type { AlgorithmIdentifier, EcCurve } from './x509-types.js';

/** The PBKDF2 pseudo-random functions pkinative derives with — the HMACs Web Crypto implements. */
export type Pbkdf2Prf = SignatureHash;

/**
 * PBES2 (RFC 8018 §6.2) with PBKDF2 and AES-CBC — the one password-based
 * scheme pkinative opens.
 */
export interface Pbes2Parameters {
    /** PBKDF2's salt, as a zero-copy view. */
    readonly salt: Uint8Array;
    /** PBKDF2's iteration count, already checked against `maxKdfIterations`. */
    readonly iterations: number;
    /** PBKDF2's PRF; `SHA-1` when the parameters omit it, as RFC 8018 §A.2 defaults. */
    readonly prf: Pbkdf2Prf;
    /** The AES key size, in bits, from the cipher OID (and equal to PBKDF2's `keyLength` when that is present). */
    readonly keyBits: 128 | 192 | 256;
    /** AES-CBC's initialisation vector, 16 octets. */
    readonly iv: Uint8Array;
    /** The cipher OID — `aes128-CBC-PAD`, `aes192-CBC-PAD` or `aes256-CBC-PAD`. */
    readonly cipherOid: string;
}

/** A password-based encryption scheme as found, whether or not pkinative will open it. */
export interface PasswordEncryption {
    /** The scheme, as encoded — PBES2's OID, or a PKCS#12 / PKCS#5 v1.5 scheme's. */
    readonly algorithm: AlgorithmIdentifier;
    /** The PBES2 parameters, or `undefined` when the scheme is one pkinative refuses. */
    readonly pbes2: Pbes2Parameters | undefined;
    /**
     * The scheme in words — `PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)`, or
     * the name of a refused one such as `pbeWithSHAAnd3-KeyTripleDES-CBC` — so
     * a tool can say what a file is protected with before anyone types a password.
     */
    readonly scheme: string;
}

/**
 * The kinds of private key a PrivateKeyInfo can name that pkinative recognises.
 *
 * `'unknown'` is open: a later minor may decode what lands here today and
 * report it under a kind of its own (ADR 0018): branch on the known kinds, and
 * treat it as a fallback rather than as a promise that the input stays unknown.
 */
export type PrivateKeyKind = 'rsa' | 'rsa-pss' | 'ec' | 'ed25519' | 'ed448' | 'unknown';

/**
 * RFC 5958 `OneAsymmetricKey` (PKCS#8 `PrivateKeyInfo` when version 0) —
 * described, never exposed: the `privateKey` octets are not a field.
 */
export interface PrivateKeyInfo {
    /** The whole structure, as a zero-copy view of the input. It contains the key in the clear. */
    readonly der: Uint8Array;
    /** 0 (`v1`, RFC 5208) or 1 (`v2`, RFC 5958, which may carry the public key). */
    readonly version: 0 | 1;
    /** The private key algorithm, as encoded. */
    readonly algorithm: AlgorithmIdentifier;
    /** What the algorithm OID names. */
    readonly kind: PrivateKeyKind;
    /** For an EC key, the curve named in the algorithm parameters, when Web Crypto implements it; otherwise `undefined`. */
    readonly curve: EcCurve | undefined;
    /** The `[0]` attributes, in encoded order; empty when absent. */
    readonly attributes: readonly Attribute[];
    /** The `[1]` public key of a version 1 structure, or `undefined`. */
    readonly publicKey: BitString | undefined;
    /** Profile concerns found while reading, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}

/** RFC 5958 §3 `EncryptedPrivateKeyInfo`: a scheme and ciphertext. */
export interface EncryptedPrivateKeyInfo {
    /** The whole structure, as a zero-copy view of the input. */
    readonly der: Uint8Array;
    /** How the key was encrypted. */
    readonly encryption: PasswordEncryption;
    /** The ciphertext, as a zero-copy view. */
    readonly encryptedData: Uint8Array;
    /** Profile concerns found while reading, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}

/**
 * Options of `importPrivateKey`: the parse options, and the algorithm the key
 * will sign with when the key alone does not say.
 */
export interface ImportPrivateKeyOptions extends PkiParseOptions {
    /**
     * The algorithm the key signs with. Optional when the key names it
     * unambiguously — an EC key signs ECDSA on its own curve with that curve's
     * customary digest (P-256 with SHA-256, P-384 with SHA-384, P-521 with
     * SHA-512), an Ed25519 or Ed448 key signs Ed25519 or Ed448. Required for
     * an RSA key, which may sign PKCS#1 v1.5 or PSS over any digest, and for
     * an `id-RSASSA-PSS` key, which signs PSS only but over a digest pkinative
     * does not guess. When given, it must fit the key: its family, and the
     * curve for ECDSA.
     */
    readonly algorithm?: SignatureAlgorithm | undefined;
}

/**
 * Options of `decryptPrivateKey`: the parse options, the password, and the
 * algorithm the key inside will sign with.
 */
export interface DecryptPrivateKeyOptions extends PkiParseOptions {
    /**
     * The password. A string is encoded as UTF-8, which is what OpenSSL 3.4
     * and later write under PBES2; a `Uint8Array` is used as given, for a file
     * written with another encoding, and is never modified or kept.
     */
    readonly password: Uint8Array | string;
    /**
     * The algorithm the key inside signs with. Required: the key's type is
     * inside the ciphertext, and the key is decrypted by the host straight into
     * a non-extractable handle, never into bytes pkinative could read first —
     * so the host must be told what it is before it decrypts.
     */
    readonly algorithm: SignatureAlgorithm;
}

/**
 * The six SafeBag types of RFC 7292 §4.2, and anything else.
 *
 * `'unknown'` is open: a later minor may decode what lands here today and
 * report it under a kind of its own (ADR 0018): branch on the known kinds, and
 * treat it as a fallback rather than as a promise that the input stays unknown.
 */
export type SafeBagKind = 'keyBag' | 'pkcs8ShroudedKeyBag' | 'certBag' | 'crlBag' | 'secretBag' | 'safeContentsBag' | 'unknown';

/** One RFC 7292 §4.2 SafeBag, read but not opened. */
export interface SafeBag {
    /** What the bag holds. */
    readonly kind: SafeBagKind;
    /** The `bagId`, as encoded. */
    readonly oid: string;
    /** The `bagValue`, the content of its `[0]` EXPLICIT tag, as exact DER. */
    readonly valueDer: Uint8Array;
    /** `friendlyName` (PKCS#9), when present once with one value. */
    readonly friendlyName: string | undefined;
    /** `localKeyId` (PKCS#9), when present once with one value — what ties a key to its certificate. */
    readonly localKeyId: Uint8Array | undefined;
    /** Every `bagAttributes` entry, in encoded order. */
    readonly attributes: readonly Attribute[];
    /** For a certBag holding an X.509 certificate, its DER; otherwise `undefined`. */
    readonly certificateDer: Uint8Array | undefined;
    /** For a crlBag holding an X.509 CRL, its DER; otherwise `undefined`. */
    readonly crlDer: Uint8Array | undefined;
    /** For a pkcs8ShroudedKeyBag, the encrypted key; otherwise `undefined`. */
    readonly encryptedKey: EncryptedPrivateKeyInfo | undefined;
    /** For a keyBag, the unencrypted key's description; otherwise `undefined`. */
    readonly privateKey: PrivateKeyInfo | undefined;
    /** The path of this bag, e.g. `authSafe[1].bags[0]`, for reports and errors. */
    readonly path: string;
}

/**
 * One ContentInfo of the AuthenticatedSafe: either plain `data` whose bags are
 * read, or password-encrypted `encryptedData` whose bags wait for a password.
 */
export interface SafeContentsInfo {
    /** Whether the SafeContents is encrypted. Public-key `envelopedData` is not read. */
    readonly encrypted: boolean;
    /** How it is encrypted, when it is. */
    readonly encryption: PasswordEncryption | undefined;
    /** The ciphertext, when it is encrypted. */
    readonly encryptedContent: Uint8Array | undefined;
    /** The bags, when it is not encrypted; empty until opened otherwise. */
    readonly bags: readonly SafeBag[];
    /** The path, e.g. `authSafe[0]`. */
    readonly path: string;
}

/** The two ways RFC 7292 and RFC 9579 compute a PKCS#12 MAC — one of which pkinative cannot check. */
export type Pkcs12MacKind =
    /** RFC 9579 PBMAC1: HMAC under a PBKDF2 key. Verifiable. */
    | 'pbmac1'
    /** RFC 7292 §5.1 with the Appendix B KDF — iterated hashing with byte arithmetic over the password. Not verifiable here, in any version. */
    | 'pkcs12-kdf';

/** A PKCS#12 `MacData`, described. */
export interface Pkcs12Mac {
    /** Which construction. */
    readonly kind: Pkcs12MacKind;
    /** The `digestAlgorithm` of the `DigestInfo`, as encoded — `id-PBMAC1` under RFC 9579. */
    readonly algorithm: AlgorithmIdentifier;
    /** The MAC octets. */
    readonly mac: Uint8Array;
    /** `macSalt`. RFC 9579 says to ignore it under PBMAC1; it is still reported. */
    readonly salt: Uint8Array;
    /** `iterations`, defaulting to 1. RFC 9579 says to ignore it under PBMAC1; it is still reported. */
    readonly iterations: number;
    /** Under PBMAC1, what the MAC key is derived with and which HMAC it keys; otherwise `undefined`. */
    readonly pbmac1: {
        readonly salt: Uint8Array;
        readonly iterations: number;
        readonly prf: Pbkdf2Prf;
        readonly keyLength: number;
        readonly hmac: Pbkdf2Prf;
    } | undefined;
}

/** RFC 7292 §4 `PFX`, read but not opened. */
export interface Pkcs12 {
    /** The whole structure, as a zero-copy view of the input. */
    readonly der: Uint8Array;
    /** Always 3; any other version is refused. */
    readonly version: 3;
    /** The bytes the MAC covers: the content of the `authSafe` data's OCTET STRING. */
    readonly authenticatedSafe: Uint8Array;
    /** The AuthenticatedSafe's entries, in encoded order. */
    readonly contents: readonly SafeContentsInfo[];
    /** The `macData`, or `undefined` when the file carries none. */
    readonly mac: Pkcs12Mac | undefined;
    /** Profile concerns found while reading, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}

