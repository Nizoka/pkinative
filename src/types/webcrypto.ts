/**
 * pkinative — Minimal Web Crypto types
 * ====================================
 * The library targets ES2020 without the DOM lib, so the handful of Web
 * Crypto members it uses are typed here, structurally, instead of pulling a
 * host's global declarations into the public types. Access always goes
 * through `globalThis` and is checked at run time.
 *
 * This file and `src/crypto/webcrypto.ts` are the only two modules of `src/`
 * allowed to name `importKey`, `verify` or `sign`, and the only two allowed
 * to reach `globalThis.crypto` (`KEY_OPERATION_POLICY` and
 * `WEBCRYPTO_HOST_MODULES` in scripts/lib/architecture.ts). This one appears
 * on the list because the architecture check fires on declarations too: the
 * boundary cannot describe the host it calls without naming them.
 *
 * What is **absent** here is the contract. There is no `generateKey`, no
 * `exportKey`, no `deriveBits`, no `encrypt` and no `wrapKey`, in any
 * version: pkinative never creates, extracts or wraps key material. What 0.8
 * added — `deriveKey`, `unwrapKey`, `decrypt` — each returns a handle or
 * public bytes, and {@link SubtlePassword} says why each was chosen over the
 * sibling that would have returned key material. That is
 * why a caller hands `createCertificate` a SubjectPublicKeyInfo in DER
 * rather than a `CryptoKey` — one line in their code, in exchange for a
 * promise a test can check.
 *
 * @module types/webcrypto
 */

/** An opaque handle to a key held by the host. pkinative never sees its bits. */
export interface CryptoKeyHandle {
    readonly type: string;
}

/** `{ name: 'SHA-256' }` and friends — the digest a signature algorithm is built on. */
export interface HashAlgorithmIdentifier {
    readonly name: string;
}

/** RSASSA-PKCS1-v1_5 and RSA-PSS import parameters. */
export interface RsaHashedImportParams {
    readonly name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';
    readonly hash: HashAlgorithmIdentifier;
}

/** ECDSA import parameters: the curve, by its Web Crypto name. */
export interface EcKeyImportParams {
    readonly name: 'ECDSA';
    readonly namedCurve: 'P-256' | 'P-384' | 'P-521';
}

/** Ed25519 and Ed448 take no parameter beyond the name. */
export interface EdKeyImportParams {
    readonly name: 'Ed25519' | 'Ed448';
}

/** Every import parameter pkinative passes. */
export type ImportParams = RsaHashedImportParams | EcKeyImportParams | EdKeyImportParams;

/** RSASSA-PKCS1-v1_5, Ed25519 and Ed448 sign and verify by name alone. */
export interface NamedVerifyParams {
    readonly name: string;
}

/** RSA-PSS signing parameters — the same shape verification takes. */
export interface RsaPssSignParams {
    readonly name: 'RSA-PSS';
    readonly saltLength: number;
}

/** RSA-PSS carries the salt length, in bytes, read from the certificate's parameters. */
export interface RsaPssVerifyParams {
    readonly name: 'RSA-PSS';
    readonly saltLength: number;
}

/** ECDSA carries the digest, and takes its signature as raw r‖s, never as DER. */
export interface EcdsaVerifyParams {
    readonly name: 'ECDSA';
    readonly hash: HashAlgorithmIdentifier;
}

/** Every verify parameter pkinative passes. */
export type VerifyParams = NamedVerifyParams | RsaPssVerifyParams | EcdsaVerifyParams;

/** The `crypto.subtle` members pkinative calls. */
export interface SubtleDigest {
    digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
}

/**
 * The public-key half of `crypto.subtle`: import a public key, check a
 * signature against public data. Both take only material that is already
 * public — an SPKI from a certificate, and the bytes it signed.
 */
export interface SubtlePublicKey {
    importKey(format: 'spki', keyData: Uint8Array, algorithm: ImportParams, extractable: boolean, keyUsages: readonly string[]): Promise<CryptoKeyHandle>;
    verify(algorithm: VerifyParams, key: CryptoKeyHandle, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
    /**
     * Signs with a key the **caller** imported and holds. There is no
     * `importKey` for a private key here and no `exportKey` anywhere: the
     * only thing pkinative ever does with a signing key is hand it back to
     * the host with the bytes to cover.
     */
    sign(algorithm: VerifyParams, key: CryptoKeyHandle, data: Uint8Array): Promise<ArrayBuffer>;
}

/** PBKDF2 (RFC 8018 §5.2), the only password-based derivation pkinative asks for. */
export interface Pbkdf2Params {
    readonly name: 'PBKDF2';
    readonly salt: Uint8Array;
    readonly iterations: number;
    readonly hash: HashAlgorithmIdentifier;
}

/** What a password-derived key is for: AES-CBC to decrypt a PBES2 payload, or HMAC to check an RFC 9579 PBMAC1 MAC. */
export type DerivedKeyParams =
    | { readonly name: 'AES-CBC'; readonly length: 128 | 192 | 256 }
    | { readonly name: 'HMAC'; readonly hash: HashAlgorithmIdentifier; readonly length: number };

/** AES-CBC with its initialisation vector, the PBES2 encryption scheme (RFC 8018 §B.2.5). */
export interface AesCbcParams {
    readonly name: 'AES-CBC';
    readonly iv: Uint8Array;
}

/**
 * The password half of `crypto.subtle`, opened in 0.8 for PKCS#8 and PKCS#12
 * under PBES2 and nothing else.
 *
 * Every member returns a **handle** or public bytes, never key material:
 * `deriveKey` rather than `deriveBits`, so the derived key is a
 * non-extractable object whose bits never reach the JavaScript heap; and
 * `unwrapKey` rather than `decrypt` for a private key, so an encrypted PKCS#8
 * becomes a `CryptoKey` without its plaintext ever existing here. `decrypt` is
 * for the one payload that has no key in it — a PKCS#12 bag of certificates.
 */
export interface SubtlePassword {
    importKey(format: 'raw', keyData: Uint8Array, algorithm: 'PBKDF2', extractable: false, keyUsages: readonly ['deriveKey']): Promise<CryptoKeyHandle>;
    importKey(format: 'pkcs8', keyData: Uint8Array, algorithm: ImportParams, extractable: false, keyUsages: readonly ['sign']): Promise<CryptoKeyHandle>;
    deriveKey(algorithm: Pbkdf2Params, baseKey: CryptoKeyHandle, derivedKeyType: DerivedKeyParams, extractable: false, keyUsages: readonly string[]): Promise<CryptoKeyHandle>;
    unwrapKey(format: 'pkcs8', wrappedKey: Uint8Array, unwrappingKey: CryptoKeyHandle, unwrapAlgorithm: AesCbcParams, unwrappedKeyAlgorithm: ImportParams, extractable: false, keyUsages: readonly ['sign']): Promise<CryptoKeyHandle>;
    decrypt(algorithm: AesCbcParams, key: CryptoKeyHandle, data: Uint8Array): Promise<ArrayBuffer>;
    verify(algorithm: { readonly name: 'HMAC' }, key: CryptoKeyHandle, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}

/**
 * What is probed on `crypto.subtle` before anything is called: each member's
 * **presence**, never its signature.
 *
 * The signatures belong to the interfaces above, and are asserted only after
 * a run-time check has found every member a caller needs. Declaring them here
 * too would claim a shape for a host object pkinative has not inspected — and
 * an intersection of `importKey` overloads that no real `SubtleCrypto` is
 * comparable to once a host's own lib types are in scope.
 */
export interface HostSubtle {
    readonly digest?: unknown;
    readonly importKey?: unknown;
    readonly verify?: unknown;
    readonly sign?: unknown;
    readonly deriveKey?: unknown;
    readonly unwrapKey?: unknown;
    readonly decrypt?: unknown;
}

/** The shape of `globalThis` as far as Web Crypto is concerned. */
export interface WebCryptoHost {
    readonly crypto?: {
        readonly subtle?: HostSubtle | undefined;
    } | undefined;
}
