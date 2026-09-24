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
 * version: pkinative never creates, extracts or wraps key material. That is
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

/** The shape of `globalThis` as far as Web Crypto is concerned. */
export interface WebCryptoHost {
    readonly crypto?: {
        readonly subtle?: Partial<SubtleDigest & SubtlePublicKey> | undefined;
    } | undefined;
}
