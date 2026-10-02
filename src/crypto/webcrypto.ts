/**
 * pkinative — the Web Crypto boundary
 * ===================================
 * The one door. This is the only module of `src/` allowed to name
 * `importKey` or `verify`, and — with `src/hash/fingerprint.ts` — one of two
 * allowed to reach `globalThis.crypto` at all
 * (`KEY_OPERATION_POLICY` and `WEBCRYPTO_HOST_MODULES` in
 * scripts/lib/architecture.ts, enforced by tests/tools/architecture.test.ts).
 *
 * Everything pkinative asks of a host is therefore readable in one file, in
 * about sixty lines. That is the whole point of the rule: not that the
 * library is careful with keys, but that a reviewer can confirm it in one
 * sitting.
 *
 * What it asks for is narrow by construction. Public keys are imported from
 * `spki` — the bytes a certificate already publishes — with
 * `extractable: false` and the single usage `['verify']`. Since 0.8, private
 * keys arrive here from a PKCS#8 the caller holds or one a password unwraps,
 * always `extractable: false` with the single usage `['sign']`. There is no
 * path from here back to key material: `exportKey`, `deriveBits` and
 * `wrapKey` are refused by the architecture test, in this file as in every
 * other.
 *
 * @module crypto/webcrypto
 */

import { PkiCryptoError } from '../types/pki-errors.js';
import type {
    CryptoKeyHandle,
    DerivedKeyParams,
    ImportParams,
    Pbkdf2Params,
    SubtlePassword,
    SubtlePublicKey,
    VerifyParams,
    WebCryptoHost,
} from '../types/webcrypto.js';

/** The host's `crypto.subtle`, or null when it cannot verify. */
function publicKeySubtle(): SubtlePublicKey | null {
    const subtle = (globalThis as WebCryptoHost).crypto?.subtle;
    if (subtle === undefined || typeof subtle.importKey !== 'function' || typeof subtle.verify !== 'function') return null;
    return subtle as SubtlePublicKey;
}

/** The host's `crypto.subtle`, or null when it cannot sign. */
function signingSubtle(): SubtlePublicKey | null {
    const subtle = (globalThis as WebCryptoHost).crypto?.subtle;
    if (subtle === undefined || typeof subtle.sign !== 'function') return null;
    return subtle as SubtlePublicKey;
}

/**
 * Whether this runtime can verify a signature at all.
 *
 * Exposed so a caller can branch before building a report rather than
 * catching an exception inside one. Every modern runtime returns `true`;
 * a page served over plain HTTP has no `crypto.subtle` and returns
 * `false`, as does a sandbox that withholds it.
 *
 * @returns Whether `globalThis.crypto.subtle` offers both `importKey` and
 *   `verify`. It does not say which algorithms the host implements —
 *   Ed448 and Ed25519 are missing on several runtimes that answer `true`.
 * @throws Never — a missing host is the answer, not an error.
 */
export function canVerify(): boolean {
    return publicKeySubtle() !== null;
}

function requireSubtle(oid: string): SubtlePublicKey {
    const subtle = publicKeySubtle();
    if (subtle === null) {
        throw new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE',
            'pkinative: this runtime exposes no crypto.subtle with importKey and verify, so no signature can be checked — call canVerify() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)', oid);
    }
    return subtle;
}

/**
 * Import a SubjectPublicKeyInfo as a non-extractable verification key.
 *
 * @param spkiDer The complete SubjectPublicKeyInfo encoding — the `der` of a
 *   parsed certificate's `subjectPublicKeyInfo`, not the key bits alone.
 * @param params What Web Crypto must be told the key is.
 * @param oid The signature algorithm OID, carried into any error.
 * @param refusal Why a refusal is to be expected, when the caller knows —
 *   it replaces the generic "try another runtime" advice in the error.
 * @returns An opaque handle. pkinative never sees the key's bits.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the host cannot
 *   verify; `PKI_CRYPTO_KEY_UNSUPPORTED` when it refuses the key — an
 *   algorithm it does not implement (Ed448 and, on several runtimes still,
 *   Ed25519), an `id-RSASSA-PSS` SubjectPublicKeyInfo, which the W3C Web
 *   Crypto specification refuses in every runtime that follows it, or key
 *   bytes it will not accept.
 */
export async function importPublicKey(spkiDer: Uint8Array, params: ImportParams, oid: string, refusal?: string): Promise<CryptoKeyHandle> {
    const subtle = requireSubtle(oid);
    try {
        return await subtle.importKey('spki', spkiDer, params, false, ['verify']);
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
            `pkinative: this runtime refused to import the issuer's ${params.name} public key (${String(cause)}) — ${refusal ?? 'the algorithm may not be implemented here, or the key may be malformed; try another runtime before concluding the certificate is at fault'}`, oid);
    }
}

/**
 * Check one signature over one message.
 *
 * A host that throws is treated as a refusal, not as an incident: several
 * runtimes throw rather than return false for a signature of the wrong
 * length, and the two answers mean the same thing to a caller. Failing
 * closed here is what keeps a malformed signature from becoming an
 * exception someone catches into a success path.
 *
 * @param key A handle from {@link importPublicKey}.
 * @param params The algorithm, already resolved.
 * @param signature Raw signature octets — `r ‖ s` for ECDSA, never DER.
 * @param data The signed bytes, `tbsCertificate` for a certificate.
 * @returns Whether the signature checks out.
 */
export async function verifySignature(key: CryptoKeyHandle, params: VerifyParams, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    const subtle = requireSubtle(params.name);
    try {
        return await subtle.verify(params, key, signature, data);
    } catch {
        // capability probe: whatever the host throws (OperationError, DataError, TypeError) is its refusal to verify, and refusal fails closed.
        return false;
    }
}

/**
 * Whether this runtime can sign at all.
 *
 * The counterpart of {@link canVerify}, and worth asking before building a
 * certificate rather than catching an exception half way through one.
 *
 * @returns Whether `globalThis.crypto.subtle` offers `sign`. It says nothing
 *   about which algorithms the host implements, nor about the key.
 * @throws Never — a missing host is the answer, not an error.
 */
export function canSign(): boolean {
    return signingSubtle() !== null;
}

/**
 * Sign bytes with a key the caller holds.
 *
 * pkinative never creates, imports or exports a private key: the
 * `CryptoKeyHandle` arrives from the caller's own `importKey` or
 * `generateKey`, and the only thing done with it here is this call. That is
 * why `generateKey` and `exportKey` can stay refused in `src/` forever
 * (`KEY_OPERATION_POLICY`), and why a reviewer can confirm the claim by
 * reading this one function.
 *
 * A failure is **not** treated as "unsigned": unlike verification, where
 * "no" is a legitimate answer, a signature that did not happen has no safe
 * falsy value — an empty signature is a certificate that verifies nowhere
 * and looks valid until someone checks. So this throws.
 *
 * @param key    A private key with the `sign` usage.
 * @param params The algorithm, already resolved.
 * @param data   The bytes to cover — `tbsCertificate` for a certificate.
 * @returns The signature octets, in whatever form Web Crypto returns
 *   (raw `r ‖ s` for ECDSA; the caller converts).
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the runtime cannot
 *   sign; `PKI_CRYPTO_KEY_UNSUPPORTED` when the host refuses the key — the
 *   wrong algorithm for it, a missing `sign` usage, or an algorithm it does
 *   not implement.
 */
export async function signData(key: CryptoKeyHandle, params: VerifyParams, data: Uint8Array): Promise<Uint8Array> {
    const subtle = signingSubtle();
    if (subtle === null) {
        throw new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE',
            'pkinative: this runtime exposes no crypto.subtle.sign, so nothing can be signed — call canSign() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)', params.name);
    }
    try {
        return new Uint8Array(await subtle.sign(params, key, data));
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
            `pkinative: this runtime refused to sign with the key given for ${params.name} (${String(cause)}) — check that the key is private, carries the "sign" usage, and matches the algorithm named`, params.name);
    }
}

// ── Passwords: PKCS#8 and PKCS#12 under PBES2 (0.8) ──────────────────
//
// Five calls, and each returns a handle or public bytes. The password is
// imported as a PBKDF2 base key and never used again; `deriveKey` turns it
// into a non-extractable AES or HMAC key; `unwrapKey` turns an encrypted
// PKCS#8 into a non-extractable signing key without its plaintext passing
// through here; `decrypt` opens a SafeContents, which holds certificates and,
// when its writer put one there, an unencrypted keyBag — plaintext by
// definition, which openPkcs12 wipes once imported; and the MAC is checked by
// the host. There is no call here that could hand
// pkinative a private key's bits, which is what lets SECURITY.md say so.

/** The host's `crypto.subtle`, or null when it lacks any of the password operations. */
function passwordSubtle(): SubtlePassword | null {
    const subtle = (globalThis as WebCryptoHost).crypto?.subtle;
    if (subtle === undefined
        || typeof subtle.importKey !== 'function' || typeof subtle.deriveKey !== 'function'
        || typeof subtle.unwrapKey !== 'function' || typeof subtle.decrypt !== 'function' || typeof subtle.verify !== 'function') {
        return null;
    }
    return subtle as SubtlePassword;
}

function requirePasswordSubtle(oid: string): SubtlePassword {
    const subtle = passwordSubtle();
    if (subtle === null) {
        throw new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE',
            'pkinative: this runtime exposes no crypto.subtle with importKey, deriveKey, unwrapKey, decrypt and verify, so no password-protected key can be opened — call canDecrypt() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)', oid);
    }
    return subtle;
}

/**
 * Whether this runtime can open a password-protected key or container at all.
 *
 * @returns Whether `globalThis.crypto.subtle` offers every operation PBES2
 *   and RFC 9579 need. It does not say which ciphers the host implements —
 *   AES-192 is missing from several browsers that answer `true`.
 * @throws Never — a missing host is the answer, not an error.
 */
export function canDecrypt(): boolean {
    return passwordSubtle() !== null;
}

/**
 * Derive a non-extractable key from a password with PBKDF2.
 *
 * @param password The password octets. The host copies them into the base
 *   key; this function does not keep them.
 * @param kdf      Salt, iteration count and PRF, already bounded by the caller.
 * @param target   What the key is for — AES-CBC to decrypt, HMAC to verify a MAC.
 * @param oid      The scheme OID, carried into any error.
 * @returns An opaque handle usable for `decrypt` and `unwrapKey` (AES) or `verify` (HMAC) only.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the host cannot;
 *   `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when it refuses the PRF or the key size.
 */
export async function derivePasswordKey(password: Uint8Array, kdf: Pbkdf2Params, target: DerivedKeyParams, oid: string): Promise<CryptoKeyHandle> {
    const subtle = requirePasswordSubtle(oid);
    try {
        const base = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveKey']);
        const usages = target.name === 'HMAC' ? ['verify'] : ['decrypt', 'unwrapKey'];
        return await subtle.deriveKey(kdf, base, target, false, usages);
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_ALGORITHM_UNSUPPORTED',
            `pkinative: this runtime refused to derive a ${target.name} key with PBKDF2 over ${kdf.hash.name} (${String(cause)}) — the PRF or the key length is not implemented here; try another runtime before concluding the file is at fault`, oid);
    }
}

/**
 * Decrypt an encrypted PKCS#8 straight into a non-extractable signing key.
 *
 * @param wrapped The `encryptedData` of an EncryptedPrivateKeyInfo.
 * @param key     A handle from {@link derivePasswordKey}.
 * @param iv      The AES-CBC initialisation vector from the PBES2 parameters.
 * @param params  What the key inside is; Web Crypto must be told before it decrypts.
 * @param oid     The encryption scheme OID, carried into any error.
 * @returns A private key with the single usage `sign`, whose bits never left the host.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE`; `PKI_CRYPTO_DECRYPTION_FAILED`
 *   for a wrong password, altered data, or a key that is not what `params` says.
 */
export async function unwrapPrivateKey(wrapped: Uint8Array, key: CryptoKeyHandle, iv: Uint8Array, params: ImportParams, oid: string): Promise<CryptoKeyHandle> {
    const subtle = requirePasswordSubtle(oid);
    try {
        return await subtle.unwrapKey('pkcs8', wrapped, key, { name: 'AES-CBC', iv }, params, false, ['sign']);
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_DECRYPTION_FAILED',
            `pkinative: the ${params.name} private key could not be decrypted (${String(cause)}) — the password is wrong, the data was altered, or the key is not an ${params.name} key; AES-CBC cannot tell these apart`, oid);
    }
}

/**
 * Import an unencrypted PKCS#8 as a non-extractable signing key.
 *
 * @param pkcs8  The PrivateKeyInfo DER, which the caller already holds in the clear.
 * @param params What the key is.
 * @param oid    The key algorithm OID, carried into any error.
 * @returns A private key with the single usage `sign`.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE`; `PKI_CRYPTO_KEY_UNSUPPORTED`
 *   when the host refuses the key.
 */
export async function importPkcs8Key(pkcs8: Uint8Array, params: ImportParams, oid: string): Promise<CryptoKeyHandle> {
    const subtle = requirePasswordSubtle(oid);
    try {
        return await subtle.importKey('pkcs8', pkcs8, params, false, ['sign']);
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
            `pkinative: this runtime refused to import the ${params.name} private key (${String(cause)}) — the algorithm may not be implemented here, or the key is not a ${params.name} key`, oid);
    }
}

/**
 * Decrypt a PBES2 payload — a PKCS#12 SafeContents, which holds certificates
 * and, when its writer put one there, an unencrypted keyBag. An encrypted
 * private key is never passed here: {@link unwrapPrivateKey} opens it.
 *
 * @param key  A handle from {@link derivePasswordKey}.
 * @param iv   The AES-CBC initialisation vector.
 * @param data The ciphertext.
 * @param oid  The encryption scheme OID, carried into any error.
 * @returns The plaintext: certificates and CRLs, and any unencrypted keyBag the writer nested inside.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE`; `PKI_CRYPTO_DECRYPTION_FAILED`.
 */
export async function decryptContent(key: CryptoKeyHandle, iv: Uint8Array, data: Uint8Array, oid: string): Promise<Uint8Array> {
    const subtle = requirePasswordSubtle(oid);
    try {
        return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, key, data));
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_DECRYPTION_FAILED',
            `pkinative: the encrypted content could not be decrypted (${String(cause)}) — the password is wrong or the data was altered; AES-CBC cannot tell the two apart`, oid);
    }
}

/**
 * Check an HMAC — RFC 9579 PBMAC1, the one PKCS#12 MAC pkinative can verify.
 *
 * Fails closed like {@link verifySignature}: a host that throws is a `false`.
 *
 * @param key  A handle from {@link derivePasswordKey} with an HMAC target.
 * @param mac  The MAC octets from MacData.
 * @param data The bytes it covers — the authenticated safe's content.
 * @returns Whether the MAC checks out.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE`.
 */
export async function verifyMac(key: CryptoKeyHandle, mac: Uint8Array, data: Uint8Array): Promise<boolean> {
    const subtle = requirePasswordSubtle('HMAC');
    try {
        return await subtle.verify({ name: 'HMAC' }, key, mac, data);
    } catch {
        // capability probe: whatever the host throws is its refusal to check the MAC, and refusal fails closed.
        return false;
    }
}
