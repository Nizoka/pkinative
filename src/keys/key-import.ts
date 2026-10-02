/**
 * pkinative — private keys into Web Crypto
 * ========================================
 * A PKCS#8 private key, in the clear or under PBES2, turned into a
 * `SigningKey`: a non-extractable `CryptoKey` whose single usage is `sign`,
 * and the algorithm it signs with.
 *
 * The key's bits are never handled here. An unencrypted PKCS#8 is the
 * caller's own buffer and goes to the host as it came; an encrypted one is
 * unwrapped by the host straight into a handle, so its plaintext never exists
 * in JavaScript at all. What this module decides is the one thing the host
 * cannot: which signature algorithm the key is for. An EC or Edwards key says
 * so; an RSA key does not — PKCS#1 v1.5 or PSS, over any digest — and a
 * guess there is a signature a relying party refuses, so the caller names it.
 *
 * @module keys/key-import
 */

import { resolveSigner } from '../crypto/crypto-algorithms.js';
import { importPkcs8Key, unwrapPrivateKey } from '../crypto/webcrypto.js';
import type { SignatureAlgorithm, SignatureHash, SigningKey } from '../types/crypto-types.js';
import type { DecryptPrivateKeyOptions, ImportPrivateKeyOptions, PrivateKeyInfo } from '../types/key-types.js';
import { PkiCryptoError, PkiError } from '../types/pki-errors.js';
import { _derivePbes2Key, _requirePbes2 } from './key-pbes2.js';
import { parseEncryptedPrivateKeyInfo, parsePrivateKeyInfo } from './key-pkcs8.js';

// ── Which algorithm a key signs with ──

/** The digest each curve is customarily paired with (RFC 5480 §4, FIPS 186-5). */
const CUSTOMARY_HASH: Readonly<Record<'P-256' | 'P-384' | 'P-521', SignatureHash>> = /*#__PURE__*/ Object.freeze({
    'P-256': 'SHA-256',
    'P-384': 'SHA-384',
    'P-521': 'SHA-512',
});

/** An algorithm in words, for an error message. */
function _algorithmName(algorithm: SignatureAlgorithm): string {
    return algorithm.name === 'ECDSA' ? `ECDSA on ${String(algorithm.namedCurve)}` : String(algorithm.name);
}

function _mismatch(key: string, algorithm: SignatureAlgorithm): PkiError {
    return new PkiError('PKI_API_MISUSE',
        `pkinative: the private key is ${key}, and the algorithm named is ${_algorithmName(algorithm)} — name an algorithm the key can sign with, or omit it where the key decides`);
}

function _ambiguous(key: string, choice: string): PkiError {
    return new PkiError('PKI_API_MISUSE',
        `pkinative: the private key is ${key}, which does not say how it signs — pass options.algorithm: ${choice}`);
}

function _unsupported(why: string, oid: string): PkiCryptoError {
    return new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
        `pkinative: the private key ${why}, and Web Crypto signs only with RSA, ECDSA on P-256, P-384 and P-521, Ed25519 and Ed448 — sign with a library or a device that implements it`, oid);
}

/**
 * The algorithm a described key signs with: the one named, checked against
 * the key, or the one the key itself decides.
 *
 * @internal
 */
export function _signingAlgorithm(info: PrivateKeyInfo, requested: SignatureAlgorithm | undefined): SignatureAlgorithm {
    const oid = info.algorithm.oid;
    switch (info.kind) {
        case 'ec': {
            const curve = info.curve;
            if (curve === undefined) throw _unsupported('is an EC key on a curve that is not P-256, P-384 or P-521, or not named', oid);
            if (requested === undefined) return { name: 'ECDSA', hash: CUSTOMARY_HASH[curve], namedCurve: curve };
            if (requested.name !== 'ECDSA' || requested.namedCurve !== curve) throw _mismatch(`an EC key on ${curve}`, requested);
            return requested;
        }
        case 'ed25519':
        case 'ed448': {
            const name = info.kind === 'ed25519' ? 'Ed25519' : 'Ed448';
            if (requested === undefined) return { name };
            if (requested.name !== name) throw _mismatch(`an ${name} key`, requested);
            return requested;
        }
        case 'rsa':
            if (requested === undefined) {
                throw _ambiguous('an RSA key (rsaEncryption)', "{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } or { name: 'RSA-PSS', hash: 'SHA-256' }, with the digest the relying party expects");
            }
            if (requested.name !== 'RSASSA-PKCS1-v1_5' && requested.name !== 'RSA-PSS') throw _mismatch('an RSA key', requested);
            return requested;
        case 'rsa-pss':
            if (requested === undefined) {
                throw _ambiguous('an RSA key restricted to PSS (id-RSASSA-PSS)', "{ name: 'RSA-PSS', hash: 'SHA-256' }, with the digest its parameters allow");
            }
            if (requested.name !== 'RSA-PSS') throw _mismatch('an RSA key restricted to PSS (id-RSASSA-PSS)', requested);
            return requested;
        case 'unknown':
            throw _unsupported(`is of a type pkinative does not sign with (${oid})`, oid);
    }
}

/** An `algorithm` option that is at least an object, before its fields are read. */
function _checkAlgorithmOption(algorithm: unknown, required: boolean): void {
    if (algorithm === undefined && !required) return;
    if (typeof algorithm !== 'object' || algorithm === null) {
        throw new PkiError('PKI_INVALID_OPTION',
            `pkinative: options.algorithm must be a SignatureAlgorithm object such as { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, got ${algorithm === null ? 'null' : typeof algorithm}`);
    }
}

// ── Public functions ──

/**
 * Import an unencrypted PKCS#8 private key — the DER of a `PRIVATE KEY` PEM
 * block — as a non-extractable signing key.
 *
 * The key goes to the host exactly as the caller holds it, and comes back as
 * a `CryptoKey` with `extractable: false` and the single usage `sign`: ready
 * for `createCertificate`, `createCsr` or `createSignedData`, and unable to
 * give its bits back to anyone.
 *
 * ```ts
 * import { decodePem, importPrivateKey } from 'pkinative';
 *
 * const [block] = decodePem(pemText, { label: 'PRIVATE KEY' });
 * const signer = await importPrivateKey(block.bytes);                // an EC or Edwards key decides
 * const rsa = await importPrivateKey(rsaDer, { algorithm: { name: 'RSA-PSS', hash: 'SHA-256' } });
 * ```
 *
 * @param der     The DER of a RFC 5958 `OneAsymmetricKey` (version 0 is RFC 5208 PKCS#8).
 * @param options Encoding rules, limits, diagnostics, and the algorithm —
 *   required for an RSA key, inferred for an EC, Ed25519 or Ed448 key.
 * @returns The key and the algorithm it signs with.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array;
 *   `PKI_INVALID_OPTION` for a bad option; `PKI_API_MISUSE` when the key is
 *   RSA and no algorithm is named, or the algorithm named does not fit the key.
 * @throws {PkiEncodingError} When the bytes are not valid DER.
 * @throws {PkiKeyError} `PKI_KEY_STRUCTURE_INVALID` or `PKI_KEY_VERSION_UNSUPPORTED`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past a named limit.
 * @throws {PkiCryptoError} `PKI_CRYPTO_KEY_UNSUPPORTED` for a key type or a
 *   curve Web Crypto does not sign with, or a key the host refuses;
 *   `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` for an algorithm with no RFC 5280 OID;
 *   `PKI_CRYPTO_UNAVAILABLE` when the runtime has no Web Crypto.
 */
export async function importPrivateKey(der: Uint8Array, options?: ImportPrivateKeyOptions): Promise<SigningKey> {
    const info = parsePrivateKeyInfo(der, options);
    _checkAlgorithmOption(options?.algorithm, false);
    const algorithm = _signingAlgorithm(info, options?.algorithm);
    const { importParams } = resolveSigner(algorithm);
    const key = await importPkcs8Key(info.der, importParams, info.algorithm.oid);
    return Object.freeze({ key, algorithm });
}

/**
 * Decrypt a password-protected PKCS#8 private key — the DER of an
 * `ENCRYPTED PRIVATE KEY` PEM block — into a non-extractable signing key.
 *
 * The host derives the key-encryption key with PBKDF2 and unwraps the private
 * key straight into a `CryptoKey` (`extractable: false`, usage `sign`): the
 * decrypted PKCS#8 never exists in JavaScript. That is also why `algorithm` is
 * required — the host must be told what the key is before it decrypts it, and
 * pkinative never looks inside first. Only PBES2 with PBKDF2 and AES-CBC is
 * opened, which is what OpenSSL 1.1 and later write by default; every other
 * scheme is refused with the conversion to run.
 *
 * ```ts
 * import { decodePem, decryptPrivateKey } from 'pkinative';
 *
 * const [block] = decodePem(pemText, { label: 'ENCRYPTED PRIVATE KEY' });
 * const signer = await decryptPrivateKey(block.bytes, {
 *     password: 'correct horse battery staple',
 *     algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
 * });
 * ```
 *
 * @param der     The DER of a RFC 5958 §3 `EncryptedPrivateKeyInfo`.
 * @param options The password, the algorithm the key signs with, and the
 *   encoding rules, limits and diagnostics of the parse.
 * @returns The key and the algorithm it signs with.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array;
 *   `PKI_INVALID_OPTION` for a missing or bad option; `PKI_API_MISUSE` for a
 *   password string with a lone surrogate, which has no UTF-8 form.
 * @throws {PkiEncodingError} When the bytes are not valid DER.
 * @throws {PkiKeyError} `PKI_KEY_STRUCTURE_INVALID`; `PKI_KEY_ENCRYPTION_UNSUPPORTED`
 *   for any scheme other than PBES2 with PBKDF2 and AES-CBC.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxKdfIterations` or another named limit.
 * @throws {PkiCryptoError} `PKI_CRYPTO_DECRYPTION_FAILED` for a wrong password,
 *   altered data, or a key that is not the algorithm named — AES-CBC cannot
 *   tell them apart; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` for a PRF or AES size
 *   the host does not implement, or an algorithm with no RFC 5280 OID;
 *   `PKI_CRYPTO_UNAVAILABLE` when the runtime has no Web Crypto.
 */
export async function decryptPrivateKey(der: Uint8Array, options: DecryptPrivateKeyOptions): Promise<SigningKey> {
    if (typeof options !== 'object' || options === null) {
        throw new PkiError('PKI_INVALID_OPTION', 'pkinative: decryptPrivateKey needs options — pass { password, algorithm }');
    }
    const password: unknown = options.password;
    // The same test as assertBytes: a Uint8Array from another realm is one too.
    if (typeof password !== 'string' && !(ArrayBuffer.isView(password) && Object.prototype.toString.call(password) === '[object Uint8Array]')) {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: options.password must be a string or a Uint8Array, got ${password === null ? 'null' : typeof password}`);
    }
    _checkAlgorithmOption(options.algorithm, true);
    const info = parseEncryptedPrivateKeyInfo(der, options);
    const path = 'encryptedPrivateKeyInfo.encryptionAlgorithm';
    const pbes2 = _requirePbes2(info.encryption, path, info.encryption.algorithm.der.byteOffset - info.der.byteOffset);
    const { importParams } = resolveSigner(options.algorithm);
    const oid = info.encryption.algorithm.oid;
    const wrappingKey = await _derivePbes2Key(options.password, pbes2, oid);
    const key = await unwrapPrivateKey(info.encryptedData, wrappingKey, pbes2.iv, importParams, oid);
    return Object.freeze({ key, algorithm: options.algorithm });
}
