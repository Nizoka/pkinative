import type { webcrypto } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
    canDecrypt,
    decryptContent,
    derivePasswordKey,
    importPkcs8Key,
    unwrapPrivateKey,
    verifyMac,
} from '../../src/crypto/webcrypto.js';
import { PkiCryptoError } from '../../src/types/pki-errors.js';
import type { CryptoKeyHandle, Pbkdf2Params } from '../../src/types/webcrypto.js';

/**
 * The password half of the Web Crypto door (0.8): PBKDF2 into a handle, a
 * PKCS#8 unwrapped into a signing key, certificate bags decrypted, and the
 * RFC 9579 HMAC checked. Every ciphertext here is produced by the test with
 * the host's own `encrypt`, `wrapKey` and `sign` — operations `src/` may never
 * name — so the door is checked against an independent writer.
 */

type CryptoKey = webcrypto.CryptoKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;

const subtle = globalThis.crypto.subtle;
const PASSWORD = new TextEncoder().encode('correct horse battery staple');
const SALT = Uint8Array.from({ length: 16 }, (_, i) => i);
const IV = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const KDF: Pbkdf2Params = { name: 'PBKDF2', salt: SALT, iterations: 2048, hash: { name: 'SHA-256' } };
const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const OID_AES256 = '2.16.840.1.101.3.4.1.42';

/** The test's own AES key, derived the way a PBES2 writer would, so the door is compared with it. */
async function writerKey(password = PASSWORD): Promise<CryptoKey> {
    const base = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ ...KDF }, base, { name: 'AES-CBC', length: 256 }, false, ['encrypt', 'wrapKey']);
}

async function ecPair(): Promise<CryptoKeyPair> {
    return subtle.generateKey(EC, true, ['sign', 'verify']);
}

describe('derivePasswordKey and unwrapPrivateKey', () => {
    it('should turn an encrypted PKCS#8 into a non-extractable key that signs', async () => {
        const pair = await ecPair();
        const wrapped = new Uint8Array(await subtle.wrapKey('pkcs8', pair.privateKey, await writerKey(), { name: 'AES-CBC', iv: IV }));
        const key = await derivePasswordKey(PASSWORD, KDF, { name: 'AES-CBC', length: 256 }, OID_AES256);
        const unwrapped = await unwrapPrivateKey(wrapped, key, IV, EC, OID_AES256) as CryptoKey;
        expect(unwrapped.extractable).toBe(false);
        expect(unwrapped.usages).toEqual(['sign']);
        const data = new TextEncoder().encode('signed by the unwrapped key');
        const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, unwrapped, data);
        expect(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, signature, data)).toBe(true);
    });

    it('should refuse the wrong password, and the wrong key algorithm, with the same code', async () => {
        // AES-CBC has no tag: the host cannot say which of the two happened,
        // and the code must not pretend to know.
        const pair = await ecPair();
        const wrapped = new Uint8Array(await subtle.wrapKey('pkcs8', pair.privateKey, await writerKey(), { name: 'AES-CBC', iv: IV }));
        const wrong = await derivePasswordKey(new TextEncoder().encode('Tr0ub4dor&3'), KDF, { name: 'AES-CBC', length: 256 }, OID_AES256);
        const right = await derivePasswordKey(PASSWORD, KDF, { name: 'AES-CBC', length: 256 }, OID_AES256);
        // Started one at a time: a second promise created up front rejects
        // while the first is awaited, and Vitest reports it as unhandled.
        for (const start of [
            () => unwrapPrivateKey(wrapped, wrong, IV, EC, OID_AES256),
            () => unwrapPrivateKey(wrapped, right, IV, { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, OID_AES256),
        ]) {
            const attempt = start();
            await expect(attempt).rejects.toBeInstanceOf(PkiCryptoError);
            await expect(attempt).rejects.toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED', algorithm: OID_AES256 });
        }
    });

    it('should report a PRF the host does not implement as unsupported, not as a wrong password', async () => {
        const call = derivePasswordKey(PASSWORD, { ...KDF, hash: { name: 'MD5' } }, { name: 'AES-CBC', length: 256 }, OID_AES256);
        await expect(call).rejects.toMatchObject({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' });
    });
});

describe('importPkcs8Key', () => {
    it('should import a PKCS#8 the caller holds as a non-extractable signing key', async () => {
        const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', (await ecPair()).privateKey));
        const key = await importPkcs8Key(pkcs8, EC, '1.2.840.10045.2.1') as CryptoKey;
        expect(key.extractable).toBe(false);
        expect(key.usages).toEqual(['sign']);
    });

    it('should refuse a key that is not the algorithm named', async () => {
        const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', (await ecPair()).privateKey));
        await expect(importPkcs8Key(pkcs8, { name: 'Ed25519' }, '1.3.101.112')).rejects.toMatchObject({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' });
    });
});

describe('decryptContent', () => {
    it('should decrypt what a PBES2 writer encrypted, and refuse it under the wrong password', async () => {
        const plaintext = new TextEncoder().encode('a SafeContents of certificates, which hold no key');
        const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: IV }, await writerKey(), plaintext));
        const right = await derivePasswordKey(PASSWORD, KDF, { name: 'AES-CBC', length: 256 }, OID_AES256);
        expect(await decryptContent(right, IV, ciphertext, OID_AES256)).toEqual(plaintext);
        const wrong = await derivePasswordKey(new Uint8Array(0), KDF, { name: 'AES-CBC', length: 256 }, OID_AES256);
        await expect(decryptContent(wrong, IV, ciphertext, OID_AES256)).rejects.toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED' });
    });
});

describe('verifyMac', () => {
    async function macKey(): Promise<{ theirs: CryptoKey; ours: CryptoKeyHandle }> {
        const target = { name: 'HMAC', hash: { name: 'SHA-256' }, length: 256 } as const;
        const base = await subtle.importKey('raw', PASSWORD, 'PBKDF2', false, ['deriveKey']);
        const theirs = await subtle.deriveKey({ ...KDF }, base, target, false, ['sign']);
        return { theirs, ours: await derivePasswordKey(PASSWORD, KDF, target, '1.2.840.113549.1.5.14') };
    }

    it('should accept an RFC 9579 MAC computed under the same password, and reject a changed byte', async () => {
        const { theirs, ours } = await macKey();
        const data = new TextEncoder().encode('the authenticated safe');
        const mac = new Uint8Array(await subtle.sign('HMAC', theirs, data));
        expect(await verifyMac(ours, mac, data)).toBe(true);
        mac[0] = (mac[0] ?? 0) ^ 1;
        expect(await verifyMac(ours, mac, data)).toBe(false);
    });

    it('should fail closed when the host throws — a key of the wrong kind is a no, not an incident', async () => {
        const aes = await derivePasswordKey(PASSWORD, KDF, { name: 'AES-CBC', length: 256 }, OID_AES256);
        expect(await verifyMac(aes, new Uint8Array(32), new Uint8Array(1))).toBe(false);
    });
});

describe('a runtime without the password operations', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

    afterEach(() => {
        if (original !== undefined) Object.defineProperty(globalThis, 'crypto', original);
    });

    function host(value: unknown): void {
        Object.defineProperty(globalThis, 'crypto', { value, configurable: true, writable: true });
    }

    const fn = (): void => undefined;
    it.each([
        ['no crypto at all', undefined],
        ['subtle without importKey', { subtle: { deriveKey: fn, unwrapKey: fn, decrypt: fn, verify: fn } }],
        ['subtle without deriveKey', { subtle: { importKey: fn, unwrapKey: fn, decrypt: fn, verify: fn } }],
        ['subtle without unwrapKey', { subtle: { importKey: fn, deriveKey: fn, decrypt: fn, verify: fn } }],
        ['subtle without decrypt', { subtle: { importKey: fn, deriveKey: fn, unwrapKey: fn, verify: fn } }],
        ['subtle without verify', { subtle: { importKey: fn, deriveKey: fn, unwrapKey: fn, decrypt: fn } }],
    ])('should report that it cannot decrypt when there is %s', (_what, value) => {
        host(value);
        expect(canDecrypt()).toBe(false);
    });

    it('should say so with a code from every entry point', async () => {
        host(undefined);
        const handle = { type: 'secret' };
        for (const call of [
            derivePasswordKey(PASSWORD, KDF, { name: 'AES-CBC', length: 256 }, OID_AES256),
            unwrapPrivateKey(new Uint8Array(16), handle, IV, EC, OID_AES256),
            importPkcs8Key(new Uint8Array(16), EC, '1.2.840.10045.2.1'),
            decryptContent(handle, IV, new Uint8Array(16), OID_AES256),
            verifyMac(handle, new Uint8Array(32), new Uint8Array(1)),
        ]) {
            await expect(call).rejects.toMatchObject({ code: 'PKI_CRYPTO_UNAVAILABLE' });
        }
    });

    it('should report that it can decrypt on a runtime that can', () => {
        expect(canDecrypt()).toBe(true);
    });
});
