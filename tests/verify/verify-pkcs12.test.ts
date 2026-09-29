import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeKeyUsage } from '../../src/build/build-structures.js';
import { signData } from '../../src/crypto/webcrypto.js';
import { PkiError } from '../../src/types/pki-errors.js';
import { readPkcs12, type ReadPkcs12Options } from '../../src/verify/verify-pkcs12.js';
import { alg, int, octets } from '../helpers/cms-signed-data-builder.js';
import {
    authenticatedSafe,
    berPfx,
    certBag,
    contentInfo,
    crlBag,
    dataInfo,
    encryptedDataInfo,
    encryptedSafeContents,
    HMAC_OID,
    keyBag,
    legacyMacData,
    localKeyId,
    friendlyName,
    macData,
    P12,
    pbmac1MacData,
    pfx,
    safeContents,
    shroudedKeyBag,
    shroudKey,
} from '../helpers/pkcs12-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';

/** Run with some `crypto.subtle` members replaced — or, given `undefined`, with no Web Crypto at all. */
async function withHost(overrides: Record<string, unknown> | undefined, run: () => Promise<void>): Promise<void> {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const real = globalThis.crypto.subtle;
    const subtle = overrides === undefined ? undefined : new Proxy(real, {
        get: (target, key: string) => {
            if (key in overrides) return overrides[key];
            // Bound: Web Crypto's methods throw an illegal invocation when
            // called with the proxy, rather than the real SubtleCrypto, as this.
            const member = (target as unknown as Record<string, unknown>)[key];
            return typeof member === 'function' ? (member as (...a: unknown[]) => unknown).bind(target) : member;
        },
    });
    Object.defineProperty(globalThis, 'crypto', { value: subtle === undefined ? undefined : { subtle }, configurable: true, writable: true });
    try {
        await run();
    } finally {
        if (original !== undefined) Object.defineProperty(globalThis, 'crypto', original);
    }
}
import { AT, DAY, codes, issue, keyPair, makeRoot, type Authority, type Family, type Holder } from './_cms-pki.js';

/**
 * `readPkcs12`: RFC 7292 opened the whole way in one call, and reported
 * rather than thrown. Every file here is assembled by the engine-independent
 * writer in tests/helpers/pkcs12-builder.ts from keys and certificates of the
 * test PKI, so the reader is checked against the standards and a real key.
 */

const PASSWORD = 'correct horse battery staple';
const ID = Uint8Array.of(0x4b, 0x45, 0x59, 0x31);
const CA_ID = Uint8Array.of(0xca);

async function pkcs8Of(holder: Holder): Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', holder.pair.privateKey as never));
}

interface FileParts {
    readonly holder: Holder;
    readonly caDer?: Uint8Array;
    /** The password the contents are encrypted under, when it differs from the MAC's. */
    readonly contentsPassword?: string;
    readonly keyId?: Uint8Array | null;
    readonly certId?: Uint8Array | null;
    readonly plainKey?: boolean;
    readonly mac?: 'pbmac1' | 'legacy' | 'none';
    readonly extra?: readonly Uint8Array[];
}

/** What OpenSSL 3.4 writes with -pbmac1_pbkdf2: certificates in an encrypted SafeContents, the key shrouded in a plain one. */
async function file(parts: FileParts): Promise<Uint8Array> {
    const password = parts.contentsPassword ?? PASSWORD;
    const certAttributes = parts.certId === null ? null : [localKeyId(parts.certId ?? ID), friendlyName('Test Signer')];
    const keyAttributes = parts.keyId === null ? null : [localKeyId(parts.keyId ?? ID)];
    const certs = safeContents(
        certBag(parts.holder.certificate.der, certAttributes),
        ...(parts.caDer === undefined ? [] : [certBag(parts.caDer, [localKeyId(CA_ID)])]),
    );
    const pkcs8 = await pkcs8Of(parts.holder);
    const keyContents = parts.plainKey === true
        ? safeContents(keyBag(pkcs8, keyAttributes))
        : await shrouded(pkcs8, password, keyAttributes);
    const auth = authenticatedSafe(await encryptedSafeContents(certs, password), dataInfo(keyContents), ...(parts.extra ?? []));
    const mac = parts.mac ?? 'pbmac1';
    return pfx({
        authSafe: auth,
        ...(mac === 'none' ? {} : { macData: mac === 'legacy' ? legacyMacData() : await pbmac1MacData(auth, PASSWORD) }),
    });
}

async function shrouded(pkcs8: Uint8Array, password: string, attributes: readonly Uint8Array[] | null): Promise<Uint8Array> {
    return safeContents(shroudedKeyBag(await shroudKey(pkcs8, password), attributes));
}

/** A certificate for a key Web Crypto does not sign with, and that key's PKCS#8 — both written by node:crypto. */
async function foreignKey(root: Authority, type: 'x25519' | 'secp256k1'): Promise<{ readonly der: Uint8Array; readonly pkcs8: Uint8Array }> {
    const pair = type === 'x25519' ? generateKeyPairSync('x25519') : generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const der = await createCertificate({
        serialNumber: 9n, issuerDer: root.certificate.subject.der, subject: [[{ type: '2.5.4.3', value: `${type} holder` }]],
        notBefore: AT - DAY, notAfter: AT + DAY,
        subjectPublicKey: new Uint8Array(pair.publicKey.export({ format: 'der', type: 'spki' })),
        extensions: [{ oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyAgreement']) }],
    }, { key: root.key, algorithm: { name: 'Ed25519' } });
    return { der, pkcs8: new Uint8Array(pair.privateKey.export({ format: 'der', type: 'pkcs8' })) };
}

const read = (der: Uint8Array, extra: Partial<ReadPkcs12Options> = {}): ReturnType<typeof readPkcs12> =>
    readPkcs12(der, { password: PASSWORD, ...extra });

async function signsLikeItsCertificate(report: Awaited<ReturnType<typeof readPkcs12>>, holder: Holder): Promise<boolean> {
    const signingKey = report.keys[0]?.signingKey;
    if (signingKey === undefined) return false;
    const data = new TextEncoder().encode('signed with the key the file held');
    const params = signingKey.algorithm.name === 'ECDSA' ? { name: 'ECDSA', hash: signingKey.algorithm.hash }
        : signingKey.algorithm.name === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: 32 } : { name: signingKey.algorithm.name };
    const signature = await signData(signingKey.key, params, data);
    // Verified with the certificate's public key, imported for the scheme the
    // key was bound to — not with the holder's CryptoKey, which is bound to
    // the scheme it was generated for.
    const a = signingKey.algorithm;
    const importParams = a.name === 'ECDSA' ? { name: 'ECDSA', namedCurve: a.namedCurve }
        : a.name === 'RSA-PSS' || a.name === 'RSASSA-PKCS1-v1_5' ? { name: a.name, hash: a.hash } : { name: a.name };
    const publicKey = await webcrypto.subtle.importKey('spki', holder.certificate.subjectPublicKeyInfo.der, importParams as never, false, ['verify']);
    return webcrypto.subtle.verify(params as never, publicKey, signature, data);
}

describe('readPkcs12 — a file it can vouch for', () => {
    it('should verify the MAC, open everything, and hand back a key that signs as its certificate', async () => {
        const root = await makeRoot();
        const holder = await issue(root);
        const report = await read(await file({ holder, caDer: root.certificate.der }));
        expect(codes(report)).toEqual([]);
        expect(report.valid).toBe(true);
        expect(report.integrity).toBe('verified');
        expect(report.certificates.map((c) => c.der)).toEqual([holder.certificate.der, root.certificate.der]);
        expect(report.keys).toHaveLength(1);
        expect(report.keys[0]).toMatchObject({ path: 'authSafe[1].bags[0]', localKeyId: ID, certificate: { der: holder.certificate.der } });
        expect(report.keys[0]?.signingKey?.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' });
        expect((report.keys[0]?.signingKey?.key as { extractable?: boolean }).extractable).toBe(false);
        expect(await signsLikeItsCertificate(report, holder)).toBe(true);
    });

    it.each<[Family, object]>([
        ['RSA', { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
        ['Ed25519', { name: 'Ed25519' }],
    ])('should take a %s key\'s algorithm from its certificate', async (family, expected) => {
        const holder = await issue(await makeRoot(), { family });
        const report = await read(await file({ holder }));
        expect(codes(report)).toEqual([]);
        expect(report.keys[0]?.signingKey?.algorithm).toEqual(expected);
        expect(await signsLikeItsCertificate(report, holder)).toBe(true);
    });

    it('should bind an RSA key to the scheme the caller chooses', async () => {
        const holder = await issue(await makeRoot(), { family: 'RSA' });
        const report = await read(await file({ holder }), { rsaAlgorithm: { name: 'RSA-PSS', hash: 'SHA-256' } });
        expect(report.keys[0]?.signingKey?.algorithm).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
        expect(await signsLikeItsCertificate(report, holder)).toBe(true);
    });

    it('should open an unencrypted keyBag through the same checks', async () => {
        const holder = await issue(await makeRoot());
        const report = await read(await file({ holder, plainKey: true }));
        expect(codes(report)).toEqual([]);
        expect(await signsLikeItsCertificate(report, holder)).toBe(true);
    });

    it('should wipe a plain key it decrypted out of an encrypted SafeContents, once imported', async () => {
        // A keyBag nested in an encrypted SafeContents is plaintext by
        // definition once that SafeContents is opened. The bytes this call
        // decrypted are the only ones it may wipe, and it does.
        const holder = await issue(await makeRoot());
        const pkcs8 = await pkcs8Of(holder);
        const inner = safeContents(certBag(holder.certificate.der, [localKeyId(ID)]), keyBag(pkcs8, [localKeyId(ID)]));
        const auth = authenticatedSafe(await encryptedSafeContents(inner, PASSWORD));
        const der = pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) });
        const opened: Uint8Array[] = [];
        const decrypt = globalThis.crypto.subtle.decrypt.bind(globalThis.crypto.subtle);
        await withHost({
            decrypt: async (...args: unknown[]): Promise<ArrayBuffer> => {
                const plain = await (decrypt as (...a: unknown[]) => Promise<ArrayBuffer>)(...args);
                opened.push(new Uint8Array(plain));
                return plain;
            },
        }, async () => {
            const report = await read(der);
            expect(codes(report)).toEqual([]);
            expect(await signsLikeItsCertificate(report, holder)).toBe(true);
        });
        const plaintext = opened[0] ?? new Uint8Array(0);
        const has = (needle: Uint8Array): boolean => plaintext.some((_, i) => needle.every((b, j) => plaintext[i + j] === b));
        expect(has(pkcs8)).toBe(false);
        expect(has(holder.certificate.der)).toBe(true);
        // Wiped means zeroed, not merely changed: the decrypted plaintext has
        // the layout of `inner`, so the key's octets sit where they sat there.
        const at = inner.findIndex((_, i) => pkcs8.every((b, j) => inner[i + j] === b));
        expect(at).toBeGreaterThan(0);
        expect([...plaintext.subarray(at, at + pkcs8.length)].every((b) => b === 0)).toBe(true);
    });

    it('should leave a plain key in an unencrypted SafeContents alone: those are the caller\'s bytes', async () => {
        const holder = await issue(await makeRoot());
        const der = await file({ holder, plainKey: true });
        const before = der.slice();
        expect(codes(await read(der))).toEqual([]);
        expect(der).toEqual(before);
    });

    it('should collect CRL bags as DER', async () => {
        const holder = await issue(await makeRoot());
        const crl = sequence(int(1));
        const report = await read(await file({ holder, extra: [dataInfo(safeContents(crlBag(crl)))] }));
        expect(report.crls).toEqual([crl]);
    });
});

describe('readPkcs12 — integrity, failing closed', () => {
    it('should stop at a MAC that does not match, before decrypting anything', async () => {
        const holder = await issue(await makeRoot());
        const report = await read(await file({ holder }), { password: 'Tr0ub4dor&3' });
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_MAC_MISMATCH']);
        expect(report.integrity).toBe('mismatch');
        expect(report.keys).toEqual([]);
        expect(report.certificates).toEqual([]);
    });

    it.each([
        ['an RFC 7292 Appendix B MAC', 'legacy', 'Appendix B KDF'],
        ['no MAC at all', 'none', 'carries no MAC'],
    ] as const)('should read a file with %s, and call it invalid unless the caller waives integrity', async (_what, mac, why) => {
        const holder = await issue(await makeRoot());
        const der = await file({ holder, mac });
        const strict = await read(der);
        expect(codes(strict)).toEqual(['PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED']);
        // The reason says which of the unverifiable kinds it is, as the PBMAC1 case below does.
        expect(strict.reasons[0]?.message).toContain(why);
        expect(strict.valid).toBe(false);
        expect(strict.integrity).toBe('unverified');
        expect(strict.keys[0]?.signingKey).toBeDefined();
        const waived = await read(der, { allowUnverifiedIntegrity: true });
        expect(codes(waived)).toEqual([]);
        expect(waived.valid).toBe(true);
        expect(waived.integrity).toBe('unverified');
    });

    it('should report a PBMAC1 whose HMAC Web Crypto does not run as unverified, not as a mismatch', async () => {
        const holder = await issue(await makeRoot());
        const kdf = alg(P12.pbkdf2, sequence(octets(new Uint8Array(16)), int(2048), int(32), alg(HMAC_OID['SHA-256'])));
        const unsupported = macData(alg(P12.pbmac1, sequence(kdf, alg(HMAC_OID['SHA-224']))), new Uint8Array(28), new Uint8Array(8));
        const auth = authenticatedSafe(dataInfo(safeContents(certBag(holder.certificate.der))));
        const report = await read(pfx({ authSafe: auth, macData: unsupported }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED']);
        expect(report.reasons[0]?.message).toContain('PBMAC1');
    });

    it('should report public-key integrity mode as unverified integrity', async () => {
        const report = await read(pfx({ authSafe: new Uint8Array(0), authSafeInfo: contentInfo(P12.signedData, sequence(int(1))) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED']);
        expect(report.reasons[0]?.path).toBe('authSafe');
        expect(report.pkcs12).toBeUndefined();
    });
});

describe('readPkcs12 — what it reports instead of throwing', () => {
    it('should report bytes that are not a PFX as malformed input', async () => {
        const report = await read(sequence(int(7)));
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        expect(report.reasons[0]).toMatchObject({ path: 'pkcs12', errorCode: 'PKI_KEY_VERSION_UNSUPPORTED' });
    });

    it('should name a refused scheme and read the rest', async () => {
        const holder = await issue(await makeRoot());
        const rc2 = alg('1.2.840.113549.1.12.1.6', sequence(octets(new Uint8Array(8)), int(2048)));
        const auth = authenticatedSafe(
            encryptedDataInfo(new Uint8Array(32), { algorithm: rc2 }),
            dataInfo(safeContents(certBag(holder.certificate.der))),
        );
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED']);
        expect(report.reasons[0]).toMatchObject({ path: 'authSafe[0]' });
        expect(report.reasons[0]?.message).toContain('pbeWithSHAAnd40BitRC2-CBC');
        expect(report.certificates).toHaveLength(1);
    });

    it('should name the refused scheme of a shrouded key whose certificate the same refusal keeps shut', async () => {
        // The shape of `openssl pkcs12 -export -legacy` and of what Windows
        // CryptoAPI exports by default: certificates in RC2- or 3DES-encrypted
        // contents, the key shrouded with pbeWithSHAAnd3-KeyTripleDES-CBC. The
        // key's own scheme is the reason, not a certificate that is missing
        // only because it could not be opened.
        const pbe = (oid: string): Uint8Array => alg(oid, sequence(octets(new Uint8Array(8)), int(2048)));
        const auth = authenticatedSafe(
            encryptedDataInfo(new Uint8Array(32), { algorithm: pbe('1.2.840.113549.1.12.1.6') }),
            dataInfo(safeContents(shroudedKeyBag(sequence(pbe('1.2.840.113549.1.12.1.3'), octets(new Uint8Array(48))), [localKeyId(ID)]))),
        );
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED', 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED']);
        expect(report.reasons.map((r) => r.path)).toEqual(['authSafe[0]', 'authSafe[1].bags[0]']);
        expect(report.reasons[0]?.message).toContain('pbeWithSHAAnd40BitRC2-CBC');
        expect(report.reasons[1]?.message).toContain('pbeWithSHAAnd3-KeyTripleDES-CBC');
        expect(report.keys[0]).toMatchObject({ certificate: undefined, signingKey: undefined });
    });

    it('should name public-key privacy mode', async () => {
        const auth = authenticatedSafe(contentInfo(P12.envelopedData, sequence(int(0))));
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED']);
        expect(report.reasons[0]?.message).toContain('envelopedData');
    });

    it('should report contents and a key that will not decrypt under the password', async () => {
        const holder = await issue(await makeRoot());
        const pkcs8 = await pkcs8Of(holder);
        const auth = authenticatedSafe(
            await encryptedSafeContents(safeContents(), 'another password'),
            dataInfo(safeContents(certBag(holder.certificate.der, [localKeyId(ID)]))),
            dataInfo(await shrouded(pkcs8, 'another password', [localKeyId(ID)])),
        );
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_DECRYPTION_FAILED', 'PKI_REASON_PKCS12_DECRYPTION_FAILED']);
        expect(report.reasons.map((r) => r.path)).toEqual(['authSafe[0]', 'authSafe[2].bags[0]']);
        expect(report.keys[0]?.signingKey).toBeUndefined();
    });

    it('should report a key that shares its localKeyId with no certificate', async () => {
        const holder = await issue(await makeRoot());
        for (const parts of [{ keyId: Uint8Array.of(9) }, { keyId: null }]) {
            const report = await read(await file({ holder, ...parts }));
            expect(codes(report)).toEqual(['PKI_REASON_PKCS12_KEY_UNMATCHED']);
            expect(report.keys[0]).toMatchObject({ certificate: undefined, signingKey: undefined });
        }
    });

    it.each([
        ['an X25519 key-agreement key', 'x25519', 'x25519'],
        ['an EC key on secp256k1', 'secp256k1', 'curve'],
    ] as const)('should report a key whose certificate carries %s, which Web Crypto cannot sign with', async (_what, type, said) => {
        const { der, pkcs8 } = await foreignKey(await makeRoot(), type);
        const auth = authenticatedSafe(dataInfo(safeContents(certBag(der, [localKeyId(ID)]), keyBag(pkcs8, [localKeyId(ID)]))));
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_KEY_UNSUPPORTED']);
        expect(report.reasons[0]?.message).toContain(said);
        expect(report.keys[0]?.certificate?.der).toEqual(der);
        expect(report.keys[0]?.signingKey).toBeUndefined();
    });

    it('should report a key that is not of its certificate\'s algorithm', async () => {
        const root = await makeRoot();
        const ec = await issue(root);
        const rsa = await issue(root, { family: 'RSA', serial: 3n });
        const auth = authenticatedSafe(dataInfo(safeContents(certBag(rsa.certificate.der, [localKeyId(ID)]), keyBag(await pkcs8Of(ec), [localKeyId(ID)]))));
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_PKCS12_KEY_UNSUPPORTED']);
        expect(report.reasons[0]?.message).toContain('do not belong together');
    });

    it('should report a certificate bag that does not parse, and keep going', async () => {
        const holder = await issue(await makeRoot());
        const auth = authenticatedSafe(dataInfo(safeContents(certBag(sequence(int(1)), [localKeyId(CA_ID)]), certBag(holder.certificate.der))));
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        expect(report.reasons[0]?.path).toBe('authSafe[0].bags[0]');
        expect(report.certificates).toHaveLength(1);
    });

    it('should report a MAC and contents whose derivation this host refuses as what they are', async () => {
        // A host without the PRF: the MAC cannot be checked here, and the
        // encrypted contents cannot be opened here — two facts about the
        // runtime, neither about the file.
        const holder = await issue(await makeRoot());
        const der = await file({ holder });
        await withHost({ deriveKey: (): Promise<never> => Promise.reject(new Error('refused')) }, async () => {
            const report = await read(der);
            // The certificates are in the encrypted SafeContents, so the key
            // that follows has no certificate to take its algorithm from.
            expect(codes(report)).toEqual([
                'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED',
                'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED',
                'PKI_REASON_PKCS12_KEY_UNMATCHED',
            ]);
            expect(report.reasons[0]?.message).toContain('PBMAC1');
            expect(report.reasons[1]).toMatchObject({ path: 'authSafe[0]' });
            expect(report.reasons[1]?.message).toContain('another runtime');
        });
    });

    it('should report a key this host refuses to import', async () => {
        const holder = await issue(await makeRoot());
        const der = await file({ holder, plainKey: true });
        const importKey = globalThis.crypto.subtle.importKey.bind(globalThis.crypto.subtle);
        await withHost({
            importKey: (format: string, ...rest: unknown[]): Promise<unknown> =>
                format === 'pkcs8' ? Promise.reject(new Error('refused')) : (importKey as (...a: unknown[]) => Promise<unknown>)(format, ...rest),
        }, async () => {
            const report = await read(der);
            expect(codes(report)).toEqual(['PKI_REASON_PKCS12_KEY_UNSUPPORTED']);
            expect(report.reasons[0]?.path).toBe('authSafe[1].bags[0]');
        });
    });

    it('should report encrypted contents that decrypt to something that is not DER', async () => {
        const holder = await issue(await makeRoot());
        const auth = authenticatedSafe(await encryptedSafeContents(Uint8Array.of(0x30, 0x80), PASSWORD), dataInfo(safeContents(certBag(holder.certificate.der))));
        const report = await read(pfx({ authSafe: auth, macData: await pbmac1MacData(auth, PASSWORD) }));
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        expect(report.reasons[0]?.path).toBe('authSafe[0]');
        expect(report.certificates).toHaveLength(1);
    });

    it('should read the BER Windows writes, under encodingRules: ber', async () => {
        const holder = await issue(await makeRoot());
        const auth = authenticatedSafe(dataInfo(safeContents(certBag(holder.certificate.der, [localKeyId(ID)]), keyBag(await pkcs8Of(holder), [localKeyId(ID)]))));
        const der = berPfx(auth, await pbmac1MacData(auth, PASSWORD));
        expect(codes(await read(der))).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        const report = await read(der, { encodingRules: 'ber' });
        expect(codes(report)).toEqual([]);
        expect(await signsLikeItsCertificate(report, holder)).toBe(true);
    });

    it('should take an Ed448 key\'s algorithm from its certificate, where the runtime has Ed448', async () => {
        const pair = await keyPair('Ed25519', { name: 'Ed448' }).catch(() => undefined);
        if (pair === undefined) return;
        const holder = await issue(await makeRoot(), { pair, family: 'Ed25519' });
        const report = await read(await file({ holder }));
        expect(codes(report)).toEqual([]);
        expect(report.keys[0]?.signingKey?.algorithm).toEqual({ name: 'Ed448' });
    });
});

describe('readPkcs12 — a runtime without Web Crypto', () => {
    it('should throw once, up front, rather than report every bag', async () => {
        await withHost(undefined, async () => {
            const call = readPkcs12(sequence(int(3)), { password: PASSWORD });
            await expect(call).rejects.toMatchObject({ code: 'PKI_CRYPTO_UNAVAILABLE' });
        });
    });
});

describe('readPkcs12 — misuse still throws', () => {
    it.each([
        ['no options', undefined],
        ['no password', {}],
        ['a numeric password', { password: 1234 }],
        ['an rsaAlgorithm that is not RSA', { password: PASSWORD, rsaAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } }],
        ['an rsaAlgorithm with a digest Web Crypto lacks', { password: PASSWORD, rsaAlgorithm: { name: 'RSA-PSS', hash: 'MD5' } }],
        ['an rsaAlgorithm that is not an object', { password: PASSWORD, rsaAlgorithm: 'RSA' }],
    ])('should refuse %s with PKI_INVALID_OPTION', async (_what, options) => {
        const call = readPkcs12(sequence(int(3)), options as unknown as ReadPkcs12Options);
        await expect(call).rejects.toBeInstanceOf(PkiError);
        await expect(call).rejects.toMatchObject({ code: 'PKI_INVALID_OPTION' });
    });

    it('should refuse input that is not bytes, and limits that are not limits', async () => {
        await expect(readPkcs12('p12' as unknown as Uint8Array, { password: PASSWORD })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
        await expect(readPkcs12(sequence(int(3)), { password: PASSWORD, limits: { maxNode: 1 } as never })).rejects.toMatchObject({ code: 'PKI_LIMIT_INVALID' });
    });

    it('should accept an empty password, which is a password', async () => {
        const report = await readPkcs12(sequence(int(3)), { password: '' });
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
    });
});
