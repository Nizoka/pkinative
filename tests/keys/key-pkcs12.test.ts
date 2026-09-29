import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openSafeContents, parsePkcs12, verifyPkcs12Mac } from '../../src/keys/key-pkcs12.js';
import type { Pkcs12, SafeContentsInfo } from '../../src/types/key-types.js';
import { PkiCryptoError, PkiEncodingError, PkiError, PkiKeyError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiParseOptions } from '../../src/types/pki-types.js';
import { alg, attribute, context, int, octets, oid } from '../helpers/cms-signed-data-builder.js';
import {
    P12,
    authenticatedSafe,
    berPfx,
    bmp,
    certBag,
    contentInfo,
    crlBag,
    dataInfo,
    encryptedDataInfo,
    encryptedSafeContents,
    friendlyName,
    keyBag,
    legacyMacData,
    localKeyId,
    macData,
    pbmac1MacData,
    pfx,
    safeBag,
    safeContents,
    safeContentsBag,
    secretBag,
    shroudKey,
    shroudedKeyBag,
} from '../helpers/pkcs12-builder.js';
import { ascii, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 7292 PKCS#12 as `keys` reads it: the PFX, the AuthenticatedSafe, every
 * SafeBag type, PBES2-encrypted SafeContents opened through Web Crypto, and
 * RFC 9579 PBMAC1 checked — while the Appendix B MAC is described and refused.
 * Every file is written by the independent tests/helpers/pkcs12-builder.ts,
 * with ciphertexts and MACs computed by the host, never by the engine.
 */

const PASSWORD = 'correct horse battery staple';
const CERT = Uint8Array.from(sequence(int(1), universal(12, ascii('not parsed here'))));
const CRL = Uint8Array.from(sequence(int(2)));
const KEY_ID = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
const PKCS8 = new Uint8Array(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'der', type: 'pkcs8' }));

function parse(der: Uint8Array, options: PkiParseOptions = {}): { p12: Pkcs12; diagnostics: PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const p12 = parsePkcs12(der, { onDiagnostic: (d) => { diagnostics.push(d); }, ...options });
    return { p12, diagnostics };
}

function refusal(fn: () => unknown): unknown {
    try {
        fn();
    } catch (error) {
        return error;
    }
    throw new Error('expected a refusal');
}

const keyError = (code: string, path?: string): unknown => expect.objectContaining(path === undefined ? { code } : { code, path });

/** A PFX whose only AuthenticatedSafe entry is a plain SafeContents of these bags. */
const plain = (...bags: Uint8Array[]): Uint8Array => pfx({ authSafe: authenticatedSafe(dataInfo(safeContents(...bags))) });

/** Parse a PFX expected to be refused, with the error. */
const refuse = (der: Uint8Array, options: PkiParseOptions = {}): unknown => refusal(() => parse(der, options));

/** The first bag of a one-entry plain PFX. */
function firstBag(bag: Uint8Array): Pkcs12['contents'][number]['bags'][number] {
    const { p12 } = parse(plain(bag));
    const found = p12.contents[0]?.bags[0];
    if (found === undefined) throw new Error('no bag');
    return found;
}

describe('parsePkcs12 — the PFX envelope (RFC 7292 §4)', () => {
    it('should read version 3, the authenticated octets and one plain SafeContents', () => {
        const safe = authenticatedSafe(dataInfo(safeContents(certBag(CERT))));
        const der = pfx({ authSafe: safe });
        const { p12, diagnostics } = parse(der);
        expect(p12.version).toBe(3);
        expect(p12.der).toEqual(der);
        expect(p12.authenticatedSafe).toEqual(safe);
        expect(p12.mac).toBeUndefined();
        expect(p12.contents).toHaveLength(1);
        expect(p12.contents[0]).toMatchObject({ encrypted: false, encryption: undefined, encryptedContent: undefined, path: 'authSafe[0]' });
        expect(diagnostics).toEqual([]);
        expect(p12.diagnostics).toEqual([]);
    });

    it('should refuse a version other than 3 with PKI_KEY_VERSION_UNSUPPORTED', () => {
        const error = refuse(pfx({ version: 2, authSafe: authenticatedSafe() }));
        expect(error).toBeInstanceOf(PkiKeyError);
        expect(error).toEqual(keyError('PKI_KEY_VERSION_UNSUPPORTED', 'pfx.version'));
    });

    it('should refuse a value after macData', () => {
        expect(refuse(pfx({ authSafe: authenticatedSafe(), macData: legacyMacData(), extra: [int(1)] }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'pfx'));
    });

    it('should refuse something that is not a PFX SEQUENCE', () => {
        expect(refuse(int(3))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'pfx'));
    });

    it('should refuse a missing authSafe', () => {
        expect(refuse(sequence(int(3)))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe'));
    });

    it('should refuse public-key integrity mode (signedData) with PKI_KEY_MAC_UNSUPPORTED', () => {
        const error = refuse(pfx({ authSafe: new Uint8Array(0), authSafeInfo: contentInfo(P12.signedData, sequence(int(1))) }));
        expect(error).toBeInstanceOf(PkiKeyError);
        expect(error).toEqual(keyError('PKI_KEY_MAC_UNSUPPORTED', 'authSafe.contentType'));
    });

    it('should refuse an authSafe of another content type', () => {
        expect(refuse(pfx({ authSafe: new Uint8Array(0), authSafeInfo: contentInfo(P12.envelopedData, sequence(int(1))) })))
            .toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe.contentType'));
    });

    it('should refuse an authSafe ContentInfo without content', () => {
        expect(refuse(pfx({ authSafe: new Uint8Array(0), authSafeInfo: sequence(oid(P12.data)) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe'));
    });

    it('should refuse a ContentInfo whose type is not an OID', () => {
        expect(refuse(pfx({ authSafe: new Uint8Array(0), authSafeInfo: sequence(int(1), context(0, true, octets([]))) })))
            .toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe.contentType'));
    });

    it.each([
        ['missing', sequence(oid(P12.data), sequence())],
        ['a universal tag', sequence(oid(P12.data), sequence(octets([])))],
        ['[1] instead of [0]', sequence(oid(P12.data), context(1, true, octets([])))],
        ['primitive [0]', sequence(oid(P12.data), context(0, false, [1]))],
        ['[0] around two values', sequence(oid(P12.data), context(0, true, [...octets([]), ...octets([])]))],
    ])('should refuse an [0] EXPLICIT content that is %s', (_label, info) => {
        expect(refuse(pfx({ authSafe: new Uint8Array(0), authSafeInfo: info }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID'));
    });

    it('should refuse authSafe data content that is not an OCTET STRING', () => {
        expect(refuse(pfx({ authSafe: new Uint8Array(0), authSafeInfo: contentInfo(P12.data, sequence()) })))
            .toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe.content'));
    });

    it('should refuse an AuthenticatedSafe that is not a SEQUENCE', () => {
        expect(refuse(pfx({ authSafe: int(1) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe'));
    });

    it('should refuse AuthenticatedSafe octets that are not DER', () => {
        expect(refuse(pfx({ authSafe: Uint8Array.of(0x30, 0x05) }))).toBeInstanceOf(PkiEncodingError);
    });

    it('should refuse an input that is not a Uint8Array', () => {
        expect(refusal(() => parsePkcs12('p12' as unknown as Uint8Array))).toEqual(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should bound the AuthenticatedSafe entries by maxPkcs12Bags', () => {
        const der = pfx({ authSafe: authenticatedSafe(dataInfo(safeContents()), dataInfo(safeContents()), dataInfo(safeContents())) });
        const error = refuse(der, { limits: { maxPkcs12Bags: 2 } });
        expect(error).toBeInstanceOf(PkiLimitError);
        expect(error).toEqual(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxPkcs12Bags' }));
    });

    it('should read a BER PFX with indefinite lengths and a segmented authSafe, as Windows writes it', () => {
        const safe = authenticatedSafe(dataInfo(safeContents(certBag(CERT, [friendlyName('win')]))));
        const { p12, diagnostics } = parse(berPfx(safe, legacyMacData()), { encodingRules: 'ber' });
        expect(p12.authenticatedSafe).toEqual(safe);
        expect(p12.contents[0]?.bags[0]?.friendlyName).toBe('win');
        expect(p12.mac?.kind).toBe('pkcs12-kdf');
        expect(diagnostics.map((d) => d.code)).toContain('PKI_DIAG_BER_CONSTRUCT_ACCEPTED');
    });

    it('should refuse the same BER PFX under DER', () => {
        expect(refuse(berPfx(authenticatedSafe(), undefined))).toBeInstanceOf(PkiEncodingError);
    });
});

describe('parsePkcs12 — AuthenticatedSafe entries', () => {
    it('should describe an encryptedData entry without opening it', async () => {
        const encrypted = await encryptedSafeContents(safeContents(certBag(CERT)), PASSWORD);
        const { p12 } = parse(pfx({ authSafe: authenticatedSafe(encrypted) }));
        const entry = p12.contents[0];
        expect(entry?.encrypted).toBe(true);
        expect(entry?.bags).toEqual([]);
        expect(entry?.encryption?.scheme).toBe('PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)');
        expect(entry?.encryptedContent?.length).toBe(Math.ceil((safeContents(certBag(CERT)).length + 1) / 16) * 16);
    });

    it('should describe a refused scheme with its name', () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(encryptedDataInfo(Uint8Array.of(1, 2, 3), { algorithm: alg(P12.pbeWithSHAAnd3KeyTripleDES, sequence(octets([1]), int(2048))) })) })).p12.contents[0];
        expect(entry?.encryption?.pbes2).toBeUndefined();
        expect(entry?.encryption?.scheme).toBe('pbeWithSHAAnd3-KeyTripleDES-CBC');
    });

    it('should report envelopedData as encrypted with no password scheme', () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(contentInfo(P12.envelopedData, sequence(int(0)))) })).p12.contents[0];
        expect(entry).toMatchObject({ encrypted: true, encryption: undefined, encryptedContent: undefined, bags: [], path: 'authSafe[0]' });
    });

    it('should refuse an entry of another content type', () => {
        expect(refuse(pfx({ authSafe: authenticatedSafe(contentInfo(P12.digestedData, sequence())) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe[0].contentType'));
    });

    it('should refuse a data entry whose content is not an OCTET STRING', () => {
        expect(refuse(pfx({ authSafe: authenticatedSafe(contentInfo(P12.data, sequence())) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe[0].content'));
    });

    it('should refuse a SafeContents that is not a SEQUENCE', () => {
        expect(refuse(pfx({ authSafe: authenticatedSafe(dataInfo(int(0))) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe[0]'));
    });

    it('should accept EncryptedData version 2 with unprotectedAttrs [1]', () => {
        const info = encryptedDataInfo(Uint8Array.of(1), { version: int(2), trailing: [context(1, true, attribute('1.2.3', int(1)))] });
        expect(parse(pfx({ authSafe: authenticatedSafe(info) })).p12.contents[0]?.encryptedContent).toEqual(Uint8Array.of(1));
    });

    it.each([
        ['a version other than 0 or 2', { version: int(1) }, 'authSafe[0].content.version'],
        ['a version that is not an INTEGER', { version: octets([0]) }, 'authSafe[0].content.version'],
        ['a trailing value that is not [1]', { trailing: [context(2, true, int(1))] }, 'authSafe[0].content'],
        ['a trailing universal value', { trailing: [sequence()] }, 'authSafe[0].content'],
        ['a primitive [1]', { trailing: [context(1, false, [1])] }, 'authSafe[0].content'],
        ['two trailing values', { trailing: [context(1, true, int(1)), context(1, true, int(1))] }, 'authSafe[0].content'],
        ['a missing encryptedContentInfo', { version: int(0), trailing: [] as Uint8Array[], replaceInfo: true }, 'authSafe[0].content.encryptedContentInfo'],
        ['an inner type other than data', { contentType: P12.signedData }, 'authSafe[0].content.encryptedContentInfo.contentType'],
        ['no ciphertext', { encryptedContent: null }, 'authSafe[0].content.encryptedContentInfo.encryptedContent'],
        ['a universal ciphertext', { encryptedContent: octets([1]) }, 'authSafe[0].content.encryptedContentInfo.encryptedContent'],
        ['ciphertext tagged [1]', { encryptedContent: context(1, false, [1]) }, 'authSafe[0].content.encryptedContentInfo.encryptedContent'],
        ['a value after the ciphertext', { infoTrailing: [int(1)] }, 'authSafe[0].content.encryptedContentInfo'],
    ])('should refuse EncryptedData with %s', (_label, parts, path) => {
        const info = 'replaceInfo' in parts
            ? contentInfo(P12.encryptedData, sequence(int(0)))
            : encryptedDataInfo(Uint8Array.of(1), parts);
        expect(refuse(pfx({ authSafe: authenticatedSafe(info) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', path));
    });

    it('should refuse EncryptedData that is not a SEQUENCE', () => {
        expect(refuse(pfx({ authSafe: authenticatedSafe(contentInfo(P12.encryptedData, int(0))) }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe[0].content'));
    });

    it('should refuse a constructed ciphertext under DER and join it under BER', () => {
        const segmented = context(0, true, [...octets([1, 2]), ...octets([3])]);
        const der = pfx({ authSafe: authenticatedSafe(encryptedDataInfo(new Uint8Array(0), { encryptedContent: segmented })) });
        expect(refuse(der)).toEqual(expect.objectContaining({ code: 'PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN' }));
        expect(parse(der, { encodingRules: 'ber' }).p12.contents[0]?.encryptedContent).toEqual(Uint8Array.of(1, 2, 3));
    });

    it('should bound the PBES2 iteration count of an encrypted entry by maxKdfIterations', async () => {
        const encrypted = await encryptedSafeContents(safeContents(), PASSWORD, { iterations: 5000 });
        const error = refuse(pfx({ authSafe: authenticatedSafe(encrypted) }), { limits: { maxKdfIterations: 4999 } });
        expect(error).toBeInstanceOf(PkiLimitError);
        expect(error).toEqual(expect.objectContaining({ limit: 'maxKdfIterations' }));
    });
});

describe('parsePkcs12 — SafeBags (RFC 7292 §4.2)', () => {
    it('should give a certBag its certificate DER, the content of the OCTET STRING', () => {
        const bag = firstBag(certBag(CERT));
        expect(bag).toMatchObject({ kind: 'certBag', oid: P12.certBag, certificateDer: CERT, crlDer: undefined, privateKey: undefined, encryptedKey: undefined, path: 'authSafe[0].bags[0]' });
        expect(bag.valueDer).toEqual(sequence(oid(P12.x509Certificate), context(0, true, octets(CERT))));
        expect(bag.attributes).toEqual([]);
    });

    it('should leave certificateDer undefined for a certificate type other than x509Certificate', () => {
        const bag = firstBag(safeBag(P12.certBag, sequence(oid(P12.sdsiCertificate), context(0, true, universal(22, ascii('sdsi'))))));
        expect(bag.kind).toBe('certBag');
        expect(bag.certificateDer).toBeUndefined();
    });

    it('should give a crlBag its CRL DER', () => {
        expect(firstBag(crlBag(CRL))).toMatchObject({ kind: 'crlBag', crlDer: CRL, certificateDer: undefined });
    });

    it('should describe a keyBag without exposing its secret', () => {
        const bag = firstBag(keyBag(PKCS8));
        expect(bag.kind).toBe('keyBag');
        expect(bag.privateKey).toMatchObject({ keyType: 'ec', namedCurve: 'P-256', version: 0, diagnostics: [] });
        expect(bag.privateKey).not.toHaveProperty('privateKey');
    });

    it('should describe a pkcs8ShroudedKeyBag, with the diagnostics of its own scheme', async () => {
        const bag = firstBag(shroudedKeyBag(await shroudKey(PKCS8, PASSWORD, { iterations: 500 })));
        expect(bag.kind).toBe('pkcs8ShroudedKeyBag');
        expect(bag.encryptedKey?.encryption.pbes2?.iterations).toBe(500);
        expect(bag.encryptedKey?.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_KEY_KDF_ITERATIONS_LOW']);
    });

    it('should read a secretBag and keep its value as DER', () => {
        const bag = firstBag(secretBag(Uint8Array.of(9)));
        expect(bag.kind).toBe('secretBag');
        expect(bag.valueDer).toEqual(sequence(oid('1.2.3.4'), context(0, true, octets([9]))));
    });

    it('should keep a bag of an unknown type as unknown', () => {
        const bag = firstBag(safeBag('1.2.3.4.5', int(7)));
        expect(bag).toMatchObject({ kind: 'unknown', oid: '1.2.3.4.5', valueDer: int(7) });
    });

    it('should flatten nested safeContentsBags depth first, in encoded order, with their paths', () => {
        const nested = safeContentsBag([certBag(CERT), safeContentsBag([crlBag(CRL)]), keyBag(PKCS8)], [friendlyName('outer')]);
        const { p12 } = parse(plain(certBag(CERT), nested, secretBag(Uint8Array.of(1))));
        const bags = p12.contents[0]?.bags ?? [];
        expect(bags.map((b) => `${b.kind}@${b.path}`)).toEqual([
            'certBag@authSafe[0].bags[0]',
            'safeContentsBag@authSafe[0].bags[1]',
            'certBag@authSafe[0].bags[1].bags[0]',
            'safeContentsBag@authSafe[0].bags[1].bags[1]',
            'crlBag@authSafe[0].bags[1].bags[1].bags[0]',
            'keyBag@authSafe[0].bags[1].bags[2]',
            'secretBag@authSafe[0].bags[2]',
        ]);
        expect(bags[1]?.friendlyName).toBe('outer');
    });

    it('should read friendlyName (BMPString) and localKeyId when each appears once with one value', () => {
        const bag = firstBag(certBag(CERT, [attribute('1.2.3', int(1)), friendlyName('Ünïcødé ✓'), localKeyId(KEY_ID)]));
        expect(bag.friendlyName).toBe('Ünïcødé ✓');
        expect(bag.localKeyId).toEqual(KEY_ID);
        expect(bag.attributes.map((a) => a.oid)).toEqual(['1.2.3', P12.friendlyName, P12.localKeyId]);
    });

    it('should leave friendlyName and localKeyId undefined when either appears twice', () => {
        const bag = firstBag(certBag(CERT, [friendlyName('a'), friendlyName('b'), localKeyId(KEY_ID), localKeyId(KEY_ID)]));
        expect(bag.friendlyName).toBeUndefined();
        expect(bag.localKeyId).toBeUndefined();
        expect(bag.attributes).toHaveLength(4);
    });

    it('should leave them undefined when the attribute carries two values', () => {
        const bag = firstBag(certBag(CERT, [attribute(P12.friendlyName, bmp('a'), bmp('b')), attribute(P12.localKeyId, octets([1]), octets([2]))]));
        expect(bag.friendlyName).toBeUndefined();
        expect(bag.localKeyId).toBeUndefined();
    });

    it('should accept an empty bagAttributes SET', () => {
        expect(firstBag(certBag(CERT, [])).attributes).toEqual([]);
    });

    it.each([
        ['a friendlyName that is not a BMPString', certBag(CERT, [attribute(P12.friendlyName, universal(12, ascii('utf8')))]), 'authSafe[0].bags[0].bagAttributes.friendlyName'],
        ['a localKeyId that is not an OCTET STRING', certBag(CERT, [attribute(P12.localKeyId, int(1))]), 'authSafe[0].bags[0].bagAttributes.localKeyId'],
        ['bagAttributes that are not a SET', sequence(oid(P12.certBag), context(0, true, sequence()), sequence()), 'authSafe[0].bags[0].bagAttributes'],
        ['a bag that is not a SEQUENCE', int(1), 'authSafe[0].bags[0]'],
        ['a bagId that is not an OID', sequence(int(1), context(0, true, int(1))), 'authSafe[0].bags[0].bagId'],
        ['a missing bagValue', sequence(oid(P12.certBag)), 'authSafe[0].bags[0].bagValue'],
        ['a value after bagAttributes', sequence(oid(P12.certBag), context(0, true, int(1)), universal(17, [], true), int(1)), 'authSafe[0].bags[0]'],
        ['a CertBag that is not a SEQUENCE', safeBag(P12.certBag, int(1)), 'authSafe[0].bags[0].bagValue'],
        ['a CertBag of one value', safeBag(P12.certBag, sequence(oid(P12.x509Certificate))), 'authSafe[0].bags[0].bagValue'],
        ['a CertBag type that is not an OID', safeBag(P12.certBag, sequence(int(1), context(0, true, octets([1])))), 'authSafe[0].bags[0].bagValue.typeId'],
        ['an x509Certificate that is not an OCTET STRING', safeBag(P12.certBag, sequence(oid(P12.x509Certificate), context(0, true, sequence()))), 'authSafe[0].bags[0].bagValue.value'],
        ['a SecretBag without its [0]', safeBag(P12.secretBag, sequence(oid('1.2.3'), int(1))), 'authSafe[0].bags[0].bagValue.value'],
        ['a nested SafeContents that is not a SEQUENCE', safeBag(P12.safeContentsBag, int(1)), 'authSafe[0].bags[0]'],
        ['a keyBag that is not a PrivateKeyInfo', keyBag(int(1)), 'authSafe[0].bags[0].bagValue'],
        ['a shrouded key that is not an EncryptedPrivateKeyInfo', shroudedKeyBag(int(1)), 'authSafe[0].bags[0].bagValue'],
    ])('should refuse %s', (_label, bag, path) => {
        const error = refuse(plain(bag));
        expect(error).toBeInstanceOf(PkiKeyError);
        expect(error).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', path));
    });

    it('should refuse a BMPString friendlyName with an odd length', () => {
        const error = refuse(plain(certBag(CERT, [attribute(P12.friendlyName, universal(30, [0, 0x41, 0]))])));
        expect(error).toEqual(expect.objectContaining({ code: 'PKI_ASN1_STRING_INVALID' }));
    });

    it('should bound the bag attributes by maxCmsAttributes', () => {
        expect(refuse(plain(certBag(CERT, [friendlyName('a'), friendlyName('b')])), { limits: { maxCmsAttributes: 1 } }))
            .toEqual(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxCmsAttributes' }));
    });

    it('should bound the bags of one call by maxPkcs12Bags, nested and across SafeContents', () => {
        const der = pfx({ authSafe: authenticatedSafe(dataInfo(safeContents(certBag(CERT))), dataInfo(safeContents(safeContentsBag([certBag(CERT)])))) });
        expect(parse(der, { limits: { maxPkcs12Bags: 3 } }).p12.contents.flatMap((c) => c.bags)).toHaveLength(3);
        const error = refuse(der, { limits: { maxPkcs12Bags: 2 } });
        expect(error).toBeInstanceOf(PkiLimitError);
        expect(error).toEqual(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxPkcs12Bags', observed: 3 }));
    });

    it('should flatten a deep chain of safeContentsBags without recursion', () => {
        let bag = certBag(CERT);
        for (let i = 0; i < 200; i++) bag = safeContentsBag([bag]);
        const bags = parse(plain(bag), { limits: { maxDepth: 2000 } }).p12.contents[0]?.bags ?? [];
        expect(bags).toHaveLength(201);
        expect(bags[200]?.kind).toBe('certBag');
    });
});

describe('parsePkcs12 — MacData', () => {
    it('should describe an RFC 7292 Appendix B MAC as pkcs12-kdf', () => {
        const mac = parse(pfx({ authSafe: authenticatedSafe(), macData: legacyMacData() })).p12.mac;
        expect(mac).toMatchObject({ kind: 'pkcs12-kdf', iterations: 2048, pbmac1: undefined });
        expect(mac?.algorithm.oid).toBe(P12.sha256);
        expect(mac?.mac).toHaveLength(32);
        expect(mac?.salt).toHaveLength(8);
    });

    it('should default the iterations to 1 when absent, and diagnose an encoded DEFAULT', () => {
        const absent = parse(pfx({ authSafe: authenticatedSafe(), macData: macData(alg(P12.sha1), new Uint8Array(20), Uint8Array.of(1), null) }));
        expect(absent.p12.mac?.iterations).toBe(1);
        expect(absent.diagnostics).toEqual([]);
        const encoded = parse(pfx({ authSafe: authenticatedSafe(), macData: macData(alg(P12.sha1), new Uint8Array(20), Uint8Array.of(1), 1) }));
        expect(encoded.p12.mac?.iterations).toBe(1);
        expect(encoded.diagnostics.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_DEFAULT_ENCODED', 'macData.iterations']]);
    });

    it('should not call an encoded iteration count other than 1 an encoded DEFAULT', () => {
        const explicit = parse(pfx({ authSafe: authenticatedSafe(), macData: macData(alg(P12.sha1), new Uint8Array(20), Uint8Array.of(1), 2) }));
        expect(explicit.p12.mac?.iterations).toBe(2);
        expect(explicit.diagnostics).toEqual([]);
    });

    it('should describe a PBMAC1 MAC (RFC 9579)', async () => {
        const safe = authenticatedSafe();
        const mac = parse(pfx({ authSafe: safe, macData: await pbmac1MacData(safe, PASSWORD, { prf: 'SHA-512', hmac: 'SHA-384', keyLength: 48 }) })).p12.mac;
        expect(mac?.kind).toBe('pbmac1');
        expect(mac?.algorithm.oid).toBe(P12.pbmac1);
        expect(mac?.pbmac1).toMatchObject({ iterations: 2048, prf: 'SHA-512', hmac: 'SHA-384', keyLength: 48 });
    });

    it('should still describe a PBMAC1 whose KDF is not PBKDF2, with pbmac1 undefined', () => {
        const params = sequence(alg('1.2.3.4', sequence()), alg('1.2.840.113549.2.9'));
        const mac = parse(pfx({ authSafe: authenticatedSafe(), macData: macData(alg(P12.pbmac1, params), new Uint8Array(32), Uint8Array.of(1)) })).p12.mac;
        expect(mac).toMatchObject({ kind: 'pbmac1', pbmac1: undefined });
    });

    const pbmac1With = (kdfParams: Uint8Array, scheme: Uint8Array): Uint8Array =>
        pfx({ authSafe: authenticatedSafe(), macData: macData(alg(P12.pbmac1, sequence(alg(P12.pbkdf2, kdfParams), scheme)), new Uint8Array(32), Uint8Array.of(1)) });
    const kdfParams = (keyLength: number | null, prf = '1.2.840.113549.2.9'): Uint8Array =>
        sequence(octets([1, 2, 3, 4]), int(2048), ...(keyLength === null ? [] : [int(keyLength)]), alg(prf));

    it.each([
        ['an HMAC Web Crypto does not run', kdfParams(32), alg('1.2.840.113549.2.8')],
        ['a PRF Web Crypto does not run', kdfParams(32, '1.2.840.113549.2.8'), alg('1.2.840.113549.2.9')],
        ['HMAC parameters other than NULL', kdfParams(32), alg('1.2.840.113549.2.9', int(1))],
        ['context-tagged HMAC parameters', kdfParams(32), alg('1.2.840.113549.2.9', context(0, false, []))],
    ])('should describe a PBMAC1 with %s, pbmac1 undefined', (_label, params, scheme) => {
        expect(parse(pbmac1With(params, scheme)).p12.mac).toMatchObject({ kind: 'pbmac1', pbmac1: undefined });
    });

    it('should accept absent HMAC parameters', () => {
        expect(parse(pbmac1With(kdfParams(32), sequence(oid('1.2.840.113549.2.9')))).p12.mac?.pbmac1?.hmac).toBe('SHA-256');
    });

    it('should refuse a PBMAC1 without keyLength (RFC 9579 §3)', () => {
        expect(refuse(pbmac1With(kdfParams(null), alg('1.2.840.113549.2.9'))))
            .toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'macData.mac.digestAlgorithm.parameters.keyDerivationFunc.parameters.keyLength'));
    });

    it('should bound the PBMAC1 iteration count by maxKdfIterations', async () => {
        const safe = authenticatedSafe();
        const error = refuse(pfx({ authSafe: safe, macData: await pbmac1MacData(safe, PASSWORD, { iterations: 3000 }) }), { limits: { maxKdfIterations: 2999 } });
        expect(error).toBeInstanceOf(PkiLimitError);
        expect(error).toEqual(expect.objectContaining({ limit: 'maxKdfIterations' }));
    });

    it.each([
        ['PBMAC1 parameters that are not a SEQUENCE', macData(alg(P12.pbmac1, int(1)), new Uint8Array(1), Uint8Array.of(1)), 'macData.mac.digestAlgorithm.parameters'],
        ['PBMAC1 parameters of one value', macData(alg(P12.pbmac1, sequence(alg(P12.pbkdf2))), new Uint8Array(1), Uint8Array.of(1)), 'macData.mac.digestAlgorithm.parameters'],
        ['a MacData that is not a SEQUENCE', int(1), 'macData'],
        ['a value after iterations', sequence(sequence(alg(P12.sha1), octets([1])), octets([1]), int(2), int(3)), 'macData'],
        ['a DigestInfo that is not a SEQUENCE', sequence(int(1), octets([1])), 'macData.mac'],
        ['a DigestInfo of one value', sequence(sequence(alg(P12.sha1)), octets([1])), 'macData.mac'],
        ['a digest that is not an OCTET STRING', sequence(sequence(alg(P12.sha1), int(1)), octets([1])), 'macData.mac.digest'],
        ['a missing macSalt', sequence(sequence(alg(P12.sha1), octets([1]))), 'macData.macSalt'],
        ['iterations that are not an INTEGER', sequence(sequence(alg(P12.sha1), octets([1])), octets([1]), octets([1])), 'macData.iterations'],
        ['zero iterations', macData(alg(P12.sha1), new Uint8Array(1), Uint8Array.of(1), 0), 'macData.iterations'],
    ])('should refuse %s', (_label, mac, path) => {
        expect(refuse(pfx({ authSafe: authenticatedSafe(), macData: mac }))).toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', path));
    });

    it('should refuse an iteration count no number can hold', () => {
        const huge = sequence(sequence(alg(P12.sha1), octets([1])), octets([1]), universal(2, [0x01, 0, 0, 0, 0, 0, 0, 0, 0]));
        expect(refuse(pfx({ authSafe: authenticatedSafe(), macData: huge }))).toEqual(expect.objectContaining({ code: 'PKI_ASN1_INTEGER_UNREPRESENTABLE' }));
    });
});

describe('verifyPkcs12Mac', () => {
    async function signed(password: string | Uint8Array = PASSWORD): Promise<Pkcs12> {
        const safe = authenticatedSafe(dataInfo(safeContents(certBag(CERT))));
        return parsePkcs12(pfx({ authSafe: safe, macData: await pbmac1MacData(safe, password) }));
    }

    it('should verify a PBMAC1 MAC under the right password', async () => {
        expect(await verifyPkcs12Mac(await signed(), PASSWORD)).toBe(true);
    });

    it('should verify with the password given as octets, and leave them intact', async () => {
        const octetsPassword = Uint8Array.of(0xff, 0x00, 0x41);
        expect(await verifyPkcs12Mac(await signed(octetsPassword), octetsPassword)).toBe(true);
        expect(octetsPassword).toEqual(Uint8Array.of(0xff, 0x00, 0x41));
    });

    it('should verify a PBMAC1 over SHA-512 with a SHA-1 PRF', async () => {
        const safe = authenticatedSafe();
        const p12 = parsePkcs12(pfx({ authSafe: safe, macData: await pbmac1MacData(safe, PASSWORD, { prf: 'SHA-1', hmac: 'SHA-512', keyLength: 64 }) }), { onDiagnostic: () => undefined });
        expect(await verifyPkcs12Mac(p12, PASSWORD)).toBe(true);
    });

    it('should answer false for a wrong password', async () => {
        expect(await verifyPkcs12Mac(await signed(), 'wrong')).toBe(false);
    });

    it('should answer false for an altered AuthenticatedSafe', async () => {
        const safe = authenticatedSafe(dataInfo(safeContents(certBag(CERT))));
        const mac = await pbmac1MacData(safe, PASSWORD);
        const altered = authenticatedSafe(dataInfo(safeContents(certBag(CRL))));
        expect(await verifyPkcs12Mac(parsePkcs12(pfx({ authSafe: altered, macData: mac })), PASSWORD)).toBe(false);
    });

    it('should refuse an Appendix B MAC with PKI_KEY_MAC_UNSUPPORTED', async () => {
        const p12 = parsePkcs12(pfx({ authSafe: authenticatedSafe(), macData: legacyMacData() }));
        await expect(verifyPkcs12Mac(p12, PASSWORD)).rejects.toBeInstanceOf(PkiKeyError);
        await expect(verifyPkcs12Mac(p12, PASSWORD)).rejects.toEqual(expect.objectContaining({ code: 'PKI_KEY_MAC_UNSUPPORTED', offset: undefined }));
    });

    it('should refuse a PBMAC1 it described without parameters', async () => {
        const params = sequence(alg('1.2.3.4', sequence()), alg('1.2.840.113549.2.9'));
        const p12 = parsePkcs12(pfx({ authSafe: authenticatedSafe(), macData: macData(alg(P12.pbmac1, params), new Uint8Array(32), Uint8Array.of(1)) }));
        await expect(verifyPkcs12Mac(p12, PASSWORD)).rejects.toEqual(keyError('PKI_KEY_MAC_UNSUPPORTED', 'macData.mac.digestAlgorithm'));
    });

    it('should call a container without MAC a misuse', async () => {
        const p12 = parsePkcs12(pfx({ authSafe: authenticatedSafe() }));
        const error: unknown = await verifyPkcs12Mac(p12, PASSWORD).catch((e: unknown) => e);
        expect(error).toBeInstanceOf(PkiError);
        expect(error).toEqual(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it.each([[null], [42]])('should refuse a container argument of %s', async (bad) => {
        await expect(verifyPkcs12Mac(bad as unknown as Pkcs12, PASSWORD)).rejects.toEqual(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it.each([[null], [42]])('should refuse a password of %s', async (bad) => {
        await expect(verifyPkcs12Mac(await signed(), bad as unknown as string)).rejects.toEqual(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

describe('openSafeContents', () => {
    it('should return the bags of a plain SafeContents as read', async () => {
        const entry = parse(plain(certBag(CERT))).p12.contents[0] as SafeContentsInfo;
        expect(await openSafeContents(entry, PASSWORD)).toBe(entry.bags);
    });

    it('should decrypt a PBES2 SafeContents and read its bags under the entry path', async () => {
        const inner = safeContents(certBag(CERT, [localKeyId(KEY_ID)]), shroudedKeyBag(await shroudKey(PKCS8, PASSWORD)), safeContentsBag([crlBag(CRL)]));
        const der = pfx({ authSafe: authenticatedSafe(dataInfo(safeContents()), await encryptedSafeContents(inner, PASSWORD, { keyBits: 128, prf: 'SHA-384' })) });
        const entry = parse(der).p12.contents[1] as SafeContentsInfo;
        const bags = await openSafeContents(entry, PASSWORD);
        expect(bags.map((b) => `${b.kind}@${b.path}`)).toEqual([
            'certBag@authSafe[1].bags[0]',
            'pkcs8ShroudedKeyBag@authSafe[1].bags[1]',
            'safeContentsBag@authSafe[1].bags[2]',
            'crlBag@authSafe[1].bags[2].bags[0]',
        ]);
        expect(bags[0]?.certificateDer).toEqual(CERT);
        expect(bags[0]?.localKeyId).toEqual(KEY_ID);
    });

    it('should report the decrypted SafeContents diagnostics through onDiagnostic', async () => {
        const inner = safeContents(shroudedKeyBag(await shroudKey(PKCS8, PASSWORD, { iterations: 10 })));
        const entry = parse(pfx({ authSafe: authenticatedSafe(await encryptedSafeContents(inner, PASSWORD)) })).p12.contents[0] as SafeContentsInfo;
        const diagnostics: PkiDiagnostic[] = [];
        const bags = await openSafeContents(entry, PASSWORD, { onDiagnostic: (d) => { diagnostics.push(d); } });
        expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_KEY_KDF_ITERATIONS_LOW']);
        expect(bags[0]?.encryptedKey?.diagnostics).toHaveLength(1);
    });

    it('should fail with PKI_CRYPTO_DECRYPTION_FAILED under a wrong password', async () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(await encryptedSafeContents(safeContents(certBag(CERT)), PASSWORD)) })).p12.contents[0] as SafeContentsInfo;
        const error: unknown = await openSafeContents(entry, 'wrong').catch((e: unknown) => e);
        // A wrong key whose padding happens to check out yields garbage instead; this pair is fixed and does not.
        expect(error).toBeInstanceOf(PkiCryptoError);
        expect(error).toEqual(expect.objectContaining({ code: 'PKI_CRYPTO_DECRYPTION_FAILED' }));
    });

    it('should refuse a scheme other than PBES2 with PKI_KEY_ENCRYPTION_UNSUPPORTED, naming it', async () => {
        const info = encryptedDataInfo(Uint8Array.of(1, 2, 3), { algorithm: alg(P12.pbeWithSHAAnd3KeyTripleDES, sequence(octets([1]), int(2048))) });
        const entry = parse(pfx({ authSafe: authenticatedSafe(info) })).p12.contents[0] as SafeContentsInfo;
        const error: unknown = await openSafeContents(entry, PASSWORD).catch((e: unknown) => e);
        expect(error).toBeInstanceOf(PkiKeyError);
        expect(error).toEqual(keyError('PKI_KEY_ENCRYPTION_UNSUPPORTED', 'authSafe[0].content.encryptedContentInfo.contentEncryptionAlgorithm'));
        expect((error as Error).message).toContain('pbeWithSHAAnd3-KeyTripleDES-CBC');
        expect((error as Error).message).not.toContain('at offset');
    });

    it('should refuse envelopedData (public-key privacy mode) with PKI_KEY_ENCRYPTION_UNSUPPORTED', async () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(contentInfo(P12.envelopedData, sequence(int(0)))) })).p12.contents[0] as SafeContentsInfo;
        await expect(openSafeContents(entry, PASSWORD)).rejects.toEqual(keyError('PKI_KEY_ENCRYPTION_UNSUPPORTED', 'authSafe[0]'));
    });

    it('should call an encrypted entry without its ciphertext a misuse', async () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(await encryptedSafeContents(safeContents(), PASSWORD)) })).p12.contents[0] as SafeContentsInfo;
        await expect(openSafeContents({ ...entry, encryptedContent: undefined }, PASSWORD)).rejects.toEqual(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it('should bound the iteration count again by the limits of this call', async () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(await encryptedSafeContents(safeContents(), PASSWORD, { iterations: 4000 })) })).p12.contents[0] as SafeContentsInfo;
        await expect(openSafeContents(entry, PASSWORD, { limits: { maxKdfIterations: 3999 } })).rejects.toEqual(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxKdfIterations' }));
    });

    it('should bound the decrypted bags by maxPkcs12Bags', async () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(await encryptedSafeContents(safeContents(certBag(CERT), certBag(CERT)), PASSWORD)) })).p12.contents[0] as SafeContentsInfo;
        await expect(openSafeContents(entry, PASSWORD, { limits: { maxPkcs12Bags: 1 } })).rejects.toEqual(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxPkcs12Bags' }));
    });

    it('should refuse decrypted content that is not a SafeContents', async () => {
        const entry = parse(pfx({ authSafe: authenticatedSafe(await encryptedSafeContents(int(5), PASSWORD)) })).p12.contents[0] as SafeContentsInfo;
        await expect(openSafeContents(entry, PASSWORD)).rejects.toEqual(keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe[0]'));
    });

    it('should refuse a bad option before decrypting', async () => {
        const entry = parse(plain()).p12.contents[0] as SafeContentsInfo;
        await expect(openSafeContents(entry, PASSWORD, { encodingRules: 'cer' as 'der' })).rejects.toEqual(expect.objectContaining({ code: 'PKI_INVALID_OPTION' }));
    });

    it.each([[null], ['entry']])('should refuse a contents argument of %s', async (bad) => {
        await expect(openSafeContents(bad as unknown as SafeContentsInfo, PASSWORD)).rejects.toEqual(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});
