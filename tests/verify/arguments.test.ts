import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { createSignedData } from '../../src/build/build-signed-data.js';
import { createTimeStampRequest } from '../../src/cms/tsp-request.js';
import { parseTstInfo } from '../../src/cms/tsp-tst-info.js';
import { importPrivateKey } from '../../src/keys/key-import.js';
import { openSafeContents, verifyPkcs12Mac } from '../../src/keys/key-pkcs12.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { verifyCertificateChain } from '../../src/verify/verify-chain.js';
import { verifySignedData } from '../../src/verify/verify-signed-data.js';
import { verifyTimeStampToken } from '../../src/verify/verify-timestamp.js';
import { WRONG, expectCode, expectInvalid, refusal } from '../core/_arguments.js';
import { AT, codes, issue, makeRoot, withSigners } from './_cms-pki.js';

/**
 * The compositions, and the readers and key functions they call, given what
 * is not what their signature names.
 *
 * A composition always resolves with a report and throws only for misuse:
 * these are the misuses decided before anything is read, so each must reject
 * with a `PkiError` — a `TypeError` here would be neither a report nor a
 * refusal a caller can act on.
 */

describe('the compositions, given the wrong type', () => {
    let root: Certificate;
    const DER = Uint8Array.of(0x30, 0x00);
    const HASH = new Uint8Array(32);

    beforeAll(async () => {
        root = (await makeRoot()).certificate;
    });

    it.each(WRONG)('verifyCertificateChain should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => verifyCertificateChain(value as never));
    });

    it.each([...WRONG, ['the DER of the certificate', DER]] as const)('verifyCertificateChain should refuse %s as the leaf', async (_label, value) => {
        await expectInvalid(() => verifyCertificateChain({ leaf: value as never, trustAnchors: [root] }));
    });

    it.each(WRONG)('verifyCertificateChain should refuse %s where the trust anchors are expected', async (_label, value) => {
        await expectInvalid(() => verifyCertificateChain({ leaf: root, trustAnchors: value as never }));
    });

    it.each(WRONG)('verifySignedData should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => verifySignedData(value as never));
    });

    it.each(WRONG)('verifySignedData should refuse %s where the trust anchors are expected', async (_label, value) => {
        await expectInvalid(() => verifySignedData({ signedData: DER, trustAnchors: value as never }));
    });

    it.each(WRONG)('verifyTimeStampToken should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => verifyTimeStampToken(value as never));
    });

    it.each(WRONG)('verifyTimeStampToken should refuse %s where the trust anchors are expected', async (_label, value) => {
        await expectInvalid(() => verifyTimeStampToken({ token: DER, imprint: HASH, trustAnchors: value as never }));
    });
});

describe('the timestamp and key functions, given the wrong type', () => {
    const HASH = new Uint8Array(32);

    it.each(WRONG)('parseTstInfo should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => parseTstInfo(value as never));
    });

    it.each([
        ['a number', 42],
        ['an object with no prototype', Object.create(null) as unknown],
        ['SHA-1, which is not offered', 'SHA-1'],
        // Names every object answers to: the table is asked for its own members only.
        ['__proto__', '__proto__'],
        ['constructor', 'constructor'],
        ['toString', 'toString'],
    ] as const)('createTimeStampRequest should refuse %s as the hash algorithm, as an option outside its domain', async (_label, value) => {
        await expectCode(() => createTimeStampRequest(HASH, { hashAlgorithm: value as never }), 'PKI_INVALID_OPTION');
    });

    it.each(WRONG)('verifyPkcs12Mac should refuse %s as the parsed PKCS#12', async (_label, value) => {
        await expectInvalid(() => verifyPkcs12Mac(value as never, 'password'));
    });

    it.each([['null', null], ['a number', 42], ['a string', 'x']] as const)('verifyPkcs12Mac should refuse a PKCS#12 whose mac is %s', async (_label, value) => {
        await expectInvalid(() => verifyPkcs12Mac({ mac: value } as never, 'password'));
    });

    it.each(WRONG)('verifyPkcs12Mac should refuse a mac of another kind whose algorithm is %s', async (_label, value) => {
        await expectInvalid(() => verifyPkcs12Mac({ mac: { kind: 'legacy', algorithm: value } } as never, 'password'));
    });

    it('verifyPkcs12Mac should name the unsupported MAC whatever its OID member is', async () => {
        await expectCode(() => verifyPkcs12Mac({ mac: { kind: 'legacy', algorithm: { oid: Object.create(null) as unknown } } } as never, 'password'), 'PKI_KEY_MAC_UNSUPPORTED');
    });

    it.each([...WRONG, ['an object with no path', { encrypted: false, bags: [] }], ['an object whose path is not text', { encrypted: true, path: Object.create(null) as unknown }]] as const)(
        'openSafeContents should refuse %s as the entry', async (_label, value) => {
            await expectInvalid(() => openSafeContents(value as never, 'password'));
        });
});

describe('the compositions, wrong in one member', () => {
    let root: Certificate;
    let leaf: Certificate;
    let signedData: Uint8Array;
    const content = Uint8Array.of(1, 2, 3);
    const DER = Uint8Array.of(0x30, 0x00);
    const NOT_INSTANTS = [['a string', '2026-01-15'], ['NaN', Number.NaN], ['a Date', new Date(0)], ['a bigint', 1n]] as const;
    const NOT_LISTS = [['a number', 42], ['a string', 'x'], ['an object', {}]] as const;

    beforeAll(async () => {
        const authority = await makeRoot();
        const holder = await issue(authority);
        root = authority.certificate;
        leaf = holder.certificate;
        signedData = await createSignedData({ content, certificate: leaf }, holder.signer);
    });

    it.each(NOT_INSTANTS)('verifyCertificateChain should refuse %s as the instant', async (_label, value) => {
        await expectInvalid(() => verifyCertificateChain({ leaf: root, trustAnchors: [root], at: value as never }));
    });

    describe.each(['crls', 'ocspResponses', 'purposes'] as const)('verifyCertificateChain, given %s', (member) => {
        it.each(NOT_LISTS)('should refuse %s where the list is expected', async (_label, value) => {
            await expectInvalid(() => verifyCertificateChain({ leaf: root, trustAnchors: [root], [member]: value }));
        });
    });

    it('verifyCertificateChain should answer for its limits first when the instant is wrong too, as 1.0.0 did', async () => {
        await expectCode(() => verifyCertificateChain({ leaf: root, trustAnchors: [root], at: 'now' as never, limits: { maxChainLength: 0 } }), 'PKI_LIMIT_INVALID');
    });

    describe.each(['crls', 'ocspResponses', 'purposes'] as const)('verifySignedData, given %s', (member) => {
        it.each(NOT_LISTS)('should refuse %s where the list is expected', async (_label, value) => {
            await expectInvalid(() => verifySignedData({ signedData, trustAnchors: [root], [member]: value }));
        });
    });

    describe.each(['crls', 'ocspResponses'] as const)('verifyTimeStampToken, given %s', (member) => {
        it.each(NOT_LISTS)('should refuse %s where the list is expected', async (_label, value) => {
            await expectInvalid(() => verifyTimeStampToken({ token: DER, data: DER, trustAnchors: [root], [member]: value }));
        });
    });

    it.each(NOT_INSTANTS)('verifySignedData should refuse %s as the instant', async (_label, value) => {
        await expectInvalid(() => verifySignedData({ signedData, trustAnchors: [root], at: value as never }));
    });

    it.each(NOT_INSTANTS)('verifyTimeStampToken should refuse %s as the instant', async (_label, value) => {
        await expectInvalid(() => verifyTimeStampToken({ token: DER, data: DER, trustAnchors: [root], at: value as never }));
    });
});

describe('the compositions, where each member is first read', () => {
    let root: Certificate;
    let leaf: Certificate;
    let signedData: Uint8Array;
    let pkcs8: Uint8Array;
    const content = Uint8Array.of(1, 2, 3);
    const DER = Uint8Array.of(0x30, 0x00);

    beforeAll(async () => {
        const authority = await makeRoot();
        const holder = await issue(authority);
        root = authority.certificate;
        leaf = holder.certificate;
        signedData = await createSignedData({ content, certificate: leaf }, holder.signer);
        pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', holder.pair.privateKey as never));
    });

    it('verifyCertificateChain should take a Set of candidates, as 1.0.0 did', async () => {
        const report = await verifyCertificateChain({ leaf, candidates: new Set([root]) as never, trustAnchors: [root], at: AT });
        expect(codes(report)).toEqual([]);
    });

    it('verifyCertificateChain should refuse candidates that can be read once only, which it reads twice', async () => {
        const once = (function* (): Generator<Certificate> { yield root; })();
        await expectInvalid(() => verifyCertificateChain({ leaf, candidates: once as never, trustAnchors: [root], at: AT }));
    });

    it('verifyCertificateChain should refuse trust anchors that are not an array', async () => {
        await expectInvalid(() => verifyCertificateChain({ leaf, trustAnchors: new Set([root]) as never, at: AT }));
    });

    it('verifySignedData should take a Set of certificates, as 1.0.0 did', async () => {
        const report = await verifySignedData({ signedData, certificates: new Set([leaf]) as never, trustAnchors: [root], at: AT });
        expect(codes(report)).toEqual([]);
    });

    it('verifySignedData should still report a message it cannot read, whatever the instant is', async () => {
        const report = await verifySignedData({ signedData: DER, trustAnchors: [root], at: 'now' as never });
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
    });

    it('verifySignedData should refuse a wrong instant once the message is read, whether or not a signer would have used it', async () => {
        // No signer, so no chain is built and nothing downstream reads `at`:
        // a misuse is refused the same way whatever the message holds.
        await expectInvalid(() => verifySignedData({ signedData: withSigners(signedData, []), trustAnchors: [root], at: 'now' as never }));
    });

    it('verifyCertificateChain should refuse a requirement written as text, which 1.0.0 read as off', async () => {
        await expectCode(() => verifyCertificateChain({ leaf, candidates: [root], trustAnchors: [root], at: AT, requireRevocation: 'true' as never }), 'PKI_INVALID_OPTION');
    });

    it('verifySignedData should still report a message it cannot read, whatever a flag is', async () => {
        const report = await verifySignedData({ signedData: DER, trustAnchors: [root], allowSha1: 'no' as never });
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
    });

    it('verifySignedData should answer for the content passed twice first when a flag is wrong too', async () => {
        await expectCode(() => verifySignedData({ signedData, content, trustAnchors: [root], atTimeStamp: 1 as never }), 'PKI_API_MISUSE');
    });

    it('verifySignedData should answer for the content passed twice first when the instant is wrong too, as 1.0.0 did', async () => {
        await expectCode(() => verifySignedData({ signedData, content, trustAnchors: [root], at: 'now' as never }), 'PKI_API_MISUSE');
    });

    it('verifyTimeStampToken should answer for its request first when the instant is wrong too, as 1.0.0 did', async () => {
        const first = await refusal(() => verifyTimeStampToken({ token: DER, request: DER, trustAnchors: [root] }));
        expect(first).toBeInstanceOf(PkiError);
        expect(await refusal(() => verifyTimeStampToken({ token: DER, request: DER, trustAnchors: [root], at: 'now' as never }))).toEqual(expect.objectContaining({ code: (first as PkiError).code }));
    });

    it('importPrivateKey should refuse an algorithm named by what is not text, with the code of one the key cannot sign with', async () => {
        await expectCode(() => importPrivateKey(pkcs8, { algorithm: { name: Object.create(null) as never, hash: 'SHA-256' } as never }), 'PKI_API_MISUSE');
    });
});
