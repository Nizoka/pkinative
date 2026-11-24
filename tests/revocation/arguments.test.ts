import { beforeAll, describe, expect, it } from 'vitest';
import { checkRevocation } from '../../src/revocation/crl-check.js';
import { parseCertificateList } from '../../src/revocation/crl-parse.js';
import { checkOcspStatus } from '../../src/revocation/ocsp-check.js';
import { createOcspRequest, encodeOcspCertId } from '../../src/revocation/ocsp-request.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import type { CertificateList } from '../../src/types/crl-types.js';
import type { OcspBasicResponse, OcspCertId, OcspResponse } from '../../src/types/ocsp-types.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { WRONG, expectCode, expectInvalid, refusal } from '../core/_arguments.js';
import { AT, issue, makeCrl, makeOcspResponse, makeRoot, quiet } from '../verify/_cms-pki.js';

/**
 * The revocation primitives, given what is not what their signature names:
 * one test per guard, on the call where that guard is the one that answers.
 */

describe('the revocation primitives, given the wrong type', () => {
    let root: Certificate;
    let leaf: Certificate;
    let crlDer: Uint8Array;
    let crl: CertificateList;
    const DER = Uint8Array.of(0x30, 0x00);

    beforeAll(async () => {
        const authority = await makeRoot();
        root = authority.certificate;
        leaf = (await issue(authority)).certificate;
        crlDer = await makeCrl(authority);
        crl = parseCertificateList(crlDer, quiet);
    });

    // ── checkRevocation ──
    it.each(WRONG)('checkRevocation should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => checkRevocation(value as never));
    });

    it.each([...WRONG, ['the DER of the certificate', DER]] as const)('checkRevocation should refuse %s as the certificate', async (_label, value) => {
        await expectInvalid(() => checkRevocation({ certificate: value as never, crl, crlDer, at: AT }));
    });

    it.each([
        ...WRONG,
        ['the DER of the list', DER],
        ['a list with no issuer', { extensions: [] }],
        ['a list whose issuer has no encoding', { issuer: {}, extensions: [] }],
        ['a list with no extension list', { issuer: { der: DER } }],
    ] as const)('checkRevocation should refuse %s as the list', async (_label, value) => {
        await expectInvalid(() => checkRevocation({ certificate: leaf, crl: value as never, crlDer, at: AT }));
    });

    it.each([['null', null], ['a number', 42], ['a string', 'x']] as const)('checkRevocation should refuse %s as the delta', async (_label, value) => {
        await expectInvalid(() => checkRevocation({ certificate: leaf, crl, crlDer, at: AT, delta: value as never }));
    });

    it.each(WRONG)('checkRevocation should refuse a delta whose list is %s', async (_label, value) => {
        await expectInvalid(() => checkRevocation({ certificate: leaf, crl, crlDer, at: AT, delta: { crl: value as never, crlDer, signatureVerified: true } }));
    });

    it('checkRevocation should still answer well-typed input', () => {
        expect(checkRevocation({ certificate: leaf, crl, crlDer, at: AT, signatureVerified: true, ...quiet }).map((reason) => reason.code)).toEqual([]);
    });

    // ── checkOcspStatus ──
    it.each(WRONG)('checkOcspStatus should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => checkOcspStatus(value as never));
    });

    it.each(WRONG)('checkOcspStatus should refuse %s as the response', async (_label, value) => {
        await expectInvalid(() => checkOcspStatus({ response: value as never, expected: { issuerNameHash: DER, issuerKeyHash: DER, serialNumber: DER }, at: AT }));
    });

    // ── encodeOcspCertId, createOcspRequest ──
    it.each([
        ...WRONG,
        ['the DER of the certificate', DER],
        ['a certificate with no subject', { der: DER, issuer: { der: DER }, extensions: [] }],
    ] as const)('encodeOcspCertId should refuse %s as the certificate', async (_label, value) => {
        await expectInvalid(() => encodeOcspCertId(value as never, root));
    });

    it.each([...WRONG, ['the DER of the certificate', DER]] as const)('encodeOcspCertId should refuse %s as the issuer', async (_label, value) => {
        await expectInvalid(() => encodeOcspCertId(leaf, value as never));
    });

    it.each(WRONG)('createOcspRequest should refuse %s as the certificate', async (_label, value) => {
        await expectInvalid(() => createOcspRequest(value as never, root));
    });
});

describe('the revocation primitives, told a value by what they read', () => {
    let root: Certificate;
    let leaf: Certificate;
    let crlDer: Uint8Array;
    let crl: CertificateList;
    let response: OcspResponse;
    let expected: { issuerNameHash: Uint8Array; issuerKeyHash: Uint8Array; serialNumber: Uint8Array };
    const DER = Uint8Array.of(0x30, 0x00);
    const NOT_INSTANTS = [['undefined', undefined], ['a string', '2026-01-15'], ['NaN', Number.NaN], ['a Date', new Date(AT)], ['a bigint', 1n]] as const;

    beforeAll(async () => {
        const authority = await makeRoot();
        root = authority.certificate;
        leaf = (await issue(authority)).certificate;
        crlDer = await makeCrl(authority);
        crl = parseCertificateList(crlDer, quiet);
        response = parseOcspResponse(await makeOcspResponse(authority, leaf, 'good'), quiet);
        const id = (response.basicResponse as OcspBasicResponse).responses[0]?.certId as OcspCertId;
        expected = { issuerNameHash: id.issuerNameHash, issuerKeyHash: id.issuerKeyHash, serialNumber: id.serialNumber.bytes };
    });

    // ── checkRevocation ──
    it.each([
        ['no issuer', (c: Certificate): object => ({ serialNumber: c.serialNumber, extensions: c.extensions })],
        ['no serial number', (c: Certificate): object => ({ issuer: c.issuer, extensions: c.extensions })],
    ] as const)('checkRevocation should refuse a certificate with %s', async (_label, make) => {
        await expectInvalid(() => checkRevocation({ certificate: make(leaf) as never, crl, crlDer, at: AT }));
    });

    it.each(NOT_INSTANTS)('checkRevocation should refuse %s as the instant', async (_label, value) => {
        await expectInvalid(() => checkRevocation({ certificate: leaf, crl, crlDer, at: value as never }));
    });

    // ── checkOcspStatus ──
    it('checkOcspStatus should answer well-typed input', () => {
        expect(checkOcspStatus({ response, expected, at: AT, signatureVerified: true, responderAuthorized: true, signer: root, ...quiet }).map((reason) => reason.code)).toEqual([]);
    });

    it.each(WRONG)('checkOcspStatus should refuse %s as what was asked about', async (_label, value) => {
        await expectInvalid(() => checkOcspStatus({ response, expected: value as never, at: AT }));
    });

    it.each(['issuerNameHash', 'issuerKeyHash', 'serialNumber'] as const)('checkOcspStatus should refuse an expected %s that is not bytes', async (member) => {
        await expectInvalid(() => checkOcspStatus({ response, expected: { ...expected, [member]: 'x' }, at: AT }));
    });

    it.each([['null', null], ['a number', 42], ['a string', 'x'], ['the DER of the certificate', DER], ['an object', {}]] as const)('checkOcspStatus should refuse %s as the signer', async (_label, value) => {
        await expectInvalid(() => checkOcspStatus({ response, expected, at: AT, signer: value as never }));
    });

    // The signer is told by the one member the responderID is compared with
    // (RFC 6960 §4.2.2.3): its key for `byKey`, its subject for `byName`.
    describe.each([
        ['byKey', 'its key', (c: Certificate): object => ({ subjectPublicKeyInfo: c.subjectPublicKeyInfo, extensions: c.extensions }), (c: Certificate): object => ({ subject: c.subject, extensions: c.extensions })],
        ['byName', 'its subject', (c: Certificate): object => ({ subject: c.subject, extensions: c.extensions }), (c: Certificate): object => ({ subjectPublicKeyInfo: c.subjectPublicKeyInfo, extensions: c.extensions })],
    ] as const)('checkOcspStatus, given a response whose responder is named %s', (kind, member, withIt, withoutIt) => {
        const answered = (): OcspResponse => (kind === 'byKey' ? response : {
            ...response,
            basicResponse: { ...(response.basicResponse as OcspBasicResponse), responderId: { kind: 'byName', nameDer: root.subject.der } },
        } as unknown as OcspResponse);

        it(`should take a signer that carries ${member} and nothing else it does not read`, () => {
            const reasons = checkOcspStatus({ response: answered(), expected, at: AT, signatureVerified: true, responderAuthorized: true, signer: withIt(root) as never, ...quiet });
            expect(reasons.map((reason) => reason.code)).toEqual([]);
        });

        it(`should refuse a signer without ${member}`, async () => {
            await expectInvalid(() => checkOcspStatus({ response: answered(), expected, at: AT, signer: withoutIt(root) as never }));
        });
    });

    it.each(NOT_INSTANTS)('checkOcspStatus should refuse %s as the instant', async (_label, value) => {
        await expectInvalid(() => checkOcspStatus({ response, expected, at: value as never }));
    });

    it('checkOcspStatus should still answer a response that declined, whatever its status is made of', () => {
        const declined = { status: Object.create(null) as never } as unknown as OcspResponse;
        expect(checkOcspStatus({ response: declined, expected, at: AT }).map((reason) => reason.code)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    // ── encodeOcspCertId ──
    it('encodeOcspCertId should refuse a certificate with no serial number', async () => {
        await expectInvalid(() => encodeOcspCertId({ der: DER } as never, root));
    });

    it.each([
        ['no DER', (c: Certificate): object => ({ subject: c.subject, subjectPublicKeyInfo: c.subjectPublicKeyInfo })],
        ['no subject', (c: Certificate): object => ({ der: c.der, subjectPublicKeyInfo: c.subjectPublicKeyInfo })],
        ['no key', (c: Certificate): object => ({ der: c.der, subject: c.subject })],
    ] as const)('encodeOcspCertId should refuse an issuer with %s', async (_label, make) => {
        await expectInvalid(() => encodeOcspCertId(leaf, make(root) as never));
    });

    it.each([['an object with no prototype', Object.create(null)], ['a symbol', Symbol('s')], ['a number', 42]] as const)('encodeOcspCertId should refuse %s as the digest, as it does an unknown name', async (_label, value) => {
        const unknown = await refusal(() => encodeOcspCertId(leaf, root, 'SHA-512' as never));
        expect(await refusal(() => encodeOcspCertId(leaf, root, value as never))).toEqual(expect.objectContaining({ code: (unknown as { code: string }).code }));
    });
});

describe('the revocation primitives, where each member is first read', () => {
    let root: Certificate;
    let leaf: Certificate;
    let crlDer: Uint8Array;
    let crl: CertificateList;
    let response: OcspResponse;
    let expected: { issuerNameHash: Uint8Array; issuerKeyHash: Uint8Array; serialNumber: Uint8Array };
    const NOT_NUMBERS = [['a string', '0'], ['NaN', Number.NaN], ['a bigint', 1n], ['a symbol', Symbol('s')], ['an object with no prototype', Object.create(null)]] as const;

    beforeAll(async () => {
        const authority = await makeRoot();
        root = authority.certificate;
        leaf = (await issue(authority)).certificate;
        crlDer = await makeCrl(authority);
        crl = parseCertificateList(crlDer, quiet);
        response = parseOcspResponse(await makeOcspResponse(authority, leaf, 'good'), quiet);
        const id = (response.basicResponse as OcspBasicResponse).responses[0]?.certId as OcspCertId;
        expected = { issuerNameHash: id.issuerNameHash, issuerKeyHash: id.issuerKeyHash, serialNumber: id.serialNumber.bytes };
    });

    // ── checkRevocation ──
    it.each(NOT_NUMBERS)('checkRevocation should refuse %s as the stale tolerance', async (_label, value) => {
        await expectCode(() => checkRevocation({ certificate: leaf, crl, crlDer, at: AT, staleTolerance: value as never }), 'PKI_INVALID_OPTION');
    });

    it.each([0, -1, 60_000, Infinity])('checkRevocation should take %d as the stale tolerance', (value) => {
        expect(() => checkRevocation({ certificate: leaf, crl, crlDer, at: AT, staleTolerance: value, ...quiet })).not.toThrow();
    });

    it('checkRevocation should not read the list of a delta nobody vouched for, as 1.0.0 did not', () => {
        const delta = { crl: 42 as never, crlDer, signatureVerified: false };
        expect(checkRevocation({ certificate: leaf, crl, crlDer, at: AT, signatureVerified: true, delta, ...quiet }).map((reason) => reason.code)).toEqual([]);
    });

    it('checkRevocation should answer for its options first when the instant is wrong too, as 1.0.0 did', async () => {
        await expectCode(() => checkRevocation({ certificate: leaf, crl, crlDer, at: new Date(AT) as never, strict: 'yes' as never }), 'PKI_INVALID_OPTION');
    });

    it('checkRevocation should answer for its options first when the serial number is missing too, as 1.0.0 did', async () => {
        const certificate = { issuer: leaf.issuer, extensions: leaf.extensions } as never;
        await expectCode(() => checkRevocation({ certificate, crl, crlDer, at: AT, strict: 'yes' as never }), 'PKI_INVALID_OPTION');
    });

    // ── checkOcspStatus ──
    it.each([['null', null], ['a number', 42], ['a string', 'x']] as const)('checkOcspStatus should refuse %s as the nonce', async (_label, value) => {
        await expectInvalid(() => checkOcspStatus({ response, expected, at: AT, nonce: value as never }));
    });

    it.each(['futureTolerance', 'staleTolerance'] as const)('checkOcspStatus should refuse a %s that is not a number, with the code of one out of range', async (member) => {
        await expectCode(() => checkOcspStatus({ response, expected, at: AT, [member]: Object.create(null) as never }), 'PKI_INVALID_OPTION');
    });

    it('checkOcspStatus should not read what was asked about when the response answers about nothing, as 1.0.0 did not', () => {
        const basicResponse = { ...(response.basicResponse as OcspBasicResponse), responses: [] };
        const empty = { ...response, basicResponse } as OcspResponse;
        expect(checkOcspStatus({ response: empty, expected: undefined as never, at: AT, signatureVerified: true, responderAuthorized: true }).map((reason) => reason.code)).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
    });

    // ── encodeOcspCertId ──
    it.each(['SHA-384', 'SHA-512', '__proto__', 'toString'])('encodeOcspCertId should refuse the digest %s before it hashes with another', async (name) => {
        await expectCode(() => encodeOcspCertId(leaf, root, name as never), 'PKI_INVALID_OPTION');
    });

    it('createOcspRequest should refuse a digest it does not write, with the same code', async () => {
        await expectCode(() => createOcspRequest(leaf, root, { hashAlgorithm: 'SHA-384' as never }), 'PKI_INVALID_OPTION');
    });
});
