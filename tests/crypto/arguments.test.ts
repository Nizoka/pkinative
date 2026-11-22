import { beforeAll, describe, expect, it } from 'vitest';
import {
    verifyAttributeCertificateSignature,
    verifyCertificateSignature,
    verifyCrlSignature,
    verifyOcspSignature,
    verifySelfSignature,
} from '../../src/crypto/x509-verify.js';
import { parseCertificateList } from '../../src/revocation/crl-parse.js';
import type { CertificateList } from '../../src/types/crl-types.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { WRONG, expectInvalid } from '../core/_arguments.js';
import { issue, makeCrl, makeRoot, quiet } from '../verify/_cms-pki.js';

/**
 * The signature verifiers, given what a reader did not make.
 *
 * Each takes a parsed structure and reads four members of it: the covered
 * bytes, the two algorithm encodings and the signature. A value that lacks
 * one is refused before any of them is read — a verifier that went on would
 * either throw a `TypeError` or, worse, answer `false` about bytes it never
 * had.
 */

describe('the signature verifiers, given the wrong type', () => {
    let root: Certificate;
    let leaf: Certificate;
    let crl: CertificateList;
    const DER = Uint8Array.of(0x30, 0x00);

    beforeAll(async () => {
        const authority = await makeRoot();
        root = authority.certificate;
        leaf = (await issue(authority)).certificate;
        crl = parseCertificateList(await makeCrl(authority), quiet);
    });

    /** The list with one member replaced: what a hand-built or half-copied value looks like. */
    const without = (member: keyof CertificateList, value: unknown): unknown => ({ ...crl, [member]: value });

    it('should verify a well-typed list, so that every refusal below is the guard\'s', async () => {
        expect(await verifyCrlSignature(crl, root)).toBe(true);
    });

    it.each([...WRONG, ['the DER of the list', DER]] as const)('verifyCrlSignature should refuse %s as the list', async (_label, value) => {
        await expectInvalid(() => verifyCrlSignature(value as never, root));
    });

    it.each([
        ['no covered bytes', 'tbsDer', undefined],
        ['covered bytes that are not bytes', 'tbsDer', [0x30, 0x00]],
        ['no signature algorithm', 'signatureAlgorithm', undefined],
        ['a signature algorithm with no encoding', 'signatureAlgorithm', { oid: '1.2.840.10045.4.3.2' }],
        ['no signature', 'signatureValue', undefined],
        ['a signature with no bytes', 'signatureValue', { unusedBits: 0 }],
        ['an inner algorithm that is null', 'tbsSignatureAlgorithm', null],
        ['an inner algorithm with no encoding', 'tbsSignatureAlgorithm', {}],
    ] as const)('verifyCrlSignature should refuse a list with %s', async (_label, member, value) => {
        await expectInvalid(() => verifyCrlSignature(without(member, value) as never, root));
    });

    it.each([
        ...WRONG,
        ['the DER of the certificate', DER],
        ['a certificate with no key', { tbsDer: DER, signatureAlgorithm: { der: DER }, signatureValue: { bytes: DER, unusedBits: 0 } }],
        ['a certificate whose key has no encoding', { tbsDer: DER, signatureAlgorithm: { der: DER }, signatureValue: { bytes: DER, unusedBits: 0 }, subjectPublicKeyInfo: {} }],
    ] as const)('verifyCrlSignature should refuse %s as the issuer', async (_label, value) => {
        await expectInvalid(() => verifyCrlSignature(crl, value as never));
    });

    it.each(WRONG)('verifyCertificateSignature should refuse %s as the certificate', async (_label, value) => {
        await expectInvalid(() => verifyCertificateSignature(value as never, root));
    });

    it.each(WRONG)('verifyCertificateSignature should refuse %s as the issuer', async (_label, value) => {
        await expectInvalid(() => verifyCertificateSignature(leaf, value as never));
    });

    it.each([...WRONG, ['the DER of the attribute certificate', DER], ['an object with no signature', { tbsDer: DER }]] as const)('verifyAttributeCertificateSignature should refuse %s', async (_label, value) => {
        await expectInvalid(() => verifyAttributeCertificateSignature(value as never, root));
    });

    it.each([...WRONG, ['the DER of the response', DER], ['an object with no signature', { tbsDer: DER }]] as const)('verifyOcspSignature should refuse %s', async (_label, value) => {
        await expectInvalid(() => verifyOcspSignature(value as never, root));
    });

    it.each([
        ...WRONG,
        ['a certificate with no subject', { ...({} as Certificate), der: DER, issuer: { der: DER }, extensions: [] }],
    ] as const)('verifySelfSignature should refuse %s', async (_label, value) => {
        await expectInvalid(() => verifySelfSignature(value as never));
    });

    it('verifySelfSignature should refuse a certificate whose names are not encoded, where it would have compared them', async () => {
        await expectInvalid(() => verifySelfSignature({ ...root, subject: {} } as never));
        await expectInvalid(() => verifySelfSignature({ ...root, issuer: {} } as never));
    });

    it('verifySelfSignature should still say a root signed itself, and a leaf did not', async () => {
        expect(await verifySelfSignature(root)).toBe(true);
        expect(await verifySelfSignature(leaf)).toBe(false);
    });
});

describe('verifySelfSignature, told a certificate by what it reads', () => {
    let root: Certificate;

    beforeAll(async () => {
        root = (await makeRoot()).certificate;
    });

    it.each(['subject', 'issuer'] as const)('should refuse a certificate with no %s', async (member) => {
        await expectInvalid(() => verifySelfSignature({ ...root, [member]: undefined } as never));
    });

    it('should ask for no more than verifyCertificateSignature does of the same value', async () => {
        const read = { ...root, der: undefined, extensions: undefined } as never;
        expect(await verifyCertificateSignature(read, read)).toBe(true);
        expect(await verifySelfSignature(read)).toBe(true);
    });

    it('should answer false for names that differ before it asks for a signature', async () => {
        const other = { subject: root.subject, issuer: { der: Uint8Array.of(0x30, 0x00) } };
        expect(await verifySelfSignature(other as never)).toBe(false);
    });
});
