import { beforeAll, describe, expect, it } from 'vitest';
import { encodeNamedBits, encodeTlv } from '../../src/asn1/asn1-encode.js';
import { createCertificate, encodeSignatureAlgorithm } from '../../src/build/build-certificate.js';
import { createCertificationRequest } from '../../src/build/build-csr.js';
import { createSignedData } from '../../src/build/build-signed-data.js';
import {
    encodeBasicConstraints,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSubjectAltName,
} from '../../src/build/build-structures.js';
import { WRONG, expectCode, expectInvalid } from '../core/_arguments.js';
import { issue, makeRoot, type Holder } from '../verify/_cms-pki.js';

/**
 * The writers, given what is not what their signature names.
 *
 * One test per guard, each on the call where that guard is the one that
 * answers: without it the same call ends in a `TypeError` from a property
 * read, which names neither a code nor a remedy.
 */

describe('the structural encoders, given the wrong type', () => {
    it.each(WRONG)('encodeNameAttribute should refuse %s', async (_label, value) => {
        await expectInvalid(() => encodeNameAttribute(value as never));
    });

    it.each(WRONG)('encodeExtension should refuse %s', async (_label, value) => {
        await expectInvalid(() => encodeExtension(value as never));
    });

    it.each(WRONG)('encodeExtensions should refuse %s where the list is expected', async (_label, value) => {
        await expectInvalid(() => encodeExtensions(value as never));
    });

    it.each(WRONG)('encodeExtensions should refuse %s as an entry of the list', async (_label, value) => {
        await expectInvalid(() => encodeExtensions([value] as never));
    });

    it.each(WRONG)('encodeBasicConstraints should refuse %s', async (_label, value) => {
        await expectInvalid(() => encodeBasicConstraints(value as never));
    });

    it.each([['undefined', undefined], ['null', null], ['a number', 42], ['an object', {}]] as const)('encodeKeyUsage should refuse %s, which cannot be iterated', async (_label, value) => {
        await expectInvalid(() => encodeKeyUsage(value as never));
    });

    it('encodeKeyUsage should refuse a usage that is not a name, with the code of an unknown one', async () => {
        await expectCode(() => encodeKeyUsage([Object.create(null)] as never), 'PKI_INVALID_OPTION');
    });

    it.each(WRONG)('encodeExtendedKeyUsage should refuse %s', async (_label, value) => {
        await expectInvalid(() => encodeExtendedKeyUsage(value as never));
    });

    it.each(WRONG)('encodeSubjectAltName should refuse %s where the list is expected', async (_label, value) => {
        await expectInvalid(() => encodeSubjectAltName(value as never));
    });

    it.each(WRONG)('encodeSubjectAltName should refuse %s as a name of the list', async (_label, value) => {
        await expectInvalid(() => encodeSubjectAltName([value] as never));
    });

    it('encodeSubjectAltName should refuse a name whose form is not a name at all, with the code of an unknown form', async () => {
        await expectCode(() => encodeSubjectAltName([{ kind: Object.create(null), value: 'x' }] as never), 'PKI_INVALID_OPTION');
    });

    it('encodeNameAttribute should refuse a value that is neither text nor bytes, whatever its type member is', async () => {
        await expectInvalid(() => encodeNameAttribute({ type: Object.create(null), value: 42 } as never));
    });

    it.each([['undefined', undefined], ['null', null], ['a number', 42], ['an object', {}]] as const)('encodeNamedBits should refuse %s, which cannot be iterated', async (_label, value) => {
        await expectInvalid(() => encodeNamedBits(value as never));
    });

    it('encodeNamedBits should refuse a position that is not a number, with the code of one out of range', async () => {
        await expectCode(() => encodeNamedBits([Object.create(null)] as never), 'PKI_ASN1_VALUE_OUT_OF_RANGE');
    });
});

describe('the signed writers, given the wrong type', () => {
    let leaf: Holder;

    beforeAll(async () => {
        leaf = await issue(await makeRoot());
    });

    it.each(WRONG)('encodeSignatureAlgorithm should refuse %s as the signer', async (_label, value) => {
        await expectInvalid(() => encodeSignatureAlgorithm(value as never));
    });

    it.each(WRONG)('encodeSignatureAlgorithm should refuse a signer whose algorithm is %s', async (_label, value) => {
        await expectInvalid(() => encodeSignatureAlgorithm({ algorithm: value, key: leaf.signer.key } as never));
    });

    it.each(WRONG)('createCertificate should refuse %s as the description', async (_label, value) => {
        await expectInvalid(() => createCertificate(value as never, leaf.signer));
    });

    it.each(WRONG)('createCertificationRequest should refuse %s as the description', async (_label, value) => {
        await expectInvalid(() => createCertificationRequest(value as never, leaf.signer));
    });

    it.each(WRONG)('createSignedData should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => createSignedData(value as never, leaf.signer));
    });

    it.each(WRONG)('createSignedData should refuse %s as the signer', async (_label, value) => {
        await expectInvalid(() => createSignedData({ content: Uint8Array.of(1), certificate: leaf.certificate }, value as never));
    });

    it.each([...WRONG, ['the DER of the certificate', Uint8Array.of(0x30, 0x00)]] as const)('createSignedData should refuse %s as the signer\'s certificate', async (_label, value) => {
        await expectInvalid(() => createSignedData({ content: Uint8Array.of(1), certificate: value as never }, leaf.signer));
    });
});

describe('the signed writers, wrong in one member', () => {
    let leaf: Holder;
    const content = Uint8Array.of(1);
    const NAME = [[{ type: '2.5.4.3', value: 'One Wrong Member' }]];
    const NOT_LISTS = [['a number', 42], ['a string', 'x'], ['an object', {}]] as const;

    beforeAll(async () => {
        leaf = await issue(await makeRoot());
    });

    it.each([
        ['no DER', (c: Holder['certificate']): object => ({ serialNumber: c.serialNumber, issuer: c.issuer })],
        ['no serial number', (c: Holder['certificate']): object => ({ der: c.der, issuer: c.issuer })],
    ] as const)('createSignedData should refuse a certificate with %s', async (_label, make) => {
        await expectInvalid(() => createSignedData({ content, certificate: make(leaf.certificate) as never }, leaf.signer));
    });

    it('createSignedData should take a certificate that is its DER, serial number and issuer, as 1.0.0 did', async () => {
        const certificate = { der: leaf.certificate.der, serialNumber: leaf.certificate.serialNumber, issuer: leaf.certificate.issuer };
        expect(await createSignedData({ content, certificate: certificate as never }, leaf.signer)).toBeInstanceOf(Uint8Array);
    });

    describe.each(['certificates', 'crls', 'signedAttributes', 'unsignedAttributes'] as const)('createSignedData, given %s', (member) => {
        it.each(NOT_LISTS)('should refuse %s where the list is expected', async (_label, value) => {
            await expectInvalid(() => createSignedData({ content, certificate: leaf.certificate, [member]: value }, leaf.signer));
        });
    });

    it('createSignedData should answer for its signer first when the certificate is wrong too, as 1.0.0 did', async () => {
        const signer = { key: leaf.signer.key, algorithm: { name: 'ECDSA', hash: 'MD5', namedCurve: 'P-256' } };
        await expectCode(() => createSignedData({ content, certificate: Uint8Array.of(0x30, 0x00) as never }, signer as never), 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED');
        await expectCode(() => createSignedData(undefined as never, signer as never), 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED');
    });

    it('createSignedData should refuse an sid that is not a name, with the code of an unknown one', async () => {
        await expectCode(() => createSignedData({ content, certificate: leaf.certificate, sid: Object.create(null) as never }, leaf.signer), 'PKI_INVALID_OPTION');
    });

    it.each([['a Set', new Set()], ['a number', 42], ['an object', {}]] as const)('the two writers should refuse %s as the extensions, which 1.0.0 dropped in silence', async (_label, value) => {
        const subjectPublicKey = leaf.certificate.subjectPublicKeyInfo.der;
        const description = { serialNumber: 1n, issuer: NAME, subject: NAME, notBefore: 0, notAfter: 1000, subjectPublicKey, extensions: value };
        await expectInvalid(() => createCertificate(description as never, leaf.signer));
        await expectInvalid(() => createCertificationRequest({ subject: NAME, subjectPublicKey, extensions: value } as never, leaf.signer));
    });

    it('encodeBasicConstraints should refuse a cA that only reads as a boolean, which 1.0.0 encoded as a CA', async () => {
        await expectCode(() => encodeBasicConstraints({ cA: 'false' as never }), 'PKI_INVALID_OPTION');
        expect(encodeBasicConstraints({ cA: false })).toEqual(Uint8Array.of(0x30, 0x00));
    });

    it.each(WRONG)('createCertificationRequest should refuse %s as the signer', async (_label, value) => {
        await expectInvalid(() => createCertificationRequest({ subject: NAME, subjectPublicKey: leaf.certificate.subjectPublicKeyInfo.der }, value as never));
    });

    it.each([['an object with no prototype', Object.create(null)], ['a symbol', Symbol('s')]] as const)('encodeSignatureAlgorithm should refuse an algorithm named by %s, with the code of an unknown one', async (_label, value) => {
        await expectCode(() => encodeSignatureAlgorithm({ key: leaf.signer.key, algorithm: { name: value, hash: 'SHA-256' } } as never), 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED');
        await expectCode(() => encodeSignatureAlgorithm({ key: leaf.signer.key, algorithm: { name: 'ECDSA', hash: value, namedCurve: 'P-256' } } as never), 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED');
        await expectCode(() => encodeSignatureAlgorithm({ key: leaf.signer.key, algorithm: { name: 'RSA-PSS', hash: value } } as never), 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED');
    });
});

describe('the writers, naming what they refuse', () => {
    it.each([['a symbol', Symbol('s')], ['an object with no prototype', Object.create(null)]] as const)('encodeNameAttribute should refuse %s as the string type, with the code of one the attribute excludes', async (_label, value) => {
        await expectCode(() => encodeNameAttribute({ type: '2.5.4.6', value: 'FR', stringType: value as never }), 'PKI_API_MISUSE');
    });

    it.each([['a symbol', Symbol('s')], ['an object with no prototype', Object.create(null)]] as const)('encodeTlv should refuse %s as the tag number, with the code of one out of range', async (_label, value) => {
        await expectCode(() => encodeTlv('universal', value as never, false, Uint8Array.of(1)), 'PKI_ASN1_VALUE_OUT_OF_RANGE');
    });
});
