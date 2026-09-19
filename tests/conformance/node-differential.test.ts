/**
 * Differential against node:crypto.X509Certificate (OpenSSL), which ships with
 * Node and adds no dependency. Every certificate here is built by the
 * engine-independent test builder; two parsers that agree on bytes neither
 * produced are evidence, one parser checked against itself is not.
 */

import { describe, it, expect } from 'vitest';
import { X509Certificate } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { getExtension } from '../../src/x509/x509-extensions.js';
import { computeFingerprint, formatFingerprint } from '../../src/hash/fingerprint.js';
import type { Certificate, DistinguishedName, GeneralName } from '../../src/types/x509-types.js';
import {
    algorithm,
    bitString,
    boolean,
    certificate,
    context,
    explicit,
    extension,
    generalizedTime,
    integer,
    name,
    nullValue,
    oid,
    printable,
    rsaKey,
    utcTime,
    utf8,
} from '../helpers/cert-builder.js';
import { ascii, sequence } from '../helpers/raw-der-builder.js';

const SHORT: ReadonlyMap<string, string> = new Map([
    ['2.5.4.6', 'C'], ['2.5.4.8', 'ST'], ['2.5.4.7', 'L'], ['2.5.4.10', 'O'], ['2.5.4.11', 'OU'], ['2.5.4.3', 'CN'],
]);

const RSA_SHA256 = algorithm('1.2.840.113549.1.1.11', nullValue());
const MODULUS = [0x00, 0xc0, ...Array.from({ length: 127 }, (_, i) => (i * 37 + 11) & 0xff)];

const SAMPLES: ReadonlyArray<readonly [string, Uint8Array]> = [
    ['a v3 server certificate', certificate({
        serialNumber: integer([0x00, 0x9a, 0xbc, 0xde, 0xf0]),
        signature: RSA_SHA256,
        signatureAlgorithm: RSA_SHA256,
        issuer: name([['2.5.4.6', printable('FR')]], [['2.5.4.10', utf8('pkinative CA')]], [['2.5.4.3', utf8('pkinative Root')]]),
        subject: name(
            [['2.5.4.6', printable('FR')]],
            [['2.5.4.8', utf8('Ile-de-France')]],
            [['2.5.4.7', utf8('Paris')]],
            [['2.5.4.10', utf8('pkinative')]],
            [['2.5.4.11', utf8('Engineering')]],
            [['2.5.4.3', utf8('www.example.com')]],
        ),
        validity: sequence(utcTime('260101120000Z'), generalizedTime('20510101120000Z')),
        subjectPublicKeyInfo: rsaKey(MODULUS),
        trailing: [explicit(3, sequence(
            extension('2.5.29.19', sequence(boolean(true), integer([0])), true),
            extension('2.5.29.15', bitString([0x06], 1), true),
            extension('2.5.29.37', sequence(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2'))),
            extension('2.5.29.17', sequence(
                context(2, false, ascii('www.example.com')),
                context(2, false, ascii('example.com')),
                context(7, false, [192, 0, 2, 1]),
                context(1, false, ascii('admin@example.com')),
                context(6, false, ascii('https://example.com/')),
            )),
        ))],
    })],
    ['a v1 certificate without extensions', certificate({
        version: null,
        serialNumber: integer([0x01]),
        signature: RSA_SHA256,
        signatureAlgorithm: RSA_SHA256,
        subjectPublicKeyInfo: rsaKey(MODULUS),
        trailing: [],
    })],
];

const FIXTURES: ReadonlyArray<readonly [string, Uint8Array]> = readdirSync(join(process.cwd(), 'tests', 'fixtures', 'certs'))
    .filter((f) => f.endsWith('.der'))
    .map((f) => [`the ${f} fixture`, new Uint8Array(readFileSync(join(process.cwd(), 'tests', 'fixtures', 'certs', f)))] as const);

function openSslName(name: DistinguishedName): string {
    return name.rdns.map((rdn) => rdn.map((a) => `${SHORT.get(a.type) ?? a.type}=${a.value?.value ?? ''}`).join('+')).join('\n');
}

function openSslGeneralName(name: GeneralName): string {
    switch (name.kind) {
        case 'dNSName': return `DNS:${name.value}`;
        case 'rfc822Name': return `email:${name.value}`;
        case 'uniformResourceIdentifier': return `URI:${name.value}`;
        case 'iPAddress': return `IP Address:${name.address}`;
        default: return name.kind;
    }
}

describe.each([...SAMPLES, ...FIXTURES])('parseCertificate and node:crypto on %s', (_, der) => {
    const ours: Certificate = parseCertificate(der, { onDiagnostic: () => undefined });
    const theirs = new X509Certificate(der);

    it('should agree on the serial number', () => {
        expect(ours.serialNumber.value).toBe(BigInt(`0x${theirs.serialNumber}`));
    });

    it('should agree on the subject and the issuer', () => {
        expect(openSslName(ours.subject)).toBe(theirs.subject);
        expect(openSslName(ours.issuer)).toBe(theirs.issuer);
    });

    it('should agree on the validity period', () => {
        expect(ours.validity.notBefore.epochMilliseconds).toBe(Date.parse(theirs.validFrom));
        expect(ours.validity.notAfter.epochMilliseconds).toBe(Date.parse(theirs.validTo));
    });

    it('should agree on the subject alternative names', () => {
        const san = getExtension(ours, 'subjectAltName');
        expect(san === undefined ? undefined : san.names.map(openSslGeneralName).join(', ')).toBe(theirs.subjectAltName);
    });

    it('should agree on the CA flag (OpenSSL X509_check_ca) and the extended key usage', () => {
        const keyUsage = getExtension(ours, 'keyUsage');
        const ca = getExtension(ours, 'basicConstraints')?.cA === true && (keyUsage === undefined || keyUsage.usages.includes('keyCertSign'));
        expect(ca).toBe(theirs.ca);
        expect(getExtension(ours, 'extendedKeyUsage')?.purposes ?? undefined).toEqual(theirs.keyUsage);
    });

    it('should agree on every fingerprint', () => {
        expect(formatFingerprint(computeFingerprint(der, 'SHA-1'))).toBe(theirs.fingerprint);
        expect(formatFingerprint(computeFingerprint(der, 'SHA-256'))).toBe(theirs.fingerprint256);
        expect(formatFingerprint(computeFingerprint(der, 'SHA-512'))).toBe(theirs.fingerprint512);
    });

    it('should agree on the key type and, for RSA and EC, its size', () => {
        const key = theirs.publicKey;
        const details = key.asymmetricKeyDetails;
        const spki = ours.subjectPublicKeyInfo;
        if (spki.kind === 'rsa') expect(spki).toMatchObject({ modulusBits: details?.modulusLength, publicExponent: details?.publicExponent });
        else if (spki.kind === 'ec') expect(details?.namedCurve).toBe({ 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' }[spki.curve ?? 'P-256']);
        else expect(key.asymmetricKeyType).toBe(spki.kind);
    });

    it('should agree on every name the certificate is valid for', () => {
        for (const name of getExtension(ours, 'subjectAltName')?.names ?? []) {
            if (name.kind === 'dNSName') expect(theirs.checkHost(name.value)).toBe(name.value);
            if (name.kind === 'iPAddress') expect(theirs.checkIP(name.address)).toBe(name.address);
            if (name.kind === 'rfc822Name') expect(theirs.checkEmail(name.value)).toBe(name.value);
        }
    });
});
