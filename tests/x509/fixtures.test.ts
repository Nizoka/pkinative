import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { getExtension } from '../../src/x509/x509-extensions.js';
import { formatDistinguishedName } from '../../src/x509/x509-name-format.js';
import { computeFingerprint, formatFingerprint } from '../../src/hash/fingerprint.js';
import type { Certificate, KeyUsageName } from '../../src/types/x509-types.js';

// Known answers for public certificates (tests/fixtures/PROVENANCE.md). Every
// expected value was read with OpenSSL 3.5.5 (`openssl x509 -text`), an
// implementation independent of pkinative, on 2026-09-19.

const load = (name: string): Uint8Array => new Uint8Array(readFileSync(join(process.cwd(), 'tests', 'fixtures', 'certs', `${name}.der`)));

interface KnownAnswer {
    readonly file: string;
    readonly subject: string;
    readonly issuer: string;
    readonly serialHex: string;
    readonly notBefore: string;
    readonly notAfter: string;
    readonly signature: string;
    readonly key: Record<string, unknown>;
    readonly sha256: string;
    readonly subjectKeyId: string;
    readonly authorityKeyId: string | undefined;
    readonly usages: readonly KeyUsageName[];
    readonly ca: boolean;
    readonly pathLen: number | undefined;
    readonly diagnostics: readonly string[];
}

const RSA_SHA256 = '1.2.840.113549.1.1.11';
const ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const ISRG = 'O=Internet Security Research Group,C=US';
const X1_KEY_ID = '79b459e67bb6e5e40173800888c81a58f6e99b6e';
const X2_KEY_ID = '7c4296aede4b483bfa92f89e8ccf6d8ba9723795';

const ANSWERS: readonly KnownAnswer[] = [
    {
        file: 'isrg-root-x1', subject: `CN=ISRG Root X1,${ISRG}`, issuer: `CN=ISRG Root X1,${ISRG}`,
        serialHex: '008210cfb0d240e3594463e0bb63828b00', notBefore: '2015-06-04T11:04:38Z', notAfter: '2035-06-04T11:04:38Z',
        signature: RSA_SHA256, key: { kind: 'rsa', modulusBits: 4096, publicExponent: 65537n },
        sha256: '96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6', subjectKeyId: X1_KEY_ID, authorityKeyId: undefined,
        usages: ['keyCertSign', 'cRLSign'], ca: true, pathLen: undefined, diagnostics: [],
    },
    {
        file: 'isrg-root-x2', subject: `CN=ISRG Root X2,${ISRG}`, issuer: `CN=ISRG Root X2,${ISRG}`,
        serialHex: '41d29dd172eaeea780c12c6ce92f8752', notBefore: '2020-09-04T00:00:00Z', notAfter: '2040-09-17T16:00:00Z',
        signature: ECDSA_SHA384, key: { kind: 'ec', curve: 'P-384', pointFormat: 'uncompressed' },
        sha256: '69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470', subjectKeyId: X2_KEY_ID, authorityKeyId: undefined,
        usages: ['keyCertSign', 'cRLSign'], ca: true, pathLen: undefined, diagnostics: [],
    },
    {
        file: 'lets-encrypt-e7', subject: "CN=E7,O=Let's Encrypt,C=US", issuer: `CN=ISRG Root X2,${ISRG}`,
        serialHex: '00c58a85a2c62345e0a8c45253879f593a', notBefore: '2024-03-13T00:00:00Z', notAfter: '2027-03-12T23:59:59Z',
        signature: ECDSA_SHA384, key: { kind: 'ec', curve: 'P-384' },
        sha256: '54715420224c5b65beed018dc3940d7338c577e322d5488f633d8c6a8fed61b2',
        subjectKeyId: 'ae489edc871d44a06fdaa2e560740478c29c0080', authorityKeyId: X2_KEY_ID,
        usages: ['digitalSignature', 'keyCertSign', 'cRLSign'], ca: true, pathLen: 0, diagnostics: [],
    },
    {
        file: 'lets-encrypt-r12', subject: "CN=R12,O=Let's Encrypt,C=US", issuer: `CN=ISRG Root X1,${ISRG}`,
        serialHex: '00c212324b70a9b49171dc40f7e285263c', notBefore: '2024-03-13T00:00:00Z', notAfter: '2027-03-12T23:59:59Z',
        signature: RSA_SHA256, key: { kind: 'rsa', modulusBits: 2048, publicExponent: 65537n },
        sha256: '131fce7784016899a5a00203a9efc80f18ebbd75580717edc1553580930836ec',
        subjectKeyId: '00b529f22d8e6f31e89b4cad783efadce90cd1d2', authorityKeyId: X1_KEY_ID,
        usages: ['digitalSignature', 'keyCertSign', 'cRLSign'], ca: true, pathLen: 0, diagnostics: [],
    },
    {
        file: 'letsencrypt-org-leaf', subject: 'CN=letsencrypt.org', issuer: "CN=YE2,O=Let's Encrypt,C=US",
        serialHex: '0543933be386b3a2b3add534f2103bc8b65f', notBefore: '2026-09-04T14:34:32Z', notAfter: '2026-12-03T14:34:31Z',
        signature: ECDSA_SHA384, key: { kind: 'ec', curve: 'P-256' },
        sha256: '1fc4f697eefa3022d872df232293bdda7624c93964d778a53026912d9d529a53',
        subjectKeyId: '16688d1e2a32488cb5f1100a160837083b9d3023', authorityKeyId: 'b959f28ecf22f086d33748ff761418ba82d85587',
        usages: ['digitalSignature'], ca: false, pathLen: undefined, diagnostics: [],
    },
    {
        file: 'rfc8410-x25519', subject: 'CN=IETF Test Demo', issuer: 'CN=IETF Test Demo',
        serialHex: '5601474a2a8dc330', notBefore: '2016-08-01T12:19:24Z', notAfter: '2040-12-31T23:59:59Z',
        signature: '1.3.101.112', key: { kind: 'x25519' },
        sha256: '180516f0a03e4893d234a28f3ad28921bc35d1b12bd35134847240dafb715a11',
        subjectKeyId: '9b1f5eeded043385e4f7bc623c5975b90bc8bb3b', authorityKeyId: undefined,
        usages: ['keyAgreement'], ca: false, pathLen: undefined,
        diagnostics: ['PKI_DIAG_DEFAULT_ENCODED', 'PKI_DIAG_DEFAULT_ENCODED', 'PKI_DIAG_DEFAULT_ENCODED'],
    },
];

const hex = (bytes: Uint8Array | undefined): string | undefined => (bytes === undefined ? undefined : formatFingerprint(bytes, { separator: '', letterCase: 'lower' }));

describe.each(ANSWERS)('the $file fixture', (answer) => {
    const der = load(answer.file);
    const cert: Certificate = parseCertificate(der, { onDiagnostic: () => undefined });

    it('should read the names, the serial number and the validity', () => {
        expect(formatDistinguishedName(cert.subject)).toBe(answer.subject);
        expect(formatDistinguishedName(cert.issuer)).toBe(answer.issuer);
        expect(cert.serialNumber.hex).toBe(answer.serialHex);
        expect(cert.validity.notBefore.epochMilliseconds).toBe(Date.parse(answer.notBefore));
        expect(cert.validity.notAfter.epochMilliseconds).toBe(Date.parse(answer.notAfter));
    });

    it('should read the signature algorithm and the public key', () => {
        expect(cert.version).toBe(3);
        expect(cert.signatureAlgorithm.oid).toBe(answer.signature);
        expect(cert.subjectPublicKeyInfo).toMatchObject(answer.key);
    });

    it('should read the key identifiers, the key usage and the basic constraints', () => {
        expect(hex(getExtension(cert, 'subjectKeyIdentifier')?.keyIdentifier)).toBe(answer.subjectKeyId);
        expect(hex(getExtension(cert, 'authorityKeyIdentifier')?.keyIdentifier)).toBe(answer.authorityKeyId);
        expect(getExtension(cert, 'keyUsage')?.usages).toEqual(answer.usages);
        expect(getExtension(cert, 'basicConstraints')).toMatchObject({ critical: true, cA: answer.ca, pathLenConstraint: answer.pathLen });
    });

    it('should compute the SHA-256 fingerprint recorded in PROVENANCE.md', () => {
        expect(formatFingerprint(computeFingerprint(der, 'SHA-256'), { separator: '', letterCase: 'lower' })).toBe(answer.sha256);
    });

    it('should record the expected diagnostics', () => {
        expect(cert.diagnostics.map((d) => d.code)).toEqual(answer.diagnostics);
    });
});

describe('the letsencrypt.org end-entity certificate', () => {
    const cert = parseCertificate(load('letsencrypt-org-leaf'));

    it('should list its ten DNS names in order', () => {
        const names = getExtension(cert, 'subjectAltName')?.names.map((n) => (n.kind === 'dNSName' ? n.value : n.kind));
        expect(names).toEqual([
            'cp.letsencrypt.org', 'cp.root-x1.letsencrypt.org', 'cps.letsencrypt.org', 'cps.root-x1.letsencrypt.org', 'lencr.org',
            'letsencrypt.com', 'letsencrypt.org', 'www.lencr.org', 'www.letsencrypt.com', 'www.letsencrypt.org',
        ]);
    });

    it('should read its server-auth purpose, its DV policy and its access points', () => {
        expect(getExtension(cert, 'extendedKeyUsage')?.purposes).toEqual(['1.3.6.1.5.5.7.3.1']);
        expect(getExtension(cert, 'certificatePolicies')?.policies.map((p) => p.policyIdentifier)).toEqual(['2.23.140.1.2.1']);
        expect(getExtension(cert, 'authorityInfoAccess')?.descriptions).toMatchObject([
            { accessMethod: '1.3.6.1.5.5.7.48.2', accessLocation: { kind: 'uniformResourceIdentifier', value: 'http://ye2.i.lencr.org/' } },
        ]);
        expect(getExtension(cert, 'crlDistributionPoints')?.points).toMatchObject([{ fullName: [{ value: 'http://ye2.c.lencr.org/96.crl' }] }]);
    });

    it('should keep its two SCTs in their TLS encoding (RFC 6962 §3.3)', () => {
        const list = getExtension(cert, 'signedCertificateTimestampList')?.list ?? new Uint8Array(0);
        expect(((list[0] ?? 0) << 8) | (list[1] ?? 0)).toBe(list.length - 2);
    });
});

describe('the RFC 8410 §10.2 example', () => {
    it('should read the X25519 public key of the example', () => {
        const key = parseCertificate(load('rfc8410-x25519'), { onDiagnostic: () => undefined }).subjectPublicKeyInfo;
        expect(key.kind === 'x25519' ? hex(key.key) : undefined).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    });
});
