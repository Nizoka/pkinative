import { KeyObject, sign as nodeSign, webcrypto } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
    canSign,
    createCertificate,
    createCertificationRequest,
    decodeAsn1,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeKeyUsage,
    encodeSubjectAltName,
    getExtension,
    parseCertificate,
    encodeSignatureAlgorithm,
    verifyCertificateSignature,
    verifySelfSignature,
    type SignatureAlgorithm,
    type SigningKey,
} from '../../src/index.js';
import type { ExternalSigner } from '../../src/types/crypto-types.js';

/**
 * Creation, proved the only way that means anything: what pkinative writes
 * is read back by pkinative's own parser **with no diagnostic**, and its
 * signature verifies. A builder whose output its own reader diagnoses has
 * written a certificate someone else's reader will refuse.
 *
 * The keys come from `node:crypto`'s Web Crypto, never from pkinative —
 * which generates none, by construction.
 */

const CN = '2.5.4.3';
const DAY = 86_400_000;
const NOW = Date.UTC(2026, 0, 1);

interface Material { readonly signer: SigningKey; readonly spki: Uint8Array }

// `CryptoKeyPair` is a DOM global, and tsconfig.test.json carries no DOM lib
// on purpose: `src/` must compile without one. Name the shape through the
// node:crypto namespace instead of pulling in an ambient library for it.
type GeneratedPair = webcrypto.CryptoKeyPair;

async function material(keyParams: object, algorithm: SignatureAlgorithm): Promise<Material> {
    const pair = await webcrypto.subtle.generateKey(keyParams as never, true, ['sign', 'verify']) as GeneratedPair;
    return {
        signer: { key: pair.privateKey as never, algorithm },
        spki: new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey)),
    };
}

const P256 = (): Promise<Material> => material({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });

const root = (m: Material, extra?: Record<string, unknown>): Parameters<typeof createCertificate>[0] => ({
    serialNumber: 0x0123456789abcdefn,
    subject: [[{ type: CN, value: 'pkinative test root' }]],
    notBefore: NOW,
    notAfter: NOW + 365 * DAY,
    subjectPublicKey: m.spki,
    ...extra,
});

describe('createCertificate', () => {
    it.each([
        ['ECDSA P-256 / SHA-256', { name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }],
        ['ECDSA P-384 / SHA-384', { name: 'ECDSA', namedCurve: 'P-384' }, { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }],
        ['ECDSA P-521 / SHA-512', { name: 'ECDSA', namedCurve: 'P-521' }, { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }],
        ['RSA PKCS#1 v1.5 / SHA-256', { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
        ['RSASSA-PSS / SHA-256', { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, { name: 'RSA-PSS', hash: 'SHA-256' }],
        ['Ed25519', { name: 'Ed25519' }, { name: 'Ed25519' }],
    ])('should write a %s certificate that parses without a diagnostic and verifies', async (_label, keyParams, algorithm) => {
        const m = await material(keyParams, algorithm as SignatureAlgorithm);
        const der = await createCertificate(root(m), m.signer);
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });

        // No diagnostic is the real assertion. Every one of them names a
        // conformance defect real issuers commit — a DEFAULT encoded anyway,
        // a GeneralizedTime before 2050 — and this library must commit none.
        expect(cert.diagnostics.map((d) => d.code)).toEqual([]);
        expect(await verifySelfSignature(cert)).toBe(true);
    }, 30_000);

    it('should produce a v1 certificate when there are no extensions, and v3 when there are', async () => {
        const m = await P256();
        // RFC 5280 §4.1.2.1 makes version DEFAULT v1, so a v1 certificate
        // omits the field entirely; writing [0] EXPLICIT INTEGER 0 would be
        // a DER violation this library refuses to commit.
        expect(parseCertificate(await createCertificate(root(m), m.signer), { onDiagnostic: () => undefined }).version).toBe(1);
        const withExtension = await createCertificate(root(m, {
            extensions: [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) }],
        }), m.signer);
        expect(parseCertificate(withExtension, { onDiagnostic: () => undefined }).version).toBe(3);
    });

    it('should carry every field the description gave', async () => {
        const m = await P256();
        const der = await createCertificate(root(m, {
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true, pathLenConstraint: 1 }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
                { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'root.example' }]) },
            ],
        }), m.signer);
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });

        expect(cert.serialNumber.value).toBe(0x0123456789abcdefn);
        expect(cert.validity.notBefore.epochMilliseconds).toBe(NOW);
        expect(cert.validity.notAfter.epochMilliseconds).toBe(NOW + 365 * DAY);
        expect(getExtension(cert, 'basicConstraints')).toMatchObject({ cA: true, pathLenConstraint: 1 });
        expect(getExtension(cert, 'keyUsage')?.usages).toEqual(['keyCertSign', 'cRLSign']);
        expect(getExtension(cert, 'subjectAltName')?.names[0]).toMatchObject({ kind: 'dNSName', value: 'root.example' });
    });

    it('should make the two signatureAlgorithm fields byte-identical', async () => {
        const m = await P256();
        const cert = parseCertificate(await createCertificate(root(m), m.signer), { onDiagnostic: () => undefined });
        // RFC 5280 §4.1.1.2 requires it, and only the inner one is signed —
        // so a builder that lets them drift produces a certificate a strict
        // verifier answers `false` for.
        expect(Array.from(cert.signatureAlgorithm.der)).toEqual(Array.from(cert.tbsSignatureAlgorithm.der));
    });

    it('should self-issue when no issuer is named, and chain when one is', async () => {
        const ca = await P256();
        const leaf = await material({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        const caCert = parseCertificate(await createCertificate(root(ca), ca.signer), { onDiagnostic: () => undefined });
        expect(Array.from(caCert.issuer.der)).toEqual(Array.from(caCert.subject.der));

        // The issuer name comes from the CA's own bytes, which is the whole
        // reason issuerDer exists: a name re-encoded from decoded attributes
        // does not always reproduce them.
        const leafDer = await createCertificate({
            serialNumber: 2n,
            issuerDer: caCert.subject.der,
            subject: [[{ type: CN, value: 'leaf.example' }]],
            notBefore: NOW,
            notAfter: NOW + 90 * DAY,
            subjectPublicKey: leaf.spki,
        }, ca.signer);
        const leafCert = parseCertificate(leafDer, { onDiagnostic: () => undefined });

        expect(await verifyCertificateSignature(leafCert, caCert)).toBe(true);
        expect(await verifySelfSignature(leafCert)).toBe(false);
    });

    it('should accept a described issuer name when there is no certificate to copy', async () => {
        const m = await P256();
        const cert = parseCertificate(await createCertificate(root(m, {
            issuer: [[{ type: CN, value: 'Another Root' }]],
        }), m.signer), { onDiagnostic: () => undefined });
        expect(Array.from(cert.issuer.der)).toEqual(Array.from(encodeDistinguishedName([[{ type: CN, value: 'Another Root' }]])));
    });

    it('should accept a subject given as DER', async () => {
        const m = await P256();
        const subjectDer = encodeDistinguishedName([[{ type: CN, value: 'From DER' }]]);
        const cert = parseCertificate(await createCertificate(root(m, { subjectDer }), m.signer), { onDiagnostic: () => undefined });
        expect(Array.from(cert.subject.der)).toEqual(Array.from(subjectDer));
    });

    it('should take a serial as content octets as well as a bigint', async () => {
        const m = await P256();
        const cert = parseCertificate(await createCertificate(root(m, {
            serialNumber: Uint8Array.of(0x00, 0xff, 0x01),
        }), m.signer), { onDiagnostic: () => undefined });
        expect(cert.serialNumber.hex).toBe('00ff01');
    });

    it('should refuse a negative serial, which most relying parties reject', async () => {
        const m = await P256();
        await expect(createCertificate(root(m, { serialNumber: -1n }), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('positive') }));
    });

    // C-05: RFC 5280 §4.1.2.2 — positive, at most 20 content octets; the
    // builder never writes a bigint serial its own parser diagnoses.
    it.each([
        { name: 'zero', serial: 0n },
        { name: '2^159, whose sign octet makes 21 content octets', serial: 2n ** 159n },
        { name: '2^160', serial: 2n ** 160n },
    ])('should refuse a bigint serial of $name', async ({ serial }) => {
        const m = await P256();
        await expect(createCertificate(root(m, { serialNumber: serial }), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it.each([
        { name: '1', serial: 1n, octets: 1 },
        { name: '2^159 − 1, the largest that fits in 20 octets', serial: 2n ** 159n - 1n, octets: 20 },
        { name: '2^151, whose high bit needs the sign octet', serial: 2n ** 151n, octets: 20 },
    ])('should write a bigint serial of $name, which reads back with no diagnostic', async ({ serial, octets }) => {
        const m = await P256();
        const codes: string[] = [];
        const cert = parseCertificate(await createCertificate(root(m, { serialNumber: serial }), m.signer), { onDiagnostic: (d) => { codes.push(d.code); } });
        expect(cert.serialNumber.hex.length / 2).toBe(octets);
        expect(codes.filter((c) => c.startsWith('PKI_DIAG_SERIAL_'))).toEqual([]);
    });

    it('should carry a negative serial given as octets, and let the parser diagnose it', async () => {
        // The byte form exists to reproduce an existing serial exactly, so a
        // non-conforming one goes through — and comes back as a diagnostic,
        // not as a refusal. Throw or diagnose, never both.
        const m = await P256();
        const codes: string[] = [];
        const cert = parseCertificate(await createCertificate(root(m, {
            serialNumber: Uint8Array.of(0x80, 0x01),
        }), m.signer), { onDiagnostic: (d) => { codes.push(d.code); } });
        expect(cert.serialNumber.hex).toBe('8001');
        expect(codes).toContain('PKI_DIAG_SERIAL_NOT_POSITIVE');
    });

    it.each([
        { name: 'empty', serial: new Uint8Array(0), says: 'at least one content octet' },
        { name: 'a redundant 0x00', serial: Uint8Array.of(0x00, 0x01), says: 'shortest form' },
        { name: 'a redundant 0xff', serial: Uint8Array.of(0xff, 0x80), says: 'shortest form' },
        { name: 'a redundant 0x00 before 0x7f', serial: Uint8Array.of(0x00, 0x7f), says: 'shortest form' },
    ])('should refuse serial octets no INTEGER can hold: $name', async ({ serial, says }) => {
        // Without this, createCertificate produces a certificate that
        // pkinative's own decoder refuses with PKI_ASN1_INTEGER_INVALID.
        const m = await P256();
        await expect(createCertificate(root(m, { serialNumber: serial }), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining(says) }));
    });

    it.each([
        { name: '0x00 before a high bit', serial: Uint8Array.of(0x00, 0x80), hex: '0080' },
        { name: '0xff before a clear bit', serial: Uint8Array.of(0xff, 0x7f), hex: 'ff7f' },
    ])('should keep a leading octet the sign needs: $name', async ({ serial, hex }) => {
        const m = await P256();
        const cert = parseCertificate(await createCertificate(root(m, { serialNumber: serial }), m.signer), { onDiagnostic: () => undefined });
        expect(cert.serialNumber.hex).toBe(hex);
    });

    it('should pass its limits down to the name and the extensions', async () => {
        const m = await P256();
        await expect(createCertificate(root(m, {
            subject: [[{ type: CN, value: 'a' }], [{ type: CN, value: 'b' }]],
        }), m.signer, { limits: { maxNameAttributes: 1 } }))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxNameAttributes' }));
    });

    it('should refuse a subjectPublicKey that is not bytes', async () => {
        const m = await P256();
        await expect(createCertificate(root(m, { subjectPublicKey: 'spki' }), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

describe('encodeSignatureAlgorithm', () => {
    it('should write RSASSA-PSS parameters a verifier reads back unchanged', async () => {
        const m = await material(
            { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
            { name: 'RSA-PSS', hash: 'SHA-256' },
        );
        const cert = parseCertificate(await createCertificate(root(m), m.signer), { onDiagnostic: () => undefined });
        // The salt length defaults to the digest size, not to the grammar's
        // DEFAULT of 20 — and it round-trips, which is what makes the
        // signature check out.
        expect(cert.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.10');
        expect(await verifySelfSignature(cert)).toBe(true);
    }, 30_000);

    it.each<['SHA-256' | 'SHA-384' | 'SHA-512', string]>([
        // CA/Browser Forum BR v2.3.0 §7.1.3.2.1: "the AlgorithmIdentifier
        // MUST be byte-for-byte identical with the specified hex-encoded
        // bytes" — the digest and MGF1 digest each with an explicit NULL.
        ['SHA-256', '304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120'],
        ['SHA-384', '304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130'],
        ['SHA-512', '304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140'],
    ])('should write the RSASSA-PSS / %s identifier byte for byte as the CA/Browser Forum requires', (hash, expected) => {
        const der = encodeSignatureAlgorithm({ key: {} as never, algorithm: { name: 'RSA-PSS', hash } });
        expect(Array.from(der, (b) => b.toString(16).padStart(2, '0')).join('')).toBe(expected);
    });

    it('should honour an explicit salt length', async () => {
        const der = encodeSignatureAlgorithm({ key: {} as never, algorithm: { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 48 } });
        const params = decodeAsn1(der).children[1];
        const salt = params?.children.find((c) => c.tagNumber === 2)?.children[0];
        expect(salt?.content[0]).toBe(48);
    });

    it('should accept a salt length of zero, which RFC 4055 allows', () => {
        const der = encodeSignatureAlgorithm({ key: {} as never, algorithm: { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 0 } });
        const salt = decodeAsn1(der).children[1]?.children.find((c) => c.tagNumber === 2)?.children[0];
        expect(salt?.content[0]).toBe(0);
    });

    it('should refuse a negative salt length', () => {
        expect(() => encodeSignatureAlgorithm({ key: {} as never, algorithm: { name: 'RSA-PSS', hash: 'SHA-256', saltLength: -1 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
    });

    it('should refuse a digest with no RFC 5280 OID', () => {
        expect(() => encodeSignatureAlgorithm({ key: {} as never, algorithm: { name: 'RSA-PSS', hash: 'SHA-3' as never } }))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
        expect(() => encodeSignatureAlgorithm({ key: {} as never, algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-3' as never } }))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
    });
});

describe('the documented name, written with every default', () => {
    // The NameDescription TSDoc example, with no stringType anywhere: what a
    // caller who reads the documentation and nothing else will write.
    // RFC 5280 Appendix A.1 makes countryName a PrintableString (SIZE (2));
    // written as a UTF8String, pkilint refuses the name outright.
    const EXAMPLE = [[{ type: '2.5.4.6', value: 'US' }], [{ type: '2.5.4.3', value: 'Example CA' }]];
    const tags = (nameNode: ReturnType<typeof decodeAsn1> | undefined): number[] =>
        (nameNode?.children ?? []).map((rdn) => rdn.children[0]?.children[1]?.tagNumber ?? -1);

    it('should write countryName as PrintableString and commonName as UTF8String in a certificate, and read back with no diagnostic', async () => {
        const m = await P256();
        const seen: string[] = [];
        const cert = parseCertificate(await createCertificate(root(m, { subject: EXAMPLE }), m.signer), { onDiagnostic: (d) => { seen.push(d.code); } });
        expect(tags(decodeAsn1(cert.subject.der))).toEqual([0x13, 0x0c]);
        expect(tags(decodeAsn1(cert.issuer.der))).toEqual([0x13, 0x0c]);
        expect(seen.filter((code) => code === 'PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE' || code === 'PKI_DIAG_COUNTRY_NAME_SIZE')).toEqual([]);
    });

    it('should write the same name the same way in a certification request', async () => {
        const m = await P256();
        const info = decodeAsn1(await createCertificationRequest({ subject: EXAMPLE, subjectPublicKey: m.spki }, m.signer)).children[0];
        expect(tags(info?.children[1])).toEqual([0x13, 0x0c]);
    });

    it('should refuse a countryName of three letters before signing anything', async () => {
        const m = await P256();
        await expect(createCertificate(root(m, { subject: [[{ type: '2.5.4.6', value: 'USA' }]] }), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('ISO 3166') }));
        await expect(createCertificationRequest({ subject: [[{ type: '2.5.4.6', value: 'USA' }]], subjectPublicKey: m.spki }, m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });
});

describe('createCertificationRequest', () => {
    it('should write a request whose signature verifies against the key it carries', async () => {
        const m = await P256();
        const csr = await createCertificationRequest({
            subject: [[{ type: CN, value: 'host.example' }]],
            subjectPublicKey: m.spki,
        }, m.signer);

        // A CSR is a proof of possession. Verify it the way a CA does:
        // import the key it carries, and check the signature over
        // certificationRequestInfo.
        const node = decodeAsn1(csr);
        const info = node.children[0];
        const signature = node.children[2];
        expect(info).toBeDefined();
        const key = await webcrypto.subtle.importKey('spki', m.spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        const raw = rawFromDer(signature?.content.subarray(1) ?? new Uint8Array(0));
        expect(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, info?.bytes ?? new Uint8Array(0))).toBe(true);
    });

    it('should always write the attributes field, present but empty', async () => {
        const m = await P256();
        const info = decodeAsn1(await createCertificationRequest({
            subject: [[{ type: CN, value: 'host.example' }]],
            subjectPublicKey: m.spki,
        }, m.signer)).children[0];
        // RFC 2986 makes it [0] IMPLICIT SET OF, not OPTIONAL: an empty SET
        // is not the same as an absent field, and OpenSSL refuses a request
        // that omits it.
        const attributes = info?.children[3];
        expect(attributes?.tagClass).toBe('context');
        expect(attributes?.tagNumber).toBe(0);
        expect(attributes?.constructed).toBe(true);
        expect(attributes?.contentLength).toBe(0);
    });

    it('should carry requested extensions inside the extensionRequest attribute', async () => {
        const m = await P256();
        const info = decodeAsn1(await createCertificationRequest({
            subject: [[{ type: CN, value: 'host.example' }]],
            subjectPublicKey: m.spki,
            extensions: [{ oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }]) }],
        }, m.signer)).children[0];
        const attribute = info?.children[3]?.children[0];
        expect(attribute?.children[0]?.bytes).toBeDefined();
        expect(info?.children[3]?.contentLength).toBeGreaterThan(0);
    });

    it('should accept a subject given as DER, and refuse a key that is not bytes', async () => {
        const m = await P256();
        const subjectDer = encodeDistinguishedName([[{ type: CN, value: 'From DER' }]]);
        await expect(createCertificationRequest({ subject: [], subjectDer, subjectPublicKey: m.spki }, m.signer)).resolves.toBeInstanceOf(Uint8Array);
        await expect(createCertificationRequest({ subject: [[{ type: CN, value: 'a' }]], subjectPublicKey: 'x' as never }, m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should pass its limits down', async () => {
        const m = await P256();
        await expect(createCertificationRequest({
            subject: [[{ type: CN, value: 'a' }], [{ type: CN, value: 'b' }]],
            subjectPublicKey: m.spki,
        }, m.signer, { limits: { maxNameAttributes: 1 } }))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED' }));
    });
});

describe('an ExternalSigner', () => {
    /** A key pkinative never sees, signing through node:crypto as an HSM binding would. */
    async function held(keyParams: object, algorithm: SignatureAlgorithm, digest: string | null): Promise<{ readonly signer: ExternalSigner; readonly spki: Uint8Array; readonly calls: Uint8Array[] }> {
        const pair = await webcrypto.subtle.generateKey(keyParams as never, true, ['sign', 'verify']) as GeneratedPair;
        const key = KeyObject.from(pair.privateKey);
        const calls: Uint8Array[] = [];
        return {
            signer: {
                algorithm,
                produceSignature: (data) => {
                    calls.push(data);
                    return new Uint8Array(nodeSign(digest, data, { key, dsaEncoding: 'ieee-p1363' }));
                },
            },
            spki: new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey)),
            calls,
        };
    }

    it.each([
        ['ECDSA P-384', { name: 'ECDSA', namedCurve: 'P-384' }, { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }, 'sha384'],
        ['RSA PKCS#1 v1.5', { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, 'sha256'],
        ['Ed25519', { name: 'Ed25519' }, { name: 'Ed25519' }, null],
    ] as const)('should sign a %s certificate with a key held elsewhere, over exactly tbsCertificate', async (_label, keyParams, algorithm, digest) => {
        const h = await held(keyParams, algorithm as SignatureAlgorithm, digest);
        const cert = parseCertificate(await createCertificate({
            serialNumber: 1n,
            subject: [[{ type: CN, value: 'held elsewhere' }]],
            notBefore: NOW,
            notAfter: NOW + DAY,
            subjectPublicKey: h.spki,
        }, h.signer), { onDiagnostic: () => undefined });
        expect(cert.diagnostics).toEqual([]);
        expect(await verifySelfSignature(cert)).toBe(true);
        expect(h.calls).toHaveLength(1);
        expect(Array.from(h.calls[0] ?? [])).toEqual(Array.from(cert.tbsDer));
    }, 30_000);

    it('should sign a request with an asynchronous signer', async () => {
        const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as GeneratedPair;
        const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
        const csr = await createCertificationRequest({ subject: [[{ type: CN, value: 'host.example' }]], subjectPublicKey: spki }, {
            algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
            produceSignature: async (data) => new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data)),
        });
        const node = decodeAsn1(csr);
        const raw = rawFromDer(node.children[2]?.content.subarray(1) ?? new Uint8Array(0));
        expect(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, raw, node.children[0]?.bytes ?? new Uint8Array(0))).toBe(true);
    });

    it('should refuse an ECDSA signature returned as DER, naming the length it expected', async () => {
        const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as GeneratedPair;
        const key = KeyObject.from(pair.privateKey);
        await expect(createCertificationRequest({ subject: [[{ type: CN, value: 'a' }]], subjectPublicKey: new Uint8Array(0) }, {
            algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
            produceSignature: (data) => new Uint8Array(nodeSign('sha256', data, key)),
        })).rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('exactly 64 octets') }));
    });

    it.each([
        ['an Int8Array', new Int8Array(64)],
        ['a DataView', new DataView(new ArrayBuffer(64))],
    ])('should refuse a signature returned as %s rather than a Uint8Array', async (_what, produced) => {
        await expect(createCertificationRequest({ subject: [[{ type: CN, value: 'a' }]], subjectPublicKey: new Uint8Array(0) }, {
            algorithm: { name: 'Ed25519' },
            produceSignature: () => produced as unknown as Uint8Array,
        })).rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('non-empty Uint8Array') }));
    });

    it('should let an error the signer throws reach the caller unchanged', async () => {
        const failure = new Error('HSM offline');
        await expect(createCertificationRequest({ subject: [[{ type: CN, value: 'a' }]], subjectPublicKey: new Uint8Array(0) }, {
            algorithm: { name: 'Ed25519' },
            produceSignature: () => Promise.reject(failure),
        })).rejects.toBe(failure);
    });
});

describe('a runtime that cannot sign', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    afterEach(() => {
        if (original !== undefined) Object.defineProperty(globalThis, 'crypto', original);
    });

    it('should report it, and say so with a code rather than fail deeper', async () => {
        const m = await P256();
        expect(canSign()).toBe(true);
        Object.defineProperty(globalThis, 'crypto', { value: { subtle: {} }, configurable: true, writable: true });
        expect(canSign()).toBe(false);
        await expect(createCertificate(root(m), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_UNAVAILABLE' }));
    });

    it('should report a host that refuses the key as PKI_CRYPTO_KEY_UNSUPPORTED', async () => {
        const m = await P256();
        Object.defineProperty(globalThis, 'crypto', {
            configurable: true,
            writable: true,
            value: { subtle: { sign: (): Promise<never> => Promise.reject(new Error('no sign usage')) } },
        });
        await expect(createCertificate(root(m), m.signer))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' }));
    });
});

/** The converter under test elsewhere, inlined so this suite verifies independently. */
function rawFromDer(der: Uint8Array): Uint8Array {
    let at = der[1] === 0x81 ? 3 : 2;
    const read = (): Uint8Array => {
        const length = der[at + 1] ?? 0;
        const start = at + 2;
        at = start + length;
        const value = der.subarray(start, at);
        return value[0] === 0x00 ? value.subarray(1) : value;
    };
    const r = read();
    const s = read();
    const raw = new Uint8Array(64);
    raw.set(r, 32 - r.length);
    raw.set(s, 64 - s.length);
    return raw;
}
