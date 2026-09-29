import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeSubjectKeyIdentifier } from '../../src/build/build-structures.js';
import {
    _describeSid,
    _digestReason,
    _signerAttributeReasons,
    _signerCandidates,
    _signingCertificateReason,
} from '../../src/cms/cms-check.js';
import * as oids from '../../src/core/cms-oids.js';
import type { Attribute, SignedData, SignerInfo, SigningCertificateAttribute } from '../../src/types/cms-types.js';
import type { AlgorithmIdentifier, Certificate, GeneralName } from '../../src/types/x509-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { ascii, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * The rules on a signer's attributes — the half of CMS verification that
 * needs no key.
 *
 * Every case here is a way a genuine signature gets believed about the wrong
 * thing: attributes that name no content, a content type swapped under them, a
 * digest the verifier trusted instead of computing, a signature presented
 * under another certificate for the same key, an algorithm the signer never
 * chose. Each is built as a plain SignerInfo value, so that the rule is tested
 * alone and not through a parser that might already have refused the input.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const AT = Date.UTC(2026, 8, 1);
const DAY = 86_400_000;
const CN = universal(6, [0x55, 0x04, 0x03]);
const nameOf = (value: string): Uint8Array => sequence(universal(17, sequence(CN, universal(12, ascii(value))), true));

const SHA256: AlgorithmIdentifier = algorithm('2.16.840.1.101.3.4.2.1', undefined);
const SHA256_NULL: AlgorithmIdentifier = algorithm('2.16.840.1.101.3.4.2.1', Uint8Array.of(0x05, 0x00));
const SHA384: AlgorithmIdentifier = algorithm('2.16.840.1.101.3.4.2.2', undefined);
const ECDSA_SHA256: AlgorithmIdentifier = algorithm('1.2.840.10045.4.3.2', undefined);

function algorithm(oid: string, parameters: Uint8Array | undefined): AlgorithmIdentifier {
    // Only oid and parameters.bytes are read by the rules under test.
    return { oid, parameters: parameters === undefined ? undefined : { bytes: parameters }, der: new Uint8Array(0) } as unknown as AlgorithmIdentifier;
}

const attribute = (oid: string, ...values: readonly Uint8Array[]): Attribute => ({ oid, values, der: new Uint8Array(0) });
const oidValue = (...content: readonly number[]): Uint8Array => universal(6, content);
const ID_DATA = oidValue(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01);

async function certificate(options: { serial?: bigint; issuer?: string; ski?: Uint8Array } = {}): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificate({
        serialNumber: options.serial ?? 7n,
        issuerDer: nameOf(options.issuer ?? 'Example CA'),
        subject: [[{ type: '2.5.4.3', value: 'signer.example' }]],
        notBefore: AT - DAY,
        notAfter: AT + DAY,
        subjectPublicKey: spki,
        extensions: options.ski === undefined ? [] : [{ oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(options.ski) }],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

const SIGNER_CERT = await certificate({ ski: Uint8Array.of(1, 2, 3, 4) });
const OTHER_CERT = await certificate({ serial: 8n });

function signer(overrides: Partial<SignerInfo> = {}): SignerInfo {
    const signed = [
        attribute(oids.OID_ATTR_CONTENT_TYPE, ID_DATA),
        attribute(oids.OID_ATTR_MESSAGE_DIGEST, universal(4, new Array<number>(32).fill(0xaa))),
    ];
    return {
        version: 1,
        sid: { kind: 'issuerAndSerialNumber', issuer: SIGNER_CERT.issuer, serialNumber: SIGNER_CERT.serialNumber },
        digestAlgorithm: SHA256,
        signedAttributes: signed,
        signedAttributesDer: new Uint8Array(0),
        signatureAlgorithm: ECDSA_SHA256,
        signature: new Uint8Array(0),
        unsignedAttributes: undefined,
        contentType: oids.OID_DATA,
        messageDigest: new Uint8Array(32).fill(0xaa),
        signingTime: undefined,
        signingCertificate: undefined,
        algorithmProtection: undefined,
        timeStampTokens: [],
        der: new Uint8Array(0),
        ...overrides,
    };
}

const DATA: SignedData = {
    der: new Uint8Array(0),
    version: 1,
    digestAlgorithms: [SHA256],
    contentType: oids.OID_DATA,
    content: undefined,
    certificates: [],
    crls: [],
    ocspResponses: [],
    signerInfos: [],
    diagnostics: [],
};

const codes = (reasons: readonly { code: string }[]): string[] => reasons.map((reason) => reason.code);

describe('_signerCandidates', () => {
    it('should select by issuer and serial, compared as bytes', () => {
        expect(_signerCandidates(signer().sid, [OTHER_CERT, SIGNER_CERT])).toEqual([SIGNER_CERT]);
    });

    it('should select by the subjectKeyIdentifier extension, never by a hash of the key', () => {
        const sid = { kind: 'subjectKeyIdentifier', keyIdentifier: Uint8Array.of(1, 2, 3, 4) } as const;
        expect(_signerCandidates(sid, [OTHER_CERT, SIGNER_CERT])).toEqual([SIGNER_CERT]);
        expect(_signerCandidates({ ...sid, keyIdentifier: Uint8Array.of(9) }, [SIGNER_CERT])).toEqual([]);
    });

    it('should offer each certificate once, however often the bag repeats it', () => {
        expect(_signerCandidates(signer().sid, [SIGNER_CERT, SIGNER_CERT])).toHaveLength(1);
    });

    it('should describe either kind of identifier for a person to read', () => {
        expect(_describeSid(signer().sid)).toContain('serial 07');
        expect(_describeSid({ kind: 'subjectKeyIdentifier', keyIdentifier: Uint8Array.of(0xab) })).toBe('subjectKeyIdentifier ab');
    });

    it('should abbreviate the issuer to its first 16 octets, from the first one', () => {
        const issuerHex = Buffer.from(SIGNER_CERT.issuer.der).toString('hex');
        expect(issuerHex.length).toBeGreaterThan(32);
        expect(_describeSid(signer().sid)).toBe(`issuer ${issuerHex.slice(0, 32)}…, serial 07`);
    });
});

describe('_signerAttributeReasons', () => {
    it('should find nothing wrong with contentType and messageDigest present once each', () => {
        expect(_signerAttributeReasons(DATA, signer(), 'signerInfos[0]')).toEqual([]);
    });

    it('should allow a signer of id-data without signed attributes', () => {
        expect(_signerAttributeReasons(DATA, signer({ signedAttributes: undefined, contentType: undefined, messageDigest: undefined }), 's')).toEqual([]);
    });

    it('should require signed attributes for any other content type', () => {
        // Without them the signature covers octets and nothing says what they
        // were meant to be — the opening a content-type confusion walks through.
        const reasons = _signerAttributeReasons({ ...DATA, contentType: oids.OID_TST_INFO }, signer({ signedAttributes: undefined }), 's');
        expect(codes(reasons)).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
    });

    it('should require a contentType attribute', () => {
        const reasons = _signerAttributeReasons(DATA, signer({ signedAttributes: [attribute(oids.OID_ATTR_MESSAGE_DIGEST, universal(4, [1]))] }), 's');
        expect(codes(reasons)).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
        expect(reasons[0]?.path).toBe('s.signedAttrs.contentType');
    });

    it('should require a messageDigest attribute, without which the signature binds no content', () => {
        const reasons = _signerAttributeReasons(DATA, signer({ signedAttributes: [attribute(oids.OID_ATTR_CONTENT_TYPE, ID_DATA)] }), 's');
        expect(reasons.map((reason) => reason.path)).toEqual(['s.signedAttrs.messageDigest']);
    });

    it('should refuse a contentType that names another type than the content', () => {
        const reasons = _signerAttributeReasons(DATA, signer({ contentType: oids.OID_TST_INFO }), 's');
        expect(codes(reasons)).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
    });

    it('should refuse a repeated messageDigest, which is not a slip but the shape of an attack', () => {
        const twice = [...(signer().signedAttributes ?? []), attribute(oids.OID_ATTR_MESSAGE_DIGEST, universal(4, [2]))];
        expect(codes(_signerAttributeReasons(DATA, signer({ signedAttributes: twice, messageDigest: undefined }), 's'))).toContain('PKI_REASON_CMS_ATTRIBUTE_INVALID');
    });

    it('should refuse a contentType holding two values', () => {
        const attrs = [attribute(oids.OID_ATTR_CONTENT_TYPE, ID_DATA, ID_DATA), attribute(oids.OID_ATTR_MESSAGE_DIGEST, universal(4, [1]))];
        expect(codes(_signerAttributeReasons(DATA, signer({ signedAttributes: attrs, contentType: undefined }), 's'))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
    });

    it('should refuse an attribute that means something only when signed, found unsigned', () => {
        const unsigned = [attribute(oids.OID_ATTR_MESSAGE_DIGEST, universal(4, [1]))];
        expect(codes(_signerAttributeReasons(DATA, signer({ unsignedAttributes: unsigned }), 's'))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
        // …whether or not the signer has signed attributes at all.
        expect(codes(_signerAttributeReasons(DATA, signer({ signedAttributes: undefined, unsignedAttributes: unsigned }), 's'))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
    });

    it('should let a timestamp token and a countersignature sit unsigned, where they belong', () => {
        const unsigned = [attribute(oids.OID_ATTR_TIMESTAMP_TOKEN, sequence()), attribute(oids.OID_ATTR_COUNTERSIGNATURE, sequence())];
        expect(_signerAttributeReasons(DATA, signer({ unsignedAttributes: unsigned }), 's')).toEqual([]);
    });

    it('should refuse a countersignature among the signed attributes', () => {
        const attrs = [...(signer().signedAttributes ?? []), attribute(oids.OID_ATTR_COUNTERSIGNATURE, sequence())];
        expect(codes(_signerAttributeReasons(DATA, signer({ signedAttributes: attrs }), 's'))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
    });

    describe('CMSAlgorithmProtection (RFC 6211)', () => {
        // The parser decodes the attribute, and refuses a malformed one; what
        // reaches this rule is a well-formed protection to compare.
        const protectedBy = (digestAlgorithm: AlgorithmIdentifier, signatureAlgorithm: AlgorithmIdentifier, extra: Partial<SignerInfo> = {}): SignerInfo =>
            signer({
                signedAttributes: [...(signer().signedAttributes ?? []), attribute(oids.OID_ATTR_ALGORITHM_PROTECTION, sequence())],
                algorithmProtection: { digestAlgorithm, signatureAlgorithm },
                ...extra,
            });

        it('should accept a protection that agrees with the algorithms outside the signature', () => {
            expect(_signerAttributeReasons(DATA, protectedBy(SHA256, ECDSA_SHA256), 's')).toEqual([]);
        });

        it('should compare modulo encoding: absent and NULL parameters are one SHA-2 algorithm', () => {
            expect(_signerAttributeReasons(DATA, protectedBy(SHA256_NULL, ECDSA_SHA256), 's')).toEqual([]);
            expect(_signerAttributeReasons(DATA, protectedBy(SHA256, ECDSA_SHA256, { digestAlgorithm: SHA256_NULL }), 's')).toEqual([]);
        });

        it('should refuse a digest the signer did not protect', () => {
            // The unsigned digestAlgorithm rewritten under a genuine signature:
            // exactly what RFC 6211 was written to catch.
            expect(codes(_signerAttributeReasons(DATA, protectedBy(SHA384, ECDSA_SHA256), 's'))).toEqual(['PKI_REASON_CMS_ALGORITHM_MISMATCH']);
        });

        it('should refuse a signature algorithm the signer did not protect', () => {
            const ecdsaSha384 = algorithm('1.2.840.10045.4.3.3', undefined);
            expect(codes(_signerAttributeReasons(DATA, protectedBy(SHA256, ecdsaSha384), 's'))).toEqual(['PKI_REASON_CMS_ALGORITHM_MISMATCH']);
        });

        it('should compare parameters as bytes when both sides carry them', () => {
            // RSASSA-PSS is the case that matters: its parameters are the whole
            // algorithm, and they must be the ones the signer protected.
            const pss = algorithm('1.2.840.113549.1.1.10', universal(4, [1, 2]));
            const other = algorithm('1.2.840.113549.1.1.10', universal(4, [9]));
            expect(_signerAttributeReasons(DATA, protectedBy(SHA256, pss, { signatureAlgorithm: pss }), 's')).toEqual([]);
            expect(codes(_signerAttributeReasons(DATA, protectedBy(SHA256, other, { signatureAlgorithm: pss }), 's'))).toEqual(['PKI_REASON_CMS_ALGORITHM_MISMATCH']);
        });

        it('should refuse parameters on one side only, unless they are a digest\'s NULL', () => {
            const withParams = algorithm('2.16.840.1.101.3.4.2.1', universal(4, [1]));
            expect(codes(_signerAttributeReasons(DATA, protectedBy(withParams, ECDSA_SHA256), 's'))).toEqual(['PKI_REASON_CMS_ALGORITHM_MISMATCH']);
        });

        it('should leave a repeated protection to the multiplicity rule, and report it once', () => {
            const attrs = [...(signer().signedAttributes ?? []), attribute(oids.OID_ATTR_ALGORITHM_PROTECTION, sequence()), attribute(oids.OID_ATTR_ALGORITHM_PROTECTION, sequence())];
            expect(codes(_signerAttributeReasons(DATA, signer({ signedAttributes: attrs }), 's'))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
        });

        it('should require the protection only when asked to', () => {
            expect(_signerAttributeReasons(DATA, signer(), 's')).toEqual([]);
            expect(codes(_signerAttributeReasons(DATA, signer(), 's', { requireAlgorithmProtection: true }))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
        });
    });
});

describe('_digestReason', () => {
    it('should accept the digest the signer committed to', () => {
        expect(_digestReason(signer(), new Uint8Array(32).fill(0xaa), 's')).toBeNull();
    });

    it('should refuse any other', () => {
        expect(_digestReason(signer(), new Uint8Array(32).fill(0xbb), 's')?.code).toBe('PKI_REASON_CMS_DIGEST_MISMATCH');
    });

    it('should have nothing to compare without a committed digest or a computed one', () => {
        expect(_digestReason(signer({ messageDigest: undefined }), new Uint8Array(32), 's')).toBeNull();
        expect(_digestReason(signer(), undefined, 's')).toBeNull();
    });
});

describe('_signingCertificateReason', () => {
    const directory = (certificate: Certificate): GeneralName => ({ kind: 'directoryName', name: certificate.issuer, der: new Uint8Array(0) });
    const hashOf = (algorithm: string, der: Uint8Array): Uint8Array => new Uint8Array(createHash(algorithm).update(der).digest());

    function binding(overrides: Partial<SigningCertificateAttribute['certIds'][number]> = {}, version: 1 | 2 = 2): SigningCertificateAttribute {
        return {
            version,
            certIds: [{
                hashAlgorithm: 'SHA-256',
                certHash: hashOf('sha256', SIGNER_CERT.der),
                issuerSerial: { issuer: [directory(SIGNER_CERT)], serialNumber: SIGNER_CERT.serialNumber },
                ...overrides,
            }],
        };
    }

    it('should have nothing to say when the signer made no binding', () => {
        expect(_signingCertificateReason(signer(), SIGNER_CERT, 's')).toBeNull();
    });

    it('should accept the certificate the signer committed to', () => {
        expect(_signingCertificateReason(signer({ signingCertificate: binding() }), SIGNER_CERT, 's')).toBeNull();
        expect(_signingCertificateReason(signer({ signingCertificate: binding({ issuerSerial: undefined }) }), SIGNER_CERT, 's')).toBeNull();
    });

    it.each([
        ['SHA-1', 'sha1'],
        ['SHA-384', 'sha384'],
        ['SHA-512', 'sha512'],
    ])('should compute the certificate hash with %s when the attribute names it', (name, node) => {
        const attr = binding({ hashAlgorithm: name, certHash: hashOf(node, SIGNER_CERT.der) }, name === 'SHA-1' ? 1 : 2);
        expect(_signingCertificateReason(signer({ signingCertificate: attr }), SIGNER_CERT, 's')).toBeNull();
    });

    it('should refuse another certificate for the same signature', () => {
        const reason = _signingCertificateReason(signer({ signingCertificate: binding() }), OTHER_CERT, 's');
        expect(reason?.code).toBe('PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH');
        expect(reason?.path).toBe('s.signedAttrs.signingCertificateV2');
    });

    it('should fail closed on a digest it does not compute', () => {
        const reason = _signingCertificateReason(signer({ signingCertificate: binding({ hashAlgorithm: '2.16.840.1.101.3.4.2.4' }, 1) }), SIGNER_CERT, 's');
        expect(reason?.code).toBe('PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH');
        expect(reason?.path).toBe('s.signedAttrs.signingCertificate');
    });

    it('should refuse an attribute that names no certificate', () => {
        expect(_signingCertificateReason(signer({ signingCertificate: { version: 2, certIds: [] } }), SIGNER_CERT, 's')?.code)
            .toBe('PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH');
    });

    it.each([
        ['another issuer', (): GeneralName[] => [directory(OTHER_CERT), directory(OTHER_CERT)]],
        ['a URI for an issuer', (): GeneralName[] => [{ kind: 'uniformResourceIdentifier', value: 'https://ca.example', der: new Uint8Array(0) }]],
        ['no issuer at all', (): GeneralName[] => []],
    ])('should refuse an issuerSerial naming %s', (_, issuer) => {
        const attr = binding({ issuerSerial: { issuer: issuer(), serialNumber: SIGNER_CERT.serialNumber } });
        expect(_signingCertificateReason(signer({ signingCertificate: attr }), SIGNER_CERT, 's')?.code).toBe('PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH');
    });

    it('should refuse an issuerSerial naming another serial', () => {
        const attr = binding({ issuerSerial: { issuer: [directory(SIGNER_CERT)], serialNumber: OTHER_CERT.serialNumber } });
        expect(_signingCertificateReason(signer({ signingCertificate: attr }), SIGNER_CERT, 's')?.code).toBe('PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH');
    });
});
