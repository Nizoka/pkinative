import { describe, expect, it } from 'vitest';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import { PkiCmsError, PkiError } from '../../src/types/pki-errors.js';
import type { ParseSignedDataOptions, SignerInfo } from '../../src/types/cms-types.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import {
    DIGEST,
    ISSUER,
    OIDS,
    alg,
    attribute,
    context,
    contentInfo,
    int,
    octets,
    oid,
    signedData,
    signerInfo,
    sorted,
} from '../helpers/cms-signed-data-builder.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The signed attributes a verifier reads (RFC 5652 §11, RFC 2634 §5.4,
 * RFC 5035 §3), read through `parseSignedData`.
 *
 * The convenience fields answer one question each, and the tests below hold
 * them to the rule that makes them safe: set only when the attribute appears
 * exactly once with exactly one value. A second `messageDigest` is not a
 * formatting slip but the shape of an attack, so "the first one" is never the
 * answer — the field is `undefined` and the raw list keeps both.
 */

const contentTypeAttr = attribute(OIDS.contentType, oid(OIDS.data));
const digestAttr = attribute(OIDS.messageDigest, octets(DIGEST));

/** Parse a message whose one signer carries these signed attributes, in the order given. */
function signerWith(signedAttrs: readonly Uint8Array[], options: ParseSignedDataOptions = {}): { readonly signer: SignerInfo; readonly codes: readonly string[] } {
    const seen: PkiDiagnostic[] = [];
    const parsed = parseSignedData(contentInfo(signedData({ signers: [signerInfo({ signedAttrs })] })), { onDiagnostic: (d) => { seen.push(d); }, ...options });
    return { signer: parsed.signerInfos[0] as SignerInfo, codes: seen.map((d) => d.code) };
}

function refusal(signedAttrs: readonly Uint8Array[], options: ParseSignedDataOptions = {}): PkiError {
    try {
        signerWith(signedAttrs, options);
    } catch (error) {
        if (error instanceof PkiError) return error;
        throw error;
    }
    throw new Error('expected a refusal');
}

const sameBytes = (a: Uint8Array | undefined, b: Uint8Array): boolean => a !== undefined && a.length === b.length && a.every((x, i) => x === b[i]);

describe('signed attributes — the single-instance, single-value rule', () => {
    it('should read contentType and messageDigest when each appears once', () => {
        const { signer } = signerWith(sorted([contentTypeAttr, digestAttr]));
        expect(signer.contentType).toBe(OIDS.data);
        expect(sameBytes(signer.messageDigest, DIGEST)).toBe(true);
    });

    it('should leave messageDigest undefined when it appears twice, and keep both in the raw list', () => {
        const second = attribute(OIDS.messageDigest, octets([1, 2, 3]));
        const { signer } = signerWith([contentTypeAttr, digestAttr, second]);
        expect(signer.messageDigest).toBeUndefined();
        expect(signer.signedAttributes?.filter((a) => a.oid === OIDS.messageDigest)).toHaveLength(2);
    });

    it('should leave contentType undefined when it carries two values', () => {
        const { signer } = signerWith([attribute(OIDS.contentType, oid(OIDS.data), oid(OIDS.tstInfo)), digestAttr]);
        expect(signer.contentType).toBeUndefined();
        expect(signer.signedAttributes?.[0]?.values).toHaveLength(2);
    });

    it('should keep an attribute with no value, and read no field from it', () => {
        const { signer } = signerWith([attribute(OIDS.contentType), digestAttr]);
        expect(signer.contentType).toBeUndefined();
        expect(signer.signedAttributes?.[0]?.values).toEqual([]);
    });

    it('should keep each value and the whole attribute as their exact DER', () => {
        const { signer } = signerWith([contentTypeAttr, digestAttr]);
        expect(sameBytes(signer.signedAttributes?.[1]?.der, digestAttr)).toBe(true);
        expect(sameBytes(signer.signedAttributes?.[1]?.values[0], octets(DIGEST))).toBe(true);
    });
});

describe('signed attributes — signingTime (RFC 5652 §11.3)', () => {
    it.each([
        ['UTCTime', universal(23, ascii('260301120000Z'))],
        ['GeneralizedTime', universal(24, ascii('20500301120000Z'))],
    ])('should read a %s', (_, value) => {
        const { signer } = signerWith([contentTypeAttr, digestAttr, attribute(OIDS.signingTime, value)]);
        expect(signer.signingTime?.type).toBe(_);
        expect(signer.signingTime?.epochMilliseconds).toBe(_ === 'UTCTime' ? Date.UTC(2026, 2, 1, 12) : Date.UTC(2050, 2, 1, 12));
    });
});

describe('signed attributes — malformed recognised values', () => {
    it.each<readonly [string, Uint8Array, string]>([
        ['a messageDigest that is an INTEGER', attribute(OIDS.messageDigest, int(1)), 'messageDigest'],
        ['a contentType that is an OCTET STRING', attribute(OIDS.contentType, octets([1])), 'contentType'],
        ['a contentType whose OID is not encoded correctly', attribute(OIDS.contentType, universal(6, [0x2a, 0x86])), 'contentType'],
        ['a signingTime that is an OCTET STRING', attribute(OIDS.signingTime, octets([1])), 'signingTime'],
        ['a signingTime in month 13', attribute(OIDS.signingTime, universal(23, ascii('261301120000Z'))), 'signingTime'],
    ])('should refuse %s with PKI_CMS_STRUCTURE_INVALID', (_, attr, field) => {
        const error = refusal([attr]);
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect((error as PkiCmsError).path).toBe(`content.signerInfos[0].signedAttrs.${field}`);
    });
});

// ── signingCertificate and signingCertificateV2 ──

const HASH = Uint8Array.from({ length: 20 }, (_, i) => i);
const directoryName = tlv(2, true, 4, ISSUER);
const issuerSerial = (serial = int(0x42)): Uint8Array => sequence(sequence(directoryName), serial);
const v1 = (...certIds: readonly Uint8Array[]): Uint8Array => attribute(OIDS.signingCertificate, sequence(sequence(...certIds)));
const v2 = (...certIds: readonly Uint8Array[]): Uint8Array => attribute(OIDS.signingCertificateV2, sequence(sequence(...certIds)));

describe('signed attributes — signingCertificate (RFC 2634 §5.4)', () => {
    it('should read an ESSCertID without issuerSerial as SHA-1', () => {
        const { signer } = signerWith([contentTypeAttr, digestAttr, v1(sequence(octets(HASH)))]);
        expect(signer.signingCertificate?.version).toBe(1);
        const id = signer.signingCertificate?.certIds[0];
        expect(id?.hashAlgorithm).toBe('SHA-1');
        expect(sameBytes(id?.certHash, HASH)).toBe(true);
        expect(id?.issuerSerial).toBeUndefined();
    });

    it('should read issuerSerial as GeneralNames and a serial', () => {
        const { signer } = signerWith([contentTypeAttr, digestAttr, v1(sequence(octets(HASH), issuerSerial()), sequence(octets(HASH)))]);
        const id = signer.signingCertificate?.certIds[0];
        expect(signer.signingCertificate?.certIds).toHaveLength(2);
        expect(id?.issuerSerial?.issuer[0]?.kind).toBe('directoryName');
        expect(id?.issuerSerial?.serialNumber.hex).toBe('42');
    });

    it('should accept policies, and not return them', () => {
        const attr = attribute(OIDS.signingCertificate, sequence(sequence(sequence(octets(HASH))), sequence(sequence(oid('2.5.29.32.0')))));
        expect(signerWith([contentTypeAttr, digestAttr, attr]).signer.signingCertificate?.certIds).toHaveLength(1);
    });
});

describe('signed attributes — signingCertificateV2 (RFC 5035 §3)', () => {
    it('should read an absent hashAlgorithm as its DEFAULT, SHA-256', () => {
        const { signer, codes } = signerWith([contentTypeAttr, digestAttr, v2(sequence(octets(HASH), issuerSerial()))]);
        expect(signer.signingCertificate?.version).toBe(2);
        expect(signer.signingCertificate?.certIds[0]?.hashAlgorithm).toBe('SHA-256');
        expect(signer.signingCertificate?.certIds[0]?.issuerSerial?.serialNumber.value).toBe(0x42n);
        expect(codes).toEqual([]);
    });

    it('should diagnose the DEFAULT written out (X.690 §11.5)', () => {
        const { signer, codes } = signerWith([contentTypeAttr, digestAttr, v2(sequence(alg(OIDS.sha256, null), octets(HASH)))]);
        expect(signer.signingCertificate?.certIds[0]?.hashAlgorithm).toBe('SHA-256');
        expect(codes).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
    });

    it('should not diagnose SHA-256 with NULL parameters, which is not the DEFAULT value', () => {
        expect(signerWith([contentTypeAttr, digestAttr, v2(sequence(alg(OIDS.sha256), octets(HASH)))]).codes).toEqual([]);
    });

    it.each([
        [OIDS.sha1, 'SHA-1'],
        [OIDS.sha384, 'SHA-384'],
        [OIDS.sha512, 'SHA-512'],
        ['1.2.3.4', '1.2.3.4'],
    ])('should name the digest %s as %s', (dotted, expected) => {
        const { signer } = signerWith([contentTypeAttr, digestAttr, v2(sequence(alg(dotted, null), octets(HASH)))]);
        expect(signer.signingCertificate?.certIds[0]?.hashAlgorithm).toBe(expected);
    });

    it('should prefer v2 when both are present', () => {
        const { signer } = signerWith(sorted([contentTypeAttr, digestAttr, v1(sequence(octets(HASH))), v2(sequence(octets(HASH)))]));
        expect(signer.signingCertificate?.version).toBe(2);
    });

    it('should not fall back to v1 when v2 is present but ambiguous', () => {
        const repeated = v2(sequence(octets(HASH)));
        const { signer } = signerWith([contentTypeAttr, digestAttr, v1(sequence(octets(HASH))), repeated, repeated]);
        expect(signer.signingCertificate).toBeUndefined();
    });

    it('should bound the certIds with maxChainLength', () => {
        const error = refusal([v2(sequence(octets(HASH)), sequence(octets(HASH)))], { limits: { maxChainLength: 1 } });
        expect(error.code).toBe('PKI_LIMIT_EXCEEDED');
        expect((error as PkiError & { readonly limit?: string }).limit).toBe('maxChainLength');
    });

    it('should let a limit inside issuerSerial surface as itself', () => {
        const error = refusal([v2(sequence(octets(HASH), sequence(sequence(directoryName, directoryName), int(1))))], { limits: { maxGeneralNames: 1 } });
        expect(error.code).toBe('PKI_LIMIT_EXCEEDED');
    });
});

describe('signed attributes — malformed signingCertificate values', () => {
    const cert = 'content.signerInfos[0].signedAttrs.signingCertificate';
    const certV2 = 'content.signerInfos[0].signedAttrs.signingCertificateV2';
    const cases: ReadonlyArray<readonly [string, Uint8Array, string]> = [
        ['a value that is not a SEQUENCE', attribute(OIDS.signingCertificate, set1(int(1))), cert],
        ['certs that is not a SEQUENCE', attribute(OIDS.signingCertificate, sequence(int(1))), `${cert}.certs`],
        ['a missing certs', attribute(OIDS.signingCertificate, sequence()), `${cert}.certs`],
        ['policies that is not a SEQUENCE', attribute(OIDS.signingCertificate, sequence(sequence(sequence(octets(HASH))), int(1))), `${cert}.policies`],
        ['three fields', attribute(OIDS.signingCertificate, sequence(sequence(sequence(octets(HASH))), sequence(), sequence())), cert],
        ['a v2 with three fields', attribute(OIDS.signingCertificateV2, sequence(sequence(sequence(octets(HASH))), sequence(), sequence())), certV2],
        ['an empty certs', v1(), `${cert}.certs`],
        ['an ESSCertID that is not a SEQUENCE', v1(octets(HASH)), `${cert}.certs[0]`],
        ['a missing certHash', v1(sequence()), `${cert}.certs[0].certHash`],
        ['a v1 certHash preceded by an algorithm', v1(sequence(alg(OIDS.sha1), octets(HASH))), `${cert}.certs[0].certHash`],
        ['a value after issuerSerial', v1(sequence(octets(HASH), issuerSerial(), int(0))), `${cert}.certs[0]`],
        ['an issuerSerial that is not a SEQUENCE', v1(sequence(octets(HASH), int(0))), `${cert}.certs[0].issuerSerial`],
        ['an issuerSerial with one field', v1(sequence(octets(HASH), sequence(sequence(directoryName)))), `${cert}.certs[0].issuerSerial`],
        ['an issuer that is not GeneralNames', v1(sequence(octets(HASH), sequence(int(1), int(1)))), `${cert}.certs[0].issuerSerial.issuer`],
        ['an issuer with a GeneralName [9]', v1(sequence(octets(HASH), sequence(sequence(context(9, false, [1])), int(1)))), `${cert}.certs[0].issuerSerial.issuer`],
        ['a serial that is not an INTEGER', v1(sequence(octets(HASH), sequence(sequence(directoryName), octets([1])))), `${cert}.certs[0].issuerSerial.serialNumber`],
        ['a v2 hashAlgorithm with three fields', v2(sequence(sequence(oid(OIDS.sha256), universal(5, []), universal(5, [])), octets(HASH))), `${certV2}.certs[0].hashAlgorithm`],
        ['a v2 hashAlgorithm whose OID is not encoded correctly', v2(sequence(sequence(universal(6, [0x2a, 0x86])), octets(HASH))), certV2],
    ];

    it.each(cases)('should refuse %s with PKI_CMS_STRUCTURE_INVALID', (_, attr, path) => {
        const error = refusal([attr]);
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect((error as PkiCmsError).path).toBe(path);
    });
});

describe('signed attributes — DER even under BER (RFC 5652 §5.3)', () => {
    const ber: ParseSignedDataOptions = { encodingRules: 'ber' };
    const refusedUnderBer = (attr: Uint8Array): PkiError => refusal([contentTypeAttr, attr], ber);

    it('should refuse an indefinite length inside the signed attributes', () => {
        const error = refusedUnderBer(tlv(0, true, 16, concat(oid('1.2.3'), universal(17, int(1), true)), { indefinite: true }));
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect((error as PkiCmsError).path).toBe('content.signerInfos[0].signedAttrs');
    });

    it('should refuse a non-minimal length inside the signed attributes', () => {
        const error = refusedUnderBer(attribute('1.2.3', tlv(0, false, 4, [1, 2], { lengthOctets: 1 })));
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it('should refuse a constructed string inside the signed attributes', () => {
        const error = refusedUnderBer(attribute(OIDS.messageDigest, tlv(0, true, 4, octets(DIGEST))));
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it('should accept DER that uses a high tag number and a long length', () => {
        const long = new Uint8Array(300).fill(7);
        const { signer } = signerWith([contentTypeAttr, digestAttr, attribute('1.2.3', tlv(2, false, 40, [1]), octets(long))], ber);
        expect(signer.signedAttributes?.[2]?.values).toHaveLength(2);
        expect(signer.messageDigest).toBeDefined();
    });
});

/** A SET holding one value — a SigningCertificate that is not a SEQUENCE. */
function set1(value: Uint8Array): Uint8Array {
    return universal(17, value, true);
}

// ── CMSAlgorithmProtection (RFC 6211) ──

describe('signed attributes — CMSAlgorithmProtection (RFC 6211)', () => {
    const PROTECTION = '1.2.840.113549.1.9.52';
    const SHA256 = '2.16.840.1.101.3.4.2.1';
    const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
    const where = 'content.signerInfos[0].signedAttrs.CMSAlgorithmProtection';
    /** [1] is IMPLICIT: it replaces the signature AlgorithmIdentifier's SEQUENCE tag. */
    const protection = (...fields: readonly Uint8Array[]): Uint8Array => attribute(PROTECTION, sequence(...fields));
    const signatureField = (dotted: string, ...params: readonly Uint8Array[]): Uint8Array => context(1, true, concat(oid(dotted), ...params));

    it('should decode the digest and the signature algorithm the signer protected', () => {
        const { signer } = signerWith(sorted([contentTypeAttr, digestAttr, protection(alg(SHA256, null), signatureField(ECDSA_SHA256))]));
        expect(signer.algorithmProtection?.digestAlgorithm.oid).toBe(SHA256);
        expect(signer.algorithmProtection?.signatureAlgorithm.oid).toBe(ECDSA_SHA256);
        expect(signer.algorithmProtection?.signatureAlgorithm.parameters).toBeUndefined();
    });

    it('should keep the parameters of the protected signature algorithm', () => {
        const { signer } = signerWith(sorted([contentTypeAttr, digestAttr, protection(alg(SHA256, null), signatureField(ECDSA_SHA256, universal(5, [])))]));
        expect(signer.algorithmProtection?.signatureAlgorithm.parameters?.tagNumber).toBe(5);
    });

    it('should leave the field undefined when the signer did not protect its algorithms', () => {
        expect(signerWith(sorted([contentTypeAttr, digestAttr])).signer.algorithmProtection).toBeUndefined();
    });

    it.each([
        ['a MAC algorithm where the signature algorithm belongs', protection(alg(SHA256, null), context(2, true, oid(ECDSA_SHA256)))],
        ['no signature algorithm', protection(alg(SHA256, null))],
        ['a MAC algorithm besides the signature algorithm', protection(alg(SHA256, null), signatureField(ECDSA_SHA256), context(2, true, oid(ECDSA_SHA256)))],
        ['a primitive [1]', protection(alg(SHA256, null), context(1, false, [0x01]))],
        ['a [1] that does not start with an OID', protection(alg(SHA256, null), context(1, true, universal(5, [])))],
        ['a [1] of three fields', protection(alg(SHA256, null), signatureField(ECDSA_SHA256, universal(5, []), universal(5, [])))],
        ['a value that is not a SEQUENCE', attribute(PROTECTION, octets([1]))],
    ])('should refuse a protection with %s, as it refuses any malformed recognised attribute', (_, value) => {
        const error = refusal(sorted([contentTypeAttr, digestAttr, value]));
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect((error as PkiCmsError).path?.startsWith(where)).toBe(true);
    });

    it('should refuse a protected digest that is not an AlgorithmIdentifier, under the CMS error', () => {
        const error = refusal(sorted([contentTypeAttr, digestAttr, protection(octets([1]), signatureField(ECDSA_SHA256))]));
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
    });
});