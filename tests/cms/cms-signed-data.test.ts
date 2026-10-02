import { describe, expect, it } from 'vitest';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import { PkiCmsError, PkiError } from '../../src/types/pki-errors.js';
import type { ParseSignedDataOptions, SignedData } from '../../src/types/cms-types.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import {
    CONTENT,
    ISSUER,
    OIDS,
    SIGNATURE,
    SKI,
    alg,
    attribute,
    context,
    contentInfo,
    defaultSignedAttributes,
    int,
    issuerAndSerial,
    octets,
    oid,
    set,
    signedData,
    signerInfo,
    subjectKeyIdentifier,
} from '../helpers/cms-signed-data-builder.js';
import type { SignedDataParts, SignerParts } from '../helpers/cms-signed-data-builder.js';
import { concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 5652 §5 SignedData parsing.
 *
 * Every message is assembled by `tests/helpers/cms-signed-data-builder.ts`,
 * which never imports `src/`: the parser is checked against the ASN.1 module,
 * not against pkinative's own encoder. Refusals are asserted by code, and the
 * interesting acceptances — detached, empty, degenerate, BER — by the decoded
 * structure, because each of them is a case where "it parsed" and "it parsed
 * into the right thing" part ways.
 */

function parse(der: Uint8Array, options: ParseSignedDataOptions = {}): { readonly signed: SignedData; readonly codes: readonly string[] } {
    const seen: PkiDiagnostic[] = [];
    const signed = parseSignedData(der, { onDiagnostic: (d) => { seen.push(d); }, ...options });
    return { signed, codes: seen.map((d) => d.code) };
}

function refusal(der: Uint8Array, options: ParseSignedDataOptions = {}): PkiError {
    try {
        parseSignedData(der, { onDiagnostic: () => undefined, ...options });
    } catch (error) {
        if (error instanceof PkiError) return error;
        throw error;
    }
    throw new Error('expected a refusal');
}

function cmsRefusal(der: Uint8Array, options: ParseSignedDataOptions = {}): PkiCmsError {
    const error = refusal(der, options);
    expect(error).toBeInstanceOf(PkiCmsError);
    return error as PkiCmsError;
}

const sameBytes = (a: Uint8Array | undefined, b: Uint8Array): boolean => a !== undefined && a.length === b.length && a.every((x, i) => x === b[i]);

describe('parseSignedData — a minimal attached SignedData', () => {
    const der = contentInfo();
    const { signed, codes } = parse(der);
    const signer = signed.signerInfos[0];

    it('should read the envelope', () => {
        expect(signed.version).toBe(1);
        expect(signed.contentType).toBe(OIDS.data);
        expect(signed.digestAlgorithms.map((a) => a.oid)).toEqual([OIDS.sha256]);
        expect(sameBytes(signed.content, CONTENT)).toBe(true);
        expect(signed.certificates).toEqual([]);
        expect(signed.crls).toEqual([]);
        expect(signed.ocspResponses).toEqual([]);
        expect(codes).toEqual([]);
        expect(signed.diagnostics).toEqual([]);
    });

    it('should return the whole ContentInfo as der, and the content as a view of the input', () => {
        expect(sameBytes(signed.der, der)).toBe(true);
        expect(signed.content?.buffer).toBe(der.buffer);
    });

    it('should read the signer', () => {
        expect(signer?.version).toBe(1);
        expect(signer?.sid.kind).toBe('issuerAndSerialNumber');
        if (signer?.sid.kind !== 'issuerAndSerialNumber') throw new Error('unreachable');
        expect(sameBytes(signer.sid.issuer.der, ISSUER)).toBe(true);
        expect(signer.sid.serialNumber.hex).toBe('1234');
        expect(signer.sid.serialNumber.value).toBe(0x1234n);
        expect(signer.digestAlgorithm.oid).toBe(OIDS.sha256);
        expect(signer.signatureAlgorithm.oid).toBe(OIDS.rsaEncryption);
        expect(sameBytes(signer.signature, SIGNATURE)).toBe(true);
        expect(signer.signedAttributes?.map((a) => a.oid)).toEqual([OIDS.contentType, OIDS.messageDigest]);
        expect(signer.unsignedAttributes).toBeUndefined();
        expect(signer.timeStampTokens).toEqual([]);
        expect(signer.contentType).toBe(OIDS.data);
        expect(sameBytes(signer.der, signerInfo())).toBe(true);
    });

    it('should freeze what it returns', () => {
        expect(Object.isFrozen(signed)).toBe(true);
        expect(Object.isFrozen(signed.signerInfos)).toBe(true);
        expect(Object.isFrozen(signer)).toBe(true);
        expect(Object.isFrozen(signer?.sid)).toBe(true);
        expect(Object.isFrozen(signer?.signedAttributes)).toBe(true);
    });
});

describe('parseSignedData — content', () => {
    it('should report detached content as undefined (RFC 5652 §5.2)', () => {
        expect(parse(contentInfo(signedData({ eContent: null }))).signed.content).toBeUndefined();
    });

    it('should report present-but-empty content as zero octets, not as detached', () => {
        const content = parse(contentInfo(signedData({ eContent: octets([]) }))).signed.content;
        expect(content).toBeInstanceOf(Uint8Array);
        expect(content?.length).toBe(0);
    });

    it('should refuse content that is not an OCTET STRING, such as Authenticode (RFC 5652 §5.2.1)', () => {
        const error = cmsRefusal(contentInfo(signedData({ contentType: '1.3.6.1.4.1.311.2.1.4', version: int(3), eContent: sequence(oid('1.2.3')) })));
        expect(error.code).toBe('PKI_CMS_CONTENT_NOT_OCTET_STRING');
        expect(error.path).toBe('content.encapContentInfo.eContent');
    });
});

describe('parseSignedData — the ContentInfo type', () => {
    it('should refuse enveloped-data by name', () => {
        const error = cmsRefusal(contentInfo(sequence(int(0)), OIDS.envelopedData));
        expect(error.code).toBe('PKI_CMS_CONTENT_TYPE_UNEXPECTED');
        expect(error.message).toMatch(/^pkinative: /);
    });

    it('should refuse an unknown content type', () => {
        expect(cmsRefusal(contentInfo(sequence(int(0)), '1.2.3.4')).code).toBe('PKI_CMS_CONTENT_TYPE_UNEXPECTED');
    });
});

describe('parseSignedData — the signer identifier', () => {
    it('should read a subjectKeyIdentifier sid as a primitive [0] (IMPLICIT by module default)', () => {
        const { signed, codes } = parse(contentInfo(signedData({ version: int(3), signers: [signerInfo({ version: int(3), sid: subjectKeyIdentifier() })] })));
        const sid = signed.signerInfos[0]?.sid;
        expect(sid?.kind).toBe('subjectKeyIdentifier');
        if (sid?.kind !== 'subjectKeyIdentifier') throw new Error('unreachable');
        expect(sameBytes(sid.keyIdentifier, SKI)).toBe(true);
        expect(signed.version).toBe(3);
        expect(signed.signerInfos[0]?.version).toBe(3);
        expect(codes).toEqual([]);
    });

    it('should diagnose a SignerInfo version that does not match its sid', () => {
        const { signed, codes } = parse(contentInfo(signedData({ version: int(3), signers: [signerInfo({ version: int(3) })] })));
        expect(signed.signerInfos[0]?.sid.kind).toBe('issuerAndSerialNumber');
        expect(codes).toEqual(['PKI_DIAG_CMS_VERSION_MISMATCH']);
    });

    it('should refuse a SignerInfo version RFC 5652 does not define rather than skip the signer', () => {
        const error = cmsRefusal(contentInfo(signedData({ signers: [signerInfo({ version: int(2) })] })));
        expect(error.code).toBe('PKI_CMS_VERSION_UNSUPPORTED');
        expect(error.path).toBe('content.signerInfos[0].version');
    });
});

describe('parseSignedData — the §5.1 version derivation', () => {
    const cert = sequence(int(7));
    const rows: ReadonlyArray<readonly [string, number, SignedDataParts]> = [
        ['a certs-only bundle', 1, { signers: [], eContent: null, certificates: [cert] }],
        ['an extendedCertificate [0]', 1, { certificates: [context(0, true, int(1))] }],
        ['an SKI signer', 3, { signers: [signerInfo({ version: int(3), sid: subjectKeyIdentifier() })] }],
        ['a content type other than id-data', 3, { contentType: OIDS.tstInfo }],
        ['a v1AttrCert [1]', 3, { certificates: [context(1, true, int(1))] }],
        ['a v2AttrCert [2]', 4, { certificates: [context(2, true, int(1))] }],
        ['an other certificate format [3]', 5, { certificates: [context(3, true, concat(oid('1.2.3'), int(1)))] }],
        ['an other revocation format [1]', 5, { crls: [context(1, true, concat(oid('1.2.3'), int(1)))] }],
    ];

    it.each(rows)('should derive the version of %s without a diagnostic when it is declared', (_, version, parts) => {
        const { signed, codes } = parse(contentInfo(signedData({ ...parts, version: int(version) })));
        expect(signed.version).toBe(version);
        expect(codes).toEqual([]);
    });

    it.each(rows)('should diagnose %s declared with the wrong version, and return the declared one', (_, version, parts) => {
        const wrong = version === 1 ? 5 : 1;
        const { signed, codes } = parse(contentInfo(signedData({ ...parts, version: int(wrong) })));
        expect(signed.version).toBe(wrong);
        expect(codes).toEqual(['PKI_DIAG_CMS_VERSION_MISMATCH']);
    });

    it.each([0, 2, 6, 300])('should refuse SignedData version %i', (version) => {
        expect(cmsRefusal(contentInfo(signedData({ version: int(version) }))).code).toBe('PKI_CMS_VERSION_UNSUPPORTED');
    });
});

describe('parseSignedData — the bag', () => {
    it('should keep certificates and CRLs as their exact DER, unparsed', () => {
        const cert = sequence(int(1), int(2));
        const crl = sequence(int(3));
        const { signed } = parse(contentInfo(signedData({ certificates: [cert], crls: [crl] })));
        expect(signed.certificates).toHaveLength(1);
        expect(sameBytes(signed.certificates[0], cert)).toBe(true);
        expect(sameBytes(signed.crls[0], crl)).toBe(true);
    });

    it('should carry an OCSP response from crls other [1] (RFC 5940), and ignore other formats', () => {
        const response = sequence(universal(10, [0]));
        const { signed } = parse(contentInfo(signedData({
            version: int(5),
            crls: [context(1, true, concat(oid(OIDS.ocspResponse), response)), context(1, true, concat(oid('1.2.3'), int(1)))],
        })));
        expect(signed.ocspResponses).toHaveLength(1);
        expect(sameBytes(signed.ocspResponses[0], response)).toBe(true);
        expect(signed.crls).toEqual([]);
    });

    it('should diagnose an unsorted certificate set once', () => {
        const { codes } = parse(contentInfo(signedData({ certificates: [sequence(int(2)), sequence(int(1)), sequence(int(0))] })));
        expect(codes).toEqual(['PKI_DIAG_CMS_SET_NOT_SORTED']);
    });

    it.each<readonly [string, SignedDataParts]>([
        ['crls', { crls: [sequence(int(2)), sequence(int(1))] }],
        ['digestAlgorithms', { digestAlgorithms: [alg(OIDS.sha512), alg(OIDS.sha256)] }],
        ['signerInfos', { signers: [signerInfo({ signature: octets([2]) }), signerInfo({ signature: octets([1]) })] }],
    ])('should diagnose an unsorted %s set', (_, parts) => {
        expect(parse(contentInfo(signedData(parts))).codes).toEqual(['PKI_DIAG_CMS_SET_NOT_SORTED']);
    });

    it('should parse a degenerate SignedData with no signer', () => {
        const { signed, codes } = parse(contentInfo(signedData({ digestAlgorithms: [], eContent: null, signers: [], certificates: [sequence(int(1))] })));
        expect(signed.signerInfos).toEqual([]);
        expect(signed.certificates).toHaveLength(1);
        expect(codes).toEqual([]);
    });
});

describe('parseSignedData — signed attributes', () => {
    it('should expose the bytes the signature covers: the received [0] with the SET OF tag, on a copy', () => {
        const der = contentInfo();
        const before = der.slice();
        const signer = parse(der).signed.signerInfos[0];
        const attrs = context(0, true, concat(...defaultSignedAttributes()));
        const expected = Uint8Array.from(attrs);
        expected[0] = 0x31;
        expect(sameBytes(signer?.signedAttributesDer, expected)).toBe(true);
        expect(sameBytes(der, before)).toBe(true);
        expect(signer?.signedAttributesDer?.buffer).not.toBe(der.buffer);
    });

    it('should diagnose unsorted signed attributes and keep them in the order received', () => {
        const attrs = [...defaultSignedAttributes()].reverse();
        const { signed, codes } = parse(contentInfo(signedData({ signers: [signerInfo({ signedAttrs: attrs })] })));
        expect(codes).toEqual(['PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER']);
        const expected = context(0, true, concat(...attrs));
        expected[0] = 0x31;
        expect(sameBytes(signed.signerInfos[0]?.signedAttributesDer, expected)).toBe(true);
        expect(signed.signerInfos[0]?.signedAttributes?.map((a) => a.oid)).toEqual([OIDS.messageDigest, OIDS.contentType]);
    });

    it('should leave every signed-attribute field undefined when there are none', () => {
        const signer = parse(contentInfo(signedData({ signers: [signerInfo({ signedAttrs: null })] }))).signed.signerInfos[0];
        expect(signer?.signedAttributes).toBeUndefined();
        expect(signer?.signedAttributesDer).toBeUndefined();
        expect(signer?.contentType).toBeUndefined();
        expect(signer?.messageDigest).toBeUndefined();
        expect(signer?.signingTime).toBeUndefined();
        expect(signer?.signingCertificate).toBeUndefined();
    });

    it('should diagnose a signer digest algorithm missing from digestAlgorithms', () => {
        const { codes } = parse(contentInfo(signedData({ signers: [signerInfo({ digestAlgorithm: alg(OIDS.sha384) })] })));
        expect(codes).toEqual(['PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED']);
    });

    it('should escalate a diagnostic under strict', () => {
        const error = refusal(contentInfo(signedData({ signers: [signerInfo({ digestAlgorithm: alg(OIDS.sha384) })] })), { strict: true });
        expect(error.code).toBe('PKI_STRICT_DIAGNOSTIC');
    });
});

describe('parseSignedData — unsigned attributes', () => {
    it('should collect every timestamp token value, and none from the signed attributes', () => {
        const token = (n: number): Uint8Array => sequence(int(n));
        const { signed } = parse(contentInfo(signedData({
            signers: [signerInfo({
                signedAttrs: [...defaultSignedAttributes(), attribute(OIDS.timeStampToken, token(9))],
                unsignedAttrs: [attribute(OIDS.timeStampToken, token(1), token(2)), attribute('1.2.3', int(0)), attribute(OIDS.timeStampToken, token(3))],
            })],
        })));
        const signer = signed.signerInfos[0];
        expect(signer?.timeStampTokens).toHaveLength(3);
        expect(sameBytes(signer?.timeStampTokens[2], token(3))).toBe(true);
        expect(signer?.unsignedAttributes?.map((a) => a.oid)).toEqual([OIDS.timeStampToken, '1.2.3', OIDS.timeStampToken]);
    });
});

describe('parseSignedData — BER', () => {
    /** The same message with an indefinite length on the ContentInfo, the [0] and the SignedData. */
    const indefinite = (): Uint8Array => {
        const inner = signedData();
        const second = inner[1] as number;
        const fields = inner.subarray(second < 0x80 ? 2 : 2 + (second & 0x7f));
        return tlv(0, true, 16, concat(oid(OIDS.signedData), tlv(2, true, 0, tlv(0, true, 16, fields, { indefinite: true }), { indefinite: true })), { indefinite: true });
    };

    it('should accept an indefinite-length envelope under ber', () => {
        const input = indefinite();
        const { signed, codes } = parse(input, { encodingRules: 'ber' });
        expect(sameBytes(signed.content, CONTENT)).toBe(true);
        expect(codes).toEqual(['PKI_DIAG_BER_CONSTRUCT_ACCEPTED']);
        expect(signed.der.length).toBe(input.length);
    });

    it('should refuse it under der', () => {
        expect(refusal(indefinite()).code).toBe('PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN');
    });

    it('should join a segmented eContent (RFC 4134 §3.1)', () => {
        const segmented = tlv(0, true, 4, concat(octets([0x68, 0x65]), octets([0x6c, 0x6c, 0x6f])), { indefinite: true });
        const { signed } = parse(contentInfo(signedData({ eContent: segmented })), { encodingRules: 'ber' });
        expect(sameBytes(signed.content, CONTENT)).toBe(true);
    });

    it('should refuse indefinite-length signed attributes even under ber (RFC 5652 §5.3)', () => {
        const signedAttrsRaw = tlv(2, true, 0, concat(...defaultSignedAttributes()), { indefinite: true });
        const error = cmsRefusal(contentInfo(signedData({ signers: [signerInfo({ signedAttrsRaw })] })), { encodingRules: 'ber' });
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect(error.path).toBe('content.signerInfos[0].signedAttrs');
    });
});

describe('parseSignedData — trailing data', () => {
    const padded = concat(contentInfo(), new Uint8Array(64));

    it('should refuse bytes after the ContentInfo by default', () => {
        expect(refusal(padded).code).toBe('PKI_ASN1_TRAILING_DATA');
    });

    it('should ignore them with allowTrailingData, and keep them out of der', () => {
        const { signed } = parse(padded, { allowTrailingData: true });
        expect(sameBytes(signed.der, contentInfo())).toBe(true);
    });

    it('should refuse an allowTrailingData that is not a boolean', () => {
        expect(refusal(contentInfo(), { allowTrailingData: 'yes' as unknown as boolean }).code).toBe('PKI_INVALID_OPTION');
    });

    it('should refuse an input that is not bytes', () => {
        expect(() => parseSignedData('30' as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

describe('parseSignedData — limits', () => {
    const tripped = (der: Uint8Array, limits: ParseSignedDataOptions['limits']): string | undefined => {
        const error = refusal(der, { limits });
        expect(error.code).toBe('PKI_LIMIT_EXCEEDED');
        return (error as PkiError & { readonly limit?: string }).limit;
    };

    it('should bound the signers with maxSignerInfos', () => {
        const der = contentInfo(signedData({ signers: [signerInfo({ signature: octets([1]) }), signerInfo({ signature: octets([2]) })] }));
        expect(tripped(der, { maxSignerInfos: 1 })).toBe('maxSignerInfos');
    });

    it('should bound the digest algorithms with maxSignerInfos', () => {
        const der = contentInfo(signedData({ digestAlgorithms: [alg(OIDS.sha256), alg(OIDS.sha384)] }));
        expect(tripped(der, { maxSignerInfos: 1 })).toBe('maxSignerInfos');
    });

    it('should admit exactly maxSignerInfos signers', () => {
        const der = contentInfo(signedData({ signers: [signerInfo({ signature: octets([1]) }), signerInfo({ signature: octets([2]) })] }));
        expect(parse(der, { limits: { maxSignerInfos: 2 } }).signed.signerInfos).toHaveLength(2);
    });

    it('should admit exactly maxSignerInfos digest algorithms', () => {
        const der = contentInfo(signedData({ digestAlgorithms: [alg(OIDS.sha256), alg(OIDS.sha384)] }));
        expect(parse(der, { limits: { maxSignerInfos: 2 } }).signed.digestAlgorithms.map((a) => a.oid)).toEqual([OIDS.sha256, OIDS.sha384]);
    });

    it('should bound the signed attributes with maxAttributes', () => {
        expect(tripped(contentInfo(), { maxAttributes: 1 })).toBe('maxAttributes');
    });

    it('should bound the values of one attribute with maxAttributes', () => {
        const der = contentInfo(signedData({ signers: [signerInfo({ signedAttrs: [attribute('1.2.3', int(1), int(2), int(3))] })] }));
        expect(tripped(der, { maxAttributes: 2 })).toBe('maxAttributes');
    });

    it('should bound certificates and CRLs together with maxCmsCertificatesAndCrls', () => {
        const der = contentInfo(signedData({ certificates: [sequence(int(1))], crls: [sequence(int(2))] }));
        expect(parse(der, { limits: { maxCmsCertificatesAndCrls: 2 } }).signed.crls).toHaveLength(1);
        expect(tripped(der, { maxCmsCertificatesAndCrls: 1 })).toBe('maxCmsCertificatesAndCrls');
    });
});

describe('parseSignedData — structures RFC 5652 does not define', () => {
    const sd = (parts: SignedDataParts): Uint8Array => contentInfo(signedData(parts));
    const signerWith = (parts: SignerParts): Uint8Array => sd({ signers: [signerInfo(parts)] });
    const defaults = { version: int(1), sid: issuerAndSerial(), digest: alg(OIDS.sha256), sigAlg: alg(OIDS.rsaEncryption), sig: octets(SIGNATURE) };
    const encap = sequence(oid(OIDS.data), context(0, true, octets(CONTENT)));

    const cases: ReadonlyArray<readonly [string, Uint8Array, string]> = [
        ['a ContentInfo that is not a SEQUENCE', set(oid(OIDS.signedData)), 'ContentInfo'],
        ['a contentType that is not an OID', sequence(int(1), context(0, true, signedData())), 'contentType'],
        ['a missing content', sequence(oid(OIDS.signedData)), 'content'],
        ['a content under [1]', sequence(oid(OIDS.signedData), context(1, true, signedData())), 'content'],
        ['a primitive [0] content', sequence(oid(OIDS.signedData), context(0, false, [1])), 'content'],
        ['two values under [0]', sequence(oid(OIDS.signedData), context(0, true, concat(signedData(), signedData()))), 'content'],
        ['a field after content', sequence(oid(OIDS.signedData), context(0, true, signedData()), int(0)), 'content'],
        ['a SignedData that is not a SEQUENCE', contentInfo(set(int(1))), 'content'],
        ['a version that is not an INTEGER', sd({ fields: [octets([1])] }), 'content.version'],
        ['digestAlgorithms that is not a SET', sd({ fields: [int(1), sequence()] }), 'content.digestAlgorithms'],
        ['a digest algorithm that is not an AlgorithmIdentifier', sd({ digestAlgorithms: [int(1)] }), 'content.digestAlgorithms[0]'],
        ['a missing encapContentInfo', sd({ fields: [int(1), set()] }), 'content.encapContentInfo'],
        ['an eContentType that is not an OID', sd({ encapRaw: sequence(int(1)) }), 'content.encapContentInfo.eContentType'],
        ['an eContent under [1]', sd({ encapRaw: sequence(oid(OIDS.data), context(1, true, octets([]))) }), 'content.encapContentInfo.eContent'],
        ['a primitive eContent [0]', sd({ encapRaw: sequence(oid(OIDS.data), context(0, false, [1])) }), 'content.encapContentInfo.eContent'],
        ['an empty eContent [0]', sd({ encapRaw: sequence(oid(OIDS.data), context(0, true, [])) }), 'content.encapContentInfo.eContent'],
        ['a field after eContent', sd({ encapRaw: sequence(oid(OIDS.data), context(0, true, octets([])), int(0)) }), 'content.encapContentInfo.eContent'],
        ['a primitive certificates [0]', sd({ fields: [int(1), set(), encap, context(0, false, [1]), set()] }), 'content.certificates'],
        ['a primitive crls [1]', sd({ fields: [int(1), set(), encap, context(1, false, [1]), set()] }), 'content.crls'],
        ['a certificate that is an INTEGER', sd({ certificates: [int(1)] }), 'content.certificates[0]'],
        ['a certificate under [4]', sd({ certificates: [context(4, true, int(1))] }), 'content.certificates[0]'],
        ['a primitive certificate [2]', sd({ certificates: [context(2, false, [1])] }), 'content.certificates[0]'],
        ['a CRL that is an INTEGER', sd({ crls: [int(1)] }), 'content.crls[0]'],
        ['a CRL under [0]', sd({ crls: [context(0, true, concat(oid('1.2.3'), int(1)))] }), 'content.crls[0]'],
        ['a primitive other [1] CRL', sd({ crls: [context(1, false, [1])] }), 'content.crls[0]'],
        ['an other [1] CRL with one field', sd({ crls: [context(1, true, oid('1.2.3'))] }), 'content.crls[0]'],
        ['an other [1] CRL whose format is not an OID', sd({ crls: [context(1, true, concat(int(1), int(1)))] }), 'content.crls[0].otherRevInfoFormat'],
        ['a missing signerInfos', sd({ fields: [int(1), set(), encap] }), 'content.signerInfos'],
        ['signerInfos that is a SEQUENCE', sd({ fields: [int(1), set(), encap, sequence()] }), 'content.signerInfos'],
        ['a field after signerInfos', sd({ fields: [int(1), set(), encap, set(), set()] }), 'content'],
        ['a SignerInfo that is not a SEQUENCE', sd({ signers: [set(int(1))] }), 'content.signerInfos[0]'],
        ['a SignerInfo version that is not an INTEGER', signerWith({ fields: [octets([1])] }), 'content.signerInfos[0].version'],
        ['a missing sid', signerWith({ fields: [defaults.version] }), 'content.signerInfos[0].sid'],
        ['a constructed [0] sid', signerWith({ sid: context(0, true, octets(SKI)) }), 'content.signerInfos[0].sid'],
        ['a [1] sid', signerWith({ sid: context(1, false, SKI) }), 'content.signerInfos[0].sid'],
        ['an issuerAndSerialNumber with one field', signerWith({ sid: sequence(ISSUER) }), 'content.signerInfos[0].sid'],
        // The two fields of an IssuerAndSerialNumber, under the SET tag: not a SignerIdentifier, however well its contents read.
        ['an issuerAndSerialNumber under a SET', signerWith({ sid: set(ISSUER, int(1)) }), 'content.signerInfos[0].sid'],
        ['an issuer that is not a Name', signerWith({ sid: sequence(int(1), int(1)) }), 'content.signerInfos[0].sid.issuer'],
        ['a serial that is not an INTEGER', signerWith({ sid: sequence(ISSUER, octets([1])) }), 'content.signerInfos[0].sid.serialNumber'],
        ['a missing digestAlgorithm', signerWith({ fields: [defaults.version, defaults.sid] }), 'content.signerInfos[0].digestAlgorithm'],
        ['a missing signatureAlgorithm', signerWith({ fields: [defaults.version, defaults.sid, defaults.digest] }), 'content.signerInfos[0].signatureAlgorithm'],
        ['a missing signature', signerWith({ fields: [defaults.version, defaults.sid, defaults.digest, defaults.sigAlg] }), 'content.signerInfos[0].signature'],
        ['a signature that is a BIT STRING', signerWith({ signature: universal(3, [0, 1]) }), 'content.signerInfos[0].signature'],
        ['a field after unsignedAttrs', signerWith({ fields: [defaults.version, defaults.sid, defaults.digest, defaults.sigAlg, defaults.sig, context(1, true, attribute('1.2.3', int(1))), int(0)] }), 'content.signerInfos[0]'],
        ['an empty signedAttrs', signerWith({ signedAttrs: [] }), 'content.signerInfos[0].signedAttrs'],
        ['a primitive signedAttrs', signerWith({ signedAttrsRaw: context(0, false, [1]) }), 'content.signerInfos[0].signedAttrs'],
        ['an empty unsignedAttrs', signerWith({ unsignedAttrs: [] }), 'content.signerInfos[0].unsignedAttrs'],
        ['an attribute that is not a SEQUENCE', signerWith({ signedAttrs: [set(oid('1.2.3'))] }), 'content.signerInfos[0].signedAttrs[0]'],
        ['an attribute with three fields', signerWith({ signedAttrs: [sequence(oid('1.2.3'), set(), set())] }), 'content.signerInfos[0].signedAttrs[0]'],
        ['an attribute type that is not an OID', signerWith({ signedAttrs: [sequence(int(1), set())] }), 'content.signerInfos[0].signedAttrs[0].attrType'],
        ['attribute values that are not a SET', signerWith({ signedAttrs: [sequence(oid('1.2.3'), sequence())] }), 'content.signerInfos[0].signedAttrs[0].attrValues'],
    ];

    it.each(cases)('should refuse %s with PKI_CMS_STRUCTURE_INVALID', (_, der, path) => {
        const error = cmsRefusal(der);
        expect(error.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect(error.path).toBe(path);
        expect(error.message).toMatch(/^pkinative: /);
    });

    it('should let a DER violation inside a shared reader surface as itself', () => {
        // An OID whose last arc is unterminated is an encoding error, not a
        // CMS structure error, wherever it sits.
        expect(refusal(sd({ digestAlgorithms: [sequence(universal(6, [0x2a, 0x86]))] })).code).toBe('PKI_OID_INVALID');
    });
});
