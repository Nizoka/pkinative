import { describe, expect, it } from 'vitest';
import {
    DEFAULT_PKI_LIMITS,
    decodeAsn1,
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeInteger,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeNull,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeValidity,
    KEY_USAGE_BITS,
} from '../../src/index.js';

/**
 * The X.509 structural encoders. The expectations are octet strings taken
 * from the RFCs, and the recurring theme is the DEFAULT: a field whose value
 * equals its DEFAULT is **absent** under DER, and encoding it anyway
 * produces the single most common conformance defect in the wild — one this
 * library refuses to create.
 */

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const CN = '2.5.4.3';

describe('encodeAlgorithmIdentifier', () => {
    it('should write NULL parameters for the PKCS#1 v1.5 family (RFC 3279 §2.2.1)', () => {
        expect(hex(encodeAlgorithmIdentifier('1.2.840.113549.1.1.11')))
            .toBe('300d06092a864886f70d01010b0500');
    });

    it('should leave parameters absent for ECDSA and the Edwards curves', () => {
        // RFC 5758 §3.2 and RFC 8410 §3 require absence, and the difference
        // is not cosmetic: a verifier comparing the outer AlgorithmIdentifier
        // to tbsCertificate.signature compares bytes.
        expect(hex(encodeAlgorithmIdentifier('1.3.101.112'))).toBe('300506032b6570');
        expect(hex(encodeAlgorithmIdentifier('1.2.840.10045.4.3.2'))).toBe('300a06082a8648ce3d040302');
    });

    it('should use explicit parameters when given, whatever the OID would imply', () => {
        expect(hex(encodeAlgorithmIdentifier('1.3.101.112', encodeNull()))).toBe('300706032b65700500');
    });

    it('should refuse parameters that are not bytes', () => {
        expect(() => encodeAlgorithmIdentifier('1.3.101.112', 'x' as unknown as Uint8Array))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

describe('encodeNameAttribute and encodeDistinguishedName', () => {
    it('should default a DirectoryString attribute to UTF8String', () => {
        expect(hex(encodeNameAttribute({ type: CN, value: 'a' }))).toBe('300806035504030c0161');
    });

    it('should default an attribute RFC 5280 Appendix A does not define to UTF8String', () => {
        expect(hex(encodeNameAttribute({ type: '1.2.3.4', value: 'a' }))).toBe('300806032a03040c0161');
    });

    it.each([
        // RFC 5280 Appendix A.1: X520countryName, X520SerialNumber and
        // X520dnQualifier are PrintableString (tag 0x13); DomainComponent and
        // EmailAddress are IA5String (tag 0x16).
        ['countryName', '2.5.4.6', 'US', '3009060355040613025553'],
        ['serialNumber', '2.5.4.5', '42', '3009060355040513023432'],
        ['dnQualifier', '2.5.4.46', 'q', '3008060355042e130171'],
        ['domainComponent', '0.9.2342.19200300.100.1.25', 'com', '3011060a0992268993f22c6401191603636f6d'],
        ['emailAddress', '1.2.840.113549.1.9.1', 'a@b', '301006092a864886f70d0109011603614062'],
    ])('should default %s to the string type Appendix A gives it', (_name, type, value, expected) => {
        expect(hex(encodeNameAttribute({ type, value }))).toBe(expected);
    });

    it('should accept PrintableString for a DirectoryString, which RFC 5280 §4.1.2.4 allows', () => {
        expect(hex(encodeNameAttribute({ type: CN, value: 'a', stringType: 'printable' }))).toBe('30080603550403130161');
        expect(hex(encodeNameAttribute({ type: '2.5.4.6', value: 'US', stringType: 'printable' }))).toBe('3009060355040613025553');
    });

    it.each([
        ['UTF8String for countryName', { type: '2.5.4.6', value: 'US', stringType: 'utf8' }, 'PrintableString'],
        ['UTF8String for serialNumber', { type: '2.5.4.5', value: '1', stringType: 'utf8' }, 'PrintableString'],
        ['PrintableString for emailAddress', { type: '1.2.840.113549.1.9.1', value: 'a', stringType: 'printable' }, 'IA5String'],
        ['IA5String for commonName', { type: CN, value: 'a', stringType: 'ia5' }, 'DirectoryString'],
        ['NumericString for organizationName', { type: '2.5.4.10', value: '1', stringType: 'numeric' }, 'DirectoryString'],
    ] as const)('should refuse %s, which the syntax of the attribute excludes', (_what, attribute, expected) => {
        expect(() => encodeNameAttribute(attribute))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining(expected) }));
    });

    it.each([
        ['a three-letter countryName', { type: '2.5.4.6', value: 'USA' }, 'exactly 2'],
        ['an empty countryName', { type: '2.5.4.6', value: '' }, 'exactly 2'],
        ['a 65-character commonName', { type: CN, value: 'x'.repeat(65) }, '1 to 64'],
        ['an empty commonName', { type: CN, value: '' }, '1 to 64'],
        ['a 65-character serialNumber', { type: '2.5.4.5', value: '1'.repeat(65) }, '1 to 64'],
        ['a 256-character emailAddress', { type: '1.2.840.113549.1.9.1', value: 'a'.repeat(256) }, '1 to 255'],
    ] as const)('should refuse %s, outside the ub-* bounds of Appendix A', (_what, attribute, bounds) => {
        expect(() => encodeNameAttribute(attribute))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining(bounds) }));
    });

    it('should name an ISO 3166 code in the countryName refusal', () => {
        expect(() => encodeNameAttribute({ type: '2.5.4.6', value: 'USA' })).toThrow(expect.objectContaining({ message: expect.stringContaining('ISO 3166') }));
        expect(() => encodeNameAttribute({ type: CN, value: '' })).toThrow(expect.objectContaining({ message: expect.not.stringContaining('ISO 3166') }));
    });

    it('should count a bound in characters, not in UTF-16 units or octets', () => {
        // 64 astral characters: 128 UTF-16 units, 256 octets, and a legal commonName.
        expect(() => encodeNameAttribute({ type: CN, value: '😀'.repeat(64) })).not.toThrow();
        expect(() => encodeNameAttribute({ type: CN, value: '😀'.repeat(65) })).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it('should accept an empty domainComponent and dnQualifier, which Appendix A leaves unbounded', () => {
        expect(hex(encodeNameAttribute({ type: '2.5.4.46', value: '' }))).toBe('3007060355042e1300');
        expect(() => encodeNameAttribute({ type: '0.9.2342.19200300.100.1.25', value: '' })).not.toThrow();
    });

    it('should leave a value given as DER alone, whatever its type — the way to reproduce an existing name', () => {
        // A UTF8String countryName, as a legacy issuer wrote it.
        expect(hex(encodeNameAttribute({ type: '2.5.4.6', value: Uint8Array.of(0x0c, 0x02, 0x55, 0x53) }))).toBe('300906035504060c025553');
    });

    it('should take a value already encoded', () => {
        expect(hex(encodeNameAttribute({ type: CN, value: encodeInteger(1) }))).toBe('30080603550403020101');
    });

    it('should sort a multi-valued RDN canonically, whatever order it was given in', () => {
        const a = encodeDistinguishedName([[{ type: CN, value: 'b' }, { type: '2.5.4.6', value: 'US' }]]);
        const b = encodeDistinguishedName([[{ type: '2.5.4.6', value: 'US' }, { type: CN, value: 'b' }]]);
        expect(hex(a)).toBe(hex(b));
    });

    it('should keep RDNs in the order given — only the SET OF inside one is sorted', () => {
        const country = { type: '2.5.4.6', value: 'US', stringType: 'printable' } as const;
        const common = { type: CN, value: 'Example' } as const;
        expect(hex(encodeDistinguishedName([[country], [common]]))).not.toBe(hex(encodeDistinguishedName([[common], [country]])));
    });

    it('should produce a name parseCertificate can read back', () => {
        const der = encodeDistinguishedName([[{ type: CN, value: 'Example Root' }]]);
        expect(decodeAsn1(der).children).toHaveLength(1);
    });

    it.each([
        ['not an array', 'C=US'],
        ['an array holding a non-array', ['x']],
        ['an array holding an empty RDN', [[]]],
    ])('should refuse a name that is %s', (_what, name) => {
        expect(() => encodeDistinguishedName(name as never)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should refuse a value that is neither a string nor bytes', () => {
        expect(() => encodeNameAttribute({ type: CN, value: 42 as unknown as string }))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should count attributes across RDNs against maxNameAttributes', () => {
        const many = Array.from({ length: 5 }, (_, i) => [{ type: CN, value: `a${String(i)}` }]);
        expect(() => encodeDistinguishedName(many, { limits: { maxNameAttributes: 4 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxNameAttributes' }));
        expect(() => encodeDistinguishedName(many, { limits: { maxNameAttributes: 5 } })).not.toThrow();
    });
});

describe('encodeValidity', () => {
    it('should follow the RFC 5280 §4.1.2.5 UTCTime / GeneralizedTime switch at 2050', () => {
        const der = encodeValidity(Date.UTC(2026, 0, 1), Date.UTC(2051, 0, 1));
        // 17 = UTCTime, 18 = GeneralizedTime.
        expect(hex(der)).toBe('3020170d3236303130313030303030305a180f32303531303130313030303030305a');
    });

    it('should refuse an inverted window — valid for a negative interval is valid nowhere', () => {
        expect(() => encodeValidity(Date.UTC(2027, 0, 1), Date.UTC(2026, 0, 1)))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('precedes') }));
    });

    it('should accept a zero-length window, which is unusual but not malformed', () => {
        expect(() => encodeValidity(Date.UTC(2026, 0, 1), Date.UTC(2026, 0, 1))).not.toThrow();
    });

    it.each([['NaN', Number.NaN], ['Infinity', Number.POSITIVE_INFINITY]])('should refuse %s', (_what, value) => {
        expect(() => encodeValidity(value, Date.UTC(2026, 0, 1))).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });
});

describe('encodeExtension and encodeExtensions', () => {
    it('should omit critical when it is false, as DER requires of a DEFAULT', () => {
        const value = Uint8Array.of(0x05, 0x00);
        expect(hex(encodeExtension({ oid: '2.5.29.19', value }))).not.toContain('0101ff');
    });

    it('should write critical when it is true', () => {
        expect(hex(encodeExtension({ oid: '2.5.29.19', critical: true, value: Uint8Array.of(0x05, 0x00) }))).toContain('0101ff');
    });

    it('should refuse the same OID twice — which instance a verifier reads is undefined', () => {
        const value = Uint8Array.of(0x05, 0x00);
        expect(() => encodeExtensions([{ oid: '2.5.29.19', value }, { oid: '2.5.29.19', value }]))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('twice') }));
    });

    it('should refuse a value that is not bytes', () => {
        expect(() => encodeExtension({ oid: '2.5.29.19', value: 'x' as unknown as Uint8Array }))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should bound the count by maxExtensions', () => {
        const many = Array.from({ length: 3 }, (_, i) => ({ oid: `2.5.29.${String(i + 10)}`, value: Uint8Array.of(0x05, 0x00) }));
        expect(() => encodeExtensions(many, { limits: { maxExtensions: 2 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxExtensions' }));
        expect(DEFAULT_PKI_LIMITS.maxExtensions).toBeGreaterThan(3);
        expect(() => encodeExtensions(many)).not.toThrow();
    });
});

describe('the extension values', () => {
    it('should omit cA when false — an end-entity basicConstraints is an empty SEQUENCE', () => {
        expect(hex(encodeBasicConstraints({ cA: false }))).toBe('3000');
        expect(hex(encodeBasicConstraints({ cA: true }))).toBe('30030101ff');
        expect(hex(encodeBasicConstraints({ cA: true, pathLenConstraint: 0 }))).toBe('30060101ff020100');
    });

    it('should refuse a pathLenConstraint on an end entity, which constrains no path', () => {
        expect(() => encodeBasicConstraints({ cA: false, pathLenConstraint: 1 }))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('cA is true') }));
    });

    it('should refuse a negative or fractional pathLenConstraint', () => {
        expect(() => encodeBasicConstraints({ cA: true, pathLenConstraint: -1 })).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        expect(() => encodeBasicConstraints({ cA: true, pathLenConstraint: 1.5 })).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it('should map every KeyUsage name of RFC 5280 §4.2.1.3 to its bit', () => {
        expect([...KEY_USAGE_BITS.keys()]).toEqual([
            'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
            'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
        ]);
        expect(hex(encodeKeyUsage(['keyCertSign', 'cRLSign']))).toBe('03020106');
    });

    it('should keep KEY_USAGE_BITS read-only at runtime, and the encoder out of its reach', () => {
        expect(KEY_USAGE_BITS).toBeInstanceOf(Map);
        expect(Object.isFrozen(KEY_USAGE_BITS)).toBe(true);
        const mutable = KEY_USAGE_BITS as Map<string, number>;
        expect(() => mutable.set('evilUsage', 3)).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('read-only') }));
        expect(() => mutable.delete('digitalSignature')).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        expect(() => { mutable.clear(); }).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        expect(KEY_USAGE_BITS.size).toBe(9);
        // Map.prototype.set.call reaches the internal slot of the public copy;
        // the encoder reads its own table, so the injection changes nothing.
        Map.prototype.set.call(KEY_USAGE_BITS, 'evilUsage', 3);
        try {
            expect(() => encodeKeyUsage(['evilUsage'])).toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION' }));
        } finally {
            Map.prototype.delete.call(KEY_USAGE_BITS, 'evilUsage');
        }
    });

    it('should refuse a usage RFC 5280 does not define', () => {
        expect(() => encodeKeyUsage(['signCertificates']))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION', message: expect.stringContaining('digitalSignature') }));
    });

    it('should refuse an empty extendedKeyUsage, which permits nothing', () => {
        expect(() => encodeExtendedKeyUsage([])).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        expect(hex(encodeExtendedKeyUsage(['1.3.6.1.5.5.7.3.1']))).toBe('300a06082b06010505070301');
    });

    it('should write the key identifiers in their two different shapes', () => {
        const id = Uint8Array.of(0xab, 0xcd);
        // subjectKeyIdentifier is a bare OCTET STRING; authorityKeyIdentifier
        // is a SEQUENCE whose [0] is that OCTET STRING re-tagged in place.
        expect(hex(encodeSubjectKeyIdentifier(id))).toBe('0402abcd');
        expect(hex(encodeAuthorityKeyIdentifier(id))).toBe('30048002abcd');
    });

    it('should tag every text GeneralName implicitly, so each stays primitive', () => {
        const der = encodeSubjectAltName([
            { kind: 'dNSName', value: 'a.example' },
            { kind: 'rfc822Name', value: 'x@a.example' },
            { kind: 'uniformResourceIdentifier', value: 'https://a.example/' },
        ]);
        const tags = decodeAsn1(der).children.map((c) => `${c.tagNumber}:${String(c.constructed)}`);
        expect(tags).toEqual(['2:false', '1:false', '6:false']);
    });

    it('should tag a directoryName explicitly, because its content is constructed', () => {
        const name = encodeDistinguishedName([[{ type: CN, value: 'a' }]]);
        const der = encodeSubjectAltName([{ kind: 'directoryNameDer', value: name }]);
        const first = decodeAsn1(der).children[0];
        expect(first?.tagNumber).toBe(4);
        expect(first?.constructed).toBe(true);
    });

    it('should refuse an empty subjectAltName and an unknown name form', () => {
        expect(() => encodeSubjectAltName([])).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        expect(() => encodeSubjectAltName([{ kind: 'x400Address', value: 'nope' } as never]))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION' }));
    });

    it('should write an iPAddress in network byte order, both families', () => {
        // [7] IMPLICIT OCTET STRING, so the tag is replaced and the value
        // stays primitive: 87 04 for IPv4, 87 10 for IPv6.
        const v4 = encodeSubjectAltName([{ kind: 'iPAddress', value: Uint8Array.of(192, 0, 2, 1) }]);
        expect(hex(v4)).toBe('30068704c0000201');
        const v6 = encodeSubjectAltName([{ kind: 'iPAddress', value: Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) }]);
        expect(hex(v6)).toBe('3012871020010db8000000000000000000000001');
    });

    it.each([
        { name: 'three octets', value: Uint8Array.of(10, 0, 1) },
        { name: 'the 8-octet nameConstraints form', value: new Uint8Array(8) },
        { name: 'the 32-octet nameConstraints form', value: new Uint8Array(32) },
    ])('should refuse an iPAddress of $name, which means nothing in a subjectAltName', ({ value }) => {
        expect(() => encodeSubjectAltName([{ kind: 'iPAddress', value }]))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION', message: expect.stringContaining('nameConstraints') }));
    });

    it('should refuse an iPAddress that is not bytes at all', () => {
        expect(() => encodeSubjectAltName([{ kind: 'iPAddress', value: '192.0.2.1' as never }]))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should write a registeredID as an implicitly tagged OID', () => {
        expect(hex(encodeSubjectAltName([{ kind: 'registeredID', value: '1.2.3' }]))).toBe('300488022a03');
    });
});

describe('encodeAttribute and encodeSubjectPublicKeyInfo', () => {
    it('should sort an attribute’s values canonically', () => {
        const a = encodeAttribute('1.2.3', [Uint8Array.of(0x02, 0x01, 0x02), Uint8Array.of(0x02, 0x01, 0x01)]);
        const b = encodeAttribute('1.2.3', [Uint8Array.of(0x02, 0x01, 0x01), Uint8Array.of(0x02, 0x01, 0x02)]);
        expect(hex(a)).toBe(hex(b));
    });

    it('should encode a SubjectPublicKeyInfo whose BIT STRING has no unused bits', () => {
        const der = encodeSubjectPublicKeyInfo('1.3.101.112', new Uint8Array(32).fill(0x11));
        const bitString = decodeAsn1(der).children[1];
        expect(bitString?.tagNumber).toBe(3);
        expect(bitString?.content[0]).toBe(0);
    });

    it('should refuse key bits that are not bytes', () => {
        expect(() => encodeSubjectPublicKeyInfo('1.3.101.112', 'x' as unknown as Uint8Array))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});
