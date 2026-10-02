import { describe, it, expect } from 'vitest';
import { decodeExtensionValue, getExtension } from '../../src/x509/x509-extensions.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { DecodeExtensionValueOptions, Extension } from '../../src/types/x509-types.js';
import {
    BASIC_CONSTRAINTS_CA,
    bitString,
    boolean,
    certificate,
    context,
    explicit,
    extension,
    ia5,
    integer,
    name,
    nullValue,
    octetString,
    oid,
    printable,
    set,
    utf8,
} from '../helpers/cert-builder.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

const QUIET: DecodeExtensionValueOptions = { onDiagnostic: () => undefined };

const OID = {
    basicConstraints: '2.5.29.19',
    keyUsage: '2.5.29.15',
    extKeyUsage: '2.5.29.37',
    subjectAltName: '2.5.29.17',
    issuerAltName: '2.5.29.18',
    subjectKeyIdentifier: '2.5.29.14',
    authorityKeyIdentifier: '2.5.29.35',
    nameConstraints: '2.5.29.30',
    certificatePolicies: '2.5.29.32',
    policyMappings: '2.5.29.33',
    policyConstraints: '2.5.29.36',
    inhibitAnyPolicy: '2.5.29.54',
    authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
    subjectInfoAccess: '1.3.6.1.5.5.7.1.11',
    crlDistributionPoints: '2.5.29.31',
    freshestCRL: '2.5.29.46',
    sct: '1.3.6.1.4.1.11129.2.4.2',
    ocspNoCheck: '1.3.6.1.5.5.7.48.1.5',
} as const;

const CPS = '1.3.6.1.5.5.7.2.1';
const USER_NOTICE = '1.3.6.1.5.5.7.2.2';
const DV = '2.23.140.1.2.1';
const OV = '2.23.140.1.2.2';

const decode = (extensionOid: string, value: Uint8Array, options: DecodeExtensionValueOptions = QUIET): Extension =>
    decodeExtensionValue(extensionOid, value, options);

function thrown(fn: () => unknown): unknown {
    try {
        fn();
    } catch (error) {
        return error;
    }
    throw new Error('expected a throw');
}

function codeOf(fn: () => unknown): string {
    const error = thrown(fn);
    if (error instanceof PkiError) return error.code;
    throw error;
}

function diagnosticsOf(extensionOid: string, value: Uint8Array, critical = false): string[] {
    const seen: string[] = [];
    decodeExtensionValue(extensionOid, value, { critical, onDiagnostic: (d) => { seen.push(d.code); } });
    return seen;
}

const malformedCode = (extensionOid: string, value: Uint8Array): string => codeOf(() => decode(extensionOid, value));

describe('decodeExtensionValue', () => {
    describe('basicConstraints', () => {
        it('should read cA and pathLenConstraint', () => {
            expect(decode(OID.basicConstraints, sequence(boolean(true), integer([3])), { critical: true }))
                .toMatchObject({ kind: 'basicConstraints', critical: true, cA: true, pathLenConstraint: 3 });
        });

        it('should read an empty sequence as an end entity', () => {
            expect(decode(OID.basicConstraints, sequence())).toMatchObject({ cA: false, pathLenConstraint: undefined });
        });

        it('should report pathLenConstraint without cA', () => {
            expect(diagnosticsOf(OID.basicConstraints, sequence(integer([0])))).toEqual(['PKI_DIAG_PATHLEN_WITHOUT_CA']);
        });

        it('should read an explicit FALSE with a diagnostic (the RFC 8410 §10.2 example encodes one)', () => {
            const value = sequence(boolean(false));
            expect(decode(OID.basicConstraints, value)).toMatchObject({ cA: false });
            expect(diagnosticsOf(OID.basicConstraints, value)).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
        });

        it.each<[string, Uint8Array]>([
            ['three values', sequence(boolean(true), integer([1]), integer([1]))],
            ['a pathLenConstraint that is not an INTEGER', sequence(boolean(true), octetString([1]))],
            ['a negative pathLenConstraint', sequence(boolean(true), integer([0xff]))],
            ['a value that is not a SEQUENCE', integer([1])],
            ['bytes after the value', concat(sequence(), [0x00])],
            ['an empty value', Uint8Array.of()],
            ['a truncated value', Uint8Array.of(0x30, 0x03, 0x01)],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.basicConstraints, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('keyUsage', () => {
        it('should name the asserted bits in order', () => {
            expect(decode(OID.keyUsage, bitString([0x86], 1))).toMatchObject({ kind: 'keyUsage', usages: ['digitalSignature', 'keyCertSign', 'cRLSign'] });
        });

        it('should read decipherOnly, the ninth bit', () => {
            expect(decode(OID.keyUsage, bitString([0x00, 0x80], 7))).toMatchObject({ usages: ['decipherOnly'] });
        });

        it('should report a key usage that asserts no bit', () => {
            expect(diagnosticsOf(OID.keyUsage, bitString([]), true)).toEqual(['PKI_DIAG_KEY_USAGE_EMPTY']);
        });

        it('should report a trailing zero bit', () => {
            expect(diagnosticsOf(OID.keyUsage, bitString([0x80]), true)).toEqual(['PKI_DIAG_NAMED_BITS_TRAILING_ZERO']);
        });

        it.each<[string, Uint8Array]>([
            ['a bit beyond decipherOnly', bitString([0x00, 0x40], 6)],
            ['a value that is not a BIT STRING', octetString([0x80])],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.keyUsage, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('extKeyUsage', () => {
        it('should read every purpose', () => {
            expect(decode(OID.extKeyUsage, sequence(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2'))))
                .toMatchObject({ kind: 'extendedKeyUsage', purposes: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'] });
        });

        it.each<[string, Uint8Array]>([
            ['an empty list', sequence()],
            ['a purpose that is not an OID', sequence(integer([1]))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.extKeyUsage, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('alternative names', () => {
        const NAMES = sequence(context(2, false, ascii('a.example')), context(7, false, [192, 0, 2, 1]));

        it.each<[string, string]>([
            [OID.subjectAltName, 'subjectAltName'],
            [OID.issuerAltName, 'issuerAltName'],
        ])('should read the names of %s', (extensionOid, kind) => {
            const decoded = decode(extensionOid, NAMES);
            expect(decoded.kind).toBe(kind);
            expect('names' in decoded ? decoded.names.map((n) => n.kind) : []).toEqual(['dNSName', 'iPAddress']);
        });

        it.each([OID.subjectAltName, OID.issuerAltName])('should report an empty %s, and only an empty one', (extensionOid) => {
            expect(diagnosticsOf(extensionOid, sequence())).toEqual(['PKI_DIAG_SAN_EMPTY']);
            expect(diagnosticsOf(extensionOid, NAMES)).toEqual([]);
        });

        it('should refuse a malformed GeneralName with the GeneralName code', () => {
            expect(codeOf(() => decode(OID.subjectAltName, sequence(context(7, false, [1, 2, 3]))))).toBe('PKI_X509_GENERAL_NAME_INVALID');
        });
    });

    describe('key identifiers', () => {
        it('should read a subjectKeyIdentifier', () => {
            const decoded = decode(OID.subjectKeyIdentifier, octetString([1, 2, 3]));
            expect(decoded.kind === 'subjectKeyIdentifier' ? [...decoded.keyIdentifier] : []).toEqual([1, 2, 3]);
        });

        it('should refuse a subjectKeyIdentifier that is not an OCTET STRING', () => {
            expect(malformedCode(OID.subjectKeyIdentifier, integer([1]))).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should read the three fields of an authorityKeyIdentifier', () => {
            const decoded = decode(OID.authorityKeyIdentifier, sequence(
                context(0, false, [1, 2]),
                context(1, true, explicit(4, name([['2.5.4.3', utf8('CA')]]))),
                context(2, false, [0x05]),
            ));
            expect(decoded).toMatchObject({ kind: 'authorityKeyIdentifier', authorityCertSerialNumber: { value: 5n, hex: '05' } });
            if (decoded.kind !== 'authorityKeyIdentifier') throw new Error('unexpected kind');
            expect([...(decoded.keyIdentifier ?? [])]).toEqual([1, 2]);
            expect(decoded.authorityCertIssuer?.map((n) => n.kind)).toEqual(['directoryName']);
        });

        it('should read a keyIdentifier alone without diagnostic', () => {
            const value = sequence(context(0, false, [1]));
            expect(decode(OID.authorityKeyIdentifier, value)).toMatchObject({ authorityCertIssuer: undefined, authorityCertSerialNumber: undefined });
            expect(diagnosticsOf(OID.authorityKeyIdentifier, value)).toEqual([]);
        });

        it.each<[string, Uint8Array]>([
            ['an issuer without serial', sequence(context(1, true, context(2, false, ascii('ca.example'))))],
            ['a serial without issuer', sequence(context(2, false, [0x05]))],
        ])('should report %s', (_, value) => {
            expect(diagnosticsOf(OID.authorityKeyIdentifier, value)).toEqual(['PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED']);
        });

        it.each<[string, Uint8Array]>([
            ['fields out of order', sequence(context(2, false, [0x05]), context(0, false, [1]))],
            ['a universal field', sequence(octetString([1]))],
            ['a field [3]', sequence(context(3, false, [1]))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.authorityKeyIdentifier, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should refuse a primitive authorityCertIssuer', () => {
            expect(codeOf(() => decode(OID.authorityKeyIdentifier, sequence(context(1, false, [1]), context(2, false, [1]))))).toBe('PKI_X509_GENERAL_NAME_INVALID');
        });
    });

    describe('nameConstraints', () => {
        it('should read permitted and excluded subtrees', () => {
            const decoded = decode(OID.nameConstraints, sequence(
                context(0, true, sequence(context(2, false, ascii('example.com')))),
                context(1, true, sequence(context(7, false, [10, 0, 0, 0, 255, 0, 0, 0]))),
            ), { critical: true });
            expect(decoded).toMatchObject({
                kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'dNSName', value: 'example.com' }, minimum: 0, maximum: undefined }],
                excludedSubtrees: [{ base: { kind: 'iPAddress', address: '10.0.0.0', mask: '255.0.0.0' } }],
            });
        });

        it('should read the bounds of a subtree', () => {
            expect(decode(OID.nameConstraints, sequence(context(0, true, sequence(context(2, false, ascii('a')), context(0, false, [1]), context(1, false, [3]))))))
                .toMatchObject({ permittedSubtrees: [{ minimum: 1, maximum: 3 }] });
        });

        it('should refuse an extension that constrains nothing', () => {
            // RFC 5280 4.2.1.10: 'Conforming CAs MUST NOT issue certificates
            // where name constraints is an empty sequence.' One that constrains
            // nothing while appearing to constrain everything is read as 'no
            // opinion' by one verifier and 'nothing permitted' by another, and
            // two readings of one encoding is what DER exists to remove.
            expect(malformedCode(OID.nameConstraints, sequence())).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should report name constraints that are not critical', () => {
            expect(diagnosticsOf(OID.nameConstraints, sequence(context(0, true, sequence(context(2, false, ascii('a')))))))
                .toEqual(['PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL']);
        });

        it('should read an explicit minimum of 0 with a diagnostic', () => {
            expect(diagnosticsOf(OID.nameConstraints, sequence(context(0, true, sequence(context(2, false, ascii('a')), context(0, false, [0])))), true))
                .toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
        });

        it.each<[string, Uint8Array]>([
            ['an empty subtree list', sequence(context(0, true, []))],
            ['a subtree without base', sequence(context(0, true, sequence()))],
            ['a primitive subtree list', sequence(context(0, false, [1]))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.nameConstraints, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should enforce maxGeneralNames on the subtrees', () => {
            const subtree = sequence(context(2, false, ascii('a')));
            const error = thrown(() => decode(OID.nameConstraints, sequence(context(0, true, concat(subtree, subtree))), { limits: { maxGeneralNames: 1 } }));
            expect(error).toBeInstanceOf(PkiLimitError);
        });
    });

    describe('certificatePolicies', () => {
        const policies = (...infos: Uint8Array[]): Uint8Array => sequence(...infos);
        const withQualifier = (qualifierOid: string, qualifier: Uint8Array): Uint8Array =>
            policies(sequence(oid(OV), sequence(sequence(oid(qualifierOid), qualifier))));

        it('should read a policy without qualifiers', () => {
            expect(decode(OID.certificatePolicies, policies(sequence(oid(DV)))))
                .toMatchObject({ kind: 'certificatePolicies', policies: [{ policyIdentifier: DV, qualifiers: [] }] });
        });

        it('should read a CPS qualifier', () => {
            expect(decode(OID.certificatePolicies, withQualifier(CPS, ia5('https://cps.example'))))
                .toMatchObject({ policies: [{ qualifiers: [{ kind: 'cps', oid: CPS, uri: 'https://cps.example' }] }] });
        });

        it('should read a user notice with a reference and a text', () => {
            const decoded = decode(OID.certificatePolicies, withQualifier(USER_NOTICE,
                sequence(sequence(utf8('Org'), sequence(integer([1]), integer([2]))), utf8('Text'))));
            expect(decoded).toMatchObject({
                policies: [{ qualifiers: [{ kind: 'userNotice', noticeRef: { organization: { value: 'Org' }, noticeNumbers: [1n, 2n] }, explicitText: { value: 'Text' } }] }],
            });
        });

        it('should read an empty user notice and one with only a text', () => {
            expect(decode(OID.certificatePolicies, withQualifier(USER_NOTICE, sequence())))
                .toMatchObject({ policies: [{ qualifiers: [{ noticeRef: undefined, explicitText: undefined }] }] });
            expect(decode(OID.certificatePolicies, withQualifier(USER_NOTICE, sequence(ia5('Hi')))))
                .toMatchObject({ policies: [{ qualifiers: [{ explicitText: { stringType: 'ia5', value: 'Hi' } }] }] });
        });

        it('should keep a qualifier of another type undecoded', () => {
            expect(decode(OID.certificatePolicies, withQualifier('1.2.3.4', integer([7]))))
                .toMatchObject({ policies: [{ qualifiers: [{ kind: 'unknown', oid: '1.2.3.4', qualifier: { tagNumber: 2 } }] }] });
        });

        it('should report a policy listed twice', () => {
            expect(diagnosticsOf(OID.certificatePolicies, policies(sequence(oid(DV)), sequence(oid(DV))))).toEqual(['PKI_DIAG_POLICY_DUPLICATE']);
        });

        it.each<[string, Uint8Array]>([
            ['an empty list', policies()],
            ['a policy of three values', policies(sequence(oid(DV), sequence(), nullValue()))],
            ['a policy identifier that is not an OID', policies(sequence(integer([1])))],
            ['an empty qualifier list', policies(sequence(oid(DV), sequence()))],
            ['a qualifier of one value', policies(sequence(oid(DV), sequence(sequence(oid(CPS)))))],
            ['a CPS pointer that is not an IA5String', withQualifier(CPS, utf8('https://cps.example'))],
            ['a CPS pointer that is not a string', withQualifier(CPS, integer([1]))],
            ['an explicit text that is not a DisplayText', withQualifier(USER_NOTICE, sequence(printable('Text')))],
            ['an explicit text that is not a string', withQualifier(USER_NOTICE, sequence(integer([1])))],
            ['a user notice of three values', withQualifier(USER_NOTICE, sequence(utf8('a'), utf8('b'), utf8('c')))],
            ['a notice reference of one value', withQualifier(USER_NOTICE, sequence(sequence(utf8('Org'))))],
            ['a notice number that is not an INTEGER', withQualifier(USER_NOTICE, sequence(sequence(utf8('Org'), sequence(octetString([1])))))],
            ['a user notice that is not a SEQUENCE', withQualifier(USER_NOTICE, utf8('Text'))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.certificatePolicies, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should enforce maxPolicies', () => {
            const error = thrown(() => decode(OID.certificatePolicies, policies(sequence(oid(DV)), sequence(oid(OV))), { limits: { maxPolicies: 1 } }));
            expect(error).toBeInstanceOf(PkiLimitError);
            expect(error).toMatchObject({ limit: 'maxPolicies' });
        });
    });

    describe('policy mappings, constraints and inhibitAnyPolicy', () => {
        it('should read policy mappings', () => {
            expect(decode(OID.policyMappings, sequence(sequence(oid(DV), oid(OV)))))
                .toMatchObject({ kind: 'policyMappings', mappings: [{ issuerDomainPolicy: DV, subjectDomainPolicy: OV }] });
        });

        it.each<[string, Uint8Array]>([
            ['an empty mapping list', sequence()],
            ['a mapping of one policy', sequence(sequence(oid(DV)))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.policyMappings, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should read policy constraints', () => {
            expect(decode(OID.policyConstraints, sequence(context(0, false, [0]), context(1, false, [2]))))
                .toMatchObject({ kind: 'policyConstraints', requireExplicitPolicy: 0, inhibitPolicyMapping: 2 });
        });

        it('should say nothing about criticality when the CA marked it critical, as §4.2.1.11 asks', () => {
            expect(diagnosticsOf(OID.policyConstraints, sequence(context(0, false, [0])), true)).toEqual([]);
        });

        it('should report empty policy constraints', () => {
            // …and that the extension is not critical, which §4.2.1.11 also
            // requires of a conforming CA. `diagnosticsOf` builds a
            // non-critical extension, so both concerns apply to this one.
            expect(diagnosticsOf(OID.policyConstraints, sequence()))
                .toEqual(['PKI_DIAG_POLICY_CONSTRAINTS_EMPTY', 'PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL']);
        });

        it('should refuse a negative SkipCerts', () => {
            expect(malformedCode(OID.policyConstraints, sequence(context(0, false, [0xff])))).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should read inhibitAnyPolicy and refuse a value that is not an INTEGER', () => {
            expect(decode(OID.inhibitAnyPolicy, integer([1]))).toMatchObject({ kind: 'inhibitAnyPolicy', skipCerts: 1 });
            expect(malformedCode(OID.inhibitAnyPolicy, octetString([1]))).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('information access', () => {
        const OCSP = sequence(sequence(oid('1.3.6.1.5.5.7.48.1'), context(6, false, ascii('http://ocsp.example'))));

        it.each<[string, string]>([
            [OID.authorityInfoAccess, 'authorityInfoAccess'],
            [OID.subjectInfoAccess, 'subjectInfoAccess'],
        ])('should read the descriptions of %s', (extensionOid, kind) => {
            expect(decode(extensionOid, OCSP)).toMatchObject({
                kind,
                descriptions: [{ accessMethod: '1.3.6.1.5.5.7.48.1', accessLocation: { kind: 'uniformResourceIdentifier', value: 'http://ocsp.example' } }],
            });
        });

        it.each<[string, Uint8Array]>([
            ['an empty list', sequence()],
            ['a description of one value', sequence(sequence(oid('1.3.6.1.5.5.7.48.1')))],
            ['an access method that is not an OID', sequence(sequence(integer([1]), context(6, false, ascii('x'))))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.authorityInfoAccess, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('distribution points', () => {
        const URI = context(6, false, ascii('http://crl.example/root.crl'));

        it('should read a fullName', () => {
            expect(decode(OID.crlDistributionPoints, sequence(sequence(explicit(0, context(0, true, URI))))))
                .toMatchObject({ kind: 'crlDistributionPoints', points: [{ fullName: [{ value: 'http://crl.example/root.crl' }], reasons: undefined, cRLIssuer: undefined }] });
        });

        it('should read a nameRelativeToCRLIssuer', () => {
            const decoded = decode(OID.crlDistributionPoints, sequence(sequence(explicit(0, context(1, true, sequence(oid('2.5.4.3'), utf8('CRL1')))))));
            expect(decoded).toMatchObject({ points: [{ fullName: undefined, nameRelativeToCRLIssuer: [{ type: '2.5.4.3', value: { value: 'CRL1' } }] }] });
        });

        it('should read reasons and cRLIssuer in freshestCRL', () => {
            expect(decode(OID.freshestCRL, sequence(sequence(context(1, false, [0x05, 0x60]), context(2, true, URI)))))
                .toMatchObject({ kind: 'freshestCRL', points: [{ reasons: ['keyCompromise', 'cACompromise'], cRLIssuer: [{ kind: 'uniformResourceIdentifier' }] }] });
        });

        it('should read an empty distribution point', () => {
            expect(decode(OID.crlDistributionPoints, sequence(sequence()))).toMatchObject({ points: [{ fullName: undefined, nameRelativeToCRLIssuer: undefined }] });
        });

        it.each<[string, Uint8Array]>([
            ['an empty list', sequence()],
            ['a distribution point that is not a SEQUENCE', sequence(integer([1]))],
            ['a name of two choices', sequence(sequence(explicit(0, context(0, true, URI), context(1, true, sequence(oid('2.5.4.3'), utf8('x'))))))],
            ['a name under the choice [2]', sequence(sequence(explicit(0, context(2, true, URI))))],
            ['a primitive name', sequence(sequence(context(0, false, [1])))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(OID.crlDistributionPoints, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('SCT list and ocspNoCheck', () => {
        it('should keep the SCT list in its TLS encoding', () => {
            const decoded = decode(OID.sct, octetString([0x00, 0x02, 0xaa, 0xbb]));
            expect(decoded.kind === 'signedCertificateTimestampList' ? [...decoded.list] : []).toEqual([0x00, 0x02, 0xaa, 0xbb]);
        });

        it('should read ocspNoCheck', () => {
            expect(decode(OID.ocspNoCheck, nullValue())).toMatchObject({ kind: 'ocspNoCheck' });
        });

        it.each<[string, string, Uint8Array]>([
            ['an SCT list that is not an OCTET STRING', OID.sct, integer([1])],
            ['an ocspNoCheck with content', OID.ocspNoCheck, universal(5, [0x01])],
            ['an ocspNoCheck that is not NULL', OID.ocspNoCheck, integer([1])],
        ])('should refuse %s', (_, extensionOid, value) => {
            expect(malformedCode(extensionOid, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('subjectDirectoryAttributes (RFC 5280 §4.2.1.8)', () => {
        const SDA = '2.5.29.9';
        const DATE_OF_BIRTH = '1.3.6.1.5.5.7.9.1';
        const CITIZENSHIP = '1.3.6.1.5.5.7.9.4';
        const born = universal(24, ascii('19700101120000Z'));
        const attribute = (type: string, ...values: Uint8Array[]): Uint8Array => sequence(oid(type), set(...values));

        it('should read each attribute with its type and every value as DER, in encoded order', () => {
            const value = sequence(attribute(DATE_OF_BIRTH, born), attribute(CITIZENSHIP, printable('FR'), printable('DE')));
            const decoded = decode(SDA, value);
            expect(decoded.kind).toBe('subjectDirectoryAttributes');
            const attributes = decoded.kind === 'subjectDirectoryAttributes' ? decoded.attributes : [];
            expect(attributes.map((a) => a.oid)).toEqual([DATE_OF_BIRTH, CITIZENSHIP]);
            expect(attributes[0]?.values).toEqual([born]);
            expect(attributes[1]?.values).toEqual([printable('FR'), printable('DE')]);
            expect(attributes[1]?.der).toEqual(attribute(CITIZENSHIP, printable('FR'), printable('DE')));
            expect(Object.isFrozen(attributes) && Object.isFrozen(attributes[0]) && Object.isFrozen(attributes[0]?.values)).toBe(true);
            expect(diagnosticsOf(SDA, value)).toEqual([]);
        });

        it('should report a critical subjectDirectoryAttributes, which RFC 5280 forbids — no longer as an unknown extension', () => {
            expect(diagnosticsOf(SDA, sequence(attribute(DATE_OF_BIRTH, born)), true)).toEqual(['PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL']);
        });

        it.each<[string, Uint8Array]>([
            ['an empty sequence — SIZE (1..MAX)', sequence()],
            ['a value that is not a SEQUENCE', set(attribute(DATE_OF_BIRTH, born))],
            ['an attribute that is not a SEQUENCE', sequence(set(oid(DATE_OF_BIRTH), set(born)))],
            ['an attribute of one field', sequence(sequence(oid(DATE_OF_BIRTH)))],
            ['an attribute of three fields', sequence(sequence(oid(DATE_OF_BIRTH), set(born), set(born)))],
            ['an attribute type that is not an OID', sequence(sequence(integer([1]), set(born)))],
            ['values that are not a SET', sequence(sequence(oid(DATE_OF_BIRTH), sequence(born)))],
            ['an attribute with no value — "at least one value is required"', sequence(attribute(DATE_OF_BIRTH))],
        ])('should refuse %s', (_, value) => {
            expect(malformedCode(SDA, value)).toBe('PKI_X509_EXTENSION_MALFORMED');
        });

        it('should bound the attributes and the values of each by maxAttributes', () => {
            const three = sequence(attribute(DATE_OF_BIRTH, born), attribute(CITIZENSHIP, printable('FR')), attribute(CITIZENSHIP, printable('DE')));
            expect(thrown(() => decode(SDA, three, { ...QUIET, limits: { maxAttributes: 2 } }))).toBeInstanceOf(PkiLimitError);
            const manyValues = sequence(attribute(CITIZENSHIP, printable('FR'), printable('DE'), printable('IT')));
            expect(thrown(() => decode(SDA, manyValues, { ...QUIET, limits: { maxAttributes: 2 } }))).toMatchObject({ limit: 'maxAttributes' });
            expect(() => decode(SDA, three, { ...QUIET, limits: { maxAttributes: 3 } })).not.toThrow();
        });
    });

    describe('unknown extensions', () => {
        it('should keep an unknown extension without diagnostic', () => {
            expect(decode('1.2.3.4', octetString([1]))).toMatchObject({ kind: 'unknown', oid: '1.2.3.4', critical: false });
            expect(diagnosticsOf('1.2.3.4', octetString([1]))).toEqual([]);
        });

        it('should report an unknown critical extension', () => {
            expect(diagnosticsOf('1.2.3.4', octetString([1]), true)).toEqual(['PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION']);
        });
    });

    describe('arguments', () => {
        it.each<[string, () => unknown, string]>([
            ['an OID that is not a string', () => decodeExtensionValue(2529 as unknown as string, sequence()), 'PKI_INVALID_INPUT'],
            ['an OID X.660 does not allow', () => decodeExtensionValue('3.1', sequence()), 'PKI_OID_INVALID'],
            ['a value that is not a Uint8Array', () => decodeExtensionValue(OID.basicConstraints, [0x30, 0x00] as unknown as Uint8Array), 'PKI_INVALID_INPUT'],
            ['a critical option that is not a boolean', () => decodeExtensionValue(OID.basicConstraints, sequence(), { critical: 'yes' as unknown as boolean }), 'PKI_INVALID_OPTION'],
        ])('should refuse %s', (_, call, code) => {
            expect(codeOf(call)).toBe(code);
        });
    });
});

describe('extensions in parseCertificate', () => {
    const SAN = extension(OID.subjectAltName, sequence(context(2, false, ascii('leaf.example'))));
    const der = certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, SAN))] });

    it('should return one typed extension with getExtension', () => {
        const cert = parseCertificate(der);
        expect(getExtension(cert, 'subjectAltName')?.names.map((n) => n.kind === 'dNSName' ? n.value : '')).toEqual(['leaf.example']);
        expect(getExtension(cert, 'basicConstraints')?.cA).toBe(true);
        expect(getExtension(cert, 'keyUsage')).toBeUndefined();
    });

    it('should find nothing in a certificate parsed with decodeExtensions: false', () => {
        expect(getExtension(parseCertificate(der, { decodeExtensions: false }), 'subjectAltName')).toBeUndefined();
    });

    it('should refuse getExtension on something that is not a certificate', () => {
        expect(codeOf(() => getExtension(null as unknown as ReturnType<typeof parseCertificate>, 'keyUsage'))).toBe('PKI_INVALID_INPUT');
        // An object, not null: it reaches the extensions check rather than
        // stopping at the null one, which is the other half of the guard.
        expect(codeOf(() => getExtension({} as unknown as ReturnType<typeof parseCertificate>, 'basicConstraints'))).toBe('PKI_INVALID_INPUT');
    });

    it('should report a malformed extension at its absolute offset', () => {
        const bad = octetString(integer([1]));
        const input = certificate({ trailing: [explicit(3, sequence(sequence(oid(OID.basicConstraints), bad)))] });
        const error = thrown(() => parseCertificate(input));
        expect(error).toBeInstanceOf(PkiCertificateError);
        expect(error).toMatchObject({ code: 'PKI_X509_EXTENSION_MALFORMED', path: 'tbsCertificate.extensions[0]', offset: indexOf(input, bad) + 2 });
    });

    it('should decode a segmented extnValue under BER', () => {
        const segmented = sequence(oid(OID.basicConstraints), boolean(true), tlv(0, true, 4, concat(octetString([0x30]), octetString([0x03, 0x01, 0x01, 0xff]))));
        const cert = parseCertificate(certificate({ trailing: [explicit(3, sequence(segmented))] }), { encodingRules: 'ber', onDiagnostic: () => undefined });
        expect(getExtension(cert, 'basicConstraints')?.cA).toBe(true);
    });

    it('should count error offsets inside a segmented extnValue from the joined content (P-07, documented)', () => {
        // Joined: 30 03 04 01 00 — a basicConstraints SEQUENCE holding an OCTET STRING.
        const segments = concat(octetString([0x30, 0x03]), octetString([0x04, 0x01, 0x00]));
        const input = certificate({ trailing: [explicit(3, sequence(sequence(oid(OID.basicConstraints), tlv(0, true, 4, segments))))] });
        const error = thrown(() => parseCertificate(input, { encodingRules: 'ber', onDiagnostic: () => undefined }));
        expect(error).toMatchObject({ code: 'PKI_X509_EXTENSION_MALFORMED', path: 'tbsCertificate.extensions[0].pathLenConstraint', offset: 2 });
        expect(indexOf(input, segments)).toBeGreaterThan(100);
    });
});

function indexOf(haystack: Uint8Array, needle: Uint8Array): number {
    outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
        for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
        return i;
    }
    return -1;
}

describe('certificatePolicies and policyMappings — the structural guards answer at the structure they guard', () => {
    const notice = (...parts: readonly Uint8Array[]): Uint8Array => sequence(sequence(oid(DV), sequence(sequence(oid(USER_NOTICE), sequence(...parts)))));

    it.each([
        ['a context-tagged explicitText', notice(context(0, false, ascii('x'))), 'extnValue[0].policyQualifiers[0].qualifier.explicitText'],
        ['an INTEGER explicitText', notice(integer([1])), 'extnValue[0].policyQualifiers[0].qualifier.explicitText'],
        ['a noticeRef of three values', notice(sequence(utf8('Org'), sequence(integer([1])), utf8('x'))), 'extnValue[0].policyQualifiers[0].qualifier.noticeRef'],
        ['an empty PolicyInformation', sequence(sequence()), 'extnValue[0]'],
        ['a PolicyInformation of three values', sequence(sequence(oid(DV), sequence(sequence(oid(CPS), ia5('http://cps.example/'))), utf8('x'))), 'extnValue[0]'],
    ])('should refuse %s at its own path', (_label, value, path) => {
        expect(thrown(() => decode(OID.certificatePolicies, value))).toMatchObject({ code: 'PKI_X509_EXTENSION_MALFORMED', path });
    });

    it.each([
        ['one value', sequence(sequence(oid(DV)))],
        ['three values', sequence(sequence(oid(DV), oid(OV), oid(DV)))],
    ])('should refuse a policy mapping of %s at the mapping', (_label, value) => {
        expect(thrown(() => decode(OID.policyMappings, value, { critical: true, onDiagnostic: () => undefined })))
            .toMatchObject({ code: 'PKI_X509_EXTENSION_MALFORMED', path: 'extnValue[0]' });
    });
});
