import { describe, expect, it } from 'vitest';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiDiagnosticCode, PkiLimits } from '../../src/types/pki-types.js';
import type { AttributeCertificate } from '../../src/types/attribute-certificate-types.js';
import { parseAttributeCertificate } from '../../src/x509/x509-attribute-certificate.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import {
    ECDSA_SHA256,
    algorithm,
    bitString,
    context,
    explicit,
    extension,
    generalizedTime,
    integer,
    name,
    nullValue,
    octetString,
    oid,
    tbsCertificate,
    certificate,
    utcTime,
    utf8,
} from '../helpers/cert-builder.js';
import {
    AUTHORITY_KEY_ID,
    CA_NAME,
    EXTENSIONS,
    ISSUER_NAME,
    NO_REV_AVAIL,
    OID_AUDIT_IDENTITY,
    OID_NO_REV_AVAIL,
    OID_TARGET_INFORMATION,
    ROLE_ATTRIBUTE,
    TARGET_INFORMATION,
    VALIDITY,
    acInfo,
    attributeCertificate,
    directoryName,
    dnsName,
    generalNames,
    holderByCertificate,
    holderByDigest,
    holderByName,
    implicitSequence,
    issuerSerialComponents,
    objectDigestComponents,
    rfc822Name,
    targetGroup,
    targetName,
    uriName,
    v2Form,
} from '../helpers/attribute-certificate-builder.js';
import { sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The RFC 5755 reader, against attribute certificates assembled from first
 * principles (tests/helpers/attribute-certificate-builder.ts): every field of
 * §4.1, every refusal by code and class, every profile concern of §4.2–§4.3
 * through `onDiagnostic` — and, for a `warning`, under `strict: true`. The
 * attributes of §4.4 are tests/x509/x509-ac-attributes.test.ts.
 */

function parse(der: Uint8Array, limits?: Partial<PkiLimits>): { ac: AttributeCertificate; diagnostics: PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const ac = parseAttributeCertificate(der, { onDiagnostic: (d) => diagnostics.push(d), ...(limits === undefined ? {} : { limits }) });
    return { ac, diagnostics };
}

const codes = (der: Uint8Array): PkiDiagnosticCode[] => parse(der).diagnostics.map((d) => d.code);

function refuses(der: Uint8Array, code: string): void {
    expect(() => parseAttributeCertificate(der, { onDiagnostic: () => undefined })).toThrow(expect.objectContaining({ code }));
    expect(() => parseAttributeCertificate(der, { onDiagnostic: () => undefined })).toThrow(PkiCertificateError);
}

function strictRefuses(der: Uint8Array): void {
    expect(() => parseAttributeCertificate(der, { strict: true })).toThrow(expect.objectContaining({ code: 'PKI_STRICT_DIAGNOSTIC' }));
}

function limitTrips(der: Uint8Array, limits: Partial<PkiLimits>, limit: keyof PkiLimits): void {
    let caught: unknown;
    try {
        parseAttributeCertificate(der, { limits, onDiagnostic: () => undefined });
    } catch (error) {
        caught = error;
    }
    expect(caught).toBeInstanceOf(PkiLimitError);
    expect(caught).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit });
}

describe('parseAttributeCertificate', () => {
    describe('a well-formed v2 attribute certificate (RFC 5755 §4.1)', () => {
        const der = attributeCertificate();
        const { ac, diagnostics } = parse(der);

        it('should read with zero diagnostics', () => {
            expect(diagnostics).toEqual([]);
        });

        it('should expose the envelope as zero-copy views and the version as 2', () => {
            expect(ac.der).toEqual(der);
            expect(ac.tbsDer).toEqual(acInfo());
            expect(ac.version).toBe(2);
            expect(ac.signatureValue.unusedBits).toBe(0);
            expect(ac.signatureAlgorithm.oid).toBe(ECDSA_SHA256);
            expect(ac.tbsSignatureAlgorithm.oid).toBe(ECDSA_SHA256);
            expect(Object.isFrozen(ac)).toBe(true);
        });

        it('should read the holder by baseCertificateID and the v2Form issuer by its one directoryName', () => {
            expect(ac.holder.baseCertificateId?.serial.hex).toBe('10');
            expect(ac.holder.baseCertificateId?.issuer[0]?.kind).toBe('directoryName');
            expect(ac.holder.baseCertificateId?.issuerUid).toBeUndefined();
            expect(ac.holder.entityName).toBeUndefined();
            expect(ac.holder.objectDigestInfo).toBeUndefined();
            expect(ac.issuer.form).toBe('v2Form');
            expect(ac.issuer.name?.der).toEqual(ISSUER_NAME);
            expect(ac.issuer.baseCertificateId).toBeUndefined();
            expect(ac.issuer.objectDigestInfo).toBeUndefined();
            expect(ac.issuer.der).toEqual(v2Form());
        });

        it('should read the serial, the validity, the attributes and the extensions', () => {
            expect(ac.serialNumber.hex).toBe('0123');
            expect(ac.serialNumber.value).toBe(0x123n);
            expect(ac.validity.notBefore.epochMilliseconds).toBe(Date.UTC(2026, 0, 1));
            expect(ac.validity.notAfter.epochMilliseconds).toBe(Date.UTC(2027, 0, 1));
            expect(ac.attributes.map((a) => a.kind)).toEqual(['role']);
            expect(ac.extensions.map((e) => e.kind)).toEqual(['authorityKeyIdentifier', 'targetInformation']);
            expect(ac.issuerUniqueId).toBeUndefined();
        });

        it('should keep every extension raw under decodeExtensions: false', () => {
            const raw = parseAttributeCertificate(der, { decodeExtensions: false });
            expect(raw.extensions.map((e) => e.kind)).toEqual(['raw', 'raw']);
        });

        it('should read an AC without extensions as one with an empty list', () => {
            expect(parse(attributeCertificate({ trailing: [] })).ac.extensions).toEqual([]);
        });
    });

    describe('arguments', () => {
        it('should refuse an input that is not bytes, and a decodeExtensions that is not a boolean', () => {
            expect(() => parseAttributeCertificate('30' as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
            expect(() => parseAttributeCertificate(attributeCertificate(), { decodeExtensions: 'yes' as unknown as boolean }))
                .toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION' }));
            expect(() => parseAttributeCertificate(attributeCertificate(), { decodeExtensions: 'yes' as unknown as boolean })).toThrow(PkiError);
        });

        it('should stop at maxInputBytes before reading a byte', () => {
            const der = attributeCertificate();
            limitTrips(der, { maxInputBytes: der.length - 1 }, 'maxInputBytes');
            expect(parse(der, { maxInputBytes: der.length }).ac.version).toBe(2);
        });
    });

    describe('the envelope', () => {
        it('should refuse a root that is not a SEQUENCE of acinfo, signatureAlgorithm and signatureValue', () => {
            refuses(integer([1]), 'PKI_X509_STRUCTURE_INVALID');
            refuses(sequence(acInfo(), algorithm(ECDSA_SHA256)), 'PKI_X509_STRUCTURE_INVALID');
            refuses(sequence(acInfo(), algorithm(ECDSA_SHA256), bitString([1]), bitString([2])), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ info: integer([1]) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ signatureValue: octetString([1]) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ signatureAlgorithm: integer([1]) }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should diagnose a signatureAlgorithm that differs from acinfo.signature', () => {
            const der = attributeCertificate({ signatureAlgorithm: algorithm('1.2.840.10045.4.3.3') });
            const found = parse(der).diagnostics;
            expect(found.map((d) => d.code)).toEqual(['PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH']);
            expect(found[0]?.message).toContain('acinfo.signature');
            strictRefuses(der);
        });

        it('should refuse an acinfo with a field missing', () => {
            refuses(attributeCertificate({ info: sequence(integer([1])) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ info: sequence(integer([1]), holderByCertificate()) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ info: sequence(integer([1]), holderByCertificate(), v2Form(), algorithm(ECDSA_SHA256)) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ info: sequence(integer([1]), holderByCertificate(), v2Form(), algorithm(ECDSA_SHA256), integer([1]), VALIDITY) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ info: sequence() }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should refuse a serialNumber that is not an INTEGER', () => {
            refuses(attributeCertificate({ serialNumber: octetString([1]) }), 'PKI_X509_STRUCTURE_INVALID');
        });
    });

    describe('version (RFC 5755 §4.2.1)', () => {
        it.each([[0], [2], [3]])('should refuse version %i with PKI_X509_VERSION_INVALID', (version) => {
            refuses(attributeCertificate({ version: integer([version]) }), 'PKI_X509_VERSION_INVALID');
        });

        it('should refuse a v1 attribute certificate of X.509 (1997), which has no version field', () => {
            const subject = implicitSequence(0, ...issuerSerialComponents());
            refuses(attributeCertificate({ info: sequence(subject, generalNames(directoryName(ISSUER_NAME)), algorithm(ECDSA_SHA256), integer([1]), VALIDITY, sequence(ROLE_ATTRIBUTE)) }),
                'PKI_X509_VERSION_INVALID');
        });

        it('should refuse an acinfo whose first field is neither a version nor a v1 subject', () => {
            refuses(attributeCertificate({ version: null }), 'PKI_X509_STRUCTURE_INVALID');
        });
    });

    describe('holder (RFC 5755 §4.2.2)', () => {
        it('should read a holder by entityName', () => {
            const { ac, diagnostics } = parse(attributeCertificate({ holder: holderByName() }));
            expect(diagnostics).toEqual([]);
            expect(ac.holder.entityName?.map((n) => n.kind)).toEqual(['rfc822Name']);
            expect(ac.holder.baseCertificateId).toBeUndefined();
        });

        it('should read a holder by objectDigestInfo, publicKey and publicKeyCert', () => {
            const { ac } = parse(attributeCertificate({ holder: holderByDigest() }));
            expect(ac.holder.objectDigestInfo?.digestedObjectType).toBe('publicKey');
            expect(ac.holder.objectDigestInfo?.otherObjectTypeId).toBeUndefined();
            expect(ac.holder.objectDigestInfo?.digestAlgorithm.oid).toBe('2.16.840.1.101.3.4.2.1');
            expect(ac.holder.objectDigestInfo?.objectDigest.bytes).toHaveLength(32);
            expect(ac.holder.objectDigestInfo?.der).toEqual(implicitSequence(2, ...objectDigestComponents()));
            expect(parse(attributeCertificate({ holder: holderByDigest(...objectDigestComponents(1)) })).ac.holder.objectDigestInfo?.digestedObjectType).toBe('publicKeyCert');
        });

        it('should read otherObjectTypes with its otherObjectTypeID', () => {
            const info = parse(attributeCertificate({ holder: holderByDigest(...objectDigestComponents(2, '1.2.3.9')) })).ac.holder.objectDigestInfo;
            expect(info?.digestedObjectType).toBe('otherObjectTypes');
            expect(info?.otherObjectTypeId).toBe('1.2.3.9');
            expect(info?.digestAlgorithm.oid).toBe('2.16.840.1.101.3.4.2.1');
        });

        it('should read a baseCertificateID with its issuerUID', () => {
            const holder = holderByCertificate(...issuerSerialComponents(undefined, undefined, bitString([0xaa])));
            expect(parse(attributeCertificate({ holder })).ac.holder.baseCertificateId?.issuerUid?.bytes).toEqual(Uint8Array.of(0xaa));
        });

        it('should diagnose a holder with no option as PKI_DIAG_AC_HOLDER_EMPTY, and refuse it under strict', () => {
            const der = attributeCertificate({ holder: sequence() });
            expect(codes(der)).toEqual(['PKI_DIAG_AC_HOLDER_EMPTY']);
            strictRefuses(der);
        });

        it('should refuse a holder whose entityName is an empty GeneralNames (RFC 5280 §4.2.1.6: SIZE (1..MAX)), which would bind the attributes to nobody without a word', () => {
            refuses(attributeCertificate({ holder: sequence(implicitSequence(1)) }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should refuse a baseCertificateID whose issuer is an empty GeneralNames', () => {
            refuses(attributeCertificate({ holder: holderByCertificate(...issuerSerialComponents(sequence())) }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should report a holder with two options as the info PKI_DIAG_AC_HOLDER_MULTIPLE, which strict does not refuse', () => {
            const holder = sequence(implicitSequence(0, ...issuerSerialComponents()), implicitSequence(1, rfc822Name('alice@example.com')));
            const der = attributeCertificate({ holder });
            const found = parse(der).diagnostics;
            expect(found.map((d) => [d.code, d.severity])).toEqual([['PKI_DIAG_AC_HOLDER_MULTIPLE', 'info']]);
            expect(found[0]?.message).toContain('baseCertificateID and entityName');
            expect(parseAttributeCertificate(der, { strict: true, onDiagnostic: () => undefined }).holder.entityName).toHaveLength(1);
        });

        it('should name all three options when the holder carries them all', () => {
            const holder = sequence(implicitSequence(0, ...issuerSerialComponents()), implicitSequence(1, rfc822Name('a@example.com')), implicitSequence(2, ...objectDigestComponents()));
            expect(parse(attributeCertificate({ holder })).diagnostics[0]?.message).toContain('baseCertificateID and entityName and objectDigestInfo');
        });

        it('should refuse a holder that is not a SEQUENCE of [0], [1] and [2] in order', () => {
            refuses(attributeCertificate({ holder: integer([1]) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: sequence(implicitSequence(3, rfc822Name('a@example.com'))) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: sequence(implicitSequence(1, rfc822Name('a@example.com')), implicitSequence(0, ...issuerSerialComponents())) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: sequence(implicitSequence(1, rfc822Name('a@example.com')), implicitSequence(1, rfc822Name('b@example.com'))) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: sequence(integer([1])) }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should refuse an IssuerSerial of the wrong shape', () => {
            const [issuer, serial] = issuerSerialComponents();
            refuses(attributeCertificate({ holder: holderByCertificate(issuer as Uint8Array) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByCertificate(issuer as Uint8Array, serial as Uint8Array, bitString([1]), bitString([2])) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByCertificate(integer([1]), serial as Uint8Array) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByCertificate(issuer as Uint8Array, octetString([1])) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByCertificate(issuer as Uint8Array, serial as Uint8Array, octetString([1])) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: sequence(context(0, false, [1, 2])) }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should refuse an entityName that is not GeneralNames', () => {
            refuses(attributeCertificate({ holder: sequence(context(1, false, [1])) }), 'PKI_X509_GENERAL_NAME_INVALID');
        });

        it('should refuse an ObjectDigestInfo of the wrong shape', () => {
            const [type, algo, digest] = objectDigestComponents() as [Uint8Array, Uint8Array, Uint8Array];
            refuses(attributeCertificate({ holder: holderByDigest(type, algo) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type, oid('1.2.3'), algo, digest, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type, algo, digest, digest, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(integer([0]), algo, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(universal(10, [3]), algo, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(universal(10, [0xff]), algo, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type, integer([1]), algo, digest) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type, algo, octetString([1])) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ holder: holderByDigest(type, integer([1]), digest) }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should read every GeneralName form RFC 5755 §4.2 requires an implementation to support', () => {
            const holder = holderByName(dnsName('alice.example'), directoryName(CA_NAME), uriName('urn:alice'), context(7, false, [192, 0, 2, 1]));
            const { ac, diagnostics } = parse(attributeCertificate({ holder }));
            expect(diagnostics).toEqual([]);
            expect(ac.holder.entityName?.map((n) => n.kind)).toEqual(['dNSName', 'directoryName', 'uniformResourceIdentifier', 'iPAddress']);
        });

        it('should stop at maxGeneralNames in the entityName', () => {
            const der = attributeCertificate({ holder: holderByName(rfc822Name('a@example.com'), rfc822Name('b@example.com')) });
            limitTrips(der, { maxGeneralNames: 1 }, 'maxGeneralNames');
            expect(parse(der, { maxGeneralNames: 2 }).ac.holder.entityName).toHaveLength(2);
        });
    });

    describe('issuer (RFC 5755 §4.2.3)', () => {
        it('should read the v1Form, and diagnose it as PKI_DIAG_AC_ISSUER_V1_FORM', () => {
            const der = attributeCertificate({ issuer: generalNames(directoryName(ISSUER_NAME)) });
            const { ac, diagnostics } = parse(der);
            expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_AC_ISSUER_V1_FORM']);
            expect(ac.issuer.form).toBe('v1Form');
            expect(ac.issuer.name?.der).toEqual(ISSUER_NAME);
            expect(ac.issuer.issuerName).toHaveLength(1);
            expect(ac.issuer.baseCertificateId).toBeUndefined();
            expect(ac.issuer.objectDigestInfo).toBeUndefined();
            strictRefuses(der);
        });

        it.each([
            ['two names', v2Form(generalNames(directoryName(ISSUER_NAME), directoryName(CA_NAME)))],
            ['a dNSName', v2Form(generalNames(dnsName('issuer.example')))],
            ['an empty distinguished name', v2Form(generalNames(directoryName(sequence())))],
            ['no issuerName', v2Form(implicitSequence(0, ...issuerSerialComponents()))],
            ['an empty v2Form', tlv(2, true, 0, [])],
        ])('should diagnose a v2Form issuer with %s as PKI_DIAG_AC_ISSUER_NOT_PROFILED, with no name', (_what, issuer) => {
            const der = attributeCertificate({ issuer });
            const { ac, diagnostics } = parse(der);
            expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_AC_ISSUER_NOT_PROFILED']);
            expect(ac.issuer.name).toBeUndefined();
            strictRefuses(der);
        });

        it('should name an issuer whose distinguished name has a single RDN', () => {
            const single = name([['2.5.4.3', utf8('AC Issuer')]]);
            const { ac, diagnostics } = parse(attributeCertificate({ issuer: v2Form(generalNames(directoryName(single))) }));
            expect(diagnostics).toEqual([]);
            expect(ac.issuer.name?.der).toEqual(single);
        });

        it('should read and diagnose a v2Form baseCertificateID and objectDigestInfo, keeping the name', () => {
            const issuer = v2Form(generalNames(directoryName(ISSUER_NAME)), implicitSequence(0, ...issuerSerialComponents()), implicitSequence(1, ...objectDigestComponents()));
            const { ac, diagnostics } = parse(attributeCertificate({ issuer }));
            expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_AC_ISSUER_NOT_PROFILED']);
            expect(diagnostics[0]?.message).toContain('carries baseCertificateID and carries objectDigestInfo');
            expect(ac.issuer.name?.der).toEqual(ISSUER_NAME);
            expect(ac.issuer.baseCertificateId?.serial.hex).toBe('10');
            expect(ac.issuer.objectDigestInfo?.digestedObjectType).toBe('publicKey');
        });

        it('should refuse an issuer that is neither GeneralNames nor v2Form [0]', () => {
            refuses(attributeCertificate({ issuer: implicitSequence(1, generalNames(directoryName(ISSUER_NAME))) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ issuer: context(0, false, [1]) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ issuer: integer([1]) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ issuer: v2Form(generalNames(directoryName(ISSUER_NAME)), implicitSequence(2, integer([1]))) }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ issuer: v2Form(generalNames(directoryName(ISSUER_NAME)), integer([1])) }), 'PKI_X509_STRUCTURE_INVALID');
        });
    });

    describe('serialNumber (RFC 5755 §4.2.5)', () => {
        it('should diagnose a serial longer than 20 octets at acinfo.serialNumber, and accept 20', () => {
            const long = parse(attributeCertificate({ serialNumber: integer(Array.from({ length: 21 }, () => 0x11)) })).diagnostics;
            expect(long.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_SERIAL_TOO_LONG', 'acinfo.serialNumber']]);
            expect(codes(attributeCertificate({ serialNumber: integer(Array.from({ length: 20 }, () => 0x11)) }))).toEqual([]);
        });

        it('should diagnose a zero or negative serial at acinfo.serialNumber', () => {
            expect(parse(attributeCertificate({ serialNumber: integer([0]) })).diagnostics.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_SERIAL_NOT_POSITIVE', 'acinfo.serialNumber']]);
            expect(codes(attributeCertificate({ serialNumber: integer([0xff]) }))).toEqual(['PKI_DIAG_SERIAL_NOT_POSITIVE']);
            expect(codes(attributeCertificate({ serialNumber: integer([1]) }))).toEqual([]);
        });
    });

    describe('attrCertValidityPeriod (RFC 5755 §4.2.6)', () => {
        it('should refuse a UTCTime, which the module types GeneralizedTime', () => {
            refuses(attributeCertificate({ validity: sequence(utcTime('260101000000Z'), generalizedTime('20270101000000Z')) }), 'PKI_X509_VALIDITY_INVALID');
            refuses(attributeCertificate({ validity: sequence(generalizedTime('20260101000000Z'), utcTime('270101000000Z')) }), 'PKI_X509_VALIDITY_INVALID');
            refuses(attributeCertificate({ validity: sequence(generalizedTime('20260101000000Z'), context(24, false, [0x32])) }), 'PKI_X509_VALIDITY_INVALID');
        });

        it('should refuse a period that is not a SEQUENCE of two times', () => {
            refuses(attributeCertificate({ validity: integer([1]) }), 'PKI_X509_VALIDITY_INVALID');
            refuses(attributeCertificate({ validity: sequence(generalizedTime('20260101000000Z')) }), 'PKI_X509_VALIDITY_INVALID');
            refuses(attributeCertificate({ validity: sequence(generalizedTime('20260101000000Z'), generalizedTime('20270101000000Z'), generalizedTime('20280101000000Z')) }), 'PKI_X509_VALIDITY_INVALID');
        });

        it('should refuse a GeneralizedTime without its seconds or its Z', () => {
            for (const text of ['202601010000Z', '20260101000000', '20260101000000+0100']) {
                const der = attributeCertificate({ validity: sequence(generalizedTime(text), generalizedTime('20270101000000Z')) });
                expect(() => parseAttributeCertificate(der, { onDiagnostic: () => undefined })).toThrow(expect.objectContaining({ code: 'PKI_ASN1_TIME_INVALID' }));
            }
        });

        it('should read a validity period wholly in the past or wholly in the future, comparing nothing with the clock', () => {
            for (const [from, to] of [['19900101000000Z', '19910101000000Z'], ['20900101000000Z', '20910101000000Z']] as const) {
                const { ac, diagnostics } = parse(attributeCertificate({ validity: sequence(generalizedTime(from), generalizedTime(to)) }));
                expect(diagnostics).toEqual([]);
                expect(ac.validity.notAfter.text).toBe(to);
            }
        });

        it('should diagnose fractional seconds at their path', () => {
            const found = parse(attributeCertificate({ validity: sequence(generalizedTime('20260101000000.5Z'), generalizedTime('20270101000000Z')) })).diagnostics;
            expect(found.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_GENERALIZED_TIME_FRACTION', 'acinfo.attrCertValidityPeriod.notBeforeTime']]);
            expect(codes(attributeCertificate({ validity: sequence(generalizedTime('20260101000000Z'), generalizedTime('20270101000000.5Z')) }))).toEqual(['PKI_DIAG_GENERALIZED_TIME_FRACTION']);
        });

        it('should diagnose an inverted period at acinfo.attrCertValidityPeriod, and accept a single instant', () => {
            const inverted = parse(attributeCertificate({ validity: sequence(generalizedTime('20270101000000Z'), generalizedTime('20260101000000Z')) })).diagnostics;
            expect(inverted.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_VALIDITY_INVERTED', 'acinfo.attrCertValidityPeriod']]);
            expect(codes(attributeCertificate({ validity: sequence(generalizedTime('20260101000000Z'), generalizedTime('20260101000000Z')) }))).toEqual([]);
        });
    });

    describe('issuerUniqueID and what may follow the attributes (RFC 5755 §4.2.8)', () => {
        it('should read an issuerUniqueID and diagnose it as PKI_DIAG_UNIQUE_ID_PRESENT', () => {
            const { ac, diagnostics } = parse(attributeCertificate({ trailing: [bitString([0x5a]), EXTENSIONS] }));
            expect(ac.issuerUniqueId?.bytes).toEqual(Uint8Array.of(0x5a));
            expect(ac.extensions).toHaveLength(2);
            expect(diagnostics.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_UNIQUE_ID_PRESENT', 'acinfo.issuerUniqueID']]);
        });

        it('should read an issuerUniqueID without extensions', () => {
            const { ac } = parse(attributeCertificate({ trailing: [bitString([0x5a])] }));
            expect(ac.issuerUniqueId?.bytes).toEqual(Uint8Array.of(0x5a));
            expect(ac.extensions).toEqual([]);
        });

        it('should refuse a field after the extensions, and extensions that are not a SEQUENCE', () => {
            refuses(attributeCertificate({ trailing: [EXTENSIONS, EXTENSIONS] }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ trailing: [bitString([1]), bitString([2])] }), 'PKI_X509_STRUCTURE_INVALID');
            refuses(attributeCertificate({ trailing: [integer([1])] }), 'PKI_X509_STRUCTURE_INVALID');
        });

        it('should refuse an empty extensions SEQUENCE and a duplicate extension, as a certificate does', () => {
            refuses(attributeCertificate({ trailing: [sequence()] }), 'PKI_X509_EXTENSIONS_EMPTY');
            refuses(attributeCertificate({ trailing: [sequence(AUTHORITY_KEY_ID, AUTHORITY_KEY_ID)] }), 'PKI_X509_EXTENSION_DUPLICATE');
        });

        it('should stop at maxExtensions', () => {
            const der = attributeCertificate({ trailing: [sequence(AUTHORITY_KEY_ID, TARGET_INFORMATION, NO_REV_AVAIL)] });
            limitTrips(der, { maxExtensions: 2 }, 'maxExtensions');
            expect(parse(der, { maxExtensions: 3 }).ac.extensions).toHaveLength(3);
        });
    });
});

// ── The extensions only an AC carries (RFC 5755 §4.3) ─────────────────

const withExtensions = (...extensions: Uint8Array[]): Uint8Array => attributeCertificate({ trailing: [sequence(...extensions)] });

describe('the AC-only extensions (RFC 5755 §4.3)', () => {
    describe('auditIdentity (§4.3.1)', () => {
        it('should read a critical audit identity of 1 to 20 octets with no diagnostic', () => {
            for (const length of [1, 20]) {
                const { ac, diagnostics } = parse(withExtensions(extension(OID_AUDIT_IDENTITY, octetString(Array.from({ length }, () => 7)), true)));
                expect(diagnostics).toEqual([]);
                const audit = ac.extensions[0];
                expect(audit?.kind === 'auditIdentity' && audit.identity.length).toBe(length);
            }
        });

        it.each([[0], [21]])('should diagnose an audit identity of %i octets as PKI_DIAG_AC_EXTENSION_PROFILE', (length) => {
            const der = withExtensions(extension(OID_AUDIT_IDENTITY, octetString(Array.from({ length }, () => 7)), true));
            expect(codes(der)).toEqual(['PKI_DIAG_AC_EXTENSION_PROFILE']);
            strictRefuses(der);
        });

        it('should diagnose a non-critical audit identity as PKI_DIAG_AC_EXTENSION_CRITICALITY', () => {
            const der = withExtensions(extension(OID_AUDIT_IDENTITY, octetString([7])));
            expect(parse(der).diagnostics.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_EXTENSION_CRITICALITY', 'acinfo.extensions[0]']]);
            strictRefuses(der);
        });

        it('should refuse an audit identity that is not an OCTET STRING', () => {
            refuses(withExtensions(extension(OID_AUDIT_IDENTITY, integer([7]), true)), 'PKI_X509_EXTENSION_MALFORMED');
        });
    });

    describe('targetInformation (§4.3.2)', () => {
        it('should read named targets and target groups', () => {
            const der = withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(targetName(dnsName('a.example')), targetGroup(uriName('urn:printers')))), true));
            const { ac, diagnostics } = parse(der);
            expect(diagnostics).toEqual([]);
            const targets = ac.extensions[0]?.kind === 'targetInformation' ? ac.extensions[0].targets : [];
            expect(targets.map((t) => t.kind)).toEqual(['targetName', 'targetGroup']);
            expect(targets[1]?.kind === 'targetGroup' && targets[1].name.kind).toBe('uniformResourceIdentifier');
        });

        it('should flatten several Targets elements into one list, and diagnose them', () => {
            const der = withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(targetName(dnsName('a.example'))), sequence(targetName(dnsName('b.example')))), true));
            const { ac, diagnostics } = parse(der);
            expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_AC_EXTENSION_PROFILE']);
            const targets = ac.extensions[0]?.kind === 'targetInformation' ? ac.extensions[0].targets : [];
            expect(targets.map((t) => t.kind === 'targetName' && t.name.kind === 'dNSName' && t.name.value)).toEqual(['a.example', 'b.example']);
        });

        it('should keep a targetCert as its DER and diagnose it', () => {
            const cert = implicitSequence(2, sequence(...issuerSerialComponents()));
            const { ac, diagnostics } = parse(withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(cert)), true)));
            expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_AC_EXTENSION_PROFILE']);
            const target = ac.extensions[0]?.kind === 'targetInformation' ? ac.extensions[0].targets[0] : undefined;
            expect(target?.kind === 'targetCert' && target.der).toEqual(cert);
        });

        it('should diagnose a non-critical targetInformation', () => {
            expect(codes(withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(targetName(dnsName('a.example')))))))).toEqual(['PKI_DIAG_AC_EXTENSION_CRITICALITY']);
        });

        it('should refuse a value that is not SEQUENCE OF Targets of Target', () => {
            for (const value of [
                integer([1]),
                sequence(integer([1])),
                sequence(sequence(context(0, false, [1]))),
                sequence(sequence(explicit(0, dnsName('a.example'), dnsName('b.example')))),
                sequence(sequence(explicit(3, dnsName('a.example')))),
                sequence(sequence(context(2, false, [1]))),
                sequence(sequence(sequence(dnsName('a.example')))),
            ]) {
                refuses(withExtensions(extension(OID_TARGET_INFORMATION, value, true)), 'PKI_X509_EXTENSION_MALFORMED');
            }
        });

        it('should refuse a target that is not a GeneralName', () => {
            refuses(withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(targetName(integer([1])))), true)), 'PKI_X509_GENERAL_NAME_INVALID');
        });

        it('should stop at maxGeneralNames, counting every target and every Targets element', () => {
            const two = withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(targetName(dnsName('a.example'))), sequence(targetName(dnsName('b.example')))), true));
            limitTrips(two, { maxGeneralNames: 1 }, 'maxGeneralNames');
            expect(parse(two, { maxGeneralNames: 2 }).ac.extensions).toHaveLength(1);
            const empties = withExtensions(extension(OID_TARGET_INFORMATION, sequence(sequence(), sequence()), true));
            limitTrips(empties, { maxGeneralNames: 1 }, 'maxGeneralNames');
            expect(parse(empties, { maxGeneralNames: 2 }).ac.extensions).toHaveLength(1);
        });
    });

    describe('noRevAvail (§4.3.6)', () => {
        it('should read a non-critical noRevAvail', () => {
            const { ac, diagnostics } = parse(withExtensions(NO_REV_AVAIL));
            expect(diagnostics).toEqual([]);
            expect(ac.extensions[0]?.kind).toBe('noRevAvail');
        });

        it('should diagnose a critical noRevAvail', () => {
            const der = withExtensions(extension(OID_NO_REV_AVAIL, nullValue(), true));
            expect(codes(der)).toEqual(['PKI_DIAG_AC_EXTENSION_CRITICALITY']);
            strictRefuses(der);
        });

        it('should refuse a value that is not an empty NULL', () => {
            refuses(withExtensions(extension(OID_NO_REV_AVAIL, integer([1]))), 'PKI_X509_EXTENSION_MALFORMED');
            refuses(withExtensions(extension(OID_NO_REV_AVAIL, universal(5, [0]), undefined)), 'PKI_X509_EXTENSION_MALFORMED');
        });
    });

    const CRL_DP = sequence(sequence(explicit(0, implicitSequence(0, uriName('http://crl.example/ac.crl')))));
    it.each<[string, Uint8Array, PkiDiagnosticCode[]]>([
        ['authorityKeyIdentifier (§4.3.3)', extension('2.5.29.35', sequence(context(0, false, [1, 2])), true), ['PKI_DIAG_AKI_CRITICAL']],
        ['authorityInfoAccess (§4.3.4)', extension('1.3.6.1.5.5.7.1.1', sequence(sequence(oid('1.3.6.1.5.5.7.48.1'), uriName('http://ocsp.example/'))), true), ['PKI_DIAG_AIA_CRITICAL']],
        ['crlDistributionPoints (§4.3.5)', extension('2.5.29.31', CRL_DP, true), ['PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL', 'PKI_DIAG_AC_EXTENSION_CRITICALITY']],
    ])('should diagnose a critical %s, which RFC 5755 requires non-critical', (_name, encoded, expected) => {
        const der = withExtensions(encoded, NO_REV_AVAIL);
        expect(codes(der)).toEqual(expected);
        strictRefuses(der);
    });

    it('should read a non-critical crlDistributionPoints at any position without the AC criticality diagnostic', () => {
        expect(codes(withExtensions(NO_REV_AVAIL, extension('2.5.29.31', CRL_DP)))).toEqual([]);
        const late = parse(withExtensions(NO_REV_AVAIL, extension('2.5.29.31', CRL_DP, true))).diagnostics.filter((d) => d.code === 'PKI_DIAG_AC_EXTENSION_CRITICALITY');
        expect(late.map((d) => d.path)).toEqual(['acinfo.extensions[1]']);
    });

    it('should diagnose an unrecognised critical extension, which an AC-using system must reject (§4.2.9)', () => {
        expect(codes(withExtensions(extension('1.2.3.4.5', nullValue(), true)))).toEqual(['PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION']);
        expect(codes(withExtensions(extension('1.2.3.4.5', nullValue())))).toEqual([]);
    });

    it('should leave the AC-only extensions unknown in a public-key certificate (ADR 0028)', () => {
        const der = certificate({ tbs: tbsCertificate({ trailing: [explicit(3, sequence(extension(OID_NO_REV_AVAIL, nullValue()), extension(OID_AUDIT_IDENTITY, integer([1]))))] }) });
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });
        expect(cert.extensions.map((e) => e.kind)).toEqual(['unknown', 'unknown']);
    });

    it('should keep the boolean FALSE critical flag reading as non-critical, with its DER diagnostic', () => {
        expect(codes(withExtensions(extension(OID_NO_REV_AVAIL, nullValue(), false)))).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
    });
});
