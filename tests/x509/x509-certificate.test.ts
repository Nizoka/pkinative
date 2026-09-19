import { describe, it, expect } from 'vitest';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiParseOptions } from '../../src/types/pki-types.js';
import {
    BASIC_CONSTRAINTS_CA,
    ECDSA_SHA256,
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
    octetString,
    oid,
    tbsCertificate,
    utcTime,
} from '../helpers/cert-builder.js';
import { ascii, concat, sequence } from '../helpers/raw-der-builder.js';

const QUIET: PkiParseOptions = { onDiagnostic: () => undefined };

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

function diagnosticsOf(der: Uint8Array, options: PkiParseOptions = {}): string[] {
    const seen: string[] = [];
    parseCertificate(der, { ...options, onDiagnostic: (d) => { seen.push(d.code); } });
    return seen;
}

describe('parseCertificate', () => {
    describe('a well-formed v3 certificate', () => {
        const input = certificate();
        const cert = parseCertificate(input);

        it('should read the version, the serial number and both signature algorithms', () => {
            expect(cert.version).toBe(3);
            expect(cert.serialNumber.value).toBe(0x123n);
            expect(cert.serialNumber.hex).toBe('0123');
            expect([...cert.serialNumber.bytes]).toEqual([0x01, 0x23]);
            expect(cert.tbsSignatureAlgorithm.oid).toBe(ECDSA_SHA256);
            expect(cert.signatureAlgorithm.oid).toBe(ECDSA_SHA256);
            expect(cert.signatureAlgorithm.parameters).toBeUndefined();
        });

        it('should read the names, the validity and the public key', () => {
            expect(cert.issuer.rdns.map((rdn) => rdn.map((a) => a.value?.value))).toEqual([['US'], ['pkinative test'], ['Test Root']]);
            expect(cert.subject.rdns[0]?.[0]?.type).toBe('2.5.4.3');
            expect(cert.validity.notBefore.epochMilliseconds).toBe(Date.UTC(2025, 0, 1));
            expect(cert.validity.notAfter.epochMilliseconds).toBe(Date.UTC(2035, 0, 1));
            expect(cert.subjectPublicKeyInfo).toMatchObject({ kind: 'ec', curve: 'P-256', pointFormat: 'uncompressed' });
        });

        it('should decode the extensions and keep their encoding', () => {
            expect(cert.extensions).toHaveLength(1);
            expect(cert.extensions[0]).toMatchObject({ kind: 'basicConstraints', oid: '2.5.29.19', critical: true, cA: true, pathLenConstraint: undefined });
            expect([...(cert.extensions[0]?.valueDer ?? [])]).toEqual([0x30, 0x03, 0x01, 0x01, 0xff]);
        });

        it('should keep every extension raw under decodeExtensions: false', () => {
            expect(parseCertificate(input, { decodeExtensions: false }).extensions[0]).toMatchObject({ kind: 'raw', oid: '2.5.29.19', critical: true });
        });

        it('should refuse a decodeExtensions option that is not a boolean', () => {
            expect(codeOf(() => parseCertificate(input, { decodeExtensions: 'no' as unknown as boolean }))).toBe('PKI_INVALID_OPTION');
        });

        it('should read the signature value and no unique identifier', () => {
            expect([...cert.signatureValue.bytes]).toEqual([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
            expect(cert.issuerUniqueId).toBeUndefined();
            expect(cert.subjectUniqueId).toBeUndefined();
        });

        it('should record no diagnostic', () => {
            expect(cert.diagnostics).toEqual([]);
        });

        it('should return zero-copy views of the input', () => {
            expect(cert.der.buffer).toBe(input.buffer);
            expect(cert.tbsDer.buffer).toBe(input.buffer);
            expect([...cert.der]).toEqual([...input]);
            expect([...cert.tbsDer]).toEqual([...tbsCertificate()]);
        });

        it('should freeze the result', () => {
            for (const part of [cert, cert.serialNumber, cert.extensions, cert.diagnostics, cert.issuer, cert.validity, cert.subjectPublicKeyInfo]) {
                expect(Object.isFrozen(part)).toBe(true);
            }
        });
    });

    describe('version', () => {
        it('should read a certificate without the version field as v1', () => {
            expect(parseCertificate(certificate({ version: null, trailing: [] })).version).toBe(1);
        });

        it('should read v2', () => {
            expect(parseCertificate(certificate({ version: explicit(0, integer([1])), trailing: [] })).version).toBe(2);
        });

        it('should refuse an explicit v1 under DER and accept it under BER', () => {
            const der = certificate({ version: explicit(0, integer([0])), trailing: [] });
            expect(codeOf(() => parseCertificate(der))).toBe('PKI_X509_DEFAULT_ENCODED');
            expect(parseCertificate(der, { encodingRules: 'ber', onDiagnostic: () => undefined }).version).toBe(1);
            expect(diagnosticsOf(der, { encodingRules: 'ber' })).toEqual(['PKI_DIAG_BER_CONSTRUCT_ACCEPTED']);
        });

        it.each<[string, number[]]>([
            ['3', [0x03]],
            ['-1', [0xff]],
        ])('should refuse version %s', (_, content) => {
            expect(codeOf(() => parseCertificate(certificate({ version: explicit(0, integer(content)) })))).toBe('PKI_X509_VERSION_INVALID');
        });

        it.each<[string, Uint8Array]>([
            ['two values', explicit(0, integer([2]), integer([2]))],
            ['a primitive [0]', context(0, false, [0x02])],
            ['an OCTET STRING', explicit(0, octetString([2]))],
        ])('should refuse a version field holding %s', (_, version) => {
            expect(codeOf(() => parseCertificate(certificate({ version })))).toBe('PKI_X509_STRUCTURE_INVALID');
        });
    });

    describe('structure', () => {
        it.each<[string, Uint8Array]>([
            ['an input that is not a SEQUENCE', integer([1])],
            ['a SEQUENCE of two values', sequence(tbsCertificate(), algorithm(ECDSA_SHA256))],
            ['a tbsCertificate that is not a SEQUENCE', certificate({ tbs: integer([1]) })],
            ['a missing serial number', certificate({ tbs: sequence(explicit(0, integer([2]))) })],
            ['a missing signature algorithm', certificate({ tbs: sequence(explicit(0, integer([2])), integer([1])) })],
            ['a signatureValue that is not a BIT STRING', certificate({ signatureValue: octetString([1]) })],
            ['a universal value after the public key', certificate({ trailing: [integer([1])] })],
            ['a context tag [4] after the public key', certificate({ trailing: [explicit(4, sequence())] })],
            ['an AlgorithmIdentifier of three values', certificate({ signature: sequence(oid(ECDSA_SHA256), nullValue(), nullValue()) })],
        ])('should refuse %s', (_, der) => {
            expect(codeOf(() => parseCertificate(der, QUIET))).toBe('PKI_X509_STRUCTURE_INVALID');
        });

        it('should refuse a missing subject as a name error', () => {
            const tbs = sequence(explicit(0, integer([2])), integer([1]), algorithm(ECDSA_SHA256), name([['2.5.4.3', utf8Value('CA')]]),
                sequence(utcTime('250101000000Z'), utcTime('350101000000Z')));
            expect(codeOf(() => parseCertificate(certificate({ tbs }), QUIET))).toBe('PKI_X509_NAME_INVALID');
        });

        it('should report the path and offset of a structural error', () => {
            const error = thrown(() => parseCertificate(certificate({ signatureValue: octetString([1]) })));
            expect(error).toBeInstanceOf(PkiCertificateError);
            expect(error).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID', path: 'signatureValue' });
            expect((error as PkiCertificateError).offset).toBeGreaterThan(0);
        });

        it('should refuse bytes after the certificate', () => {
            expect(codeOf(() => parseCertificate(concat(certificate(), [0x00])))).toBe('PKI_ASN1_TRAILING_DATA');
        });

        it('should refuse an input that is not a Uint8Array and a malformed option', () => {
            expect(codeOf(() => parseCertificate('MIIB' as unknown as Uint8Array))).toBe('PKI_INVALID_INPUT');
            expect(codeOf(() => parseCertificate(certificate(), { encodingRules: 'cer' as 'der' }))).toBe('PKI_INVALID_OPTION');
        });
    });

    describe('serial number', () => {
        it('should report a serial number longer than 20 octets', () => {
            expect(diagnosticsOf(certificate({ serialNumber: integer([0x01, ...new Array<number>(20).fill(0)]) }))).toEqual(['PKI_DIAG_SERIAL_TOO_LONG']);
        });

        it.each<[string, number[]]>([
            ['zero', [0x00]],
            ['negative', [0xff]],
        ])('should report a %s serial number', (_, content) => {
            expect(diagnosticsOf(certificate({ serialNumber: integer(content) }))).toEqual(['PKI_DIAG_SERIAL_NOT_POSITIVE']);
        });

        it('should return a negative serial number as decoded', () => {
            expect(parseCertificate(certificate({ serialNumber: integer([0xff]) }), QUIET).serialNumber.value).toBe(-1n);
        });

        it('should throw on the first diagnostic under strict', () => {
            expect(codeOf(() => parseCertificate(certificate({ serialNumber: integer([0x00]) }), { strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
        });

        it('should deliver each diagnostic to onDiagnostic and record it on the result', () => {
            const seen: PkiDiagnostic[] = [];
            const cert = parseCertificate(certificate({ serialNumber: integer([0x00]) }), { onDiagnostic: (d) => { seen.push(d); } });
            expect(cert.diagnostics).toEqual(seen);
            expect(seen[0]).toMatchObject({ code: 'PKI_DIAG_SERIAL_NOT_POSITIVE', path: 'tbsCertificate.serialNumber' });
        });
    });

    describe('signature algorithms', () => {
        const RSA_SHA256 = '1.2.840.113549.1.1.11';

        it('should report an outer algorithm that differs from tbsCertificate.signature', () => {
            expect(diagnosticsOf(certificate({ signatureAlgorithm: algorithm('1.2.840.10045.4.3.3') }))).toEqual(['PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH']);
        });

        it('should report RSA PKCS #1 v1.5 algorithms without NULL parameters, in both places', () => {
            const rsa = algorithm(RSA_SHA256);
            expect(diagnosticsOf(certificate({ signature: rsa, signatureAlgorithm: rsa })))
                .toEqual(['PKI_DIAG_RSA_PARAMETERS_NOT_NULL', 'PKI_DIAG_RSA_PARAMETERS_NOT_NULL']);
        });

        it('should accept RSA PKCS #1 v1.5 algorithms with NULL parameters', () => {
            const rsa = algorithm(RSA_SHA256, nullValue());
            expect(diagnosticsOf(certificate({ signature: rsa, signatureAlgorithm: rsa }))).toEqual([]);
        });
    });

    describe('validity', () => {
        const withValidity = (notBefore: Uint8Array, notAfter: Uint8Array): Uint8Array => certificate({ validity: sequence(notBefore, notAfter) });

        it('should report a GeneralizedTime before 2050', () => {
            expect(diagnosticsOf(withValidity(generalizedTime('20490101000000Z'), generalizedTime('20500101000000Z'))))
                .toEqual(['PKI_DIAG_GENERALIZED_TIME_BEFORE_2050']);
        });

        it('should report a GeneralizedTime with fractional seconds', () => {
            expect(diagnosticsOf(withValidity(utcTime('250101000000Z'), generalizedTime('20500101000000.5Z')))).toEqual(['PKI_DIAG_GENERALIZED_TIME_FRACTION']);
        });

        it('should report a notBefore later than notAfter', () => {
            expect(diagnosticsOf(withValidity(utcTime('350101000000Z'), utcTime('250101000000Z')))).toEqual(['PKI_DIAG_VALIDITY_INVERTED']);
        });

        it('should read UTCTime years 50 to 99 as 1950 to 1999', () => {
            const cert = parseCertificate(withValidity(utcTime('500101000000Z'), utcTime('491231235959Z')));
            expect(cert.validity.notBefore.epochMilliseconds).toBe(Date.UTC(1950, 0, 1));
            expect(cert.validity.notAfter.epochMilliseconds).toBe(Date.UTC(2049, 11, 31, 23, 59, 59));
        });

        it.each<[string, Uint8Array]>([
            ['a validity of one time', certificate({ validity: sequence(utcTime('250101000000Z')) })],
            ['a time of another type', withValidity(utcTime('250101000000Z'), integer([1]))],
            ['a validity that is not a SEQUENCE', certificate({ validity: integer([1]) })],
        ])('should refuse %s', (_, der) => {
            expect(codeOf(() => parseCertificate(der))).toBe('PKI_X509_VALIDITY_INVALID');
        });
    });

    describe('names', () => {
        const SAN = sequence(context(2, false, ascii('a.example')));

        it('should report an empty issuer', () => {
            expect(diagnosticsOf(certificate({ issuer: name() }))).toEqual(['PKI_DIAG_EMPTY_ISSUER']);
        });

        it('should report an empty subject without a subjectAltName', () => {
            expect(diagnosticsOf(certificate({ subject: name() }))).toEqual(['PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL']);
        });

        it('should report an empty subject with a non-critical subjectAltName', () => {
            const trailing = [explicit(3, sequence(extension('2.5.29.17', SAN)))];
            expect(diagnosticsOf(certificate({ subject: name(), trailing }))).toEqual(['PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL']);
        });

        it('should accept an empty subject with a critical subjectAltName', () => {
            const trailing = [explicit(3, sequence(extension('2.5.29.17', SAN, true)))];
            expect(diagnosticsOf(certificate({ subject: name(), trailing }))).toEqual([]);
        });
    });

    describe('unique identifiers', () => {
        const V2 = explicit(0, integer([1]));

        it('should read both identifiers of a v2 certificate', () => {
            const cert = parseCertificate(certificate({ version: V2, trailing: [context(1, false, [0x00, 0xaa]), context(2, false, [0x04, 0xb0])] }));
            expect([...(cert.issuerUniqueId?.bytes ?? [])]).toEqual([0xaa]);
            expect(cert.subjectUniqueId).toMatchObject({ unusedBits: 4 });
            expect(cert.diagnostics).toEqual([]);
        });

        it('should report unique identifiers in a v1 certificate', () => {
            expect(diagnosticsOf(certificate({ version: null, trailing: [context(1, false, [0x00, 0xaa])] }))).toEqual(['PKI_DIAG_UNIQUE_ID_REQUIRES_V2']);
        });

        it.each<[string, readonly Uint8Array[]]>([
            ['out of order', [context(2, false, [0x00, 0xaa]), context(1, false, [0x00, 0xbb])]],
            ['twice', [context(1, false, [0x00, 0xaa]), context(1, false, [0x00, 0xbb])]],
            ['in constructed form under DER', [context(1, true, bitString([0xaa]))]],
        ])('should refuse identifiers %s', (_, trailing) => {
            expect(codeOf(() => parseCertificate(certificate({ version: V2, trailing }), QUIET))).toBe('PKI_X509_UNIQUE_ID_INVALID');
        });

        it('should accept an identifier in constructed form under BER', () => {
            const cert = parseCertificate(certificate({ version: V2, trailing: [context(1, true, bitString([0xaa]))] }), { encodingRules: 'ber', onDiagnostic: () => undefined });
            expect([...(cert.issuerUniqueId?.bytes ?? [])]).toEqual([0xaa]);
        });
    });

    describe('extensions', () => {
        const withExtensions = (...extensions: Uint8Array[]): Uint8Array => certificate({ trailing: [explicit(3, sequence(...extensions))] });
        const KEY_USAGE = extension('2.5.29.15', bitString([0x06], 1), true);

        it('should keep every extension in order with its critical flag', () => {
            const cert = parseCertificate(withExtensions(BASIC_CONSTRAINTS_CA, extension('2.5.29.14', octetString([1, 2]))));
            expect(cert.extensions.map((e) => [e.oid, e.critical])).toEqual([['2.5.29.19', true], ['2.5.29.14', false]]);
        });

        it('should report extensions in a certificate below v3', () => {
            expect(diagnosticsOf(certificate({ version: explicit(0, integer([1])) }))).toEqual(['PKI_DIAG_EXTENSIONS_REQUIRE_V3']);
        });

        it('should refuse an empty extensions field', () => {
            expect(codeOf(() => parseCertificate(withExtensions()))).toBe('PKI_X509_EXTENSIONS_EMPTY');
        });

        it('should refuse an extension that appears twice', () => {
            expect(codeOf(() => parseCertificate(withExtensions(BASIC_CONSTRAINTS_CA, BASIC_CONSTRAINTS_CA)))).toBe('PKI_X509_EXTENSION_DUPLICATE');
        });

        it('should refuse an explicit FALSE critical flag under DER and accept it under BER', () => {
            const der = withExtensions(extension('2.5.29.14', octetString([1]), false));
            expect(codeOf(() => parseCertificate(der))).toBe('PKI_X509_DEFAULT_ENCODED');
            const seen: string[] = [];
            const cert = parseCertificate(der, { encodingRules: 'ber', onDiagnostic: (d) => { seen.push(d.code); } });
            expect(cert.extensions[0]?.critical).toBe(false);
            expect(seen).toEqual(['PKI_DIAG_BER_CONSTRUCT_ACCEPTED']);
        });

        it('should enforce maxExtensions', () => {
            const error = thrown(() => parseCertificate(withExtensions(BASIC_CONSTRAINTS_CA, KEY_USAGE), { limits: { maxExtensions: 1 } }));
            expect(error).toBeInstanceOf(PkiLimitError);
            expect(error).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxExtensions' });
        });

        it.each<[string, Uint8Array]>([
            ['an extension of one value', withExtensions(sequence(oid('2.5.29.19')))],
            ['an extension of four values', withExtensions(sequence(oid('2.5.29.19'), boolean(true), octetString([]), nullValue()))],
            ['a critical flag that is not a BOOLEAN', withExtensions(sequence(oid('2.5.29.19'), integer([1]), octetString([])))],
            ['an extnValue that is not an OCTET STRING', withExtensions(sequence(oid('2.5.29.19'), boolean(true)))],
            ['an extnID that is not an OID', withExtensions(sequence(integer([1]), octetString([])))],
            ['an extensions field of two SEQUENCEs', certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA), sequence(KEY_USAGE))] })],
            ['a primitive extensions field', certificate({ trailing: [context(3, false, [0x00])] })],
            ['an extensions field twice', certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA)), explicit(3, sequence(KEY_USAGE))] })],
            ['extensions that are not a SEQUENCE', certificate({ trailing: [explicit(3, integer([1]))] })],
        ])('should refuse %s', (_, der) => {
            expect(codeOf(() => parseCertificate(der))).toBe('PKI_X509_STRUCTURE_INVALID');
        });
    });
});

function utf8Value(text: string): Uint8Array {
    return concat([0x0c, text.length], ascii(text));
}
