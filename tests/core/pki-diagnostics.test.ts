import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as diagnostics from '../../src/core/pki-diagnostics.js';
import { createDiagnosticEmitter, sanEmptyDiagnostic, serialTooLongDiagnostic } from '../../src/core/pki-diagnostics.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';

const ROOT = resolve(import.meta.dirname, '..', '..');

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

describe('createDiagnosticEmitter', () => {
    it('should throw PKI_STRICT_DIAGNOSTIC under strict, naming the diagnostic code, and record nothing', () => {
        const emitter = createDiagnosticEmitter(true, undefined);
        let caught: unknown;
        try {
            emitter.emit(serialTooLongDiagnostic(21, 4));
        } catch (err) {
            caught = err;
        }
        expect(caught).toBeInstanceOf(PkiError);
        expect(caught).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        expect((caught as PkiError).message).toMatch(/^pkinative: \[PKI_DIAG_SERIAL_TOO_LONG\]/);
        expect(emitter.diagnostics).toEqual([]);
    });

    it('should deliver every diagnostic to the handler, record them in order, and never touch the console', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        const received: PkiDiagnostic[] = [];
        const emitter = createDiagnosticEmitter(false, (d) => received.push(d));
        const a = serialTooLongDiagnostic(21);
        const b = serialTooLongDiagnostic(22);
        emitter.emit(a);
        emitter.emit(b);
        expect(received).toEqual([a, b]);
        expect(emitter.diagnostics).toEqual([a, b]);
        expect(warn).not.toHaveBeenCalled();
    });

    it('should warn once per code by default, while still recording every diagnostic', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        const emitter = createDiagnosticEmitter(undefined, undefined);
        emitter.emit(serialTooLongDiagnostic(21));
        emitter.emit(serialTooLongDiagnostic(30));
        emitter.emit(sanEmptyDiagnostic('tbsCertificate.extensions.subjectAltName'));
        expect(warn).toHaveBeenCalledTimes(2);
        expect(warn.mock.calls[0]?.[0]).toMatch(/^pkinative: \[PKI_DIAG_SERIAL_TOO_LONG\] the serial number is 21 octets/);
        expect(emitter.diagnostics).toHaveLength(3);
    });

    it('should stay silent on a host without a console', () => {
        vi.stubGlobal('console', undefined);
        const emitter = createDiagnosticEmitter(false, undefined);
        expect(() => emitter.emit(serialTooLongDiagnostic(21))).not.toThrow();
        expect(emitter.diagnostics).toHaveLength(1);
    });
});

describe('diagnostic payload factories', () => {
    const cases: ReadonlyArray<readonly [string, PkiDiagnostic]> = [
        ['PKI_DIAG_SERIAL_TOO_LONG', diagnostics.serialTooLongDiagnostic(21, 3)],
        ['PKI_DIAG_SERIAL_NOT_POSITIVE', diagnostics.serialNotPositiveDiagnostic(3)],
        ['PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH', diagnostics.signatureAlgorithmMismatchDiagnostic('1.2.840.113549.1.1.11', '1.2.840.113549.1.1.5')],
        ['PKI_DIAG_RSA_PARAMETERS_NOT_NULL', diagnostics.rsaParametersNotNullDiagnostic('signatureAlgorithm', 9)],
        ['PKI_DIAG_EXTENSIONS_REQUIRE_V3', diagnostics.extensionsRequireV3Diagnostic(1)],
        ['PKI_DIAG_UNIQUE_ID_REQUIRES_V2', diagnostics.uniqueIdRequiresV2Diagnostic(1)],
        ['PKI_DIAG_GENERALIZED_TIME_BEFORE_2050', diagnostics.generalizedTimeBefore2050Diagnostic('tbsCertificate.validity.notBefore', '20300101000000Z', 40)],
        ['PKI_DIAG_GENERALIZED_TIME_FRACTION', diagnostics.generalizedTimeFractionDiagnostic('tbsCertificate.validity.notAfter', '20510101000000.5Z')],
        ['PKI_DIAG_VALIDITY_INVERTED', diagnostics.validityInvertedDiagnostic('2030-01-01T00:00:00.000Z', '2020-01-01T00:00:00.000Z')],
        ['PKI_DIAG_EMPTY_ISSUER', diagnostics.emptyIssuerDiagnostic()],
        ['PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL', diagnostics.emptySubjectSanNotCriticalDiagnostic()],
        ['PKI_DIAG_SAN_EMPTY', diagnostics.sanEmptyDiagnostic('tbsCertificate.extensions.subjectAltName')],
        ['PKI_DIAG_RDN_SET_NOT_SORTED', diagnostics.rdnSetNotSortedDiagnostic('tbsCertificate.subject[0]', 60)],
        ['PKI_DIAG_CMS_VERSION_MISMATCH', diagnostics.cmsVersionMismatchDiagnostic('content.version', 1, 3, 4)],
        ['PKI_DIAG_CMS_SET_NOT_SORTED', diagnostics.cmsSetNotSortedDiagnostic('content.certificates', 40)],
        ['PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER', diagnostics.cmsSignedAttributesNotDerDiagnostic('content.signerInfos[0].signedAttrs', 900)],
        ['PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED', diagnostics.cmsDigestAlgorithmNotListedDiagnostic('content.signerInfos[0].digestAlgorithm', '2.16.840.1.101.3.4.2.3')],
        ['PKI_DIAG_CRL_EXTENSION_MALFORMED', diagnostics.crlExtensionMalformedDiagnostic('tbsCertList.crlExtensions.cRLNumber', 'cRLNumber', 'not a DER INTEGER (PKI_ASN1_INTEGER_INVALID)')],
        ['PKI_DIAG_KEY_KDF_ITERATIONS_LOW', diagnostics.keyKdfIterationsLowDiagnostic('encryptionAlgorithm.parameters.keyDerivationFunc.parameters.iterationCount', 1)],
        ['PKI_DIAG_PRINTABLE_STRING_CHARSET', diagnostics.printableStringCharsetDiagnostic('tbsCertificate.subject[2]', '*')],
        ['PKI_DIAG_TELETEX_AS_LATIN1', diagnostics.teletexAsLatin1Diagnostic('tbsCertificate.issuer[1]')],
        ['PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE', diagnostics.nameAttributeStringTypeDiagnostic('tbsCertificate.subject.rdns[0][0].value', 'countryName', 'UTF8String', 'a PrintableString', 70)],
        ['PKI_DIAG_COUNTRY_NAME_SIZE', diagnostics.countryNameSizeDiagnostic('tbsCertificate.subject.rdns[0][0].value', 3, 70)],
        ['PKI_DIAG_STRING_SIGNATURE', diagnostics.stringSignatureDiagnostic('tbsCertificate.subject.rdns[0][0].value', 'BMPString', 70)],
        ['PKI_DIAG_STRING_ESCAPE_SEQUENCE', diagnostics.stringEscapeSequenceDiagnostic('tbsCertificate.subject.rdns[0][0].value', 'UTF8String', 'ESC', 70)],
        ['PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION', diagnostics.unknownCriticalExtensionDiagnostic('1.3.6.1.4.1.99999.1', 'tbsCertificate.extensions[4]')],
        ['PKI_DIAG_PATHLEN_WITHOUT_CA', diagnostics.pathLenWithoutCaDiagnostic()],
        ['PKI_DIAG_KEY_USAGE_EMPTY', diagnostics.keyUsageEmptyDiagnostic()],
        ['PKI_DIAG_NAMED_BITS_TRAILING_ZERO', diagnostics.namedBitsTrailingZeroDiagnostic('tbsCertificate.extensions.keyUsage')],
        ['PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL', diagnostics.nameConstraintsNotCriticalDiagnostic()],
        ['PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY', diagnostics.nameConstraintsInEndEntityDiagnostic()],
        ['PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL', diagnostics.basicConstraintsNotCriticalDiagnostic()],
        ['PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL', diagnostics.policyConstraintsNotCriticalDiagnostic()],
        ['PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL', diagnostics.subjectDirectoryAttributesCriticalDiagnostic()],
        ['PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA', diagnostics.keyCertSignWithoutCaDiagnostic()],
        ['PKI_DIAG_AKI_MISSING', diagnostics.akiMissingDiagnostic()],
        ['PKI_DIAG_SKI_MISSING', diagnostics.skiMissingDiagnostic()],
        ['PKI_DIAG_COMMON_NAME_NOT_IN_SAN', diagnostics.commonNameNotInSanDiagnostic('notinsan.example.com')],
        ['PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX', diagnostics.dnsNameNotPreferredSyntaxDiagnostic('under_score.example.com', 'tbsCertificate.extensions.subjectAltName[0]')],
        ['PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED', diagnostics.akiIssuerSerialUnpairedDiagnostic()],
        ['PKI_DIAG_POLICY_DUPLICATE', diagnostics.policyDuplicateDiagnostic('2.23.140.1.2.1')],
        ['PKI_DIAG_POLICY_CONSTRAINTS_EMPTY', diagnostics.policyConstraintsEmptyDiagnostic()],
        ['PKI_DIAG_DEFAULT_ENCODED', diagnostics.defaultEncodedDiagnostic('tbsCertificate.extensions[0].cA', 'FALSE', 177)],
        ['PKI_DIAG_BER_CONSTRUCT_ACCEPTED', diagnostics.berConstructAcceptedDiagnostic('indefinite length', 0)],
        ['PKI_DIAG_PEM_LAX_ACCEPTED', diagnostics.pemLaxAcceptedDiagnostic('line longer than 64 characters', 28)],
        ['PKI_DIAG_SPKI_RSA_EXPONENT_WEAK', diagnostics.spkiRsaExponentWeakDiagnostic('tbsCertificate.subjectPublicKeyInfo.subjectPublicKey', 1n, 180)],
        ['PKI_DIAG_SPKI_EC_PARAMETERS_INVALID', diagnostics.spkiEcParametersInvalidDiagnostic('tbsCertificate.subjectPublicKeyInfo.algorithm.parameters', undefined, 170)],
    ];

    it.each(cases)('should build %s as a frozen, fully described payload', (code, payload) => {
        expect(payload.code).toBe(code);
        expect(Object.isFrozen(payload)).toBe(true);
        expect(['warning', 'info']).toContain(payload.severity);
        expect(payload.message.length).toBeGreaterThan(20);
        expect(payload.message.startsWith('pkinative')).toBe(false);
        // A diagnostic names the document it comes from, and the Web PKI's own
        // profile is one of them: CA/Browser Forum BR 7.1.4.3 is what forbids a
        // commonName that no subjectAltName repeats, and no RFC says it.
        expect(payload.standard).toMatch(/^(RFC|ITU-T|CA\/Browser Forum) /);
        expect(typeof payload.path).toBe('string');
    });

    it('should cover exactly the codes of docs/data/diagnostics.json, one factory each', () => {
        const registry = JSON.parse(readFileSync(resolve(ROOT, 'docs', 'data', 'diagnostics.json'), 'utf8')) as { diagnostics: Array<{ code: string; severity: string; standard: string }> };
        expect(cases.map(([code]) => code).sort()).toEqual(registry.diagnostics.map((d) => d.code).sort());
        const factories = Object.keys(diagnostics).filter((name) => name.endsWith('Diagnostic'));
        expect(factories).toHaveLength(cases.length);
        for (const [, payload] of cases) {
            const entry = registry.diagnostics.find((d) => d.code === payload.code);
            expect(entry?.severity, payload.code).toBe(payload.severity);
            expect(entry?.standard, payload.code).toBe(payload.standard);
        }
    });
});
