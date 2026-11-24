import { readFileSync } from 'node:fs';
import { describe, it, expect, vi } from 'vitest';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiParseOptions } from '../../src/types/pki-types.js';
import {
    AUTHORITY_KEY_ID,
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
    SUBJECT_KEY_ID,
    tbsCertificate,
    utcTime,
    utf8,
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
            // basicConstraints, and the two key identifiers a conforming CA
            // must include — §4.2.1.1 and §4.2.1.2.
            expect(cert.extensions.map((e) => e.kind)).toEqual(['basicConstraints', 'subjectKeyIdentifier', 'authorityKeyIdentifier']);
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

    describe('profile diagnostics that need the whole certificate', () => {
        /**
         * Each of these is a sentence RFC 5280 or the CA/Browser Forum addresses
         * to the issuing CA, so each is a diagnostic and none refuses the
         * certificate: pkinative reads and enforces the extension whatever the
         * profile says about it, `strict` escalates for a caller who wants the
         * stricter reading, and the reason each one stays a diagnostic is
         * written beside its x509-limbo case in scripts/data/limbo-score.json.
         */
        const leaf = (...extensions: readonly Uint8Array[]): Uint8Array =>
            certificate({ trailing: [explicit(3, sequence(...extensions))] });
        const BC_LEAF = extension('2.5.29.19', sequence(boolean(false)), true);
        const dnsSan = (host: string): Uint8Array => extension('2.5.29.17', sequence(context(2, false, [...ascii(host)])));

        it('should report a missing authorityKeyIdentifier, and not on a self-signed root', () => {
            // §4.2.1.1 exempts a certificate that names nobody above it: a
            // self-signed root has no authority to identify. Equal encoded names
            // is how that is visible without a key operation.
            expect(diagnosticsOf(leaf(BC_LEAF))).toContain('PKI_DIAG_AKI_MISSING');
            expect(diagnosticsOf(leaf(BC_LEAF, AUTHORITY_KEY_ID))).not.toContain('PKI_DIAG_AKI_MISSING');
            const selfSigned = certificate({
                issuer: name([['2.5.4.3', utf8('Root')]]),
                subject: name([['2.5.4.3', utf8('Root')]]),
                trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID))],
            });
            expect(diagnosticsOf(selfSigned)).not.toContain('PKI_DIAG_AKI_MISSING');
        });

        it('should report a missing subjectKeyIdentifier on a CA and not on a leaf', () => {
            // §4.2.1.2 requires it of CA certificates; for an end entity it is a
            // SHOULD, and reporting a SHOULD on the commonest shape in existence
            // would be chatter rather than signal.
            expect(diagnosticsOf(leaf(BASIC_CONSTRAINTS_CA, AUTHORITY_KEY_ID))).toContain('PKI_DIAG_SKI_MISSING');
            expect(diagnosticsOf(leaf(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID, AUTHORITY_KEY_ID))).not.toContain('PKI_DIAG_SKI_MISSING');
            expect(diagnosticsOf(leaf(BC_LEAF, AUTHORITY_KEY_ID))).not.toContain('PKI_DIAG_SKI_MISSING');
        });

        it('should report neither on a v1 certificate, which has nowhere to put them', () => {
            // RFC 5280 §4.1.2.1 ties the extensions field to the version, so a
            // v1 certificate cannot carry either. Reporting them as missing
            // would be reporting the format rather than a choice the issuer made.
            const v1 = diagnosticsOf(certificate({ version: null, trailing: [] }));
            expect(v1).not.toContain('PKI_DIAG_AKI_MISSING');
            expect(v1).not.toContain('PKI_DIAG_SKI_MISSING');
        });

        it('should report nameConstraints in a certificate that is not a CA', () => {
            // §4.2.1.10's "MUST be used only in a CA certificate" addresses the
            // CA. An end-entity certificate issues nothing, so its constraints
            // bind nothing — §6.1.4 (g) only accumulates the constraints of a
            // certificate that issued the next one.
            // Non-empty: an extension that constrains nothing is refused
            // outright, so the fixture has to constrain something.
            const nc = extension('2.5.29.30', sequence(context(0, true, sequence(context(2, false, [...ascii('example.com')])))), true);
            expect(diagnosticsOf(leaf(BC_LEAF, nc))).toContain('PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY');
            // …and not on a CA, where they are exactly where they belong.
            expect(diagnosticsOf(leaf(BASIC_CONSTRAINTS_CA, nc))).not.toContain('PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY');
        });

        it('should report basicConstraints asserting cA without being critical', () => {
            const nonCritical = extension('2.5.29.19', sequence(boolean(true)), false);
            expect(diagnosticsOf(leaf(nonCritical))).toContain('PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL');
            expect(diagnosticsOf(leaf(BASIC_CONSTRAINTS_CA))).not.toContain('PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL');
            // A leaf's basicConstraints need not be critical: the sentence is
            // about CA certificates.
            expect(diagnosticsOf(leaf(extension('2.5.29.19', sequence(boolean(false)), false))))
                .not.toContain('PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL');
        });

        it('should report keyCertSign on a certificate that is not a CA', () => {
            // §4.2.1.3: the bit "is for use in CA certificates only". It grants
            // nothing either way — §6.1.4 (k) refuses to let a certificate
            // without cA issue another, whatever its keyUsage claims.
            const keyCertSign = extension('2.5.29.15', bitString([0x05]), true);
            expect(diagnosticsOf(leaf(BC_LEAF, keyCertSign))).toContain('PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA');
            expect(diagnosticsOf(leaf(BASIC_CONSTRAINTS_CA, keyCertSign))).not.toContain('PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA');
        });

        it('should report a commonName that names a host the subjectAltName does not', () => {
            // CA/Browser Forum BR 7.1.4.3. The default subject is
            // `CN=leaf.example`, which looks like a host and is not in this SAN.
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('other.example')))).toContain('PKI_DIAG_COMMON_NAME_NOT_IN_SAN');
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('leaf.example')))).not.toContain('PKI_DIAG_COMMON_NAME_NOT_IN_SAN');
        });

        it('should say nothing about a commonName no relying party could match as a host', () => {
            // The security question is whether a name a lenient relying party
            // might accept is here without the issuer having put it in the SAN.
            // `CN=Example Issuing CA` is not such a name, and reporting it would
            // be reporting the ordinary shape of every organisational subject.
            const organisational = certificate({
                subject: name([['2.5.4.3', utf8('Example Issuing CA')]]),
                trailing: [explicit(3, sequence(BC_LEAF, dnsSan('other.example')))],
            });
            expect(diagnosticsOf(organisational)).not.toContain('PKI_DIAG_COMMON_NAME_NOT_IN_SAN');
        });

        it('should say nothing about a commonName when the subjectAltName names no host', () => {
            const emailOnly = extension('2.5.29.17', sequence(context(1, false, [...ascii('a@other.example')])));
            expect(diagnosticsOf(leaf(BC_LEAF, emailOnly))).not.toContain('PKI_DIAG_COMMON_NAME_NOT_IN_SAN');
        });

        it('should report a dNSName outside RFC 1034 preferred name syntax', () => {
            // Underscores are everywhere in real certificates and resolve in
            // DNS, which is why this reports rather than refuses. Nothing
            // normalises the name, so it can only match the same spelling.
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('under_score.example')))).toContain('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX');
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('-leading.example')))).toContain('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX');
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('a..example')))).toContain('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX');
            // A wildcard is the everyday case and RFC 9525 gives it its own
            // grammar, so a leading `*` label is not reported.
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('*.leaf.example')))).not.toContain('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX');
            expect(diagnosticsOf(leaf(BC_LEAF, dnsSan('leaf.example')))).not.toContain('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX');
        });

        it('should escalate every one of them under strict, and none of them by itself', () => {
            // The whole point of the channel: the same certificate parses for a
            // caller who wants to read it and is refused for one who wants to
            // conform. A refusal here would take that choice away.
            const der = leaf(BC_LEAF, extension('2.5.29.15', bitString([0x05]), true));
            expect(parseCertificate(der, QUIET).diagnostics.map((d) => d.code)).toContain('PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA');
            expect(codeOf(() => parseCertificate(der, { strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
        });
    });

    describe('a public key of an algorithm it does not classify', () => {
        // 1.2.3.4 is no key algorithm and never will be: the test does not
        // depend on which real schemes the engine has learnt.
        const der = certificate({ subjectPublicKeyInfo: sequence(algorithm('1.2.3.4'), bitString([1, 2, 3])) });

        it('should report PKI_DIAG_SPKI_ALGORITHM_UNRECOGNISED at tbsCertificate.subjectPublicKeyInfo.algorithm, as an info', () => {
            const seen: PkiDiagnostic[] = [];
            const cert = parseCertificate(der, { onDiagnostic: (d) => { seen.push(d); } });
            expect(seen.map((d) => [d.code, d.severity, d.path])).toEqual([['PKI_DIAG_SPKI_ALGORITHM_UNRECOGNISED', 'info', 'tbsCertificate.subjectPublicKeyInfo.algorithm']]);
            expect(cert.diagnostics).toEqual(seen);
            expect(cert.subjectPublicKeyInfo.kind).toBe('unknown');
            // The offset is the AlgorithmIdentifier's own, in the input.
            expect(der[seen[0]?.offset ?? 0]).toBe(0x30);
            expect([...der.subarray((seen[0]?.offset ?? 0) + 2, (seen[0]?.offset ?? 0) + 7)]).toEqual([...oid('1.2.3.4')]);
        });

        it('should parse it under strict, with the diagnostic recorded: an info never refuses', () => {
            const cert = parseCertificate(der, { strict: true });
            expect(cert.subjectPublicKeyInfo).toMatchObject({ kind: 'unknown', algorithm: { oid: '1.2.3.4' } });
            expect(cert.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_SPKI_ALGORITHM_UNRECOGNISED']);
        });

        it('should warn once on the default sink', () => {
            const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
            try {
                parseCertificate(der);
                expect(warn).toHaveBeenCalledTimes(1);
            } finally {
                warn.mockRestore();
            }
        });
    });

    // ADR 0026: the three post-quantum key families whose RFC says what a
    // keyUsage may assert. One `it` per sentence, named with its section.
    describe('keyUsage against a post-quantum key (RFC 9881 §5, RFC 9909 §6, RFC 9935 §5)', () => {
        const CODE = 'PKI_DIAG_KEY_USAGE_KEY_ALGORITHM_MISMATCH';
        /** RFC 5280 §4.2.1.3, the named bits in order. */
        const BITS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
        /** A critical keyUsage asserting exactly these bits, as DER writes a named bit list: no trailing zero bit. */
        const keyUsage = (...names: readonly string[]): Uint8Array => {
            const indexes = names.map((n) => BITS.indexOf(n));
            const last = Math.max(-1, ...indexes);
            const bytes = new Array<number>(last < 0 ? 0 : (last >> 3) + 1).fill(0);
            for (const i of indexes) bytes[i >> 3] = (bytes[i >> 3] as number) | (0x80 >> (i & 7));
            return extension('2.5.29.15', bitString(bytes, last < 0 ? 0 : 7 - (last & 7)), true);
        };
        const key = (dotted: string, length: number, parameters?: Uint8Array): Uint8Array => sequence(algorithm(dotted, parameters), bitString(new Array<number>(length).fill(7)));
        const KEYS = {
            'ml-dsa-44': key('2.16.840.1.101.3.4.3.17', 1312),
            'ml-dsa-65': key('2.16.840.1.101.3.4.3.18', 1952),
            'ml-dsa-87': key('2.16.840.1.101.3.4.3.19', 2592),
            'slh-dsa-sha2-128s': key('2.16.840.1.101.3.4.3.20', 32),
            'slh-dsa-shake-256f': key('2.16.840.1.101.3.4.3.31', 64),
            'ml-kem-512': key('2.16.840.1.101.3.4.4.1', 800),
            'ml-kem-768': key('2.16.840.1.101.3.4.4.2', 1184),
            'ml-kem-1024': key('2.16.840.1.101.3.4.4.3', 1568),
        } as const;
        const SIGNATURE_KEYS = ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128s', 'slh-dsa-shake-256f'] as const;
        const KEM_KEYS = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'] as const;
        const cert = (spki: Uint8Array, ...extensions: readonly Uint8Array[]): Uint8Array =>
            certificate({ subjectPublicKeyInfo: spki, trailing: [explicit(3, sequence(...extensions, AUTHORITY_KEY_ID))] });
        const raised = (der: Uint8Array): PkiDiagnostic[] => {
            const seen: PkiDiagnostic[] = [];
            parseCertificate(der, { onDiagnostic: (d) => { seen.push(d); } });
            return seen.filter((d) => d.code === CODE);
        };

        it.each(SIGNATURE_KEYS)('should say nothing about an %s key that asserts only signature usages — "at least one of" the four', (kind) => {
            for (const usages of [['digitalSignature'], ['nonRepudiation'], ['keyCertSign'], ['cRLSign'], ['digitalSignature', 'nonRepudiation', 'keyCertSign', 'cRLSign']]) {
                expect(raised(cert(KEYS[kind], keyUsage(...usages)))).toEqual([]);
            }
        });

        it.each(SIGNATURE_KEYS.flatMap((kind) => ['keyEncipherment', 'dataEncipherment', 'keyAgreement', 'encipherOnly', 'decipherOnly'].map((usage) => [kind, usage] as const)))(
            'should report an %s key that asserts %s beside digitalSignature — "MUST NOT have any of"',
            (kind, usage) => {
                const [diagnostic] = raised(cert(KEYS[kind], keyUsage('digitalSignature', usage)));
                expect(diagnostic).toMatchObject({ code: CODE, severity: 'warning', path: 'tbsCertificate.extensions.keyUsage', standard: 'RFC 9881 §5, RFC 9909 §6, RFC 9935 §5' });
                // The message names the clause of the key's own RFC, the key and what it asserts.
                expect(diagnostic?.message).toContain(kind.startsWith('ml-dsa-') ? 'RFC 9881 §5' : 'RFC 9909 §6');
                expect(diagnostic?.message).toContain(kind);
                expect(diagnostic?.message).toContain(`[digitalSignature, ${usage}]`);
            },
        );

        it.each(SIGNATURE_KEYS)('should report an %s key whose only usage is one it cannot have', (kind) => {
            expect(raised(cert(KEYS[kind], keyUsage('keyEncipherment')))).toHaveLength(1);
            expect(raised(cert(KEYS[kind], keyUsage('keyAgreement', 'decipherOnly')))).toHaveLength(1);
        });

        it.each(SIGNATURE_KEYS)('should report an %s key whose keyUsage asserts nothing: not one of the four is set', (kind) => {
            // RFC 5280 already wants one bit (PKI_DIAG_KEY_USAGE_EMPTY); RFC 9881 §5 and RFC 9909 §6 want one of these four.
            const seen: string[] = [];
            parseCertificate(cert(KEYS[kind], keyUsage()), { onDiagnostic: (d) => { seen.push(d.code); } });
            expect(seen).toEqual(expect.arrayContaining(['PKI_DIAG_KEY_USAGE_EMPTY', CODE]));
        });

        it.each(KEM_KEYS)('should say nothing about an %s key that asserts keyEncipherment alone (RFC 9935 §5)', (kind) => {
            expect(raised(cert(KEYS[kind], keyUsage('keyEncipherment')))).toEqual([]);
        });

        it.each(KEM_KEYS.flatMap((kind) => [
            ['digitalSignature'], ['keyAgreement'], ['dataEncipherment'],
            ['keyEncipherment', 'dataEncipherment'], ['digitalSignature', 'keyEncipherment'], ['keyEncipherment', 'keyAgreement', 'decipherOnly'], [],
        ].map((usages) => [kind, usages] as const)))('should report an %s key that asserts %j — keyEncipherment "MUST be the only key usage set"', (kind, usages) => {
            const [diagnostic] = raised(cert(KEYS[kind], keyUsage(...usages)));
            expect(diagnostic).toMatchObject({ code: CODE, severity: 'warning', path: 'tbsCertificate.extensions.keyUsage' });
            expect(diagnostic?.message).toContain('RFC 9935 §5');
            expect(diagnostic?.message).toContain(kind);
        });

        it.each([...SIGNATURE_KEYS, ...KEM_KEYS])('should say nothing about an %s key without a keyUsage — each sentence opens "if the keyUsage extension is present"', (kind) => {
            expect(raised(cert(KEYS[kind], SUBJECT_KEY_ID))).toEqual([]);
        });

        it('should say nothing when the extension is left undecoded: an unread keyUsage is not judged', () => {
            const seen: string[] = [];
            parseCertificate(cert(KEYS['ml-dsa-65'], keyUsage('keyEncipherment')), { decodeExtensions: false, onDiagnostic: (d) => { seen.push(d.code); } });
            expect(seen).not.toContain(CODE);
        });

        it.each<[string, Uint8Array]>([
            ['an RSA key', sequence(algorithm('1.2.840.113549.1.1.1', nullValue()), bitString(sequence(integer([0x41, 0x02, 0x03]), integer([0x01, 0x00, 0x01]))))],
            ['an EC key', sequence(algorithm('1.2.840.10045.2.1', oid('1.2.840.10045.3.1.7')), bitString([0x04, ...new Array<number>(64).fill(1)]))],
            ['an Ed25519 key', key('1.3.101.112', 32)],
            ['an X25519 key', key('1.3.101.110', 32)],
            ['a key of an algorithm pkinative does not classify', key('1.2.3.4', 8)],
        ])('should say nothing about %s, whatever its keyUsage: no RFC of these three speaks of it', (_label, spki) => {
            for (const usages of [['keyEncipherment'], ['digitalSignature', 'keyAgreement'], ['keyEncipherment', 'dataEncipherment'], []]) {
                expect(raised(cert(spki, keyUsage(...usages)))).toEqual([]);
            }
        });

        it('should refuse the certificate under strict: a warning is a MUST the issuer broke', () => {
            const error = thrown(() => parseCertificate(cert(KEYS['ml-kem-768'], keyUsage('digitalSignature')), { strict: true }));
            expect(error).toBeInstanceOf(PkiError);
            expect(error).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
            expect((error as PkiError).message).toContain(CODE);
            expect(() => parseCertificate(cert(KEYS['ml-kem-768'], keyUsage('keyEncipherment'), SUBJECT_KEY_ID), { strict: true })).not.toThrow();
        });

        it('should say nothing about the fixtures OpenSSL and the RFC 9881 authors wrote', () => {
            for (const name of ['root-ml-dsa-65', 'leaf-ml-dsa-44', 'rfc9881-ml-dsa-44', 'rfc9881-ml-dsa-65', 'rfc9881-ml-dsa-87']) {
                expect(raised(new Uint8Array(readFileSync(`tests/fixtures/ml-dsa/${name}.der`))), name).toEqual([]);
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

        it('should read an explicit v1 as v1 with a diagnostic, and refuse it under strict', () => {
            const der = certificate({ version: explicit(0, integer([0])), trailing: [] });
            expect(parseCertificate(der, QUIET).version).toBe(1);
            expect(diagnosticsOf(der)).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
            expect(codeOf(() => parseCertificate(der, { strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
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
            // The AKI is absent from this minimal trailing, and §4.2.1.1 asks
            // for one on any certificate that names another subject as issuer.
            const trailing = [explicit(3, sequence(extension('2.5.29.17', SAN), SUBJECT_KEY_ID))];
            expect(diagnosticsOf(certificate({ subject: name(), trailing })))
                .toEqual(['PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL', 'PKI_DIAG_AKI_MISSING']);
        });

        it('should accept an empty subject with a critical subjectAltName', () => {
            const trailing = [explicit(3, sequence(extension('2.5.29.17', SAN, true), AUTHORITY_KEY_ID, SUBJECT_KEY_ID))];
            expect(diagnosticsOf(certificate({ subject: name(), trailing }))).toEqual([]);
        });
    });

    describe('unique identifiers', () => {
        const V2 = explicit(0, integer([1]));

        it('should read both identifiers of a v2 certificate', () => {
            const cert = parseCertificate(certificate({ version: V2, trailing: [context(1, false, [0x00, 0xaa]), context(2, false, [0x04, 0xb0])] }));
            expect([...(cert.issuerUniqueId?.bytes ?? [])]).toEqual([0xaa]);
            expect(cert.subjectUniqueId).toMatchObject({ unusedBits: 4 });
            // Read, and reported: §4.1.2.8 forbids conforming CAs to generate either.
            expect(cert.diagnostics.map((d) => d.path)).toEqual(['tbsCertificate.issuerUniqueID', 'tbsCertificate.subjectUniqueID']);
            expect(cert.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_UNIQUE_ID_PRESENT', 'PKI_DIAG_UNIQUE_ID_PRESENT']);
        });

        it('should report unique identifiers in a v1 certificate', () => {
            expect(diagnosticsOf(certificate({ version: null, trailing: [context(1, false, [0x00, 0xaa])] }))).toEqual(['PKI_DIAG_UNIQUE_ID_REQUIRES_V2', 'PKI_DIAG_UNIQUE_ID_PRESENT']);
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

        it('should read an explicit FALSE critical flag with a diagnostic', () => {
            const der = withExtensions(extension('2.5.29.14', octetString([1]), false), AUTHORITY_KEY_ID);
            expect(parseCertificate(der, QUIET).extensions[0]?.critical).toBe(false);
            expect(diagnosticsOf(der)).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
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

describe('parseCertificate — the structural guards answer at the structure they guard', () => {
    const errorOf = (der: Uint8Array): unknown => thrown(() => parseCertificate(der, QUIET));
    const SKI_VALUE = octetString([0x04, 0x01, 0x01]);

    it.each([
        ['one value', sequence(oid('2.5.29.14'))],
        ['four values', sequence(oid('2.5.29.14'), boolean(true), SKI_VALUE, SKI_VALUE)],
    ])('should refuse an Extension of %s at the extension itself', (_label, ext) => {
        const error = errorOf(certificate({ trailing: [explicit(3, sequence(ext))] }));
        expect(error).toBeInstanceOf(PkiCertificateError);
        expect(error).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID', path: 'tbsCertificate.extensions[0]' });
    });

    it.each([
        ['two', sequence(tbsCertificate(), algorithm(ECDSA_SHA256))],
        ['four', sequence(tbsCertificate(), algorithm(ECDSA_SHA256), bitString([0x00]), nullValue())],
    ])('should refuse a Certificate of %s values at the certificate itself', (_label, der) => {
        expect(errorOf(der)).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID', path: 'certificate' });
    });

    it.each([
        ['issuerUniqueID', 1],
        ['subjectUniqueID', 2],
    ])('should name the repeated %s in the error path', (field, tag) => {
        const der = certificate({ trailing: [context(tag, false, [0x00, 0xaa]), context(tag, false, [0x00, 0xbb])] });
        expect(errorOf(der)).toMatchObject({ code: 'PKI_X509_UNIQUE_ID_INVALID', path: `tbsCertificate.${field}` });
    });

    it('should not call a validity that starts and ends at the same instant inverted', () => {
        const der = certificate({ validity: sequence(utcTime('250101000000Z'), utcTime('250101000000Z')) });
        expect(diagnosticsOf(der)).toEqual([]);
    });

    it('should not hold an organisational commonName with a colon and a space to the SAN', () => {
        const san = extension('2.5.29.17', sequence(context(2, false, ascii('a.example'))));
        const der = certificate({
            subject: name([['2.5.4.3', utf8('Example: CA')]]),
            trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID, AUTHORITY_KEY_ID, san))],
        });
        expect(diagnosticsOf(der)).toEqual([]);
    });
});
