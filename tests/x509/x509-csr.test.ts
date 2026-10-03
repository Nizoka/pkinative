import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { createCertificationRequest } from '../../src/build/build-csr.js';
import { encodeKeyUsage, encodeSubjectAltName } from '../../src/build/build-structures.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { SignatureAlgorithm } from '../../src/types/crypto-types.js';
import type { PkiParseOptions } from '../../src/types/pki-types.js';
import { parseCertificationRequest } from '../../src/x509/x509-csr.js';
import { samples } from '../../scripts/lib/samples.js';
import {
    ECDSA_SHA256,
    algorithm,
    bitString,
    boolean,
    context,
    ecKey,
    extension,
    integer,
    name,
    octetString,
    oid,
    printable,
    set,
    utf8,
} from '../helpers/cert-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';

/**
 * The PKCS#10 reader, held two ways. Against the writer: what
 * `createCertificationRequest` emits is read back with **zero diagnostics**,
 * for every key family it signs with — the rule that holds `build/` and
 * `x509/` together. And against hostile bytes assembled from first principles:
 * every structural error names its code, every bound names its limit.
 */

const QUIET: PkiParseOptions = { onDiagnostic: () => undefined };
const CN = '2.5.4.3';
const EXTENSION_REQUEST = '1.2.840.113549.1.9.14';
const CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7';
const SHA256_RSA = '1.2.840.113549.1.1.11';

function codeOf(fn: () => unknown): string {
    try {
        fn();
    } catch (error) {
        if (error instanceof PkiError) return error.code;
        throw error;
    }
    throw new Error('expected a throw');
}

function errorOf(fn: () => unknown): PkiError {
    try {
        fn();
    } catch (error) {
        if (error instanceof PkiError) return error;
        throw error;
    }
    throw new Error('expected a throw');
}

function diagnosticsOf(der: Uint8Array, options: PkiParseOptions = {}): string[] {
    const seen: string[] = [];
    parseCertificationRequest(der, { ...options, onDiagnostic: (d) => { seen.push(d.code); } });
    return seen;
}

// ── Synthetic requests, from first principles ──

const SUBJECT = name([[CN, utf8('host.example')]]);
const SIGNATURE = bitString(sequence(integer([0x01]), integer([0x02])));

/** An Attribute: a type and its SET OF values. */
const attribute = (type: string, ...values: Uint8Array[]): Uint8Array => sequence(oid(type), set(...values));

interface InfoParts {
    readonly version?: Uint8Array;
    readonly subject?: Uint8Array;
    readonly spki?: Uint8Array;
    /** The whole attributes field; `null` omits it. */
    readonly attributes?: Uint8Array | null;
}

/** A CertificationRequestInfo; attributes is `[0] IMPLICIT SET OF`, empty by default. */
function info(parts: InfoParts = {}): Uint8Array {
    return sequence(
        parts.version ?? integer([0x00]),
        parts.subject ?? SUBJECT,
        parts.spki ?? ecKey(),
        ...(parts.attributes === null ? [] : [parts.attributes ?? context(0, true, [])]),
    );
}

/** The attributes field holding these attributes. */
const attributes = (...entries: Uint8Array[]): Uint8Array => context(0, true, entries.flatMap((e) => Array.from(e)));

function csr(parts: InfoParts & { readonly info?: Uint8Array; readonly signatureAlgorithm?: Uint8Array; readonly signature?: Uint8Array } = {}): Uint8Array {
    return sequence(parts.info ?? info(parts), parts.signatureAlgorithm ?? algorithm(ECDSA_SHA256), parts.signature ?? SIGNATURE);
}

const SAN = extension('2.5.29.17', encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }]));
const KEY_USAGE = extension('2.5.29.15', encodeKeyUsage(['digitalSignature']), true);

// ── Real requests, signed by Web Crypto ──

type GeneratedPair = webcrypto.CryptoKeyPair;

async function signed(keyParams: object, signWith: SignatureAlgorithm, withExtensions = true): Promise<Uint8Array> {
    const pair = await webcrypto.subtle.generateKey(keyParams as never, true, ['sign', 'verify']) as GeneratedPair;
    const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
    return createCertificationRequest({
        subject: [[{ type: '2.5.4.6', value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'host.example' }]],
        subjectPublicKey: spki,
        ...(withExtensions ? {
            extensions: [
                { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }, { kind: 'dNSName', value: 'www.host.example' }]) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
            ],
        } : {}),
    }, { key: pair.privateKey as never, algorithm: signWith });
}

describe('parseCertificationRequest — what createCertificationRequest writes', () => {
    it.each([
        ['RSA PKCS#1 v1.5 / SHA-256', { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, 'rsa', SHA256_RSA],
        ['ECDSA P-256 / SHA-256', { name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, 'ec', ECDSA_SHA256],
        ['Ed25519', { name: 'Ed25519' }, { name: 'Ed25519' }, 'ed25519', '1.3.101.112'],
    ])('should read back a %s request with zero diagnostics', async (_label, keyParams, signWith, kind, signatureOid) => {
        const der = await signed(keyParams, signWith as SignatureAlgorithm);
        expect(diagnosticsOf(der)).toEqual([]);
        const request = parseCertificationRequest(der, QUIET);
        expect(request.version).toBe(0);
        expect(request.subject.rdns.map((rdn) => rdn.map((a) => `${a.type}=${a.value?.value ?? '?'}`))).toEqual([['2.5.4.6=FR'], [`${CN}=host.example`]]);
        expect(request.subjectPublicKeyInfo.kind).toBe(kind);
        expect(request.signatureAlgorithm.oid).toBe(signatureOid);
        expect(request.signatureValue.unusedBits).toBe(0);
        expect(request.challengePassword).toBeUndefined();
        expect(request.attributes.map((a) => a.oid)).toEqual([EXTENSION_REQUEST]);
        expect(request.attributes[0]?.values).toHaveLength(1);
        expect(request.extensions?.map((e) => `${e.kind}${e.critical ? '!' : ''}`)).toEqual(['subjectAltName', 'keyUsage!']);
        const san = request.extensions?.[0];
        expect(san?.kind === 'subjectAltName' ? san.names.map((n) => (n.kind === 'dNSName' ? n.value : '?')) : []).toEqual(['host.example', 'www.host.example']);
        // The signed bytes are exactly the first child of the envelope, as a view of the input.
        expect(request.tbsDer).toEqual(decodeAsn1(der).children[0]?.bytes);
        expect(request.tbsDer.buffer).toBe(der.buffer);
        expect(request.der).toEqual(der);
        expect(Object.isFrozen(request)).toBe(true);
        expect(Object.isFrozen(request.attributes)).toBe(true);
        expect(request.diagnostics).toEqual([]);
    });

    it('should read a request that asks for nothing: attributes present and empty, extensions undefined', async () => {
        const der = await signed({ name: 'Ed25519' }, { name: 'Ed25519' }, false);
        expect(diagnosticsOf(der)).toEqual([]);
        const request = parseCertificationRequest(der, QUIET);
        expect(request.attributes).toEqual([]);
        expect(request.extensions).toBeUndefined();
    });

    it('should keep every requested extension raw under decodeExtensions: false, and refuse a non-boolean', async () => {
        const der = await signed({ name: 'Ed25519' }, { name: 'Ed25519' });
        const request = parseCertificationRequest(der, { ...QUIET, decodeExtensions: false });
        expect(request.extensions?.map((e) => e.kind)).toEqual(['raw', 'raw']);
        expect(request.extensions?.map((e) => e.oid)).toEqual(['2.5.29.17', '2.5.29.15']);
        expect(request.extensions?.[1]?.critical).toBe(true);
        expect(codeOf(() => parseCertificationRequest(der, { decodeExtensions: 'yes' as unknown as boolean }))).toBe('PKI_INVALID_OPTION');
    });

    it('should read back every frozen CSR sample with zero diagnostics', async () => {
        const catalogue = await samples();
        const names = [...catalogue.keys()].filter((key) => key.startsWith('csr/'));
        expect(names).toEqual(['csr/no-attributes', 'csr/with-requested-extensions']);
        for (const key of names) {
            const der = catalogue.get(key) as Uint8Array;
            expect(diagnosticsOf(der), key).toEqual([]);
            const request = parseCertificationRequest(der, QUIET);
            expect(request.subject.rdns.at(-1)?.[0]?.value?.value, key).toBe('sample.example');
            expect(request.subjectPublicKeyInfo.kind, key).toBe('ed25519');
        }
        const rich = parseCertificationRequest(catalogue.get('csr/with-requested-extensions') as Uint8Array, QUIET);
        expect(rich.extensions?.map((e) => e.kind)).toEqual(['subjectAltName', 'keyUsage']);
        expect(parseCertificationRequest(catalogue.get('csr/no-attributes') as Uint8Array, QUIET).extensions).toBeUndefined();
    }, 30_000);
});

describe('parseCertificationRequest — a well-formed synthetic request', () => {
    const der = csr({
        attributes: attributes(
            attribute(CHALLENGE_PASSWORD, utf8('open sesame')),
            attribute(EXTENSION_REQUEST, sequence(SAN, KEY_USAGE)),
            attribute('1.2.3.4.5', integer([0x07]), printable('two')),
        ),
    });
    const request = parseCertificationRequest(der, QUIET);

    it('should expose the challenge password, the extensions and every other attribute as DER', () => {
        expect(request.challengePassword).toBe('open sesame');
        expect(request.extensions?.map((e) => e.kind)).toEqual(['subjectAltName', 'keyUsage']);
        expect(request.attributes.map((a) => [a.oid, a.values.length])).toEqual([[CHALLENGE_PASSWORD, 1], [EXTENSION_REQUEST, 1], ['1.2.3.4.5', 2]]);
        expect(request.attributes[2]?.values[0]).toEqual(integer([0x07]));
        expect(request.attributes[2]?.values[1]).toEqual(printable('two'));
    });

    it('should hold zero-copy views of the input', () => {
        expect(request.attributes[2]?.values[1]?.buffer).toBe(der.buffer);
        expect(request.subject.der.buffer).toBe(der.buffer);
        expect(request.tbsDer.buffer).toBe(der.buffer);
        expect(Object.isFrozen(request.attributes[2]?.values)).toBe(true);
    });

    it('should read a PrintableString challenge password too', () => {
        const printableDer = csr({ attributes: attributes(attribute(CHALLENGE_PASSWORD, printable('abc'))) });
        expect(parseCertificationRequest(printableDer, QUIET).challengePassword).toBe('abc');
    });

    it('should refuse a non-Uint8Array input', () => {
        expect(codeOf(() => parseCertificationRequest('MIIB' as unknown as Uint8Array))).toBe('PKI_INVALID_INPUT');
    });
});

describe('parseCertificationRequest — structure', () => {
    const structure = (der: Uint8Array, path: string): void => {
        const error = errorOf(() => parseCertificationRequest(der, QUIET));
        expect(error.code).toBe('PKI_X509_STRUCTURE_INVALID');
        expect(error.message).toContain(`${path} at offset`);
    };

    it('should refuse an envelope that is not a SEQUENCE of three', () => {
        structure(integer([0x01]), 'certificationRequest');
        structure(sequence(info(), algorithm(ECDSA_SHA256)), 'certificationRequest');
        structure(sequence(info(), algorithm(ECDSA_SHA256), SIGNATURE, SIGNATURE), 'certificationRequest');
    });

    it('should refuse a certificationRequestInfo that is not a SEQUENCE of four', () => {
        structure(csr({ info: octetString([1]) }), 'certificationRequestInfo');
        structure(csr({ attributes: null }), 'certificationRequestInfo');
        structure(csr({ info: sequence(integer([0]), SUBJECT, ecKey(), context(0, true, []), context(1, true, [])) }), 'certificationRequestInfo');
    });

    it('should refuse a version that is not an INTEGER, and one other than 0 with its own code', () => {
        structure(csr({ version: octetString([0]) }), 'certificationRequestInfo.version');
        const error = errorOf(() => parseCertificationRequest(csr({ version: integer([0x01]) }), QUIET));
        expect(error.code).toBe('PKI_X509_VERSION_INVALID');
        expect(error.message).toContain('is 1; RFC 2986 defines v1 (0)');
        expect(codeOf(() => parseCertificationRequest(csr({ version: integer([0x02]) }), QUIET))).toBe('PKI_X509_VERSION_INVALID');
    });

    it('should refuse a subject and a key the certificate readers refuse, with their codes', () => {
        expect(codeOf(() => parseCertificationRequest(csr({ subject: octetString([1]) }), QUIET))).toBe('PKI_X509_NAME_INVALID');
        expect(codeOf(() => parseCertificationRequest(csr({ subject: sequence(set()) }), QUIET))).toBe('PKI_X509_NAME_INVALID');
        expect(codeOf(() => parseCertificationRequest(csr({ spki: sequence(algorithm('1.2.840.10045.2.1', oid('1.2.840.10045.3.1.7'))) }), QUIET))).toBe('PKI_X509_SPKI_INVALID');
    });

    it('should refuse an attributes field that is not a constructed [0]', () => {
        structure(csr({ attributes: set() }), 'certificationRequestInfo.attributes');
        structure(csr({ attributes: context(1, true, []) }), 'certificationRequestInfo.attributes');
        structure(csr({ attributes: context(0, false, []) }), 'certificationRequestInfo.attributes');
    });

    it('should refuse an attribute that is not a type and a SET OF values', () => {
        structure(csr({ attributes: attributes(integer([1])) }), 'certificationRequestInfo.attributes[0]');
        structure(csr({ attributes: attributes(sequence(oid('1.2.3'))) }), 'certificationRequestInfo.attributes[0]');
        structure(csr({ attributes: attributes(sequence(integer([1]), set())) }), 'certificationRequestInfo.attributes[0].type');
        structure(csr({ attributes: attributes(sequence(oid('1.2.3'), sequence())) }), 'certificationRequestInfo.attributes[0].values');
    });

    it('should refuse a repeated attribute type as a duplicate, naming the second instance', () => {
        const error = errorOf(() => parseCertificationRequest(csr({
            attributes: attributes(attribute('1.2.3', integer([1])), attribute('1.2.4', integer([2])), attribute('1.2.3', integer([3]))),
        }), QUIET));
        expect(error.code).toBe('PKI_X509_EXTENSION_DUPLICATE');
        expect(error.message).toContain('attributes[2]');
    });

    it('should refuse an extensionRequest that is not one SEQUENCE of at least one extension', () => {
        structure(csr({ attributes: attributes(attribute(EXTENSION_REQUEST)) }), 'certificationRequestInfo.attributes[0].values');
        structure(csr({ attributes: attributes(attribute(EXTENSION_REQUEST, sequence(SAN), sequence(KEY_USAGE))) }), 'certificationRequestInfo.attributes[0].values');
        structure(csr({ attributes: attributes(attribute(EXTENSION_REQUEST, octetString([1]))) }), 'certificationRequestInfo.attributes[0].values[0]');
        expect(codeOf(() => parseCertificationRequest(csr({ attributes: attributes(attribute(EXTENSION_REQUEST, sequence())) }), QUIET))).toBe('PKI_X509_EXTENSIONS_EMPTY');
    });

    it('should hold the requested extensions to the certificate rules: duplicates and malformed values', () => {
        expect(codeOf(() => parseCertificationRequest(csr({ attributes: attributes(attribute(EXTENSION_REQUEST, sequence(SAN, SAN))) }), QUIET))).toBe('PKI_X509_EXTENSION_DUPLICATE');
        const malformed = csr({ attributes: attributes(attribute(EXTENSION_REQUEST, sequence(extension('2.5.29.19', integer([1]))))) });
        expect(codeOf(() => parseCertificationRequest(malformed, QUIET))).toBe('PKI_X509_EXTENSION_MALFORMED');
        expect(parseCertificationRequest(malformed, { ...QUIET, decodeExtensions: false }).extensions?.map((e) => e.kind)).toEqual(['raw']);
    });

    it('should report an explicitly FALSE criticality inside a request as the certificate reader does', () => {
        const der = csr({ attributes: attributes(attribute(EXTENSION_REQUEST, sequence(extension('2.5.29.17', encodeSubjectAltName([{ kind: 'dNSName', value: 'a.example' }]), false)))) });
        expect(diagnosticsOf(der)).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
    });

    it('should refuse a challengePassword that is not one DirectoryString', () => {
        structure(csr({ attributes: attributes(attribute(CHALLENGE_PASSWORD, utf8('a'), utf8('b'))) }), 'certificationRequestInfo.attributes[0].values');
        structure(csr({ attributes: attributes(attribute(CHALLENGE_PASSWORD, integer([1]))) }), 'certificationRequestInfo.attributes[0].values[0]');
        structure(csr({ attributes: attributes(attribute(CHALLENGE_PASSWORD, boolean(true))) }), 'certificationRequestInfo.attributes[0].values[0]');
    });

    it('should refuse a signature algorithm and a signature of the wrong type', () => {
        structure(csr({ signatureAlgorithm: octetString([1]) }), 'signatureAlgorithm');
        structure(csr({ signature: octetString([0, 1]) }), 'signature');
    });

    it('should refuse trailing data and a BER length under the default rules, with ASN.1 codes', () => {
        const der = csr();
        expect(codeOf(() => parseCertificationRequest(new Uint8Array([...der, 0x00]), QUIET))).toMatch(/^PKI_ASN1_/);
        expect(codeOf(() => parseCertificationRequest(der.subarray(0, der.length - 1), QUIET))).toMatch(/^PKI_ASN1_/);
    });
});

describe('parseCertificationRequest — bounds', () => {
    const limit = (der: Uint8Array, limits: Record<string, number>): PkiError => errorOf(() => parseCertificationRequest(der, { ...QUIET, limits }));

    it('should bound the attribute count by maxExtensions', () => {
        const der = csr({ attributes: attributes(attribute('1.2.3', integer([1])), attribute('1.2.4', integer([2])), attribute('1.2.5', integer([3]))) });
        const error = limit(der, { maxExtensions: 2 });
        expect(error.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(error.message).toContain('the attributes of the certification request (3) exceeds limits.maxExtensions (2)');
        expect(parseCertificationRequest(der, { ...QUIET, limits: { maxExtensions: 3 } }).attributes).toHaveLength(3);
    });

    it('should bound the value count of one attribute by maxExtensions', () => {
        const der = csr({ attributes: attributes(attribute('1.2.3', integer([1]), integer([2]), integer([3]))) });
        const error = limit(der, { maxExtensions: 2 });
        expect(error.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(error.message).toContain('the values of the attribute 1.2.3 (3) exceeds limits.maxExtensions (2)');
    });

    it('should bound the requested extensions by maxExtensions, as a certificate\'s are', () => {
        const third = extension('2.5.29.19', sequence(boolean(true)));
        const der = csr({ attributes: attributes(attribute(EXTENSION_REQUEST, sequence(SAN, KEY_USAGE, third))) });
        const error = limit(der, { maxExtensions: 2 });
        expect(error.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(error.message).toContain('the extensions requested by the certification request (3) exceeds limits.maxExtensions (2)');
    });

    it('should bound the subject by maxNameAttributes', () => {
        const der = csr({ subject: name([[CN, utf8('a')]], [['2.5.4.10', utf8('b')]]) });
        expect(limit(der, { maxNameAttributes: 1 }).code).toBe('PKI_LIMIT_EXCEEDED');
    });
});
