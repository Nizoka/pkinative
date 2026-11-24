import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createOcspRequest, encodeOcspCertId, parseOcspRequest } from '../../src/revocation/ocsp-request.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import type { OcspRequest } from '../../src/types/ocsp-types.js';
import { PkiCertificateError, PkiEncodingError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 6960 §4.1 OCSPRequest — the question, read back.
 *
 * The reader is checked two ways. On requests `createOcspRequest` wrote, the
 * fields are compared with hashes `node:crypto` computes here, never with the
 * writer's own: the two would otherwise agree on any mistake they share. On
 * everything the writer does not write — a requestor, a signature, several
 * certificates, extensions of every kind, and every malformed shape — the
 * request is assembled from raw DER, field by field.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const ROOT = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/isrg-root-x1.der')), quiet);
const R12 = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/lets-encrypt-r12.der')), quiet);
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const digest = (algorithm: 'sha1' | 'sha256', data: Uint8Array): string => createHash(algorithm).update(data).digest('hex');

// ── Raw DER, from the module of RFC 6960 §4.1.1 ──────────────────────

const oid = (content: readonly number[]): Uint8Array => universal(6, content);
const NULL = universal(5, []);
const TRUE = universal(1, [0xff]);
const SHA1 = oid([0x2b, 0x0e, 0x03, 0x02, 0x1a]);
const NONCE_OID = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
const PRIVATE_OID = [0x2a, 0x03, 0x04, 0x05];
const SKI_OID = [0x55, 0x1d, 0x0e];
const BASIC_CONSTRAINTS_OID = [0x55, 0x1d, 0x13];
/** `[n] EXPLICIT`: a constructed context tag around the values. */
const explicit = (n: number, ...content: ReadonlyArray<ArrayLike<number>>): Uint8Array => tlv(2, true, n, concat(...content));
/** `CertID`, with a serial that tells one from another. */
const certId = (serial: readonly number[] = [0x2a]): Uint8Array => sequence(
    sequence(SHA1, NULL),
    universal(4, new Array<number>(20).fill(0xaa)),
    universal(4, new Array<number>(20).fill(0xbb)),
    universal(2, serial),
);
/** One `Extension`: an OID, an optional critical flag, and the value in its OCTET STRING. */
const extension = (id: readonly number[], value: ArrayLike<number>, critical = false): Uint8Array =>
    sequence(oid(id), ...(critical ? [TRUE] : []), universal(4, value));
/** The nonce extension: an OCTET STRING inside the extnValue's own. */
const nonceExtension = (nonce: ArrayLike<number>): Uint8Array => extension(NONCE_OID, universal(4, nonce));
const LIST = sequence(sequence(certId()));
/** `OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature [0] EXPLICIT OPTIONAL }`. */
const ocspRequest = (tbsFields: ReadonlyArray<ArrayLike<number>>, ...after: ReadonlyArray<ArrayLike<number>>): Uint8Array => sequence(sequence(...tbsFields), ...after);
const ED25519 = sequence(oid([0x2b, 0x65, 0x70]));
const SIGNATURE_BITS = universal(3, [0x00, 0xde, 0xad, 0xbe, 0xef]);
const signatureOf = (...fields: ReadonlyArray<ArrayLike<number>>): Uint8Array => explicit(0, sequence(...fields));
/** `directoryName [4] EXPLICIT Name`, CN=Requestor. */
const DIRECTORY_NAME = explicit(4, sequence(universal(17, sequence(oid([0x55, 0x04, 0x03]), universal(12, ascii('Requestor'))), true)));
const DNS_NAME = tlv(2, false, 2, ascii('ocsp-client.example'));

function read(der: Uint8Array, options: { strict?: boolean; limits?: Record<string, number> } = {}): { request: OcspRequest; diagnostics: PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const request = parseOcspRequest(der, { ...options, onDiagnostic: (d) => { diagnostics.push(d); } });
    return { request, diagnostics };
}
const codes = (diagnostics: readonly PkiDiagnostic[]): string[] => diagnostics.map((d) => d.code);
const thrownBy = (fn: () => unknown): unknown => {
    try {
        fn();
    } catch (error) {
        return error;
    }
    return undefined;
};

describe('parseOcspRequest', () => {
    describe('on what createOcspRequest writes', () => {
        it('should read the CertID back as the hashes node:crypto computes, with no diagnostic', () => {
            const nonce = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
            const der = createOcspRequest(R12, ROOT, { nonce });
            const { request, diagnostics } = read(der);
            expect(diagnostics).toEqual([]);
            expect(request.diagnostics).toEqual([]);
            expect(request.version).toBe(1);
            expect(request.requestorName).toBeUndefined();
            expect(request.signature).toBeUndefined();
            expect(request.requests).toHaveLength(1);
            const { certId: id } = request.requests[0] as OcspRequest['requests'][number];
            expect(id.hashAlgorithm.oid).toBe('1.3.14.3.2.26');
            // RFC 6960 §4.1.1: the hash of the issuer's encoded Name, and of its key BITS.
            expect(hex(id.issuerNameHash)).toBe(digest('sha1', ROOT.subject.der));
            expect(hex(id.issuerKeyHash)).toBe(digest('sha1', ROOT.subjectPublicKeyInfo.publicKey.bytes));
            expect(id.serialNumber.hex).toBe(R12.serialNumber.hex);
            expect(id.serialNumber.value).toBe(R12.serialNumber.value);
            expect(hex(id.serialNumber.bytes)).toBe(hex(R12.serialNumber.bytes));
            expect(request.nonce).toEqual(nonce);
        });

        it('should keep each CertID exactly as encoded, so it compares with encodeOcspCertId byte for byte', () => {
            const der = createOcspRequest(R12, ROOT, { hashAlgorithm: 'SHA-256' });
            const { request } = read(der);
            const entry = request.requests[0] as OcspRequest['requests'][number];
            expect(entry.certIdDer).toEqual(encodeOcspCertId(R12, ROOT, 'SHA-256'));
            expect(entry.certIdDer.buffer).toBe(der.buffer);
            expect(entry.certId.hashAlgorithm.oid).toBe('2.16.840.1.101.3.4.2.1');
            expect(hex(entry.certId.issuerNameHash)).toBe(digest('sha256', ROOT.subject.der));
            expect(hex(entry.certId.issuerKeyHash)).toBe(digest('sha256', ROOT.subjectPublicKeyInfo.publicKey.bytes));
            expect(entry.extensions).toEqual([]);
            expect(request.nonce).toBeUndefined();
            expect(request.extensions).toEqual([]);
        });

        it('should return the request and its tbsRequest as views of the input, frozen', () => {
            const der = createOcspRequest(R12, ROOT, { nonce: Uint8Array.of(7) });
            const { request } = read(der);
            expect(request.der).toEqual(der);
            expect(request.der.buffer).toBe(der.buffer);
            // OCSPRequest ::= SEQUENCE { tbsRequest }: the content of the outer SEQUENCE is the tbsRequest, whole.
            const header = der[1] === 0x81 ? 3 : der[1] === 0x82 ? 4 : 2;
            expect(request.tbsDer).toEqual(der.subarray(header));
            expect(request.tbsDer.buffer).toBe(der.buffer);
            expect(Object.isFrozen(request)).toBe(true);
            expect(Object.isFrozen(request.requests)).toBe(true);
            expect(Object.isFrozen(request.requests[0])).toBe(true);
        });

        it('should keep the nonce extension itself, raw, beside the nonce it read out of it', () => {
            const { request } = read(createOcspRequest(R12, ROOT, { nonce: Uint8Array.of(1, 2, 3) }));
            expect(request.extensions).toEqual([{ kind: 'unknown', oid: '1.3.6.1.5.5.7.48.1.2', critical: false, valueDer: Uint8Array.of(0x04, 0x03, 1, 2, 3) }]);
            expect(request.nonce).toEqual(Uint8Array.of(1, 2, 3));
        });
    });

    describe('the fields createOcspRequest does not write', () => {
        it('should read several Requests in encoded order, each with its own extensions', () => {
            const single = explicit(0, sequence(extension(PRIVATE_OID, NULL)));
            const der = ocspRequest([sequence(sequence(certId([0x01])), sequence(certId([0x02]), single), sequence(certId([0x03])))]);
            const { request, diagnostics } = read(der);
            expect(diagnostics).toEqual([]);
            expect(request.requests.map((r) => r.certId.serialNumber.hex)).toEqual(['01', '02', '03']);
            expect(request.requests.map((r) => r.extensions.length)).toEqual([0, 1, 0]);
            expect(request.requests[1]?.extensions[0]).toEqual({ kind: 'unknown', oid: '1.2.3.4.5', critical: false, valueDer: NULL });
            expect(request.requests[1]?.certIdDer).toEqual(certId([0x02]));
            expect(Object.isFrozen(request.requests[1]?.extensions)).toBe(true);
        });

        it('should accept a requestList that asks about nothing: the grammar sets no minimum', () => {
            const { request, diagnostics } = read(ocspRequest([sequence()]));
            expect(request.requests).toEqual([]);
            expect(diagnostics).toEqual([]);
        });

        it.each([
            ['a directoryName', DIRECTORY_NAME, 'directoryName'],
            ['a dNSName', DNS_NAME, 'dNSName'],
        ])('should read requestorName [1] EXPLICIT when it is %s', (_, name, kind) => {
            const { request, diagnostics } = read(ocspRequest([explicit(1, name), LIST]));
            expect(request.requestorName?.kind).toBe(kind);
            expect(request.requests).toHaveLength(1);
            expect(diagnostics).toEqual([]);
        });

        it('should read the version, the requestor, the list and the extensions together, in the order the module fixes', () => {
            const der = ocspRequest([explicit(0, universal(2, [0x00])), explicit(1, DNS_NAME), LIST, explicit(2, sequence(nonceExtension([0x09])))]);
            const { request, diagnostics } = read(der);
            expect(request.requestorName).toMatchObject({ kind: 'dNSName', value: 'ocsp-client.example' });
            expect(request.nonce).toEqual(Uint8Array.of(0x09));
            expect(codes(diagnostics)).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
        });

        it('should refuse a requestorName that is not a GeneralName, as the certificate reader refuses one', () => {
            const thrown = thrownBy(() => parseOcspRequest(ocspRequest([explicit(1, universal(12, ascii('nobody'))), LIST]), quiet));
            expect(thrown).toBeInstanceOf(PkiCertificateError);
            expect(thrown).toMatchObject({ code: 'PKI_X509_GENERAL_NAME_INVALID', path: 'TBSRequest.requestorName' });
        });
    });

    describe('the version (RFC 6960 §4.1.1)', () => {
        it('should name an explicit v1 as a DEFAULT that DER omits, and refuse it under strict (X.690 §11.5)', () => {
            const der = ocspRequest([explicit(0, universal(2, [0x00])), LIST]);
            const { request, diagnostics } = read(der);
            expect(request.version).toBe(1);
            expect(diagnostics.map((d) => [d.code, d.severity, d.path, d.offset])).toEqual([['PKI_DIAG_DEFAULT_ENCODED', 'warning', 'TBSRequest.version', 4]]);
            expect(thrownBy(() => read(der, { strict: true }))).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        });

        it.each([
            ['the version 1 (a v2 that does not exist)', universal(2, [0x01])],
            ['a two-octet zero', universal(2, [0x00, 0x00])],
            ['a NULL where the INTEGER goes', NULL],
            ['nothing inside the [0]', new Uint8Array(0)],
        ])('should diagnose a version that is %s, and read the request as v1', (_, inner) => {
            const der = ocspRequest([explicit(0, inner), LIST]);
            const { request, diagnostics } = read(der);
            expect(request.version).toBe(1);
            expect(request.requests).toHaveLength(1);
            expect(diagnostics.map((d) => [d.code, d.severity, d.path, d.standard, d.offset]))
                .toEqual([['PKI_DIAG_OCSP_VERSION_NOT_V1', 'warning', 'TBSRequest.version', 'RFC 6960 §4.1.1, §4.2.2.3', 4]]);
            expect(thrownBy(() => read(der, { strict: true }))).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        });

        it('should leave the same diagnostic of a response on the path of its own version', () => {
            // One reader, two messages: the response's diagnostic must not start naming the request.
            const generalized = universal(24, ascii('20260501000000Z'));
            const single = sequence(certId(), tlv(2, false, 0, []), generalized);
            const tbs = sequence(explicit(0, universal(2, [0x01])), explicit(2, universal(4, new Array<number>(20).fill(0xcc))), generalized, sequence(single));
            const basic = sequence(tbs, ED25519, universal(3, [0x00, 0xde, 0xad]));
            const response = sequence(universal(10, [0]), explicit(0, sequence(oid([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]), universal(4, basic))));
            const seen: PkiDiagnostic[] = [];
            parseOcspResponse(response, { onDiagnostic: (d) => { seen.push(d); } });
            expect(seen.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_OCSP_VERSION_NOT_V1', 'ResponseData.version']]);
        });
    });

    describe('the nonce (RFC 9654 §2.1, which obsoletes RFC 8954)', () => {
        it.each([1, 32, 33, 128])('should accept a nonce of %i octet(s) with no diagnostic: the type is OCTET STRING (SIZE(1..128))', (length) => {
            const nonce = new Array<number>(length).fill(0x5c);
            const { request, diagnostics } = read(ocspRequest([LIST, explicit(2, sequence(nonceExtension(nonce)))]));
            expect(request.nonce).toEqual(Uint8Array.from(nonce));
            expect(diagnostics).toEqual([]);
        });

        it.each([0, 129])('should return a nonce of %i octets as it is, diagnose it, and refuse it under strict', (length) => {
            const nonce = new Array<number>(length).fill(0x5c);
            const der = ocspRequest([LIST, explicit(2, sequence(nonceExtension(nonce)))]);
            const { request, diagnostics } = read(der);
            expect(request.nonce).toEqual(Uint8Array.from(nonce));
            expect(diagnostics.map((d) => [d.code, d.severity, d.standard, d.path])).toEqual([['PKI_DIAG_OCSP_NONCE_LENGTH', 'warning', 'RFC 9654 §2.1', 'TBSRequest.requestExtensions[0]']]);
            expect(thrownBy(() => read(der, { strict: true }))).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        });

        it('should point the diagnostic at the nonce value inside the request, and find the nonce wherever it sits among the extensions', () => {
            const der = ocspRequest([LIST, explicit(2, sequence(extension(PRIVATE_OID, NULL), nonceExtension([])))]);
            const { request, diagnostics } = read(der);
            expect(request.nonce).toEqual(new Uint8Array(0));
            expect(diagnostics).toHaveLength(1);
            expect(diagnostics[0]?.path).toBe('TBSRequest.requestExtensions[1]');
            // The value is the inner OCTET STRING, `04 00`, the last two octets of the request.
            expect(diagnostics[0]?.offset).toBe(der.length - 2);
        });

        it.each([
            ['an INTEGER where the inner OCTET STRING goes', universal(2, [0x05])],
            ['a context tag with the number of an OCTET STRING', tlv(2, false, 4, [0x05])],
            ['an OCTET STRING followed by another value', concat(universal(4, [0x05]), NULL)],
            ['an OCTET STRING cut short', [0x04, 0x05, 0x01]],
            ['nothing at all', []],
        ])('should refuse a nonce extension whose value is %s, as PKI_X509_EXTENSION_MALFORMED', (_, value) => {
            const der = ocspRequest([LIST, explicit(2, sequence(extension(NONCE_OID, value)))]);
            const thrown = thrownBy(() => parseOcspRequest(der, quiet));
            expect(thrown).toBeInstanceOf(PkiCertificateError);
            expect(thrown).toMatchObject({ code: 'PKI_X509_EXTENSION_MALFORMED', path: 'TBSRequest.requestExtensions[0]', offset: der.length - value.length });
        });

        it('should not look for a nonce among the extensions of a single Request', () => {
            const der = ocspRequest([sequence(sequence(certId(), explicit(0, sequence(nonceExtension([0x01])))))]);
            const { request, diagnostics } = read(der);
            expect(request.nonce).toBeUndefined();
            expect(request.requests[0]?.extensions).toHaveLength(1);
            expect(diagnostics).toEqual([]);
        });
    });

    describe('the extensions (RFC 6960 §4.1.2)', () => {
        it('should keep an extension it does not recognise and say nothing: unrecognised extensions are ignored, not refused', () => {
            const der = ocspRequest([LIST, explicit(2, sequence(extension(PRIVATE_OID, NULL)))]);
            const { request, diagnostics } = read(der);
            expect(request.extensions).toEqual([{ kind: 'unknown', oid: '1.2.3.4.5', critical: false, valueDer: NULL }]);
            expect(diagnostics).toEqual([]);
            expect(() => read(der, { strict: true })).not.toThrow();
        });

        it('should name an unrecognised extension that is critical — the one a responder may refuse — and refuse it under strict', () => {
            const der = ocspRequest([LIST, explicit(2, sequence(extension(PRIVATE_OID, NULL, true)))]);
            const { request, diagnostics } = read(der);
            expect(request.extensions[0]).toMatchObject({ kind: 'unknown', critical: true });
            expect(diagnostics.map((d) => [d.code, d.severity, d.path])).toEqual([
                ['PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION', 'warning', 'TBSRequest.requestExtensions[0]'],
                ['PKI_DIAG_OCSP_REQUEST_EXTENSION_CRITICAL', 'info', 'TBSRequest.requestExtensions[0]'],
            ]);
            expect(thrownBy(() => read(der, { strict: true }))).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        });

        it('should report a critical flag on an extension it does recognise as an info, which strict does not refuse: "SHOULD NOT be set"', () => {
            // basicConstraints is decoded by the certificate reader, and critical is what it
            // is in a certificate; in a request the flag breaks only the SHOULD NOT of §4.1.2.
            const constraints = extension(BASIC_CONSTRAINTS_OID, sequence(), true);
            const der = ocspRequest([sequence(sequence(certId(), explicit(0, sequence(extension(PRIVATE_OID, NULL), constraints))))]);
            const { request, diagnostics } = read(der, { strict: true });
            expect(request.requests[0]?.extensions[1]).toMatchObject({ kind: 'basicConstraints', critical: true });
            expect(diagnostics.map((d) => [d.code, d.severity, d.standard, d.path])).toEqual([
                ['PKI_DIAG_OCSP_REQUEST_EXTENSION_CRITICAL', 'info', 'RFC 6960 §4.1.2', 'TBSRequest.requestList[0].singleRequestExtensions[1]'],
            ]);
        });

        it('should refuse a recognised extension whose value is not its ASN.1 definition', () => {
            const der = ocspRequest([LIST, explicit(2, sequence(extension(SKI_OID, NULL)))]);
            const thrown = thrownBy(() => parseOcspRequest(der, quiet));
            expect(thrown).toBeInstanceOf(PkiCertificateError);
            expect(thrown).toMatchObject({ code: 'PKI_X509_EXTENSION_MALFORMED' });
        });
    });

    describe('a signed request (RFC 6960 §4.1.2)', () => {
        const certificate = sequence(universal(2, [0x01]));

        it('should expose the algorithm, the signature and the certificates, and verify nothing', () => {
            const der = ocspRequest([explicit(1, DIRECTORY_NAME), LIST], signatureOf(ED25519, SIGNATURE_BITS, explicit(0, sequence(certificate, certificate))));
            const { request, diagnostics } = read(der);
            expect(diagnostics).toEqual([]);
            expect(request.signature?.signatureAlgorithm.oid).toBe('1.3.101.112');
            expect(request.signature?.signatureValue).toEqual({ bytes: Uint8Array.of(0xde, 0xad, 0xbe, 0xef), unusedBits: 0 });
            expect(request.signature?.certificates).toEqual([certificate, certificate]);
            expect(request.signature?.certificates[0]?.buffer).toBe(der.buffer);
            expect(Object.isFrozen(request.signature)).toBe(true);
            expect(Object.isFrozen(request.signature?.certificates)).toBe(true);
            // The signature covers the tbsRequest, which is what tbsDer is.
            expect(request.tbsDer).toEqual(sequence(explicit(1, DIRECTORY_NAME), LIST));
        });

        it('should read a signature that attaches no certificate, with or without the certs field', () => {
            for (const certs of [[], [explicit(0, sequence())]]) {
                const { request, diagnostics } = read(ocspRequest([explicit(1, DNS_NAME), LIST], signatureOf(ED25519, SIGNATURE_BITS, ...certs)));
                expect(request.signature?.certificates).toEqual([]);
                expect(diagnostics).toEqual([]);
            }
        });

        it('should diagnose a signed request that names no requestor, and refuse it under strict: "the requestor SHALL specify its name"', () => {
            const der = ocspRequest([LIST], signatureOf(ED25519, SIGNATURE_BITS));
            const { request, diagnostics } = read(der);
            expect(request.signature).toBeDefined();
            expect(request.requestorName).toBeUndefined();
            expect(diagnostics.map((d) => [d.code, d.severity, d.standard, d.path, d.offset]))
                .toEqual([['PKI_DIAG_OCSP_REQUEST_SIGNED_UNNAMED', 'warning', 'RFC 6960 §4.1.2', 'TBSRequest.requestorName', 2 + sequence(LIST).length]]);
            expect(thrownBy(() => read(der, { strict: true }))).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        });

        it('should say nothing of an unsigned request that names no requestor: the name is required of a signer only', () => {
            expect(read(ocspRequest([LIST])).diagnostics).toEqual([]);
        });

        it.each([
            ['a second field that is not [0]', explicit(1, sequence(ED25519, SIGNATURE_BITS)), 'OCSPRequest.optionalSignature'],
            ['a [0] holding nothing', explicit(0), 'OCSPRequest.optionalSignature'],
            ['a [0] holding something other than a SEQUENCE', explicit(0, universal(2, [0x01])), 'OCSPRequest.optionalSignature'],
            ['a Signature with no field', signatureOf(), 'Signature'],
            ['a Signature with an algorithm and no signature', signatureOf(ED25519), 'Signature'],
            ['a signature that is an OCTET STRING', signatureOf(ED25519, universal(4, [0xde, 0xad])), 'Signature.signature'],
            ['a signature under a context tag', signatureOf(ED25519, tlv(2, false, 3, [0x00, 0xde, 0xad])), 'Signature.signature'],
            ['certs under a tag that is not [0]', signatureOf(ED25519, SIGNATURE_BITS, explicit(1, sequence(certificate))), 'Signature.certs'],
            ['certs [0] holding nothing', signatureOf(ED25519, SIGNATURE_BITS, explicit(0)), 'Signature.certs'],
            ['certs [0] holding a SET', signatureOf(ED25519, SIGNATURE_BITS, explicit(0, universal(17, certificate, true))), 'Signature.certs'],
            ['a fourth field in the Signature', signatureOf(ED25519, SIGNATURE_BITS, explicit(0, sequence(certificate)), NULL), 'Signature'],
            ['an algorithm that is not an AlgorithmIdentifier', signatureOf(universal(4, [0x01]), SIGNATURE_BITS), 'Signature.signatureAlgorithm'],
        ])('should refuse %s', (_, signature, path) => {
            const thrown = thrownBy(() => parseOcspRequest(ocspRequest([explicit(1, DNS_NAME), LIST], signature), quiet));
            expect(thrown).toBeInstanceOf(PkiCertificateError);
            expect(thrown).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID', path });
        });

        it('should refuse a BIT STRING that declares more than seven unused bits, as an encoding error', () => {
            const thrown = thrownBy(() => parseOcspRequest(ocspRequest([explicit(1, DNS_NAME), LIST], signatureOf(ED25519, universal(3, [0x08, 0xde]))), quiet));
            expect(thrown).toBeInstanceOf(PkiEncodingError);
            expect(thrown).toMatchObject({ code: 'PKI_ASN1_BIT_STRING_INVALID' });
        });
    });

    describe('the structure', () => {
        it.each([
            ['a SET at the root', universal(17, sequence(LIST), true), 'OCSPRequest'],
            ['an empty OCSPRequest', sequence(), 'OCSPRequest.tbsRequest'],
            ['a tbsRequest that is a SET', sequence(universal(17, LIST, true)), 'OCSPRequest.tbsRequest'],
            ['a third field in the OCSPRequest', sequence(sequence(LIST), signatureOf(ED25519, SIGNATURE_BITS), NULL), 'OCSPRequest'],
            ['a tbsRequest with no requestList', ocspRequest([]), 'TBSRequest.requestList'],
            ['a requestList that is a SET', ocspRequest([universal(17, sequence(certId()), true)]), 'TBSRequest.requestList'],
            ['the requestExtensions before the requestList', ocspRequest([explicit(2, sequence(nonceExtension([0x01]))), LIST]), 'TBSRequest.requestList'],
            ['the requestorName after the requestList', ocspRequest([LIST, explicit(1, DNS_NAME)]), 'TBSRequest'],
            ['an extensions field under [3]', ocspRequest([LIST, explicit(3, sequence(nonceExtension([0x01])))]), 'TBSRequest'],
            ['a field after the requestExtensions', ocspRequest([LIST, explicit(2, sequence(nonceExtension([0x01]))), NULL]), 'TBSRequest'],
            ['five fields in the tbsRequest', ocspRequest([explicit(0, universal(2, [0x01])), explicit(1, DNS_NAME), LIST, explicit(2, sequence(nonceExtension([0x01]))), NULL]), 'TBSRequest'],
            ['an empty requestorName', ocspRequest([explicit(1), LIST]), 'TBSRequest.requestorName'],
            ['a Request that is a SET', ocspRequest([sequence(universal(17, certId(), true))]), 'TBSRequest.requestList[0]'],
            ['a Request that holds nothing', ocspRequest([sequence(sequence())]), 'TBSRequest.requestList[0].reqCert'],
            ['a reqCert that is a SET', ocspRequest([sequence(sequence(universal(17, certId().subarray(2), true)))]), 'TBSRequest.requestList[0].reqCert'],
            ['a CertID of three values', ocspRequest([sequence(sequence(sequence(sequence(SHA1, NULL), universal(4, [0xaa]), universal(4, [0xbb]))))]), 'TBSRequest.requestList[0].reqCert'],
            ['singleRequestExtensions under [1]', ocspRequest([sequence(sequence(certId(), explicit(1, sequence(extension(PRIVATE_OID, NULL)))))]), 'TBSRequest.requestList[0].singleRequestExtensions'],
            ['a third field in a Request', ocspRequest([sequence(sequence(certId(), explicit(0, sequence(extension(PRIVATE_OID, NULL))), NULL))]), 'TBSRequest.requestList[0]'],
            ['an extension that is not an Extension', ocspRequest([LIST, explicit(2, sequence(sequence(oid(PRIVATE_OID))))]), 'TBSRequest.requestExtensions[0]'],
        ])('should refuse %s', (_, der, path) => {
            const thrown = thrownBy(() => parseOcspRequest(der, quiet));
            expect(thrown).toBeInstanceOf(PkiCertificateError);
            expect(thrown).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID', path });
        });

        it('should name the message it refuses: a caller of this reader is never told about an OCSPResponse', () => {
            const thrown = thrownBy(() => parseOcspRequest(sequence(), quiet)) as PkiError;
            expect(thrown.message).toContain('OCSPRequest');
            expect(thrown.message).not.toContain('OCSPResponse');
        });

        it('should refuse octets after the request, at the offset where they begin (CWE-436)', () => {
            const der = createOcspRequest(R12, ROOT);
            const thrown = thrownBy(() => parseOcspRequest(concat(der, [0x00]), quiet));
            expect(thrown).toBeInstanceOf(PkiEncodingError);
            expect(thrown).toMatchObject({ code: 'PKI_ASN1_TRAILING_DATA', offset: der.length });
        });

        it('should refuse a request cut short at every octet, with a PkiError and never anything else', () => {
            const der = ocspRequest([explicit(1, DNS_NAME), LIST, explicit(2, sequence(nonceExtension([0x01, 0x02])))], signatureOf(ED25519, SIGNATURE_BITS, explicit(0, sequence(certificateOf()))));
            expect(() => parseOcspRequest(der, quiet)).not.toThrow();
            for (let cut = 0; cut < der.length; cut++) {
                expect(thrownBy(() => parseOcspRequest(der.subarray(0, cut), quiet)), `cut at ${String(cut)}`).toBeInstanceOf(PkiError);
            }
        });

        it('should refuse an argument that is not bytes as PKI_INVALID_INPUT, never as a TypeError', () => {
            for (const value of ['30 03 30 01 00', undefined, null, [0x30, 0x00]]) {
                expect(() => parseOcspRequest(value as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
                expect(() => parseOcspRequest(value as unknown as Uint8Array)).toThrow(PkiError);
            }
        });
    });

    describe('the limits', () => {
        const limited = (der: Uint8Array, limits: Record<string, number>): unknown => thrownBy(() => parseOcspRequest(der, { ...quiet, limits }));

        it('should refuse an input past maxInputBytes before reading a byte', () => {
            const der = createOcspRequest(R12, ROOT);
            expect(limited(der, { maxInputBytes: der.length })).toBeUndefined();
            const thrown = limited(der, { maxInputBytes: der.length - 1 });
            expect(thrown).toBeInstanceOf(PkiLimitError);
            expect(thrown).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxInputBytes' });
        });

        it('should stop the requestList at maxOcspSingleResponses, the bound of the list a response answers with', () => {
            const der = ocspRequest([sequence(sequence(certId([0x01])), sequence(certId([0x02])), sequence(certId([0x03])))]);
            expect(limited(der, { maxOcspSingleResponses: 3 })).toBeUndefined();
            const thrown = limited(der, { maxOcspSingleResponses: 2 });
            expect(thrown).toBeInstanceOf(PkiLimitError);
            expect(thrown).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxOcspSingleResponses', configured: 2, observed: 3 });
        });

        it('should stop the extensions of the request, and of one Request, at maxExtensions', () => {
            const two = sequence(extension(PRIVATE_OID, NULL), extension([0x2a, 0x03, 0x04, 0x06], NULL));
            for (const der of [ocspRequest([LIST, explicit(2, two)]), ocspRequest([sequence(sequence(certId(), explicit(0, two)))])]) {
                expect(limited(der, { maxExtensions: 2 })).toBeUndefined();
                const thrown = limited(der, { maxExtensions: 1 });
                expect(thrown).toBeInstanceOf(PkiLimitError);
                expect(thrown).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxExtensions' });
            }
        });

        it('should stop the certificates of a signed request at maxChainLength', () => {
            const der = ocspRequest([explicit(1, DNS_NAME), LIST], signatureOf(ED25519, SIGNATURE_BITS, explicit(0, sequence(certificateOf(), certificateOf(), certificateOf()))));
            expect(limited(der, { maxChainLength: 3 })).toBeUndefined();
            const thrown = limited(der, { maxChainLength: 2 });
            expect(thrown).toBeInstanceOf(PkiLimitError);
            expect(thrown).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxChainLength', configured: 2, observed: 3 });
        });

        it('should refuse a tbsRequest of a hundred thousand values at the field bound, not by walking them all', () => {
            const content = new Uint8Array(200_000);
            for (let i = 0; i < content.length; i += 2) content[i] = 0x05;
            const thrown = thrownBy(() => parseOcspRequest(sequence(universal(16, content, true)), quiet));
            expect(thrown).toBeInstanceOf(PkiCertificateError);
            expect(thrown).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID', path: 'TBSRequest' });
        });
    });
});

/** Bytes standing where a certificate goes: the reader keeps them, it does not parse them. */
function certificateOf(): Uint8Array {
    return sequence(universal(2, [0x01]), universal(4, [0xca, 0xfe]));
}
