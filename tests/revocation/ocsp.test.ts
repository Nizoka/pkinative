import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints } from '../../src/build/build-structures.js';
import { verifyOcspSignature } from '../../src/crypto/x509-verify.js';
import { sha1 } from '../../src/hash/sha1.js';
import { sha256 } from '../../src/hash/sha256.js';
import { createOcspRequest, encodeOcspCertId } from '../../src/revocation/ocsp-request.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 6960 OCSP, both directions.
 *
 * The two things this file exists to nail down are the two places OCSP clients
 * get it wrong. On the way out: `issuerKeyHash` is over the public key **bits**,
 * not over the SubjectPublicKeyInfo — hashing the SPKI produces a request a
 * responder answers `unknown` to, which a careless client then reports as "not
 * revoked". On the way back: `good`, `revoked` and `unknown` are three states,
 * and `unknown` is the responder saying it does not know.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const AT = Date.UTC(2026, 5, 1);
const DAY = 86_400_000;

const ROOT = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/isrg-root-x1.der')), quiet);
const R12 = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/lets-encrypt-r12.der')), quiet);

const hex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

// ── The request ──────────────────────────────────────────────────────

describe('encodeOcspCertId', () => {
    it('should hash the issuer’s encoded Name, not a rendering of it', () => {
        const certId = decodeAsn1(encodeOcspCertId(R12, ROOT), quiet);
        const nameHash = certId.children[1]?.content;
        expect(hex(nameHash ?? new Uint8Array(0))).toBe(hex(sha1(ROOT.subject.der)));
    });

    it('should hash the public key BITS, never the SubjectPublicKeyInfo', () => {
        // The single most common OCSP client bug. Hashing the SPKI produces a
        // request the responder answers `unknown` to.
        const certId = decodeAsn1(encodeOcspCertId(R12, ROOT), quiet);
        const keyHash = certId.children[2]?.content;
        expect(hex(keyHash ?? new Uint8Array(0))).toBe(hex(sha1(ROOT.subjectPublicKeyInfo.publicKey.bytes)));
        expect(hex(keyHash ?? new Uint8Array(0))).not.toBe(hex(sha1(ROOT.subjectPublicKeyInfo.der)));
    });

    it('should carry the subject certificate’s serial, not the issuer’s', () => {
        const certId = decodeAsn1(encodeOcspCertId(R12, ROOT), quiet);
        expect(hex(certId.children[3]?.content ?? new Uint8Array(0))).toBe(R12.serialNumber.hex);
    });

    it('should name SHA-1 with an explicit NULL parameter', () => {
        // RFC 5754 says SHOULD omit; real responders answer `unknown` to the
        // absent form often enough that NULL is the interoperable choice.
        const certId = decodeAsn1(encodeOcspCertId(R12, ROOT), quiet);
        const algorithm = certId.children[0];
        expect(algorithm?.children).toHaveLength(2);
        expect(algorithm?.children[1]?.tagNumber).toBe(5);
    });

    it('should use SHA-256 when asked', () => {
        const certId = decodeAsn1(encodeOcspCertId(R12, ROOT, 'SHA-256'), quiet);
        expect(hex(certId.children[1]?.content ?? new Uint8Array(0))).toBe(hex(sha256(ROOT.subject.der)));
        expect(certId.children[1]?.content).toHaveLength(32);
    });

    it.each([
        { what: 'certificate', call: (): unknown => encodeOcspCertId(new Uint8Array(4) as never, ROOT) },
        { what: 'issuer', call: (): unknown => encodeOcspCertId(R12, 'not a certificate' as never) },
    ])('should refuse raw bytes for $what', ({ call }) => {
        expect(call).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

describe('createOcspRequest', () => {
    it('should omit the version field, which takes its DEFAULT', () => {
        const request = decodeAsn1(createOcspRequest(R12, ROOT), quiet);
        const tbs = request.children[0];
        // tbsRequest holds only requestList when there is no nonce.
        expect(tbs?.children).toHaveLength(1);
        expect(tbs?.children[0]?.tagNumber).toBe(16);
    });

    it('should hold exactly one Request, carrying the CertID', () => {
        const request = decodeAsn1(createOcspRequest(R12, ROOT), quiet);
        const list = request.children[0]?.children[0];
        expect(list?.children).toHaveLength(1);
        expect(hex(list?.children[0]?.children[0]?.bytes ?? new Uint8Array(0))).toBe(hex(encodeOcspCertId(R12, ROOT)));
    });

    it('should wrap a nonce in two OCTET STRINGs, which is what a responder reads', () => {
        // The extension value is an OCTET STRING, and the nonce inside it is
        // another one. One layer is a nonce a responder silently ignores.
        const nonce = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
        const request = decodeAsn1(createOcspRequest(R12, ROOT, { nonce }), quiet);
        const tbs = request.children[0];
        expect(tbs?.children).toHaveLength(2);
        const extensions = tbs?.children[1]?.children[0];
        const extension = extensions?.children[0];
        expect(hex(extension?.children[0]?.content ?? new Uint8Array(0))).toBe('2b06010505073001 02'.replace(' ', ''));
        const outerValue = extension?.children[1]?.content ?? new Uint8Array(0);
        const innerNonce = decodeAsn1(outerValue, quiet);
        expect(innerNonce.tagNumber).toBe(4);
        expect(hex(innerNonce.content)).toBe(hex(nonce));
    });

    it('should refuse a nonce that is not bytes', () => {
        expect(() => createOcspRequest(R12, ROOT, { nonce: 'random' as never }))
            .toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

// ── The response ─────────────────────────────────────────────────────

const ALG_ED25519 = sequence(universal(6, [0x2b, 0x65, 0x70]));
const OID_BASIC = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
const gen = (text: string): Uint8Array => universal(24, ascii(text));
const CERT_ID = sequence(
    sequence(universal(6, [0x2b, 0x0e, 0x03, 0x02, 0x1a]), universal(5, [])),
    universal(4, [...new Array<number>(20).fill(0xaa)]),
    universal(4, [...new Array<number>(20).fill(0xbb)]),
    universal(2, [0x2a]),
);

interface SingleOptions {
    readonly status?: Uint8Array;
    readonly nextUpdate?: Uint8Array;
}

/** One `SingleResponse`, `good` unless told otherwise. */
const single = (options: SingleOptions = {}): Uint8Array => sequence(
    CERT_ID,
    options.status ?? tlv(2, false, 0, new Uint8Array(0)),
    gen('20260501000000Z'),
    ...(options.nextUpdate === undefined ? [] : [tlv(2, true, 0, options.nextUpdate)]),
);

interface ResponseOptions {
    readonly statusCode?: number;
    readonly withBody?: boolean;
    readonly responses?: readonly Uint8Array[];
    readonly responderId?: Uint8Array;
    readonly responseType?: Uint8Array;
    readonly tbsExtra?: readonly Uint8Array[];
}

function buildResponse(options: ResponseOptions = {}): Uint8Array {
    const responderId = options.responderId ?? tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)]));
    const tbs = sequence(
        responderId,
        gen('20260501000000Z'),
        sequence(...(options.responses ?? [single()])),
        ...(options.tbsExtra ?? []),
    );
    const basic = sequence(tbs, ALG_ED25519, universal(3, [0x00, 0xde, 0xad]));
    const body = options.withBody === false
        ? []
        : [tlv(2, true, 0, sequence(options.responseType ?? OID_BASIC, universal(4, [...basic])))];
    return sequence(universal(10, [options.statusCode ?? 0]), ...body);
}

describe('parseOcspResponse', () => {
    it('should read a successful response with one good answer', () => {
        const response = parseOcspResponse(buildResponse(), quiet);
        expect(response.status).toBe('successful');
        const basic = response.basicResponse;
        expect(basic?.responses).toHaveLength(1);
        expect(basic?.responses[0]?.status.kind).toBe('good');
        expect(basic?.responses[0]?.certId.serialNumber.hex).toBe('2a');
        expect(basic?.responderId.kind).toBe('byKey');
    });

    it.each([
        { code: 1, status: 'malformedRequest' },
        { code: 2, status: 'internalError' },
        { code: 3, status: 'tryLater' },
        { code: 5, status: 'sigRequired' },
        { code: 6, status: 'unauthorized' },
    ])('should read the declining status $status and carry no body', ({ code, status }) => {
        // Each of these is a reason to look elsewhere, not a statement about a
        // certificate — which is why none of them has a response body.
        const response = parseOcspResponse(buildResponse({ statusCode: code, withBody: false }), quiet);
        expect(response.status).toBe(status);
        expect(response.basicResponse).toBeUndefined();
    });

    it('should keep revoked, good and unknown as three states', () => {
        // [1] IMPLICIT RevokedInfo: the tag REPLACES the SEQUENCE's, so the
        // contents sit directly inside it. Wrapping them in a SEQUENCE is the
        // mistake this comment exists to stop being made twice.
        const revoked = tlv(2, true, 1, concat(gen('20260401000000Z'), tlv(2, true, 0, universal(10, [0x01]))));
        const unknown = tlv(2, false, 2, new Uint8Array(0));
        const response = parseOcspResponse(buildResponse({ responses: [single(), single({ status: revoked }), single({ status: unknown })] }), quiet);
        const kinds = response.basicResponse?.responses.map((r) => r.status.kind);
        expect(kinds).toEqual(['good', 'revoked', 'unknown']);
        const second = response.basicResponse?.responses[1]?.status;
        expect(second?.kind === 'revoked' ? second.reason : undefined).toBe('keyCompromise');
        expect(second?.kind === 'revoked' ? new Date(second.revocationTime.epochMilliseconds).toISOString() : '').toBe('2026-04-01T00:00:00.000Z');
    });

    it('should read a revoked answer with no reason given', () => {
        const revoked = tlv(2, true, 1, gen('20260401000000Z'));
        const response = parseOcspResponse(buildResponse({ responses: [single({ status: revoked })] }), quiet);
        const status = response.basicResponse?.responses[0]?.status;
        expect(status?.kind).toBe('revoked');
        expect(status?.kind === 'revoked' ? status.reason : 'set').toBeUndefined();
    });

    it('should read nextUpdate when the responder promises one', () => {
        const response = parseOcspResponse(buildResponse({ responses: [single({ nextUpdate: gen('20260601000000Z') })] }), quiet);
        expect(new Date(response.basicResponse?.responses[0]?.nextUpdate?.epochMilliseconds ?? 0).toISOString()).toBe('2026-06-01T00:00:00.000Z');
        const without = parseOcspResponse(buildResponse(), quiet);
        expect(without.basicResponse?.responses[0]?.nextUpdate).toBeUndefined();
    });

    it('should read a byName responder', () => {
        const nameDer = sequence(universal(17, sequence(universal(6, [0x55, 0x04, 0x03]), universal(12, ascii('Responder'))), true));
        const response = parseOcspResponse(buildResponse({ responderId: tlv(2, true, 1, nameDer) }), quiet);
        const id = response.basicResponse?.responderId;
        expect(id?.kind).toBe('byName');
        expect(hex(id?.kind === 'byName' ? id.nameDer : new Uint8Array(0))).toBe(hex(nameDer));
    });

    it('should expose the attached certificates without trusting them', () => {
        // A responder can put anything here. They are carried because a client
        // needs them to build a path; trusting them would let the responder
        // nominate its own authority.
        const tbs = sequence(
            tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
            gen('20260501000000Z'),
            sequence(single()),
        );
        const basic = sequence(tbs, ALG_ED25519, universal(3, [0x00, 0xde]), tlv(2, true, 0, sequence(R12.der, ROOT.der)));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
        const response = parseOcspResponse(der, quiet);
        expect(response.basicResponse?.certificates).toHaveLength(2);
        expect(hex(response.basicResponse?.certificates[0] ?? new Uint8Array(0))).toBe(hex(R12.der));
    });

    it('should skip an explicit version field', () => {
        const withVersion = sequence(
            tlv(2, true, 0, universal(2, [0x00])),
            tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
            gen('20260501000000Z'),
            sequence(single()),
        );
        const basic = sequence(withVersion, ALG_ED25519, universal(3, [0x00, 0xde]));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
        expect(parseOcspResponse(der, quiet).basicResponse?.responses).toHaveLength(1);
    });

    it('should refuse a BasicOCSPResponse that is not DER, under any encodingRules (RFC 6960 §4.2.1)', () => {
        // The byKey responder ID with its 20-octet length in the long form, 0x81 0x14,
        // where DER requires the one octet 0x14.
        const byKey = tlv(2, true, 2, concat([0x04, 0x81, 20], new Array<number>(20).fill(0xcc)));
        const basic = sequence(sequence(byKey, gen('20260501000000Z'), sequence(single())), ALG_ED25519, universal(3, [0x00, 0xde]));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
        expect(() => parseOcspResponse(der, quiet)).toThrow(expect.objectContaining({ code: 'PKI_ASN1_LENGTH_INVALID', message: expect.stringContaining('DER requires the short form') }));
        expect(() => parseOcspResponse(der, { ...quiet, encodingRules: 'ber' })).toThrow(expect.objectContaining({ code: 'PKI_ASN1_LENGTH_INVALID', message: expect.stringContaining('DER requires the short form') }));
    });

    it.each([
        { name: 'not a SEQUENCE', der: universal(2, [0x00]) },
        { name: 'a responseStatus that is not an ENUMERATED', der: sequence(universal(2, [0x00])) },
        { name: 'a responseStatus wider than one octet', der: sequence(universal(10, [0x00, 0x00])) },
        { name: 'the unassigned responseStatus 4', der: sequence(universal(10, [0x04])) },
        { name: 'responseBytes that are not [0] EXPLICIT', der: sequence(universal(10, [0x00]), universal(4, [0x00])) },
    ])('should refuse an OCSPResponse with $name', ({ der }) => {
        expect(() => parseOcspResponse(der, quiet)).toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse a successful response with no body, and a declining one with a body', () => {
        expect(() => parseOcspResponse(sequence(universal(10, [0x00])), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
        expect(() => parseOcspResponse(buildResponse({ statusCode: 3 }), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse a response type it cannot read, rather than report no answer', () => {
        // A type nobody here understands is an inability, and returning "no
        // answer" for it would look like `unknown` — a status.
        const other = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x09]);
        expect(() => parseOcspResponse(buildResponse({ responseType: other }), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse a certStatus that is not one of the three', () => {
        const bogus = tlv(2, false, 5, new Uint8Array(0));
        expect(() => parseOcspResponse(buildResponse({ responses: [single({ status: bogus })] }), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse a CertID that does not hold four values', () => {
        const short = sequence(CERT_ID.subarray(0, 0));
        const broken = sequence(short, tlv(2, false, 0, new Uint8Array(0)), gen('20260501000000Z'));
        expect(() => parseOcspResponse(buildResponse({ responses: [broken] }), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should stop at maxOcspSingleResponses', () => {
        const many = Array.from({ length: 20 }, () => single());
        expect(() => parseOcspResponse(buildResponse({ responses: many }), { ...quiet, limits: { maxOcspSingleResponses: 5 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxOcspSingleResponses' }));
    });
});

describe('parseOcspResponse — extensions and every structural refusal', () => {
    const NONCE_OID = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]);
    const nonceExtension = sequence(NONCE_OID, universal(4, [...universal(4, [1, 2, 3, 4])]));

    /** A BasicOCSPResponse assembled from exactly the fields given. */
    const basicOf = (...fields: readonly Uint8Array[]): Uint8Array =>
        sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...sequence(...fields)]))));

    const tbsOf = (...fields: readonly Uint8Array[]): Uint8Array => sequence(...fields);
    const BY_KEY = tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)]));
    const SIG = universal(3, [0x00, 0xde]);

    it('should read responseExtensions, which is where a nonce echo lives', () => {
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, sequence(nonceExtension)));
        const response = parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet);
        expect(response.basicResponse?.extensions).toHaveLength(1);
        expect(response.basicResponse?.extensions[0]?.oid).toBe('1.3.6.1.5.5.7.48.1.2');
    });

    it('should refuse an extnValue that is not an OCTET STRING (RFC 5280 §4.1)', () => {
        // The TSTInfo reader had read any tag as the extnValue; this reader and
        // the CRL parser shared the gap.
        const nonceOid = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]);
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, sequence(sequence(nonceOid, universal(2, [0x01])))));
        expect(() => parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID', path: expect.stringMatching(/Extensions\[0\]\.extnValue$/) }));
    });

    it('should refuse a critical flag that is not a BOOLEAN (RFC 5280 §4.1)', () => {
        const nonceOid = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]);
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, sequence(sequence(nonceOid, universal(2, [0x01]), universal(4, [0x04, 0x01, 0x07])))));
        expect(() => parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID', path: expect.stringMatching(/Extensions\[0\]\.critical$/) }));
    });

    it('should decode a recognised extension in place, as the CRL parser learned to', () => {
        // The nonce is unknown to the certificate extension reader, so it is
        // never decoded and never exercises the decoding path. A recognised one
        // is — here extKeyUsage — and the reader must be handed a view that ends
        // where the extnValue ends, starting at the value's content. Handed the
        // whole response and the Extension's own offset, it reads the SEQUENCE
        // header as the value and refuses a well-formed response: the defect
        // that once made the CRL parser refuse every list with such an extension.
        const eku = sequence(universal(6, [0x55, 0x1d, 0x25]), universal(4, [...sequence(universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]))]));
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, sequence(eku)));
        const response = parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet);
        expect(response.basicResponse?.extensions[0]).toMatchObject({ kind: 'extendedKeyUsage', oid: '2.5.29.37' });
    });

    it('should read singleExtensions on one answer', () => {
        const withExtensions = sequence(CERT_ID, tlv(2, false, 0, new Uint8Array(0)), gen('20260501000000Z'), tlv(2, true, 1, sequence(nonceExtension)));
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(withExtensions));
        const response = parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet);
        expect(response.basicResponse?.responses[0]?.extensions).toHaveLength(1);
    });

    it('should accept an empty extensions field', () => {
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, new Uint8Array(0)));
        expect(parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet).basicResponse?.extensions).toEqual([]);
    });

    it('should accept an empty certs field', () => {
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()));
        const der = basicOf(tbs, ALG_ED25519, SIG, tlv(2, true, 0, new Uint8Array(0)));
        expect(parseOcspResponse(der, quiet).basicResponse?.certificates).toEqual([]);
    });

    it('should read a revoked answer whose reason field is malformed, without inventing one', () => {
        // A reason nobody can read must not become a reason invented, and must
        // not hide the revocation either.
        const wide = tlv(2, true, 1, concat(gen('20260401000000Z'), tlv(2, true, 0, universal(10, [0x00, 0x01]))));
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single({ status: wide })));
        const status = parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet).basicResponse?.responses[0]?.status;
        expect(status?.kind).toBe('revoked');
        expect(status?.kind === 'revoked' ? status.reason : 'set').toBeUndefined();
    });

    it('should accept an empty nextUpdate wrapper without a date', () => {
        const noDate = sequence(CERT_ID, tlv(2, false, 0, new Uint8Array(0)), gen('20260501000000Z'), tlv(2, true, 0, new Uint8Array(0)));
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(noDate));
        expect(parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet).basicResponse?.responses[0]?.nextUpdate).toBeUndefined();
    });

    it.each([
        { name: 'responseBytes that are empty', der: sequence(universal(10, [0x00]), tlv(2, true, 0, new Uint8Array(0))) },
        { name: 'a ResponseBytes with one field', der: sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC))) },
        { name: 'a BasicOCSPResponse with two fields', der: basicOf(tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single())), ALG_ED25519) },
        { name: 'a signature that is not a BIT STRING', der: basicOf(tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single())), ALG_ED25519, universal(4, [0x00])) },
        { name: 'a responderID that is neither [1] nor [2]', der: basicOf(tbsOf(tlv(2, true, 3, universal(4, [0x01])), gen('20260501000000Z'), sequence(single())), ALG_ED25519, SIG) },
        { name: 'an empty responderID', der: basicOf(tbsOf(tlv(2, true, 2, new Uint8Array(0)), gen('20260501000000Z'), sequence(single())), ALG_ED25519, SIG) },
        { name: 'a byKey responderID that is not an OCTET STRING', der: basicOf(tbsOf(tlv(2, true, 2, universal(2, [0x01])), gen('20260501000000Z'), sequence(single())), ALG_ED25519, SIG) },
        { name: 'no producedAt', der: basicOf(tbsOf(BY_KEY), ALG_ED25519, SIG) },
        { name: 'responses that are not a SEQUENCE', der: basicOf(tbsOf(BY_KEY, gen('20260501000000Z'), universal(2, [0x01])), ALG_ED25519, SIG) },
        { name: 'a SingleResponse with two fields', der: basicOf(tbsOf(BY_KEY, gen('20260501000000Z'), sequence(sequence(CERT_ID, tlv(2, false, 0, new Uint8Array(0))))), ALG_ED25519, SIG) },
        { name: 'a certStatus that is not context-tagged', der: basicOf(tbsOf(BY_KEY, gen('20260501000000Z'), sequence(sequence(CERT_ID, universal(5, []), gen('20260501000000Z')))), ALG_ED25519, SIG) },
        { name: 'a revoked answer with no revocationTime', der: basicOf(tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single({ status: tlv(2, true, 1, new Uint8Array(0)) }))), ALG_ED25519, SIG) },
    ])('should refuse $name', ({ der }) => {
        expect(() => parseOcspResponse(der, quiet)).toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should read an empty signature BIT STRING without inventing a padding count', () => {
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()));
        const response = parseOcspResponse(basicOf(tbs, ALG_ED25519, universal(3, [])), quiet);
        expect(response.basicResponse?.signatureValue.unusedBits).toBe(0);
        expect(response.basicResponse?.signatureValue.bytes).toHaveLength(0);
    });

    it('should refuse an extensions field that is not context-tagged', () => {
        // Unwrapping a bare SEQUENCE one level short would read the extensions
        // as the wrapper and hand back their innards.
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), sequence(nonceExtension));
        expect(() => parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse an extension with fewer than two fields', () => {
        const broken = sequence(NONCE_OID);
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, sequence(broken)));
        expect(() => parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should read a critical extension and record it as one', () => {
        const critical = sequence(NONCE_OID, universal(1, [0xff]), universal(4, [...universal(4, [1])]));
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()), tlv(2, true, 1, sequence(critical)));
        expect(parseOcspResponse(basicOf(tbs, ALG_ED25519, SIG), quiet).basicResponse?.extensions[0]?.critical).toBe(true);
    });

    it('should stop at maxChainLength while reading attached certificates', () => {
        const tbs = tbsOf(BY_KEY, gen('20260501000000Z'), sequence(single()));
        const der = basicOf(tbs, ALG_ED25519, SIG, tlv(2, true, 0, sequence(R12.der, ROOT.der, R12.der)));
        expect(() => parseOcspResponse(der, { ...quiet, limits: { maxChainLength: 2 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED' }));
    });
});

describe('verifyOcspSignature', () => {
    it('should refuse anything that did not come from parseOcspResponse', async () => {
        await expect(verifyOcspSignature(buildResponse() as never, ROOT))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should return false for a signature that is not one', async () => {
        const basic = parseOcspResponse(buildResponse(), quiet).basicResponse;
        expect(await verifyOcspSignature(basic as never, ROOT)).toBe(false);
    });

    it('should verify a response that was really signed, and refuse it under another key', async () => {
        // Ed25519, so the signature is reproducible. The response is signed
        // here because no public OCSP response is stable enough to pin.
        const pair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
        const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
        const tbs = sequence(
            tlv(2, true, 2, universal(4, [...sha1(spki)])),
            gen('20260501000000Z'),
            sequence(single()),
        );
        const signature = new Uint8Array(await webcrypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, tbs));
        const basicDer = sequence(tbs, ALG_ED25519, universal(3, [0x00, ...signature]));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basicDer]))));

        const responderDer = await createCertificate({
            serialNumber: 1n,
            subject: [[{ type: '2.5.4.3', value: 'Responder' }]],
            notBefore: AT - DAY,
            notAfter: AT + DAY,
            subjectPublicKey: spki,
            extensions: [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) }],
        }, { key: pair.privateKey as never, algorithm: { name: 'Ed25519' } });
        const responder = parseCertificate(responderDer, quiet);

        const basic = parseOcspResponse(der, quiet).basicResponse;
        expect(await verifyOcspSignature(basic as never, responder)).toBe(true);
        expect(await verifyOcspSignature(basic as never, ROOT)).toBe(false);
    });
});
