import { describe, expect, it } from 'vitest';
import { parseTimeStampResponse, parseTimeStampToken } from '../../src/cms/tsp-response.js';
import { PkiCmsError, PkiEncodingError } from '../../src/types/pki-errors.js';
import { alg, contentInfo, int, octets, oid, OIDS, signedData } from '../helpers/cms-signed-data-builder.js';
import { ascii, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 3161 §2.4.2 TimeStampResp and TimeStampToken, read.
 *
 * Every response and token is assembled here field by field with the
 * engine-independent builders, so the reader is checked against the RFC's
 * ASN.1 module and not against pkinative's own writer. Nothing here is
 * verified — that is `verifyTimeStampToken`'s job — only read.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const IMPRINT = new Uint8Array(32).fill(0x3c);
const POLICY = '1.3.6.1.4.1.99999.1';

/** `TSTInfo`, minimal: version, policy, messageImprint, serialNumber, genTime. */
const TST_INFO = sequence(
    int(1),
    oid(POLICY),
    sequence(alg(OIDS.sha256), octets(IMPRINT)),
    int(77),
    universal(24, ascii('20260115000000Z')),
);

/** A token around a TSTInfo — the signature is not looked at by the reader. */
const token = (eContent: Uint8Array | null = octets(TST_INFO), contentType: string = OIDS.tstInfo): Uint8Array =>
    contentInfo(signedData({ contentType, eContent }));

const TOKEN = token();

/** `PKIStatusInfo`, from its fields. */
const statusInfo = (...fields: Uint8Array[]): Uint8Array => sequence(...fields);
const utf8 = (text: string): Uint8Array => universal(12, ascii(text));
/** A BIT STRING from its content octets: unused-bit count first. */
const bits = (...content: number[]): Uint8Array => universal(3, content);
const response = (...fields: Uint8Array[]): Uint8Array => sequence(...fields);

function thrown(run: () => unknown): unknown {
    try {
        run();
    } catch (error) {
        return error;
    }
    throw new Error('expected a throw');
}

describe('parseTimeStampToken', () => {
    it('should read the SignedData envelope and the TSTInfo it carries', () => {
        const parsed = parseTimeStampToken(TOKEN, quiet);
        expect(parsed.signedData.contentType).toBe(OIDS.tstInfo);
        expect(parsed.tstInfo.policy).toBe(POLICY);
        expect(parsed.tstInfo.messageImprint.hashedMessage).toEqual(IMPRINT);
        expect(parsed.tstInfo.genTime.epochMilliseconds).toBe(Date.UTC(2026, 0, 15));
        expect(Object.isFrozen(parsed)).toBe(true);
    });

    it('should refuse a SignedData over anything but a TSTInfo with PKI_CMS_CONTENT_TYPE_UNEXPECTED', () => {
        const error = thrown(() => parseTimeStampToken(token(octets(TST_INFO), OIDS.data), quiet));
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error).toMatchObject({ code: 'PKI_CMS_CONTENT_TYPE_UNEXPECTED', path: 'content.encapContentInfo.eContentType' });
    });

    it('should refuse a detached TSTInfo with PKI_CMS_STRUCTURE_INVALID — the token is the assertion', () => {
        const error = thrown(() => parseTimeStampToken(token(null), quiet));
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path: 'content.encapContentInfo.eContent' });
    });

    it('should let a malformed TSTInfo through as the TSTInfo reader\'s error', () => {
        const error = thrown(() => parseTimeStampToken(token(octets(sequence(int(1)))), quiet));
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID' });
    });
});

describe('parseTimeStampResponse', () => {

    it('should refuse an argument that is not bytes as PKI_INVALID_INPUT, never as a TypeError', () => {
        // A caller's type error, not a fact about any encoding: it used to
        // escape as a TypeError, or as a length error about bytes nobody passed.
        for (const value of ['30 03 02 01 01', undefined, null, [0x30, 0x00]]) {
            expect(() => parseTimeStampResponse(value as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
        }
    });
    describe('a granted response', () => {
        it.each([
            ['granted', 0],
            ['grantedWithMods', 1],
        ] as const)('should read %s with its token, as a zero-copy view of the exact token bytes', (status, value) => {
            const der = response(statusInfo(int(value)), TOKEN);
            const parsed = parseTimeStampResponse(der, quiet);
            expect(parsed.status).toBe(status);
            expect(parsed.statusStrings).toEqual([]);
            expect(parsed.failInfo).toEqual([]);
            expect(parsed.tokenDer).toEqual(TOKEN);
            expect(parsed.tokenDer?.buffer).toBe(der.buffer);
            expect(parsed.token?.tstInfo.messageImprint.hashedMessage).toEqual(IMPRINT);
            expect(parsed.der).toEqual(der);
            expect(parsed.diagnostics).toEqual([]);
        });

        it('should refuse a grant without a token (RFC 3161 §2.4.2)', () => {
            const error = thrown(() => parseTimeStampResponse(response(statusInfo(int(0))), quiet));
            expect(error).toBeInstanceOf(PkiCmsError);
            expect(error).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path: 'TimeStampResp' });
        });

        it('should refuse a token that is not a timestamp token with the token reader\'s error', () => {
            expect(thrown(() => parseTimeStampResponse(response(statusInfo(int(0)), token(octets(TST_INFO), OIDS.data)), quiet)))
                .toMatchObject({ code: 'PKI_CMS_CONTENT_TYPE_UNEXPECTED' });
        });
    });

    describe('a declined response', () => {
        it('should read a rejection with its status strings and every failure named, and no token', () => {
            // badRequest (bit 2) and badDataFormat (bit 5): 0010 0100, two unused bits.
            const der = response(statusInfo(int(2), sequence(utf8('malformed request'), utf8('try again')), bits(0x02, 0x24)));
            const parsed = parseTimeStampResponse(der, quiet);
            expect(parsed.status).toBe('rejection');
            expect(parsed.statusStrings).toEqual(['malformed request', 'try again']);
            expect(parsed.failInfo).toEqual(['badRequest', 'badDataFormat']);
            expect(parsed.tokenDer).toBeUndefined();
            expect(parsed.token).toBeUndefined();
        });

        it.each([
            ['badAlg', [0x07, 0x80]],
            ['timeNotAvailable', [0x01, 0x00, 0x02]],
            ['unacceptedPolicy', [0x00, 0x00, 0x01]],
            ['unacceptedExtension', [0x07, 0x00, 0x00, 0x80]],
            ['addInfoNotAvailable', [0x06, 0x00, 0x00, 0x40]],
            ['systemFailure', [0x06, 0x00, 0x00, 0x00, 0x40]],
        ])('should name the failure bit %s', (name, content) => {
            const parsed = parseTimeStampResponse(response(statusInfo(int(2), bits(...content))), quiet);
            expect(parsed.failInfo).toEqual([name]);
        });

        it.each([
            ['waiting', 3],
            ['revocationWarning', 4],
            ['revocationNotification', 5],
        ] as const)('should read the status %s', (status, value) => {
            expect(parseTimeStampResponse(response(statusInfo(int(value))), quiet).status).toBe(status);
        });

        it('should read a failInfo without a statusString', () => {
            const parsed = parseTimeStampResponse(response(statusInfo(int(2), bits(0x07, 0x80))), quiet);
            expect(parsed.statusStrings).toEqual([]);
            expect(parsed.failInfo).toEqual(['badAlg']);
        });

        it('should read no failInfo bit from the padding, whose zero bits X.690 §11.2.1 requires of DER only', () => {
            // badAlg (bit 0), then seven unused bits of which the first is set: 1100 0000.
            const parsed = parseTimeStampResponse(response(statusInfo(int(2), bits(0x07, 0xc0))), { ...quiet, encodingRules: 'ber' });
            expect(parsed.failInfo).toEqual(['badAlg']);
        });

        it('should refuse a declined response that still carries a token', () => {
            const error = thrown(() => parseTimeStampResponse(response(statusInfo(int(2)), TOKEN), quiet));
            expect(error).toBeInstanceOf(PkiCmsError);
            expect(error).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path: 'TimeStampResp' });
        });
    });

    describe('what RFC 3161 does not define', () => {
        it.each([
            ['a response that is not a SEQUENCE', universal(17, sequence(int(0)), true), 'TimeStampResp'],
            // A complete rejection under the SET tag: only the root tag is wrong.
            ['a rejection under the SET tag', universal(17, statusInfo(int(2)), true), 'TimeStampResp'],
            ['an empty response', response(), 'TimeStampResp'],
            ['a response of three fields', response(statusInfo(int(0)), TOKEN, TOKEN), 'TimeStampResp'],
            ['a status that is not a SEQUENCE', response(int(0)), 'TimeStampResp.status'],
            ['a PKIStatusInfo without a status', response(statusInfo()), 'TimeStampResp.status.status'],
            ['a status that is not an INTEGER', response(statusInfo(octets([0]))), 'TimeStampResp.status.status'],
            ['a status beyond revocationNotification', response(statusInfo(int(6))), 'TimeStampResp.status.status'],
            ['a negative status', response(statusInfo(universal(2, [0xff]))), 'TimeStampResp.status.status'],
            ['an empty statusString', response(statusInfo(int(2), sequence())), 'TimeStampResp.status.statusString'],
            ['a statusString that is not UTF8String', response(statusInfo(int(2), sequence(universal(19, ascii('printable'))))), 'TimeStampResp.status.statusString[0]'],
            ['a failInfo bit RFC 3161 does not name', response(statusInfo(int(2), bits(0x06, 0x40))), 'TimeStampResp.status.failInfo'],
            ['failInfo before statusString', response(statusInfo(int(2), bits(0x07, 0x80), sequence(utf8('late')))), 'TimeStampResp.status'],
            ['statusString twice', response(statusInfo(int(2), sequence(utf8('a')), sequence(utf8('b')))), 'TimeStampResp.status'],
            ['a field PKIStatusInfo does not define', response(statusInfo(int(2), int(0))), 'TimeStampResp.status'],
        ])('should refuse %s with PKI_CMS_STRUCTURE_INVALID', (_label, der, path) => {
            const error = thrown(() => parseTimeStampResponse(der, quiet));
            expect(error).toBeInstanceOf(PkiCmsError);
            expect(error).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path });
        });

        it('should refuse bytes after the response with the encoding error', () => {
            const der = response(statusInfo(int(0)), TOKEN);
            const padded = new Uint8Array(der.length + 2);
            padded.set(der);
            const error = thrown(() => parseTimeStampResponse(padded, quiet));
            expect(error).toBeInstanceOf(PkiEncodingError);
            expect(error).toMatchObject({ code: 'PKI_ASN1_TRAILING_DATA' });
        });

        it('should refuse bytes that are not DER with the encoding error', () => {
            expect(thrown(() => parseTimeStampResponse(Uint8Array.of(0x30, 0x05, 0x02), quiet))).toBeInstanceOf(PkiEncodingError);
        });
    });
});
