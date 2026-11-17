import { describe, expect, it } from 'vitest';
import { _parseTimeStampRequest, createTimeStampRequest, parseTimeStampRequest } from '../../src/cms/tsp-request.js';
import { PkiCmsError, PkiEncodingError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { TimeStampRequest } from '../../src/types/tsp-types.js';
import { concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 3161 §2.4.1 TimeStampReq — the question, written and read back.
 *
 * The writer is checked against bytes assembled here from first principles,
 * never against the reader: the two would otherwise agree on any mistake they
 * share. The reader is then checked on requests the writer produced, which is
 * the one direction in which using our own output is sound.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const SHA256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const HASH = new Uint8Array(32).fill(0x5a);

const oid = (content: readonly number[]): Uint8Array => universal(6, content);
const int = (...bytes: readonly number[]): Uint8Array => universal(2, bytes);
const NULL = universal(5, []);
const TRUE = universal(1, [0xff]);

const code = (fn: () => unknown): string | undefined => {
    try {
        fn();
    } catch (error) {
        return (error as { code?: string }).code;
    }
    return undefined;
};

describe('createTimeStampRequest', () => {
    it('should write version 1, a SHA-256 imprint with NULL parameters, and certReq TRUE', () => {
        // certReq TRUE is written because it is not the DEFAULT; the helpful
        // default is the one the grammar does not have.
        expect(createTimeStampRequest(HASH)).toEqual(sequence(
            int(1),
            sequence(sequence(oid(SHA256), NULL), universal(4, HASH)),
            TRUE,
        ));
    });

    it('should write the policy and the nonce in the order the module fixes, and omit a FALSE certReq', () => {
        const hash = new Uint8Array(48).fill(0x11);
        expect(createTimeStampRequest(hash, { hashAlgorithm: 'SHA-384', policy: '1.2.3.4', nonce: 0x1234n, certReq: false })).toEqual(sequence(
            int(1),
            sequence(sequence(oid(SHA384), NULL), universal(4, hash)),
            oid([0x2a, 0x03, 0x04]),
            int(0x12, 0x34),
        ));
    });

    it('should encode a nonce whose top bit is set with the leading zero DER requires', () => {
        // A 64-bit random nonce has its top bit set half the time. Without the
        // 0x00 it would encode a negative number the TSA echoes back as another.
        const der = createTimeStampRequest(HASH, { nonce: 0x80n });
        expect(_parseTimeStampRequest(der, quiet).nonce).toBe(0x80n);
        // …, nonce 02 02 00 80, certReq 01 01 ff.
        expect([...der.subarray(der.length - 7, der.length - 3)]).toEqual([0x02, 0x02, 0x00, 0x80]);
    });

    it('should accept SHA-512', () => {
        expect(_parseTimeStampRequest(createTimeStampRequest(new Uint8Array(64), { hashAlgorithm: 'SHA-512' }), quiet).messageImprint.hashAlgorithm.oid)
            .toBe('2.16.840.1.101.3.4.2.3');
    });

    it('should refuse SHA-1 by name', () => {
        // A collision on the imprint would let one token cover two documents.
        expect(code(() => createTimeStampRequest(new Uint8Array(20), { hashAlgorithm: 'SHA-1' as never }))).toBe('PKI_INVALID_OPTION');
    });

    it('should refuse a hash that is not as long as its algorithm', () => {
        expect(code(() => createTimeStampRequest(new Uint8Array(20)))).toBe('PKI_API_MISUSE');
    });

    it('should refuse input of the wrong type', () => {
        expect(code(() => createTimeStampRequest('abc' as never))).toBe('PKI_INVALID_INPUT');
        expect(code(() => createTimeStampRequest(HASH, { nonce: 5 as never }))).toBe('PKI_INVALID_INPUT');
        expect(() => createTimeStampRequest('abc' as never)).toThrow(PkiError);
    });
});

describe('_parseTimeStampRequest', () => {

    it('should refuse an argument that is not bytes as PKI_INVALID_INPUT, never as a TypeError', () => {
        // A caller's type error, not a fact about any encoding: it used to
        // escape as a TypeError, or as a length error about bytes nobody passed.
        for (const value of ['30 03 02 01 01', undefined, null, [0x30, 0x00]]) {
            expect(() => _parseTimeStampRequest(value as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
        }
    });
    it('should read back everything a response must echo', () => {
        const request = _parseTimeStampRequest(createTimeStampRequest(HASH, { policy: '1.2.3.4', nonce: 99n }), quiet);
        expect(request.messageImprint.hashedMessage).toEqual(HASH);
        expect(request.policy).toBe('1.2.3.4');
        expect(request.nonce).toBe(99n);
        expect(request.certReq).toBe(true);
    });

    it('should read an absent certReq as the FALSE it defaults to', () => {
        const request = _parseTimeStampRequest(createTimeStampRequest(HASH, { certReq: false }), quiet);
        expect(request.certReq).toBe(false);
        expect(request.policy).toBeUndefined();
        expect(request.nonce).toBeUndefined();
    });

    it('should read past the extensions, which only the TSA acts on', () => {
        const der = sequence(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH)), TRUE, tlv(2, true, 0, sequence()));
        expect(_parseTimeStampRequest(der, quiet).certReq).toBe(true);
    });

    it('should refuse a version other than 1', () => {
        const der = sequence(int(2), sequence(sequence(oid(SHA256), NULL), universal(4, HASH)));
        expect(() => _parseTimeStampRequest(der, quiet)).toThrow(PkiCmsError);
        expect(code(() => _parseTimeStampRequest(der, quiet))).toBe('PKI_CMS_VERSION_UNSUPPORTED');
    });

    it.each([
        ['not a SEQUENCE', universal(4, [0x01])],
        ['no version', sequence()],
        ['a version and nothing to stamp', sequence(int(1))],
        ['a version that is not an INTEGER', sequence(TRUE, sequence(sequence(oid(SHA256), NULL), universal(4, HASH)))],
        ['the nonce before the policy', sequence(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH)), int(5), oid([0x2a, 0x03]))],
        ['a field twice', sequence(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH)), TRUE, TRUE)],
        ['a field the request does not define', sequence(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH)), universal(4, [0x01]))],
        ['an unknown context tag', sequence(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH)), tlv(2, true, 1, sequence()))],
    ])('should refuse %s', (_, der) => {
        expect(code(() => _parseTimeStampRequest(der, quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it.each([
        ['the SET tag', 17, 0],
        ['a context [16] tag', 16, 2],
    ] as const)('should refuse a well-formed request under %s, at the root', (_, tagNumber, cls) => {
        const der = tlv(cls, true, tagNumber, concat(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH))));
        const thrown = (() => { try { _parseTimeStampRequest(der, quiet); } catch (error) { return error; } return undefined; })();
        expect(thrown).toBeInstanceOf(PkiCmsError);
        expect(thrown).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path: 'TimeStampReq', offset: 0 });
    });
});

describe('parseTimeStampRequest', () => {
    const IMPRINT = sequence(sequence(oid(SHA256), NULL), universal(4, HASH));
    const FALSE = universal(1, [0x00]);
    /** One `Extension`: an OID, an optional critical flag, and the value in its OCTET STRING. */
    const extension = (id: readonly number[], value: ArrayLike<number>, critical = false): Uint8Array =>
        sequence(oid(id), ...(critical ? [TRUE] : []), universal(4, value));
    /** `extensions [0] IMPLICIT Extensions`: the [0] stands where the SEQUENCE tag would. */
    const extensions = (...list: readonly Uint8Array[]): Uint8Array => tlv(2, true, 0, concat(...list));
    const PRIVATE_OID = [0x2a, 0x03, 0x04, 0x05];
    const SKI_OID = [0x55, 0x1d, 0x0e];

    const collect = (der: Uint8Array, options: { strict?: boolean } = {}): { codes: string[]; request: TimeStampRequest } => {
        const codes: string[] = [];
        const request = parseTimeStampRequest(der, { ...options, onDiagnostic: (d) => { codes.push(d.code); } });
        return { codes, request };
    };
    const thrownBy = (fn: () => unknown): unknown => {
        try {
            fn();
        } catch (error) {
            return error;
        }
        return undefined;
    };

    it('should read back every field createTimeStampRequest wrote, with no diagnostic', () => {
        const der = createTimeStampRequest(HASH, { policy: '1.2.3.4', nonce: 0x80n });
        const { codes, request } = collect(der);
        expect(request.version).toBe(1);
        expect(request.messageImprint.hashAlgorithm.oid).toBe('2.16.840.1.101.3.4.2.1');
        expect(request.messageImprint.hashedMessage).toEqual(HASH);
        expect(request.policy).toBe('1.2.3.4');
        expect(request.nonce).toBe(0x80n);
        expect(request.certReq).toBe(true);
        expect(request.extensions).toEqual([]);
        expect(request.diagnostics).toEqual([]);
        expect(codes).toEqual([]);
    });

    it('should return the whole request as a view of the input, not a copy', () => {
        const der = createTimeStampRequest(HASH);
        const request = parseTimeStampRequest(der, quiet);
        expect(request.der).toEqual(der);
        expect(request.der.buffer).toBe(der.buffer);
        expect(Object.isFrozen(request)).toBe(true);
    });

    it('should read an absent policy, nonce and certReq as undefined, undefined and FALSE', () => {
        const { codes, request } = collect(sequence(int(1), IMPRINT));
        expect(request.policy).toBeUndefined();
        expect(request.nonce).toBeUndefined();
        expect(request.certReq).toBe(false);
        expect(codes).toEqual([]);
    });

    it('should name a certReq that encodes its DEFAULT FALSE, and refuse it under strict (X.690 §11.5)', () => {
        const der = sequence(int(1), IMPRINT, FALSE);
        const { codes, request } = collect(der);
        expect(request.certReq).toBe(false);
        expect(codes).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
        expect(request.diagnostics.map((d) => [d.code, d.path, d.offset])).toEqual([['PKI_DIAG_DEFAULT_ENCODED', 'TimeStampReq.certReq', der.length - 3]]);
        expect(code(() => collect(der, { strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
    });

    it('should leave the reader of the verifier silent on the same request: a verdict does not move with a remark', () => {
        const seen: string[] = [];
        const request = _parseTimeStampRequest(sequence(int(1), IMPRINT, FALSE), { strict: true, onDiagnostic: (d) => { seen.push(d.code); } });
        expect(request.certReq).toBe(false);
        expect(seen).toEqual([]);
        // …and nothing for a certReq TRUE either.
        _parseTimeStampRequest(sequence(int(1), IMPRINT, TRUE), { onDiagnostic: (d) => { seen.push(d.code); } });
        expect(seen).toEqual([]);
        expect(Object.keys(request).sort()).toEqual(['certReq', 'messageImprint', 'nonce', 'policy']);
    });

    it('should keep an extension it does not recognise, raw, and decode one it does', () => {
        const keyId = universal(4, [0xde, 0xad, 0xbe, 0xef]);
        const { codes, request } = collect(sequence(int(1), IMPRINT, TRUE, extensions(extension(PRIVATE_OID, [0x05, 0x00]), extension(SKI_OID, keyId))));
        expect(request.extensions).toHaveLength(2);
        expect(request.extensions[0]).toEqual({ kind: 'unknown', oid: '1.2.3.4.5', critical: false, valueDer: Uint8Array.of(0x05, 0x00) });
        expect(request.extensions[1]).toMatchObject({ kind: 'subjectKeyIdentifier', oid: '2.5.29.14', critical: false });
        expect(codes).toEqual([]);
        expect(Object.isFrozen(request.extensions)).toBe(true);
    });

    it('should name a critical extension it does not recognise, and refuse it under strict (RFC 5280 §4.2)', () => {
        const der = sequence(int(1), IMPRINT, extensions(extension(PRIVATE_OID, [0x05, 0x00], true)));
        const { codes, request } = collect(der);
        expect(request.extensions[0]).toMatchObject({ kind: 'unknown', critical: true });
        expect(codes).toEqual(['PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION']);
        expect(code(() => collect(der, { strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
    });

    it('should refuse a recognised extension whose value is not its ASN.1 definition, as a CMS refusal', () => {
        // subjectKeyIdentifier is an OCTET STRING; a NULL in its place is refused by
        // the certificate reader, and reported under the class this caller catches.
        const der = sequence(int(1), IMPRINT, extensions(extension(SKI_OID, [0x05, 0x00])));
        expect(() => parseTimeStampRequest(der, quiet)).toThrow(PkiCmsError);
        expect(code(() => parseTimeStampRequest(der, quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it.each([
        ['a primitive [0], octets where Extension values belong', tlv(2, false, 0, [0x01, 0x02, 0x03]), 'TimeStampReq.extensions'],
        ['an entry that is not an Extension', tlv(2, true, 0, sequence()), 'TimeStampReq.extensions[0]'],
    ])('should refuse extensions that are %s, which the reader of the verifier reads past', (_, field, path) => {
        const der = sequence(int(1), IMPRINT, TRUE, field);
        const thrown = thrownBy(() => parseTimeStampRequest(der, quiet));
        expect(thrown).toBeInstanceOf(PkiCmsError);
        expect(thrown).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path });
        expect(_parseTimeStampRequest(der, quiet).certReq).toBe(true);
    });

    it('should stop at maxExtensions, the limit that bounds the extensions of a certificate', () => {
        const der = sequence(int(1), IMPRINT, extensions(extension(PRIVATE_OID, [0x05, 0x00]), extension([0x2a, 0x03, 0x04, 0x06], [0x05, 0x00])));
        expect(parseTimeStampRequest(der, { ...quiet, limits: { maxExtensions: 2 } }).extensions).toHaveLength(2);
        const thrown = thrownBy(() => parseTimeStampRequest(der, { ...quiet, limits: { maxExtensions: 1 } }));
        expect(thrown).toBeInstanceOf(PkiLimitError);
        expect(thrown).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxExtensions' });
    });

    it('should refuse a version other than 1', () => {
        const der = sequence(int(2), IMPRINT);
        expect(() => parseTimeStampRequest(der, quiet)).toThrow(PkiCmsError);
        expect(code(() => parseTimeStampRequest(der, quiet))).toBe('PKI_CMS_VERSION_UNSUPPORTED');
    });

    it.each([
        ['not a SEQUENCE', universal(4, [0x01])],
        ['no version', sequence()],
        ['a version and nothing to stamp', sequence(int(1))],
        ['an imprint whose hash is not as long as its algorithm (RFC 3161 §2.4.1)', sequence(int(1), sequence(sequence(oid(SHA256), NULL), universal(4, HASH.subarray(0, 20))))],
        ['the nonce before the policy', sequence(int(1), IMPRINT, int(5), oid([0x2a, 0x03]))],
        ['the extensions before certReq', sequence(int(1), IMPRINT, extensions(extension(PRIVATE_OID, [0x05, 0x00])), TRUE)],
        ['a field twice', sequence(int(1), IMPRINT, TRUE, TRUE)],
        ['an unknown context tag', sequence(int(1), IMPRINT, tlv(2, true, 1, sequence()))],
    ])('should refuse %s', (_, der) => {
        expect(() => parseTimeStampRequest(der, quiet)).toThrow(PkiCmsError);
        expect(code(() => parseTimeStampRequest(der, quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it('should read the request as DER whatever encodingRules says (RFC 3161 §3: every transport carries DER)', () => {
        // The same request under an indefinite length: BER, and refused.
        const ber = tlv(0, true, 16, concat(int(1), IMPRINT), { indefinite: true });
        expect(thrownBy(() => parseTimeStampRequest(ber, { ...quiet, encodingRules: 'ber' }))).toBeInstanceOf(PkiEncodingError);
        expect(thrownBy(() => parseTimeStampRequest(concat(sequence(int(1), IMPRINT), [0x00]), quiet))).toBeInstanceOf(PkiEncodingError);
    });

    it('should refuse an argument that is not bytes as PKI_INVALID_INPUT, never as a TypeError', () => {
        for (const value of ['30 03 02 01 01', undefined, null, [0x30, 0x00]]) {
            expect(() => parseTimeStampRequest(value as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
            expect(() => parseTimeStampRequest(value as unknown as Uint8Array)).toThrow(PkiError);
        }
    });
});
