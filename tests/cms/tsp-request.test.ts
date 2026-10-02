import { describe, expect, it } from 'vitest';
import { _parseTimeStampRequest, createTimeStampRequest } from '../../src/cms/tsp-request.js';
import { PkiCmsError, PkiError } from '../../src/types/pki-errors.js';
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
