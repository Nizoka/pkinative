import { describe, expect, it } from 'vitest';
import { parseTstInfo } from '../../src/cms/tsp-tst-info.js';
import { PkiCmsError, PkiLimitError } from '../../src/types/pki-errors.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 3161 §2.4.2 TSTInfo — what a timestamp authority asserts.
 *
 * Every value is built from first principles with the engine-independent
 * builder: a reader tested against its own writer would share its mistakes.
 * The interesting cases are the ones a lax reader gets wrong in the permissive
 * direction — a truncated imprint read as a full one, an out-of-range accuracy
 * widened into a longer window, a BER variant of bytes the TSA signed as DER.
 */

const quiet = { onDiagnostic: (): undefined => undefined };

// ── Hand-encoded values ───────────────────────────────────────────────

const SHA256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA512 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const UNKNOWN_HASH = [0x2a, 0x03, 0x04, 0x05];
const POLICY = [0x2a, 0x03, 0x04]; // 1.2.3.4
const CN = universal(6, [0x55, 0x04, 0x03]);

const oid = (content: readonly number[]): Uint8Array => universal(6, content);
const int = (...bytes: readonly number[]): Uint8Array => universal(2, bytes);
const bool = (value: boolean): Uint8Array => universal(1, [value ? 0xff : 0x00]);
const generalizedTime = (text: string): Uint8Array => universal(24, ascii(text));
const imprint = (algorithm: readonly number[], length: number): Uint8Array =>
    sequence(sequence(oid(algorithm), universal(5, [])), universal(4, new Array<number>(length).fill(0xab)));

interface TstParts {
    readonly version?: Uint8Array;
    readonly imprint?: Uint8Array;
    readonly serial?: Uint8Array;
    readonly genTime?: Uint8Array;
    readonly tail?: readonly Uint8Array[];
}

function tstInfo(parts: TstParts = {}): Uint8Array {
    return sequence(
        parts.version ?? int(1),
        oid(POLICY),
        parts.imprint ?? imprint(SHA256, 32),
        parts.serial ?? int(0x2b),
        parts.genTime ?? generalizedTime('20260928120000Z'),
        ...(parts.tail ?? []),
    );
}

const code = (fn: () => unknown): string | undefined => {
    try {
        fn();
    } catch (error) {
        return (error as { code?: string }).code;
    }
    return undefined;
};

describe('parseTstInfo', () => {
    it('should read the five mandatory fields', () => {
        const info = parseTstInfo(tstInfo(), quiet);
        expect(info.version).toBe(1);
        expect(info.policy).toBe('1.2.3.4');
        expect(info.messageImprint.hashAlgorithm.oid).toBe('2.16.840.1.101.3.4.2.1');
        expect(info.messageImprint.hashedMessage).toHaveLength(32);
        expect(info.serialNumber.hex).toBe('2b');
        expect(new Date(info.genTime.epochMilliseconds).toISOString()).toBe('2026-09-28T12:00:00.000Z');
        expect(info.accuracy).toBeUndefined();
        expect(info.ordering).toBe(false);
        expect(info.nonce).toBeUndefined();
        expect(info.tsa).toBeUndefined();
        expect(info.extensions).toEqual([]);
    });

    it('should hand back the exact bytes the TSA signed', () => {
        const der = tstInfo();
        const info = parseTstInfo(der, quiet);
        expect(info.der).toEqual(der);
        expect(info.der.buffer).toBe(der.buffer);
        expect(Object.isFrozen(info)).toBe(true);
    });

    it('should keep a fractional second, which RFC 3161 allows and RFC 5280 does not', () => {
        const diagnostics: string[] = [];
        const info = parseTstInfo(tstInfo({ genTime: generalizedTime('20260928120000.123Z') }), {
            onDiagnostic: (d): void => { diagnostics.push(d.code); },
        });
        expect(info.genTime.epochMilliseconds % 1000).toBe(123);
        expect(info.genTime.text).toBe('20260928120000.123Z');
        expect(diagnostics).toEqual([]);
    });

    it('should refuse a version other than 1', () => {
        expect(() => parseTstInfo(tstInfo({ version: int(2) }), quiet)).toThrow(PkiCmsError);
        expect(code(() => parseTstInfo(tstInfo({ version: int(2) }), quiet))).toBe('PKI_CMS_VERSION_UNSUPPORTED');
    });

    it.each([
        ['not a SEQUENCE', universal(4, [0x01])],
        ['a SEQUENCE holding only the version', sequence(int(1))],
        ['a version that is not an INTEGER', tstInfo({ version: bool(true) })],
        ['an imprint that is not a pair', tstInfo({ imprint: sequence(universal(4, [0x01])) })],
        ['a serial that is not an INTEGER', tstInfo({ serial: universal(4, [0x01]) })],
        ['a genTime that is a UTCTime', tstInfo({ genTime: universal(23, ascii('260928120000Z')) })],
        ['a field after the extensions', tstInfo({ tail: [tlv(2, true, 1, sequence()), int(5)] })],
        ['the nonce before ordering', tstInfo({ tail: [int(5), bool(true)] })],
        ['an unknown context tag', tstInfo({ tail: [tlv(2, true, 3, sequence())] })],
    ])('should refuse %s', (_, der) => {
        expect(code(() => parseTstInfo(der, quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it('should refuse an imprint shorter than its algorithm', () => {
        // A 20-octet "SHA-256" is a truncated hash. Stamping it as the full one
        // would bind the time to every input sharing those 20 octets.
        expect(code(() => parseTstInfo(tstInfo({ imprint: imprint(SHA256, 20) }), quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it('should accept an imprint of any length under a digest it does not know', () => {
        const info = parseTstInfo(tstInfo({ imprint: imprint(UNKNOWN_HASH, 7) }), quiet);
        expect(info.messageImprint.hashedMessage).toHaveLength(7);
        expect(parseTstInfo(tstInfo({ imprint: imprint(SHA512, 64) }), quiet).messageImprint.hashedMessage).toHaveLength(64);
    });

    describe('the optional tail', () => {
        it('should read every field when all are present', () => {
            const info = parseTstInfo(tstInfo({
                tail: [
                    sequence(int(1), tlv(2, false, 0, [0x01, 0xf4]), tlv(2, false, 1, [0x0a])),
                    bool(true),
                    int(0x00, 0x9a),
                    tlv(2, true, 0, tlv(2, true, 4, sequence(universal(17, sequence(CN, universal(12, ascii('TSA'))), true)))),
                    tlv(2, true, 1, concat(sequence(oid([0x2a, 0x03, 0x05]), universal(4, [0x05, 0x00])))),
                ],
            }), quiet);
            expect(info.accuracy).toEqual({ seconds: 1, millis: 500, micros: 10 });
            expect(info.ordering).toBe(true);
            expect(info.nonce).toBe(0x9an);
            expect(info.tsa?.kind).toBe('directoryName');
            expect(info.extensions).toHaveLength(1);
            expect(info.extensions[0]?.oid).toBe('1.2.3.5');
        });

        it('should read an accuracy of whole seconds only, the missing fields counting as zero', () => {
            expect(parseTstInfo(tstInfo({ tail: [sequence(int(2))] }), quiet).accuracy).toEqual({ seconds: 2, millis: 0, micros: 0 });
            expect(parseTstInfo(tstInfo({ tail: [sequence()] }), quiet).accuracy).toEqual({ seconds: 0, millis: 0, micros: 0 });
        });

        it.each([
            ['a millis of 0', sequence(tlv(2, false, 0, [0x00]))],
            ['a micros of 1000', sequence(tlv(2, false, 1, [0x03, 0xe8]))],
            ['a negative seconds', sequence(int(0xff))],
            ['a seconds wider than a clock can mean', sequence(int(0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))],
            ['millis before seconds', sequence(tlv(2, false, 0, [0x05]), int(1))],
            ['a constructed millis', sequence(tlv(2, true, 0, int(5)))],
            ['a field Accuracy does not define', sequence(tlv(2, false, 2, [0x05]))],
        ])('should refuse %s, which the type does not allow', (_, accuracy) => {
            expect(code(() => parseTstInfo(tstInfo({ tail: [accuracy] }), quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
        });

        it('should name an ordering encoded as its DEFAULT', () => {
            const diagnostics: string[] = [];
            const info = parseTstInfo(tstInfo({ tail: [bool(false)] }), { onDiagnostic: (d): void => { diagnostics.push(d.code); } });
            expect(info.ordering).toBe(false);
            expect(diagnostics).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
        });

        it('should refuse a tsa that is not one explicitly tagged GeneralName', () => {
            // [0] is EXPLICIT here despite the module's IMPLICIT TAGS: GeneralName
            // is a CHOICE. Read implicitly, the [0] would be mistaken for the
            // GeneralName's own otherName tag.
            expect(code(() => parseTstInfo(tstInfo({ tail: [tlv(2, false, 0, ascii('tsa'))] }), quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
        });

        it.each([
            ['a primitive entry', tlv(2, true, 1, universal(4, [0x01]))],
            ['an entry holding only an OID', tlv(2, true, 1, sequence(oid([0x2a, 0x03])))],
            ['an entry of four fields', tlv(2, true, 1, sequence(oid([0x2a, 0x03]), bool(true), universal(4, []), universal(4, [])))],
        ])('should refuse an extensions field with %s', (_, extensions) => {
            expect(code(() => parseTstInfo(tstInfo({ tail: [extensions] }), quiet))).toBe('PKI_CMS_STRUCTURE_INVALID');
        });

        it('should read a critical extension as critical', () => {
            const info = parseTstInfo(tstInfo({ tail: [tlv(2, true, 1, sequence(oid([0x2a, 0x03, 0x05]), bool(true), universal(4, [0x05, 0x00])))] }), quiet);
            expect(info.extensions[0]?.critical).toBe(true);
        });

        it('should stop at maxExtensions', () => {
            const one = sequence(oid([0x2a, 0x03, 0x05]), universal(4, [0x05, 0x00]));
            const der = tstInfo({ tail: [tlv(2, true, 1, concat(one, one, one))] });
            expect(() => parseTstInfo(der, { ...quiet, limits: { maxExtensions: 2 } })).toThrow(PkiLimitError);
        });
    });

    it('should read DER even when the caller asked for BER', () => {
        // RFC 3161 §2.4.2: the eContent SHALL be DER. The TSA signed those exact
        // bytes, so a BER variant is not the TSTInfo that was signed.
        const indefinite = concat([0x30, 0x80], int(1), oid(POLICY), imprint(SHA256, 32), int(0x2b), generalizedTime('20260928120000Z'), [0x00, 0x00]);
        expect(code(() => parseTstInfo(indefinite, { ...quiet, encodingRules: 'ber' }))).toBe('PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN');
    });
});
