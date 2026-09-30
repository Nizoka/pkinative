import { describe, it, expect } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { daysInMonth, readTime } from '../../src/asn1/asn1-time.js';
import type { ReadTimeOptions } from '../../src/types/asn1-types.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import { ascii, concat, hex, tlv, universal } from '../helpers/raw-der-builder.js';

const BER: ReadTimeOptions = { encodingRules: 'ber', onDiagnostic: () => undefined };
const utc = (text: string): Uint8Array => universal(23, ascii(text));
const generalized = (text: string): Uint8Array => universal(24, ascii(text));
const read = (bytes: Uint8Array, options?: ReadTimeOptions): ReturnType<typeof readTime> => readTime(decodeAsn1(bytes, options), options);

function codeOf(fn: () => unknown): string {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err.code;
        throw err;
    }
    return 'no error';
}

function thrownMessage(fn: () => unknown): string {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err.message;
        throw err;
    }
    return 'no error';
}

describe('readTime — UTCTime', () => {
    it('should decode the DER form to the exact instant and keep the text', () => {
        expect(read(utc('250101000000Z'))).toEqual({ type: 'UTCTime', epochMilliseconds: Date.parse('2025-01-01T00:00:00Z'), text: '250101000000Z' });
    });

    it('should apply the RFC 5280 pivot: 50–99 are 1950–1999, 00–49 are 2000–2049', () => {
        expect(read(utc('500101000000Z')).epochMilliseconds).toBe(Date.parse('1950-01-01T00:00:00Z'));
        expect(read(utc('991231235959Z')).epochMilliseconds).toBe(Date.parse('1999-12-31T23:59:59Z'));
        expect(read(utc('000101000000Z')).epochMilliseconds).toBe(Date.parse('2000-01-01T00:00:00Z'));
        expect(read(utc('491231235959Z')).epochMilliseconds).toBe(Date.parse('2049-12-31T23:59:59Z'));
    });

    it('should refuse the forms without seconds or with an offset under DER and accept them under BER', () => {
        expect(codeOf(() => read(utc('2501010000Z')))).toBe('PKI_ASN1_TIME_INVALID');
        expect(codeOf(() => read(utc('250101000000+0100')))).toBe('PKI_ASN1_TIME_INVALID');
        expect(read(utc('2501010000Z'), BER).epochMilliseconds).toBe(Date.parse('2025-01-01T00:00:00Z'));
        expect(read(utc('250101000000+0100'), BER).epochMilliseconds).toBe(Date.parse('2024-12-31T23:00:00Z'));
    });
});

describe('readTime — GeneralizedTime', () => {
    it('should decode years 0000 to 9999 exactly, never through the two-digit Date.UTC mapping', () => {
        expect(new Date(read(generalized('00000101000000Z')).epochMilliseconds).getUTCFullYear()).toBe(0);
        expect(new Date(read(generalized('00990101000000Z')).epochMilliseconds).getUTCFullYear()).toBe(99);
        expect(read(generalized('99991231235959Z')).epochMilliseconds).toBe(Date.parse('9999-12-31T23:59:59Z'));
        expect(read(generalized('20500101000000Z')).epochMilliseconds).toBe(Date.parse('2050-01-01T00:00:00Z'));
    });

    it('should decode a fraction to the millisecond, truncating finer digits', () => {
        expect(read(generalized('20240229120000.5Z')).epochMilliseconds).toBe(Date.parse('2024-02-29T12:00:00.500Z'));
        expect(read(generalized('20240229120000.123Z')).epochMilliseconds).toBe(Date.parse('2024-02-29T12:00:00.123Z'));
        expect(read(generalized('20240229120000.1239Z')).epochMilliseconds).toBe(Date.parse('2024-02-29T12:00:00.123Z'));
    });

    it.each([
        ['a trailing zero in the fraction', '20240101000000.50Z'],
        ['a comma as the decimal mark', '20240101000000,5Z'],
        ['an offset instead of Z', '20240101000000-0130'],
        ['missing seconds', '202401010000Z'],
    ])('should refuse %s under DER and accept it under BER', (_label, text) => {
        expect(codeOf(() => read(generalized(text)))).toBe('PKI_ASN1_TIME_INVALID');
        expect(codeOf(() => read(generalized(text), BER))).toBe('no error');
    });

    it('should apply the offset under BER', () => {
        expect(read(generalized('20240101000000-0130'), BER).epochMilliseconds).toBe(Date.parse('2024-01-01T01:30:00Z'));
    });

    it('should report the tolerated BER form once', () => {
        const seen: PkiDiagnostic[] = [];
        read(generalized('20240101000000,5Z'), { encodingRules: 'ber', onDiagnostic: (d) => seen.push(d) });
        expect(seen).toEqual([expect.objectContaining({ code: 'PKI_DIAG_BER_CONSTRUCT_ACCEPTED' })]);
    });

    it.each([
        ['a local time without a zone', '20240101000000'],
        ['a fraction without seconds', '202401010000.5Z'],
    ])('should refuse %s in every mode', (_label, text) => {
        expect(codeOf(() => read(generalized(text), BER))).toBe('PKI_ASN1_TIME_INVALID');
    });

    it.each([
        ['hours only', '1985110621Z'],
        ['a fraction of a minute', '198511062106.456Z'],
        ['a fraction of an hour', '1985110621.14159Z'],
        ['an offset in whole hours', '19851106210627-05'],
    ])('should refuse the X.680 form with %s under BER, naming its own subset rather than blaming the standard', (_label, text) => {
        const ber = thrownMessage(() => read(generalized(text), BER));
        expect(ber).toContain('under BER pkinative reads YYYYMMDDHHMM[SS[(.|,)f]]');
        expect(ber).not.toContain('leave no lenient interpretation');
        // Under DER the restricted form is the only one, so the rule stands.
        expect(thrownMessage(() => read(generalized(text)))).toContain('leave no lenient interpretation');
    });
});

describe('readTime — impossible instants', () => {
    it.each([
        ['month 13', utc('251301000000Z')],
        ['month 0', utc('250001000000Z')],
        ['day 0', utc('250100000000Z')],
        ['31 April', utc('250431000000Z')],
        ['29 February 1900', generalized('19000229000000Z')],
        ['30 February 2024', generalized('20240230000000Z')],
        ['hour 24', utc('250101240000Z')],
        ['minute 60', utc('250101006000Z')],
        ['second 60', utc('250101000060Z')],
        ['a non-digit', utc('25010100000AZ')],
    ])('should refuse %s', (_label, bytes) => {
        expect(codeOf(() => read(bytes))).toBe('PKI_ASN1_TIME_INVALID');
    });

    it('should accept 29 February of a leap year, 2000 included', () => {
        expect(read(generalized('20000229000000Z')).epochMilliseconds).toBe(Date.parse('2000-02-29T00:00:00Z'));
    });

    it('should refuse an impossible offset under BER and an oversized content before decoding it', () => {
        expect(codeOf(() => read(utc('250101000000+2400'), BER))).toBe('PKI_ASN1_TIME_INVALID');
        const oversized = universal(24, new Uint8Array(65).fill(0x31));
        expect(codeOf(() => read(oversized))).toBe('PKI_ASN1_TIME_INVALID');
        let message = '';
        try {
            read(oversized);
        } catch (err) {
            message = (err as Error).message;
        }
        expect(message).toContain('65 octets');
    });

    it('should refuse an oversized UTCTime too, on the length alone', () => {
        // The guard is type-independent, and this is what says so: UTCTime and
        // GeneralizedTime share it, rather than each testing the length again.
        const oversized = universal(23, new Uint8Array(65).fill(0x31));
        expect(codeOf(() => read(oversized))).toBe('PKI_ASN1_TIME_INVALID');
    });
});

describe('readTime — tags and options', () => {
    it('should refuse another universal type', () => {
        expect(codeOf(() => readTime(decodeAsn1(hex('02 01 00'))))).toBe('PKI_ASN1_UNEXPECTED_TAG');
    });

    it('should read an implicit tag only with timeType, and refuse an unknown timeType', () => {
        const implicit = decodeAsn1(tlv(2, false, 0, ascii('20240101000000Z')));
        expect(codeOf(() => readTime(implicit))).toBe('PKI_API_MISUSE');
        expect(readTime(implicit, { timeType: 'GeneralizedTime' }).type).toBe('GeneralizedTime');
        expect(codeOf(() => readTime(implicit, { timeType: 'Epoch' as unknown as 'UTCTime' }))).toBe('PKI_INVALID_OPTION');
    });

    it('should join a BER constructed UTCTime', () => {
        const segmented = tlv(0, true, 23, concat(universal(4, ascii('250101')), universal(4, ascii('000000Z'))));
        expect(read(segmented, BER).epochMilliseconds).toBe(Date.parse('2025-01-01T00:00:00Z'));
    });
});

describe('daysInMonth', () => {
    it('should follow the Gregorian leap-year rule', () => {
        expect(daysInMonth(2000, 2)).toBe(29);
        expect(daysInMonth(2024, 2)).toBe(29);
        expect(daysInMonth(2100, 2)).toBe(28);
        expect(daysInMonth(2025, 4)).toBe(30);
        expect(daysInMonth(2025, 1)).toBe(31);
    });
});
