/**
 * pkinative — ASN.1 time types
 * ============================
 * UTCTime and GeneralizedTime, decoded to an exact instant.
 *
 * Under DER the only accepted forms are the restricted ones of X.690
 * §11.7–11.8: `YYMMDDHHMMSSZ` and `YYYYMMDDHHMMSS[.f]Z` (no trailing zero in
 * the fraction). Under BER, seconds may be omitted, a comma may mark the
 * fraction, the fraction may keep trailing zeros, and a `±hhmm` offset may
 * replace `Z`; a local time without a zone is refused in every mode, because
 * it names no instant. Out-of-range fields — month 13, 31 April, 29 February
 * of a common year, hour 24, second 60 — are refused, never rolled over.
 *
 * Dates are built with `setUTCFullYear`, because `Date.UTC` maps the years 0
 * to 99 to 1900–1999.
 *
 * @module asn1/asn1-time
 */

import type { Asn1Node, PkiTime, ReadTimeOptions, TimeType } from '../types/asn1-types.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import { createAsn1Context, noteBer, type Asn1Context } from './asn1-context.js';
import { assertNode, stringContent } from './asn1-read.js';
import { TAG_GENERALIZED_TIME, TAG_OCTET_STRING, TAG_UTC_TIME, tagLabel } from './asn1-tags.js';

/** Longer than any well-formed time with a millisecond-scale fraction: refuse before decoding text. */
const MAX_TIME_OCTETS = 64;

// The zone is matched but not captured: `zoneOf` reads it back off the end of
// the text, which is always a string, where a capture group is
// `string | undefined` and needs a `?? 'Z'` no match can reach.
const UTC_TIME = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:Z|[+-]\d{4})$/;
const GENERALIZED_TIME = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:([.,])(\d+))?(?:Z|[+-]\d{4})$/;

/** `Z`, or the `±hhmm` offset the grammar puts last. */
function zoneOf(text: string): string {
    return text.endsWith('Z') ? 'Z' : text.slice(-5);
}

function isLeapYear(year: number): boolean {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

/** Days in a month of the proleptic Gregorian calendar. */
export function daysInMonth(year: number, month: number): number {
    return month === 2 ? (isLeapYear(year) ? 29 : 28) : month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

interface Fields {
    readonly year: number;
    readonly month: number;
    readonly day: number;
    readonly hour: number;
    readonly minute: number;
    readonly second: number;
    readonly millisecond: number;
    readonly zone: string;
}

function invalidTime(node: Asn1Node, type: TimeType, text: string, why: string): PkiEncodingError {
    return new PkiEncodingError('PKI_ASN1_TIME_INVALID',
        `pkinative: the ${type} "${text}" at offset ${node.offset} ${why} — RFC 5280 and X.690 leave no lenient interpretation`, node.offset);
}

/** The instant the fields name, or throws for an impossible field. */
function toEpoch(node: Asn1Node, type: TimeType, text: string, f: Fields): number {
    if (f.month < 1 || f.month > 12) throw invalidTime(node, type, text, `names month ${f.month}`);
    if (f.day < 1 || f.day > daysInMonth(f.year, f.month)) throw invalidTime(node, type, text, `names day ${f.day} of a month that has ${daysInMonth(f.year, f.month)}`);
    if (f.hour > 23) throw invalidTime(node, type, text, `names hour ${f.hour}`);
    if (f.minute > 59) throw invalidTime(node, type, text, `names minute ${f.minute}`);
    if (f.second > 59) throw invalidTime(node, type, text, `names second ${f.second}`);
    let offsetMinutes = 0;
    if (f.zone !== 'Z') {
        const hours = Number(f.zone.slice(1, 3));
        const minutes = Number(f.zone.slice(3, 5));
        if (hours > 23 || minutes > 59) throw invalidTime(node, type, text, `has the impossible offset ${f.zone}`);
        offsetMinutes = (f.zone[0] === '-' ? -1 : 1) * (hours * 60 + minutes);
    }
    const date = new Date(0);
    date.setUTCFullYear(f.year, f.month - 1, f.day);
    date.setUTCHours(f.hour, f.minute, f.second, f.millisecond);
    return date.getTime() - offsetMinutes * 60_000;
}

/** @internal */
export function _readTime(node: Asn1Node, ctx: Asn1Context, implicitType: TimeType | undefined): PkiTime {
    let type: TimeType;
    if (node.tagClass === 'universal') {
        if (node.tagNumber === TAG_UTC_TIME) type = 'UTCTime';
        else if (node.tagNumber === TAG_GENERALIZED_TIME) type = 'GeneralizedTime';
        else {
            throw new PkiEncodingError('PKI_ASN1_UNEXPECTED_TAG',
                `pkinative: expected UTCTime or GeneralizedTime at offset ${node.offset}, found ${tagLabel(node.tagClass, node.tagNumber)}`, node.offset);
        }
    } else if (implicitType === undefined) {
        throw new PkiError('PKI_API_MISUSE',
            `pkinative: the value at offset ${node.offset} carries the implicit tag ${tagLabel(node.tagClass, node.tagNumber)}; pass timeType to say which time type it is`);
    } else {
        type = implicitType;
    }

    const raw = stringContent(node, ctx, TAG_OCTET_STRING, type);
    // Refuse the oversize value here rather than threading a text/shown pair
    // through a ternary in each branch below: no well-formed time of either
    // type comes close to this, so the length alone settles it.
    if (raw.length > MAX_TIME_OCTETS) {
        throw invalidTime(node, type, `${raw.length} octets`,
            `is longer than the ${MAX_TIME_OCTETS} octets any well-formed ${type} needs`);
    }
    const text = String.fromCharCode(...raw);

    if (type === 'UTCTime') {
        const m = UTC_TIME.exec(text);
        if (m === null) throw invalidTime(node, type, text, 'is not YYMMDDHHMM[SS](Z|±hhmm)');
        const [, yy, mo, dd, hh, mi, ss] = m;
        const zone = zoneOf(text);
        if (ss === undefined || zone !== 'Z') {
            if (ctx.rules === 'der') throw invalidTime(node, type, text, 'omits the seconds or the Z; DER requires YYMMDDHHMMSSZ (X.690 §11.8)');
            noteBer(ctx, 'UTCTime without seconds or with an offset', node.offset);
        }
        const twoDigit = Number(yy);
        const epochMilliseconds = toEpoch(node, type, text, {
            year: twoDigit >= 50 ? 1900 + twoDigit : 2000 + twoDigit,
            month: Number(mo), day: Number(dd), hour: Number(hh), minute: Number(mi), second: Number(ss ?? '0'),
            millisecond: 0, zone,
        });
        return Object.freeze({ type, epochMilliseconds, text });
    }

    const m = GENERALIZED_TIME.exec(text);
    if (m === null) throw invalidTime(node, type, text, 'is not YYYYMMDDHHMM[SS[.f]](Z|±hhmm)');
    const [, yyyy, mo, dd, hh, mi, ss, separator, fraction] = m;
    const zone = zoneOf(text);
    if (fraction !== undefined && ss === undefined) throw invalidTime(node, type, text, 'has a fraction without seconds');
    const nonCanonical = ss === undefined || zone !== 'Z' || separator === ',' || (fraction !== undefined && fraction.endsWith('0'));
    if (nonCanonical) {
        if (ctx.rules === 'der') {
            throw invalidTime(node, type, text, 'is not in the DER form YYYYMMDDHHMMSS[.f]Z with no trailing zero in the fraction (X.690 §11.7)');
        }
        noteBer(ctx, 'non-canonical GeneralizedTime', node.offset);
    }
    const epochMilliseconds = toEpoch(node, type, text, {
        year: Number(yyyy), month: Number(mo), day: Number(dd), hour: Number(hh), minute: Number(mi), second: Number(ss ?? '0'),
        millisecond: fraction === undefined ? 0 : Number(`${fraction}000`.slice(0, 3)), zone,
    });
    return Object.freeze({ type, epochMilliseconds, text });
}

/**
 * Read a UTCTime or a GeneralizedTime.
 *
 * @param node    A time node, or an implicitly tagged one together with `timeType`.
 * @param options Encoding rules (DER requires the restricted forms), diagnostics, and the type of an implicit tag.
 * @returns The type, the instant in epoch milliseconds and the encoded text. UTCTime years 50–99 are 1950–1999, 00–49 are 2000–2049.
 * @throws {PkiEncodingError} `PKI_ASN1_TIME_INVALID` for a malformed or impossible time; `PKI_ASN1_UNEXPECTED_TAG` for another type.
 * @throws {PkiError} `PKI_API_MISUSE` for an implicit tag without `timeType`; `PKI_INVALID_OPTION` for an unknown `timeType`.
 */
export function readTime(node: Asn1Node, options?: ReadTimeOptions): PkiTime {
    const checked = assertNode(node, 'readTime');
    const ctx = createAsn1Context(options);
    const implicitType = options?.timeType;
    if (implicitType !== undefined && implicitType !== 'UTCTime' && implicitType !== 'GeneralizedTime') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: timeType must be 'UTCTime' or 'GeneralizedTime', got ${String(implicitType)}`);
    }
    return _readTime(checked, ctx, implicitType);
}
