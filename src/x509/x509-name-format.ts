/**
 * pkinative — RFC 4514 string form of a distinguished name
 * ========================================================
 * RDNs in reverse encoded order, joined by `,`; the attributes of one RDN
 * joined by `+`. Types with an RFC 4514 §3 short name print it; every other
 * type prints its dotted OID, and its value as `#` and the hex of its
 * encoding (§2.4), as does a value that is not a character string.
 *
 * Beyond the escapes §2.4 requires, C0 and C1 control characters, DEL and
 * the bidirectional controls are escaped as the `\hh` pairs of their UTF-8
 * octets, so a crafted name can neither drive the terminal that displays it
 * nor reorder what it shows.
 *
 * @module x509/x509-name-format
 */

import { toHex } from '../core/bytes.js';
import { PkiError } from '../types/pki-errors.js';
import type { AttributeTypeAndValue, DistinguishedName } from '../types/x509-types.js';

const SHORT_NAMES: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    ['2.5.4.3', 'CN'],
    ['2.5.4.7', 'L'],
    ['2.5.4.8', 'ST'],
    ['2.5.4.10', 'O'],
    ['2.5.4.11', 'OU'],
    ['2.5.4.6', 'C'],
    ['2.5.4.9', 'STREET'],
    ['0.9.2342.19200300.100.1.25', 'DC'],
    ['0.9.2342.19200300.100.1.1', 'UID'],
]);

const SPECIAL = '"+,;<>\\';

/** Bidirectional controls: they reorder what a terminal or a UI shows (CVE-2021-42574). */
const BIDI_CONTROLS: ReadonlySet<number> = /*#__PURE__*/ new Set([0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);

const hex2 = (octet: number): string => `\\${octet.toString(16).padStart(2, '0')}`;

/**
 * RFC 4514 §2.4 hexpairs: the UTF-8 octets of one BMP code point, each as
 * `\hh`. Taking the code point rather than the character keeps `encodeUtf8`'s
 * lone-surrogate `null` out of a path whose caller only ever passes one of
 * three known control classes.
 */
function hexpairs(code: number): string {
    if (code < 0x80) return hex2(code);
    if (code < 0x800) return hex2(0xc0 | (code >> 6)) + hex2(0x80 | (code & 0x3f));
    return hex2(0xe0 | (code >> 12)) + hex2(0x80 | ((code >> 6) & 0x3f)) + hex2(0x80 | (code & 0x3f));
}

function escapeValue(text: string): string {
    let out = '';
    for (let i = 0; i < text.length; i++) {
        const ch = text.charAt(i);
        const code = text.charCodeAt(i);
        if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || BIDI_CONTROLS.has(code)) out += hexpairs(code);
        else if (SPECIAL.includes(ch)) out += `\\${ch}`;
        else if ((i === 0 && (ch === ' ' || ch === '#')) || (i === text.length - 1 && ch === ' ')) out += `\\${ch}`;
        else out += ch;
    }
    return out;
}

function formatAttribute(attribute: AttributeTypeAndValue): string {
    const short = SHORT_NAMES.get(attribute.type);
    if (short === undefined || attribute.value === undefined) return `${short ?? attribute.type}=#${toHex(attribute.valueDer)}`;
    return `${short}=${escapeValue(attribute.value.value)}`;
}

/**
 * Format a distinguished name as an RFC 4514 string, e.g. `CN=example.com,O=Example,C=US`.
 *
 * @param name A name from a parsed certificate (`certificate.subject`, `certificate.issuer`).
 * @returns The RFC 4514 string; an empty name gives the empty string.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the argument is not a DistinguishedName.
 */
export function formatDistinguishedName(name: DistinguishedName): string {
    if (typeof name !== 'object' || name === null || !Array.isArray(name.rdns)) {
        throw new PkiError('PKI_INVALID_INPUT',
            `pkinative: formatDistinguishedName expects the subject or issuer of a parsed certificate, got ${name === null ? 'null' : typeof name}`);
    }
    const parts: string[] = [];
    for (const rdn of name.rdns) {
        // The `?? []` this replaces printed ",," for a sparse or malformed
        // rdns array instead of saying what was wrong, and a bare for…of
        // would leak a TypeError, which the security rules call a bug.
        if (!Array.isArray(rdn)) {
            throw new PkiError('PKI_INVALID_INPUT',
                'pkinative: formatDistinguishedName expects the subject or issuer of a parsed certificate, whose rdns are arrays of attributes');
        }
        parts.push(rdn.map(formatAttribute).join('+'));
    }
    // RFC 4514 §2.1: the RDNs print in the reverse of their encoded order.
    parts.reverse();
    return parts.join(',');
}
