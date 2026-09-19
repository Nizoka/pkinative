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
import { encodeUtf8 } from '../core/text.js';
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

/** RFC 4514 §2.4 hexpairs: the UTF-8 octets of one character, each as `\hh`. */
function hexpairs(ch: string): string {
    let out = '';
    for (const octet of encodeUtf8(ch) ?? []) out += `\\${octet.toString(16).padStart(2, '0')}`;
    return out;
}

function escapeValue(text: string): string {
    let out = '';
    for (let i = 0; i < text.length; i++) {
        const ch = text.charAt(i);
        const code = text.charCodeAt(i);
        if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || BIDI_CONTROLS.has(code)) out += hexpairs(ch);
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
    for (let i = name.rdns.length - 1; i >= 0; i--) {
        const rdn = name.rdns[i] ?? [];
        parts.push(rdn.map(formatAttribute).join('+'));
    }
    return parts.join(',');
}
