/**
 * Synthetic certificates for the X.509 suites, built TLV by TLV. It NEVER
 * imports src/: a parser tested only against its own encoder proves nothing.
 * Every part of a certificate can be replaced to build the hostile variant a
 * test needs; the defaults form a well-formed, diagnostic-free v3 certificate.
 */

import { ascii, concat, sequence, tlv, universal } from './raw-der-builder.js';

/** An OBJECT IDENTIFIER TLV from its dotted form, encoded independently of the engine. */
export function oid(dotted: string): Uint8Array {
    const arcs = dotted.split('.').map((arc) => BigInt(arc));
    const out: number[] = [];
    for (const arc of [(arcs[0] ?? 0n) * 40n + (arcs[1] ?? 0n), ...arcs.slice(2)]) {
        const digits = [Number(arc & 0x7fn)];
        for (let rest = arc >> 7n; rest > 0n; rest >>= 7n) digits.unshift(Number(rest & 0x7fn) | 0x80);
        out.push(...digits);
    }
    return universal(6, out);
}

export const integer = (content: ArrayLike<number>): Uint8Array => universal(2, content);
export const boolean = (value: boolean): Uint8Array => universal(1, [value ? 0xff : 0x00]);
export const nullValue = (): Uint8Array => universal(5, []);
export const bitString = (bytes: ArrayLike<number>, unusedBits = 0): Uint8Array => universal(3, [unusedBits, ...Array.from(bytes)]);
export const octetString = (bytes: ArrayLike<number>): Uint8Array => universal(4, bytes);
export const utf8 = (text: string): Uint8Array => universal(12, new TextEncoder().encode(text));
export const printable = (text: string): Uint8Array => universal(19, ascii(text));
export const ia5 = (text: string): Uint8Array => universal(22, ascii(text));
export const utcTime = (text: string): Uint8Array => universal(23, ascii(text));
export const generalizedTime = (text: string): Uint8Array => universal(24, ascii(text));
export const set = (...children: ReadonlyArray<ArrayLike<number>>): Uint8Array => tlv(0, true, 17, concat(...children));

/** A context-specific TLV with raw content. */
export const context = (tagNumber: number, constructed: boolean, content: ArrayLike<number>): Uint8Array => tlv(2, constructed, tagNumber, content);

/** An explicit context tag around already-encoded values. */
export const explicit = (tagNumber: number, ...children: ReadonlyArray<ArrayLike<number>>): Uint8Array => tlv(2, true, tagNumber, concat(...children));

export const algorithm = (dotted: string, parameters?: Uint8Array): Uint8Array =>
    parameters === undefined ? sequence(oid(dotted)) : sequence(oid(dotted), parameters);

/** A Name from RDNs, each a list of `[type OID, encoded value]`. */
export function name(...rdns: ReadonlyArray<ReadonlyArray<readonly [string, Uint8Array]>>): Uint8Array {
    return sequence(...rdns.map((rdn) => set(...rdn.map(([type, value]) => sequence(oid(type), value)))));
}

/** An Extension; `critical` undefined omits the flag, a boolean encodes it (FALSE included). */
export function extension(dotted: string, value: Uint8Array, critical?: boolean): Uint8Array {
    return critical === undefined
        ? sequence(oid(dotted), octetString(value))
        : sequence(oid(dotted), boolean(critical), octetString(value));
}

export const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
export const P256_POINT: readonly number[] = [0x04, ...Array.from({ length: 64 }, (_, i) => i + 1)];

export const ecKey = (point: ArrayLike<number> = P256_POINT, curve = '1.2.840.10045.3.1.7'): Uint8Array =>
    sequence(algorithm('1.2.840.10045.2.1', oid(curve)), bitString(point));

export const rsaKey = (modulus: ArrayLike<number>, exponent: ArrayLike<number> = [0x01, 0x00, 0x01]): Uint8Array =>
    sequence(algorithm('1.2.840.113549.1.1.1', nullValue()), bitString(sequence(integer(modulus), integer(exponent))));

export const BASIC_CONSTRAINTS_CA = extension('2.5.29.19', sequence(boolean(true)), true);

export interface TbsParts {
    /** `null` omits the field (a v1 certificate). */
    readonly version?: Uint8Array | null;
    readonly serialNumber?: Uint8Array;
    readonly signature?: Uint8Array;
    readonly issuer?: Uint8Array;
    readonly validity?: Uint8Array;
    readonly subject?: Uint8Array;
    readonly subjectPublicKeyInfo?: Uint8Array;
    /** Everything after the public key: unique identifiers and extensions. */
    readonly trailing?: readonly Uint8Array[];
}

export function tbsCertificate(parts: TbsParts = {}): Uint8Array {
    const fields: Uint8Array[] = [];
    const version = parts.version === undefined ? explicit(0, integer([2])) : parts.version;
    if (version !== null) fields.push(version);
    fields.push(
        parts.serialNumber ?? integer([0x01, 0x23]),
        parts.signature ?? algorithm(ECDSA_SHA256),
        parts.issuer ?? name([['2.5.4.6', printable('US')]], [['2.5.4.10', utf8('pkinative test')]], [['2.5.4.3', utf8('Test Root')]]),
        parts.validity ?? sequence(utcTime('250101000000Z'), utcTime('350101000000Z')),
        parts.subject ?? name([['2.5.4.3', utf8('leaf.example')]]),
        parts.subjectPublicKeyInfo ?? ecKey(),
        ...(parts.trailing ?? [explicit(3, sequence(BASIC_CONSTRAINTS_CA))]),
    );
    return sequence(...fields);
}

export interface CertificateParts extends TbsParts {
    readonly tbs?: Uint8Array;
    readonly signatureAlgorithm?: Uint8Array;
    readonly signatureValue?: Uint8Array;
}

export function certificate(parts: CertificateParts = {}): Uint8Array {
    return sequence(
        parts.tbs ?? tbsCertificate(parts),
        parts.signatureAlgorithm ?? algorithm(ECDSA_SHA256),
        parts.signatureValue ?? bitString([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
    );
}
