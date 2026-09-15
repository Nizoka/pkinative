/**
 * An engine-independent TLV builder for tests. It NEVER imports src/: a
 * decoder tested only against its own encoder proves nothing, so fixtures —
 * valid and hostile — are assembled here from first principles, including
 * the forms DER forbids (long lengths, indefinite lengths, raw identifiers).
 */

/** Parse `"30 03 02 01 05"` (whitespace ignored) into bytes. */
export function hex(text: string): Uint8Array {
    const clean = text.replace(/\s+/g, '');
    if (clean.length % 2 !== 0 || /[^0-9a-f]/i.test(clean)) throw new Error(`hex: malformed "${text}"`);
    return Uint8Array.from({ length: clean.length / 2 }, (_, i) => parseInt(clean.slice(i * 2, i * 2 + 2), 16));
}

/** The octets of an ASCII string. */
export function ascii(text: string): number[] {
    return [...text].map((c) => c.charCodeAt(0));
}

/** Concatenate octet sequences into one array. */
export function concat(...parts: ReadonlyArray<ArrayLike<number>>): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) {
        out.set(Array.from(p), at);
        at += p.length;
    }
    return out;
}

/** Identifier octets for a class (0 universal, 1 application, 2 context, 3 private), form and tag number. */
export function identifierOctets(cls: 0 | 1 | 2 | 3, constructed: boolean, tagNumber: number): number[] {
    const leading = (cls << 6) | (constructed ? 0x20 : 0);
    if (tagNumber < 31) return [leading | tagNumber];
    const digits: number[] = [];
    let rest = tagNumber;
    do {
        digits.unshift(rest % 128);
        rest = Math.floor(rest / 128);
    } while (rest > 0);
    return [leading | 0x1f, ...digits.map((d, i) => (i < digits.length - 1 ? d | 0x80 : d))];
}

/** Length octets: minimal by default, or exactly `octets` long-form octets (non-minimal when that is more than needed). */
export function lengthOctets(length: number, octets?: number): number[] {
    if (octets === undefined) {
        if (length < 0x80) return [length];
        const body: number[] = [];
        let rest = length;
        while (rest > 0) {
            body.unshift(rest % 256);
            rest = Math.floor(rest / 256);
        }
        return [0x80 | body.length, ...body];
    }
    const body: number[] = [];
    let rest = length;
    for (let i = 0; i < octets; i++) {
        body.unshift(rest % 256);
        rest = Math.floor(rest / 256);
    }
    return [0x80 | octets, ...body];
}

export interface TlvOptions {
    /** Force the long length form with this many octets. */
    readonly lengthOctets?: number;
    /** Use the indefinite length form and append an end-of-contents marker. */
    readonly indefinite?: boolean;
}

/** One TLV with any class, form, tag and length encoding. */
export function tlv(cls: 0 | 1 | 2 | 3, constructed: boolean, tagNumber: number, content: ArrayLike<number>, options: TlvOptions = {}): Uint8Array {
    const id = identifierOctets(cls, constructed, tagNumber);
    if (options.indefinite) return concat(id, [0x80], content, [0x00, 0x00]);
    return concat(id, lengthOctets(content.length, options.lengthOctets), content);
}

/** A universal TLV. */
export function universal(tagNumber: number, content: ArrayLike<number>, constructed = false): Uint8Array {
    return tlv(0, constructed, tagNumber, content);
}

/** A DER SEQUENCE of already-encoded children. */
export function sequence(...children: ReadonlyArray<ArrayLike<number>>): Uint8Array {
    return universal(16, concat(...children), true);
}

/** `depth` DER SEQUENCEs nested around a NULL. */
export function derNest(depth: number): Uint8Array {
    let inner: Uint8Array = Uint8Array.of(0x05, 0x00);
    for (let i = 0; i < depth; i++) inner = sequence(inner);
    return inner;
}

/** `depth` BER indefinite-length SEQUENCEs nested around a NULL, built in linear time. */
export function berNest(depth: number): Uint8Array {
    const out = new Uint8Array(depth * 4 + 2);
    for (let i = 0; i < depth; i++) {
        out[i * 2] = 0x30;
        out[i * 2 + 1] = 0x80;
    }
    out[depth * 2] = 0x05;
    out[depth * 2 + 1] = 0x00;
    return out; // the trailing depth * 2 octets are already zero: the end-of-contents markers
}
