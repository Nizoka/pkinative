/**
 * pkinative — independent DER walker
 * ==================================
 * A deliberately small TLV reader for the conformance gate. It NEVER imports
 * src/: the gate checks the engine's structure boundaries against a second,
 * separately written reading of the same bytes, so a shared bug cannot make
 * both agree (zipnative's validate-zip doctrine). Definite lengths only —
 * certificates are DER.
 *
 * @module scripts/lib/raw-der
 */

export interface RawTlv {
    /** 0 universal, 1 application, 2 context, 3 private. */
    readonly tagClass: number;
    readonly constructed: boolean;
    readonly tagNumber: number;
    readonly offset: number;
    readonly headerLength: number;
    readonly length: number;
    /** Offset just past the value. */
    readonly end: number;
}

/** Read the TLV at `offset`; throws a plain Error on anything it cannot read. */
export function readTlv(bytes: Uint8Array, offset: number): RawTlv {
    let pos = offset;
    const first = bytes[pos++];
    if (first === undefined) throw new Error(`raw-der: no identifier octet at ${offset}`);
    let tagNumber = first & 0x1f;
    if (tagNumber === 0x1f) {
        tagNumber = 0;
        for (;;) {
            const b = bytes[pos++];
            if (b === undefined) throw new Error(`raw-der: truncated tag at ${offset}`);
            tagNumber = tagNumber * 128 + (b & 0x7f);
            if ((b & 0x80) === 0) break;
        }
    }
    const lengthOctet = bytes[pos++];
    if (lengthOctet === undefined) throw new Error(`raw-der: no length at ${offset}`);
    let length = lengthOctet;
    if (lengthOctet & 0x80) {
        const count = lengthOctet & 0x7f;
        if (count === 0 || count > 6) throw new Error(`raw-der: unsupported length form at ${offset}`);
        length = 0;
        for (let i = 0; i < count; i++) {
            const b = bytes[pos++];
            if (b === undefined) throw new Error(`raw-der: truncated length at ${offset}`);
            length = length * 256 + b;
        }
    }
    const end = pos + length;
    if (end > bytes.length) throw new Error(`raw-der: value at ${offset} runs past the input`);
    return { tagClass: first >> 6, constructed: (first & 0x20) !== 0, tagNumber, offset, headerLength: pos - offset, length, end };
}

/** The TLVs directly inside a constructed value. */
export function childrenOf(bytes: Uint8Array, parent: RawTlv): RawTlv[] {
    const out: RawTlv[] = [];
    for (let pos = parent.offset + parent.headerLength; pos < parent.end;) {
        const child = readTlv(bytes, pos);
        out.push(child);
        pos = child.end;
    }
    return out;
}

export interface CertificateBounds {
    readonly tbs: RawTlv;
    readonly signatureAlgorithm: RawTlv;
    readonly signatureValue: RawTlv;
}

/** The three top-level parts of a Certificate, located without the engine. */
export function certificateBounds(der: Uint8Array): CertificateBounds {
    const outer = readTlv(der, 0);
    const parts = childrenOf(der, outer);
    const [tbs, signatureAlgorithm, signatureValue] = parts;
    if (parts.length !== 3 || tbs === undefined || signatureAlgorithm === undefined || signatureValue === undefined) {
        throw new Error(`raw-der: a Certificate holds 3 values, found ${parts.length}`);
    }
    return { tbs, signatureAlgorithm, signatureValue };
}
