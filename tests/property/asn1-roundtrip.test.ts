import { describe, it, expect } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { encodeAsn1Node, encodeEnumerated, encodeInteger, encodeObjectIdentifier, encodeRelativeOid, encodeString, encodeTime } from '../../src/asn1/asn1-encode.js';
import { readObjectIdentifier, readRelativeOid } from '../../src/asn1/asn1-oid.js';
import { readEnumerated, readInteger, readString } from '../../src/asn1/asn1-read.js';
import { readTime } from '../../src/asn1/asn1-time.js';
import type { Asn1Node, Asn1StringType } from '../../src/types/asn1-types.js';
import { createPrng, type Prng } from '../helpers/prng.js';
import { concat, tlv, universal } from '../helpers/raw-der-builder.js';

interface Shape {
    readonly cls: number;
    readonly tag: number;
    readonly constructed: boolean;
    readonly children: readonly Shape[];
}

/** A random DER tree, built by the independent builder, with its expected shape. */
function randomTree(rng: Prng, depth: number): { readonly bytes: Uint8Array; readonly shape: Shape } {
    const constructed = depth < 5 && rng.int(3) === 0;
    if (constructed) {
        const universalSequence = rng.int(3) === 0;
        const cls = universalSequence ? 0 : 1 + rng.int(3);
        const tag = universalSequence ? rng.pick([16, 17]) : rng.int(3) === 0 ? 31 + rng.int(5000) : rng.int(31);
        const kids = Array.from({ length: rng.int(5) }, () => randomTree(rng, depth + 1));
        return {
            bytes: tlv(cls as 0 | 1 | 2 | 3, true, tag, concat(...kids.map((k) => k.bytes))),
            shape: { cls, tag, constructed: true, children: kids.map((k) => k.shape) },
        };
    }
    const kind = rng.int(4);
    if (kind === 0) {
        let content = Array.from(rng.bytes(1 + rng.int(8)));
        while (content.length > 1 && ((content[0] === 0 && (content[1] ?? 0) < 0x80) || (content[0] === 0xff && (content[1] ?? 0) >= 0x80))) content = content.slice(1);
        return { bytes: universal(2, content), shape: { cls: 0, tag: 2, constructed: false, children: [] } };
    }
    if (kind === 1) {
        const length = rng.int(4) === 0 ? 128 + rng.int(400) : rng.int(40);
        return { bytes: universal(4, rng.bytes(length)), shape: { cls: 0, tag: 4, constructed: false, children: [] } };
    }
    if (kind === 2) return { bytes: universal(5, []), shape: { cls: 0, tag: 5, constructed: false, children: [] } };
    const cls = 1 + rng.int(3);
    const tag = rng.int(2) === 0 ? rng.int(31) : 31 + rng.int(100_000);
    return { bytes: tlv(cls as 0 | 1 | 2 | 3, false, tag, rng.bytes(rng.int(20))), shape: { cls, tag, constructed: false, children: [] } };
}

const CLASS = ['universal', 'application', 'context', 'private'] as const;

function expectShape(node: Asn1Node, shape: Shape): void {
    expect(node.tagClass).toBe(CLASS[shape.cls]);
    expect(node.tagNumber).toBe(shape.tag);
    expect(node.constructed).toBe(shape.constructed);
    expect(node.children).toHaveLength(shape.children.length);
    node.children.forEach((child, i) => expectShape(child, shape.children[i] as Shape));
}

describe('property — DER trees', () => {
    it('should decode 2 000 random trees to their shape and re-encode them byte for byte', () => {
        const rng = createPrng(0x5eed_1001);
        for (let i = 0; i < 2000; i++) {
            const { bytes, shape } = randomTree(rng, 0);
            const node = decodeAsn1(bytes);
            expectShape(node, shape);
            expect([...encodeAsn1Node(node)]).toEqual([...bytes]);
        }
    });
});

describe('property — values', () => {
    it('should round-trip random INTEGERs of up to 64 octets', () => {
        const rng = createPrng(0x5eed_1002);
        for (let i = 0; i < 2000; i++) {
            const octets = 1 + rng.int(64);
            let value = BigInt(`0x${Buffer.from(rng.bytes(octets)).toString('hex')}`);
            if (rng.int(2) === 0) value = -value;
            expect(readInteger(decodeAsn1(encodeInteger(value)))).toBe(value);
        }
    });

    it('should round-trip random OBJECT IDENTIFIERs, arcs beyond 2^53 included', () => {
        const rng = createPrng(0x5eed_1003);
        const arc = (): string => (rng.int(4) === 0 ? BigInt(`0x${Buffer.from(rng.bytes(1 + rng.int(12))).toString('hex')}`).toString() : String(rng.int(100_000)));
        for (let i = 0; i < 2000; i++) {
            const first = rng.int(3);
            const second = first === 2 ? arc() : String(rng.int(40));
            const oid = [String(first), second, ...Array.from({ length: rng.int(8) }, arc)].join('.');
            expect(readObjectIdentifier(decodeAsn1(encodeObjectIdentifier(oid)))).toBe(oid);
        }
    });

    it('should round-trip random ENUMERATEDs of up to 64 octets, as INTEGERs under tag 10', () => {
        const rng = createPrng(0x5eed_1006);
        for (let i = 0; i < 2000; i++) {
            const octets = 1 + rng.int(64);
            let value = BigInt(`0x${Buffer.from(rng.bytes(octets)).toString('hex')}`);
            if (rng.int(2) === 0) value = -value;
            const encoded = encodeEnumerated(value);
            expect(encoded[0]).toBe(10);
            expect(readEnumerated(decodeAsn1(encoded))).toBe(value);
            // The same content octets as the INTEGER: only the tag differs (X.690 §8.4).
            expect([...encoded.subarray(1)]).toEqual([...encodeInteger(value).subarray(1)]);
        }
    });

    it('should round-trip random RELATIVE-OIDs of one to eight arcs, arcs beyond 2^53 included', () => {
        const rng = createPrng(0x5eed_1007);
        const arc = (): string => (rng.int(4) === 0 ? BigInt(`0x${Buffer.from(rng.bytes(1 + rng.int(12))).toString('hex')}`).toString() : String(rng.int(100_000)));
        for (let i = 0; i < 2000; i++) {
            const oid = Array.from({ length: 1 + rng.int(8) }, arc).join('.');
            const encoded = encodeRelativeOid(oid);
            expect(encoded[0]).toBe(13);
            expect(readRelativeOid(decodeAsn1(encoded))).toBe(oid);
        }
    });

    it('should round-trip random instants across the years 0000 to 9999 in every time mode', () => {
        const rng = createPrng(0x5eed_1004);
        const min = Date.parse('0000-01-01T00:00:00Z');
        const max = Date.parse('9999-12-31T23:59:59Z');
        for (let i = 0; i < 2000; i++) {
            const seconds = Math.floor(min / 1000 + rng.next() * ((max - min) / 1000));
            const whole = seconds * 1000;
            expect(readTime(decodeAsn1(encodeTime(whole))).epochMilliseconds).toBe(whole);
            const fractional = whole + rng.int(1000);
            expect(readTime(decodeAsn1(encodeTime(fractional, 'GeneralizedTime'))).epochMilliseconds).toBe(fractional);
        }
    });

    it('should round-trip random text in every string type', () => {
        const rng = createPrng(0x5eed_1005);
        const alphabets: Readonly<Record<Asn1StringType, () => string>> = {
            utf8: () => String.fromCodePoint(rng.pick([rng.int(0xd800), 0xe000 + rng.int(0x2000), 0x10000 + rng.int(0xfffff)])),
            printable: () => rng.pick([..."ABCXYZabcxyz0189 '()+,-./:=?"]),
            ia5: () => String.fromCharCode(rng.int(128)),
            visible: () => String.fromCharCode(0x20 + rng.int(95)),
            numeric: () => rng.pick([...'0123456789 ']),
            teletex: () => String.fromCharCode(rng.int(256)),
            bmp: () => String.fromCharCode(rng.pick([rng.int(0xd800), 0xe000 + rng.int(0x2000)])),
            universal: () => String.fromCodePoint(rng.pick([rng.int(0xd800), 0x10000 + rng.int(0xfffff)])),
        };
        for (let i = 0; i < 400; i++) {
            for (const [type, char] of Object.entries(alphabets) as Array<[Asn1StringType, () => string]>) {
                const text = Array.from({ length: rng.int(30) }, char).join('');
                expect(readString(decodeAsn1(encodeString(type, text)), { onDiagnostic: () => undefined }).value).toBe(text);
            }
        }
    });
});
