/**
 * Recipe: the primitive encoders and readers, and the two SET forms.
 *
 * `asn1-and-oids.ts` builds a SEQUENCE; this one covers what is left — the
 * BOOLEAN, NULL, BIT STRING and OCTET STRING pairs, `encodeTlv` for a tag
 * no named encoder covers, the SET/SET OF distinction DER cares about, and
 * `decodeAsn1Sequence` for values placed back to back with no container.
 */
import {
    decodeAsn1,
    decodeAsn1Sequence,
    encodeBitString,
    encodeBoolean,
    encodeInteger,
    encodeNull,
    encodeOctetString,
    encodeSet,
    encodeSetOf,
    encodeTlv,
    readBitString,
    readBoolean,
    readNull,
    readOctetString,
    readSmallInteger,
} from 'pkinative';

const hex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

export default function run(): Record<string, string> {
    // Four primitives, back to back with no container: decodeAsn1Sequence
    // reads a stream of values, where decodeAsn1 insists on exactly one.
    const stream = new Uint8Array([
        ...encodeBoolean(true),
        ...encodeNull(),
        ...encodeInteger(65537n),
        ...encodeOctetString(Uint8Array.of(0xde, 0xad, 0xbe, 0xef)),
    ]);
    const [booleanNode, nullNode, integerNode, octetNode] = decodeAsn1Sequence(stream);

    // DER encodes TRUE as 0xFF and rejects every other non-zero octet, so a
    // BOOLEAN round-trips through exactly one encoding.
    const flag = readBoolean(booleanNode);
    const nothing = readNull(nullNode);
    // readSmallInteger refuses what a JavaScript number cannot hold exactly;
    // readInteger returns a bigint and always succeeds.
    const small = readSmallInteger(integerNode);
    const octets = readOctetString(octetNode);

    // A BIT STRING carries its own count of padding bits: 0b1011 is four bits
    // in one octet, so four of that octet's eight bits are unused.
    const bits = readBitString(decodeAsn1(encodeBitString(Uint8Array.of(0b1011_0000), 4)));

    // SET OF is sorted by the encoded bytes (X.690 §11.6); SET keeps the order
    // the schema fixes. Feeding the same three components to both shows it.
    const components = [encodeInteger(3n), encodeInteger(1n), encodeInteger(2n)];
    const setOf = hex(encodeSetOf(components));
    const set = hex(encodeSet(components));

    // encodeTlv reaches a tag no named encoder covers: [0] EXPLICIT, the
    // context-specific constructed tag that wraps an optional field.
    const explicit = encodeTlv('context', 0, true, encodeBoolean(false));

    return {
        stream: `${String(flag)} ${String(nothing)} ${String(small)} ${hex(octets)}`,
        bitString: `${hex(bits.bytes)}/${String(bits.unusedBits)}`,
        setOf,
        set,
        sorted: String(setOf !== set),
        explicit: hex(explicit),
    };
}
