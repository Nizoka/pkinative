/**
 * Recipe: the primitive encoders and readers, and the two SET forms.
 *
 * `asn1-and-oids.ts` builds a SEQUENCE; this one covers what is left — the
 * BOOLEAN, NULL, BIT STRING and OCTET STRING pairs, `encodeTlv` for a tag
 * no named encoder covers, the SET/SET OF distinction DER cares about, the
 * two taggings an ASN.1 module writes as `[0]`, and `decodeAsn1Sequence`
 * for values placed back to back with no container.
 */
import {
    decodeAsn1,
    decodeAsn1Sequence,
    encodeBitString,
    encodeBoolean,
    encodeEnumerated,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeNamedBits,
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

    // The same thing, said once: encodeExplicit wraps a complete TLV in a
    // constructed context tag, so [0] BOOLEAN FALSE is two headers deep.
    // encodeImplicit instead REPLACES the value's own tag, keeping its
    // constructed bit — which is why the two produce different bytes for the
    // same inner value, and why an ASN.1 module's `IMPLICIT` is never a
    // wrapper. Get these backwards and the structure decodes as a shape
    // nobody declared.
    const asExplicit = hex(encodeExplicit(0, encodeBoolean(false)));
    const asImplicit = hex(encodeImplicit(0, encodeBoolean(false)));

    // ENUMERATED is INTEGER's twin with tag 10: a CRL's reasonCode (RFC 5280
    // §5.3.1) is one, and writing it as an INTEGER is a structure a CRL
    // reader will refuse. 1 is keyCompromise.
    const reason = hex(encodeEnumerated(1));

    // A BIT STRING of NAMED bits is not a BIT STRING of bytes: X.690 §11.2.2
    // makes DER drop every trailing zero bit, so the encoder takes the bit
    // numbers and the length falls out. Bits 0 and 5 — digitalSignature and
    // keyCertSign in a KeyUsage — need six bits, so two of one octet's eight
    // are used and the padding count is 2.
    const named = hex(encodeNamedBits([0, 5]));

    return {
        stream: `${String(flag)} ${String(nothing)} ${String(small)} ${hex(octets)}`,
        bitString: `${hex(bits.bytes)}/${String(bits.unusedBits)}`,
        setOf,
        set,
        sorted: String(setOf !== set),
        explicit: hex(explicit),
        tagging: `${asExplicit} ${asImplicit} ${String(asExplicit !== asImplicit)}`,
        enumerated: reason,
        namedBits: named,
    };
}
