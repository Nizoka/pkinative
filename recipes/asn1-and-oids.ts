/**
 * Recipe: below the certificate — build a DER value with the encoders,
 * decode it and read typed fields back, re-encode a real certificate byte
 * for byte from its decoded tree, and work with OIDs: encode, decode,
 * validate, name. ENUMERATED and RELATIVE-OID (X.690 §8.4, §8.20) have
 * their own readers: an INTEGER reader refuses tag 10, and a RELATIVE-OID
 * has no first-two-arcs packing.
 */
import {
    decodeAsn1,
    decodeOid,
    encodeAsn1Node,
    encodeEnumerated,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOid,
    encodeRelativeOid,
    encodeSequence,
    encodeString,
    encodeTime,
    getOidName,
    isValidOid,
    OID_REGISTRY,
    readEnumerated,
    readInteger,
    readObjectIdentifier,
    readRelativeOid,
    readString,
    readTime,
} from 'pkinative';
import { fixture } from './_fixtures.ts';

export default function run(): Record<string, string> {
    // SEQUENCE { OBJECT IDENTIFIER, INTEGER, UTF8String, Time, ENUMERATED, RELATIVE-OID }, DER-encoded.
    // encodeTime picks UTCTime before 2050 and GeneralizedTime after, as RFC 5280 requires.
    // The ENUMERATED is CRLReason superseded(4); the RELATIVE-OID is X.690 §8.20.2's own example.
    const der = encodeSequence([
        encodeObjectIdentifier('2.5.29.17'),
        encodeInteger(65537n),
        encodeString('utf8', 'Zoë'),
        encodeTime(Date.UTC(2049, 11, 31, 23, 59, 59)),
        encodeEnumerated(4),
        encodeRelativeOid('8571.3.2'),
    ]);
    const [oidNode, integerNode, textNode, timeNode, enumeratedNode, relativeOidNode] = decodeAsn1(der).children;
    const oid = readObjectIdentifier(oidNode);
    const time = readTime(timeNode);

    // A decoded DER tree re-encodes to the exact input — what a signature covers.
    const certificate = fixture('isrg-root-x1');
    const again = encodeAsn1Node(decodeAsn1(certificate));
    const identical = again.length === certificate.length && again.every((b, i) => b === certificate[i]);

    const sha256WithRsa = '1.2.840.113549.1.1.11';
    // getOidName gives the name; OID_REGISTRY is the whole table behind it,
    // and each entry also names the standard that defines the OID.
    const entry = OID_REGISTRY.find((e) => e.oid === sha256WithRsa);

    return {
        oidStandard: entry?.standard ?? '?',
        oid: `${oid} ${getOidName(oid) ?? '?'}`,
        integer: String(readInteger(integerNode)),
        text: readString(textNode).value,
        time: `${time.type} ${time.text}`,
        enumerated: String(readEnumerated(enumeratedNode)),
        relativeOid: readRelativeOid(relativeOidNode),
        reencoded: String(identical),
        oidRoundTrip: String(decodeOid(encodeOid(sha256WithRsa)) === sha256WithRsa),
        oidName: getOidName(sha256WithRsa) ?? '?',
        validOid: `${String(isValidOid('1.2.3'))} ${String(isValidOid('3.1'))}`,
    };
}
