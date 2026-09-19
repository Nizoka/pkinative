/**
 * Recipe: below the certificate — build a DER value with the encoders,
 * decode it and read typed fields back, re-encode a real certificate byte
 * for byte from its decoded tree, and work with OIDs: encode, decode,
 * validate, name.
 */
import {
    decodeAsn1,
    decodeOid,
    encodeAsn1Node,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOid,
    encodeSequence,
    encodeString,
    encodeTime,
    getOidName,
    isValidOid,
    readInteger,
    readObjectIdentifier,
    readString,
    readTime,
} from 'pkinative';
import { fixture } from './_fixtures.ts';

export default function run(): Record<string, string> {
    // SEQUENCE { OBJECT IDENTIFIER, INTEGER, UTF8String, Time }, DER-encoded.
    // encodeTime picks UTCTime before 2050 and GeneralizedTime after, as RFC 5280 requires.
    const der = encodeSequence([
        encodeObjectIdentifier('2.5.29.17'),
        encodeInteger(65537n),
        encodeString('utf8', 'Zoë'),
        encodeTime(Date.UTC(2049, 11, 31, 23, 59, 59)),
    ]);
    const [oidNode, integerNode, textNode, timeNode] = decodeAsn1(der).children;
    const oid = readObjectIdentifier(oidNode);
    const time = readTime(timeNode);

    // A decoded DER tree re-encodes to the exact input — what a signature covers.
    const certificate = fixture('isrg-root-x1');
    const again = encodeAsn1Node(decodeAsn1(certificate));
    const identical = again.length === certificate.length && again.every((b, i) => b === certificate[i]);

    const sha256WithRsa = '1.2.840.113549.1.1.11';
    return {
        oid: `${oid} ${getOidName(oid) ?? '?'}`,
        integer: String(readInteger(integerNode)),
        text: readString(textNode).value,
        time: `${time.type} ${time.text}`,
        reencoded: String(identical),
        oidRoundTrip: String(decodeOid(encodeOid(sha256WithRsa)) === sha256WithRsa),
        oidName: getOidName(sha256WithRsa) ?? '?',
        validOid: `${String(isValidOid('1.2.3'))} ${String(isValidOid('3.1'))}`,
    };
}
