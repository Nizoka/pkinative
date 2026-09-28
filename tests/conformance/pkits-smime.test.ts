import { describe, expect, it } from 'vitest';
import { splitPkitsMessage } from '../../scripts/lib/pkits-smime.js';

/**
 * Taking a PKITS `multipart/signed` message apart, without the corpus.
 *
 * The one rule this must get exactly right is which line break belongs to the
 * content. RFC 2046 §5.1.1 gives the break before a delimiter to the
 * delimiter; PKITS writes its envelope with bare LF and its signed part with
 * CRLF. Measured on all 224 messages of the pinned archive before this was
 * written: the content the signer hashed ends with the part's own CRLF, and
 * the bare LF after it is the delimiter's.
 */

const encoder = new TextEncoder();
const SIGNATURE = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]);

function message(boundary: string, signedPart: string): Uint8Array {
    return encoder.encode([
        'To: recipient@testcertificates.gov',
        `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"; boundary="${boundary}"`,
        '',
        'This is an S/MIME signed message',
        '',
        `--${boundary}`,
        signedPart,
        `--${boundary}`,
        'Content-Type: application/pkcs7-signature; name="smime.p7s"',
        'Content-Transfer-Encoding: base64',
        '',
        btoa(String.fromCharCode(...SIGNATURE)),
        '',
        `--${boundary}--`,
        '',
    ].join('\n'));
}

describe('splitPkitsMessage', () => {
    it('should keep the part\'s own CRLF and give the envelope\'s LF to the delimiter', () => {
        const signed = 'Content-Type: text/plain\r\n\r\nThis is a sample signed message.\r\n';
        const split = splitPkitsMessage('smime/SignedValidSignaturesTest1.eml', message('----B', signed));
        expect(new TextDecoder().decode(split.content)).toBe(signed);
        expect(split.signature).toEqual(SIGNATURE);
        expect(split.test).toBe('ValidSignaturesTest1');
    });

    it('should give a CRLF before the delimiter to the delimiter too', () => {
        // Every bare LF of the envelope made CRLF; the part's own CRLF left alone.
        const bytes = encoder.encode(new TextDecoder().decode(message('----B', 'Content-Type: text/plain\r\n\r\nbody')).replace(/(?<!\r)\n/g, '\r\n'));
        expect(new TextDecoder().decode(splitPkitsMessage('smime/SignedValidTest2.eml', bytes).content)).toBe('Content-Type: text/plain\r\n\r\nbody');
    });

    it('should hand back a view of the input, not a re-encoding of it', () => {
        const bytes = message('----B', 'Content-Type: text/plain\r\n\r\nbody\r\n');
        expect(splitPkitsMessage('smime/SignedValidTest3.eml', bytes).content.buffer).toBe(bytes.buffer);
    });

    it.each([
        ['names no boundary', encoder.encode('To: x\n\nplain text\n')],
        ['has one part only', encoder.encode('Content-Type: multipart/signed; boundary="B"\n\n--B\nbody\n--B--\n')],
    ])('should refuse a message that %s', (_, bytes) => {
        expect(() => splitPkitsMessage('smime/SignedValidTest4.eml', bytes)).toThrow(/pkits-smime/);
    });

    it('should refuse a file name that does not follow the PKITS convention', () => {
        expect(() => splitPkitsMessage('smime/other.eml', message('----B', 'x\r\n'))).toThrow(/naming/);
    });
});
