import { describe, expect, it } from 'vitest';
import { encodeKeyUsage, encodeSubjectAltName } from '../../src/build/build-structures.js';
import { PkiError } from '../../src/types/pki-errors.js';
import { parseCertificationRequest } from '../../src/x509/x509-csr.js';
import { ECDSA_SHA256, algorithm, bitString, context, ecKey, extension, integer, name, oid, printable, rsaKey, set, utf8 } from '../helpers/cert-builder.js';
import { createPrng } from '../helpers/prng.js';
import { sequence } from '../helpers/raw-der-builder.js';

/**
 * `parseCertificationRequest` under hostile bytes: every proper prefix, every
 * single-octet rewrite and a seeded run of multi-octet flips end in a request
 * or a `PkiError` — never in a TypeError, a RangeError or a hang. Seeded and
 * deterministic, so a failure names its seed and its input.
 */

const QUIET = { onDiagnostic: (): void => undefined };
const CN = '2.5.4.3';
const EXTENSION_REQUEST = '1.2.840.113549.1.9.14';
const CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7';

/** A request, or the code of the PkiError it ends in; any other exception fails the suite. */
function outcome(bytes: Uint8Array): string {
    try {
        parseCertificationRequest(bytes, QUIET);
        return 'ok';
    } catch (error) {
        if (error instanceof PkiError) return error.code;
        throw error;
    }
}

const attribute = (type: string, ...values: Uint8Array[]): Uint8Array => sequence(oid(type), set(...values));
const attributes = (...entries: Uint8Array[]): Uint8Array => context(0, true, entries.flatMap((e) => Array.from(e)));

const SAMPLES: ReadonlyArray<readonly [string, Uint8Array]> = [
    ['an EC request with no attributes', sequence(
        sequence(integer([0x00]), name([[CN, utf8('host.example')]]), ecKey(), context(0, true, [])),
        algorithm(ECDSA_SHA256),
        bitString(sequence(integer([0x01]), integer([0x02]))),
    )],
    ['an RSA request with a challenge password, two requested extensions and an unknown attribute', sequence(
        sequence(
            integer([0x00]),
            name([['2.5.4.6', printable('FR')]], [[CN, utf8('host.example')]]),
            rsaKey([0x00, 0xc1, 0x02, 0x03, 0x04]),
            attributes(
                attribute(CHALLENGE_PASSWORD, utf8('open sesame')),
                attribute(EXTENSION_REQUEST, sequence(
                    extension('2.5.29.17', encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }])),
                    extension('2.5.29.15', encodeKeyUsage(['digitalSignature']), true),
                )),
                attribute('1.2.3.4.5', integer([0x07]), printable('two')),
            ),
        ),
        algorithm('1.2.840.113549.1.1.11', Uint8Array.of(0x05, 0x00)),
        bitString(new Uint8Array(32).fill(0xab)),
    )],
];

describe('parseCertificationRequest under truncation', () => {
    it.each(SAMPLES)('should refuse every proper prefix of %s with a PkiError', (_, der) => {
        expect(outcome(der)).toBe('ok');
        for (let length = 0; length < der.length; length++) {
            expect(outcome(der.subarray(0, length)), `prefix of ${length} octets`).not.toBe('ok');
        }
    });
});

describe('parseCertificationRequest under single-octet mutation', () => {
    it.each(SAMPLES)('should end every mutation of %s in a request or a PkiError', (_, der) => {
        const outcomes = new Set<string>();
        for (let i = 0; i < der.length; i++) {
            for (const value of [0x00, 0x80, 0xff, (der[i] ?? 0) ^ 0x01]) {
                const mutated = der.slice();
                mutated[i] = value;
                outcomes.add(outcome(mutated));
            }
        }
        expect(outcomes.has('ok')).toBe(true);
        expect(outcomes.size).toBeGreaterThan(5);
    });
});

describe('parseCertificationRequest under seeded multi-octet flips', () => {
    it.each(SAMPLES)('should end every seeded flip of %s in a request or a PkiError', (_, der) => {
        const prng = createPrng(0x5eed_00c5 ^ der.length);
        const outcomes = new Set<string>();
        for (let round = 0; round < 400; round++) {
            const mutated = der.slice();
            const flips = 1 + prng.int(4);
            for (let f = 0; f < flips; f++) {
                const at = prng.int(mutated.length);
                mutated[at] = (mutated[at] ?? 0) ^ (1 << prng.int(8));
            }
            outcomes.add(outcome(mutated));
        }
        expect(outcomes.size).toBeGreaterThan(3);
        for (const code of outcomes) if (code !== 'ok') expect(code).toMatch(/^PKI_/);
    });
});
