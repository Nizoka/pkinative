import { describe, expect, it } from 'vitest';
import { createTimeStampRequest, parseTimeStampRequest, type TimeStampHashAlgorithm } from '../../src/cms/tsp-request.js';
import { createPrng, type Prng } from '../helpers/prng.js';

/**
 * The requests pkinative writes, read back — seeded, in both directions.
 *
 * A reader checked only on the cases someone thought of is checked on the
 * cases someone thought of. Here the inputs are drawn, and what is asserted
 * is a relation rather than a value: what the writer was given is what the
 * reader returns, and what the reader returns rebuilds the bytes it read.
 * Every failure message carries the seed and the iteration.
 */

const HASHES: ReadonlyArray<{ readonly name: TimeStampHashAlgorithm; readonly oid: string; readonly bytes: number }> = [
    { name: 'SHA-256', oid: '2.16.840.1.101.3.4.2.1', bytes: 32 },
    { name: 'SHA-384', oid: '2.16.840.1.101.3.4.2.2', bytes: 48 },
    { name: 'SHA-512', oid: '2.16.840.1.101.3.4.2.3', bytes: 64 },
];

/** A non-negative integer of up to `octets` random octets — the sizes a nonce comes in, the top bit set half the time. */
function randomBigInt(rng: Prng, octets: number): bigint {
    let value = 0n;
    for (const byte of rng.bytes(1 + rng.int(octets))) value = (value << 8n) | BigInt(byte);
    return value;
}

/** A dotted OID under an arc of 1 or 2 — arcs past 127, so the base-128 form is exercised. */
function randomOid(rng: Prng): string {
    const arcs = [rng.pick([1, 2]), rng.int(40), ...Array.from({ length: 1 + rng.int(6) }, () => rng.int(3) === 0 ? rng.int(2 ** 31) : rng.int(200))];
    return arcs.join('.');
}

describe('property — RFC 3161 timestamp requests', () => {
    const SEED = 0x5eed_3161;

    it('should read back what createTimeStampRequest was given, and rebuild the same bytes from what it read (1 000 requests)', () => {
        const rng = createPrng(SEED);
        for (let i = 0; i < 1000; i++) {
            const where = `seed 0x${SEED.toString(16)}, iteration ${String(i)}`;
            const hash = rng.pick(HASHES);
            const imprint = rng.bytes(hash.bytes);
            const options = {
                hashAlgorithm: hash.name,
                policy: rng.int(2) === 0 ? randomOid(rng) : undefined,
                nonce: rng.int(3) === 0 ? undefined : randomBigInt(rng, 16),
                certReq: rng.int(2) === 0,
            };
            const der = createTimeStampRequest(imprint, options);

            const codes: string[] = [];
            const request = parseTimeStampRequest(der, { onDiagnostic: (d) => { codes.push(d.code); } });
            // What the writer writes, its reader reads with nothing to say.
            expect(codes, where).toEqual([]);
            expect(request.version, where).toBe(1);
            expect(request.messageImprint.hashAlgorithm.oid, where).toBe(hash.oid);
            expect(request.messageImprint.hashedMessage, where).toEqual(imprint);
            expect(request.policy, where).toBe(options.policy);
            expect(request.nonce, where).toBe(options.nonce);
            expect(request.certReq, where).toBe(options.certReq);
            expect(request.extensions, where).toEqual([]);
            expect(request.der, where).toEqual(der);

            // The other direction: the parsed fields are the writer's options.
            const rebuilt = createTimeStampRequest(request.messageImprint.hashedMessage, {
                hashAlgorithm: HASHES.find((h) => h.oid === request.messageImprint.hashAlgorithm.oid)?.name,
                policy: request.policy,
                nonce: request.nonce,
                certReq: request.certReq,
            });
            expect(rebuilt, where).toEqual(der);
        }
    });
});
