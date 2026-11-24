import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createTimeStampRequest, parseTimeStampRequest, type TimeStampHashAlgorithm } from '../../src/cms/tsp-request.js';
import { createOcspRequest, encodeOcspCertId, parseOcspRequest, type OcspHashAlgorithm } from '../../src/revocation/ocsp-request.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
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

describe('property — RFC 6960 OCSP requests', () => {
    const SEED = 0x5eed_6960;
    const quiet = { onDiagnostic: (): undefined => undefined };
    // The committed certificates, in every (certificate, issuer) pairing: a CertID is three
    // values computed from two certificates, whether or not one issued the other.
    const CERTIFICATES = readdirSync('tests/fixtures/certs').filter((f) => f.endsWith('.der')).sort()
        .map((f) => parseCertificate(new Uint8Array(readFileSync(`tests/fixtures/certs/${f}`)), quiet));
    const DIGESTS: Readonly<Record<OcspHashAlgorithm, { readonly node: string; readonly oid: string }>> = {
        'SHA-1': { node: 'sha1', oid: '1.3.14.3.2.26' },
        'SHA-256': { node: 'sha256', oid: '2.16.840.1.101.3.4.2.1' },
    };
    const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

    it('should read back what createOcspRequest was given — the hashes node:crypto computes, the serial, the nonce (500 requests)', () => {
        const rng = createPrng(SEED);
        for (let i = 0; i < 500; i++) {
            const where = `seed 0x${SEED.toString(16)}, iteration ${String(i)}`;
            const certificate = rng.pick(CERTIFICATES);
            const issuer = rng.pick(CERTIFICATES);
            const hashAlgorithm = rng.pick<OcspHashAlgorithm>(['SHA-1', 'SHA-256']);
            // 1 to 32 octets: everything the writer accepts.
            const nonce = rng.int(4) === 0 ? undefined : rng.bytes(1 + rng.int(32));
            const der = createOcspRequest(certificate, issuer, { hashAlgorithm, nonce });

            const codes: string[] = [];
            const request = parseOcspRequest(der, { onDiagnostic: (d) => { codes.push(d.code); } });
            // What the writer writes, its reader reads with nothing to say.
            expect(codes, where).toEqual([]);
            expect(request.der, where).toEqual(der);
            expect(request.version, where).toBe(1);
            expect(request.requestorName, where).toBeUndefined();
            expect(request.signature, where).toBeUndefined();
            expect(request.nonce, where).toEqual(nonce);
            expect(request.extensions.length, where).toBe(nonce === undefined ? 0 : 1);
            expect(request.requests, where).toHaveLength(1);

            const [entry] = request.requests;
            const digest = (data: Uint8Array): string => createHash(DIGESTS[hashAlgorithm].node).update(data).digest('hex');
            expect(entry?.certId.hashAlgorithm.oid, where).toBe(DIGESTS[hashAlgorithm].oid);
            expect(hex(entry?.certId.issuerNameHash ?? new Uint8Array(0)), where).toBe(digest(issuer.subject.der));
            expect(hex(entry?.certId.issuerKeyHash ?? new Uint8Array(0)), where).toBe(digest(issuer.subjectPublicKeyInfo.publicKey.bytes));
            expect(entry?.certId.serialNumber.hex, where).toBe(certificate.serialNumber.hex);
            expect(entry?.certId.serialNumber.value, where).toBe(certificate.serialNumber.value);
            // The CertID as encoded is the encoder's output, byte for byte.
            expect(entry?.certIdDer, where).toEqual(encodeOcspCertId(certificate, issuer, hashAlgorithm));
            expect(entry?.extensions, where).toEqual([]);
        }
    });
});
