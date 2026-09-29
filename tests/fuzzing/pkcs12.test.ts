import { beforeAll, describe, expect, it } from 'vitest';
import { parsePkcs12 } from '../../src/keys/key-pkcs12.js';
import type { PkiParseOptions } from '../../src/types/pki-types.js';
import { alg, attribute, int, octets } from '../helpers/cms-signed-data-builder.js';
import {
    P12,
    authenticatedSafe,
    berPfx,
    certBag,
    contentInfo,
    crlBag,
    dataInfo,
    encryptedDataInfo,
    encryptedSafeContents,
    friendlyName,
    keyBag,
    legacyMacData,
    localKeyId,
    pbmac1MacData,
    pfx,
    safeContents,
    safeContentsBag,
    secretBag,
    shroudKey,
    shroudedKeyBag,
} from '../helpers/pkcs12-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';
import { createPrng } from '../helpers/prng.js';
import { outcome } from './_harness.js';

/**
 * Adversarial PKCS#12: truncation and seeded byte-level mutation.
 *
 * A .p12 arrives from a mail attachment, a download, a user's disk — all
 * places an attacker writes, and it is parsed before any password is asked
 * for. Every iteration must end in a value or a `PkiError` subclass; a
 * TypeError from an unchecked index or a RangeError from a runaway walk
 * fails the suite with the seed and the input.
 */

const PASSWORD = 'fuzz';
const CERT = sequence(int(1), octets([1, 2, 3]));
/** A structurally valid PKCS#8 of an EC key; its octets are never used as a key here. */
const PKCS8 = sequence(int(0), alg('1.2.840.10045.2.1', Uint8Array.of(0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07)), octets([4, 5, 6]));

/** PFX files that between them reach every branch of the reader: each bag type, nesting, encrypted and enveloped entries, both MAC kinds, BER. */
const CORPUS: Uint8Array[] = [];

beforeAll(async () => {
    const bags = safeContents(
        certBag(CERT, [friendlyName('cert'), localKeyId([1, 2])]),
        crlBag(sequence(int(2))),
        keyBag(PKCS8, [attribute('1.2.3', int(1))]),
        shroudedKeyBag(await shroudKey(PKCS8, PASSWORD)),
        secretBag(Uint8Array.of(7)),
        safeContentsBag([certBag(CERT), safeContentsBag([crlBag(sequence(int(3)))])]),
    );
    const mixed = authenticatedSafe(
        dataInfo(bags),
        await encryptedSafeContents(safeContents(certBag(CERT)), PASSWORD),
        contentInfo(P12.envelopedData, sequence(int(0))),
        encryptedDataInfo(Uint8Array.of(1, 2, 3), { algorithm: alg(P12.pbeWithSHAAnd3KeyTripleDES, sequence(octets([1]), int(2048))) }),
    );
    CORPUS.push(
        pfx({ authSafe: mixed, macData: await pbmac1MacData(mixed, PASSWORD) }),
        pfx({ authSafe: authenticatedSafe(dataInfo(bags)), macData: legacyMacData() }),
        berPfx(authenticatedSafe(dataInfo(bags)), legacyMacData()),
    );
});

const RULES: readonly PkiParseOptions[] = [
    { onDiagnostic: () => undefined },
    { encodingRules: 'ber', onDiagnostic: () => undefined },
];

describe('fuzzing — parsePkcs12 under truncation', () => {
    it('should refuse every proper prefix of every corpus file with a PkiError', () => {
        for (const [index, file] of CORPUS.entries()) {
            const rules = index === 2 ? RULES[1] : RULES[0];
            expect(outcome(`corpus ${index}`, file, () => parsePkcs12(file, rules))).toBe('ok');
            for (let length = 0; length < file.length; length++) {
                const prefix = file.subarray(0, length);
                expect(outcome(`corpus ${index} prefix ${length}`, prefix, () => parsePkcs12(prefix, rules))).not.toBe('ok');
            }
        }
    });
});

describe('fuzzing — parsePkcs12 under byte flips, insertions and deletions', () => {
    it('should end 10 000 seeded mutations in a PKCS#12 or a PkiError', () => {
        const seed = 0x5eed_0012;
        const rng = createPrng(seed);
        const outcomes = new Map<string, number>();
        for (let iteration = 0; iteration < 10_000; iteration++) {
            const bytes = Array.from(rng.pick(CORPUS));
            const edits = 1 + rng.int(3);
            for (let e = 0; e < edits; e++) {
                const at = rng.int(bytes.length + 1);
                const kind = rng.int(3);
                if (kind === 0 && at < bytes.length) bytes[at] = rng.int(256);
                else if (kind === 1) bytes.splice(at, 0, rng.int(256));
                else if (bytes.length > 0) bytes.splice(Math.min(at, bytes.length - 1), 1);
            }
            const mutated = Uint8Array.from(bytes);
            const options = rng.pick(RULES);
            const result = outcome(`seed ${seed} iteration ${iteration}`, mutated, () => parsePkcs12(mutated, options));
            outcomes.set(result, (outcomes.get(result) ?? 0) + 1);
        }
        // Both outcomes must be reached, or the fuzzer tests nothing.
        expect(outcomes.get('ok') ?? 0).toBeGreaterThan(100);
        expect([...outcomes.keys()].filter((k) => k !== 'ok').length).toBeGreaterThan(5);
    }, 120_000);
});
