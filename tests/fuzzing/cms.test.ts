import { describe, expect, it } from 'vitest';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import type { ParseSignedDataOptions } from '../../src/types/cms-types.js';
import {
    DIGEST,
    OIDS,
    alg,
    attribute,
    context,
    contentInfo,
    defaultSignedAttributes,
    int,
    octets,
    oid,
    signedData,
    signerInfo,
    subjectKeyIdentifier,
} from '../helpers/cms-signed-data-builder.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';
import { createPrng } from '../helpers/prng.js';
import { outcome } from './_harness.js';

/**
 * Adversarial SignedData: truncation and seeded byte-level mutation.
 *
 * A SignedData reaches pkinative from a PDF, a mail, a timestamp server — all
 * places an attacker writes. Every iteration must end in a value or a
 * `PkiError` subclass; a TypeError from an unchecked index or a RangeError
 * from a runaway walk fails the suite with the seed and the input.
 */

const directoryName = tlv(2, true, 4, sequence(universal(17, sequence(oid('2.5.4.3'), universal(12, ascii('CA'))), true)));

/** Messages that between them reach every branch of the parser: both sids, both bags, both attribute sets, ESS v1 and v2. */
const CORPUS: readonly Uint8Array[] = [
    contentInfo(),
    contentInfo(signedData({
        version: int(5),
        certificates: [sequence(int(1)), context(2, true, int(1)), context(3, true, concat(oid('1.2.3'), int(1)))],
        crls: [sequence(int(2)), context(1, true, concat(oid(OIDS.ocspResponse), sequence(universal(10, [0]))))],
        signers: [
            signerInfo({
                version: int(3),
                sid: subjectKeyIdentifier(),
                signedAttrs: [
                    ...defaultSignedAttributes(),
                    attribute(OIDS.signingTime, universal(23, ascii('260301120000Z'))),
                    attribute(OIDS.signingCertificateV2, sequence(sequence(sequence(alg(OIDS.sha384), octets(DIGEST), sequence(sequence(directoryName), int(7)))))),
                ],
                unsignedAttrs: [attribute(OIDS.timeStampToken, sequence(int(1)))],
            }),
            signerInfo({
                signedAttrs: [...defaultSignedAttributes(), attribute(OIDS.signingCertificate, sequence(sequence(sequence(octets(DIGEST)))))],
            }),
        ],
    })),
    contentInfo(signedData({ signers: [], eContent: null, digestAlgorithms: [], certificates: [sequence(int(1))] })),
];

const RULES: readonly ParseSignedDataOptions[] = [
    { onDiagnostic: () => undefined },
    { encodingRules: 'ber', onDiagnostic: () => undefined },
    { allowTrailingData: true, onDiagnostic: () => undefined },
];

describe('fuzzing — parseSignedData under truncation', () => {
    it('should refuse every proper prefix of every corpus message with a PkiError', () => {
        for (const [index, message] of CORPUS.entries()) {
            expect(outcome(`corpus ${index}`, message, () => parseSignedData(message, RULES[0]))).toBe('ok');
            for (let length = 0; length < message.length; length++) {
                const prefix = message.subarray(0, length);
                expect(outcome(`corpus ${index} prefix ${length}`, prefix, () => parseSignedData(prefix, RULES[0]))).not.toBe('ok');
            }
        }
    });
});

describe('fuzzing — parseSignedData under byte flips, insertions and deletions', () => {
    it('should end 10 000 seeded mutations in a SignedData or a PkiError', () => {
        const seed = 0x5eed_c305;
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
            const result = outcome(`seed ${seed} iteration ${iteration}`, mutated, () => parseSignedData(mutated, options));
            outcomes.set(result, (outcomes.get(result) ?? 0) + 1);
        }
        // Both outcomes must be reached, or the fuzzer tests nothing.
        expect(outcomes.get('ok') ?? 0).toBeGreaterThan(100);
        expect([...outcomes.keys()].filter((k) => k !== 'ok').length).toBeGreaterThan(5);
    }, 120_000);
});
