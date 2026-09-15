import { describe, it, expect } from 'vitest';
import { decodeAsn1, decodeAsn1Sequence } from '../../src/asn1/asn1-decode.js';
import { encodeAsn1Node } from '../../src/asn1/asn1-encode.js';
import { readObjectIdentifier } from '../../src/asn1/asn1-oid.js';
import { readBitString, readBoolean, readInteger, readNull, readOctetString, readString } from '../../src/asn1/asn1-read.js';
import { readTime } from '../../src/asn1/asn1-time.js';
import type { Asn1Node } from '../../src/types/asn1-types.js';
import type { PkiParseOptions } from '../../src/types/pki-types.js';
import { createPrng } from '../helpers/prng.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';
import { outcome } from './_harness.js';

/** A small corpus that exercises every reader, built without the engine. */
const CORPUS: readonly Uint8Array[] = [
    sequence(
        universal(2, [0x01, 0x00, 0x01]),
        sequence(universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), universal(5, [])),
        tlv(1, true, 0, universal(12, ascii('example'))),
        sequence(universal(23, ascii('250101000000Z')), universal(24, ascii('20500101000000Z'))),
        universal(3, [0x00, 0x30, 0x03, 0x02, 0x01, 0x05]),
        tlv(2, true, 3, sequence(sequence(universal(6, [0x55, 0x1d, 0x13]), universal(1, [0xff]), universal(4, [0x30, 0x00])))),
    ),
    sequence(universal(19, ascii('Example CA')), universal(22, ascii('ca@example.com')), universal(30, [0x00, 0x41]), universal(28, [0, 0, 0, 0x42])),
    concat([0x30, 0x81, 0x90], new Uint8Array(0x90).fill(0x05).map((v, i) => (i % 2 === 0 ? v : 0))),
];

const RULES: readonly PkiParseOptions[] = [{}, { encodingRules: 'ber', onDiagnostic: () => undefined }];

/** Run every reader on every node: each must return or throw a PkiError. */
function exerciseReaders(label: string, input: Uint8Array, root: Asn1Node, options: PkiParseOptions): void {
    const stack: Asn1Node[] = [root];
    const quiet = { ...options, onDiagnostic: () => undefined };
    while (stack.length > 0) {
        const node = stack.pop() as Asn1Node;
        for (const child of node.children) stack.push(child);
        outcome(`${label} readBoolean`, input, () => readBoolean(node, quiet));
        outcome(`${label} readInteger`, input, () => readInteger(node, quiet));
        outcome(`${label} readNull`, input, () => readNull(node));
        outcome(`${label} readBitString`, input, () => readBitString(node, quiet));
        outcome(`${label} readOctetString`, input, () => readOctetString(node, quiet));
        outcome(`${label} readString`, input, () => readString(node, { ...quiet, stringType: 'utf8' }));
        outcome(`${label} readTime`, input, () => readTime(node, { ...quiet, timeType: 'GeneralizedTime' }));
        outcome(`${label} readObjectIdentifier`, input, () => readObjectIdentifier(node, quiet));
        outcome(`${label} encodeAsn1Node`, input, () => encodeAsn1Node(node));
    }
}

describe('fuzzing — truncation', () => {
    it('should refuse every proper prefix of every corpus value with a PkiError', () => {
        for (const [index, value] of CORPUS.entries()) {
            expect(decodeAsn1(value).bytes.length).toBe(value.length);
            for (let length = 0; length < value.length; length++) {
                const prefix = value.subarray(0, length);
                for (const options of RULES) {
                    expect(outcome(`corpus ${index} prefix ${length}`, prefix, () => decodeAsn1(prefix, options))).not.toBe('ok');
                }
            }
        }
    });
});

describe('fuzzing — byte flips, insertions and deletions', () => {
    it('should end 20 000 seeded mutations in a value or a PkiError, readers included', () => {
        const seed = 0x5eed_0001;
        const rng = createPrng(seed);
        const outcomes = new Map<string, number>();
        for (let iteration = 0; iteration < 20_000; iteration++) {
            const source = rng.pick(CORPUS);
            const bytes = Array.from(source);
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
            const label = `seed ${seed} iteration ${iteration}`;
            const result = outcome(label, mutated, () => decodeAsn1(mutated, options));
            outcomes.set(result, (outcomes.get(result) ?? 0) + 1);
            // Every decode is checked; the nine readers run on every eighth decodable mutation.
            if (result === 'ok' && iteration % 8 === 0) exerciseReaders(label, mutated, decodeAsn1(mutated, options), options);
            outcome(`${label} sequence`, mutated, () => decodeAsn1Sequence(mutated, options));
        }
        // The mutations must reach both outcomes, or the fuzzer tests nothing.
        expect(outcomes.get('ok') ?? 0).toBeGreaterThan(100);
        expect([...outcomes.keys()].filter((k) => k !== 'ok').length).toBeGreaterThan(5);
    }, 120_000);
});
