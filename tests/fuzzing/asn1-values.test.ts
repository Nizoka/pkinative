import { describe, it, expect } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { encodeInteger, encodeObjectIdentifier } from '../../src/asn1/asn1-encode.js';
import { decodeOid } from '../../src/asn1/asn1-oid.js';
import { readInteger, readString } from '../../src/asn1/asn1-read.js';
import { readTime } from '../../src/asn1/asn1-time.js';
import { decodeUtf8 } from '../../src/core/text.js';
import { createPrng } from '../helpers/prng.js';
import { ascii, universal } from '../helpers/raw-der-builder.js';
import { outcome } from './_harness.js';

describe('fuzzing — INTEGER encodings', () => {
    it('should read every minimal INTEGER back to its own encoding and refuse the non-minimal ones', () => {
        const seed = 0x5eed_0004;
        const rng = createPrng(seed);
        for (let iteration = 0; iteration < 5000; iteration++) {
            const content = rng.bytes(1 + rng.int(12));
            if (rng.int(3) === 0) content[0] = rng.pick([0x00, 0xff]);
            const input = universal(2, content);
            const result = outcome(`seed ${seed} iteration ${iteration}`, input, () => readInteger(decodeAsn1(input)));
            const first = content[0] ?? 0;
            const second = content[1] ?? 0;
            const nonMinimal = content.length > 1 && ((first === 0 && second < 0x80) || (first === 0xff && second >= 0x80));
            expect(result, `content ${Buffer.from(content).toString('hex')}`).toBe(nonMinimal ? 'PKI_ASN1_INTEGER_INVALID' : 'ok');
            if (!nonMinimal) expect([...encodeInteger(readInteger(decodeAsn1(input)))]).toEqual([...input]);
        }
    });
});

describe('fuzzing — OBJECT IDENTIFIER arcs', () => {
    it('should decode random content to a string that re-encodes identically, or refuse it with PKI_OID_INVALID', () => {
        const seed = 0x5eed_0005;
        const rng = createPrng(seed);
        let decoded = 0;
        for (let iteration = 0; iteration < 5000; iteration++) {
            const content = rng.bytes(1 + rng.int(24));
            const result = outcome(`seed ${seed} iteration ${iteration}`, content, () => decodeOid(content));
            if (result === 'ok') {
                decoded++;
                expect([...encodeObjectIdentifier(decodeOid(content)).subarray(2)]).toEqual([...content]);
            } else {
                expect(result).toBe('PKI_OID_INVALID');
            }
        }
        expect(decoded).toBeGreaterThan(100);
    });
});

describe('fuzzing — time rollover', () => {
    it('should decode only real calendar instants from random digit strings', () => {
        const seed = 0x5eed_0006;
        const rng = createPrng(seed);
        const digits = (n: number): string => Array.from({ length: n }, () => String(rng.int(10))).join('');
        for (let iteration = 0; iteration < 5000; iteration++) {
            const generalized = rng.int(2) === 0;
            const text = generalized ? `${digits(4)}${digits(10)}Z` : `${digits(12)}Z`;
            const input = universal(generalized ? 24 : 23, ascii(text));
            const result = outcome(`seed ${seed} iteration ${iteration}`, input, () => readTime(decodeAsn1(input)));
            if (result === 'ok') {
                const time = readTime(decodeAsn1(input));
                const iso = new Date(time.epochMilliseconds).toISOString();
                const year = generalized ? Number(text.slice(0, 4)) : (Number(text.slice(0, 2)) >= 50 ? 1900 : 2000) + Number(text.slice(0, 2));
                const rest = generalized ? text.slice(4) : text.slice(2);
                const expected = `${String(year).padStart(4, '0')}-${rest.slice(0, 2)}-${rest.slice(2, 4)}T${rest.slice(4, 6)}:${rest.slice(6, 8)}:${rest.slice(8, 10)}`;
                // The instant renders back to the same fields: nothing was rolled over.
                expect(iso.replace(/^\+0*/, '').startsWith(expected.replace(/^0+(?=\d{4})/, ''))).toBe(true);
            } else {
                expect(result).toBe('PKI_ASN1_TIME_INVALID');
            }
        }
    });
});

describe('fuzzing — string type confusion', () => {
    it('should agree with a fatal TextDecoder on random UTF8String content, and type every refusal', () => {
        // 5 000 iterations across eight string tags is 40 000 decode-and-read
        // cycles. The assertions are collected and asserted once at the end
        // rather than called inside the loop: vitest builds an assertion
        // object per `expect`, and 45 000 of them cost more than the work
        // being measured — enough to push this suite past the 30 s timeout
        // when the machine is busy, which is a flake on a slow runner rather
        // than a finding. The search budget is unchanged; only the
        // bookkeeping moved out of the hot path.
        const seed = 0x5eed_0007;
        const rng = createPrng(seed);
        const fatal = new TextDecoder('utf-8', { fatal: true });
        const mismatches: string[] = [];
        for (let iteration = 0; iteration < 5000; iteration++) {
            const content = Uint8Array.from({ length: rng.int(16) }, () => (rng.int(3) === 0 ? rng.int(128) : 0x80 + rng.int(128)));
            let reference: string | null;
            try {
                reference = fatal.decode(content);
            } catch {
                reference = null;
            }
            const mine = decodeUtf8(content);
            if (mine !== reference) mismatches.push(`seed ${seed} iteration ${iteration}: decodeUtf8 ${JSON.stringify(mine)} vs TextDecoder ${JSON.stringify(reference)}`);
            for (const tag of [12, 18, 19, 20, 22, 26, 28, 30]) {
                const input = universal(tag, content);
                const result = outcome(`seed ${seed} iteration ${iteration} tag ${tag}`, input, () => readString(decodeAsn1(input), { onDiagnostic: () => undefined }));
                if (result !== 'ok' && result !== 'PKI_ASN1_STRING_INVALID') {
                    mismatches.push(`seed ${seed} iteration ${iteration} tag ${tag}: ${result}`);
                }
            }
        }
        expect(mismatches).toEqual([]);
        // An explicit budget, like the 20 000-mutation suite next door: the
        // default 30 s is what this test silently ran against before, and a
        // search budget whose time limit is implicit is one slow runner away
        // from being a flake nobody can reproduce.
    }, 60_000);
});
