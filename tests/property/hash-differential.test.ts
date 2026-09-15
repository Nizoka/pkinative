import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { sha1 } from '../../src/hash/sha1.js';
import { sha256 } from '../../src/hash/sha256.js';
import { sha384, sha512 } from '../../src/hash/sha512.js';
import { createPrng } from '../helpers/prng.js';

describe('property — hashes against node:crypto', () => {
    it('should agree with node:crypto on 2 000 random inputs of up to 2 048 octets', () => {
        const rng = createPrng(0x5eed_2001);
        const algorithms = [['sha1', sha1], ['sha256', sha256], ['sha384', sha384], ['sha512', sha512]] as const;
        for (let i = 0; i < 2000; i++) {
            const input = rng.bytes(rng.int(2049));
            const [name, fn] = rng.pick(algorithms);
            expect(Buffer.from(fn(input)).toString('hex'), `${name} length ${input.length}`).toBe(createHash(name).update(input).digest('hex'));
        }
    });
});
