import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The conformance guide quotes the PKITS deviation count four times, and
 * nothing generated it: when 0.9.0 moved InvalidDNandRFC822nameConstraintsTest29
 * from a deviation to an agreement, three mentions became 8 and one stayed 9.
 * Every "<n> deviations" in the guide is about PKITS (L6 says
 * "disagreements"), so each must equal the reviewed baseline, which the L7
 * and L8 runners already hold to the corpus.
 */
const ROOT = process.cwd();

describe('the deviation counts the conformance guide quotes', () => {
    it('should all equal the reviewed PKITS baseline', () => {
        const guide = readFileSync(join(ROOT, 'docs', 'guides', 'conformance.md'), 'utf8');
        const score = JSON.parse(readFileSync(join(ROOT, 'scripts', 'data', 'pkits-score.json'), 'utf8')) as { deviations: Record<string, unknown>; totals: { deviations: number } };
        const count = Object.keys(score.deviations).length;
        expect(score.totals.deviations, 'pkits-score.json disagrees with itself').toBe(count);
        const quoted = [...guide.matchAll(/\b(\d+) (?:reviewed )?deviations\b/g)].map((m) => Number(m[1]));
        expect(quoted.length, 'the guide no longer quotes the count; drop this test or the guide lost a sentence').toBeGreaterThan(0);
        expect(quoted).toEqual(quoted.map(() => count));
    });
});
