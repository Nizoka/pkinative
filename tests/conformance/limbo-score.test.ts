import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SKIP_FEATURES } from '../../scripts/lib/limbo-score.js';
import { CORPORA } from '../../scripts/lib/corpora.js';

/**
 * The shape of the x509-limbo score baseline, checked without the corpus.
 *
 * L6 itself needs 9 793 downloaded cases and four minutes, so it runs in the
 * publish profile only. What this suite holds is the **discipline** around it,
 * which is what makes the number mean anything and which costs nothing to
 * check: every accepted disagreement carries a sentence a human wrote, the
 * canaries are set, and the pins are pins rather than a second copy of the
 * deviation list.
 *
 * The reason to assert it here rather than only in the conformance run is that
 * the one thing a reviewer cannot catch by reading a diff is an empty string.
 */

interface ScoreBaseline {
    readonly $comment: string;
    readonly corpus: string;
    readonly commit: string;
    readonly canaries: { readonly mustSucceed: string; readonly mustFail: string };
    readonly totals: { readonly scored: number; readonly agree: number; readonly deviations: number; readonly unparsed: number; readonly skipped: number };
    readonly deviations: Readonly<Record<string, { readonly expected: string; readonly why: string }>>;
    readonly reasons: Readonly<Record<string, string>>;
}

const baseline = JSON.parse(readFileSync('scripts/data/limbo-score.json', 'utf8')) as ScoreBaseline;
const ids = Object.keys(baseline.deviations);

describe('the x509-limbo score baseline', () => {
    it('should be pinned to the corpus commit the gate fetches', () => {
        const corpus = CORPORA.find((c) => c.id === 'x509-limbo');
        expect(baseline.corpus).toBe('x509-limbo');
        expect(baseline.commit).toBe(corpus?.commit);
    });

    it('should carry a written reason for every single deviation', () => {
        // The one check a reviewer cannot make by eye: a disagreement is either
        // a defect or a decision, and only a sentence tells them apart. The
        // scorer never fills one in, which is what keeps this honest.
        const unexplained = ids.filter((id) => baseline.deviations[id]?.why.trim() === '');
        expect(unexplained).toEqual([]);
    });

    it('should not let a reason be a placeholder', () => {
        // A short reason is a shrug. Every category in this file needs at least
        // a sentence naming the standard and the decision.
        const tooShort = ids.filter((id) => (baseline.deviations[id]?.why ?? '').length < 120);
        expect(tooShort).toEqual([]);
    });

    it('should say what the corpus expected, so the direction of each deviation is readable', () => {
        for (const id of ids) expect(['SUCCESS', 'FAILURE'], id).toContain(baseline.deviations[id]?.expected);
    });

    it('should name two canaries, and neither of them a deviation', () => {
        // A scorer that refuses everything scores well against a corpus that is
        // mostly FAILURE. The positive canary is the only thing that notices, so
        // it must be a case the scorer is expected to accept — which means it
        // cannot also be listed as a disagreement.
        const { mustSucceed, mustFail } = baseline.canaries;
        expect(mustSucceed).not.toBe('');
        expect(mustFail).not.toBe('');
        expect(mustSucceed).not.toBe(mustFail);
        expect(ids).not.toContain(mustSucceed);
        expect(ids).not.toContain(mustFail);
    });

    it('should pin cases on their reason codes without pinning a deviation', () => {
        // A pinned case asserts "this is refused, and for exactly these
        // reasons". Pinning a deviation would assert the reasons of an answer
        // the baseline already records as wrong.
        const pins = Object.keys(baseline.reasons);
        expect(pins.length).toBeGreaterThan(20);
        expect(pins.filter((id) => ids.includes(id))).toEqual([]);
        for (const [id, codes] of Object.entries(baseline.reasons)) {
            expect(codes, id).not.toBe('');
            for (const code of codes.split(',')) expect(code, id).toMatch(/^PKI_REASON_[A-Z_]+$/);
        }
    });

    it('should spread the pins across the corpus rather than over one suite', () => {
        // Twenty pins all inside bettertls would prove one code path twice.
        const namespaces = new Set(Object.keys(baseline.reasons).map((id) => id.slice(0, id.indexOf('::'))));
        expect(namespaces.size).toBeGreaterThanOrEqual(4);
    });

    it('should keep the totals self-consistent', () => {
        expect(baseline.totals.agree + baseline.totals.deviations).toBe(baseline.totals.scored);
        expect(baseline.totals.deviations).toBe(ids.length);
    });

    it('should explain every feature it skips', () => {
        // A SKIP is a claim too: "this case asks for something pkinative does
        // not do". One with no reason beside it is indistinguishable from an
        // oversight.
        for (const [feature, why] of Object.entries(SKIP_FEATURES)) {
            expect(feature, feature).toMatch(/^[a-z0-9-]+$/);
            expect(why.length, feature).toBeGreaterThan(40);
        }
    });
});
