import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SKIP_FEATURES } from '../../scripts/lib/limbo-score.js';
import { CORPORA } from '../../scripts/lib/corpora.js';
import { expectationOfName } from '../../scripts/lib/pkits.js';

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

/**
 * The PKITS baseline has the same shape and the same discipline, so it is held
 * to the same rules here. Two corpora, one contract: a disagreement is either a
 * defect or a decision, and the difference is a sentence someone wrote.
 */
const pkits = JSON.parse(readFileSync('scripts/data/pkits-score.json', 'utf8')) as ScoreBaseline;
const pkitsIds = Object.keys(pkits.deviations);

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

describe('the NIST PKITS score baseline', () => {
    it('should be pinned to the archive the gate fetches', () => {
        const corpus = CORPORA.find((c) => c.id === 'pkits');
        expect(pkits.corpus).toBe('pkits');
        expect(pkits.commit).toBe(corpus?.commit);
        // An archive corpus is pinned by its own digest, so the pin IS a
        // SHA-256 — 64 hex characters, not a git commit's 40.
        expect(pkits.commit).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should carry a written reason for every single deviation', () => {
        expect(pkitsIds.filter((id) => pkits.deviations[id]?.why.trim() === '')).toEqual([]);
    });

    it('should not let a reason be a placeholder', () => {
        expect(pkitsIds.filter((id) => (pkits.deviations[id]?.why ?? '').length < 120)).toEqual([]);
    });

    it('should name two canaries, and neither of them a deviation', () => {
        const { mustSucceed, mustFail } = pkits.canaries;
        expect(mustSucceed).not.toBe('');
        expect(mustFail).not.toBe('');
        // NIST's own convention, which is also the only machine-readable
        // statement of intent the archive carries: the canaries have to be
        // tests whose names say what they expect.
        expect(mustSucceed.startsWith('Valid')).toBe(true);
        expect(mustFail.startsWith('Invalid')).toBe(true);
        expect(pkitsIds).not.toContain(mustSucceed);
        expect(pkitsIds).not.toContain(mustFail);
    });

    it('should pin tests on their reason codes without pinning a deviation', () => {
        const pins = Object.keys(pkits.reasons);
        expect(pins.length).toBeGreaterThan(20);
        expect(pins.filter((id) => pkitsIds.includes(id))).toEqual([]);
        for (const [id, codes] of Object.entries(pkits.reasons)) {
            expect(codes, id).not.toBe('');
            for (const code of codes.split(',')) expect(code, id).toMatch(/^PKI_REASON_[A-Z_]+$/);
        }
    });

    it('should keep the totals self-consistent', () => {
        expect(pkits.totals.agree + pkits.totals.deviations).toBe(pkits.totals.scored);
        expect(pkits.totals.deviations).toBe(pkitsIds.length);
        // The 20 skipped are the §4.8 policy tests, whose expected result
        // depends on a `user-initial-policy-set` the archive does not state.
        expect(pkits.totals.skipped).toBeGreaterThan(0);
    });

    it('should judge a test only where its own name says what it expects', () => {
        // The one rule the whole PKITS score rests on. A baseline entry for a
        // test whose name says nothing would be a guess wearing a reviewed
        // reason.
        for (const id of [...pkitsIds, ...Object.keys(pkits.reasons)]) {
            expect(expectationOfName(id), id).not.toBeNull();
        }
    });
});
