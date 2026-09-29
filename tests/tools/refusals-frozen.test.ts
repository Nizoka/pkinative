import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { planRefusalsFrozen, releaseRefusalsMode, type Reader, type RefusalsMode } from '../../scripts/build-refusals-frozen.js';
import {
    decisionSurfaceSection, diffRefusals, parseRefusalBaseline, parseRefusalsFrozen, renderRefusalsFrozen,
    REFUSAL_BASELINE, REFUSALS_FROZEN, type RefusalsFrozen,
} from '../../scripts/lib/refusals-frozen.js';

/**
 * scripts/build-refusals-frozen.ts: the decision surface of ADR 0014 written
 * only in the ways the record allows — retaken while unreleased, rebased at a
 * major only if the rehearsal held, ratcheted at a 1.x release only over
 * additions, and re-pinned only with an ADR when a promised certificate left
 * the corpus.
 */

const ROOT = resolve(import.meta.dirname, '..', '..');
const fsReader: Reader = (path) => (existsSync(join(ROOT, path)) ? readFileSync(join(ROOT, path), 'utf8') : null);

const C1 = '1'.repeat(40);
const C2 = '2'.repeat(40);
const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);
const ADR = 'docs/adr/0099-re-pin.md';

const baseline = (refusals: Record<string, string>, commit = C1): string => JSON.stringify({ $comment: 'test', corpus: 'x509-limbo', commit, refusals });
const snapshot = (s: Partial<RefusalsFrozen> = {}): string => renderRefusalsFrozen({
    frozenAt: '0.9.0', phase: 'rehearsal', asOf: '0.9.0', corpus: 'x509-limbo', commit: C1,
    refusals: [{ sha256: A, code: 'PKI_X' }, { sha256: B, code: 'PKI_Y' }], ...s,
});
const STABLE = snapshot({ frozenAt: '1.0.0', phase: 'stable', asOf: '1.0.0' });
const tree = (files: Record<string, string | null>): Reader => (path) => files[path] ?? null;
const plan = (base: string, snap: string | null, version: string, mode: RefusalsMode, extra: Record<string, string> = {}): ReturnType<typeof planRefusalsFrozen> =>
    planRefusalsFrozen(tree({ [REFUSAL_BASELINE]: base, [REFUSALS_FROZEN]: snap, ...extra }), version, mode);
const written = (p: ReturnType<typeof planRefusalsFrozen>): RefusalsFrozen => {
    const parsed = parseRefusalsFrozen(p.text ?? '');
    if ('problems' in parsed) throw new Error(parsed.problems.join('; '));
    return parsed.snapshot;
};
const HELD = baseline({ [A]: 'PKI_X', [B]: 'PKI_Y' });

describe('planRefusalsFrozen', () => {
    it('should be in sync with the committed snapshot and baseline', () => {
        const version = (JSON.parse(fsReader('package.json') ?? '{}') as { version: string }).version;
        expect(planRefusalsFrozen(fsReader, version, { kind: 'default' }).action).toBe('unchanged');
    });

    it('should retake the snapshot while it is unreleased, and refuse once it is', () => {
        const moved = baseline({ [A]: 'PKI_X', [B]: 'PKI_Y', [C]: 'PKI_Z' });
        expect(plan(moved, snapshot(), '0.8.0', { kind: 'default' }).action).toBe('write');
        expect(plan(moved, snapshot(), '0.9.0', { kind: 'default' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('rehearsal admits no change') });
    });

    it('should write a rehearsal snapshot from nothing below 1.0.0, and never a stable one', () => {
        expect(written(plan(HELD, null, '0.9.0', { kind: 'default' }))).toMatchObject({ phase: 'rehearsal', frozenAt: '0.9.0', commit: C1 });
        expect(plan(HELD, null, '1.0.0', { kind: 'default' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('--major') });
    });

    it('should rebase at 1.0.0 only if the rehearsal held', () => {
        const rebased = written(plan(HELD, snapshot(), '1.0.0', { kind: 'major', version: '1.0.0' }));
        expect(rebased).toMatchObject({ phase: 'stable', frozenAt: '1.0.0', asOf: '1.0.0' });
        expect(rebased.refusals.map((r) => r.sha256)).toEqual([A, B]);
        expect(plan(baseline({ [A]: 'PKI_X' }), snapshot(), '1.0.0', { kind: 'major', version: '1.0.0' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('1 lifted') });
        expect(plan(baseline({ [A]: 'PKI_X', [B]: 'PKI_Y' }, C2), snapshot(), '1.0.0', { kind: 'major', version: '1.0.0' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('re-pinned') });
        expect(plan(HELD, snapshot(), '0.9.1', { kind: 'major', version: '1.0.0' }).action).toBe('refuse');
        expect(plan(HELD, STABLE, '1.0.0', { kind: 'major', version: '1.0.0' }).action).toBe('refuse');
    });

    it('should ratchet a new refusal in with the release as its since, and refuse over a lifted or recoded one', () => {
        const ratcheted = written(plan(baseline({ [A]: 'PKI_X', [B]: 'PKI_Y', [C]: 'PKI_Z' }), STABLE, '1.1.0', { kind: 'ratchet' }));
        expect(ratcheted.asOf).toBe('1.1.0');
        expect(ratcheted.refusals.find((r) => r.sha256 === C)).toEqual({ sha256: C, code: 'PKI_Z', since: '1.1.0' });
        expect(ratcheted.refusals.find((r) => r.sha256 === A)?.since).toBeUndefined();
        expect(plan(baseline({ [A]: 'PKI_X' }), STABLE, '1.1.0', { kind: 'ratchet' })).toMatchObject({ action: 'refuse', message: expect.stringContaining(`${B} (PKI_Y) is no longer refused`) });
        expect(plan(baseline({ [A]: 'PKI_W', [B]: 'PKI_Y' }), STABLE, '1.1.0', { kind: 'ratchet' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('refused with PKI_W, promised PKI_X') });
        expect(plan(baseline({ [A]: 'PKI_X', [B]: 'PKI_Y' }, C2), STABLE, '1.1.0', { kind: 'ratchet' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('--repin') });
        expect(plan(HELD, snapshot(), '0.9.1', { kind: 'ratchet' }).action).toBe('refuse');
        expect(plan(HELD, STABLE, '1.0.0', { kind: 'ratchet' }).action).toBe('unchanged');
    });

    it('should re-pin: carry what the corpus still holds, add its new refusals without a since, and retire a dropped one only on an accepted ADR', () => {
        const repinned = baseline({ [A]: 'PKI_X', [C]: 'PKI_Z' }, C2);
        expect(plan(repinned, STABLE, '1.1.0', { kind: 'repin' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('--adr') });
        expect(plan(repinned, STABLE, '1.1.0', { kind: 'repin', adr: ADR }, { [ADR]: '---\nstatus: proposed\n---\n' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('not an accepted ADR') });
        const moved = written(plan(repinned, STABLE, '1.1.0', { kind: 'repin', adr: ADR }, { [ADR]: '---\nstatus: accepted\n---\n' }));
        expect(moved.commit).toBe(C2);
        expect(moved.refusals).toEqual([{ sha256: A, code: 'PKI_X' }, { sha256: C, code: 'PKI_Z' }]);
        expect(moved.retired).toEqual([{ sha256: B, code: 'PKI_Y', commit: C1, adr: ADR }]);
        expect(written(plan(baseline({ [A]: 'PKI_X', [B]: 'PKI_Y' }, C2), STABLE, '1.1.0', { kind: 'repin' })).retired).toBeUndefined();
        expect(plan(baseline({ [A]: 'PKI_W', [B]: 'PKI_Y' }, C2), STABLE, '1.1.0', { kind: 'repin' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('code change') });
        expect(plan(HELD, STABLE, '1.1.0', { kind: 'repin' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('nothing to re-pin') });
    });

    it('should refuse a malformed snapshot or baseline rather than overwrite it', () => {
        expect(plan('{}', snapshot(), '0.9.0', { kind: 'default' }).action).toBe('refuse');
        expect(plan(HELD, '{"phase":"later"}', '0.9.0', { kind: 'default' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('malformed') });
    });
});

describe('releaseRefusalsMode', () => {
    it('should rebase at a new major, ratchet a stable release, and leave a rehearsal release alone', () => {
        const rehearsal = written(plan(HELD, null, '0.9.0', { kind: 'default' }));
        const stable = written(plan(HELD, snapshot(), '1.0.0', { kind: 'major', version: '1.0.0' }));
        expect(releaseRefusalsMode('1.0.0', rehearsal)).toEqual({ kind: 'major', version: '1.0.0' });
        expect(releaseRefusalsMode('0.9.1', rehearsal)).toBeNull();
        expect(releaseRefusalsMode('1.2.0', stable)).toEqual({ kind: 'ratchet' });
        expect(releaseRefusalsMode('2.0.0', stable)).toEqual({ kind: 'major', version: '2.0.0' });
        expect(releaseRefusalsMode('1.0.0', null)).toBeNull();
    });
});

describe('the snapshot format', () => {
    it('should refuse a since in the rehearsal, a duplicate, and a refusal retired at the commit it is verified at', () => {
        const problems = (text: string): readonly string[] => { const p = parseRefusalsFrozen(text); return 'problems' in p ? p.problems : []; };
        expect(problems(snapshot({ refusals: [{ sha256: A, code: 'PKI_X', since: '0.9.0' }] }))).toEqual([expect.stringContaining('in the rehearsal')]);
        expect(problems(snapshot({ refusals: [{ sha256: A, code: 'PKI_X' }, { sha256: A, code: 'PKI_X' }] }))).toEqual([expect.stringContaining('listed twice')]);
        expect(problems(snapshot({ retired: [{ sha256: C, code: 'PKI_Z', commit: C1, adr: ADR }] }))).toEqual([expect.stringContaining('only by a re-pin')]);
        expect(problems('not json')).toEqual([expect.stringContaining('not JSON')]);
    });

    it('should diff a retired refusal only on a changed code, never as lifted', () => {
        const parsed = parseRefusalsFrozen(snapshot({ commit: C2, retired: [{ sha256: C, code: 'PKI_Z', commit: C1, adr: ADR }] }));
        if ('problems' in parsed) throw new Error(parsed.problems.join('; '));
        const b = parseRefusalBaseline(baseline({ [A]: 'PKI_X', [B]: 'PKI_Y', [C]: 'PKI_W' }, C2));
        if (b === null) throw new Error('baseline');
        expect(diffRefusals(parsed.snapshot, b)).toEqual({ lifted: [], recoded: [{ row: expect.objectContaining({ sha256: C }), now: 'PKI_W' }], added: [] });
    });

    it('should read the decision-surface section of a release note up to the next heading', () => {
        expect(decisionSurfaceSection('# v\n\n### Decision surface\n\n- `aaaa`\n\n## Links\n- `bbbb`\n')).toBe('\n- `aaaa`\n');
        expect(decisionSurfaceSection('# v\n')).toBeNull();
    });
});
