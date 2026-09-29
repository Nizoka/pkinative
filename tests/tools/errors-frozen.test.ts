import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { planErrorsFrozen, renderFrozenSnapshot } from '../../scripts/build-errors-frozen.js';

/**
 * scripts/build-errors-frozen.ts: the error vocabulary written once, before
 * its freeze is released, and ratcheted after — so that a code shipped under
 * the freeze stays a promise, and not only the codes frozen on day one.
 */

const registry = (rows: ReadonlyArray<{ code: string; since: string; class?: string }>): string =>
    JSON.stringify({ errors: rows.map((r) => ({ code: r.code, class: r.class ?? 'PkiError', since: r.since })) });

const BASE = registry([{ code: 'PKI_A', since: '0.1.0' }, { code: 'PKI_B', since: '0.8.0' }]);
const FROZEN = renderFrozenSnapshot(BASE, '0.8.0');

describe('planErrorsFrozen', () => {
    it('should be in sync with the committed snapshot', () => {
        const committed = readFileSync('docs/data/errors.frozen.json', 'utf8');
        const live = readFileSync('docs/data/errors.json', 'utf8');
        expect(planErrorsFrozen(live, committed, '0.8.0', 'default').action).toBe('unchanged');
    });

    it('should rewrite the snapshot while its freeze is unreleased, and refuse once it is', () => {
        const added = registry([{ code: 'PKI_A', since: '0.1.0' }, { code: 'PKI_B', since: '0.8.0' }, { code: 'PKI_C', since: '0.8.0' }]);
        expect(planErrorsFrozen(added, FROZEN, '0.7.0', 'default').action).toBe('write');
        expect(planErrorsFrozen(added, FROZEN, '0.8.0', 'default')).toMatchObject({ action: 'refuse', message: expect.stringContaining('--ratchet') });
    });

    it('should refresh the $comment under the freeze, and still refuse when a code leaves with it', () => {
        const recommented = FROZEN.replace(/"\$comment": "(?:[^"\\]|\\.)*"/, '"$comment": "an older explanation"');
        const same = registry([{ code: 'PKI_A', since: '0.1.0' }, { code: 'PKI_B', since: '0.8.0' }]);
        expect(recommented).not.toBe(FROZEN);
        expect(planErrorsFrozen(same, recommented, '0.9.0', 'default')).toMatchObject({ action: 'write', message: expect.stringContaining('$comment') });
        const removed = registry([{ code: 'PKI_A', since: '0.1.0' }]);
        expect(planErrorsFrozen(removed, recommented, '0.9.0', 'default').action).toBe('refuse');
    });

    it('should ratchet a shipped addition into the snapshot, so that removing it later fails', () => {
        const withC = registry([{ code: 'PKI_A', since: '0.1.0' }, { code: 'PKI_B', since: '0.8.0' }, { code: 'PKI_C', since: '1.1.0' }]);
        const ratcheted = planErrorsFrozen(withC, FROZEN, '1.1.0', 'ratchet');
        expect(ratcheted.action).toBe('write');
        const snapshot = JSON.parse(ratcheted.text ?? '{}') as { frozenAt: string; asOf: string; codes: Array<{ code: string }> };
        expect(snapshot).toMatchObject({ frozenAt: '0.8.0', asOf: '1.1.0' });
        expect(snapshot.codes.map((c) => c.code)).toEqual(['PKI_A', 'PKI_B', 'PKI_C']);
        // In 1.2, PKI_C is gone: the ratchet refuses to record that.
        expect(planErrorsFrozen(BASE, ratcheted.text, '1.2.0', 'ratchet')).toMatchObject({ action: 'refuse', message: expect.stringContaining('PKI_C left the registry') });
    });

    it('should not record a code the release being prepared does not ship yet', () => {
        const future = registry([{ code: 'PKI_A', since: '0.1.0' }, { code: 'PKI_B', since: '0.8.0' }, { code: 'PKI_D', since: '1.3.0' }]);
        const snapshot = JSON.parse(planErrorsFrozen(future, FROZEN, '1.2.0', 'ratchet').text ?? '{}') as { codes: Array<{ code: string }> };
        expect(snapshot.codes.map((c) => c.code)).not.toContain('PKI_D');
    });

    it('should refuse to ratchet before the freeze, or without a snapshot', () => {
        expect(planErrorsFrozen(BASE, FROZEN, '0.7.0', 'ratchet').action).toBe('refuse');
        expect(planErrorsFrozen(BASE, null, '1.0.0', 'ratchet').action).toBe('refuse');
        expect(planErrorsFrozen(BASE, FROZEN, '0.8.0', 'ratchet').action).toBe('unchanged');
    });
});
