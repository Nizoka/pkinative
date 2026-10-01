import { describe, it, expect } from 'vitest';
import { STEPS } from '../../scripts/gate.ts';

// The gate's step order is load-bearing, and nothing else states why.
// tests/tools/bundle-probe.test.ts reads dist/, so the build has to happen
// before the suites; GATE_REQUIRE_ARTIFACTS is what turns a missing dist/
// there into a failure rather than a skip that quietly proves nothing.

const indexOf = (id: string): number => STEPS.findIndex((s) => s.id === id);

describe('the gate step table', () => {
    it('should build and check dist/ before the suites that read it', () => {
        expect(indexOf('build')).toBeGreaterThanOrEqual(0);
        expect(indexOf('build')).toBeLessThan(indexOf('test:coverage'));
        expect(indexOf('dist-check')).toBeLessThan(indexOf('test:coverage'));
    });

    it('should require artifacts of the coverage run', () => {
        expect(STEPS.find((s) => s.id === 'test:coverage')?.env).toEqual({ GATE: '1', GATE_REQUIRE_ARTIFACTS: '1' });
    });

    it('should run the interoperability matrix with --require-all, as the conformance workflow does', () => {
        // A required tool missing from the release machine fails the gate
        // instead of being skipped (scripts/run-interop.ts reads the variable).
        expect(STEPS.find((s) => s.id === 'interop')?.env).toEqual({ PKINATIVE_INTEROP_REQUIRE_ALL: '1' });
    });

    it('should probe the bundle right after dist-check', () => {
        expect(indexOf('bundle-check')).toBe(indexOf('dist-check') + 1);
        expect(STEPS.find((s) => s.id === 'bundle-check')?.inline, 'bundle-check is an inline step').toBeTypeOf('function');
    });

    it('should run every step of the ci profile in the publish profile too', () => {
        for (const step of STEPS.filter((s) => s.profiles.includes('ci'))) {
            expect(step.profiles, `${step.id} is in ci but not in publish`).toContain('publish');
        }
    });

    it('should give every step a unique id', () => {
        expect(new Set(STEPS.map((s) => s.id)).size).toBe(STEPS.length);
    });
});
