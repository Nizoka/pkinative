import { describe, it, expect } from 'vitest';
import { decideNpmDrift, parseNpmView, PLACEHOLDER, type RegistryState } from '../../scripts/check-npm-drift.js';

// scripts/check-npm-drift.ts reads the registry online; its decision is
// pinned here offline, against registry answers written by hand.

const registry = (latest: string, ...versions: string[]): RegistryState => ({ found: true, distTags: { latest }, versions: versions.length > 0 ? versions : [latest] });

describe('decideNpmDrift', () => {
    it('should pass pre-1.0 when the registry holds the placeholder and nothing else', () => {
        expect(decideNpmDrift('0.8.0', registry(PLACEHOLDER))).toEqual([]);
    });

    it('should fail pre-1.0 on any real 0.x version, even one published under another dist-tag', () => {
        expect(decideNpmDrift('0.8.0', registry('0.8.0', PLACEHOLDER, '0.8.0'))).toEqual([
            expect.stringContaining('pre-1.0 version(s) 0.8.0 reached npm'),
            expect.stringContaining('latest must be the 0.0.1 placeholder'),
        ]);
        const tagged: RegistryState = { found: true, distTags: { latest: PLACEHOLDER, next: '0.9.0' }, versions: [PLACEHOLDER, '0.9.0'] };
        expect(decideNpmDrift('0.9.0', tagged)).toEqual([expect.stringContaining('refusal did not hold')]);
    });

    it('should fail when the name is not reserved at all', () => {
        expect(decideNpmDrift('0.8.0', { found: false })).toEqual([expect.stringContaining('the name is unreserved')]);
    });

    it('should require latest to be the manifest version from 1.0.0, the placeholder staying behind', () => {
        expect(decideNpmDrift('1.0.0', registry('1.0.0', PLACEHOLDER, '1.0.0'))).toEqual([]);
        expect(decideNpmDrift('1.1.0', registry('1.0.0', PLACEHOLDER, '1.0.0'))).toEqual([expect.stringContaining('1.1.0 is not published yet')]);
        expect(decideNpmDrift('1.0.0', registry('1.1.0', PLACEHOLDER, '1.0.0', '1.1.0'))).toEqual([expect.stringContaining('ahead of the manifest')]);
        expect(decideNpmDrift('1.0.0', registry(PLACEHOLDER))).toEqual([expect.stringContaining('1.0.0 is not published yet')]);
    });

    it('should fail on a dist-tag that points at a version the registry does not list', () => {
        expect(decideNpmDrift('0.8.0', { found: true, distTags: { latest: '0.0.2' }, versions: [PLACEHOLDER] })).toEqual([
            expect.stringContaining('dist-tag latest points at 0.0.2'),
            expect.stringContaining('latest must be the 0.0.1 placeholder'),
        ]);
    });
});

describe('parseNpmView', () => {
    it('should read the answer for one version and for several', () => {
        expect(parseNpmView('{"dist-tags":{"latest":"0.0.1"},"versions":"0.0.1"}', '', 0)).toEqual({ found: true, distTags: { latest: '0.0.1' }, versions: ['0.0.1'] });
        expect(parseNpmView('{"dist-tags":{"latest":"1.0.0"},"versions":["0.0.1","1.0.0"]}', '', 0)).toEqual({ found: true, distTags: { latest: '1.0.0' }, versions: ['0.0.1', '1.0.0'] });
    });

    it('should read a 404 as an absent package, and anything else as an error rather than a verdict', () => {
        expect(parseNpmView('{"error":{"code":"E404"}}', 'npm error code E404', 1)).toEqual({ found: false });
        expect(() => parseNpmView('', 'npm error code ETIMEDOUT', 1)).toThrow(/exited 1/);
        expect(() => parseNpmView('{}', '', 0)).toThrow(/no dist-tags/);
    });
});
