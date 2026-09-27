import { describe, it, expect } from 'vitest';
import { DEFAULT_PKI_LIMITS, enforceLimit, resolveLimits } from '../../src/core/pki-limits.js';
import { PkiLimitError } from '../../src/types/pki-errors.js';

function thrown(fn: () => unknown): PkiLimitError {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiLimitError) return err;
        throw err;
    }
    throw new Error('expected a PkiLimitError');
}

describe('DEFAULT_PKI_LIMITS', () => {
    it('should be frozen and hold the documented defaults', () => {
        expect(Object.isFrozen(DEFAULT_PKI_LIMITS)).toBe(true);
        expect(DEFAULT_PKI_LIMITS).toEqual({
            maxInputBytes: 67_108_864,
            maxDepth: 64,
            maxNodes: 200_000,
            maxIntegerBytes: 8192,
            maxOidBytes: 256,
            maxBerSegments: 10_000,
            maxPemBlocks: 10_000,
            maxExtensions: 256,
            maxGeneralNames: 10_000,
            maxNameAttributes: 1024,
            maxPolicies: 1024,
            maxChainLength: 10,
            maxPolicyNodes: 4096,
            maxRevokedCertificates: 1_000_000,
            maxOcspResponses: 256,
        });
    });
});

describe('resolveLimits', () => {
    it('should return the defaults themselves when there is no override', () => {
        expect(resolveLimits(undefined)).toBe(DEFAULT_PKI_LIMITS);
    });

    it('should merge overrides over the defaults into a new frozen object', () => {
        const limits = resolveLimits({ maxDepth: 8, maxNodes: Infinity });
        expect(limits).toMatchObject({ maxDepth: 8, maxNodes: Infinity, maxOidBytes: 256 });
        expect(Object.isFrozen(limits)).toBe(true);
        expect(DEFAULT_PKI_LIMITS.maxDepth).toBe(64);
    });

    it('should ignore keys whose value is undefined', () => {
        expect(resolveLimits({ maxDepth: undefined } as unknown as Partial<typeof DEFAULT_PKI_LIMITS>)).toMatchObject({ maxDepth: 64 });
    });

    it('should refuse an unknown key and name the valid ones', () => {
        const err = thrown(() => resolveLimits({ maxDepht: 3 } as unknown as Partial<typeof DEFAULT_PKI_LIMITS>));
        expect(err.code).toBe('PKI_LIMIT_INVALID');
        expect(err.limit).toBe('maxDepht');
        expect(err.message).toContain('valid keys are');
        expect(Number.isNaN(err.configured) && Number.isNaN(err.observed)).toBe(true);
    });

    it.each([0, -1, 1.5, NaN, -Infinity, '10', null])('should refuse the value %s', (value) => {
        const err = thrown(() => resolveLimits({ maxDepth: value } as unknown as Partial<typeof DEFAULT_PKI_LIMITS>));
        expect(err.code).toBe('PKI_LIMIT_INVALID');
        expect(err.limit).toBe('maxDepth');
    });

    it.each([null, 5, 'x', [1]])('should refuse a limits option that is not an object (%s)', (value) => {
        const err = thrown(() => resolveLimits(value as unknown as Partial<typeof DEFAULT_PKI_LIMITS>));
        expect(err).toMatchObject({ code: 'PKI_LIMIT_INVALID', limit: 'limits' });
    });
});

describe('enforceLimit', () => {
    it('should accept a value equal to the bound', () => {
        expect(() => enforceLimit(DEFAULT_PKI_LIMITS, 'maxDepth', 64, 'nesting depth')).not.toThrow();
    });

    it('should throw PKI_LIMIT_EXCEEDED above the bound, naming the limit and the remedy', () => {
        const err = thrown(() => enforceLimit(DEFAULT_PKI_LIMITS, 'maxDepth', 65, 'nesting depth'));
        expect(err).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxDepth', configured: 64, observed: 65 });
        expect(err.message).toBe('pkinative: nesting depth (65) exceeds limits.maxDepth (64) — raise limits.maxDepth explicitly if this input is trusted');
    });

    it('should never throw under an Infinity bound', () => {
        expect(() => enforceLimit(resolveLimits({ maxNodes: Infinity }), 'maxNodes', Number.MAX_SAFE_INTEGER, 'nodes')).not.toThrow();
    });
});
