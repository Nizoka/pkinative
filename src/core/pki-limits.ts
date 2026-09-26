/**
 * pkinative — Security bounds table
 * =================================
 * THE named-limits table every loop over untrusted input consults
 * (.github/instructions/security.instructions.md). Each limit is
 * caller-configurable through `options.limits`; each violation throws
 * `PkiLimitError` naming the limit and the remedy. The table below is
 * mirrored in SECURITY.md and docs/data/limits.json — the `limits-parity`
 * rule of `verify:docs` holds the copies together.
 *
 * | Limit             | Default | CWE     |
 * |-------------------|---------|---------|
 * | maxInputBytes     | 64 MiB  | CWE-400 |
 * | maxDepth          | 64      | CWE-674 |
 * | maxNodes          | 200 000 | CWE-770 |
 * | maxIntegerBytes   | 8 192   | CWE-407 |
 * | maxOidBytes       | 256     | CWE-400 |
 * | maxBerSegments    | 10 000  | CWE-400 |
 * | maxPemBlocks      | 10 000  | CWE-400 |
 * | maxExtensions     | 256     | CWE-400 |
 * | maxGeneralNames   | 10 000  | CWE-400 |
 * | maxNameAttributes | 1 024   | CWE-400 |
 * | maxPolicies       | 1 024   | CWE-400 |
 * | maxChainLength    | 10      | CWE-400 |
 *
 * @module core/pki-limits
 */

import { PkiLimitError } from '../types/pki-errors.js';
import type { PkiLimits } from '../types/pki-types.js';

/** Default security bounds — the safe path for untrusted input. */
export const DEFAULT_PKI_LIMITS: PkiLimits = /*#__PURE__*/ Object.freeze({
    maxInputBytes: 64 * 1024 * 1024,
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
});

/**
 * Merge caller overrides over the defaults — validated before any input is
 * read. Each value must be a positive integer or `Infinity`.
 *
 * @throws {PkiLimitError} `PKI_LIMIT_INVALID` for a non-object override, an unknown key or an invalid value.
 */
export function resolveLimits(overrides: Partial<PkiLimits> | undefined): PkiLimits {
    if (overrides === undefined) return DEFAULT_PKI_LIMITS;
    if (typeof overrides !== 'object' || overrides === null || Array.isArray(overrides)) {
        throw new PkiLimitError('PKI_LIMIT_INVALID',
            'pkinative: options.limits must be an object of named limits — see DEFAULT_PKI_LIMITS for the keys',
            'limits', NaN, NaN);
    }
    const merged: Record<string, number> = { ...DEFAULT_PKI_LIMITS };
    const entries = overrides as Readonly<Record<string, unknown>>;
    for (const key of Object.keys(entries)) {
        const value = entries[key];
        if (value === undefined) continue;
        if (!Object.prototype.hasOwnProperty.call(DEFAULT_PKI_LIMITS, key)) {
            throw new PkiLimitError('PKI_LIMIT_INVALID',
                `pkinative: unknown limit '${key}' — valid keys are ${Object.keys(DEFAULT_PKI_LIMITS).join(', ')}`,
                key, NaN, NaN);
        }
        if (typeof value !== 'number' || !(value > 0) || (value !== Infinity && !Number.isInteger(value))) {
            throw new PkiLimitError('PKI_LIMIT_INVALID',
                `pkinative: limit '${key}' must be a positive integer or Infinity, got ${String(value)}`,
                key, NaN, NaN);
        }
        merged[key] = value;
    }
    return Object.freeze(merged) as unknown as PkiLimits;
}

/**
 * Enforce one limit.
 *
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` when `observed` exceeds the configured bound.
 */
export function enforceLimit(limits: PkiLimits, limit: keyof PkiLimits, observed: number, context: string): void {
    const configured = limits[limit];
    if (observed > configured) {
        throw new PkiLimitError('PKI_LIMIT_EXCEEDED',
            `pkinative: ${context} (${observed}) exceeds limits.${limit} (${configured}) — `
            + `raise limits.${limit} explicitly if this input is trusted`,
            limit, configured, observed);
    }
}
