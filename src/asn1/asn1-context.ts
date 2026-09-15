/**
 * pkinative — ASN.1 operation context
 * ===================================
 * One context per public call: the validated options, the resolved limits and
 * the diagnostics channel. Internal functions receive it by parameter, so a
 * certificate parse shares one node budget and one diagnostics list across the
 * decoder, the value readers and the structure parser.
 *
 * @module asn1/asn1-context
 */

import { berConstructAcceptedDiagnostic, createDiagnosticEmitter } from '../core/pki-diagnostics.js';
import { resolveLimits } from '../core/pki-limits.js';
import { PkiError } from '../types/pki-errors.js';
import type { EncodingRules, PkiDiagnosticEmitter, PkiLimits, PkiParseOptions } from '../types/pki-types.js';

export interface Asn1Context {
    readonly rules: EncodingRules;
    readonly limits: PkiLimits;
    readonly emitter: PkiDiagnosticEmitter;
    /** BER constructs already reported in this operation (one diagnostic per construct). */
    readonly berReported: Set<string>;
    /** Values decoded so far in this operation, against `limits.maxNodes`. */
    nodes: number;
}

/**
 * Validate options and build the context of one operation.
 *
 * @throws {PkiError} `PKI_INVALID_OPTION` for a malformed option.
 * @throws {PkiLimitError} `PKI_LIMIT_INVALID` for a malformed limits override.
 */
export function createAsn1Context(options: PkiParseOptions | undefined): Asn1Context {
    if (options !== undefined && (typeof options !== 'object' || options === null)) {
        throw new PkiError('PKI_INVALID_OPTION', 'pkinative: options must be an object — pass { encodingRules, limits, strict, onDiagnostic } or omit it');
    }
    const rules = options?.encodingRules ?? 'der';
    if (rules !== 'der' && rules !== 'ber') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: encodingRules must be 'der' or 'ber', got ${String(rules)}`);
    }
    if (options?.strict !== undefined && typeof options.strict !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: strict must be a boolean, got ${typeof options.strict}`);
    }
    if (options?.onDiagnostic !== undefined && typeof options.onDiagnostic !== 'function') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: onDiagnostic must be a function, got ${typeof options.onDiagnostic}`);
    }
    return {
        rules,
        limits: resolveLimits(options?.limits),
        emitter: createDiagnosticEmitter(options?.strict, options?.onDiagnostic),
        berReported: new Set<string>(),
        nodes: 0,
    };
}

/**
 * Record that a BER-only construct was accepted. Callers have already thrown
 * under DER; this reports the tolerance once per construct per operation.
 */
export function noteBer(ctx: Asn1Context, construct: string, offset: number): void {
    if (ctx.berReported.has(construct)) return;
    ctx.berReported.add(construct);
    ctx.emitter.emit(berConstructAcceptedDiagnostic(construct, offset));
}
