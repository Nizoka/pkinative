/**
 * pkinative — Public entry point
 * ==============================
 * The single entry point of the package: everything public is exported from
 * this file, grouped in the category order of
 * `.github/instructions/api-design.instructions.md`. Nothing inside the
 * library imports it (tests/tools/architecture.test.ts).
 *
 * @packageDocumentation
 */

// ── 1. Errors, limits and diagnostics ────────────────────────────────

export { PkiError, PkiEncodingError, PkiCertificateError, PkiLimitError } from './types/pki-errors.js';
export type {
    PkiErrorCode,
    PkiBaseErrorCode,
    PkiEncodingErrorCode,
    PkiCertificateErrorCode,
    PkiLimitErrorCode,
} from './types/pki-errors.js';
export { DEFAULT_PKI_LIMITS } from './core/pki-limits.js';
export type {
    PkiLimits,
    PkiDiagnostic,
    PkiDiagnosticCode,
    PkiDiagnosticSeverity,
    PkiDiagnosticHandler,
    PkiParseOptions,
    EncodingRules,
} from './types/pki-types.js';
