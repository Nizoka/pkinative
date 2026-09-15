/**
 * pkinative — PEM types
 * =====================
 * The decoded shape of RFC 7468 textual encodings.
 *
 * @module types/pem-types
 */

import type { PkiDiagnosticHandler, PkiLimits } from './pki-types.js';

/** One `-----BEGIN label-----` … `-----END label-----` block. */
export interface PemBlock {
    /** The label, e.g. `CERTIFICATE` (may be empty, as RFC 7468 allows). */
    readonly label: string;
    /** The decoded binary payload. */
    readonly bytes: Uint8Array;
    /** RFC 1421 encapsulated headers, in order — only ever non-empty in lax mode. */
    readonly headers: readonly (readonly [name: string, value: string])[];
    /** Character offset of the `-----BEGIN` line in the text. */
    readonly offset: number;
}

/** Options of `decodePem`. */
export interface DecodePemOptions {
    /**
     * `'strict'` (default) accepts the RFC 7468 strict grammar: exact boundary
     * lines, 64-character base64 lines, no headers. `'lax'` also accepts
     * whitespace anywhere in the base64 text, lines of any length and RFC 1421
     * headers, reporting each deviation once as a diagnostic.
     */
    readonly mode?: 'strict' | 'lax' | undefined;
    /** Require every block to carry this label (e.g. `CERTIFICATE`). */
    readonly label?: string | undefined;
    /** Overrides for `maxInputBytes` (text length) and `maxPemBlocks`. */
    readonly limits?: Partial<PkiLimits> | undefined;
    /** Escalate every diagnostic to a thrown `PkiError` with code `PKI_STRICT_DIAGNOSTIC`. */
    readonly strict?: boolean | undefined;
    /** Receive every diagnostic instead of the default once-per-code `console.warn`. */
    readonly onDiagnostic?: PkiDiagnosticHandler | undefined;
}
