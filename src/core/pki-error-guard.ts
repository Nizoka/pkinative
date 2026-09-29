/**
 * pkinative — The one guard every catch goes through
 * ==================================================
 * Catching in JavaScript catches *everything*. A `catch` that means "this
 * input was malformed" must not also mean "this code has a bug", or a
 * `TypeError` becomes a verdict, a diagnostic, or nothing at all — and reads
 * like a statement about the certificate.
 *
 * So every catch in `src/` that handles a `PkiError` passes the caught value
 * through {@link _pkiError}: a `PkiError` comes back, anything else is thrown
 * on as the bug it is. It lives in `core` because two layers need it —
 * `verify/`, the only one that turns a `PkiError` into a reason, and
 * `revocation/`, which diagnoses and drops the CRL extensions no verdict
 * depends on — and stating the invariant once is what keeps its single
 * coverage exemption single.
 *
 * @internal
 * @module core/pki-error-guard
 */

import { PkiError } from '../types/pki-errors.js';

/**
 * The `PkiError` a layer below threw, or a rethrow of anything else.
 *
 * @internal
 */
export function _pkiError(error: unknown): PkiError {
    /* v8 ignore next -- unreachable: every layer promises that only a PkiError subclass escapes for an input reason, and tests/tools/architecture.test.ts holds the shape that makes that true. The rethrow exists so that a breach of that promise reaches the caller as the bug it is instead of being reported as a fact about their input; no input can reach it. */
    if (!(error instanceof PkiError)) throw error;
    return error;
}
