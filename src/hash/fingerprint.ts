/**
 * pkinative — Certificate fingerprints
 * ====================================
 * A fingerprint is a digest of the exact DER of a certificate (or of any
 * public object). The synchronous path uses the pure-TypeScript hashes; the
 * asynchronous path uses Web Crypto when the host has it and falls back to the
 * same pure-TypeScript hashes otherwise — both return identical bytes, which
 * the test suite checks against `node:crypto`.
 *
 * @module hash/fingerprint
 */

import { assertBytes, toHex } from '../core/bytes.js';
import type { FingerprintAlgorithm, FormatFingerprintOptions } from '../types/hash-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { WebCryptoHost } from '../types/webcrypto.js';
import { sha1 } from './sha1.js';
import { sha256 } from './sha256.js';
import { sha384, sha512 } from './sha512.js';

const ALGORITHMS: readonly FingerprintAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

function digestFunction(algorithm: FingerprintAlgorithm): (data: Uint8Array) => Uint8Array {
    switch (algorithm) {
        case 'SHA-1': return sha1;
        case 'SHA-256': return sha256;
        case 'SHA-384': return sha384;
        case 'SHA-512': return sha512;
        default:
            throw new PkiError('PKI_INVALID_OPTION', `pkinative: the fingerprint algorithm must be one of ${ALGORITHMS.join(', ')}, got ${String(algorithm)}`);
    }
}

/**
 * Compute a fingerprint synchronously.
 *
 * @param der       The exact encoding to fingerprint, typically `certificate.der`.
 * @param algorithm `'SHA-1'`, `'SHA-256'`, `'SHA-384'` or `'SHA-512'`.
 * @returns The digest octets.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array; `PKI_INVALID_OPTION` for an unknown algorithm.
 */
export function computeFingerprint(der: Uint8Array, algorithm: FingerprintAlgorithm): Uint8Array {
    const hash = digestFunction(algorithm);
    return hash(assertBytes(der, 'computeFingerprint input'));
}

/**
 * Compute a fingerprint through Web Crypto when available, and through the
 * pure-TypeScript hashes otherwise. The result is identical either way.
 *
 * @param der       The exact encoding to fingerprint.
 * @param algorithm `'SHA-1'`, `'SHA-256'`, `'SHA-384'` or `'SHA-512'`.
 * @returns A promise of the digest octets.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION`, synchronously checked before any work.
 */
export async function computeFingerprintAsync(der: Uint8Array, algorithm: FingerprintAlgorithm): Promise<Uint8Array> {
    const hash = digestFunction(algorithm);
    const bytes = assertBytes(der, 'computeFingerprintAsync input');
    const subtle = (globalThis as WebCryptoHost).crypto?.subtle;
    if (subtle !== undefined && typeof subtle.digest === 'function') {
        try {
            return new Uint8Array(await subtle.digest(algorithm, bytes));
        } catch {
            // A host that exposes Web Crypto but refuses the algorithm or the
            // input (some embedded runtimes lack SHA-1): the pure path agrees.
        }
    }
    return hash(bytes);
}

/**
 * Render a digest the way certificate tools display it, e.g. `AB:CD:…`.
 *
 * @param digest  The digest octets.
 * @param options Separator (`':'` by default) and letter case (`'upper'` by default).
 * @returns The formatted fingerprint.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `digest` is not a Uint8Array; `PKI_INVALID_OPTION` for a malformed option.
 */
export function formatFingerprint(digest: Uint8Array, options?: FormatFingerprintOptions): string {
    const bytes = assertBytes(digest, 'formatFingerprint digest');
    const separator = options?.separator ?? ':';
    const letterCase = options?.letterCase ?? 'upper';
    if (typeof separator !== 'string') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: separator must be a string, got ${typeof separator}`);
    }
    if (letterCase !== 'upper' && letterCase !== 'lower') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: letterCase must be 'upper' or 'lower', got ${String(letterCase)}`);
    }
    const hex = toHex(bytes, separator);
    return letterCase === 'upper' ? hex.toUpperCase() : hex;
}
