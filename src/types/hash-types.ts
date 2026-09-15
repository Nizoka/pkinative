/**
 * pkinative — Fingerprint types
 * =============================
 * @module types/hash-types
 */

/** The digest algorithms a fingerprint can use, named as Web Crypto names them. */
export type FingerprintAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

/** Options of `formatFingerprint`. */
export interface FormatFingerprintOptions {
    /** Placed between octets; `':'` by default. */
    readonly separator?: string | undefined;
    /** `'upper'` (default) or `'lower'` hexadecimal digits. */
    readonly letterCase?: 'upper' | 'lower' | undefined;
}
