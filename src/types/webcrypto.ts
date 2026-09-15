/**
 * pkinative — Minimal Web Crypto types
 * ====================================
 * The library targets ES2020 without the DOM lib, so the handful of Web
 * Crypto members it uses are typed here, structurally, instead of pulling a
 * host's global declarations into the public types. Access always goes
 * through `globalThis` and is checked at run time: a host without Web Crypto
 * gets the pure-TypeScript path, never an exception.
 *
 * @module types/webcrypto
 */

/** The `crypto.subtle` members pkinative calls. */
export interface SubtleDigest {
    digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
}

/** The shape of `globalThis` as far as Web Crypto is concerned. */
export interface WebCryptoHost {
    readonly crypto?: { readonly subtle?: Partial<SubtleDigest> | undefined } | undefined;
}
