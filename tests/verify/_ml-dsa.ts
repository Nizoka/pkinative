/**
 * The ML-DSA fixtures, and a host that verifies ML-DSA — or does not.
 *
 * pkinative implements no signature algorithm, so an ML-DSA verdict is the
 * host's (ADR 0026), and the hosts disagree: Node.js 24.7 and later carry
 * ML-DSA in Web Crypto, Node.js 22 answers `NotSupportedError`. A suite that
 * asserted one verdict would be wrong on one kind of host, so every verdict
 * here is asked three ways:
 *
 * - **on the real host**, under `it.runIf(HOST_HAS_ML_DSA)` for the positive
 *   verdict and under the complementary condition for the refusal — the probe
 *   is one `importKey`, evaluated once per file;
 * - **on a host stubbed to refuse** every ML-DSA key, which is Node.js 22
 *   reproduced on any runtime;
 * - **on a host stubbed to accept**, which records what it was handed. That
 *   proves nothing about ML-DSA arithmetic, and is not meant to: it proves
 *   that everything around the signature holds, and that the key, the
 *   signature and the covered bytes reaching the host are the right ones —
 *   the three values an independent verifier is given.
 *
 * The fixtures were signed by OpenSSL 3.5 and by the authors of RFC 9881, not
 * by anything in this repository (tests/fixtures/PROVENANCE.md).
 */

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { vi } from 'vitest';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import type { Certificate } from '../../src/types/x509-types.js';

const FIXTURES = resolve(import.meta.dirname, '..', 'fixtures', 'ml-dsa');

/** The bytes of `tests/fixtures/ml-dsa/<name>.der`. */
export const mlDsaBytes = (name: string): Uint8Array => new Uint8Array(readFileSync(join(FIXTURES, `${name}.der`)));

/** A fixture certificate, parsed; its diagnostics are another suite's subject. */
export const mlDsaCertificate = (name: string): Certificate => parseCertificate(mlDsaBytes(name), { onDiagnostic: () => undefined });

/** An instant inside every fixture's validity: the day after OpenSSL signed the CMS, the OCSP response and the token. */
export const ML_DSA_AT = Date.UTC(2026, 10, 18);

/** The content the two CMS fixtures sign, and the datum the timestamp token covers. */
export const ML_DSA_CONTENT = new TextEncoder().encode('pkinative ML-DSA CMS fixture\n');

/** The three parameter sets: the fixture of RFC 9881 Appendix C.3, its key kind, its signature OID, the host's name and the signature length of FIPS 204. */
export const ML_DSA_SETS: readonly (readonly [string, string, string, string, number])[] = [
    ['rfc9881-ml-dsa-44', 'ml-dsa-44', '2.16.840.1.101.3.4.3.17', 'ML-DSA-44', 2420],
    ['rfc9881-ml-dsa-65', 'ml-dsa-65', '2.16.840.1.101.3.4.3.18', 'ML-DSA-65', 3309],
    ['rfc9881-ml-dsa-87', 'ml-dsa-87', '2.16.840.1.101.3.4.3.19', 'ML-DSA-87', 4627],
];

const isMlDsa = (algorithm: unknown): boolean => String((algorithm as { readonly name?: unknown }).name).startsWith('ML-DSA-');

/**
 * Whether this host imports an ML-DSA public key — the only detection there
 * is, and the one `importPublicKey` relies on. Await it once, at the top of a
 * test file.
 */
export async function hostImportsMlDsa(): Promise<boolean> {
    const spki = mlDsaCertificate('rfc9881-ml-dsa-44').subjectPublicKeyInfo.der;
    try {
        await crypto.subtle.importKey('spki', spki, { name: 'ML-DSA-44' }, false, ['verify']);
        return true;
    } catch {
        return false;
    }
}

/**
 * Make the host refuse every ML-DSA key, as Node.js 22 does, and leave every
 * other algorithm to it.
 *
 * @returns The function that restores the host.
 */
export function refuseMlDsa(): () => void {
    const real = crypto.subtle.importKey.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format, data, algorithm, extractable, usages) =>
        isMlDsa(algorithm)
            ? Promise.reject(new DOMException('Unrecognized algorithm name', 'NotSupportedError'))
            : real(format as never, data as never, algorithm as never, extractable, usages)) as typeof crypto.subtle.importKey);
    return () => { spy.mockRestore(); };
}

/** One verification a stubbed host was asked for. */
export interface HostVerification {
    /** What `importKey` was told the key is. */
    readonly importName: string;
    readonly format: string;
    readonly spki: Uint8Array;
    readonly extractable: boolean;
    readonly usages: readonly string[];
    /** The whole `verify` algorithm object. */
    readonly verifyParams: unknown;
    readonly signature: Uint8Array;
    readonly data: Uint8Array;
}

/**
 * Make the host accept every ML-DSA key and answer `verdict` to every
 * verification under one, recording each; every other algorithm is left to
 * the real host.
 *
 * @returns The recorded verifications, and the function that restores the host.
 */
export function acceptMlDsa(verdict = true): { readonly verifications: HostVerification[]; readonly restore: () => void } {
    const verifications: HostVerification[] = [];
    const handles = new WeakMap<object, Omit<HostVerification, 'verifyParams' | 'signature' | 'data'>>();
    const realImport = crypto.subtle.importKey.bind(crypto.subtle);
    const realVerify = crypto.subtle.verify.bind(crypto.subtle);
    const importSpy = vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format, data, algorithm, extractable, usages) => {
        if (!isMlDsa(algorithm)) return realImport(format as never, data as never, algorithm as never, extractable, usages);
        const handle = { type: 'public' };
        handles.set(handle, {
            importName: (algorithm as { readonly name: string }).name,
            format: String(format),
            spki: Uint8Array.from(data as Uint8Array),
            extractable,
            usages: [...usages],
        });
        return Promise.resolve(handle);
    }) as typeof crypto.subtle.importKey);
    const verifySpy = vi.spyOn(crypto.subtle, 'verify').mockImplementation(((algorithm, key, signature, data) => {
        const imported = handles.get(key);
        if (imported === undefined) return realVerify(algorithm as never, key, signature as never, data as never);
        verifications.push({ ...imported, verifyParams: algorithm, signature: Uint8Array.from(signature as Uint8Array), data: Uint8Array.from(data as Uint8Array) });
        return Promise.resolve(verdict);
    }) as typeof crypto.subtle.verify);
    return { verifications, restore: () => { importSpy.mockRestore(); verifySpy.mockRestore(); } };
}
