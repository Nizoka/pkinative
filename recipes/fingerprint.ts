/**
 * Recipe: certificate fingerprints — synchronous everywhere, or through Web
 * Crypto when the host has it — with the same bytes either way, formatted
 * the way certificate tools and pinning configurations write them.
 */
import { computeFingerprint, computeFingerprintAsync, formatFingerprint } from 'pkinative';
import { fixture } from './_fixtures.ts';

export default async function run(): Promise<Record<string, string>> {
    const der = fixture('isrg-root-x1');
    const sync = computeFingerprint(der, 'SHA-256');
    const viaWebCrypto = await computeFingerprintAsync(der, 'SHA-256');
    return {
        sha256: formatFingerprint(sync),
        pin: formatFingerprint(sync, { separator: '', letterCase: 'lower' }),
        sameBytes: String(formatFingerprint(viaWebCrypto) === formatFingerprint(sync)),
        sha1: formatFingerprint(computeFingerprint(der, 'SHA-1')),
    };
}
