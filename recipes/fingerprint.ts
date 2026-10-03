/**
 * Recipe: certificate fingerprints — synchronous everywhere, or through Web
 * Crypto when the host has it — with the same bytes either way, formatted
 * the way certificate tools and pinning configurations write them; and
 * SHAKE256 at the output length the caller names, the digest of an Ed448
 * CMS signer (RFC 8419 §3.1), which Web Crypto does not compute.
 */
import { computeFingerprint, computeFingerprintAsync, formatFingerprint, shake256 } from 'pkinative';
import { fixture } from './_fixtures.ts';

export default async function run(): Promise<Record<string, string>> {
    const der = fixture('isrg-root-x1');
    const sync = computeFingerprint(der, 'SHA-256');
    const viaWebCrypto = await computeFingerprintAsync(der, 'SHA-256');
    // 64 octets: what the messageDigest attribute of an Ed448 signer holds for
    // this content — and the `contentDigest` to pass verifySignedData for a
    // detached one.
    const shake = shake256(der, 64);
    return {
        sha256: formatFingerprint(sync),
        pin: formatFingerprint(sync, { separator: '', letterCase: 'lower' }),
        sameBytes: String(formatFingerprint(viaWebCrypto) === formatFingerprint(sync)),
        sha1: formatFingerprint(computeFingerprint(der, 'SHA-1')),
        shake256: formatFingerprint(shake, { separator: '', letterCase: 'lower' }),
        shake256Prefix: String(formatFingerprint(shake256(der, 32), { separator: '' }) === formatFingerprint(shake.subarray(0, 32), { separator: '' })),
    };
}
