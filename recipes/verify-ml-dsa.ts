/**
 * Recipe: verify an ML-DSA certificate chain and an ML-DSA CMS message, and
 * read the report on a runtime that has ML-DSA and on one that has not.
 *
 * pkinative implements no signature algorithm: an ML-DSA signature (FIPS 204,
 * RFC 9881, RFC 9882) is verified by the host's Web Crypto, in one call. Hosts
 * are gaining the algorithm release by release — Node.js has it from 24.7,
 * Node.js 22 does not — so the same input has two right answers, and a third
 * that is always wrong:
 *
 *   - `valid: true` where the host verified the signature;
 *   - `PKI_REASON_SIGNATURE_NOT_CHECKED` carrying `PKI_CRYPTO_KEY_UNSUPPORTED`
 *     where the host refused the key. That says nothing about the signature;
 *   - `PKI_REASON_SIGNATURE_INVALID`, which no host gives for these files.
 *
 * Nothing here detects the host. The report says which it was — branch on the
 * reason, never on the runtime's name or version.
 *
 * The certificates and the message were written by OpenSSL 3.5
 * (tests/fixtures/PROVENANCE.md): pkinative signs nothing with ML-DSA.
 */
import { parseCertificate, verifyCertificateChain, verifyCertificateSignature, verifySignedData } from 'pkinative';
import type { PkiReason } from 'pkinative';
import { mlDsaFixture } from './_fixtures.ts';

/** The three readings of a report over an ML-DSA signature. */
function outcome(report: { readonly valid: boolean; readonly reasons: readonly PkiReason[] }): string {
    if (report.valid) return 'verified';
    const [only] = report.reasons;
    const notChecked = report.reasons.length === 1 && only?.code === 'PKI_REASON_SIGNATURE_NOT_CHECKED' && only.errorCode === 'PKI_CRYPTO_KEY_UNSUPPORTED';
    return notChecked ? 'not checked' : `refused: ${report.reasons.map((reason) => reason.code).join(', ')}`;
}

export default async function run(): Promise<Record<string, string>> {
    const quiet = { onDiagnostic: () => undefined };
    const root = parseCertificate(mlDsaFixture('root-ml-dsa-65'), quiet);
    const leaf = parseCertificate(mlDsaFixture('leaf-ml-dsa-44'), quiet);
    const at = Date.UTC(2026, 10, 18);

    // The key kind names the parameter set; the three are different algorithms.
    const keys = `${root.subjectPublicKeyInfo.kind} ${leaf.subjectPublicKeyInfo.kind}`;

    // One call each, exactly as for an RSA or an ECDSA chain.
    const chain = outcome(await verifyCertificateChain({ leaf, trustAnchors: [root], at }));
    const message = outcome(await verifySignedData({ signedData: mlDsaFixture('cms-ml-dsa-44-sha512'), trustAnchors: [root], at }));

    // Decided on every host, without asking it: the leaf was signed "ML-DSA-65",
    // and the leaf's own key is ML-DSA-44. Another parameter set is a plain `false`.
    const wrongParameterSet = await verifyCertificateSignature(leaf, leaf);

    return {
        keys,
        chain,
        message,
        // The two right answers, and the same one for both structures on one host.
        decided: String(chain === 'verified' || chain === 'not checked'),
        sameAnswer: String(chain === message),
        branch: chain === 'verified'
            ? 'this host verifies ML-DSA'
            : 'this host has no ML-DSA: PKI_REASON_SIGNATURE_NOT_CHECKED / PKI_CRYPTO_KEY_UNSUPPORTED',
        wrongParameterSet: String(wrongParameterSet),
    };
}
