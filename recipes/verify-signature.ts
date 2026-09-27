/**
 * Recipe: ask whether an issuer's key actually signed a certificate, and
 * read the three answers apart.
 *
 * `true` and `false` are both answers. A throw is not: it means the
 * question could not be put — no Web Crypto here, an algorithm pkinative
 * does not map, a key the host will not import. Branch on `PkiCryptoError`
 * to tell "the signature does not stand up" from "I could not check".
 *
 * A `true` is one link, not a chain. It says nothing about expiry, trust,
 * revocation, or whether the issuer was entitled to sign — that is
 * RFC 5280 §6, and it arrives in 0.5.
 */
import { canVerify, formatDistinguishedName, parseCertificate, PkiCryptoError, verifyCertificateSignature, verifySelfSignature } from 'pkinative';
import type { VerifyCertificateSignatureOptions } from 'pkinative';
import { fixture } from './_fixtures.ts';

const cn = (cert: { subject: Parameters<typeof formatDistinguishedName>[0] }): string =>
    formatDistinguishedName(cert.subject).split(',')[0] ?? '';

/**
 * The three answers, as one value. `signed` is the verdict when there is
 * one; `code` names the reason there is none. Keeping them apart in the
 * type is what stops "could not check" from being read as "not signed".
 */
async function verify(ask: () => Promise<boolean>): Promise<{ signed: boolean; code: string | undefined }> {
    try {
        return { signed: await ask(), code: undefined };
    } catch (error) {
        if (error instanceof PkiCryptoError) return { signed: false, code: error.code };
        throw error;
    }
}

export default async function run(): Promise<Record<string, string>> {
    const quiet = { onDiagnostic: () => undefined };
    const rootRsa = parseCertificate(fixture('isrg-root-x1'), quiet);
    const rootEc = parseCertificate(fixture('isrg-root-x2'), quiet);
    const intermediateRsa = parseCertificate(fixture('lets-encrypt-r12'), quiet);
    const intermediateEc = parseCertificate(fixture('lets-encrypt-e7'), quiet);

    // Nothing below works without a Web Crypto host. Ask first rather than
    // catching an exception out of a report you are half way through.
    if (!canVerify()) return { available: 'no' };

    // A root is a certificate that signed itself. That is a fact about the
    // bytes, not a reason to trust it: every attacker's root has it too.
    const selfRsa = await verifySelfSignature(rootRsa);
    const selfEc = await verifySelfSignature(rootEc);

    // One link of a chain: did this issuer's key sign this certificate?
    const rsaLink = await verifyCertificateSignature(intermediateRsa, rootRsa);
    const ecLink = await verifyCertificateSignature(intermediateEc, rootEc);

    // The wrong root is a plain `false`, not an error — which is what lets
    // a path builder walk candidate issuers without a try/catch per step.
    const wrongRoot = await verifyCertificateSignature(intermediateRsa, rootEc);

    // The RFC 8410 §10.2 certificate is self-issued by name and its subject
    // key is X25519 — key agreement, not signature. So it is decided, and
    // decided "no": a plain `false`, with nothing thrown.
    const x25519 = await verify(() => verifySelfSignature(parseCertificate(fixture('rfc8410-x25519'), quiet)));

    // The same helper around every call is the shape worth copying. With
    // these six public certificates nothing throws, which is the point of
    // reporting it: `couldNotCheck` stays empty on input a modern runtime
    // can handle, and names the code on input it cannot.
    const couldNotCheck = x25519.code ?? 'none';

    // RFC 5280 §4.1.1.2 requires the two signatureAlgorithm fields to be
    // equal, and only the inner one is signed. A tool that wants to see a
    // mismatch rather than be protected from it can say so.
    const lenient: VerifyCertificateSignatureOptions = { requireAlgorithmMatch: false };
    const stillTrue = await verifyCertificateSignature(intermediateRsa, rootRsa, lenient);

    // A SHA-1 signature is refused rather than answered, and `allowSha1` is the
    // only way past it. Neither boolean would be true: the arithmetic may check
    // out, and a chosen-prefix collision has been practical since 2017, so the
    // signature does not bind the bytes it covers. `PkiCryptoError` is exactly
    // the family for "this question cannot be put", and the path validator turns
    // it into PKI_REASON_SIGNATURE_NOT_CHECKED rather than a silent pass.
    //
    // Turn it on to examine a historical artefact, never to authenticate with
    // one. None of these six fixtures uses SHA-1, so the honest thing this
    // recipe can show is the option's shape and its default.
    const archival: VerifyCertificateSignatureOptions = { allowSha1: true };
    const sha1IsOptIn = archival.allowSha1 === true && new Set<unknown>([undefined, false]).has(lenient.allowSha1);

    return {
        sha1IsOptIn: String(sha1IsOptIn),
        available: 'yes',
        selfSigned: `${cn(rootRsa)}=${String(selfRsa)} ${cn(rootEc)}=${String(selfEc)}`,
        links: `${cn(intermediateRsa)}<-${cn(rootRsa)}=${String(rsaLink)} ${cn(intermediateEc)}<-${cn(rootEc)}=${String(ecLink)}`,
        wrongRoot: String(wrongRoot),
        x25519SelfSignature: String(x25519.signed),
        couldNotCheck,
        lenient: String(stillTrue),
    };
}
