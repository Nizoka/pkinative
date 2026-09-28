import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
    encodeBitString,
    encodeBoolean,
    encodeExplicit,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeEnumerated,
    encodeNull,
    encodeSequence,
    encodeTime,
    encodeTlv,
} from '../../src/asn1/asn1-encode.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import {
    encodeAlgorithmIdentifier,
    encodeBasicConstraints,
    encodeExtendedKeyUsage,
    encodeKeyUsage,
    encodeSubjectAltName,
} from '../../src/build/build-structures.js';
import { computeKeyIdentifier } from '../../src/hash/key-identifier.js';
import { sha1 } from '../../src/hash/sha1.js';
import { sha256 } from '../../src/hash/sha256.js';
import { KEY_PURPOSES } from '../../src/path/path-purpose.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { verifyCertificateChain } from '../../src/verify/verify-chain.js';
import type { SignatureAlgorithm } from '../../src/types/crypto-types.js';
import type { CryptoKeyHandle } from '../../src/types/webcrypto.js';
import type { Certificate } from '../../src/types/x509-types.js';

/**
 * The composition layer.
 *
 * Every question this call asks is already tested where it is implemented, so
 * what is asserted here is the **composition**: that each question is asked at
 * all, that the answers arrive together rather than one per round trip, and
 * that nothing throws for an input the caller got wrong.
 *
 * The signatures are **real** throughout — no verdict is asserted, every one is
 * computed — which is why the hierarchy is built here: holding all three keys
 * is the only way a test can watch the layer verify a chain end to end. One
 * case runs on the committed Let's Encrypt pair, whose signature was made by
 * somebody else, so that the verification is not being checked against this
 * library's own encoder.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const load = (name: string): Certificate =>
    parseCertificate(new Uint8Array(readFileSync(`tests/fixtures/certs/${name}.der`)), quiet);

const ROOT_X1 = load('isrg-root-x1');
const R12 = load('lets-encrypt-r12');
/** Inside R12's window (2024-03-13 … 2027-03-12) and ISRG Root X1's. */
const AT = Date.UTC(2026, 9, 1);
const DAY = 86_400_000;

const codes = (report: { reasons: ReadonlyArray<{ code: string }> }): string[] => report.reasons.map((r) => r.code);

interface Material { readonly certificate: Certificate; readonly key: CryptoKeyHandle }

/** A certificate signed by a key generated here, and kept so it can sign in turn. */
async function issue(options: {
    readonly subject: string;
    readonly issuerDer: Uint8Array;
    readonly signer?: CryptoKeyHandle;
    readonly ca: boolean;
    readonly serial: bigint;
    readonly purposes?: readonly string[];
    readonly host?: string;
    readonly notAfter?: number;
    /** Sign over SHA-1, which pkinative refuses to treat as evidence. */
    readonly sha1?: boolean;
    /** Add cRLSign, without which a CA may not issue a revocation list. */
    readonly crlSign?: boolean;
}): Promise<Material> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const der = await createCertificate({
        serialNumber: options.serial,
        issuerDer: options.issuerDer,
        subject: [[{ type: '2.5.4.3', value: options.subject }]],
        notBefore: AT - DAY,
        notAfter: options.notAfter ?? AT + DAY,
        subjectPublicKey: spki,
        extensions: [
            ...(options.ca
                ? [
                    { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
                    { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(options.crlSign === true ? ['keyCertSign', 'cRLSign'] : ['keyCertSign']) },
                ]
                : [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) }]),
            ...(options.purposes === undefined ? [] : [{ oid: '2.5.29.37', value: encodeExtendedKeyUsage([...options.purposes]) }]),
            ...(options.host === undefined ? [] : [{ oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: options.host }]) }]),
        ],
    }, { key: options.signer ?? pair.privateKey, algorithm: { name: 'ECDSA', hash: options.sha1 === true ? 'SHA-1' : 'SHA-256', namedCurve: 'P-256' } });
    return { certificate: parseCertificate(der, quiet), key: pair.privateKey };
}

/** root → ica → leaf, every signature real, the leaf naming `leaf.example`. */
async function hierarchy(overrides: { leafNotAfter?: number; crlSign?: boolean } = {}): Promise<{ root: Certificate; ica: Certificate; leaf: Certificate }> {
    const rootName = encodeSequence([]);
    const root = await issue({ subject: 'Verify Root', issuerDer: rootName, ca: true, serial: 1n });
    const realRoot = await issue({ subject: 'Verify Root', issuerDer: root.certificate.subject.der, signer: root.key, ca: true, serial: 1n });
    const ica = await issue({
        subject: 'Verify ICA', issuerDer: realRoot.certificate.subject.der, signer: realRoot.key, ca: true, serial: 2n,
        ...(overrides.crlSign === undefined ? {} : { crlSign: overrides.crlSign }),
    });
    const leaf = await issue({
        subject: 'leaf.example', issuerDer: ica.certificate.subject.der, signer: ica.key, ca: false, serial: 3n,
        purposes: [KEY_PURPOSES.serverAuth], host: 'leaf.example',
        ...(overrides.leafNotAfter === undefined ? {} : { notAfter: overrides.leafNotAfter }),
    });
    return { root: realRoot.certificate, ica: ica.certificate, leaf: leaf.certificate };
}

describe('verifyCertificateChain', () => {
    it('should accept a sound chain for the host it names', async () => {
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            purposes: [KEY_PURPOSES.serverAuth],
        });
        expect(codes(report)).toEqual([]);
        expect(report.valid).toBe(true);
        expect(report.path).toHaveLength(3);
    });

    it('should refuse a sound chain for a host it does not name', async () => {
        // The point of the whole layer in one assertion: §6 is perfectly happy
        // and the certificate is for somebody else. A caller who only validated
        // the path would have accepted it.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'bank.example' },
        });
        expect(codes(report)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        // …and the path it judged is the whole one, so the reason is about the
        // name and nothing else.
        expect(report.path).toHaveLength(3);
    });

    it('should verify a signature made by somebody else', async () => {
        // The committed Let's Encrypt pair: R12 really was signed by ISRG Root
        // X1, by a key nothing in this repository holds. A verifier tested only
        // on certificates it built itself is tested against its own encoder.
        const report = await verifyCertificateChain({ leaf: R12, trustAnchors: [ROOT_X1], at: AT });
        expect(codes(report)).toEqual([]);
        expect(report.verified).toBe(1);
    });

    it('should report how many signatures it had to compute', async () => {
        // The cost of the call, and a number far above the path length is what
        // a bag full of plausible issuers looks like.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({ leaf, candidates: [ica], trustAnchors: [root], at: AT });
        expect(report.verified).toBe(2);
        expect(report.explored).toBeGreaterThanOrEqual(1);
    });

    it('should report the chain, the name and the purpose together, not one at a time', async () => {
        // A caller fixing one problem per round trip is a caller the report
        // failed. This chain is expired, for the wrong host, and for a purpose
        // it does not permit — and says all three once.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT + 30 * DAY,
            serverName: { kind: 'dns', value: 'bank.example' },
            purposes: [KEY_PURPOSES.codeSigning],
        });
        expect(codes(report)).toContain('PKI_REASON_EXPIRED');
        expect(codes(report)).toContain('PKI_REASON_NAME_MISMATCH');
        expect(codes(report)).toContain('PKI_REASON_PURPOSE_NOT_PERMITTED');
    });

    it('should say the purpose once when the search refused for it', async () => {
        // The search rejects a path the purpose forbids, and the composition
        // restates the purpose on the path that was walked. When both fire on
        // the same chain they would say the same thing twice, and a report that
        // repeats itself is one a caller starts skimming.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            purposes: [KEY_PURPOSES.codeSigning],
        });
        expect(codes(report)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
    });

    it('should report NO_TRUST_ANCHOR rather than throw when nothing is trusted', async () => {
        const { ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({ leaf, candidates: [ica], trustAnchors: [], at: AT });
        expect(codes(report)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
    });

    it('should default the instant to now', async () => {
        // The synthetic leaf's window is around AT and long past "now", so
        // omitting `at` must reach the same answer as asking about today.
        const { root, ica, leaf } = await hierarchy();
        const omitted = await verifyCertificateChain({ leaf, candidates: [ica], trustAnchors: [root] });
        const explicit = await verifyCertificateChain({ leaf, candidates: [ica], trustAnchors: [root], at: Date.now() });
        expect(codes(omitted)).toEqual(codes(explicit));
    });

    it('should take the purpose into the search rather than apply it afterwards', async () => {
        // Two intermediates of the same name, one restricted to signing e-mail
        // and listed first. A layer that checked the purpose after choosing a
        // path would answer "not permitted" while an acceptable path existed.
        const root = await issue({ subject: 'Purpose Root', issuerDer: encodeSequence([]), ca: true, serial: 10n });
        const realRoot = await issue({ subject: 'Purpose Root', issuerDer: root.certificate.subject.der, signer: root.key, ca: true, serial: 10n });
        const restricted = await issue({ subject: 'Shared ICA', issuerDer: realRoot.certificate.subject.der, signer: realRoot.key, ca: true, serial: 11n, purposes: [KEY_PURPOSES.emailProtection] });
        const open = await issue({ subject: 'Shared ICA', issuerDer: realRoot.certificate.subject.der, signer: realRoot.key, ca: true, serial: 12n });
        // Signed by the *open* intermediate, but naming a subject both share —
        // so the builder meets the restricted one first and has to look past it.
        const leaf = await issue({
            subject: 'leaf.example', issuerDer: open.certificate.subject.der, signer: open.key, ca: false, serial: 13n,
            purposes: [KEY_PURPOSES.serverAuth], host: 'leaf.example',
        });

        const report = await verifyCertificateChain({
            leaf: leaf.certificate,
            candidates: [restricted.certificate, open.certificate],
            trustAnchors: [realRoot.certificate],
            at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            purposes: [KEY_PURPOSES.serverAuth],
        });
        expect(codes(report)).toEqual([]);
        expect(report.valid).toBe(true);
    });
});

describe('verifyCertificateChain — the one place that catches', () => {
    it('should report a malformed CRL as a reason carrying the error code', async () => {
        // The rule the whole library runs on: primitives return and throw,
        // compositions report, and exactly one layer converts. This is it, and
        // PKI_REASON_INPUT_MALFORMED is how a report promises never to throw
        // for bad input without copying the encoding vocabulary into a second
        // registry that would then have to be frozen too.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [Uint8Array.of(0x30, 0x80, 0x00)],
        });
        expect(codes(report)).toContain('PKI_REASON_INPUT_MALFORMED');
        const malformed = report.reasons.find((r) => r.code === 'PKI_REASON_INPUT_MALFORMED');
        expect(malformed?.errorCode).toMatch(/^PKI_/);
        expect(malformed?.path).toBe('crl[0]');
    });

    it('should say nothing about revocation when no list was supplied', async () => {
        // Soft-fail is the default, because the alternative refuses every chain
        // for which the caller happened not to download a list — which is a
        // library callers route around.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
        });
        expect(codes(report)).toEqual([]);
    });

    it('should report UNKNOWN when the caller asked for revocation and gave no list', async () => {
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should report UNKNOWN when every supplied list is about another CA', async () => {
        // A list nobody in this chain issued is skipped in silence — a caller
        // handing over every list they hold is the ordinary case — but with
        // `requireRevocation` the absence of a covering one is an answer.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(root)], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should consult a list that does cover the certificate', async () => {
        // Issued by the certificate's own CA, so it is consulted — and its
        // signature was never checked against that CA's key here, which is
        // UNKNOWN rather than "not revoked": an unsigned list is not evidence.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica)],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });
});

describe('verifyCertificateChain — what it passes through', () => {
    it('should pass every §6.1.1 initial setting to the walk', async () => {
        // The four initial-policy inputs and the limits are the caller's, and a
        // composition that quietly dropped them would be a validator running
        // under settings nobody chose. requireExplicitPolicy is the visible one:
        // this chain establishes no certificate policy, so turning it on is the
        // difference between accepted and NO_VALID_POLICY.
        const { root, ica, leaf } = await hierarchy();
        const common = { leaf, candidates: [ica], trustAnchors: [root], at: AT } as const;
        expect(codes(await verifyCertificateChain(common))).toEqual([]);
        const strictPolicy = await verifyCertificateChain({
            ...common,
            initialPolicySet: ['2.23.140.1.2.1'],
            requireExplicitPolicy: true,
            inhibitPolicyMapping: true,
            inhibitAnyPolicy: true,
            limits: { maxPathsExplored: 50 },
        });
        expect(codes(strictPolicy)).toEqual(['PKI_REASON_NO_VALID_POLICY']);
    });

    it('should throw for API misuse, which is not a verification issue', async () => {
        const { root, ica, leaf } = await hierarchy();
        await expect(verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            limits: { maxPathsExploredd: 3 } as never,
        })).rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_INVALID' }));
    });

    it('should silence the diagnostics of a list it parses, and still report its verdict', async () => {
        // A CRL is read to answer one question, and its profile concerns are
        // not this report's business — a caller who wants them calls
        // parseCertificateList themselves. This list dates itself with a
        // GeneralizedTime before 2050, which RFC 5280 §4.1.2.5 says must be a
        // UTCTime, so parsing it does emit a diagnostic. What must survive is
        // the verdict.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica, { oddExtension: true })],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should report NOT_CHECKED, never INVALID, for a signature it refuses to weigh', async () => {
        // Signed over SHA-1, whose collisions have been practical since 2017.
        // Neither boolean is honest, so verifyCertificateSignature throws — and
        // this layer is where that becomes a reason a reader can act on rather
        // than an exception a caller has to catch.
        const root = await issue({ subject: 'Legacy Root', issuerDer: encodeSequence([]), ca: true, serial: 20n });
        const realRoot = await issue({ subject: 'Legacy Root', issuerDer: root.certificate.subject.der, signer: root.key, ca: true, serial: 20n });
        const leaf = await issue({
            subject: 'legacy.example', issuerDer: realRoot.certificate.subject.der, signer: realRoot.key,
            ca: false, serial: 21n, host: 'legacy.example', sha1: true,
        });
        const report = await verifyCertificateChain({
            leaf: leaf.certificate, trustAnchors: [realRoot.certificate], at: AT,
        });
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_NOT_CHECKED');
        expect(codes(report)).not.toContain('PKI_REASON_SIGNATURE_INVALID');
        const notChecked = report.reasons.find((r) => r.code === 'PKI_REASON_SIGNATURE_NOT_CHECKED');
        expect(notChecked?.errorCode).toBe('PKI_CRYPTO_ALGORITHM_REFUSED');
        // …and the caller who is reading an archival artefact can say so.
        const archival = await verifyCertificateChain({
            leaf: leaf.certificate, trustAnchors: [realRoot.certificate], at: AT, allowSha1: true,
        });
        expect(codes(archival)).toEqual([]);
    });

    it('should report a list whose signature check could not be put', async () => {
        // The CRL here is signed over SHA-1, which pkinative refuses to treat as
        // evidence. That is "never checked", not "checked and wrong", and
        // checkRevocation words the two differently.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica, { sha1: true })],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should refuse a list from a CA that may not issue one', async () => {
        // RFC 5280 §4.2.1.3: a CA that issues CRLs MUST assert `cRLSign`. The
        // hierarchy here gives its intermediates `keyCertSign` and nothing else,
        // so its list is not evidence whatever the arithmetic says — accepting
        // it would let a CA constrained to signing certificates revoke them
        // instead. `signatureVerified: false` is the exact answer, because the
        // field asks whether a key **entitled** to sign it did.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica)],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
        expect(report.reasons.find((r) => r.code === 'PKI_REASON_REVOCATION_UNKNOWN')?.message)
            .toMatch(/signature|signed/i);
    });

    it('should check the signature of a list its CA was entitled to issue', async () => {
        // With `cRLSign` present the entitlement question is answered yes and
        // the arithmetic one is actually put. This list is signed by nobody, so
        // the answer is "checked and wrong" — which is still UNKNOWN rather than
        // "not revoked", because an unsigned list is not evidence and pretending
        // otherwise lets anyone publish one.
        const { root, ica, leaf } = await hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica)],
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should report NOT CHECKED rather than forged for a list signed over SHA-1', async () => {
        // The entitlement holds, the arithmetic is refused: neither boolean is
        // honest about a SHA-1 signature, so the question was never put.
        const { root, ica, leaf } = await hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica, { sha1: true })],
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        // …and saying so is allowed when the caller is reading an archive.
        const archival = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica, { sha1: true })], allowSha1: true,
        });
        expect(codes(archival)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should believe an OCSP response the CA signed itself', async () => {
        // The simple half of RFC 6960 §4.2.2.2, and the only one needing no
        // extra certificate: the CA that issued the certificate answered about
        // it. `good` with a fresh window is a clean answer and says nothing.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey } });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should report REVOKED from a response the CA signed', async () => {
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const revoked = encodeExplicit(1, encodeTime(AT - 30 * DAY, 'GeneralizedTime'), { tagClass: 'context' });
        const response = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey }, status: revoked });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOKED');
    });

    it('should believe a delegate the CA actually issued and marked as a responder', async () => {
        // The other half: the CA delegated by issuing a certificate that
        // carries id-kp-OCSPSigning, and that certificate signed the response.
        // The delegate is attached to the response, which is where a real
        // responder puts it.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const delegate = await issueEd25519({
            subject: 'OCSP Responder', issuerDer: ica.subject.der, signer: icaKey,
            purposes: [OCSP_SIGNING],
        });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: delegate.key, certificates: [delegate.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should refuse a responder that nominated itself', async () => {
        // A certificate the response *attached* is a convenience for reaching
        // the delegate, never a claim of authority. This one has the purpose
        // and signs the response, and the CA never issued it — which is exactly
        // what §4.2.2.2 exists to stop, and what a client that trusted the
        // attached bag would accept.
        const { root, ica, leaf } = await ed25519Hierarchy();
        const impostor = await issueEd25519({
            subject: 'OCSP Responder', issuerDer: ica.subject.der, signer: undefined,
            purposes: [OCSP_SIGNING],
        });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: impostor.key, certificates: [impostor.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should refuse a delegate the CA issued without the purpose', async () => {
        // Issued by the right CA, signs the response, and was never marked as a
        // responder. Accepting it would let any certificate a CA ever issued
        // answer for every certificate that CA ever issued.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const ordinary = await issueEd25519({ subject: 'Ordinary Leaf', issuerDer: ica.subject.der, signer: icaKey });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: ordinary.key, certificates: [ordinary.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should report an answer about somebody else as a mismatch, not a status', async () => {
        // A response may carry several answers, and taking the first is how a
        // client reads somebody else's status as its own. All three CertID
        // fields have to match.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({
            certificate: leaf, issuer: ica, signer: { key: icaKey }, serial: Uint8Array.of(0x7f),
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_MISMATCH');
    });

    it('should report a responder that declined to answer at all', async () => {
        // The six non-successful statuses carry no body — the protocol has
        // nowhere to put one — so there is nothing to match and the answer is
        // the refusal itself.
        const { root, ica, leaf } = await ed25519Hierarchy();
        const declined = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: (await ed25519Key()).privateKey }, statusCode: 3 });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [declined],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should compute the expected CertID under the digest the responder used', async () => {
        // A response may use SHA-256, which RFC 6960 §4.3 allows. Computing the
        // expected values under the wrong digest turns every answer into a
        // mismatch, so the algorithm is read from the answer about our serial.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey }, sha256: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should match a nonce that comes back and miss one that does not', async () => {
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const nonce = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
        const common = {
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' }, ocspNonce: nonce,
        } as const;
        const echoed = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey }, nonce });
        expect(codes(await verifyCertificateChain({ ...common, ocsp: [echoed] }))).toEqual([]);

        // A different nonce is always a mismatch; a missing echo is reported
        // only when asked, because most public responders omit it on purpose.
        const other = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey }, nonce: Uint8Array.of(9, 9) });
        expect(codes(await verifyCertificateChain({ ...common, ocsp: [other] }))).toContain('PKI_REASON_REVOCATION_MISMATCH');

        const silent = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey } });
        expect(codes(await verifyCertificateChain({ ...common, ocsp: [silent] }))).toEqual([]);
        expect(codes(await verifyCertificateChain({ ...common, ocsp: [silent], requireOcspNonce: true })))
            .toContain('PKI_REASON_REVOCATION_MISMATCH');
    });

    it('should ignore an attached certificate it cannot use, and still refuse', async () => {
        // Two hints a responder can attach and neither of them authority: a
        // well-formed SEQUENCE that is not a certificate, and a certificate
        // another CA issued. Each is skipped, and skipping is right — an
        // attached certificate was a convenience for reaching the delegate, so
        // an unusable one is a hint that did not help rather than a reason to
        // refuse. Neither makes the response evidence.
        const { root, ica, leaf } = await ed25519Hierarchy();
        const elsewhere = await issueEd25519({ subject: 'Other Responder', issuerDer: root.subject.der, signer: undefined, purposes: [OCSP_SIGNING] });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: elsewhere.key, certificates: [encodeSequence([]), elsewhere.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should refuse a delegate whose own window has closed', async () => {
        // A responder certificate is a certificate: the CA marked it, and the
        // marking expires. Accepting an expired delegate would let a retired
        // responder keep answering.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const retired = await issueEd25519({
            subject: 'Retired Responder', issuerDer: ica.subject.der, signer: icaKey,
            purposes: [OCSP_SIGNING], notBefore: AT - 400 * DAY, notAfter: AT - 300 * DAY,
        });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: retired.key, certificates: [retired.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should refuse when the authorised delegate is not the one who signed', async () => {
        // Everything about this delegate checks out — issued by the CA, marked
        // as a responder, in date — and somebody else signed the response. An
        // authorised certificate in the bag is not a signature.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const genuine = await issueEd25519({
            subject: 'Genuine Responder', issuerDer: ica.subject.der, signer: icaKey, purposes: [OCSP_SIGNING],
        });
        const stranger = await ed25519Key();
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: stranger.privateKey, certificates: [genuine.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should refuse a response signed under an algorithm it does not map', async () => {
        // "Could not be put" is not "forged". A responder using something this
        // library maps to no Web Crypto algorithm leaves the signature
        // unchecked, and an unchecked signature is not evidence.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({
            certificate: leaf, issuer: ica, signer: { key: icaKey },
            // 1.2.840.113549.1.1.4, md5WithRSAEncryption: in no table here.
            signatureAlgorithm: encodeSequence([encodeObjectIdentifier('1.2.840.113549.1.1.4'), encodeNull()]),
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should refuse a delegate whose own signature cannot be weighed', async () => {
        // The CA signed this responder certificate over SHA-1, so asking
        // whether the CA issued it is a question that cannot be put — and a
        // delegate whose credentials cannot be checked is not a delegate.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ ecdsaIca: true });
        const delegate = await issueEd25519({
            subject: 'Legacy Responder', issuerDer: ica.subject.der, signer: icaKey,
            purposes: [OCSP_SIGNING], signWith: { name: 'ECDSA', hash: 'SHA-1', namedCurve: 'P-256' },
        });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: delegate.key, certificates: [delegate.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should say the answer is not evidence when no issuer was established', async () => {
        // With nothing trusted there is no CA to hash, so no CertID can be
        // computed — and an OCSP answer about a certificate whose issuer was
        // never established is not evidence, whoever signed it.
        const { ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey } });
        const report = await verifyCertificateChain({ leaf, trustAnchors: [], at: AT, ocsp: [response] });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_MISMATCH');
    });

    it('should report a malformed OCSP response as a reason, never an exception', async () => {
        const { root, ica, leaf } = await ed25519Hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocsp: [Uint8Array.of(0x30, 0x80, 0x00)],
        });
        expect(codes(report)).toContain('PKI_REASON_INPUT_MALFORMED');
        expect(report.reasons.find((r) => r.code === 'PKI_REASON_INPUT_MALFORMED')?.path).toBe('ocsp[0]');
    });

    it('should consult a covering list even when the path stopped at the leaf', async () => {
        // No candidates and no anchor, so `path[1]` does not exist and there is
        // no issuer to check the list's signature against. The list still
        // covers the certificate, and an unverifiable list is UNKNOWN.
        const { ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, trustAnchors: [], at: AT, crls: [emptyCrl(ica)],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });
});

// ── OCSP, signed for real ────────────────────────────────────────────

/** `id-kp-OCSPSigning`: the purpose that makes a certificate a responder. */
const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

interface Ed25519Material { readonly certificate: Certificate; readonly key: CryptoKeyHandle }

/** Web Crypto's own type is not in this project's lib, and only these two fields are used. */
interface Pair { readonly privateKey: CryptoKeyHandle; readonly publicKey: CryptoKeyHandle }
const ed25519Key = async (): Promise<Pair> =>
    await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as unknown as Pair;

/**
 * A certificate whose key is Ed25519, so its signature is 64 raw bytes and an
 * OCSP response can be signed without a DER conversion.
 *
 * `signer: undefined` self-signs it, which is how the impostor is built: a
 * certificate that *names* the CA as its issuer and that the CA never issued.
 */
async function issueEd25519(options: {
    readonly subject: string;
    readonly issuerDer: Uint8Array;
    readonly signer: CryptoKeyHandle | undefined;
    readonly purposes?: readonly string[];
    /** The signer's algorithm; Ed25519 unless the issuer holds an EC key. */
    readonly signWith?: { name: string; hash?: string; namedCurve?: string };
    readonly notBefore?: number;
    readonly notAfter?: number;
}): Promise<Ed25519Material> {
    const pair = await ed25519Key();
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const der = await createCertificate({
        serialNumber: 42n,
        issuerDer: options.issuerDer,
        subject: [[{ type: '2.5.4.3', value: options.subject }]],
        notBefore: options.notBefore ?? AT - DAY,
        notAfter: options.notAfter ?? AT + DAY,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            ...(options.purposes === undefined ? [] : [{ oid: '2.5.29.37', value: encodeExtendedKeyUsage([...options.purposes]) }]),
        ],
    }, { key: options.signer ?? pair.privateKey, algorithm: (options.signWith ?? { name: 'Ed25519' }) as SignatureAlgorithm });
    return { certificate: parseCertificate(der, quiet), key: pair.privateKey };
}

/** root → ica → leaf, all Ed25519, with the ICA's key kept so it can answer. */
async function ed25519Hierarchy(options: { ecdsaIca?: boolean } = {}): Promise<{ root: Certificate; ica: Certificate; leaf: Certificate; icaKey: CryptoKeyHandle }> {
    const rootPair = await ed25519Key();
    const rootSpki = new Uint8Array(await crypto.subtle.exportKey('spki', rootPair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const rootSubject = [[{ type: '2.5.4.3', value: 'OCSP Root' }]];
    const rootDer = await createCertificate({
        serialNumber: 1n, issuer: rootSubject, subject: rootSubject,
        notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: rootSpki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign']) },
        ],
    }, { key: rootPair.privateKey, algorithm: { name: 'Ed25519' } });
    const root = parseCertificate(rootDer, quiet);

    // An EC intermediate when asked, so that it can sign something over SHA-1 —
    // Ed25519 has no such variant, and the refusal being tested is about the
    // digest rather than about the curve.
    const icaPair = options.ecdsaIca === true
        ? await (crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as unknown as Promise<Pair>)
        : await ed25519Key();
    const icaAlgorithm = (options.ecdsaIca === true
        ? { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }
        : { name: 'Ed25519' }) as SignatureAlgorithm;
    const icaSpki = new Uint8Array(await crypto.subtle.exportKey('spki', icaPair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const icaDer = await createCertificate({
        serialNumber: 2n, issuerDer: root.subject.der, subject: [[{ type: '2.5.4.3', value: 'OCSP ICA' }]],
        notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: icaSpki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign']) },
        ],
    }, { key: rootPair.privateKey, algorithm: { name: 'Ed25519' } });
    const ica = parseCertificate(icaDer, quiet);

    const leafPair = await ed25519Key();
    const leafSpki = new Uint8Array(await crypto.subtle.exportKey('spki', leafPair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const leafDer = await createCertificate({
        serialNumber: 3n, issuerDer: ica.subject.der, subject: [[{ type: '2.5.4.3', value: 'leaf.example' }]],
        notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: leafSpki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'leaf.example' }]) },
        ],
    }, { key: icaPair.privateKey, algorithm: icaAlgorithm });
    return { root, ica, leaf: parseCertificate(leafDer, quiet), icaKey: icaPair.privateKey };
}

/** `1.3.101.112`, Ed25519: a raw 64-byte signature, so no DER conversion. */
const ED25519 = encodeSequence([encodeObjectIdentifier('1.3.101.112')]);
const SHA1_ALG = encodeSequence([encodeObjectIdentifier('1.3.14.3.2.26'), encodeNull()]);
const SHA256_ALG = encodeSequence([encodeObjectIdentifier('2.16.840.1.101.3.4.2.1'), encodeNull()]);
const OID_BASIC_RESPONSE = '1.3.6.1.5.5.7.48.1.1';

/**
 * A `BasicOCSPResponse` about `certificate`, signed by a key generated here.
 *
 * The signature is real because the layer under test verifies it: a response
 * with a made-up signature would prove only that the parser reads one.
 */
async function ocspResponse(options: {
    readonly certificate: Certificate;
    readonly issuer: Certificate;
    readonly signer: { key: CryptoKeyHandle; certificates?: readonly Uint8Array[] };
    readonly status?: Uint8Array;
    readonly serial?: Uint8Array;
    /** SHA-256 CertID hashes, which RFC 6960 §4.3 allows and few responders use. */
    readonly sha256?: boolean;
    /** A non-successful responseStatus, which carries no body at all. */
    readonly statusCode?: number;
    readonly nonce?: Uint8Array;
    /** Declare a different signature algorithm than the one actually used. */
    readonly signatureAlgorithm?: Uint8Array;
}): Promise<Uint8Array> {
    if (options.statusCode !== undefined) return encodeSequence([encodeEnumerated(options.statusCode)]);
    const wide = options.sha256 === true;
    const digest = wide ? sha256 : sha1;
    const certId = encodeSequence([
        wide ? SHA256_ALG : SHA1_ALG,
        encodeOctetString(digest(options.issuer.subject.der)),
        encodeOctetString(computeKeyIdentifier(options.issuer.subjectPublicKeyInfo.publicKey.bytes, wide ? 'SHA-256' : 'SHA-1')),
        encodeTlv('universal', 2, false, options.serial ?? options.certificate.serialNumber.bytes),
    ]);
    const single = encodeSequence([
        certId,
        options.status ?? encodeTlv('context', 0, false, new Uint8Array(0)),
        encodeTime(AT - DAY, 'GeneralizedTime'),
        encodeExplicit(0, encodeTime(AT + DAY, 'GeneralizedTime'), { tagClass: 'context' }),
    ]);
    const tbs = encodeSequence([
        // responderID ::= [2] KeyHash — by key, which needs no name to match.
        encodeExplicit(2, encodeOctetString(new Uint8Array(20).fill(0xcc)), { tagClass: 'context' }),
        encodeTime(AT - DAY, 'GeneralizedTime'),
        encodeSequence([single]),
        // responseExtensions ::= [1] EXPLICIT Extensions — the nonce echo, whose
        // value sits inside TWO OCTET STRINGs.
        ...(options.nonce === undefined
            ? []
            : [encodeExplicit(1, encodeSequence([encodeSequence([
                encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.2'),
                encodeOctetString(encodeOctetString(options.nonce)),
            ])]), { tagClass: 'context' })]),
    ]);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, options.signer.key as unknown as Parameters<typeof crypto.subtle.sign>[1], tbs));
    const basic = encodeSequence([
        tbs,
        options.signatureAlgorithm ?? ED25519,
        encodeBitString(signature),
        ...(options.signer.certificates === undefined
            ? []
            : [encodeExplicit(0, encodeSequence([...options.signer.certificates]), { tagClass: 'context' })]),
    ]);
    return encodeSequence([
        encodeEnumerated(0),
        encodeExplicit(0, encodeSequence([encodeObjectIdentifier(OID_BASIC_RESPONSE), encodeOctetString(basic)]), { tagClass: 'context' }),
    ]);
}

/** An empty CRL naming `issuer`, whose signature is nonsense on purpose. */
function emptyCrl(issuer: Certificate, options: { version?: bigint; sha1?: boolean; oddExtension?: boolean } = {}): Uint8Array {
    // ecdsa-with-SHA1 when asked: pkinative refuses to treat such a signature as
    // evidence, which is what makes "never checked" reachable here.
    const algorithm = encodeAlgorithmIdentifier(options.sha1 === true ? '1.2.840.10045.4.1' : '1.2.840.10045.4.3.2');
    const tbs = encodeSequence([
        encodeInteger(options.version ?? 1n),
        algorithm,
        issuer.subject.der,
        encodeTime(AT - DAY, 'UTCTime'),
        encodeTime(AT + DAY, 'UTCTime'),
        // A critical extension nobody recognises, so that reading the list
        // emits a diagnostic and the report can be seen swallowing it.
        ...(options.oddExtension === true
            ? [encodeExplicit(0, encodeSequence([encodeSequence([
                encodeObjectIdentifier('1.3.6.1.4.1.99999.1'),
                encodeBoolean(true),
                encodeOctetString(Uint8Array.of(0x05, 0x00)),
            ])]))]
            : []),
    ]);
    return encodeSequence([tbs, algorithm, encodeBitString(Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))]);
}
