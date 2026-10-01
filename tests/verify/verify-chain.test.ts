import type { webcrypto } from 'node:crypto';
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
import { ecdsaRawToDer } from '../../src/crypto/crypto-signature.js';
import { computeKeyIdentifier } from '../../src/hash/key-identifier.js';
import { sha1 } from '../../src/hash/sha1.js';
import { sha256 } from '../../src/hash/sha256.js';
import { KEY_PURPOSES } from '../../src/path/path-purpose.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { verifyCertificateChain } from '../../src/verify/verify-chain.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { ExtensionDescription } from '../../src/types/build-types.js';
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
    /** Reuse a key pair — how two certificates for one key are made. */
    readonly pair?: webcrypto.CryptoKeyPair;
    readonly extensions?: readonly ExtensionDescription[];
}): Promise<Material & { readonly pair: webcrypto.CryptoKeyPair }> {
    const pair = options.pair ?? await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
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
            ...(options.extensions ?? []),
        ],
    }, { key: options.signer ?? pair.privateKey, algorithm: { name: 'ECDSA', hash: options.sha1 === true ? 'SHA-1' : 'SHA-256', namedCurve: 'P-256' } });
    return { certificate: parseCertificate(der, quiet), key: pair.privateKey, pair };
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
        expect(report.signatureVerifications).toBe(1);
    });

    it('should report how many signatures it had to compute', async () => {
        // The cost of the call, and a number far above the path length is what
        // a bag full of plausible issuers looks like.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({ leaf, candidates: [ica], trustAnchors: [root], at: AT });
        expect(report.signatureVerifications).toBe(2);
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
        const open = await issue({ subject: 'Shared ICA', issuerDer: realRoot.certificate.subject.der, signer: realRoot.key, ca: true, serial: 12n, pair: restricted.pair });
        // One key, two certificates, one subject: the leaf's signature verifies
        // under either, so only the purpose can make the builder look past the
        // restricted one it meets first.
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
        expect(report.path.map((c) => c.serialNumber.hex)).not.toContain(restricted.certificate.serialNumber.hex);
    });

    it('should not take a self-signed certificate that copies the anchor\'s name for the anchor', async () => {
        // RFC 5280 §6.1.1 (d): a trust anchor is a name and a key. Whoever sends
        // the chain controls `candidates`, so a "Verify Root" of their own
        // making, signing a leaf for whoever they like, must be one more link
        // whose signature the real anchor has to vouch for — and it never did.
        const { root, ica } = await hierarchy();
        const fake = await issue({ subject: 'Verify Root', issuerDer: root.subject.der, ca: true, serial: 77n });
        const victim = await issue({
            subject: 'bank.example', issuerDer: fake.certificate.subject.der, signer: fake.key, ca: false, serial: 78n,
            purposes: [KEY_PURPOSES.serverAuth], host: 'bank.example',
        });
        const report = await verifyCertificateChain({
            leaf: victim.certificate, candidates: [fake.certificate, ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'bank.example' },
        });
        expect(report.valid).toBe(false);
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_INVALID');
    });

    it('should restate the purpose on a one-certificate path the search refused for another reason', async () => {
        // The anchor itself as the leaf: a path of one. It has expired, which
        // the search reports and stops at; the purpose it does not permit is
        // said by the restatement, because the caller renewing it needs both.
        const root = await issue({ subject: 'Lone Root', issuerDer: encodeSequence([]), ca: true, serial: 20n });
        const lone = await issue({
            subject: 'Lone Root', issuerDer: root.certificate.subject.der, signer: root.key, ca: true, serial: 20n,
            pair: root.pair, purposes: [KEY_PURPOSES.emailProtection],
        });
        const report = await verifyCertificateChain({
            leaf: lone.certificate, trustAnchors: [lone.certificate], at: AT + 5 * DAY, purposes: [KEY_PURPOSES.serverAuth],
        });
        expect(report.path).toHaveLength(1);
        expect(codes(report)).toEqual(['PKI_REASON_EXPIRED', 'PKI_REASON_PURPOSE_NOT_PERMITTED']);
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
        expect(malformed?.path).toBe('crls[0]');
    });

    const bytes = new Uint8Array(1);
    it.each([
        ['a leaf that is its DER', { leaf: R12.der }],
        ['a leaf of null', { leaf: null }],
        ['a candidate without its DER', { candidates: [{ ...R12, der: undefined }] }],
        ['a candidate without a subject', { candidates: [{ der: bytes }] }],
        ['a trust anchor without an issuer', { trustAnchors: [{ der: bytes, subject: { der: bytes } }] }],
        ['a candidate without an issuer, its extensions a list', { candidates: [{ der: bytes, subject: { der: bytes }, extensions: [] }] }],
        ['a trust anchor whose extensions are not a list', { trustAnchors: [{ ...ROOT_X1, extensions: 'none' }] }],
        ['a CRL that is not bytes', { crls: ['MIIB'] }],
        ['an OCSP response that is not bytes', { ocspResponses: [[0x30, 0x00]] }],
        ['a nonce that is not bytes', { ocspNonce: 'nonce' }],
    ])('should throw PKI_INVALID_INPUT for %s — misuse, never a reason and never a TypeError', async (_label, extra) => {
        // Decided before anything is read: past that point every PkiError is
        // converted into a reason about the input, and an object that is not a
        // certificate reached `subject.der` and escaped as a TypeError.
        const call = verifyCertificateChain({ leaf: R12, candidates: [], trustAnchors: [ROOT_X1], at: AT, ...extra } as never);
        await expect(call).rejects.toBeInstanceOf(PkiError);
        await expect(call).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
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
        // Two answers, and both are right. The list names the root, so it covers
        // the INTERMEDIATE — which is now checked, because a revoked CA is a
        // revoked chain — and its signature is nonsense, so that is unknown. The
        // leaf is covered by nothing at all, which is the second. What is
        // required is an answer about the leaf; what is checked is everything.
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN', 'PKI_REASON_REVOCATION_UNKNOWN']);
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

    describe('each §6.1.1 input and the limits, each where it changes the answer', () => {
        const P1 = '1.3.6.1.4.1.55555.1.1';
        const P2 = '1.3.6.1.4.1.55555.1.2';
        const ANY_POLICY = '2.5.29.32.0';
        const policies = (...oids: string[]): ExtensionDescription =>
            ({ oid: '2.5.29.32', value: encodeSequence(oids.map((oid) => encodeSequence([encodeObjectIdentifier(oid)]))) });
        const mapping = (from: string, to: string): ExtensionDescription =>
            ({ oid: '2.5.29.33', critical: true, value: encodeSequence([encodeSequence([encodeObjectIdentifier(from), encodeObjectIdentifier(to)])]) });

        /** root → ica → leaf, the intermediate and the leaf carrying the extensions given. */
        async function policyChain(ica: readonly ExtensionDescription[], leaf: readonly ExtensionDescription[]): Promise<{ leaf: Certificate; candidates: Certificate[]; trustAnchors: Certificate[]; at: number }> {
            const seed = await issue({ subject: 'Policy Root', issuerDer: encodeSequence([]), ca: true, serial: 30n });
            const root = await issue({ subject: 'Policy Root', issuerDer: seed.certificate.subject.der, signer: seed.key, ca: true, serial: 30n, pair: seed.pair });
            const intermediate = await issue({ subject: 'Policy ICA', issuerDer: root.certificate.subject.der, signer: root.key, ca: true, serial: 31n, extensions: ica });
            const end = await issue({ subject: 'policy.example', issuerDer: intermediate.certificate.subject.der, signer: intermediate.key, ca: false, serial: 32n, extensions: leaf });
            return { leaf: end.certificate, candidates: [intermediate.certificate], trustAnchors: [root.certificate], at: AT };
        }

        it('should pass initialPolicySet: a chain under P1 is refused when only P2 is acceptable', async () => {
            const chain = await policyChain([policies(P1)], [policies(P1)]);
            expect(codes(await verifyCertificateChain({ ...chain, requireExplicitPolicy: true, initialPolicySet: [P1] }))).toEqual([]);
            expect(codes(await verifyCertificateChain({ ...chain, requireExplicitPolicy: true, initialPolicySet: [P2] }))).toEqual(['PKI_REASON_NO_VALID_POLICY']);
        });

        it('should pass inhibitAnyPolicy: an intermediate asserting only anyPolicy then establishes nothing', async () => {
            const chain = await policyChain([policies(ANY_POLICY)], [policies(P1)]);
            expect(codes(await verifyCertificateChain({ ...chain, requireExplicitPolicy: true }))).toEqual([]);
            expect(codes(await verifyCertificateChain({ ...chain, requireExplicitPolicy: true, inhibitAnyPolicy: true }))).toEqual(['PKI_REASON_NO_VALID_POLICY']);
        });

        it('should pass inhibitPolicyMapping: a policy reached only through a mapping is then lost', async () => {
            const chain = await policyChain([policies(P1), mapping(P1, P2)], [policies(P2)]);
            expect(codes(await verifyCertificateChain({ ...chain, requireExplicitPolicy: true }))).toEqual([]);
            expect(codes(await verifyCertificateChain({ ...chain, requireExplicitPolicy: true, inhibitPolicyMapping: true }))).toEqual(['PKI_REASON_NO_VALID_POLICY']);
        });

        it('should pass the limits: a path bound of one certificate cannot reach the anchor', async () => {
            const chain = await policyChain([], []);
            expect(codes(await verifyCertificateChain(chain))).toEqual([]);
            expect(codes(await verifyCertificateChain({ ...chain, limits: { maxChainLength: 1 } }))).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        });
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
            crls: [emptyCrl(ica, { wideTime: true })],
        });
        // The list is usable and was used — its signature is nonsense on
        // purpose, which is the verdict — and the profile concern stayed where
        // it belongs, on a `parseCertificateList` the caller did not make.
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
        expect(codes(report)).not.toContain('PKI_REASON_UNKNOWN_CRITICAL_EXTENSION');
    });

    it('should say so rather than move on when a covering list carries a critical extension it cannot process', async () => {
        // RFC 5280 §6.3.3: such a list MUST NOT be used. A validator that just
        // skipped it would have used nothing *and said nothing* — reporting the
        // certificate exactly as if the CA had published no list at all, which
        // is the difference between "I could not read the CA's answer" and "the
        // CA gave no answer".
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica, { oddExtension: true })],
        });
        expect(codes(report)).toContain('PKI_REASON_UNKNOWN_CRITICAL_EXTENSION');
        expect(report.valid).toBe(false);
    });

    it('should name a list by where the caller put it, even after one before it could not be read', async () => {
        // The path used to be the list's position among those that parsed, so
        // an unreadable first list shifted every later reason onto its neighbour.
        const { root, ica, leaf } = await hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01), emptyCrl(ica, { oddExtension: true })],
        });
        const paths = report.reasons.map((r) => `${r.code}@${r.path}`);
        expect(paths).toContain('PKI_REASON_INPUT_MALFORMED@crls[0]');
        expect(paths.some((p) => p.startsWith('PKI_REASON_UNKNOWN_CRITICAL_EXTENSION@crls[1]'))).toBe(true);
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

    it('should refuse a list its CA really signed when its keyUsage omits cRLSign', async () => {
        // The test above, with a real signature: the arithmetic would say yes,
        // and the entitlement is what says no.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, icaKey)], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should not take a list from a key certified under another name', async () => {
        // RFC 5280 §6.3.3 (f): the list's signer is found among certificates
        // whose subject is the list's issuer. This key is certified by the CA,
        // may sign lists, and signed this one — under a name that is not the CA's.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const pair = await ed25519Key();
        const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
        const other = parseCertificate(await createCertificate({
            serialNumber: 41n, issuerDer: ica.subject.der, subject: [[{ type: '2.5.4.3', value: 'Another Signer' }]],
            notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: spki,
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['cRLSign']) },
            ],
        }, { key: icaKey, algorithm: { name: 'Ed25519' } }), quiet);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, other], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, pair.privateKey)], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should weigh a list really signed over SHA-1 only with allowSha1', async () => {
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ ecdsaIca: true, crlSign: true });
        const ECDSA_SHA1 = encodeSequence([encodeObjectIdentifier('1.2.840.10045.4.1')]);
        const tbs = encodeSequence([
            encodeInteger(1n), ECDSA_SHA1, ica.subject.der,
            encodeTime(AT - DAY, 'UTCTime'), encodeTime(AT + DAY, 'UTCTime'),
        ]);
        const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-1' }, icaKey as unknown as webcrypto.CryptoKey, tbs));
        const crl = encodeSequence([tbs, ECDSA_SHA1, encodeBitString(ecdsaRawToDer(raw, 32))]);
        const common = { leaf, candidates: [ica], trustAnchors: [root], at: AT, crls: [crl], requireRevocation: true } as const;
        expect(codes(await verifyCertificateChain(common))).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        expect(codes(await verifyCertificateChain({ ...common, allowSha1: true }))).toEqual([]);
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
            ocspResponses: [response], requireRevocation: true,
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
            ocspResponses: [response],
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
            ocspResponses: [response], requireRevocation: true,
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
            ocspResponses: [response],
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
            ocspResponses: [response],
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
            ocspResponses: [response],
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
            ocspResponses: [declined],
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
            ocspResponses: [response], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should take the digest from the answer about our serial, not from another answer before it', async () => {
        // A multi-answer response whose first answer, about another serial,
        // uses SHA-1 while ours uses SHA-256: reading the digest anywhere but
        // from our own answer computes the expected CertID wrongly, and the
        // good answer is never recognised.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey }, sha256: true, others: [{ serial: Uint8Array.of(0x7a, 0x01) }] });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocspResponses: [response], requireRevocation: true,
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
        expect(codes(await verifyCertificateChain({ ...common, ocspResponses: [echoed] }))).toEqual([]);

        // A different nonce is always a mismatch; a missing echo is reported
        // only when asked, because most public responders omit it on purpose.
        const other = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey }, nonce: Uint8Array.of(9, 9) });
        expect(codes(await verifyCertificateChain({ ...common, ocspResponses: [other] }))).toContain('PKI_REASON_REVOCATION_MISMATCH');

        const silent = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey } });
        expect(codes(await verifyCertificateChain({ ...common, ocspResponses: [silent] }))).toEqual([]);
        expect(codes(await verifyCertificateChain({ ...common, ocspResponses: [silent], requireOcspNonce: true })))
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
            ocspResponses: [response],
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
            ocspResponses: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it.each([
        ['the first instant', { notBefore: AT }],
        ['the last instant', { notAfter: AT }],
    ])('should believe a delegate at %s of its own window', async (_label, window) => {
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const delegate = await issueEd25519({
            subject: 'OCSP Responder', issuerDer: ica.subject.der, signer: icaKey,
            purposes: [OCSP_SIGNING], ...window,
        });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: delegate.key, certificates: [delegate.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocspResponses: [response], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should refuse a delegate that names another issuer, even signed by the key of the CA', async () => {
        // RFC 6960 §4.2.2.2: the responder certificate is issued *directly by
        // the CA that is identified in the request*. The CA's key under a name
        // that is not the CA's is not that.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy();
        const delegate = await issueEd25519({
            subject: 'OCSP Responder', issuerDer: root.subject.der, signer: icaKey,
            purposes: [OCSP_SIGNING],
        });
        const response = await ocspResponse({
            certificate: leaf, issuer: ica,
            signer: { key: delegate.key, certificates: [delegate.certificate.der] },
        });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocspResponses: [response], requireRevocation: true,
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
            ocspResponses: [response],
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
            ocspResponses: [response],
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
            ocspResponses: [response],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should say the answer is not evidence when no issuer was established', async () => {
        // With nothing trusted there is no CA to hash, so no CertID can be
        // computed — and an OCSP answer about a certificate whose issuer was
        // never established is not evidence, whoever signed it.
        const { ica, leaf, icaKey } = await ed25519Hierarchy();
        const response = await ocspResponse({ certificate: leaf, issuer: ica, signer: { key: icaKey } });
        const report = await verifyCertificateChain({ leaf, trustAnchors: [], at: AT, ocspResponses: [response] });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_MISMATCH');
    });

    it('should report a malformed OCSP response as a reason, never an exception', async () => {
        const { root, ica, leaf } = await ed25519Hierarchy();
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            ocspResponses: [Uint8Array.of(0x30, 0x80, 0x00)],
        });
        expect(codes(report)).toContain('PKI_REASON_INPUT_MALFORMED');
        expect(report.reasons.find((r) => r.code === 'PKI_REASON_INPUT_MALFORMED')?.path).toBe('ocspResponses[0]');
    });

    it('should check the certificate above the leaf, because a revoked CA is a revoked chain', async () => {
        // The CA whose key signed this leaf has had that key withdrawn. A
        // verifier that asked only about the leaf would accept everything below
        // a CA its own issuer had disowned — NIST PKITS has the test, and it is
        // the shape a compromised sub-CA takes in the real world.
        const { root, ica, leaf, rootKey } = await ed25519Hierarchy({ rootCrlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [await signedCrl(root, rootKey, { revoked: ica })],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOKED');
        expect(report.reasons.find((r) => r.code === 'PKI_REASON_REVOKED')?.path).toContain('crl');
    });

    it('should not call a certificate revoked on the word of a list nobody verified', async () => {
        // RFC 5280 §6.3.3 (g): a list is consulted once its signature is valid.
        // An unsigned list is one anyone can write, so what it names is a
        // claim, carried in an UNKNOWN, and never PKI_REASON_REVOKED — which a
        // caller reading the codes rightly takes as "this certificate is revoked".
        const { root, ica, leaf } = await hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [revokingCrl(root, ica)],
        });
        expect(report.valid).toBe(false);
        expect(codes(report)).not.toContain('PKI_REASON_REVOKED');
        expect(report.reasons.some((r) => r.code === 'PKI_REASON_REVOCATION_UNKNOWN' && r.message.includes('not authenticated'))).toBe(true);
    });

    it('should try every certificate of that name for the list signature', async () => {
        // A CA is a name, not a key: a rollover leaves two live at once, and
        // PKITS has a CA that signs certificates with one key and its lists with
        // another. Trying only the certificate that sits above the leaf asks
        // about one of the CA's keys and calls the `false` an answer about the
        // CA.
        const { root, ica, leaf } = await hierarchy({ crlSign: true });
        // A second certificate for the same CA name, holding a different key,
        // and the list is signed by neither — so the answer is "checked and
        // wrong" rather than "never checked", whichever one was tried.
        const sibling = await issue({ subject: 'Verify ICA', issuerDer: root.subject.der, ca: true, serial: 99n, crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, sibling.certificate], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [emptyCrl(ica)], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should believe a list the CA really signed', async () => {
        // Every other list here is nonsense on purpose, because what those tests
        // are about is which certificate is consulted. This one is signed, so
        // the answer is a clean "not revoked" — and a revocation check that
        // never once verified a signature would be checking nothing.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [await signedCrl(ica, icaKey)], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should report what one partial list left unproven', async () => {
        // keyCompromise and cACompromise only. The serial's absence rules those
        // two out and says nothing about the other six, and a report that came
        // back clean would have turned a partial answer into a complete one.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, icaKey, { reasons: [0x05, 0x60] })], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_PARTIAL']);
    });

    it('should add two partial lists up into a complete answer', async () => {
        // RFC 5280 §6.3.3's `reasons_mask`, and the reason
        // PKI_REASON_REVOCATION_PARTIAL is a code rather than a wording of
        // UNKNOWN: a CA that publishes a keyCompromise list it can reissue in
        // minutes and a second list for everything else has answered
        // completely, and **only a caller holding both can see that**. Each
        // list says what it ruled out; the composition does the addition.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { reasons: [0x05, 0x60] }),
                await signedCrl(ica, icaKey, { reasons: [0x07, 0x1f, 0x80] }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
        expect(report.valid).toBe(true);
    });

    it('should still add up to nothing when the halves leave a gap', async () => {
        // The same two lists minus `superseded`. One reason unaccounted for is
        // one reason the certificate could have been revoked for, so the answer
        // stays partial — a completeness test that rounded up would be worse
        // than no test at all.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { reasons: [0x05, 0x60] }),
                await signedCrl(ica, icaKey, { reasons: [0x07, 0x17, 0x80] }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_PARTIAL', 'PKI_REASON_REVOCATION_PARTIAL']);
    });

    it('should apply a delta over the base it belongs to', async () => {
        // The pairing only the composition can do: it is the one layer holding
        // both lists. The base is clean, the delta carries the revocation, and
        // reading either alone gives the wrong answer.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4 }),
                await signedCrl(ica, icaKey, { number: 6, over: 4, revoked: leaf }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
    });

    it('should read a list passed twice once, and a stapled response passed twice once', async () => {
        // A signed message carries the CRL its signer relied on and the caller
        // passes the one they downloaded: the same bytes, one piece of
        // evidence. Each copy used to report the revocation again.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const crl = await signedCrl(ica, icaKey, { number: 4, revoked: leaf });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT, crls: [crl, crl.slice()], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
        const junk = Uint8Array.of(0x30, 0x00);
        const twice = await verifyCertificateChain({ leaf, candidates: [ica], trustAnchors: [root], at: AT, ocspResponses: [junk, junk.slice()] });
        expect(codes(twice)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
    });

    it('should let a delta withdraw a revocation the base still records', async () => {
        // `removeFromCRL`, the entry reason that exists only on a delta. A
        // verifier that ignored deltas would keep refusing this certificate
        // long after the CA stopped saying it was revoked.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4, revoked: leaf }),
                await signedCrl(ica, icaKey, { number: 6, over: 4, revoked: leaf, entryReason: 8 }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should apply one delta to every certificate on the path the pair covers', async () => {
        // A key rollover leaves two certificates with the same issuer name, so
        // one base and one delta speak about both — and the delta's signature
        // is computed once and reused, because whether a key entitled to sign
        // it did is a property of the list rather than of each certificate.
        const { root, ica, leaf, icaKey, rollover } = await ed25519Hierarchy({ crlSign: true, rollover: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, rollover as Certificate], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4 }),
                await signedCrl(ica, icaKey, { number: 6, over: 4, revoked: rollover as Certificate }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
    });

    it('should not pair a delta that does not cover the certificate', async () => {
        // The numbers line up and the scope does not: a delta about CA
        // certificates says nothing about an end-entity one, so the base's
        // answer stands rather than the delta's.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4, revoked: leaf }),
                await signedCrl(ica, icaKey, { number: 6, over: 4, revoked: leaf, entryReason: 8, onlyCACerts: true }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
    });

    it('should pass over a delta outside the certificate\'s scope and pair the next one that covers it', async () => {
        // Two deltas over one base: the first speaks only of CA certificates,
        // the second of everything. Stopping at the first, and letting the
        // revocation check discard it, would leave the second unread — and
        // the revocation it carries with it.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4 }),
                await signedCrl(ica, icaKey, { number: 5, over: 4, onlyCACerts: true }),
                await signedCrl(ica, icaKey, { number: 6, over: 4, revoked: leaf }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
    });

    it('should pair a delta it could not check the signature of, and say so', async () => {
        // No candidates and no anchor, so the path stops at the leaf and there
        // is nobody to check either list against. The pair is still *about*
        // this certificate — scope is a fact about the lists, not about how far
        // the search got — and an unverifiable pair is UNKNOWN, not "revoked".
        const { ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, trustAnchors: [], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4 }),
                await signedCrl(ica, icaKey, { number: 6, over: 4, revoked: leaf }),
            ],
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
        expect(codes(report)).not.toContain('PKI_REASON_REVOKED');
    });

    it('should not answer from a delta with no base to apply it over', async () => {
        // On its own a delta reports every certificate absent from it as
        // unrevoked, which is nearly all of them.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, icaKey, { number: 6, over: 4 })],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should believe a list signed by the key the CA delegated it to', async () => {
        // The canary for the three tests below: without it, a rule that refused
        // every delegate would score perfectly against all of them.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const delegate = await crlDelegate(ica, icaKey);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, delegate.key),
                // A list the CA itself signed, covering the delegate and saying
                // nothing about it: the delegate is looked up and comes back
                // clean, which is the half of the rule below that must not
                // refuse anything.
                await signedCrl(ica, icaKey),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should stop believing a delegated signer whose own certificate is revoked', async () => {
        // The rule that makes revoking a compromised CRL-signing key mean
        // anything. Without it, whoever holds that key keeps publishing
        // "nothing is revoked" for as long as the certificate's validity runs
        // — and the CA has no way to say otherwise. NIST PKITS builds
        // InvalidSeparateCertificateandCRLKeysTest21 on exactly this.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const delegate = await crlDelegate(ica, icaKey);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, delegate.key),
                // Signed by the CA itself, which the path vouches for: that is
                // the rank that cuts the recursion.
                await signedCrl(ica, icaKey, { revoked: delegate.certificate }),
            ],
            requireRevocation: true,
        });
        expect(codes(report)).toContain('PKI_REASON_REVOCATION_UNKNOWN');
    });

    it('should not let a delegate revoke itself', async () => {
        // The rank that cuts the recursion, seen from the other side: only a
        // list the **path** vouches for may disqualify a delegated signer. This
        // one carries the CA's name and the delegate's own signature, so it
        // proves nothing about the delegate — and taking its word would let
        // whoever holds that key decide whether their own key is still good.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const delegate = await crlDelegate(ica, icaKey);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, delegate.key, { revoked: delegate.certificate })],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should report a signed list whose entry is malformed as INPUT_MALFORMED, never an exception', async () => {
        // The envelope parses, so the parse this composition catches does not
        // trip; the entry is read only by the walk that looks for the serial,
        // and that walk used to throw out of a call that promises not to.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, icaKey, { malformedEntry: true })],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        expect(report.reasons[0]).toMatchObject({ errorCode: 'PKI_X509_STRUCTURE_INVALID', path: 'crls[0]' });
    });

    it('should stop believing a delegated signer when the list that would clear it cannot be walked', async () => {
        // The canary above with one change: the CA's own list about the
        // delegate carries a malformed entry. It has not said the delegate is
        // unrevoked, so the delegate's list is not believed — fail closed —
        // and the unreadable list is reported where it stands.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const delegate = await crlDelegate(ica, icaKey);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, delegate.key), await signedCrl(ica, icaKey, { malformedEntry: true })],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN', 'PKI_REASON_INPUT_MALFORMED']);
        expect(report.reasons[1]).toMatchObject({ errorCode: 'PKI_X509_STRUCTURE_INVALID', path: 'crls[1]' });
    });

    it('should stop believing a delegated signer whose certificate has expired', async () => {
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const delegate = await crlDelegate(ica, icaKey, { notAfter: AT - DAY / 2 });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, delegate.key)], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should not believe a list signed by a self-signed certificate that merely copies the CA\'s name', async () => {
        // RFC 5280 §6.3.3 (f): a CRL issuer off the path is believed only once
        // its own certificate validates under the same anchors. The bag is the
        // sender's, so a revoked signer puts in it an "OCSP ICA" of its own
        // making, asserting cRLSign, and a list that clears it.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const impostor = await selfSignedLike('OCSP ICA');
        // A forged complete list answers nothing…
        const complete = await verifyCertificateChain({
            leaf, candidates: [ica, impostor.certificate], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, impostor.key)], requireRevocation: true,
        });
        expect(codes(complete)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        // …and a forged delta hides no revocation the CA's own base list made.
        const hidden = await verifyCertificateChain({
            leaf, candidates: [ica, impostor.certificate], trustAnchors: [root], at: AT,
            crls: [
                await signedCrl(ica, icaKey, { number: 4, revoked: leaf }),
                await signedCrl(ica, impostor.key, { number: 6, over: 4, revoked: leaf, entryReason: 8 }),
            ],
        });
        expect(codes(hidden)).toEqual(['PKI_REASON_REVOKED']);
    });

    it.each([
        ['the first instant', { notBefore: AT }],
        ['the last instant', { notAfter: AT }],
    ])('should believe a delegated signer at %s of its validity', async (_label, window) => {
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const delegate = await crlDelegate(ica, icaKey, window);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, delegate.key)], requireRevocation: true,
        });
        expect(codes(report)).toEqual([]);
    });

    it('should judge a delegated signer only by lists about it, not by a list of another issuer it cannot walk', async () => {
        // The root's list is signed by a key the path vouches for, but it is
        // the root's list: the delegate was issued by the CA, so the list says
        // nothing about it (RFC 5280 §6.3.3 (b)(1)), unreadable entry or not.
        // It does speak about the CA, where its unreadable entry is reported —
        // once, and without taking the delegate's list down with it.
        const { root, ica, leaf, icaKey, rootKey } = await ed25519Hierarchy({ crlSign: true, rootCrlSign: true });
        const delegate = await crlDelegate(ica, icaKey);
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT,
            crls: [await signedCrl(ica, delegate.key), await signedCrl(root, rootKey, { malformedEntry: true })],
            requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        expect(report.reasons[0]).toMatchObject({ path: 'crls[1]' });
    });

    it('should refuse a signer the list does not name in its authorityKeyIdentifier', async () => {
        // A CA holding several keys under one name can say which of them
        // revokes. Any same-named certificate asserting cRLSign is what makes a
        // key rollover work, and what cannot tell a designated signer from an
        // undesignated sibling.
        const { root, ica, leaf, icaKey } = await ed25519Hierarchy({ crlSign: true });
        const mine = Uint8Array.from({ length: 20 }, (_, i) => i + 1);
        const other = Uint8Array.from({ length: 20 }, () => 0xaa);
        const delegate = await crlDelegate(ica, icaKey, { ski: mine });
        const chain = { leaf, candidates: [ica, delegate.certificate], trustAnchors: [root], at: AT, requireRevocation: true };
        expect(codes(await verifyCertificateChain({ ...chain, crls: [await signedCrl(ica, delegate.key, { aki: mine })] }))).toEqual([]);
        expect(codes(await verifyCertificateChain({ ...chain, crls: [await signedCrl(ica, delegate.key, { aki: other })] })))
            .toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
    });

    it('should apply one list to every certificate on the path that it covers', async () => {
        // A CA rolling its key over leaves two certificates with the same
        // subject: the one its own issuer signed, and one it signed itself. The
        // leaf and that self-issued certificate then have the **same** issuer
        // name, so a single list speaks about both — and it is asked once and
        // applied twice, because whether a key entitled to sign it did is a
        // property of the list rather than of each certificate.
        const { root, ica, leaf, icaKey, rollover } = await ed25519Hierarchy({ crlSign: true, rollover: true });
        const report = await verifyCertificateChain({
            leaf, candidates: [ica, rollover as Certificate], trustAnchors: [root], at: AT,
            serverName: { kind: 'dns', value: 'leaf.example' },
            crls: [await signedCrl(ica, icaKey, { revoked: leaf })], requireRevocation: true,
        });
        expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
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
async function ed25519Hierarchy(options: { ecdsaIca?: boolean; crlSign?: boolean; rollover?: boolean; rootCrlSign?: boolean } = {}): Promise<{ root: Certificate; ica: Certificate; leaf: Certificate; icaKey: CryptoKeyHandle; rootKey: CryptoKeyHandle; rollover?: Certificate }> {
    const rootPair = await ed25519Key();
    const rootSpki = new Uint8Array(await crypto.subtle.exportKey('spki', rootPair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const rootSubject = [[{ type: '2.5.4.3', value: 'OCSP Root' }]];
    const rootDer = await createCertificate({
        serialNumber: 1n, issuer: rootSubject, subject: rootSubject,
        notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: rootSpki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(options.rootCrlSign === true ? ['keyCertSign', 'cRLSign'] : ['keyCertSign']) },
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
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(options.crlSign === true ? ['keyCertSign', 'cRLSign'] : ['keyCertSign']) },
        ],
    }, { key: rootPair.privateKey, algorithm: { name: 'Ed25519' } });
    const ica = parseCertificate(icaDer, quiet);

    // A key rollover: the SAME subject name, signed by the CA's own key, which
    // is what makes the leaf and this certificate share an issuer name.
    let rollover: Certificate | undefined;
    let signsLeaf = icaPair;
    if (options.rollover === true) {
        const rollPair = await ed25519Key();
        // The leaf is signed by the NEW key, so the only chain that verifies
        // goes through the rollover certificate and both it and the leaf end up
        // on the path with the same issuer name.
        signsLeaf = rollPair;
        const rollSpki = new Uint8Array(await crypto.subtle.exportKey('spki', rollPair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
        rollover = parseCertificate(await createCertificate({
            serialNumber: 9n, issuerDer: ica.subject.der, subject: [[{ type: '2.5.4.3', value: 'OCSP ICA' }]],
            notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: rollSpki,
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
            ],
        }, { key: icaPair.privateKey, algorithm: { name: 'Ed25519' } }), quiet);
    }

    const leafPair = await ed25519Key();
    const leafSpki = new Uint8Array(await crypto.subtle.exportKey('spki', leafPair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const leafDer = await createCertificate({
        serialNumber: 3n, issuerDer: ica.subject.der, subject: [[{ type: '2.5.4.3', value: 'leaf.example' }]],
        notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: leafSpki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'leaf.example' }]) },
        ],
    }, { key: signsLeaf.privateKey, algorithm: options.rollover === true ? { name: 'Ed25519' } as SignatureAlgorithm : icaAlgorithm });
    return { root, ica, leaf: parseCertificate(leafDer, quiet), icaKey: icaPair.privateKey, rootKey: rootPair.privateKey, ...(rollover === undefined ? {} : { rollover }) };
}

/** A self-signed Ed25519 certificate under `commonName`, with its own key, cA and cRLSign: what an attacker puts in the bag. */
async function selfSignedLike(commonName: string): Promise<{ certificate: Certificate; key: CryptoKeyHandle }> {
    const pair = await ed25519Key();
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const name = [[{ type: '2.5.4.3', value: commonName }]];
    const der = await createCertificate({
        serialNumber: 66n, issuer: name, subject: name,
        notBefore: AT - DAY, notAfter: AT + DAY, subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
        ],
    }, { key: pair.privateKey, algorithm: { name: 'Ed25519' } });
    return { certificate: parseCertificate(der, quiet), key: pair.privateKey };
}

/**
 * A second certificate under the CA's own name, holding its own key and
 * entitled to sign lists and nothing else — the dedicated CRL signer a CA
 * designates when it does not want its issuing key answering revocation
 * queries (RFC 5280 §5.2.1).
 */
async function crlDelegate(ca: Certificate, caKey: CryptoKeyHandle, options: {
    readonly serial?: bigint;
    readonly ski?: Uint8Array;
    readonly notBefore?: number;
    readonly notAfter?: number;
} = {}): Promise<{ certificate: Certificate; key: CryptoKeyHandle }> {
    const pair = await ed25519Key();
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey as unknown as Parameters<typeof crypto.subtle.exportKey>[1]));
    const der = await createCertificate({
        serialNumber: options.serial ?? 40n,
        issuerDer: ca.subject.der,
        subject: [[{ type: '2.5.4.3', value: 'OCSP ICA' }]],
        notBefore: options.notBefore ?? AT - DAY,
        notAfter: options.notAfter ?? AT + DAY,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['cRLSign']) },
            ...(options.ski === undefined ? [] : [{ oid: '2.5.29.14', value: encodeOctetString(options.ski) }]),
        ],
    }, { key: caKey, algorithm: { name: 'Ed25519' } });
    return { certificate: parseCertificate(der, quiet), key: pair.privateKey };
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
    /** Answers about other serials, placed before ours, each with its own CertID digest. */
    readonly others?: ReadonlyArray<{ readonly serial: Uint8Array; readonly sha256?: boolean }>;
}): Promise<Uint8Array> {
    if (options.statusCode !== undefined) return encodeSequence([encodeEnumerated(options.statusCode)]);
    const singleResponse = (serial: Uint8Array, wide: boolean, status: Uint8Array): Uint8Array => {
        const digest = wide ? sha256 : sha1;
        const certId = encodeSequence([
            wide ? SHA256_ALG : SHA1_ALG,
            encodeOctetString(digest(options.issuer.subject.der)),
            encodeOctetString(computeKeyIdentifier(options.issuer.subjectPublicKeyInfo.publicKey.bytes, wide ? 'SHA-256' : 'SHA-1')),
            encodeTlv('universal', 2, false, serial),
        ]);
        return encodeSequence([
            certId,
            status,
            encodeTime(AT - DAY, 'GeneralizedTime'),
            encodeExplicit(0, encodeTime(AT + DAY, 'GeneralizedTime'), { tagClass: 'context' }),
        ]);
    };
    const good = encodeTlv('context', 0, false, new Uint8Array(0));
    const single = singleResponse(options.serial ?? options.certificate.serialNumber.bytes, options.sha256 === true, options.status ?? good);
    const others = (options.others ?? []).map((other) => singleResponse(other.serial, other.sha256 === true, good));
    const tbs = encodeSequence([
        // responderID ::= [2] KeyHash — by key, which needs no name to match.
        encodeExplicit(2, encodeOctetString(new Uint8Array(20).fill(0xcc)), { tagClass: 'context' }),
        encodeTime(AT - DAY, 'GeneralizedTime'),
        encodeSequence([...others, single]),
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

/**
 * A CRL naming `issuer` and **really signed** by `key`, Ed25519 so the
 * signature is 64 raw bytes and needs no DER conversion.
 */
interface SignedCrlOptions {
    /** A certificate to list as revoked. */
    readonly revoked?: Certificate;
    /** `removeFromCRL` (8) and the rest of RFC 5280 §5.3.1, on that entry. */
    readonly entryReason?: number;
    /** `onlySomeReasons`, as the BIT STRING content: unused-bit count first. */
    readonly reasons?: readonly number[];
    /** `onlyContainsCACerts`, so the list covers no end-entity certificate. */
    readonly onlyCACerts?: boolean;
    /** `authorityKeyIdentifier`: which of the CA's keys signed this list. */
    readonly aki?: Uint8Array;
    /** `cRLNumber`. */
    readonly number?: number;
    /** `deltaCRLIndicator`, which also makes the list a delta over that base. */
    readonly over?: number;
    /**
     * An entry holding a serial and no revocationDate, after any other: the
     * envelope parses, and only the walk that looks for a serial trips on it.
     */
    readonly malformedEntry?: boolean;
}

async function signedCrl(issuer: Certificate, key: CryptoKeyHandle, options: SignedCrlOptions = {}): Promise<Uint8Array> {
    const { revoked, reasons, aki } = options;
    const entries = [
        ...(revoked === undefined ? [] : [encodeSequence([
            encodeTlv('universal', 2, false, revoked.serialNumber.bytes),
            encodeTime(AT - 30 * DAY, 'UTCTime'),
            ...(options.entryReason === undefined ? [] : [encodeSequence([encodeSequence([
                encodeObjectIdentifier('2.5.29.21'),
                encodeOctetString(encodeEnumerated(BigInt(options.entryReason))),
            ])])]),
        ])]),
        ...(options.malformedEntry === true ? [encodeSequence([encodeInteger(0x7777n)])] : []),
    ];
    // issuingDistributionPoint { onlySomeReasons [3] ReasonFlags }, when asked:
    // the bytes are the BIT STRING content, unused-bit count first.
    // authorityKeyIdentifier { keyIdentifier [0] }, when asked: the CA naming
    // which of its keys signed this list.
    const scope = [
        ...(options.onlyCACerts === true ? [encodeTlv('context', 2, false, Uint8Array.of(0xff))] : []),
        ...(reasons === undefined ? [] : [encodeTlv('context', 3, false, Uint8Array.from(reasons))]),
    ];
    const extensions = [
        ...(scope.length === 0 ? [] : [encodeSequence([
            encodeObjectIdentifier('2.5.29.28'),
            encodeBoolean(true),
            encodeOctetString(encodeSequence(scope)),
        ])]),
        ...(aki === undefined ? [] : [encodeSequence([
            encodeObjectIdentifier('2.5.29.35'),
            encodeOctetString(encodeSequence([encodeTlv('context', 0, false, aki)])),
        ])]),
        ...(options.number === undefined ? [] : [encodeSequence([
            encodeObjectIdentifier('2.5.29.20'),
            encodeOctetString(encodeInteger(BigInt(options.number))),
        ])]),
        ...(options.over === undefined ? [] : [encodeSequence([
            encodeObjectIdentifier('2.5.29.27'),
            encodeBoolean(true),
            encodeOctetString(encodeInteger(BigInt(options.over))),
        ])]),
    ];
    const tbs = encodeSequence([
        encodeInteger(1n),
        ED25519,
        issuer.subject.der,
        encodeTime(AT - DAY, 'UTCTime'),
        encodeTime(AT + DAY, 'UTCTime'),
        ...(entries.length === 0 ? [] : [encodeSequence(entries)]),
        ...(extensions.length === 0 ? [] : [encodeExplicit(0, encodeSequence(extensions))]),
    ]);
    const signature = new Uint8Array(await crypto.subtle.sign(
        { name: 'Ed25519' },
        key as unknown as Parameters<typeof crypto.subtle.sign>[1],
        tbs,
    ));
    return encodeSequence([tbs, ED25519, encodeBitString(signature)]);
}

/**
 * A CRL naming `issuer` that revokes `revoked` — unsigned, so that what is
 * under test is what an unauthenticated listing is reported as.
 */
function revokingCrl(issuer: Certificate, revoked: Certificate): Uint8Array {
    const algorithm = encodeAlgorithmIdentifier('1.2.840.10045.4.3.2');
    const entry = encodeSequence([
        encodeTlv('universal', 2, false, revoked.serialNumber.bytes),
        encodeTime(AT - 30 * DAY, 'UTCTime'),
    ]);
    const tbs = encodeSequence([
        encodeInteger(1n),
        algorithm,
        issuer.subject.der,
        encodeTime(AT - DAY, 'UTCTime'),
        encodeTime(AT + DAY, 'UTCTime'),
        encodeSequence([entry]),
    ]);
    return encodeSequence([tbs, algorithm, encodeBitString(Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))]);
}

/** An empty CRL naming `issuer`, whose signature is nonsense on purpose. */
function emptyCrl(issuer: Certificate, options: { version?: bigint; sha1?: boolean; oddExtension?: boolean; wideTime?: boolean } = {}): Uint8Array {
    // ecdsa-with-SHA1 when asked: pkinative refuses to treat such a signature as
    // evidence, which is what makes "never checked" reachable here.
    const algorithm = encodeAlgorithmIdentifier(options.sha1 === true ? '1.2.840.10045.4.1' : '1.2.840.10045.4.3.2');
    const tbs = encodeSequence([
        encodeInteger(options.version ?? 1n),
        algorithm,
        issuer.subject.der,
        // A GeneralizedTime before 2050 when asked, which RFC 5280 §4.1.2.5 says
        // must be a UTCTime: a diagnostic on a list that is otherwise perfectly
        // usable, so the report can be seen swallowing one without the list
        // becoming unusable for a different reason.
        encodeTime(AT - DAY, options.wideTime === true ? 'GeneralizedTime' : 'UTCTime'),
        encodeTime(AT + DAY, 'UTCTime'),
        // A critical extension nobody recognises. RFC 5280 §6.3.3 says such a
        // list MUST NOT be used.
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
