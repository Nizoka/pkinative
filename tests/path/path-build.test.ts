import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints, encodeExtendedKeyUsage, encodeKeyUsage } from '../../src/build/build-structures.js';
import { buildCertificatePath } from '../../src/path/path-build.js';
import type { SignatureResult } from '../../src/types/path-types.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';

/**
 * Path building, and the two things that make it a search rather than a walk.
 *
 * **Cross-signing.** One subject name can have several plausible issuers, and a
 * builder that took the first match would fail on chains that validate
 * perfectly through the other. Let's Encrypt's own hierarchy is the everyday
 * case, so the test below constructs it: two CAs with the *same subject name*,
 * only one of which leads to the trusted root.
 *
 * **The bound.** Path building is exponential in the candidate set and only
 * linear in the chain length, which is why `maxPathsExplored` is the
 * denial-of-service bound here rather than `maxChainLength`.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const AT = Date.UTC(2026, 9, 1);
const DAY = 86_400_000;

const ROOT = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/isrg-root-x1.der')), quiet);
const R12 = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/lets-encrypt-r12.der')), quiet);

interface Material { readonly certificate: Certificate; readonly sign: (data: Uint8Array) => Promise<Uint8Array> }

/** Build a certificate signed by a key generated here, and keep its signer. */
async function issue(options: {
    readonly subject: string;
    readonly issuerDer: Uint8Array;
    readonly ca: boolean;
    readonly serial: bigint;
    readonly notAfter?: number;
    /** KeyPurposeId OIDs for an extKeyUsage extension; omitted means the extension is absent. */
    readonly purposes?: readonly string[];
}): Promise<Material> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
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
                    { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign']) },
                ]
                : [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) }]),
            ...(options.purposes === undefined ? [] : [{ oid: '2.5.29.37', value: encodeExtendedKeyUsage([...options.purposes]) }]),
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return {
        certificate: parseCertificate(der, quiet),
        sign: async (data) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data)),
    };
}

/** Every certificate is asserted valid: the point here is the search, not the maths. */
const allValid = (...certificates: readonly Certificate[]): SignatureResult[] =>
    certificates.map((certificate) => ({ certificate, verdict: 'valid' as const }));

const codes = (report: { reasons: ReadonlyArray<{ code: string }> }): string[] => report.reasons.map((r) => r.code);

// ── A hierarchy under ISRG Root X1, built here ───────────────────────

const INTERMEDIATE = await issue({ subject: 'Example Intermediate', issuerDer: ROOT.subject.der, ca: true, serial: 100n });
const LEAF = await issue({ subject: 'host.example', issuerDer: INTERMEDIATE.certificate.subject.der, ca: false, serial: 101n });

describe('buildCertificatePath', () => {
    it('should find a two-step path from an unordered bag', () => {
        // The order is deliberately wrong: a builder that assumed the bag was
        // a chain would fail here.
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [ROOT, R12, INTERMEDIATE.certificate],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate),
        });
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        // Three: the anchor joins the path even when it was supplied only in
        // trustAnchors, because section 6.1.2 initialises the state FROM it —
        // its name constraints and its basicConstraints bind what it issued.
        expect(report.path).toHaveLength(3);
        expect(report.explored).toBeGreaterThan(0);
    });

    it('should ignore candidates that have nothing to do with the path', () => {
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [R12, R12, ROOT, INTERMEDIATE.certificate, R12],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate),
        });
        expect(report.valid).toBe(true);
    });

    it('should find a path when the anchor is supplied only in trustAnchors', () => {
        // The anchor is a usable issuer too, and a caller who supplied it only
        // there still expects a path through it.
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [INTERMEDIATE.certificate],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate),
        });
        expect(report.valid).toBe(true);
    });

    it('should backtrack past a cross-signed issuer that leads nowhere', async () => {
        // THE case this function exists for. Two CAs share a subject name; only
        // one is issued by the trusted root. A builder taking the first match
        // fails on the chains that validate through the other.
        const decoy = await issue({ subject: 'Example Intermediate', issuerDer: R12.subject.der, ca: true, serial: 200n });
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            // The decoy comes first on purpose.
            candidates: [decoy.certificate, INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate, decoy.certificate),
        });
        expect(report.valid).toBe(true);
        expect(report.path).toHaveLength(3);
        // It had to try the decoy before finding the real one.
        expect(report.explored).toBeGreaterThan(2);
    });

    it('should report the deepest attempt’s reasons when no path is accepted', () => {
        // "No path found" without saying why is a report nobody can act on.
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [INTERMEDIATE.certificate],
            trustAnchors: [R12],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate),
        });
        expect(report.valid).toBe(false);
        expect(codes(report)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        // The path shown is how far it got, not just the leaf.
        expect(report.path.length).toBeGreaterThan(1);
    });

    it('should report why the leaf alone failed when there is nothing to extend with', () => {
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate),
        });
        expect(report.valid).toBe(false);
        expect(codes(report)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        expect(report.path).toEqual([LEAF.certificate]);
    });

    it('should fail closed on a pair with no signature verdict', () => {
        // A builder that assumed an unverified link was fine would construct
        // paths §6 then accepts on evidence nobody supplied.
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
        });
        expect(report.valid).toBe(false);
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_NOT_CHECKED');
    });

    it('should not follow a loop, however the candidates name each other', async () => {
        // Two CAs that each name the other as issuer: a builder without a
        // visited set recurses until the stack gives out.
        const a = await issue({ subject: 'Loop A', issuerDer: ROOT.subject.der, ca: true, serial: 300n });
        const b = await issue({ subject: 'Loop B', issuerDer: a.certificate.subject.der, ca: true, serial: 301n });
        const aAgain = await issue({ subject: 'Loop A', issuerDer: b.certificate.subject.der, ca: true, serial: 302n });
        const leaf = await issue({ subject: 'looped.example', issuerDer: a.certificate.subject.der, ca: false, serial: 303n });
        const report = buildCertificatePath({
            leaf: leaf.certificate,
            candidates: [aAgain.certificate, b.certificate, a.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(leaf.certificate, a.certificate, b.certificate, aAgain.certificate),
        });
        // It terminates, and it finds the path through the real A.
        expect(report.valid).toBe(true);
        // [leaf], [leaf, A'], [leaf, A', B], [leaf, A', B, A] — A' is never revisited.
        expect(report.explored).toBe(4);
    });

    it('should stop at maxPathsExplored and say so', () => {
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate),
            limits: { maxPathsExplored: 1 },
        });
        expect(report.valid).toBe(false);
        const reason = report.reasons.find((r) => r.code === 'PKI_REASON_LIMIT_EXCEEDED');
        expect(reason?.limit).toBe('maxPathsExplored');
        expect(report.explored).toBe(1);
    });

    it('should not spend the whole budget on a bag designed to be expensive', async () => {
        // The denial-of-service shape: many CAs sharing one subject name, so
        // every step has many candidates. A few kilobytes of input, unbounded
        // work without the bound.
        const decoys: Certificate[] = [];
        const verdicts: SignatureResult[] = [];
        for (let i = 0; i < 12; i += 1) {
            const decoy = await issue({ subject: 'Example Intermediate', issuerDer: R12.subject.der, ca: true, serial: BigInt(400 + i) });
            decoys.push(decoy.certificate);
            verdicts.push({ certificate: decoy.certificate, verdict: 'valid' });
        }
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [...decoys, INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: [...allValid(LEAF.certificate, INTERMEDIATE.certificate), ...verdicts],
            limits: { maxPathsExplored: 20 },
        });
        // Either it found the real path, or it hit the bound — never a hang.
        expect(report.explored).toBeLessThanOrEqual(20);
        if (!report.valid) expect(codes(report)).toContain('PKI_REASON_LIMIT_EXCEEDED');
    });

    it('should read the verdicts once per search, not once per path it tries', async () => {
        // Each candidate path used to rebuild the verdict index, re-encoding
        // every verdict's certificates: paths x verdicts x certificate size.
        // Sixty-five certificates sharing one name took eighteen minutes.
        let reads = 0;
        const counted = (certificate: Certificate): Certificate => new Proxy(certificate, {
            get: (target, key, receiver) => {
                if (key === 'der') reads += 1;
                return Reflect.get(target, key, receiver) as unknown;
            },
        });
        const verdicts: SignatureResult[] = [];
        for (let i = 0; i < 12; i += 1) {
            const decoy = await issue({ subject: 'Example Intermediate', issuerDer: R12.subject.der, ca: true, serial: BigInt(500 + i) });
            verdicts.push({ certificate: counted(decoy.certificate), verdict: 'valid' });
        }
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [...verdicts.map((v) => v.certificate), ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: verdicts,
            limits: { maxPathsExplored: 20 },
        });
        expect(report.explored).toBe(13);
        // Twelve reads to index the verdicts, and a few per path for the
        // certificates it walks — never twelve per path.
        expect(reads).toBeLessThan(verdicts.length * report.explored);
        reads = 0;
        buildCertificatePath({ leaf: LEAF.certificate, candidates: [], trustAnchors: [ROOT], at: AT, signatures: verdicts });
        expect(reads).toBe(verdicts.length);
    });

    it('should not extend past maxChainLength', () => {
        const report = buildCertificatePath({
            leaf: LEAF.certificate,
            candidates: [INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(LEAF.certificate, INTERMEDIATE.certificate),
            limits: { maxChainLength: 1 },
        });
        expect(report.valid).toBe(false);
        // The leaf alone fills a chain of one: nothing is extended.
        expect(report.explored).toBe(1);
    });

    it('should accept a leaf that is itself a trust anchor, without exploring', () => {
        // The real question "is this root in my trust store?" — and the shortest
        // possible path, which is one certificate.
        const report = buildCertificatePath({
            leaf: ROOT, candidates: [R12, INTERMEDIATE.certificate], trustAnchors: [ROOT], at: AT,
            signatures: [],
        });
        expect(report.valid).toBe(true);
        expect(report.path).toEqual([ROOT]);
        expect(report.explored).toBe(1);
    });

    it('should abandon the whole search once the budget runs out deep in it', async () => {
        // The bound has to stop the search, not just the branch it was reached
        // on: a builder that carried on with the next sibling would spend the
        // budget again at every level.
        const subCa = await issue({ subject: 'Example Sub CA', issuerDer: INTERMEDIATE.certificate.subject.der, ca: true, serial: 500n });
        const deepLeaf = await issue({ subject: 'deep.example', issuerDer: subCa.certificate.subject.der, ca: false, serial: 501n });
        const report = buildCertificatePath({
            leaf: deepLeaf.certificate,
            candidates: [subCa.certificate, INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(deepLeaf.certificate, subCa.certificate, INTERMEDIATE.certificate),
            limits: { maxPathsExplored: 2 },
        });
        expect(report.valid).toBe(false);
        expect(report.explored).toBe(2);
        expect(codes(report)).toContain('PKI_REASON_LIMIT_EXCEEDED');
    });

    it('should find that same deep path when the budget allows it', async () => {
        const subCa = await issue({ subject: 'Example Sub CA 2', issuerDer: INTERMEDIATE.certificate.subject.der, ca: true, serial: 600n });
        const deepLeaf = await issue({ subject: 'deep2.example', issuerDer: subCa.certificate.subject.der, ca: false, serial: 601n });
        const report = buildCertificatePath({
            leaf: deepLeaf.certificate,
            candidates: [subCa.certificate, INTERMEDIATE.certificate, ROOT],
            trustAnchors: [ROOT],
            at: AT,
            signatures: allValid(deepLeaf.certificate, subCa.certificate, INTERMEDIATE.certificate),
        });
        expect(report.reasons).toEqual([]);
        expect(report.path).toHaveLength(4);
    });

    it('should refuse a budget of zero as API misuse, not as a policy', () => {
        // Limits are positive integers or Infinity by contract, so a zero is a
        // configuration mistake rather than a caller disabling the search — and
        // the closed enumeration says so instead of silently exploring nothing.
        expect(() => buildCertificatePath({
            leaf: LEAF.certificate, candidates: [], trustAnchors: [ROOT], at: AT,
            limits: { maxPathsExplored: 0 },
        })).toThrow(expect.objectContaining({ code: 'PKI_LIMIT_INVALID' }));
    });

    it('should still throw for API misuse, which is not a path-building issue', () => {
        expect(() => buildCertificatePath({
            leaf: LEAF.certificate, candidates: [], trustAnchors: [], at: AT,
            limits: { maxPathsExploredd: 3 } as never,
        })).toThrow(expect.objectContaining({ code: 'PKI_LIMIT_INVALID' }));
    });

    it('should never throw for a path-building issue', () => {
        expect(() => buildCertificatePath({ leaf: LEAF.certificate, candidates: [], trustAnchors: [], at: 0 })).not.toThrow();
    });
});

describe('buildCertificatePath — the purpose is part of the search', () => {
    const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
    const EMAIL = '1.3.6.1.5.5.7.3.4';

    /**
     * A bag holding two intermediates of the same name: one restricted to
     * signing e-mail, one unrestricted. Only the second can carry a serverAuth
     * leaf, and the restricted one comes **first** so that a builder unaware of
     * the purpose picks it.
     *
     * This is x509-limbo's `bettertls::pathbuilding` shape, and it is what
     * proves the purposes have to go *into* the search: checking them after a
     * path is chosen answers "no acceptable path" while one existed.
     */
    async function bag(): Promise<{ leaf: Certificate; candidates: Certificate[]; signatures: SignatureResult[] }> {
        const restricted = await issue({ subject: 'Shared ICA', issuerDer: ROOT.subject.der, ca: true, serial: 91n, purposes: [EMAIL] });
        const open = await issue({ subject: 'Shared ICA', issuerDer: ROOT.subject.der, ca: true, serial: 92n });
        const leaf = await issue({ subject: 'leaf.example', issuerDer: restricted.certificate.subject.der, ca: false, serial: 93n, purposes: [SERVER_AUTH] });
        const candidates = [restricted.certificate, open.certificate];
        return {
            leaf: leaf.certificate,
            candidates,
            // Both intermediates are asserted to have signed the leaf, which is
            // what a cross-signed pair looks like to a builder.
            signatures: [
                { certificate: leaf.certificate, issuer: restricted.certificate, verdict: 'valid' },
                { certificate: leaf.certificate, issuer: open.certificate, verdict: 'valid' },
                ...allValid(restricted.certificate, open.certificate),
            ],
        };
    }

    it('should backtrack past an issuer that forbids the purpose, and find the one that does not', async () => {
        const { leaf, candidates, signatures } = await bag();
        const report = buildCertificatePath({ leaf, candidates, trustAnchors: [ROOT], at: AT, signatures, purposes: [SERVER_AUTH] });
        expect(codes(report)).toEqual([]);
        expect(report.valid).toBe(true);
        // The path it settled on is the unrestricted one, which is the whole
        // point: the restricted intermediate is still in the bag.
        expect(report.path).toHaveLength(3);
        expect(report.path[1]?.der).not.toEqual(candidates[0]?.der);
    });

    it('should report the purpose, not "no path", when every path forbids it', async () => {
        const { leaf, candidates, signatures } = await bag();
        const report = buildCertificatePath({
            leaf, candidates: [candidates[0] as Certificate], trustAnchors: [ROOT], at: AT, signatures,
            purposes: [SERVER_AUTH],
        });
        expect(codes(report)).toContain('PKI_REASON_PURPOSE_NOT_PERMITTED');
        // A caller told only "no path found" cannot see that the one path there
        // was is restricted to signing e-mail.
        expect(report.reasons.some((r) => r.message.includes(EMAIL))).toBe(true);
    });

    it('should take the first path when no purpose is required, as before', async () => {
        // The option is opt-in: omitting it leaves the search exactly as it was,
        // which is what keeps this a fix rather than a behaviour change for
        // callers who never asked the purpose question.
        const { leaf, candidates, signatures } = await bag();
        const report = buildCertificatePath({ leaf, candidates, trustAnchors: [ROOT], at: AT, signatures });
        expect(report.valid).toBe(true);
        expect(report.path[1]?.der).toEqual(candidates[0]?.der);
    });

    it('should judge the leaf alone against the purpose too', async () => {
        const solo = await issue({ subject: 'Self', issuerDer: ROOT.subject.der, ca: false, serial: 94n, purposes: [EMAIL] });
        const report = buildCertificatePath({
            leaf: solo.certificate, candidates: [], trustAnchors: [ROOT], at: AT,
            signatures: allValid(solo.certificate), purposes: [SERVER_AUTH],
        });
        expect(codes(report)).toContain('PKI_REASON_PURPOSE_NOT_PERMITTED');
    });
});

describe('buildCertificatePath — the search, step by step', () => {
    /** A CA named `subject`, issued under `issuer`'s name, whose own issuer is nowhere in the bag. */
    const ca = async (subject: string, issuer: string, serial: bigint): Promise<Certificate> => {
        const issuerName = (await issue({ subject: issuer, issuerDer: ROOT.subject.der, ca: true, serial: serial + 1000n })).certificate.subject.der;
        return (await issue({ subject, issuerDer: issuerName, ca: true, serial })).certificate;
    };

    it('should report the deepest dead end, not the last one, and not a shallower one found first', async () => {
        // leaf -> {A -> B, C}: the deepest attempt is [leaf, A, B], tried before C.
        const leaf = (await issue({ subject: 'deep.example', issuerDer: (await ca('Search X', 'Nowhere', 600n)).subject.der, ca: false, serial: 601n })).certificate;
        const a = await ca('Search X', 'Search Y', 602n);
        const b = await ca('Search Y', 'Nowhere Else', 603n);
        const c = await ca('Search X', 'Search Z', 604n);
        const report = buildCertificatePath({ leaf, candidates: [a, b, c], trustAnchors: [ROOT], at: AT, signatures: allValid(leaf, a, b, c) });
        expect(report.valid).toBe(false);
        expect(report.explored).toBe(4);
        expect(report.path.map((x) => x.der)).toEqual([leaf, a, b].map((x) => x.der));
    });

    it('should keep the first of two dead ends of the same depth', async () => {
        // leaf -> {A -> B -> F, C -> D -> G}: both reach depth three; the first stays.
        const leaf = (await issue({ subject: 'tie.example', issuerDer: (await ca('Tie X', 'Nowhere', 610n)).subject.der, ca: false, serial: 611n })).certificate;
        const a = await ca('Tie X', 'Tie Y', 612n);
        const b = await ca('Tie Y', 'Tie W', 613n);
        const f = await ca('Tie W', 'Nowhere Else', 614n);
        const c = await ca('Tie X', 'Tie Z', 615n);
        const d = await ca('Tie Z', 'Tie V', 616n);
        const g = await ca('Tie V', 'Nowhere Else', 617n);
        const report = buildCertificatePath({ leaf, candidates: [a, b, f, c, d, g], trustAnchors: [ROOT], at: AT, signatures: allValid(leaf, a, b, f, c, d, g) });
        expect(report.explored).toBe(7);
        expect(report.path.map((x) => x.der)).toEqual([leaf, a, b, f].map((x) => x.der));
    });

    it('should extend a certificate that merely bears an anchor\'s name, and never try one anchor twice', async () => {
        // C is named like the anchor without being it — another key, another
        // issuer. RFC 5280 §6.1.1 (d) makes an anchor a name *and* a key, so C
        // is one more link to walk through, not where the walk ends. And an
        // anchor also among the candidates is one issuer, not two.
        const anchor = await ca('Search Anchor', 'Anchor Parent', 620n);
        const other = await ca('Search Other', 'Nowhere', 621n);
        const lookalike = (await issue({ subject: 'Search Anchor', issuerDer: other.subject.der, ca: true, serial: 622n })).certificate;
        const leaf = (await issue({ subject: 'anchored.example', issuerDer: anchor.subject.der, ca: false, serial: 623n })).certificate;
        const report = buildCertificatePath({
            leaf, candidates: [lookalike, other, anchor], trustAnchors: [anchor], at: AT,
            signatures: [{ certificate: leaf, verdict: 'invalid' }],
        });
        expect(report.valid).toBe(false);
        // [leaf], [leaf, lookalike], [leaf, lookalike, other], [leaf, anchor] — never the anchor twice.
        expect(report.explored).toBe(4);
    });

    it('should not take a self-signed certificate that copies an anchor\'s name for the anchor', async () => {
        // The bag is the sender's. A self-signed "Search Anchor" with its own
        // key, signing a leaf for whoever the attacker likes, must not end the
        // walk as if it were the anchor: it is a link whose signature the real
        // anchor never made. Stopping on the name alone validated this chain.
        const anchor = await ca('Impostor Target', 'Impostor Parent', 640n);
        const impostor = await ca('Impostor Target', 'Impostor Target', 641n);
        const leaf = (await issue({ subject: 'victim.example', issuerDer: impostor.subject.der, ca: false, serial: 642n })).certificate;
        const report = buildCertificatePath({
            leaf, candidates: [impostor], trustAnchors: [anchor], at: AT,
            signatures: [
                // The impostor's key did sign the leaf; the anchor's did not sign the impostor.
                { certificate: leaf, issuer: impostor, verdict: 'valid' },
                { certificate: leaf, issuer: anchor, verdict: 'invalid' },
                { certificate: impostor, issuer: anchor, verdict: 'invalid' },
            ],
        });
        expect(report.valid).toBe(false);
        expect(report.reasons.map((r) => r.code)).toContain('PKI_REASON_SIGNATURE_INVALID');
        // …while the real anchor presented inside the bag is still itself.
        const real = buildCertificatePath({
            leaf, candidates: [impostor, anchor], trustAnchors: [anchor], at: AT,
            signatures: [{ certificate: leaf, issuer: anchor, verdict: 'valid' }, { certificate: leaf, issuer: impostor, verdict: 'invalid' }],
        });
        expect(real.valid).toBe(true);
        expect(real.path).toHaveLength(2);
    });

    it('should find a path through the second of two anchors that share a name', async () => {
        // A key rollover in the trust store: the leaf's issuer is the second
        // anchor, and the first anchor of that name, which validation tries on
        // its own, does not verify it. The anchors are issuers to the search too.
        const first = await ca('Rolled Root', 'Rolled Parent', 630n);
        const second = await ca('Rolled Root', 'Rolled Parent', 631n);
        const leaf = (await issue({ subject: 'rolled.example', issuerDer: second.subject.der, ca: false, serial: 632n })).certificate;
        const report = buildCertificatePath({
            leaf, candidates: [], trustAnchors: [first, second], at: AT,
            signatures: [{ certificate: leaf, issuer: first, verdict: 'invalid' }, { certificate: leaf, issuer: second, verdict: 'valid' }],
        });
        expect(report.valid).toBe(true);
        expect(report.path.map((x) => x.der)).toEqual([leaf, second].map((x) => x.der));
    });
});
