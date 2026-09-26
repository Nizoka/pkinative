import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
    checkCriticalExtensions,
    checkIssuingCapability,
    checkSignature,
    checkValidity,
    PROCESSED_CRITICAL_EXTENSIONS,
    validateCertificatePath,
    type PathContext,
    type PathState,
} from '../../src/path/path-validate.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints, encodeKeyUsage, encodeSubjectAltName } from '../../src/build/build-structures.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import type { Certificate } from '../../src/types/x509-types.js';
import type { SignatureResult, SignatureVerdict } from '../../src/types/path-types.js';

/**
 * RFC 5280 §6, clause by clause.
 *
 * Every step function is exported precisely so it can be tested against its
 * clause with a synthetic state, rather than only end to end through a whole
 * chain. A closure factory would have hidden the state and left the steps
 * reachable one way only — which is the difference between a PKITS case being
 * a three-line test and being an afternoon.
 *
 * The chain is Let's Encrypt's real hierarchy from `tests/fixtures/certs`,
 * because a path validator tested only on certificates it built itself is a
 * path validator tested against its own assumptions.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const load = (name: string): Certificate => parseCertificate(new Uint8Array(readFileSync(`tests/fixtures/certs/${name}.der`)), quiet);

/**
 * `R12` really is issued by `ROOT_X1`; the committed leaf is **not** issued by
 * R12 — its issuer is `CN=YE2`, which is not in the fixture set. That is a
 * fact about the fixtures worth stating rather than working around, and it is
 * why the three-certificate cases use a leaf built here, with `R12`'s own
 * subject bytes as its issuer. Signature verdicts are an *input* to §6, so a
 * synthetic leaf tests exactly what this module decides and nothing else.
 */
const ROOT_X1 = load('isrg-root-x1');
const R12 = load('lets-encrypt-r12');
const FIXTURE_LEAF = load('letsencrypt-org-leaf');

/** Inside the validity of R12 (2024-03-13 … 2027-03-12) and of the root. */
const AT = Date.UTC(2026, 9, 1);

/** A leaf that chains to R12 by encoded name, valid around `AT`. */
async function syntheticLeaf(overrides: { notBefore?: number; notAfter?: number } = {}): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificate({
        serialNumber: 7n,
        issuerDer: R12.subject.der,
        subject: [[{ type: '2.5.4.3', value: 'leaf.example' }]],
        notBefore: overrides.notBefore ?? AT - 86_400_000,
        notAfter: overrides.notAfter ?? AT + 86_400_000,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

/** A leaf that chains to R12 and asserts one DNS name in its SAN. */
async function syntheticLeafWithDns(host: string): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificate({
        serialNumber: 11n,
        issuerDer: R12.subject.der,
        subject: [[{ type: '2.5.4.3', value: host }]],
        notBefore: AT - 86_400_000,
        notAfter: AT + 86_400_000,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: host }]) },
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

const LEAF = await syntheticLeaf();

const valid = (...certificates: readonly Certificate[]): SignatureResult[] =>
    certificates.map((certificate) => ({ certificate, verdict: 'valid' as SignatureVerdict }));

const state = (maxPathLength = 10): PathState => ({ maxPathLength, expectedIssuer: null, seen: new Set(), reasons: [] });

const context = (overrides: Partial<PathContext> = {}): PathContext => ({
    at: AT,
    signatures: new Map(),
    trustAnchorSubjects: new Set(),
    maxPathLength: 10,
    maxCertificates: 10,
    ...overrides,
});

const codes = (report: { reasons: ReadonlyArray<{ code: string }> }): string[] => report.reasons.map((r) => r.code);

describe('checkValidity — §6.1.3 (a)(2)', () => {
    it('should accept an instant inside the window', () => {
        expect(checkValidity(LEAF, LEAF.validity.notBefore.epochMilliseconds + 1000, 'path[0]')).toBeNull();
    });

    it('should report NOT_YET_VALID before notBefore, with both instants in the message', () => {
        const reason = checkValidity(LEAF, LEAF.validity.notBefore.epochMilliseconds - 1, 'path[0]');
        expect(reason?.code).toBe('PKI_REASON_NOT_YET_VALID');
        expect(reason?.path).toBe('path[0].validity');
        expect(reason?.message).toContain(new Date(LEAF.validity.notBefore.epochMilliseconds).toISOString());
    });

    it('should report EXPIRED after notAfter', () => {
        const reason = checkValidity(LEAF, LEAF.validity.notAfter.epochMilliseconds + 1, 'path[0]');
        expect(reason?.code).toBe('PKI_REASON_EXPIRED');
    });

    it('should treat both boundary instants as inside the window', () => {
        // RFC 5280 §4.1.2.5 makes the window inclusive at both ends. Getting
        // this wrong rejects a certificate for one millisecond a year.
        expect(checkValidity(LEAF, LEAF.validity.notBefore.epochMilliseconds, 'p')).toBeNull();
        expect(checkValidity(LEAF, LEAF.validity.notAfter.epochMilliseconds, 'p')).toBeNull();
    });
});

describe('checkCriticalExtensions — §6.1.3 (f)', () => {
    it('should accept a real certificate whose critical extensions are all processed', () => {
        expect(checkCriticalExtensions(FIXTURE_LEAF, 'path[0]')).toEqual([]);
        expect(checkCriticalExtensions(ROOT_X1, 'path[1]')).toEqual([]);
    });

    it('should refuse a critical extension this validator does not process', () => {
        // Fail closed: the whole reason incremental implementation is safe.
        const certificate = { ...FIXTURE_LEAF, extensions: [{ oid: '1.3.6.1.4.1.99999.7', critical: true, valueDer: new Uint8Array(0), kind: 'unknown' }] } as unknown as Certificate;
        const reasons = checkCriticalExtensions(certificate, 'path[0]');
        expect(reasons.map((r) => r.code)).toEqual(['PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION']);
        expect(reasons[0]?.message).toContain('1.3.6.1.4.1.99999.7');
    });

    it('should ignore a non-critical extension it does not process', () => {
        const certificate = { ...FIXTURE_LEAF, extensions: [{ oid: '1.3.6.1.4.1.99999.7', critical: false, valueDer: new Uint8Array(0), kind: 'unknown' }] } as unknown as Certificate;
        expect(checkCriticalExtensions(certificate, 'path[0]')).toEqual([]);
    });

    it('should process nameConstraints, and refuse the policy extensions until they are implemented', () => {
        // The extensions whose silent omission would be a CVE: a chain the
        // issuing CA constrained, answered "valid". nameConstraints is
        // processed now; the three policy extensions are still refused.
        expect(PROCESSED_CRITICAL_EXTENSIONS.has('2.5.29.30')).toBe(true);
        for (const oid of ['2.5.29.36', '2.5.29.33', '2.5.29.54']) {
            expect(PROCESSED_CRITICAL_EXTENSIONS.has(oid), oid).toBe(false);
        }
    });
});

describe('checkSignature — §6.1.3 (a)(1)', () => {
    it('should accept a verdict of valid', () => {
        const signatures = new Map([[Buffer.from(LEAF.der).toString('hex'), { verdict: 'valid' as SignatureVerdict }]]);
        expect(checkSignature(LEAF, context({ signatures }), 'path[0]')).toBeNull();
    });

    it('should report SIGNATURE_INVALID for a verdict of invalid', () => {
        const signatures = new Map([[Buffer.from(LEAF.der).toString('hex'), { verdict: 'invalid' as SignatureVerdict }]]);
        expect(checkSignature(LEAF, context({ signatures }), 'path[0]')?.code).toBe('PKI_REASON_SIGNATURE_INVALID');
    });

    it('should report NOT_CHECKED, never INVALID, when the host could not decide', () => {
        const signatures = new Map([[Buffer.from(LEAF.der).toString('hex'), { verdict: 'not-checked' as SignatureVerdict, errorCode: 'PKI_CRYPTO_KEY_UNSUPPORTED', detail: 'no Ed448 here' }]]);
        const reason = checkSignature(LEAF, context({ signatures }), 'path[0]');
        expect(reason?.code).toBe('PKI_REASON_SIGNATURE_NOT_CHECKED');
        expect(reason?.errorCode).toBe('PKI_CRYPTO_KEY_UNSUPPORTED');
    });

    it('should report NOT_CHECKED with a default explanation when the caller gave none', () => {
        // A caller may legitimately say only "could not check". The report
        // still has to carry a code and a sentence, because a reason with an
        // empty message is a reason nobody can act on.
        const signatures = new Map([[Buffer.from(LEAF.der).toString('hex'), { verdict: 'not-checked' as SignatureVerdict }]]);
        const reason = checkSignature(LEAF, context({ signatures }), 'path[0]');
        expect(reason?.code).toBe('PKI_REASON_SIGNATURE_NOT_CHECKED');
        expect(reason?.errorCode).toBe('PKI_CRYPTO_KEY_UNSUPPORTED');
        expect(reason?.message).toContain('the signature could not be checked');
    });

    it('should report NOT_CHECKED, never silence, when no verdict was supplied at all', () => {
        // The default that keeps a validator from passing when the caller
        // forgot to verify anything.
        const reason = checkSignature(LEAF, context(), 'path[0]');
        expect(reason?.code).toBe('PKI_REASON_SIGNATURE_NOT_CHECKED');
        expect(reason?.message).toContain('no signature verdict was supplied');
    });
});

describe('checkIssuingCapability — §6.1.4 (k), (l), (n)', () => {
    it('should accept a real CA that asserts cA and keyCertSign', () => {
        expect(checkIssuingCapability(R12, state(), 'path[1]')).toEqual([]);
        expect(checkIssuingCapability(ROOT_X1, state(), 'path[2]')).toEqual([]);
    });

    it('should refuse an end-entity certificate as an issuer', () => {
        // The leaf asserts cA: FALSE. A validator that skipped this check is
        // the 2008 Basic Constraints attack.
        const reasons = checkIssuingCapability(FIXTURE_LEAF, state(), 'path[1]');
        expect(reasons.map((r) => r.code)).toContain('PKI_REASON_NOT_A_CA');
        expect(reasons[0]?.message).toContain('cA in basicConstraints');
    });

    it('should refuse a CA whose keyUsage omits keyCertSign', () => {
        const certificate = { ...R12, extensions: R12.extensions.map((e) => (e.kind === 'keyUsage' ? { ...e, usages: ['digitalSignature'] } : e)) } as unknown as Certificate;
        const reasons = checkIssuingCapability(certificate, state(), 'path[1]');
        expect(reasons.some((r) => r.message.includes('keyCertSign in keyUsage'))).toBe(true);
    });

    it('should spend one unit of path length per issuer, and report when it runs out', () => {
        const s = state(1);
        expect(checkIssuingCapability(R12, s, 'path[1]')).toEqual([]);
        expect(s.maxPathLength).toBe(0);
        expect(checkIssuingCapability(R12, s, 'path[2]').map((r) => r.code)).toContain('PKI_REASON_PATH_TOO_LONG');
    });

    it('should leave the budget alone when a pathLenConstraint is looser than it', () => {
        // §6.1.4 (m) lowers the budget, never raises it. A CA asserting
        // pathLenConstraint: 9 under a budget of 2 does not buy seven more
        // certificates, and a validator that took the constraint at face
        // value would let it.
        const certificate = { ...R12, extensions: R12.extensions.map((e) => (e.kind === 'basicConstraints' ? { ...e, pathLenConstraint: 9 } : e)) } as unknown as Certificate;
        const s = state(3);
        expect(checkIssuingCapability(certificate, s, 'path[1]')).toEqual([]);
        expect(s.maxPathLength).toBe(2);
    });

    it('should lower the budget to a pathLenConstraint that is tighter', () => {
        // R12 carries pathLenConstraint 0, so nothing may be issued below it.
        const s = state(10);
        checkIssuingCapability(R12, s, 'path[1]');
        expect(s.maxPathLength).toBe(0);
    });
});

describe('validateCertificatePath', () => {
    it('should accept the real Let’s Encrypt chain against its root', () => {
        const report = validateCertificatePath({
            certificates: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(LEAF, R12),
        });
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        expect(report.path).toHaveLength(3);
    });

    it('should not check the trust anchor’s own signature', () => {
        // A root's self-signature proves it is self-consistent, which is not
        // what trust is. Only the leaf and the intermediate need a verdict.
        const report = validateCertificatePath({
            certificates: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(LEAF, R12),
        });
        expect(codes(report)).not.toContain('PKI_REASON_SIGNATURE_NOT_CHECKED');
    });

    it('should report NO_TRUST_ANCHOR for a chain that ends nowhere', () => {
        const report = validateCertificatePath({ certificates: [LEAF, R12], trustAnchors: [], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        expect(report.valid).toBe(false);
    });

    it('should report ISSUER_NOT_FOUND when two certificates do not chain, naming the name looked for', () => {
        const report = validateCertificatePath({ certificates: [FIXTURE_LEAF, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(FIXTURE_LEAF) });
        const reason = report.reasons.find((r) => r.code === 'PKI_REASON_ISSUER_NOT_FOUND');
        expect(reason).toBeDefined();
        // The committed leaf names CN=YE2, which is not in the fixture set:
        // a genuine mismatch rather than a contrived one.
        expect(reason?.message).toContain('YE2');
    });

    it('should report every applicable reason, not only the first', () => {
        // A caller fixing one problem per round trip is a caller the report
        // failed. Expired AND unverified, in one answer.
        const report = validateCertificatePath({
            certificates: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: LEAF.validity.notAfter.epochMilliseconds + 1,
            signatures: [{ certificate: LEAF, verdict: 'invalid' }],
        });
        expect(codes(report)).toContain('PKI_REASON_EXPIRED');
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_INVALID');
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_NOT_CHECKED');
    });

    it('should report PATH_LOOPS rather than following a repeated certificate', () => {
        const report = validateCertificatePath({ certificates: [LEAF, R12, R12, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).toContain('PKI_REASON_PATH_LOOPS');
    });

    it('should stop at maxChainLength and say which limit stopped it', () => {
        const report = validateCertificatePath({
            certificates: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(LEAF, R12),
            limits: { maxChainLength: 2 },
        });
        const reason = report.reasons.find((r) => r.code === 'PKI_REASON_LIMIT_EXCEEDED');
        expect(reason?.limit).toBe('maxChainLength');
    });

    it('should accept a chain whose anchor is supplied only in trustAnchors', () => {
        // A server sends the chain both ways in practice; refusing one of them
        // would be refusing half the internet.
        const report = validateCertificatePath({ certificates: [LEAF, R12], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).not.toContain('PKI_REASON_NO_TRUST_ANCHOR');
        expect(report.reasons).toEqual([]);
    });

    it('should answer rather than throw for an empty chain', () => {
        const report = validateCertificatePath({ certificates: [], trustAnchors: [ROOT_X1], at: AT });
        expect(report.valid).toBe(false);
        expect(codes(report)).toEqual(['PKI_REASON_NO_TRUST_ANCHOR']);
        expect(report.path).toEqual([]);
    });

    it('should never throw for a validation issue, whatever is wrong', () => {
        // The contract the whole third vocabulary exists for.
        expect(() => validateCertificatePath({ certificates: [LEAF], trustAnchors: [], at: 0 })).not.toThrow();
    });

    it('should still throw for API misuse, which is not a validation issue', () => {
        expect(() => validateCertificatePath({ certificates: [LEAF], trustAnchors: [], at: AT, limits: { maxChainLenght: 3 } as never }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_INVALID' }));
    });

    it('should refuse a leaf whose name falls outside its CA’s name constraints', async () => {
        // The classic attack this check exists for: a CA constrained to
        // `.example.com` issuing for a host it was never allowed to name.
        const constrained = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'dNSName', value: 'example.com', der: new Uint8Array(0) }, minimum: 0, maximum: undefined }],
                excludedSubtrees: undefined },
        ] } as unknown as Certificate;
        const outside = await syntheticLeafWithDns('evil.test');
        const report = validateCertificatePath({
            certificates: [outside, constrained, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(outside, constrained),
        });
        expect(codes(report)).toContain('PKI_REASON_NAME_NOT_PERMITTED');
        expect(report.valid).toBe(false);
    });

    it('should accept a leaf whose name is inside its CA’s name constraints', async () => {
        const constrained = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'dNSName', value: 'example.com', der: new Uint8Array(0) }, minimum: 0, maximum: undefined }],
                excludedSubtrees: undefined },
        ] } as unknown as Certificate;
        const inside = await syntheticLeafWithDns('host.example.com');
        const report = validateCertificatePath({
            certificates: [inside, constrained, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(inside, constrained),
        });
        expect(codes(report)).not.toContain('PKI_REASON_NAME_NOT_PERMITTED');
    });

    it('should not constrain the constraining CA by its own subtrees', async () => {
        // §6.1.4 (g) binds what a CA issues, never the CA itself. R12's own
        // subject (CN=R12) is nothing like `example.com`, and a validator that
        // applied a CA's constraints to itself would refuse every constrained
        // hierarchy in existence.
        const constrained = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'directoryName', name: { rdns: [], der: new Uint8Array(0) }, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }],
                excludedSubtrees: undefined },
        ] } as unknown as Certificate;
        const inside = await syntheticLeafWithDns('host.example.com');
        const report = validateCertificatePath({
            certificates: [inside, constrained, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(inside, constrained),
        });
        // An empty directoryName subtree is a prefix of every name, so the
        // leaf passes; what matters is that R12 was never tested against it.
        expect(codes(report)).not.toContain('PKI_REASON_NAME_NOT_PERMITTED');
    });

    it('should report an excluded subject and an excluded SAN as excluded, not merely unpermitted', async () => {
        // The two are different answers: "not permitted" can be fixed by a CA
        // above granting the name, "excluded" cannot be fixed at all.
        const excluding = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: undefined,
                excludedSubtrees: [
                    { base: { kind: 'dNSName', value: 'banned.test', der: new Uint8Array(0) }, minimum: 0, maximum: undefined },
                    { base: { kind: 'directoryName', name: { rdns: [], der: new Uint8Array(0) }, der: new Uint8Array(0) }, minimum: 0, maximum: undefined },
                ] },
        ] } as unknown as Certificate;
        const banned = await syntheticLeafWithDns('host.banned.test');
        const report = validateCertificatePath({
            certificates: [banned, excluding, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(banned, excluding),
        });
        const excluded = report.reasons.filter((r) => r.code === 'PKI_REASON_NAME_EXCLUDED');
        // One for the subject (every name is below an empty directoryName
        // subtree) and one for the SAN.
        expect(excluded.map((r) => r.path).sort()).toEqual(['path[0].subject', 'path[0].subjectAltName']);
        expect(codes(report)).not.toContain('PKI_REASON_NAME_NOT_PERMITTED');
    });

    it('should refuse a subject outside a directoryName permitted subtree', async () => {
        // The subject is constrained too, not only the SAN: testing only the
        // SAN lets a constrained CA issue for a CN nobody checked.
        const constrained = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'directoryName', name: { rdns: [[{ type: '2.5.4.6', value: undefined, valueDer: Uint8Array.of(0x13, 0x02, 0x46, 0x52) }]], der: new Uint8Array(0) }, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }],
                excludedSubtrees: undefined },
        ] } as unknown as Certificate;
        // The leaf's subject is CN=host.example.com with no country RDN, so it
        // is not below C=FR.
        const outside = await syntheticLeafWithDns('host.example.com');
        const report = validateCertificatePath({
            certificates: [outside, constrained, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(outside, constrained),
        });
        const subject = report.reasons.find((r) => r.path === 'path[0].subject');
        expect(subject?.code).toBe('PKI_REASON_NAME_NOT_PERMITTED');
        expect(subject?.message).toContain('host.example.com');
    });

    it('should not constrain an empty subject as a directoryName', async () => {
        // RFC 5280 §4.1.2.6 puts the identity in a critical SAN when the
        // subject is empty; testing that empty name against a directoryName
        // subtree would refuse a certificate for having no name.
        const constrained = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'directoryName', name: { rdns: [[{ type: '2.5.4.6', value: undefined, valueDer: Uint8Array.of(0x13, 0x02, 0x46, 0x52) }]], der: new Uint8Array(0) }, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }],
                excludedSubtrees: undefined },
        ] } as unknown as Certificate;
        const anonymous = { ...LEAF, subject: { rdns: [], der: new Uint8Array(0) } } as unknown as Certificate;
        const report = validateCertificatePath({
            certificates: [anonymous, constrained, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(anonymous, constrained),
        });
        expect(report.reasons.filter((r) => r.path === 'path[0].subject')).toEqual([]);
    });

    it('should be true only when there is no reason at all', () => {
        const report = validateCertificatePath({ certificates: [LEAF, R12, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(report.valid).toBe(report.reasons.length === 0);
    });
});
