import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
    checkCriticalExtensions,
    checkIssuingCapability,
    checkNamesAgainstConstraints,
    checkSignature,
    checkValidity,
    PROCESSED_CRITICAL_EXTENSIONS,
    validateCertificatePath,
    type PathContext,
    type PathState,
} from '../../src/path/path-validate.js';
import { accumulateNameConstraints, initialNameConstraints, type NameConstraintState } from '../../src/path/path-name-constraints.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints, encodeKeyUsage, encodeSubjectAltName } from '../../src/build/build-structures.js';
import { encodeImplicit, encodeSequence, encodeString } from '../../src/asn1/asn1-encode.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import type { Certificate } from '../../src/types/x509-types.js';
import type { SignatureResult, SignatureVerdict } from '../../src/types/path-types.js';
import * as raw from '../helpers/cert-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';

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

/**
 * `excludedSubtrees` holding one dNSName, built from the public encoders.
 *
 * NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL,
 * excludedSubtrees [1] OPTIONAL }, each a SEQUENCE OF GeneralSubtree, itself a
 * SEQUENCE whose first element is a GeneralName — `[2] IA5String` for a DNS
 * name, and `minimum` left at its DEFAULT 0.
 */
function excludeDns(host: string): Uint8Array {
    const base = encodeImplicit(2, encodeString('ia5', host), { tagClass: 'context' });
    const subtrees = encodeSequence([encodeSequence([base])]);
    return encodeSequence([encodeImplicit(1, subtrees, { tagClass: 'context' })]);
}

/** A self-signed CA with the given subject, window and extra extensions. */
async function syntheticCa(options: {
    subject: string;
    notBefore?: number;
    notAfter?: number;
    extensions?: ReadonlyArray<{ oid: string; critical?: boolean; value: Uint8Array }>;
}): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const subject = [[{ type: '2.5.4.3', value: options.subject }]];
    const der = await createCertificate({
        serialNumber: 3n,
        issuer: subject,
        subject,
        notBefore: options.notBefore ?? AT - 86_400_000,
        notAfter: options.notAfter ?? AT + 86_400_000,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign']) },
            ...(options.extensions ?? []),
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

/** A certificate naming `issuerDer` as its issuer, with one DNS name in its SAN. */
async function syntheticUnder(issuerDer: Uint8Array, subject: string, host: string, ca = false): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificate({
        serialNumber: 5n,
        issuerDer,
        subject: [[{ type: '2.5.4.3', value: subject }]],
        notBefore: AT - 86_400_000,
        notAfter: AT + 86_400_000,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints(ca ? { cA: true } : { cA: false }) },
            ...(ca ? [{ oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign']) }] : []),
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: host }]) },
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

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
        expect(reasons.map((r) => r.code)).toEqual(['PKI_REASON_UNKNOWN_CRITICAL_EXTENSION']);
        expect(reasons[0]?.message).toContain('1.3.6.1.4.1.99999.7');
    });

    it('should ignore a non-critical extension it does not process', () => {
        const certificate = { ...FIXTURE_LEAF, extensions: [{ oid: '1.3.6.1.4.1.99999.7', critical: false, valueDer: new Uint8Array(0), kind: 'unknown' }] } as unknown as Certificate;
        expect(checkCriticalExtensions(certificate, 'path[0]')).toEqual([]);
    });

    it('should process every §6 extension that can constrain a chain', () => {
        // The extensions whose silent omission would be a CVE: a chain the
        // issuing CA constrained, answered "valid". All of §6's inputs are
        // processed now, so nothing in this list may quietly leave it.
        for (const oid of ['2.5.29.19', '2.5.29.15', '2.5.29.17', '2.5.29.30', '2.5.29.32', '2.5.29.33', '2.5.29.36', '2.5.29.54']) {
            expect(PROCESSED_CRITICAL_EXTENSIONS.has(oid), oid).toBe(true);
        }
    });

    it('should still refuse a critical extension outside that set', () => {
        // The fail-closed property itself, which is what makes the set above
        // the exact boundary of what a chain may rely on.
        expect(PROCESSED_CRITICAL_EXTENSIONS.has('2.5.29.31')).toBe(false); // cRLDistributionPoints
        expect(PROCESSED_CRITICAL_EXTENSIONS.has('1.3.6.1.5.5.7.1.1')).toBe(false); // authorityInfoAccess
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

    it('should spend no budget on a self-issued certificate', () => {
        // §6.1.4 (l): "If the certificate was not self-issued, verify that
        // max_path_length is greater than zero and decrement max_path_length by
        // 1." A CA re-keying itself adds a certificate to the path without
        // adding a link to the hierarchy, and charging it a step refuses a
        // rollover that fits the constraint its issuer wrote. ISRG Root X1 is
        // self-signed, so it is the fixture for this.
        const s = state(1);
        expect(checkIssuingCapability(ROOT_X1, s, 'path[2]')).toEqual([]);
        expect(s.maxPathLength).toBe(1);
        // …and a budget already exhausted is not reported against it either.
        const empty = state(0);
        expect(checkIssuingCapability(ROOT_X1, empty, 'path[2]')).toEqual([]);
        expect(checkIssuingCapability(R12, empty, 'path[1]').map((r) => r.code)).toContain('PKI_REASON_PATH_TOO_LONG');
    });

    it('should still honour a pathLenConstraint on a self-issued certificate', () => {
        // (m) applies either way: a constraint on a self-issued certificate
        // still binds what is below it, and skipping it because the step was
        // free would let a rollover certificate widen its own hierarchy.
        const certificate = { ...ROOT_X1, extensions: [...ROOT_X1.extensions, { kind: 'basicConstraints', oid: '2.5.29.19', critical: true, valueDer: new Uint8Array(0), cA: true, pathLenConstraint: 1 }] } as unknown as Certificate;
        const s = state(10);
        // `getExtension` returns the first match, so the constraint has to
        // replace ROOT_X1's own basicConstraints rather than follow it.
        const replaced = { ...ROOT_X1, extensions: certificate.extensions.filter((e, i) => !(e.kind === 'basicConstraints' && i < certificate.extensions.length - 1)) } as unknown as Certificate;
        checkIssuingCapability(replaced, s, 'path[2]');
        expect(s.maxPathLength).toBe(1);
    });
});

describe('validateCertificatePath', () => {
    it('should accept the real Let’s Encrypt chain against its root', () => {
        const report = validateCertificatePath({
            path: [LEAF, R12, ROOT_X1],
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
            path: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(LEAF, R12),
        });
        expect(codes(report)).not.toContain('PKI_REASON_SIGNATURE_NOT_CHECKED');
    });

    it('should check the trust anchor’s validity window even when it arrives only as an anchor', async () => {
        // Trusting a key is not the same as believing its owner still holds it.
        // x509-limbo's rfc5280::validity::expired-root expects a refusal, every
        // browser refuses, and this escaped until the anchor joined the path:
        // the post-loop branch pushed it without judging it, so a certificate
        // was judged differently depending on which input the caller put it in.
        const root = await syntheticCa({ subject: 'Retired Root', notBefore: AT - 200_000_000, notAfter: AT - 100_000_000 });
        const leaf = await syntheticUnder(root.subject.der, 'leaf.example', 'leaf.example');
        const report = validateCertificatePath({ path: [leaf], trustAnchors: [root], at: AT, signatures: valid(leaf) });
        expect(codes(report)).toEqual(['PKI_REASON_EXPIRED']);
        expect(report.reasons[0]?.path).toBe('path[1].validity');
        // …and the same anchor inside `path` gives the same answer.
        const inChain = validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: valid(leaf) });
        expect(codes(inChain)).toEqual(['PKI_REASON_EXPIRED']);
    });

    it('should refuse an unprocessed critical extension on the anchor too', async () => {
        const root = await syntheticCa({
            subject: 'Odd Root',
            // 2.5.29.35 authorityKeyIdentifier, which §6 does not process and
            // RFC 5280 §4.2.1.1 requires to be non-critical.
            extensions: [{ oid: '2.5.29.35', critical: true, value: encodeSequence([]) }],
        });
        const leaf = await syntheticUnder(root.subject.der, 'leaf.example', 'leaf.example');
        const report = validateCertificatePath({ path: [leaf], trustAnchors: [root], at: AT, signatures: valid(leaf) });
        expect(codes(report)).toEqual(['PKI_REASON_UNKNOWN_CRITICAL_EXTENSION']);
    });

    it('should not apply name constraints to a self-issued certificate that is not the final one', async () => {
        // §6.1.3: "Name constraints are not applied to self-issued certificates
        // (unless the certificate is the final certificate in the path)". A CA
        // re-keying itself keeps its own name, which its own constraints need
        // not permit — and refusing that refuses every key rollover.
        const top = await syntheticCa({ subject: 'Rollover CA', extensions: [{ oid: '2.5.29.30', critical: true, value: excludeDns('old.example') }] });
        // Self-issued: subject and issuer are the same name, a different key.
        const rekeyed = await syntheticUnder(top.subject.der, 'Rollover CA', 'old.example', true);
        const leaf = await syntheticUnder(rekeyed.subject.der, 'leaf.example', 'fine.example');
        // Nothing is trusted, so the walk runs past the self-issued certificate
        // rather than stopping at it — which is the only shape in which a
        // self-issued certificate is not the final one.
        const report = validateCertificatePath({ path: [leaf, rekeyed, top], trustAnchors: [], at: AT, signatures: valid(leaf, rekeyed, top) });
        expect(codes(report)).toEqual(['PKI_REASON_NO_TRUST_ANCHOR']);

        // The exemption stops at the leaf: the same excluded name on the final
        // certificate is refused, because that one is the identity being judged.
        const excludedLeaf = await syntheticUnder(rekeyed.subject.der, 'leaf.example', 'old.example');
        const refused = validateCertificatePath({ path: [excludedLeaf, rekeyed, top], trustAnchors: [], at: AT, signatures: valid(excludedLeaf, rekeyed, top) });
        expect(codes(refused)).toContain('PKI_REASON_NAME_EXCLUDED');
    });

    it('should apply name constraints to a self-issued certificate that IS the final one', async () => {
        // A CA that issued a certificate with its OWN name to another key, and
        // that certificate is what is being judged: the parenthetical in
        // §6.1.3 puts it back under the constraints.
        const top = await syntheticCa({ subject: 'Self CA', extensions: [{ oid: '2.5.29.30', critical: true, value: excludeDns('old.example') }] });
        const selfNamed = await syntheticUnder(top.subject.der, 'Self CA', 'old.example');
        const report = validateCertificatePath({ path: [selfNamed, top], trustAnchors: [], at: AT, signatures: valid(selfNamed, top) });
        expect(codes(report)).toContain('PKI_REASON_NAME_EXCLUDED');
    });

    it('should decide a cross-signed link from the verdict that names its issuer', async () => {
        // Two CAs sharing one subject name is what cross-signing produces, and
        // it is the case buildCertificatePath exists for. A verdict keyed by the
        // subject alone says "this certificate's signature is good" without
        // saying good under WHICH of them — so naming the issuer is the only way
        // the caller can be precise, and the pair is looked up first.
        const real = await syntheticCa({ subject: 'Shared Name' });
        const decoy = await syntheticCa({ subject: 'Shared Name' });
        const leaf = await syntheticUnder(real.subject.der, 'leaf.example', 'leaf.example');

        const report = validateCertificatePath({
            path: [leaf, real],
            trustAnchors: [real, decoy],
            at: AT,
            signatures: [
                { certificate: leaf, issuer: real, verdict: 'valid' },
                { certificate: leaf, issuer: decoy, verdict: 'invalid' },
            ],
        });
        expect(codes(report)).toEqual([]);

        // …and through the decoy, the same two verdicts refuse it.
        const throughDecoy = validateCertificatePath({
            path: [leaf, decoy],
            trustAnchors: [real, decoy],
            at: AT,
            signatures: [
                { certificate: leaf, issuer: real, verdict: 'valid' },
                { certificate: leaf, issuer: decoy, verdict: 'invalid' },
            ],
        });
        // The link is refused on its signature; the name chain never matched
        // either, because `decoy` is not the issuer the leaf named.
        expect(codes(throughDecoy)).toContain('PKI_REASON_SIGNATURE_INVALID');
    });

    it('should report NOT_CHECKED, never guess, when two issuer-less verdicts disagree', async () => {
        // Resolving this by insertion order is how a validator accepts the decoy
        // half of a cross-signed pair: whichever verdict happened to be passed
        // last would decide the chain. Ambiguity is an answer.
        const real = await syntheticCa({ subject: 'Shared Name' });
        const leaf = await syntheticUnder(real.subject.der, 'leaf.example', 'leaf.example');
        const report = validateCertificatePath({
            path: [leaf, real],
            trustAnchors: [real],
            at: AT,
            signatures: [
                { certificate: leaf, verdict: 'valid' },
                { certificate: leaf, verdict: 'invalid' },
            ],
        });
        expect(codes(report)).toEqual(['PKI_REASON_SIGNATURE_NOT_CHECKED']);
        expect(report.reasons[0]?.errorCode).toBe('PKI_API_MISUSE');
        expect(report.reasons[0]?.message).toContain('pass `issuer`');
    });

    it('should stay ambiguous once a third verdict arrives, whatever it says', async () => {
        const real = await syntheticCa({ subject: 'Shared Name' });
        const leaf = await syntheticUnder(real.subject.der, 'leaf.example', 'leaf.example');
        const report = validateCertificatePath({
            path: [leaf, real],
            trustAnchors: [real],
            at: AT,
            signatures: [
                { certificate: leaf, verdict: 'valid' },
                { certificate: leaf, verdict: 'invalid' },
                { certificate: leaf, verdict: 'valid' },
            ],
        });
        expect(report.reasons[0]?.errorCode).toBe('PKI_API_MISUSE');
    });

    it('should accept agreeing issuer-less duplicates, which say the same thing', async () => {
        // Two 'valid' verdicts give the same answer whichever issuer was meant,
        // so there is nothing to be ambiguous about — refusing them would make
        // a caller who verified one pair twice look like a caller who guessed.
        const real = await syntheticCa({ subject: 'Shared Name' });
        const leaf = await syntheticUnder(real.subject.der, 'leaf.example', 'leaf.example');
        const report = validateCertificatePath({
            path: [leaf, real],
            trustAnchors: [real],
            at: AT,
            signatures: [{ certificate: leaf, verdict: 'valid' }, { certificate: leaf, verdict: 'valid' }],
        });
        expect(codes(report)).toEqual([]);
    });

    it('should report NO_TRUST_ANCHOR for a chain that ends nowhere', () => {
        const report = validateCertificatePath({ path: [LEAF, R12], trustAnchors: [], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        expect(report.valid).toBe(false);
    });

    it('should report ISSUER_NOT_FOUND when two certificates do not chain, naming the name looked for', () => {
        const report = validateCertificatePath({ path: [FIXTURE_LEAF, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(FIXTURE_LEAF) });
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
            path: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: LEAF.validity.notAfter.epochMilliseconds + 1,
            signatures: [{ certificate: LEAF, verdict: 'invalid' }],
        });
        expect(codes(report)).toContain('PKI_REASON_EXPIRED');
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_INVALID');
        expect(codes(report)).toContain('PKI_REASON_SIGNATURE_NOT_CHECKED');
    });

    it('should report PATH_LOOPS rather than following a repeated certificate', () => {
        const report = validateCertificatePath({ path: [LEAF, R12, R12, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).toContain('PKI_REASON_PATH_LOOPS');
    });

    it('should stop at maxChainLength and say which limit stopped it', () => {
        const report = validateCertificatePath({
            path: [LEAF, R12, ROOT_X1],
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
        const report = validateCertificatePath({ path: [LEAF, R12], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).not.toContain('PKI_REASON_NO_TRUST_ANCHOR');
        expect(report.reasons).toEqual([]);
    });

    it('should answer rather than throw for an empty chain', () => {
        const report = validateCertificatePath({ path: [], trustAnchors: [ROOT_X1], at: AT });
        expect(report.valid).toBe(false);
        expect(codes(report)).toEqual(['PKI_REASON_NO_TRUST_ANCHOR']);
        expect(report.path).toEqual([]);
    });

    it('should never throw for a validation issue, whatever is wrong', () => {
        // The contract the whole third vocabulary exists for.
        expect(() => validateCertificatePath({ path: [LEAF], trustAnchors: [], at: 0 })).not.toThrow();
    });

    it('should still throw for API misuse, which is not a validation issue', () => {
        expect(() => validateCertificatePath({ path: [LEAF], trustAnchors: [], at: AT, limits: { maxChainLenght: 3 } as never }))
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
            path: [outside, constrained, ROOT_X1],
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
            path: [inside, constrained, ROOT_X1],
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
            path: [inside, constrained, ROOT_X1],
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
            path: [banned, excluding, ROOT_X1],
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
            path: [outside, constrained, ROOT_X1],
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
            path: [anonymous, constrained, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(anonymous, constrained),
        });
        expect(report.reasons.filter((r) => r.path === 'path[0].subject')).toEqual([]);
    });

    it('should exclude a subject that matches an excluded directoryName only after §7.1 preparation', async () => {
        // The subtree is `CN=host.example.com` as a PrintableString; the leaf's
        // subject is `CN=HOST.Example.com` as a UTF8String. Byte comparison
        // alone accepted this path (PKITS InvalidDNandRFC822nameConstraintsTest29).
        const excludedName = parseCertificate(raw.certificate({ subject: raw.name([['2.5.4.3', raw.printable('host.example.com')]]) }), quiet).subject;
        const excluding = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: undefined,
                excludedSubtrees: [{ base: { kind: 'directoryName', name: excludedName, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }] },
        ] } as unknown as Certificate;
        const leaf = await syntheticLeafWithDns('HOST.Example.com');
        const report = validateCertificatePath({ path: [leaf, excluding, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(leaf, excluding) });
        expect(report.valid).toBe(false);
        expect(report.reasons.filter((r) => r.code === 'PKI_REASON_NAME_EXCLUDED').map((r) => r.path)).toEqual(['path[0].subject']);
    });

    it('should keep a directoryName permitted subtree byte-exact: a case difference is not permitted', async () => {
        const permittedName = parseCertificate(raw.certificate({ subject: raw.name([['2.5.4.3', raw.printable('host.example.com')]]) }), quiet).subject;
        const constrained = { ...R12, extensions: [
            ...R12.extensions,
            { oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), kind: 'nameConstraints',
                permittedSubtrees: [{ base: { kind: 'directoryName', name: permittedName, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }],
                excludedSubtrees: undefined },
        ] } as unknown as Certificate;
        const leaf = await syntheticLeafWithDns('HOST.Example.com');
        const report = validateCertificatePath({ path: [leaf, constrained, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(leaf, constrained) });
        expect(report.reasons.find((r) => r.path === 'path[0].subject')?.code).toBe('PKI_REASON_NAME_NOT_PERMITTED');
    });

    it('should accept a chain with no certificate policies when nobody required one', () => {
        // §6.1.5 (a). An empty policy tree means the question was never asked.
        const report = validateCertificatePath({ path: [LEAF, R12, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(codes(report)).not.toContain('PKI_REASON_NO_VALID_POLICY');
    });

    it('should refuse a chain with no certificate policies when one was required', () => {
        const report = validateCertificatePath({
            path: [LEAF, R12, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(LEAF, R12),
            requireExplicitPolicy: true,
        });
        expect(codes(report)).toContain('PKI_REASON_NO_VALID_POLICY');
        expect(report.valid).toBe(false);
    });

    it('should report a policy mapping that names anyPolicy, and ignore it', () => {
        const mapping = { oid: '2.5.29.33', critical: true, valueDer: new Uint8Array(0), kind: 'policyMappings',
            mappings: [{ issuerDomainPolicy: '2.5.29.32.0', subjectDomainPolicy: '1.3.6.1.4.1.2' }] };
        const mapper = { ...R12, extensions: [...R12.extensions, mapping] } as unknown as Certificate;
        const report = validateCertificatePath({ path: [LEAF, mapper, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, mapper) });
        expect(codes(report)).toContain('PKI_REASON_POLICY_MAPPING_INVALID');
    });

    it('should accept a legitimate policy mapping', () => {
        const mapping = { oid: '2.5.29.33', critical: true, valueDer: new Uint8Array(0), kind: 'policyMappings',
            mappings: [{ issuerDomainPolicy: '1.3.6.1.4.1.1', subjectDomainPolicy: '1.3.6.1.4.1.2' }] };
        const mapper = { ...R12, extensions: [...R12.extensions, mapping] } as unknown as Certificate;
        const report = validateCertificatePath({ path: [LEAF, mapper, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, mapper) });
        expect(codes(report)).not.toContain('PKI_REASON_POLICY_MAPPING_INVALID');
    });

    it('should stop at maxPolicyNodes and name it', () => {
        const policies = { oid: '2.5.29.32', critical: false, valueDer: new Uint8Array(0), kind: 'certificatePolicies',
            policies: Array.from({ length: 40 }, (_, i) => ({ policyIdentifier: `1.3.6.1.4.1.${String(i)}`, qualifiers: [] })) };
        // Replace rather than append: R12 already carries a certificatePolicies
        // extension, and getExtension returns the FIRST match — an appended one
        // would never be seen, and the test would pass for the wrong reason.
        const wide = { ...R12, extensions: R12.extensions.map((e) => (e.kind === 'certificatePolicies' ? policies : e)) } as unknown as Certificate;
        const report = validateCertificatePath({
            path: [LEAF, wide, ROOT_X1],
            trustAnchors: [ROOT_X1],
            at: AT,
            signatures: valid(LEAF, wide),
            limits: { maxPolicyNodes: 3 },
        });
        const reason = report.reasons.find((r) => r.code === 'PKI_REASON_LIMIT_EXCEEDED' && r.limit === 'maxPolicyNodes');
        expect(reason).toBeDefined();
    });

    it('should name the last certificate walked when no anchor is reached', () => {
        const report = validateCertificatePath({ path: [LEAF, R12], trustAnchors: [], at: AT, signatures: valid(LEAF, R12) });
        expect(report.reasons.map((r) => [r.code, r.path])).toEqual([['PKI_REASON_NO_TRUST_ANCHOR', 'path[1]']]);
    });

    it('should judge a lone leaf by the verdict naming the anchor whose subject it names, not another anchor', async () => {
        // The chain stops at the leaf, so the issuer is looked up among the
        // anchors by subject. An unrelated anchor listed first must not be
        // taken for it: the only verdict supplied names the real issuer.
        const other = await syntheticCa({ subject: 'Unrelated CA' });
        const real = await syntheticCa({ subject: 'Real CA' });
        const leaf = await syntheticUnder(real.subject.der, 'leaf.example', 'leaf.example');
        const report = validateCertificatePath({ path: [leaf], trustAnchors: [other, real], at: AT, signatures: [{ certificate: leaf, issuer: real, verdict: 'valid' }] });
        expect(codes(report)).toEqual([]);
    });

    // §6.1.4 (h)–(j), end to end: the unit tests of path-policies pin each
    // step; these pin that validateCertificatePath wires the counters, the
    // self-issued test and the caller's three switches into them.
    const withExtensions = (certificate: Certificate, replace: readonly string[], extra: readonly unknown[]): Certificate =>
        ({ ...certificate, extensions: [...certificate.extensions.filter((e) => !replace.includes(e.kind)), ...extra] }) as unknown as Certificate;
    const policiesOf = (...ids: string[]): unknown => ({ oid: '2.5.29.32', critical: false, valueDer: new Uint8Array(0), kind: 'certificatePolicies',
        policies: ids.map((policyIdentifier) => ({ policyIdentifier, qualifiers: [] })) });
    const P1 = '1.3.6.1.4.1.99999.1';
    const P2 = '1.3.6.1.4.1.99999.2';

    it.each([[1, ['PKI_REASON_NO_VALID_POLICY']], [2, []]])('should spend requireExplicitPolicy %i on the non-self-issued leaf below it (§6.1.4 (h))', (skipCerts, expected) => {
        // R12 asserts a policy, the leaf asserts none, so the tree dies at the
        // leaf. requireExplicitPolicy: 1 makes a policy mandatory from the leaf
        // on — which only happens if the leaf, not being self-issued, spends it.
        const constrained = withExtensions(R12, [], [{ oid: '2.5.29.36', critical: true, valueDer: new Uint8Array(0), kind: 'policyConstraints',
            requireExplicitPolicy: skipCerts, inhibitPolicyMapping: undefined }]);
        const report = validateCertificatePath({ path: [LEAF, constrained, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, constrained) });
        expect(codes(report)).toEqual(expected);
    });

    it('should honour a policy mapping unless the caller inhibits mapping (§6.1.4 (b))', () => {
        const mapper = withExtensions(R12, ['certificatePolicies'], [policiesOf(P1), { oid: '2.5.29.33', critical: true, valueDer: new Uint8Array(0), kind: 'policyMappings',
            mappings: [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }] }]);
        const leaf = withExtensions(LEAF, [], [policiesOf(P2)]);
        const input = { path: [leaf, mapper, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(leaf, mapper), requireExplicitPolicy: true };
        expect(codes(validateCertificatePath(input))).toEqual([]);
        expect(codes(validateCertificatePath({ ...input, inhibitPolicyMapping: true }))).toEqual(['PKI_REASON_NO_VALID_POLICY']);
    });

    it('should let a leaf policy descend from an asserted anyPolicy unless the caller inhibits anyPolicy (§6.1.3 (d)(2))', () => {
        const wildcard = withExtensions(R12, ['certificatePolicies'], [policiesOf('2.5.29.32.0')]);
        const leaf = withExtensions(LEAF, [], [policiesOf(P1)]);
        const input = { path: [leaf, wildcard, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(leaf, wildcard), requireExplicitPolicy: true };
        expect(codes(validateCertificatePath(input))).toEqual([]);
        expect(codes(validateCertificatePath({ ...input, inhibitAnyPolicy: true }))).toEqual(['PKI_REASON_NO_VALID_POLICY']);
    });

    it('should be true only when there is no reason at all', () => {
        const report = validateCertificatePath({ path: [LEAF, R12, ROOT_X1], trustAnchors: [ROOT_X1], at: AT, signatures: valid(LEAF, R12) });
        expect(report.valid).toBe(report.reasons.length === 0);
    });
});

describe('checkNamesAgainstConstraints — a directoryName in the subjectAltName', () => {
    /** An excluded `C=US, O=Example Org`, both PrintableStrings, read back by the parser. */
    const excludedState = (): NameConstraintState => {
        const dn = parseCertificate(raw.certificate({ subject: raw.name([['2.5.4.6', raw.printable('US')]], [['2.5.4.10', raw.printable('Example Org')]]) }), quiet).subject;
        const names = initialNameConstraints();
        accumulateNameConstraints(names, undefined, [{ base: { kind: 'directoryName', name: dn, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }]);
        return names;
    };
    /** A certificate whose subject is `C=FR, CN=leaf` and whose SAN holds one directoryName. */
    const withSanDirectory = (organization: Uint8Array): Certificate => parseCertificate(raw.certificate({
        subject: raw.name([['2.5.4.6', raw.printable('FR')]], [['2.5.4.3', raw.utf8('leaf')]]),
        trailing: [raw.explicit(3, sequence(raw.SUBJECT_KEY_ID, raw.AUTHORITY_KEY_ID,
            raw.extension('2.5.29.17', sequence(raw.explicit(4, raw.name([['2.5.4.6', raw.printable('US')]], [['2.5.4.10', organization]], [['2.5.4.3', raw.utf8('x')]]))))))],
    }), quiet);

    it('should exclude a SAN directoryName that differs from the subtree by case, spaces and string type', () => {
        const reasons = checkNamesAgainstConstraints(withSanDirectory(raw.utf8('  EXAMPLE   org')), excludedState(), 'path[0]');
        expect(reasons.map((r) => [r.code, r.path])).toEqual([['PKI_REASON_NAME_EXCLUDED', 'path[0].subjectAltName']]);
    });

    it('should not exclude a SAN directoryName whose value differs', () => {
        expect(checkNamesAgainstConstraints(withSanDirectory(raw.utf8('Example Organisation')), excludedState(), 'path[0]')).toEqual([]);
    });
});

describe('checkNamesAgainstConstraints — a subject emailAddress under rfc822Name constraints (§4.2.1.10)', () => {
    const EMAIL_ADDRESS = '1.2.840.113549.1.9.1';
    const mailSubtree = (value: string) => [{ base: { kind: 'rfc822Name' as const, value, der: new Uint8Array(0) }, minimum: 0, maximum: undefined }];
    const constrained = (permitted: string | undefined, excluded: string | undefined): NameConstraintState => {
        const names = initialNameConstraints();
        accumulateNameConstraints(names, permitted === undefined ? undefined : mailSubtree(permitted), excluded === undefined ? undefined : mailSubtree(excluded));
        return names;
    };
    /** `C=US, CN=leaf, emailAddress=<value>`; `san` adds a subjectAltName holding one dNSName. */
    const withEmail = (value: Uint8Array, san = false): Certificate => parseCertificate(raw.certificate({
        subject: raw.name([['2.5.4.6', raw.printable('US')]], [['2.5.4.3', raw.utf8('leaf')]], [[EMAIL_ADDRESS, value]]),
        trailing: [raw.explicit(3, sequence(raw.SUBJECT_KEY_ID, raw.AUTHORITY_KEY_ID,
            ...(san ? [raw.extension('2.5.29.17', sequence(raw.context(2, false, [0x61, 0x2e, 0x74])))] : [])))],
    }), quiet);
    const verdicts = (certificate: Certificate, names: NameConstraintState): string[][] =>
        checkNamesAgainstConstraints(certificate, names, 'path[0]').map((r) => [r.code, r.path]);

    it('should refuse a subject mailbox outside the permitted rfc822Name subtree when there is no SAN', () => {
        // PKITS InvalidDNandRFC822nameConstraintsTest29, in miniature.
        expect(verdicts(withEmail(raw.ia5('a@evil.test')), constrained('example.com', undefined))).toEqual([['PKI_REASON_NAME_NOT_PERMITTED', 'path[0].subject']]);
    });

    it('should accept a subject mailbox inside the permitted rfc822Name subtree', () => {
        expect(verdicts(withEmail(raw.ia5('a@example.com')), constrained('example.com', undefined))).toEqual([]);
    });

    it('should refuse a subject mailbox inside an excluded rfc822Name subtree', () => {
        expect(verdicts(withEmail(raw.ia5('a@example.com')), constrained(undefined, 'example.com'))).toEqual([['PKI_REASON_NAME_EXCLUDED', 'path[0].subject']]);
    });

    it('should refuse an emailAddress that is not a character string, when rfc822Name is constrained', () => {
        expect(verdicts(withEmail(raw.octetString([0x61])), constrained('example.com', undefined))).toEqual([['PKI_REASON_NAME_NOT_PERMITTED', 'path[0].subject']]);
    });

    it('should leave the subject mailbox alone when rfc822Name is not constrained', () => {
        expect(verdicts(withEmail(raw.ia5('a@evil.test')), initialNameConstraints())).toEqual([]);
    });

    it('should leave the subject mailbox alone when the certificate has a SAN, as §4.2.1.10 scopes the rule', () => {
        expect(verdicts(withEmail(raw.ia5('a@evil.test'), true), constrained('example.com', undefined))).toEqual([]);
    });
});
