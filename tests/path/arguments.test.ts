import { beforeAll, describe, expect, it } from 'vitest';
import { buildCertificatePath } from '../../src/path/path-build.js';
import { checkExtendedKeyUsage } from '../../src/path/path-purpose.js';
import { checkServerName, matchDnsName } from '../../src/path/path-server-name.js';
import { validateCertificatePath } from '../../src/path/path-validate.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { WRONG, expectCode, expectInvalid } from '../core/_arguments.js';
import { AT, eku, issue, makeRoot } from '../verify/_cms-pki.js';

/**
 * The path functions, given what is not what their signature names: one test
 * per guard, on the call where that guard is the one that answers.
 */

describe('the path functions, given the wrong type', () => {
    let root: Certificate;
    let leaf: Certificate;
    const DER = Uint8Array.of(0x30, 0x00);

    beforeAll(async () => {
        const authority = await makeRoot();
        root = authority.certificate;
        leaf = (await issue(authority)).certificate;
    });

    // ── buildCertificatePath ──
    it.each(WRONG)('buildCertificatePath should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => buildCertificatePath(value as never));
    });

    it.each([...WRONG, ['the DER of the certificate', DER]] as const)('buildCertificatePath should refuse %s as the leaf', async (_label, value) => {
        await expectInvalid(() => buildCertificatePath({ leaf: value as never, candidates: [], trustAnchors: [root], at: AT }));
    });

    it.each(WRONG)('buildCertificatePath should refuse %s where the candidates are expected', async (_label, value) => {
        await expectInvalid(() => buildCertificatePath({ leaf, candidates: value as never, trustAnchors: [root], at: AT }));
    });

    it.each([
        ...WRONG,
        ['a certificate with no subject', { issuer: { der: DER }, extensions: [] }],
        ['a certificate whose subject has no encoding', { subject: {}, issuer: { der: DER }, extensions: [] }],
    ] as const)('buildCertificatePath should refuse %s among the candidates', async (_label, value) => {
        await expectInvalid(() => buildCertificatePath({ leaf, candidates: [root, value as never], trustAnchors: [root], at: AT }));
    });

    it.each(WRONG)('buildCertificatePath should refuse %s where the trust anchors are expected', async (_label, value) => {
        await expectInvalid(() => buildCertificatePath({ leaf, candidates: [], trustAnchors: value as never, at: AT }));
    });

    it('buildCertificatePath should still find the path of well-typed input', () => {
        const report = buildCertificatePath({ leaf, candidates: [], trustAnchors: [root], at: AT, signatures: [{ certificate: leaf, verdict: 'valid' }] });
        expect(report.path.map((certificate) => certificate.der)).toEqual([leaf.der, root.der]);
    });

    // ── validateCertificatePath ──
    it.each(WRONG)('validateCertificatePath should refuse %s as the input', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath(value as never));
    });

    it.each(WRONG)('validateCertificatePath should refuse %s where the path is expected', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: value as never, trustAnchors: [root], at: AT }));
    });

    it.each(WRONG)('validateCertificatePath should refuse %s where the trust anchors are expected', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: value as never, at: AT }));
    });

    // `undefined` and `null` both mean "no verdict was computed", which is an answer and not a refusal.
    it.each([['a number', 42], ['a string', 'x'], ['an object', {}]] as const)('validateCertificatePath should refuse %s where the verdicts are expected', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: value as never }));
    });

    it.each(WRONG)('validateCertificatePath should refuse %s as a verdict', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: [value as never] }));
    });

    it.each([...WRONG, ['a certificate with no DER', {}]] as const)('validateCertificatePath should refuse a verdict about %s', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: [{ certificate: value as never, verdict: 'valid' }] }));
    });

    it.each([['null', null], ['a number', 42], ['a string', 'x'], ['a certificate with no DER', {}]] as const)('validateCertificatePath should refuse a verdict whose issuer is %s', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: [{ certificate: leaf, issuer: value as never, verdict: 'valid' }] }));
    });

    // ── checkExtendedKeyUsage, checkServerName, matchDnsName ──
    it.each(WRONG)('checkExtendedKeyUsage should refuse %s where the path is expected', async (_label, value) => {
        await expectInvalid(() => checkExtendedKeyUsage(value as never, '1.3.6.1.5.5.7.3.1'));
    });

    it.each(WRONG)('checkExtendedKeyUsage should refuse %s as a certificate of the path', async (_label, value) => {
        await expectInvalid(() => checkExtendedKeyUsage([value as never], '1.3.6.1.5.5.7.3.1'));
    });

    it.each(WRONG)('checkServerName should refuse %s as the identity', async (_label, value) => {
        await expectInvalid(() => checkServerName(leaf, value as never));
    });

    it.each([['undefined', undefined], ['null', null], ['a number', 42], ['bytes', Uint8Array.of(1, 2, 3, 4)]] as const)('checkServerName should refuse a dns identity whose value is %s', async (_label, value) => {
        await expectInvalid(() => checkServerName(leaf, { kind: 'dns', value: value as never }));
    });

    it.each(WRONG)('checkServerName should refuse an ip identity whose value is %s', async (_label, value) => {
        await expectInvalid(() => checkServerName(leaf, { kind: 'ip', value: value as never }));
    });

    it.each(WRONG)('checkServerName should refuse %s as the certificate', async (_label, value) => {
        await expectInvalid(() => checkServerName(value as never, { kind: 'dns', value: 'example.com' }));
    });

    it.each([['undefined', undefined], ['null', null], ['a number', 42], ['an object', {}]] as const)('matchDnsName should refuse %s as the presented name', async (_label, value) => {
        await expectInvalid(() => matchDnsName(value as never, 'example.com'));
    });

    it.each([['undefined', undefined], ['null', null], ['a number', 42], ['an object', {}]] as const)('matchDnsName should refuse %s as the reference name', async (_label, value) => {
        await expectInvalid(() => matchDnsName('example.com', value as never));
    });
});

describe('the path functions, told a certificate by what they read', () => {
    let root: Certificate;
    let leaf: Certificate;
    let named: Certificate;
    let restricted: Certificate;
    const DER = Uint8Array.of(0x30, 0x00);
    const NOT_INSTANTS = [['undefined', undefined], ['a string', '2026-01-15'], ['NaN', Number.NaN], ['a Date', new Date(AT)], ['a bigint', 1n]] as const;
    const NOT_LISTS = [['null', null], ['a number', 42], ['a string', 'x'], ['an object', {}]] as const;

    beforeAll(async () => {
        const authority = await makeRoot();
        root = authority.certificate;
        leaf = (await issue(authority)).certificate;
        named = (await issue(authority, { subject: 'host.example' })).certificate;
        restricted = (await issue(authority, { extensions: [eku(['1.3.6.1.5.5.7.3.2'])] })).certificate;
    });

    // ── buildCertificatePath ──
    it.each([
        ['no subject', { issuer: { der: DER } }],
        ['no issuer', { subject: { der: DER } }],
    ] as const)('buildCertificatePath should refuse a leaf with %s', async (_label, value) => {
        await expectInvalid(() => buildCertificatePath({ leaf: value as never, candidates: [], trustAnchors: [root], at: AT }));
    });

    it('buildCertificatePath should take any iterable of candidates, as 1.0.0 did', () => {
        const report = buildCertificatePath({ leaf, candidates: new Set([root]) as never, trustAnchors: [root], at: AT, signatures: [{ certificate: leaf, verdict: 'valid' }] });
        expect(report.path.map((certificate) => certificate.der)).toEqual([leaf.der, root.der]);
    });

    it.each([
        ['no DER', (c: Certificate): object => ({ subject: c.subject, subjectPublicKeyInfo: c.subjectPublicKeyInfo })],
        ['no subject', (c: Certificate): object => ({ der: c.der, subjectPublicKeyInfo: c.subjectPublicKeyInfo })],
        ['no key', (c: Certificate): object => ({ der: c.der, subject: c.subject })],
    ] as const)('buildCertificatePath should refuse a trust anchor with %s', async (_label, make) => {
        await expectInvalid(() => buildCertificatePath({ leaf, candidates: [], trustAnchors: [make(root) as never], at: AT }));
    });

    it.each(NOT_LISTS)('buildCertificatePath should refuse %s as the purposes', async (_label, value) => {
        // Read once a path is found, so the call has to find one.
        await expectInvalid(() => buildCertificatePath({ leaf, candidates: [], trustAnchors: [root], at: AT, signatures: [{ certificate: leaf, verdict: 'valid' }], purposes: value as never }));
    });

    it('buildCertificatePath should answer for its limits first when a certificate is wrong too, as 1.0.0 did', async () => {
        await expectCode(() => buildCertificatePath({ leaf: DER as never, candidates: [], trustAnchors: [root], at: AT, limits: { maxChainLength: 0 } }), 'PKI_LIMIT_INVALID');
    });

    // ── validateCertificatePath ──
    it.each(NOT_INSTANTS)('validateCertificatePath should refuse %s as the instant', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: value as never }));
    });

    it.each([
        ['no subject', (c: Certificate): object => ({ subjectPublicKeyInfo: c.subjectPublicKeyInfo })],
        ['no key', (c: Certificate): object => ({ subject: c.subject })],
    ] as const)('validateCertificatePath should refuse a trust anchor with %s', async (_label, make) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [make(root) as never], at: AT }));
    });

    it('validateCertificatePath should take an anchor that is a name and a key, as 1.0.0 did', () => {
        const anchor = { subject: root.subject, subjectPublicKeyInfo: root.subjectPublicKeyInfo };
        const report = validateCertificatePath({ path: [leaf, root], trustAnchors: [anchor as never], at: AT, signatures: [{ certificate: leaf, verdict: 'valid' }, { certificate: root, verdict: 'valid' }] });
        expect(report.reasons.map((reason) => reason.code)).toEqual([]);
    });

    it.each([
        ['no subject', { issuer: { der: DER } }],
        ['no issuer', { subject: { der: DER } }],
    ] as const)('validateCertificatePath should refuse a certificate of the path with %s', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, value as never], trustAnchors: [root], at: AT }));
    });

    // `null` is read as no policy set, as `undefined` is; the set is read where the walk ends.
    it.each(NOT_LISTS.slice(1))('validateCertificatePath should refuse %s as the initial policy set', async (_label, value) => {
        await expectInvalid(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: [{ certificate: leaf, verdict: 'valid' }, { certificate: root, verdict: 'valid' }], initialPolicySet: value as never }));
    });

    it('validateCertificatePath should take any iterable of verdicts, as 1.0.0 did', () => {
        const signatures = new Set([{ certificate: leaf, verdict: 'valid' }, { certificate: root, verdict: 'valid' }]);
        const report = validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: AT, signatures: signatures as never });
        expect(report.reasons.map((reason) => reason.code)).toEqual([]);
    });

    it('validateCertificatePath should answer for its limits first when the instant is wrong too, as 1.0.0 did', async () => {
        await expectCode(() => validateCertificatePath({ path: [leaf, root], trustAnchors: [root], at: 'now' as never, limits: { maxChainLength: 0 } }), 'PKI_LIMIT_INVALID');
    });

    // ── checkServerName, checkExtendedKeyUsage ──
    it.each(NOT_LISTS)('checkServerName should refuse %s as the path the commonName fallback needs', async (_label, value) => {
        await expectInvalid(() => checkServerName(named, { kind: 'dns', value: 'host.example' }, { allowCommonNameFallback: true, path: value as never }));
    });

    it('checkServerName should still answer the commonName fallback given its path', () => {
        expect(checkServerName(named, { kind: 'dns', value: 'host.example' }, { allowCommonNameFallback: true, path: [named, root] })).toEqual([]);
    });

    it.each([['undefined', undefined], ['a number', 42], ['an object with no prototype', Object.create(null)]] as const)('checkExtendedKeyUsage should refuse %s as the purpose', async (_label, value) => {
        await expectInvalid(() => checkExtendedKeyUsage([restricted], value as never));
    });

    it('checkExtendedKeyUsage should still answer a purpose the certificate does not name', () => {
        expect(checkExtendedKeyUsage([restricted], '1.3.6.1.5.5.7.3.1').map((reason) => reason.code)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
    });

    it('buildCertificatePath should take a bag that can be read once only, as 1.0.0 did', () => {
        const once = (function* (): Generator<Certificate> { yield root; })();
        const report = buildCertificatePath({ leaf, candidates: once as never, trustAnchors: [root], at: AT, signatures: [{ certificate: leaf, verdict: 'valid' }] });
        expect(report.path.map((certificate) => certificate.der)).toEqual([leaf.der, root.der]);
    });

    it('buildCertificatePath should not ask for purposes it never reads', () => {
        // No verdict, so no path is found and the purposes are not looked at.
        expect(buildCertificatePath({ leaf, candidates: [], trustAnchors: [root], at: AT, purposes: 42 as never }).valid).toBe(false);
    });

    it('validateCertificatePath should refuse a certificate of the path with no DER', async () => {
        await expectInvalid(() => validateCertificatePath({ path: [{ subject: leaf.subject, issuer: leaf.issuer } as never], trustAnchors: [root], at: AT }));
    });

    it('buildCertificatePath should refuse a leaf with no DER', async () => {
        await expectInvalid(() => buildCertificatePath({ leaf: { subject: leaf.subject, issuer: leaf.issuer } as never, candidates: [], trustAnchors: [root], at: AT }));
    });
});
