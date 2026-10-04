import type { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { readObjectIdentifier } from '../../src/asn1/asn1-oid.js';
import { readInteger, readOctetString } from '../../src/asn1/asn1-read.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints, encodeKeyUsage } from '../../src/build/build-structures.js';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import { DEFAULT_PKI_LIMITS } from '../../src/core/pki-limits.js';
import { decryptPrivateKey } from '../../src/keys/key-import.js';
import { parseEncryptedPrivateKeyInfo } from '../../src/keys/key-pkcs8.js';
import { parsePkcs12 } from '../../src/keys/key-pkcs12.js';
import { buildCertificatePath } from '../../src/path/path-build.js';
import { decodePem } from '../../src/pem/pem.js';
import { parseCertificateList } from '../../src/revocation/crl-parse.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiLimits } from '../../src/types/pki-types.js';
import type { SignatureResult } from '../../src/types/path-types.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { verifyCertificateChain } from '../../src/verify/verify-chain.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { certificate, context, explicit, extension, ia5, integer, name, oid, utf8 } from '../helpers/cert-builder.js';
import { alg, attribute, contentInfo as cmsContentInfo, octets, OIDS, signedData, signerInfo } from '../helpers/cms-signed-data-builder.js';
import { authenticatedSafe, certBag, dataInfo, pbes2Algorithm, pfx, safeContents } from '../helpers/pkcs12-builder.js';
import { ascii, concat, derNest, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * Time budgets at every named limit (src/core/pki-limits.ts).
 *
 * A limit bounds the work an input can demand; this suite is the proof that
 * the bound is **reached in bounded time** — that the code behind each limit
 * is linear in the input up to the limit and refuses past it before doing the
 * work the limit forbids. Each case builds the hostile input at or just over
 * its limit with the independent builders of tests/helpers/ (never the
 * library's own encoder), then runs the call that consults the limit under
 * the clock. Only the library's calls are timed: the builders are quadratic
 * in places and their cost is not pkinative's.
 *
 * The budgets are deliberately loose — about ten times a laptop measurement,
 * never under a second — because a shared runner varies two to five
 * times run to run, and a budget that trips on noise teaches people to re-run
 * until green. They are not performance targets: bench/RESULTS.md carries
 * those. They are the line between "slow" and "unbounded", and an input that
 * crosses it is the CWE-400 class of bug this suite exists to catch.
 *
 * Two limits are budgeted by the CVE-class corpus already, where the hostile
 * construction is the published vulnerability's own; `EXTERNAL` names them,
 * and the parity test below holds every key of `DEFAULT_PKI_LIMITS` to one
 * of the two tables.
 */

const QUIET = { onDiagnostic: (): undefined => undefined };
const L = DEFAULT_PKI_LIMITS;
const AT = Date.UTC(2026, 0, 15);
const DAY = 86_400_000;

/** Times the library's calls, and only those. */
interface Clock {
    sync<T>(call: () => T): T;
    async<T>(call: () => Promise<T>): Promise<T>;
    readonly elapsedMs: () => number;
}

function createClock(): Clock {
    let total = 0;
    return {
        sync(call) {
            const started = performance.now();
            try { return call(); } finally { total += performance.now() - started; }
        },
        async async(call) {
            const started = performance.now();
            try { return await call(); } finally { total += performance.now() - started; }
        },
        elapsedMs: () => total,
    };
}

/** `run` must throw PKI_LIMIT_EXCEEDED naming `limit`. */
function refused(limit: keyof PkiLimits, run: () => unknown): void {
    let error: unknown;
    try {
        run();
    } catch (caught) {
        error = caught;
    }
    expect(error).toBeInstanceOf(PkiError);
    expect(error).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit });
}

const repeat = (part: Uint8Array, times: number): Uint8Array => {
    const out = new Uint8Array(part.length * times);
    for (let i = 0; i < times; i += 1) out.set(part, i * part.length);
    return out;
};

interface Budget {
    readonly limit: keyof PkiLimits;
    /** Milliseconds of library time; about ten times a laptop measurement, never under 1 000. */
    readonly budgetMs: number;
    readonly run: (clock: Clock) => unknown;
}

const NULL_TLV = universal(5, []);
const UNKNOWN_EXTENSION = (i: number): Uint8Array => extension(`1.3.6.1.4.1.99999.${String(i)}`, universal(5, []));
const DNS_NAME = (i: number): Uint8Array => context(2, false, ascii(`h${String(i)}.example`));
const POLICY = (i: number): Uint8Array => sequence(oid(`1.3.6.1.4.1.99999.1.${String(i)}`));

/** A CRL of `entries` revoked serials, unsigned (the parser never checks the signature). */
function crl(entries: number): Uint8Array {
    const entry = sequence(integer([0x01, 0x02, 0x03, 0x04]), universal(23, ascii('260101000000Z')));
    const tbs = sequence(
        integer([1]), alg(OIDS.sha256), name([['2.5.4.3', utf8('Budget CA')]]),
        universal(23, ascii('260101000000Z')), universal(23, ascii('270101000000Z')),
        sequence(repeat(entry, entries)),
    );
    return sequence(tbs, alg(OIDS.sha256), universal(3, [0, 1, 2, 3]));
}

/** An OCSP response of `singles` answers, unsigned. */
function ocspResponse(singles: number): Uint8Array {
    const certId = sequence(alg('1.3.14.3.2.26'), octets(new Uint8Array(20)), octets(new Uint8Array(20)), integer([0x01]));
    const single = sequence(certId, context(0, false, []), universal(24, ascii('20260101000000Z')));
    const tbs = sequence(
        explicit(2, octets(new Uint8Array(20))), universal(24, ascii('20260101000000Z')), sequence(repeat(single, singles)),
    );
    const basic = sequence(tbs, alg(OIDS.sha256), universal(3, [0, 1, 2, 3]));
    return sequence(universal(10, [0]), explicit(0, sequence(oid('1.3.6.1.5.5.7.48.1.1'), octets(basic))));
}

/** `count` certificates sharing one subject and issuer: the name graph is a clique, so the path search explodes until its limit. */
function clique(count: number): { leaf: Certificate; candidates: Certificate[]; signatures: SignatureResult[] } {
    const shared = name([['2.5.4.3', utf8('Clique CA')]]);
    const parse = (der: Uint8Array): Certificate => parseCertificate(der, QUIET);
    const candidates = Array.from({ length: count }, (_, i) => parse(certificate({
        serialNumber: integer([0x10, i + 1]), issuer: shared, subject: shared,
    })));
    const leaf = parse(certificate({ serialNumber: integer([0x7f]), issuer: shared, trailing: [explicit(3, sequence(extension('2.5.29.19', sequence(), true)))] }));
    const signatures: SignatureResult[] = [];
    for (const subject of [leaf, ...candidates]) {
        for (const issuer of candidates) if (issuer !== subject) signatures.push({ certificate: subject, issuer, verdict: 'valid' });
    }
    return { leaf, candidates, signatures };
}

/** A chain of `depth` real Ed25519 certificates, root first. */
async function chain(depth: number): Promise<Certificate[]> {
    const out: Certificate[] = [];
    let issuer: { name: string; key: webcrypto.CryptoKey } | undefined;
    for (let i = 0; i < depth; i += 1) {
        const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
        const subject = `Depth ${String(i)}`;
        const der = await createCertificate({
            serialNumber: BigInt(i + 1),
            subject: [[{ type: '2.5.4.3', value: subject }]],
            ...(issuer === undefined ? {} : { issuer: [[{ type: '2.5.4.3', value: issuer.name }]] }),
            notBefore: AT - DAY, notAfter: AT + DAY,
            subjectPublicKey: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign']) },
            ],
        }, { key: (issuer?.key ?? pair.privateKey) as never, algorithm: { name: 'Ed25519' } });
        out.push(parseCertificate(der, QUIET));
        issuer = { name: subject, key: pair.privateKey };
    }
    return out;
}

const BUDGETS: readonly Budget[] = [
    {
        limit: 'maxInputBytes', budgetMs: 1000,
        // The largest single value an 8 MiB input can hold, decoded whole; one byte over a limit set at 8 MiB is refused before a byte is read.
        run: async (clock) => {
            const eight = 8 * 1024 * 1024;
            const big = tlv(0, false, 4, new Uint8Array(eight - 6));
            const over = new Uint8Array(eight + 1);
            expect(clock.sync(() => decodeAsn1(big)).contentLength).toBe(eight - 6);
            refused('maxInputBytes', () => clock.sync(() => decodeAsn1(over, { limits: { maxInputBytes: eight } })));
            // The CRL and OCSP readers walk the root with the cursor, not the node decoder: the same
            // size refusal first, and a root of four million two-octet values refused at the field
            // bound (review of 2026-10-04: it once cost seconds and gigabytes per reader).
            refused('maxInputBytes', () => clock.sync(() => parseCertificateList(over, { limits: { maxInputBytes: eight } })));
            refused('maxInputBytes', () => clock.sync(() => parseOcspResponse(over, { limits: { maxInputBytes: eight } })));
            const hostile = tlv(0, true, 16, new Uint8Array(eight - 6).map((_, i) => (i % 2 === 0 ? 0x05 : 0x00)));
            for (const read of [parseCertificateList, parseOcspResponse]) {
                expect(() => clock.sync(() => read(hostile))).toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
            }
            // The same bytes through the chain report, which once keyed every list by its hex before any
            // reader saw it (1.8 GiB of strings for 32 MiB): compared byte for byte now, the same list once.
            const certs = await chain(2);
            const report = await clock.async(() => verifyCertificateChain({
                leaf: certs[1] as Certificate, candidates: [], trustAnchors: [certs[0] as Certificate], at: AT,
                crls: [hostile, hostile], ocspResponses: [hostile],
            }));
            expect(report.reasons.filter((r) => r.code === 'PKI_REASON_INPUT_MALFORMED').map((r) => r.path).sort()).toEqual(['crls[0]', 'ocspResponses[0]']);
        },
    },
    {
        limit: 'maxDepth', budgetMs: 1000,
        // A thousand deep: the refusal comes at the sixty-fifth level, whatever lies below it.
        run: (clock) => {
            const deep = derNest(1000);
            refused('maxDepth', () => clock.sync(() => decodeAsn1(deep)));
        },
    },
    {
        limit: 'maxNodes', budgetMs: 2500,
        run: (clock) => {
            const many = sequence(repeat(NULL_TLV, L.maxNodes + 1));
            refused('maxNodes', () => clock.sync(() => decodeAsn1(many)));
        },
    },
    {
        limit: 'maxIntegerBytes', budgetMs: 1000,
        run: (clock) => {
            const at = decodeAsn1(universal(2, [0x7f, ...new Uint8Array(L.maxIntegerBytes - 1).fill(0xff)]));
            const over = decodeAsn1(universal(2, [0x7f, ...new Uint8Array(L.maxIntegerBytes)]));
            expect(clock.sync(() => readInteger(at)) > 0n).toBe(true);
            refused('maxIntegerBytes', () => clock.sync(() => readInteger(over)));
        },
    },
    {
        limit: 'maxOidBytes', budgetMs: 1500,
        // Every sub-identifier at the longest encoding the limit allows, read a thousand times.
        run: (clock) => {
            const content = [0x2a, ...new Uint8Array(L.maxOidBytes - 2).fill(0xff), 0x7f];
            const at = decodeAsn1(universal(6, content));
            const over = decodeAsn1(universal(6, [...content.slice(0, -1), 0x80, 0x7f]));
            for (let i = 0; i < 1000; i += 1) expect(clock.sync(() => readObjectIdentifier(at)).startsWith('1.2.')).toBe(true);
            refused('maxOidBytes', () => clock.sync(() => readObjectIdentifier(over)));
        },
    },
    {
        limit: 'maxBerSegments', budgetMs: 1000,
        run: (clock) => {
            const ber = { encodingRules: 'ber' } as const;
            const segment = universal(4, [0x41]);
            const at = concat([0x24, 0x80], repeat(segment, L.maxBerSegments), [0x00, 0x00]);
            const over = concat([0x24, 0x80], repeat(segment, L.maxBerSegments + 1), [0x00, 0x00]);
            expect(clock.sync(() => readOctetString(decodeAsn1(at, ber), ber)).length).toBe(L.maxBerSegments);
            refused('maxBerSegments', () => clock.sync(() => readOctetString(decodeAsn1(over, ber), ber)));
        },
    },
    {
        limit: 'maxPemBlocks', budgetMs: 1500,
        run: (clock) => {
            const block = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
            const at = block.repeat(L.maxPemBlocks);
            const over = block.repeat(L.maxPemBlocks + 1);
            expect(clock.sync(() => decodePem(at))).toHaveLength(L.maxPemBlocks);
            refused('maxPemBlocks', () => clock.sync(() => decodePem(over)));
        },
    },
    {
        limit: 'maxExtensions', budgetMs: 1000,
        run: (clock) => {
            const many = (count: number): Uint8Array => certificate({ trailing: [explicit(3, sequence(...Array.from({ length: count }, (_, i) => UNKNOWN_EXTENSION(i))))] });
            const [at, over] = [many(L.maxExtensions), many(L.maxExtensions + 1)];
            expect(clock.sync(() => parseCertificate(at, QUIET)).extensions).toHaveLength(L.maxExtensions);
            refused('maxExtensions', () => clock.sync(() => parseCertificate(over, QUIET)));
        },
    },
    {
        limit: 'maxGeneralNames', budgetMs: 1500,
        run: (clock) => {
            const san = (count: number): Uint8Array => certificate({ trailing: [explicit(3, sequence(extension('2.5.29.17', sequence(...Array.from({ length: count }, (_, i) => DNS_NAME(i))))))] });
            const [at, over] = [san(L.maxGeneralNames), san(L.maxGeneralNames + 1)];
            expect(clock.sync(() => parseCertificate(at, QUIET)).extensions).toHaveLength(1);
            refused('maxGeneralNames', () => clock.sync(() => parseCertificate(over, QUIET)));
        },
    },
    {
        limit: 'maxNameAttributes', budgetMs: 1000,
        run: (clock) => {
            const subject = (count: number): Uint8Array => certificate({ subject: name(...Array.from({ length: count }, (_, i) => [['2.5.4.3', ia5(`a${String(i)}`)] as const])) });
            const [at, over] = [subject(L.maxNameAttributes), subject(L.maxNameAttributes + 1)];
            expect(clock.sync(() => parseCertificate(at, QUIET)).subject.rdns).toHaveLength(L.maxNameAttributes);
            refused('maxNameAttributes', () => clock.sync(() => parseCertificate(over, QUIET)));
        },
    },
    {
        limit: 'maxPolicies', budgetMs: 1000,
        run: (clock) => {
            const policies = (count: number): Uint8Array => certificate({ trailing: [explicit(3, sequence(extension('2.5.29.32', sequence(...Array.from({ length: count }, (_, i) => POLICY(i))))))] });
            const [at, over] = [policies(L.maxPolicies), policies(L.maxPolicies + 1)];
            expect(clock.sync(() => parseCertificate(at, QUIET)).extensions).toHaveLength(1);
            refused('maxPolicies', () => clock.sync(() => parseCertificate(over, QUIET)));
        },
    },
    {
        limit: 'maxChainLength', budgetMs: 1000,
        // Twelve real certificates deep, every signature verified, and the search stops at the bound rather than reaching the root.
        run: async (clock) => {
            const certs = await chain(L.maxChainLength + 2);
            const root = certs[0] as Certificate;
            const leaf = certs[certs.length - 1] as Certificate;
            const report = await clock.async(() => verifyCertificateChain({ leaf, candidates: certs.slice(1, -1), trustAnchors: [root], at: AT }));
            expect(report.valid).toBe(false);
            expect(report.reasons.map((r) => r.code)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        },
    },
    {
        limit: 'maxRevokedCertificates', budgetMs: 1000,
        // A tenth of the default, held as the limit for the run: the parser is linear, and a megabyte of entries is what a laptop reads in tenths of a second.
        run: (clock) => {
            const limits = { maxRevokedCertificates: 100_000 };
            const [at, over] = [crl(100_000), crl(100_001)];
            expect(clock.sync(() => parseCertificateList(at, { ...QUIET, limits })).entryCount).toBe(100_000);
            refused('maxRevokedCertificates', () => clock.sync(() => parseCertificateList(over, { ...QUIET, limits })));
        },
    },
    {
        limit: 'maxOcspSingleResponses', budgetMs: 1000,
        run: (clock) => {
            const [at, over] = [ocspResponse(L.maxOcspSingleResponses), ocspResponse(L.maxOcspSingleResponses + 1)];
            expect(clock.sync(() => parseOcspResponse(at, QUIET)).basicResponse?.responses).toHaveLength(L.maxOcspSingleResponses);
            refused('maxOcspSingleResponses', () => clock.sync(() => parseOcspResponse(over, QUIET)));
        },
    },
    {
        limit: 'maxPathsExplored', budgetMs: 15000,
        // Thirty same-named issuers: 30! name paths, stopped at the thousandth — each of the thousand is a full §6 walk, hence the widest budget here.
        run: (clock) => {
            const { leaf, candidates, signatures } = clique(30);
            const report = clock.sync(() => buildCertificatePath({ leaf, candidates, trustAnchors: [], at: AT, signatures }));
            expect(report.valid).toBe(false);
            expect(report.explored).toBeLessThanOrEqual(L.maxPathsExplored);
        },
    },
    {
        limit: 'maxSignerInfos', budgetMs: 1000,
        run: (clock) => {
            const message = (count: number): Uint8Array => cmsContentInfo(signedData({ signers: Array.from({ length: count }, () => signerInfo()) }));
            const [at, over] = [message(L.maxSignerInfos), message(L.maxSignerInfos + 1)];
            expect(clock.sync(() => parseSignedData(at, QUIET)).signerInfos).toHaveLength(L.maxSignerInfos);
            refused('maxSignerInfos', () => clock.sync(() => parseSignedData(over, QUIET)));
        },
    },
    {
        limit: 'maxAttributes', budgetMs: 1000,
        run: (clock) => {
            const attrs = (count: number): Uint8Array[] => Array.from({ length: count }, (_, i) => attribute(`1.3.6.1.4.1.99999.2.${String(i)}`, universal(5, [])));
            const message = (count: number): Uint8Array => cmsContentInfo(signedData({ signers: [signerInfo({ unsignedAttrs: attrs(count) })] }));
            const [at, over] = [message(L.maxAttributes), message(L.maxAttributes + 1)];
            expect(clock.sync(() => parseSignedData(at, QUIET)).signerInfos[0]?.unsignedAttributes).toHaveLength(L.maxAttributes);
            refused('maxAttributes', () => clock.sync(() => parseSignedData(over, QUIET)));
        },
    },
    {
        limit: 'maxCmsCertificatesAndCrls', budgetMs: 1500,
        run: (clock) => {
            const one = certificate();
            const message = (count: number): Uint8Array => cmsContentInfo(signedData({ certificates: Array.from({ length: count }, () => one) }));
            const [at, over] = [message(L.maxCmsCertificatesAndCrls), message(L.maxCmsCertificatesAndCrls + 1)];
            expect(clock.sync(() => parseSignedData(at, QUIET)).certificates).toHaveLength(L.maxCmsCertificatesAndCrls);
            refused('maxCmsCertificatesAndCrls', () => clock.sync(() => parseSignedData(over, QUIET)));
        },
    },
    {
        limit: 'maxKdfIterations', budgetMs: 1000,
        // Ten million and one iterations declared: refused by the parser and by the opener before a single PBKDF2 round runs.
        run: async (clock) => {
            const shrouded = sequence(pbes2Algorithm({ iterations: L.maxKdfIterations + 1 }), octets(new Uint8Array(48)));
            refused('maxKdfIterations', () => clock.sync(() => parseEncryptedPrivateKeyInfo(shrouded, QUIET)));
            await expect(clock.async(() => decryptPrivateKey(shrouded, { password: 'budget', algorithm: { name: 'Ed25519' } })))
                .rejects.toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxKdfIterations' });
        },
    },
    {
        limit: 'maxPkcs12Bags', budgetMs: 1500,
        run: (clock) => {
            const bag = certBag(certificate());
            const file = (count: number): Uint8Array => pfx({ authSafe: authenticatedSafe(dataInfo(safeContents(...Array.from({ length: count }, () => bag)))) });
            const [at, over] = [file(L.maxPkcs12Bags), file(L.maxPkcs12Bags + 1)];
            expect(clock.sync(() => parsePkcs12(at, QUIET)).contents[0]?.bags).toHaveLength(L.maxPkcs12Bags);
            refused('maxPkcs12Bags', () => clock.sync(() => parsePkcs12(over, QUIET)));
        },
    },
];

/** Limits whose budget lives with the CVE class that motivated them. */
const EXTERNAL: ReadonlyArray<{ readonly limit: keyof PkiLimits; readonly file: string; readonly test: string }> = [
    { limit: 'maxPolicyNodes', file: 'tests/security/cve-classes.test.ts', test: 'CVE-2023-0464: a policy tree built to grow exponentially stops at maxPolicyNodes in bounded time' },
    { limit: 'maxPkcs12KdfIterations', file: 'tests/security/cve-classes.test.ts', test: 'CVE-2022-36083: a PKCS#12 declaring more PBKDF2 work than maxPkcs12KdfIterations is refused before any derivation' },
];

describe('every named limit is reached in bounded time', () => {
    it.each(BUDGETS.map((b) => [b.limit, b] as const))('%s', async (_limit, budget) => {
        const clock = createClock();
        await budget.run(clock);
        const elapsed = clock.elapsedMs();
        expect(elapsed, `${budget.limit}: ${elapsed.toFixed(0)} ms of library time against a budget of ${String(budget.budgetMs)} ms`).toBeLessThan(budget.budgetMs);
    }, 60_000);

    it('should budget every key of DEFAULT_PKI_LIMITS exactly once, here or in the CVE-class corpus', () => {
        const here = BUDGETS.map((b) => b.limit);
        const elsewhere = EXTERNAL.map((e) => e.limit);
        const all = [...here, ...elsewhere].sort();
        expect(all).toEqual([...new Set(all)]);
        expect(all).toEqual(Object.keys(DEFAULT_PKI_LIMITS).sort());
        for (const external of EXTERNAL) {
            expect(readFileSync(external.file, 'utf8'), `${external.file} names ${external.limit}`).toContain(external.test);
        }
    });

    it('should keep every budget at a second or more — a shared runner varies two to five times run to run, a loaded one more', () => {
        for (const budget of BUDGETS) expect(budget.budgetMs, budget.limit).toBeGreaterThanOrEqual(1000);
    });
});
