import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import {
    encodeBitString,
    encodeEnumerated,
    encodeExplicit,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeTime,
    encodeTlv,
} from '../../src/asn1/asn1-encode.js';
import { addTimeStampToken, createSignedData } from '../../src/build/build-signed-data.js';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import { createTimeStampRequest } from '../../src/cms/tsp-request.js';
import { computeKeyIdentifier } from '../../src/hash/key-identifier.js';
import { sha1 } from '../../src/hash/sha1.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiLimits } from '../../src/types/pki-types.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { verifyCertificateChain } from '../../src/verify/verify-chain.js';
import { verifySignedData } from '../../src/verify/verify-signed-data.js';
import { openPkcs12 } from '../../src/verify/verify-pkcs12.js';
import { verifyTimeStampToken } from '../../src/verify/verify-timestamp.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import {
    authenticatedSafe,
    certBag,
    dataInfo,
    encryptedSafeContents,
    friendlyName,
    localKeyId,
    pbmac1MacData,
    pfx,
    safeContents,
    shroudedKeyBag,
    shroudKey,
} from '../helpers/pkcs12-builder.js';
import { createPrng, type Prng } from '../helpers/prng.js';
import {
    AT,
    type Authority,
    DAY,
    type Holder,
    issue,
    issueTsa,
    makeCrl,
    makeRoot,
    makeToken,
    quiet,
    rawSign,
    sha,
    tstInfo,
} from '../verify/_cms-pki.js';

/**
 * Adversarial inputs against the four one-call reports.
 *
 * `verifyCertificateChain`, `verifySignedData`, `verifyTimeStampToken` and
 * `openPkcs12` promise to **report** every input problem and to throw only
 * for API misuse.
 * Each run starts from a valid input — every signature real — and mutates one
 * byte-array field: truncation at every structural boundary, byte flips,
 * length inflation, appended garbage, children dropped or duplicated, retagged
 * values, subtrees swapped in from another structure, and limits set tiny so
 * that they trip half way through a judgement. Every call must resolve, with a
 * boolean verdict and reasons whose codes are registered; an input-malformed
 * reason must carry a registered error code. Seeded and deterministic: a
 * failure prints its seed, its iteration and the mutated input.
 */

const REASON_CODES = new Set((JSON.parse(readFileSync('docs/data/reasons.json', 'utf8')) as { reasons: Array<{ code: string }> }).reasons.map((r) => r.code));
const ERROR_CODES = new Set((JSON.parse(readFileSync('docs/data/errors.json', 'utf8')) as { errors: Array<{ code: string }> }).errors.map((e) => e.code));

// ── A minimal TLV tree, independent of the engine ──

/** One TLV. A primitive OCTET STRING whose content is itself one DER value is opened (`children`), so mutations reach what it encapsulates. */
interface Tlv {
    tag: Uint8Array;
    content: Uint8Array;
    children: Tlv[] | undefined;
    /** Added to the encoded length without adding bytes — length inflation. */
    inflate: number;
}

function readTlv(der: Uint8Array, at: number, end: number, depth: number): { node: Tlv; next: number } | undefined {
    if (depth > 40 || at >= end) return undefined;
    let p = at;
    const first = der[p++] as number;
    if ((first & 0x1f) === 0x1f) {
        while (p < end && ((der[p] as number) & 0x80) !== 0) p += 1;
        p += 1;
    }
    if (p >= end) return undefined;
    const tag = der.subarray(at, p);
    let length = der[p++] as number;
    if (length === 0x80) return undefined;
    if (length > 0x80) {
        const count = length & 0x7f;
        if (count > 4 || p + count > end) return undefined;
        length = 0;
        for (let i = 0; i < count; i += 1) length = length * 256 + (der[p++] as number);
    }
    if (p + length > end) return undefined;
    const content = der.subarray(p, p + length);
    const next = p + length;
    let children: Tlv[] | undefined;
    if ((first & 0x20) !== 0) {
        children = readAll(der, p, next, depth + 1);
        if (children === undefined) return undefined;
    } else if (first === 0x04 && length > 1 && ((content[0] as number) & 0x20) !== 0) {
        const inner = readAll(der, p, next, depth + 1);
        if (inner?.length === 1) children = inner;
    }
    return { node: { tag, content, children, inflate: 0 }, next };
}

function readAll(der: Uint8Array, at: number, end: number, depth: number): Tlv[] | undefined {
    const out: Tlv[] = [];
    let p = at;
    while (p < end) {
        const read = readTlv(der, p, end, depth);
        if (read === undefined) return undefined;
        out.push(read.node);
        p = read.next;
    }
    return out;
}

function parseTree(der: Uint8Array): Tlv | undefined {
    const read = readTlv(der, 0, der.length, 0);
    return read !== undefined && read.next === der.length ? read.node : undefined;
}

function lengthOctets(n: number): number[] {
    if (n < 0x80) return [n];
    const out: number[] = [];
    for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
    return [0x80 | out.length, ...out];
}

function encodeTree(node: Tlv): Uint8Array {
    const content = node.children === undefined ? node.content : Buffer.concat(node.children.map(encodeTree));
    return Uint8Array.from([...node.tag, ...lengthOctets(content.length + node.inflate), ...content]);
}

function nodesOf(root: Tlv): Tlv[] {
    const out: Tlv[] = [];
    const stack = [root];
    while (stack.length > 0) {
        const node = stack.pop() as Tlv;
        out.push(node);
        for (const child of node.children ?? []) stack.push(child);
    }
    return out;
}

/** Every offset at which a TLV begins, its content begins, or it ends — the structural boundaries. */
function boundariesOf(der: Uint8Array): number[] {
    const out = new Set<number>();
    const walk = (at: number, end: number, depth: number): void => {
        let p = at;
        while (p < end) {
            const read = readTlv(der, p, end, depth);
            if (read === undefined) return;
            const contentStart = read.next - read.node.content.length;
            out.add(p);
            out.add(contentStart);
            out.add(read.next);
            if (read.node.children !== undefined) walk(contentStart, read.next, depth + 1);
            p = read.next;
        }
    };
    walk(0, der.length, 0);
    out.delete(der.length);
    return [...out].sort((a, b) => a - b);
}

// ── Mutations ──

const TAGS = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x0c, 0x13, 0x17, 0x18, 0x30, 0x31, 0x80, 0x81, 0xa0, 0xa1, 0xa3];

type Mutation = (prng: Prng, der: Uint8Array, donors: readonly Uint8Array[]) => Uint8Array;

/** Structural edits on a fresh tree; `undefined` when the input does not parse as definite-length DER. */
const onTree = (edit: (prng: Prng, nodes: Tlv[], donors: readonly Uint8Array[]) => void): Mutation => (prng, der, donors) => {
    const root = parseTree(der);
    if (root === undefined) return Uint8Array.from([...der, 0x00]);
    edit(prng, nodesOf(root), donors);
    return encodeTree(root);
};

const MUTATIONS: ReadonlyArray<readonly [string, Mutation]> = [
    ['truncate-at-boundary', (prng, der) => der.slice(0, prng.pick(boundariesOf(der)))],
    ['truncate-anywhere', (prng, der) => der.slice(0, prng.int(der.length))],
    ['flip', (prng, der) => {
        const out = der.slice();
        for (let n = 1 + prng.int(3); n > 0; n -= 1) {
            const at = prng.int(out.length);
            out[at] = (out[at] as number) ^ (1 + prng.int(255));
        }
        return out;
    }],
    ['append-garbage', (prng, der) => Uint8Array.from([...der, ...prng.bytes(1 + prng.int(16))])],
    ['inflate-length', onTree((prng, nodes) => { prng.pick(nodes).inflate = prng.pick([1, 2, 7, 0x10000]); })],
    ['drop-child', onTree((prng, nodes) => {
        const parents = nodes.filter((n) => (n.children?.length ?? 0) > 0);
        if (parents.length === 0) return;
        const parent = prng.pick(parents);
        (parent.children as Tlv[]).splice(prng.int((parent.children as Tlv[]).length), 1);
    })],
    ['duplicate-child', onTree((prng, nodes) => {
        const parents = nodes.filter((n) => (n.children?.length ?? 0) > 0);
        if (parents.length === 0) return;
        const parent = prng.pick(parents);
        const kids = parent.children as Tlv[];
        const at = prng.int(kids.length);
        kids.splice(at, 0, kids[at] as Tlv);
    })],
    ['retag', onTree((prng, nodes) => { prng.pick(nodes).tag = Uint8Array.of(prng.pick(TAGS)); })],
    ['truncate-primitive', onTree((prng, nodes) => {
        const leaves = nodes.filter((n) => n.children === undefined && n.content.length > 0);
        if (leaves.length === 0) return;
        const leaf = prng.pick(leaves);
        leaf.content = leaf.content.subarray(0, prng.int(leaf.content.length));
    })],
    ['swap-subtree', onTree((prng, nodes, donors) => {
        const donor = parseTree(prng.pick(donors));
        if (donor === undefined) return;
        const from = prng.pick(nodesOf(donor));
        const into = prng.pick(nodes);
        into.tag = from.tag;
        into.content = from.content;
        into.children = from.children;
    })],
];

/** Limits small enough to trip in the middle of a judgement. */
const TINY_LIMITS: ReadonlyArray<Partial<PkiLimits> | undefined> = [
    undefined,
    undefined,
    { maxNodes: 50 },
    { maxNodes: 400 },
    { maxDepth: 6 },
    { maxSignerInfos: 1 },
    { maxPathsExplored: 1 },
    { maxChainLength: 1 },
    { maxRevokedCertificates: 1 },
    { maxAttributes: 1 },
    { maxCmsCertificatesAndCrls: 1 },
    { maxInputBytes: 512 },
];

function mutate(prng: Prng, der: Uint8Array, donors: readonly Uint8Array[]): { name: string; bytes: Uint8Array } {
    const [name, fn] = prng.pick(MUTATIONS);
    return { name, bytes: fn(prng, der, donors) };
}

// ── The property ──

interface AnyReport {
    readonly valid: unknown;
    readonly reasons: ReadonlyArray<{ readonly code: string; readonly errorCode?: string | undefined; readonly path: string }>;
}

function assertReport(report: AnyReport): void {
    if (typeof report.valid !== 'boolean') throw new Error(`valid is ${typeof report.valid}`);
    if (report.valid !== (report.reasons.length === 0)) throw new Error('valid disagrees with the reasons');
    for (const reason of report.reasons) {
        if (!REASON_CODES.has(reason.code)) throw new Error(`unregistered reason ${reason.code} at ${reason.path}`);
        if (reason.code === 'PKI_REASON_INPUT_MALFORMED' && reason.errorCode === undefined) throw new Error(`INPUT_MALFORMED without errorCode at ${reason.path}`);
        if (reason.errorCode !== undefined && !ERROR_CODES.has(reason.errorCode)) throw new Error(`unregistered errorCode ${reason.errorCode} at ${reason.path}`);
    }
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes.subarray(0, 96)).toString('hex');

/**
 * Run one call and hold it to the property. `tolerated` names a documented
 * throw the caller has already established applies (a `PkiError` whose code
 * it returns true for).
 */
async function check(
    label: string,
    input: Uint8Array,
    call: () => Promise<AnyReport>,
    tolerated: (error: PkiError) => boolean = () => false,
): Promise<string> {
    try {
        const report = await call();
        assertReport(report);
        return report.valid ? 'valid' : [...new Set(report.reasons.map((r) => r.errorCode ?? r.code))].join('+');
    } catch (error) {
        if (error instanceof PkiError && tolerated(error)) return `throw:${error.code}`;
        const what = error instanceof PkiError ? `${error.name} ${error.code}` : `${(error as Error).name}`;
        throw new Error(`${label}: ${what}: ${(error as Error).message} — input ${hex(input)}`, { cause: error });
    }
}

// ── A small PKI, every signature real ──

const OID_BASIC_RESPONSE = '1.3.6.1.5.5.7.48.1.1';
const ED25519 = encodeSequence([encodeObjectIdentifier('1.3.101.112')]);
const SHA1_ALG = encodeSequence([encodeObjectIdentifier('1.3.14.3.2.26'), Uint8Array.of(0x05, 0x00)]);
const DATA = new TextEncoder().encode('the bytes a signer committed to');

/** An OCSP response about `certificate`, signed by its issuing CA itself (RFC 6960 §4.2.2.2). */
async function ocspResponse(certificate: Certificate, ca: Authority): Promise<Uint8Array> {
    const certId = encodeSequence([
        SHA1_ALG,
        encodeOctetString(sha1(ca.certificate.subject.der)),
        encodeOctetString(computeKeyIdentifier(ca.certificate.subjectPublicKeyInfo.publicKey.bytes, 'SHA-1')),
        encodeTlv('universal', 2, false, certificate.serialNumber.bytes),
    ]);
    const single = encodeSequence([
        certId,
        encodeTlv('context', 0, false, new Uint8Array(0)),
        encodeTime(AT - DAY, 'GeneralizedTime'),
        encodeExplicit(0, encodeTime(AT + DAY, 'GeneralizedTime'), { tagClass: 'context' }),
    ]);
    const tbs = encodeSequence([
        encodeExplicit(2, encodeOctetString(new Uint8Array(20).fill(0xcc)), { tagClass: 'context' }),
        encodeTime(AT - DAY, 'GeneralizedTime'),
        encodeSequence([single]),
    ]);
    const basic = encodeSequence([tbs, ED25519, encodeBitString(await rawSign({ name: 'Ed25519' }, ca.key, tbs))]);
    return encodeSequence([
        encodeEnumerated(0),
        encodeExplicit(0, encodeSequence([encodeObjectIdentifier(OID_BASIC_RESPONSE), encodeOctetString(basic)]), { tagClass: 'context' }),
    ]);
}

interface World {
    readonly root: Authority;
    readonly signer: Holder;
    readonly tsa: Holder;
    readonly crl: Uint8Array;
    readonly ocsp: Uint8Array;
    /** Attached content, a CRL in the bag, a timestamp token on the signature. */
    readonly attached: Uint8Array;
    readonly detached: Uint8Array;
    readonly token: Uint8Array;
    readonly response: Uint8Array;
    readonly request: Uint8Array;
    readonly imprint: Uint8Array;
    /** The signer's key and certificate, shrouded and MACed under PASSWORD the way OpenSSL 3.4 writes them. */
    readonly pkcs12: Uint8Array;
    readonly donors: readonly Uint8Array[];
}

const PASSWORD = 'correct horse battery staple';
const KEY_ID = Uint8Array.of(0x4b, 0x45, 0x59, 0x31);

let w: World;

beforeAll(async () => {
    const root = await makeRoot('Fuzz Root');
    const signer = await issue(root, { subject: 'Fuzz Signer' });
    const tsa = await issueTsa(root);
    const other = await issue(root, { subject: 'Somebody Revoked', serial: 99n });
    const another = await issue(root, { subject: 'Somebody Else Revoked', serial: 98n });
    const crl = await makeCrl(root, [other.certificate, another.certificate]);
    const ocsp = await ocspResponse(signer.certificate, root);
    const imprint = await sha('SHA-256', DATA);
    const token = await makeToken(tsa, tstInfo({ imprint, nonce: 0x1234n }), { crls: [crl] });
    const response = encodeSequence([encodeSequence([encodeInteger(0)]), token]);
    const request = createTimeStampRequest(imprint, { nonce: 0x1234n });
    const plain = await createSignedData({ content: DATA, certificate: signer.certificate, crls: [crl] }, signer.signer);
    const signature = parseSignedData(plain).signerInfos[0]?.signature as Uint8Array;
    const stamp = await makeToken(tsa, tstInfo({ imprint: await sha('SHA-256', signature) }));
    const attached = addTimeStampToken(plain, 0, stamp);
    const detached = await createSignedData({ content: DATA, detached: true, certificate: signer.certificate }, signer.signer);
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', signer.pair.privateKey as never));
    const certs = safeContents(certBag(signer.certificate.der, [localKeyId(KEY_ID), friendlyName('Fuzz Signer')]), certBag(root.certificate.der));
    const keys = safeContents(shroudedKeyBag(await shroudKey(pkcs8, PASSWORD), [localKeyId(KEY_ID)]));
    const authSafe = authenticatedSafe(await encryptedSafeContents(certs, PASSWORD), dataInfo(keys));
    const pkcs12 = pfx({ authSafe, macData: await pbmac1MacData(authSafe, PASSWORD) });
    w = {
        root, signer, tsa, crl, ocsp, attached, detached, token, response, request, imprint, pkcs12,
        donors: [crl, ocsp, token, attached, signer.certificate.der, tsa.certificate.der, pkcs12],
    };
}, 30_000);

// ── The runs ──

const SEED = 0x5eed_0008;
/** Iterations per report: 480 calls in all, a few seconds. */
const BUDGET = 120;

describe('verifyCertificateChain under adversarial CRLs, OCSP responses and certificates', () => {
    it('should always resolve with a registered report', async () => {
        const prng = createPrng(SEED);
        const seen = new Map<string, number>();
        const base = { leaf: w.signer.certificate, trustAnchors: [w.root.certificate], at: AT };
        // The valid starting point is valid: the property is not satisfied by an input nothing accepts.
        expect((await verifyCertificateChain({ ...base, crls: [w.crl], ocspResponses: [w.ocsp], requireRevocation: true })).valid).toBe(true);
        for (let i = 0; i < BUDGET; i += 1) {
            const limits = TINY_LIMITS[prng.int(TINY_LIMITS.length)];
            const which = prng.int(4);
            const target = which === 0 ? w.crl : which === 1 ? w.ocsp : which === 2 ? w.signer.certificate.der : w.root.certificate.der;
            const { name, bytes } = mutate(prng, target, w.donors);
            const label = `seed ${String(prng.seed)} iteration ${String(i)} ${name} on ${['crl', 'ocsp', 'leaf', 'candidate'][which] as string} limits ${JSON.stringify(limits)}`;
            let leaf = w.signer.certificate;
            let candidates: Certificate[] = [];
            if (which >= 2) {
                let parsed: Certificate | undefined;
                try { parsed = parseCertificate(bytes, quiet); } catch (error) { if (!(error instanceof PkiError)) throw error; }
                if (parsed === undefined) continue;
                if (which === 2) leaf = parsed;
                else candidates = [parsed];
            }
            const result = await check(label, bytes, () => verifyCertificateChain({
                ...base,
                leaf,
                candidates,
                crls: which === 0 ? [bytes, w.crl] : [w.crl],
                ocspResponses: which === 1 ? [bytes] : [w.ocsp],
                requireRevocation: true,
                serverName: { kind: 'dns', value: 'fuzz.example' },
                ...(limits === undefined ? {} : { limits }),
            }));
            seen.set(result, (seen.get(result) ?? 0) + 1);
        }
        expect(seen.size).toBeGreaterThan(3);
    });
});

describe('verifySignedData under adversarial messages, content and digests', () => {
    it('should always resolve with a registered report', async () => {
        const prng = createPrng(SEED + 1);
        const seen = new Map<string, number>();
        const base = { trustAnchors: [w.root.certificate], at: AT };
        expect((await verifySignedData({ ...base, signedData: w.attached })).valid).toBe(true);
        expect((await verifySignedData({ ...base, signedData: w.detached, content: DATA })).valid).toBe(true);
        for (let i = 0; i < BUDGET; i += 1) {
            const limits = TINY_LIMITS[prng.int(TINY_LIMITS.length)];
            const mode = prng.pick(['attached', 'detached-content', 'detached-digest', 'wrong-content', 'wrong-digest', 'extra-crl'] as const);
            const detached = mode.startsWith('detached') || mode.startsWith('wrong');
            const source = detached ? w.detached : w.attached;
            const mutated = mode.startsWith('wrong') ? { name: 'none', bytes: source } : mutate(prng, source, w.donors);
            const digest = await sha('SHA-256', DATA);
            const extra = mode === 'detached-content' ? { content: DATA }
                : mode === 'detached-digest' ? { contentDigest: digest }
                    : mode === 'wrong-content' ? { content: DATA.subarray(0, prng.int(DATA.length)) }
                        : mode === 'wrong-digest' ? { contentDigest: prng.bytes(prng.pick([0, 1, 20, 31, 33, 64])) }
                            : mode === 'extra-crl' ? { crls: [mutate(prng, w.crl, w.donors).bytes], ocspResponses: [mutate(prng, w.ocsp, w.donors).bytes] }
                                : {};
            const encodingRules = prng.int(4) === 0 ? 'ber' as const : undefined;
            const allowTrailingData = prng.int(4) === 0 ? true : undefined;
            const reading = {
                ...quiet,
                ...(limits === undefined ? {} : { limits }),
                ...(encodingRules === undefined ? {} : { encodingRules }),
                ...(allowTrailingData === undefined ? {} : { allowTrailingData }),
            };
            const label = `seed ${String(prng.seed)} iteration ${String(i)} ${mutated.name} ${mode} ${JSON.stringify({ limits, encodingRules, allowTrailingData })}`;
            const result = await check(label, mutated.bytes, () => verifySignedData({
                ...base,
                signedData: mutated.bytes,
                ...extra,
                ...(limits === undefined ? {} : { limits }),
                ...(encodingRules === undefined ? {} : { encodingRules }),
                ...(allowTrailingData === undefined ? {} : { allowTrailingData }),
            }), (error) => {
                // Documented misuse: detached content passed for a message a
                // mutation turned into one that carries its own.
                if (error.code !== 'PKI_API_MISUSE') return false;
                return parseSignedData(mutated.bytes, reading).content !== undefined;
            });
            seen.set(result, (seen.get(result) ?? 0) + 1);
        }
        expect(seen.size).toBeGreaterThan(3);
    });
});

describe('verifyTimeStampToken under adversarial tokens, responses and requests', () => {
    it('should always resolve with a registered report', async () => {
        const prng = createPrng(SEED + 2);
        const seen = new Map<string, number>();
        const base = { trustAnchors: [w.root.certificate], at: AT };
        expect((await verifyTimeStampToken({ ...base, token: w.token, request: w.request })).reasons).toEqual([]);
        expect((await verifyTimeStampToken({ ...base, response: w.response, data: DATA })).valid).toBe(true);
        for (let i = 0; i < BUDGET; i += 1) {
            const limits = TINY_LIMITS[prng.int(TINY_LIMITS.length)];
            const mode = prng.pick(['token', 'response', 'request', 'imprint', 'crl'] as const);
            const source = mode === 'response' ? w.response : mode === 'request' ? w.request : mode === 'crl' ? w.crl : w.token;
            const mutated = mode === 'imprint' ? { name: 'imprint', bytes: prng.bytes(prng.pick([0, 1, 20, 31, 32, 33])) } : mutate(prng, source, w.donors);
            const label = `seed ${String(prng.seed)} iteration ${String(i)} ${mutated.name} ${mode} limits ${JSON.stringify(limits)}`;
            const stamped = mode === 'response' ? { response: mutated.bytes } : { token: w.token };
            const said = mode === 'request' ? { request: mutated.bytes }
                : mode === 'imprint' ? { imprint: mutated.bytes }
                    : prng.int(2) === 0 ? { request: w.request } : { data: DATA };
            const result = await check(label, mutated.bytes, () => verifyTimeStampToken({
                ...base,
                ...(mode === 'token' ? { token: mutated.bytes } : stamped),
                ...said,
                ...(mode === 'crl' ? { crls: [mutated.bytes] } : {}),
                ...(limits === undefined ? {} : { limits }),
            }), (error) => mode === 'request' && error.code !== 'PKI_API_MISUSE');
            seen.set(result, (seen.get(result) ?? 0) + 1);
        }
        expect(seen.size).toBeGreaterThan(3);
    });
});

describe('openPkcs12 under adversarial files, passwords and limits', () => {
    it('should always resolve with a registered report', async () => {
        const prng = createPrng(SEED + 3);
        const seen = new Map<string, number>();
        const sound = await openPkcs12(w.pkcs12, { password: PASSWORD });
        expect(sound.reasons).toEqual([]);
        expect(sound.keys).toHaveLength(1);
        for (let i = 0; i < BUDGET; i += 1) {
            const limits = TINY_LIMITS[prng.int(TINY_LIMITS.length)];
            const mode = prng.int(4) === 0 ? 'password' : 'file';
            const mutated = mode === 'file' ? mutate(prng, w.pkcs12, w.donors) : { name: 'password', bytes: w.pkcs12 };
            const password = mode === 'password' ? prng.pick(['', 'wrong', PASSWORD.slice(0, -1), ' ', `${PASSWORD} `]) : PASSWORD;
            const label = `seed ${String(prng.seed)} iteration ${String(i)} ${mutated.name} ${mode} limits ${JSON.stringify(limits)}`;
            const result = await check(label, mutated.bytes, () => openPkcs12(mutated.bytes, {
                password,
                ...(limits === undefined ? {} : { limits }),
            }));
            seen.set(result, (seen.get(result) ?? 0) + 1);
        }
        expect(seen.size).toBeGreaterThan(3);
    });
});

/**
 * The property above must not be satisfied by swallowing everything: misuse
 * still throws its documented code, whatever the bytes beside it.
 */
describe('the reports under API misuse', () => {
    const notACertificate = { der: new Uint8Array(1) } as unknown as Certificate;

    it('should still throw from verifyCertificateChain', async () => {
        const base = { leaf: w.signer.certificate, trustAnchors: [w.root.certificate], at: AT, crls: [w.crl], ocspResponses: [w.ocsp] };
        await expect(verifyCertificateChain({ ...base, limits: { maxNode: 1 } as Partial<PkiLimits> })).rejects.toMatchObject({ code: 'PKI_LIMIT_INVALID' });
        await expect(verifyCertificateChain({ ...base, leaf: notACertificate })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
        await expect(verifyCertificateChain({ ...base, crls: ['MIIB' as unknown as Uint8Array] })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
    });

    it('should still throw from verifySignedData', async () => {
        const base = { signedData: w.attached, trustAnchors: [w.root.certificate], at: AT };
        await expect(verifySignedData({ ...base, limits: { maxNodes: 0 } })).rejects.toMatchObject({ code: 'PKI_LIMIT_INVALID' });
        await expect(verifySignedData({ ...base, encodingRules: 'cer' as 'der' })).rejects.toMatchObject({ code: 'PKI_INVALID_OPTION' });
        await expect(verifySignedData({ ...base, certificates: [notACertificate] })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
        await expect(verifySignedData({ ...base, signedData: w.detached, content: DATA, contentDigest: w.imprint })).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
        await expect(verifySignedData({ ...base, content: DATA })).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
    });

    it('should still throw from verifyTimeStampToken', async () => {
        const base = { token: w.token, data: DATA, trustAnchors: [w.root.certificate], at: AT };
        await expect(verifyTimeStampToken({ ...base, limits: { maxNode: 1 } as Partial<PkiLimits> })).rejects.toMatchObject({ code: 'PKI_LIMIT_INVALID' });
        await expect(verifyTimeStampToken({ ...base, token: 'MIIB' as unknown as Uint8Array })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
        await expect(verifyTimeStampToken({ ...base, trustAnchors: [notACertificate] })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
        await expect(verifyTimeStampToken({ ...base, response: w.response })).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
        await expect(verifyTimeStampToken({ token: w.token, trustAnchors: [w.root.certificate] })).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
    });

    it('should still throw from openPkcs12', async () => {
        await expect(openPkcs12(w.pkcs12, { password: PASSWORD, limits: { maxNode: 1 } as Partial<PkiLimits> })).rejects.toMatchObject({ code: 'PKI_LIMIT_INVALID' });
        await expect(openPkcs12('MIIB' as unknown as Uint8Array, { password: PASSWORD })).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
    });
});
