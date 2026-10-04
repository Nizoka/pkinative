import { describe, it, expect, beforeAll } from 'vitest';
import { webcrypto } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import * as pkinative from '../../src/index.js';
import { GUIDE_INPUTS, extractTsFences, guideFiles, type Fence } from '../../scripts/check-guides.js';
import { fuzzSeeds } from '../fuzzing/_fuzz-seeds.js';
import { shroudKey } from '../helpers/pkcs12-builder.js';
import { DAY, issue, issueTsa, keyPair, makeToken, rawSign, sha, spkiOf, tstInfo, type Authority, type Holder } from '../verify/_cms-pki.js';

/**
 * Every ```ts fence of README.md, the guides AND the TSDoc of `src/`, EXECUTED — not only compiled,
 * which is what `scripts/check-guides.ts` does for the guides (the TSDoc fences had no net at all).
 * The final review of 2026-10-04 found the guide's primary writer example throwing on every call
 * while it type-checked, and the second review found a TSDoc example doing the same: this suite
 * closes that class.
 *
 * Each fence runs as the reader would run it: `import … from 'pkinative'` resolves to the
 * library, the free identifiers receive real values built here (a test PKI valid now, a CRL, an
 * OCSP response, a detached SignedData, a timestamp token, a PKCS#12 from the fuzz seeds, keys),
 * `fetch` answers from the same PKI, and a function the fence defines and does not call is called
 * with the arguments its parameters name. A fence that throws fails; a fence of `EXPECT_SILENT` —
 * the examples that print only when something is wrong — fails if it printed or returned a failure
 * message; a function fence of `EXPECT_RESULT` fails if its result is not the one the prose shows.
 */

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

/** Fences not executed, each with its reason; the test refuses an entry without one. */
const NOT_RUN: Readonly<Record<string, string>> = {};

/** Fences whose only output is a failure: no log line, no returned string, is the proof they succeeded. */
const EXPECT_SILENT = new Set<string>([
    'README.md:67', 'docs/guides/quickstart.md:19', 'docs/guides/quickstart.md:95',
    'docs/guides/use-cases.md:178', 'docs/guides/use-cases.md:204', 'docs/guides/use-cases.md:235',
    'docs/guides/use-cases.md:266', 'docs/guides/use-cases.md:325', 'docs/guides/use-cases.md:407',
    'docs/guides/use-cases.md:499', 'docs/guides/use-cases.md:529', 'docs/guides/use-cases.md:572', 'docs/guides/use-cases.md:609',
    'src/path/path-validate.ts:396', 'src/verify/verify-chain.ts:273', 'src/verify/verify-signed-data.ts:145',
    'src/revocation/ocsp-check.ts:154', 'src/verify/verify-pkcs12.ts:128',
    'src/crypto/x509-verify.ts:107', 'src/crypto/x509-verify.ts:219', 'src/crypto/x509-verify.ts:253', 'src/crypto/cms-verify.ts:55',
]);

/** Fences that print their success: the line the prose shows must appear. */
const EXPECT_PRINTED: Readonly<Record<string, RegExp>> = {
    'src/verify/verify-timestamp.ts:162': /^existed by 20\d\d-/,
    'docs/guides/use-cases.md:470': /^good$/,
};

/** What the functions a fence defines must return when called with the inputs below (the prose's own answer). */
const EXPECT_RESULT: Readonly<Record<string, (results: readonly unknown[]) => void>> = {
    'README.md:67': (r) => { expect(r[0]).toEqual(expect.arrayContaining([expect.stringContaining('Guide Leaf'), expect.stringContaining('Guide Root')])); },
    'docs/guides/use-cases.md:178': (r) => { expect(r[0]).toBe('yes'); },
    'docs/guides/use-cases.md:204': (r) => { expect(r[0]).toBeInstanceOf(Uint8Array); expect(pkinative.parseCertificate(r[0] as Uint8Array).subject.der.length).toBeGreaterThan(0); },
    'docs/guides/use-cases.md:52': (r) => { expect(r[0]).toHaveLength(2); },   // both test certificates expire within the year
    'docs/guides/use-cases.md:104': (r) => { expect(typeof r[0]).toBe('string'); },
    'docs/guides/use-cases.md:160': (r) => { expect(r[0]).toBe(true); },
};

type Inputs = Record<string, unknown>;
let inputs: Inputs;
/** Inputs whose meaning a module's TSDoc fixes differently from the guides: by file prefix, then by exact fence. */
let overrides: Readonly<Record<string, Inputs>>;
const overridesFor = (key: string): Inputs => Object.assign({}, ...Object.entries(overrides).filter(([prefix]) => key.startsWith(prefix)).map(([, values]) => values)) as Inputs;
let fetchStub: (url: string, init?: { body?: Uint8Array }) => Promise<{ arrayBuffer(): Promise<ArrayBuffer> }>;

/** The instant the fences run at (`Date.now()` in several of them), rounded to the second RFC 5280 writes. */
const NOW = Math.floor(Date.now() / 1000) * 1000;
const quiet = { onDiagnostic: (): undefined => undefined };
const ED25519 = pkinative.encodeSequence([pkinative.encodeObjectIdentifier('1.3.101.112')]);

/** A self-signed Ed25519 root valid NOW ± 30 days (the shared `makeRoot` is valid around a fixed instant). */
async function makeRootNow(cn: string): Promise<Authority> {
    const pair = await keyPair('Ed25519');
    const name = [[{ type: '2.5.4.3', value: cn }]];
    const der = await pkinative.createCertificate({
        serialNumber: 1n, issuer: name, subject: name, notBefore: NOW - 30 * DAY, notAfter: NOW + 30 * DAY,
        subjectPublicKey: await spkiOf(pair),
        extensions: [
            { oid: '2.5.29.19', critical: true, value: pkinative.encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: pkinative.encodeKeyUsage(['keyCertSign', 'cRLSign']) },
        ],
    }, { key: pair.privateKey, algorithm: { name: 'Ed25519' } });
    return { certificate: pkinative.parseCertificate(der, quiet), key: pair.privateKey };
}

/** An empty v2 CRL by `ca`, current NOW ± 20 days. */
async function makeCrlNow(ca: Authority): Promise<Uint8Array> {
    const tbs = pkinative.encodeSequence([
        pkinative.encodeInteger(1), ED25519, ca.certificate.subject.der,
        pkinative.encodeTime(NOW - 20 * DAY, 'UTCTime'), pkinative.encodeTime(NOW + 20 * DAY, 'UTCTime'),
    ]);
    return pkinative.encodeSequence([tbs, ED25519, pkinative.encodeBitString(await rawSign({ name: 'Ed25519' }, ca.key, tbs))]);
}

/** A `good` BasicOCSPResponse about `certificate`, signed by its issuer `ca`, current NOW ± 1 day, echoing `nonce` when given. */
async function makeOcspResponseNow(ca: Authority, certificate: pkinative.Certificate, nonce?: Uint8Array): Promise<Uint8Array> {
    const keyHash = await sha('SHA-1', ca.certificate.subjectPublicKeyInfo.publicKey.bytes);
    const certId = pkinative.encodeSequence([
        pkinative.encodeSequence([pkinative.encodeObjectIdentifier('1.3.14.3.2.26'), pkinative.encodeNull()]),
        pkinative.encodeOctetString(await sha('SHA-1', ca.certificate.subject.der)),
        pkinative.encodeOctetString(keyHash),
        pkinative.encodeTlv('universal', 2, false, certificate.serialNumber.bytes),
    ]);
    const single = pkinative.encodeSequence([
        certId, pkinative.encodeTlv('context', 0, false, new Uint8Array(0)),
        pkinative.encodeTime(NOW - DAY, 'GeneralizedTime'),
        pkinative.encodeExplicit(0, pkinative.encodeTime(NOW + DAY, 'GeneralizedTime'), { tagClass: 'context' }),
    ]);
    const nonceExtension = nonce === undefined ? [] : [pkinative.encodeExplicit(1, pkinative.encodeSequence([pkinative.encodeSequence([
        pkinative.encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.2'), pkinative.encodeOctetString(pkinative.encodeOctetString(nonce)),
    ])]), { tagClass: 'context' })];
    const tbs = pkinative.encodeSequence([
        pkinative.encodeExplicit(2, pkinative.encodeOctetString(keyHash), { tagClass: 'context' }),
        pkinative.encodeTime(NOW - DAY, 'GeneralizedTime'),
        pkinative.encodeSequence([single]),
        ...nonceExtension,
    ]);
    const basic = pkinative.encodeSequence([tbs, ED25519, pkinative.encodeBitString(await rawSign({ name: 'Ed25519' }, ca.key, tbs))]);
    return pkinative.encodeSequence([
        pkinative.encodeEnumerated(0),
        pkinative.encodeExplicit(0, pkinative.encodeSequence([pkinative.encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.1'), pkinative.encodeOctetString(basic)]), { tagClass: 'context' }),
    ]);
}

/** TimeStampReq (RFC 3161 §2.4.1): the imprint's hash and the nonce, read with the decoder. */
function readTimeStampRequest(der: Uint8Array): { hash: Uint8Array; nonce: bigint | undefined } {
    const req = pkinative.decodeAsn1(der);
    const hash = req.children?.[1]?.children?.[1]?.content ?? new Uint8Array(0);
    const nonceNode = req.children?.find((c, i) => i >= 2 && c.tagNumber === 2 && c.tagClass === 'universal');
    return { hash, nonce: nonceNode === undefined ? undefined : pkinative.readInteger(nonceNode) };
}

/** OCSPRequest: the nonce extension's value, when the request carries one. */
function readOcspNonce(der: Uint8Array): Uint8Array | undefined {
    const hex = Array.from(der, (b) => b.toString(16).padStart(2, '0')).join('');
    const at = hex.indexOf('06092b0601050507300102');   // id-pkix-ocsp-nonce
    if (at < 0) return undefined;
    const rest = der.subarray(at / 2 + 11);
    const outer = pkinative.decodeAsn1(rest.subarray(0, rest[1]! + 2));   // OCTET STRING { OCTET STRING nonce }
    return outer.content[0] === 0x04 ? outer.content.subarray(2) : outer.content;
}

beforeAll(async () => {
    const root: Authority = await makeRootNow('Guide Root');
    // A server certificate as the chain and server-name fences expect: bank.example, serverAuth.
    const leaf: Holder = await issue(root, {
        subject: 'Guide Leaf', family: 'ECDSA', notBefore: NOW - DAY, notAfter: NOW + DAY,
        extensions: [
            { oid: '2.5.29.17', value: pkinative.encodeSubjectAltName([{ kind: 'dNSName', value: 'bank.example' }]) },
            { oid: '2.5.29.37', value: pkinative.encodeExtendedKeyUsage(['1.3.6.1.5.5.7.3.1']) },
        ],
    });
    const tsa: Holder = await issueTsa(root, { notBefore: NOW - DAY, notAfter: NOW + 9 * DAY });
    const der = leaf.certificate.der;
    const message = new TextEncoder().encode('guide fence content');
    const crlDer = await makeCrlNow(root);
    const crl = pkinative.parseCertificateList(crlDer);
    const nonce = crypto.getRandomValues(new Uint8Array(8));
    const ocspDer = await makeOcspResponseNow(root, leaf.certificate, nonce);
    const spki = await spkiOf(leaf.pair);
    const seeds = await fuzzSeeds();
    const bundle = [leaf.certificate, root.certificate].map((c) => pkinative.encodePem('CERTIFICATE', c.der)).join('');
    const p7s = await pkinative.createSignedData({ content: message, certificate: leaf.certificate, detached: true }, leaf.signer);
    const imprint = await sha('SHA-256', pkinative.parseSignedData(p7s).signerInfos[0]!.signature);
    const tokenDer = await makeToken(tsa, tstInfo({ imprint, genTime: NOW, nonce: 0x1234n }));
    const tspResponse = async (requestDer: Uint8Array): Promise<Uint8Array> => {
        const { hash, nonce: n } = readTimeStampRequest(requestDer);
        const token = await makeToken(tsa, tstInfo({ imprint: hash, genTime: NOW, ...(n === undefined ? {} : { nonce: n }) }));
        return pkinative.encodeSequence([pkinative.encodeSequence([pkinative.encodeInteger(0)]), token]);
    };
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', leaf.pair.privateKey as never));
    const rsaPair = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
    const rsaDer = new Uint8Array(await crypto.subtle.exportKey('pkcs8', rsaPair.privateKey));
    inputs = {
        // bytes and text
        der, pemText: pkinative.encodePem('CERTIFICATE', der), crlDer, baseDer: crlDer, newerDer: crlDer, p7s,
        p12Bytes: seeds.pkcs12[0], p12: seeds.pkcs12[0], message, document: message, signedContent: message, password: 'fuzz-seed',
        url: 'http://127.0.0.1/ocsp', tsaUrl: 'http://127.0.0.1/tsa',
        csrDer: await pkinative.createCertificationRequest({ subject: [[{ type: '2.5.4.3', value: 'Guide Leaf' }]], subjectPublicKey: spki }, leaf.signer),
        certDer: der, signerDer: der, leafDer: der, issuerDer: root.certificate.der, serialNumber: leaf.certificate.serialNumber.bytes,
        token: tokenDer, tokenDer, ecDer: pkcs8, rsaDer, pkcs8, request: pkinative.createTimeStampRequest(imprint, { nonce: 0x1234n }), content: message,
        report: { path: [leaf.certificate, root.certificate] },
        // parsed structures
        leaf: leaf.certificate, certificate: leaf.certificate, caCertificate: root.certificate, issuer: root.certificate, ca: root.certificate,
        signerCertificate: leaf.certificate, responderCertificate: root.certificate,
        chain: [leaf.certificate], candidates: [leaf.certificate, root.certificate], whateverTheServerSent: [leaf.certificate, root.certificate],
        roots: [root.certificate], yourRoots: [root.certificate], trustAnchors: [root.certificate], tsaRoots: [root.certificate], signatures: [],
        base: crl, newer: crl, crl, response: pkinative.parseOcspResponse(ocspDer), nonce,
        // verdicts the prose says were computed
        signatureVerified: true, deltaVerified: true, responderAuthorized: true,
        // keys
        publicKey: leaf.pair.publicKey, privateKey: leaf.pair.privateKey, signingKey: leaf.signer, signer: leaf.signer, spki,
        // the reader's own helpers, and the arguments of the functions the fences define
        log: (): void => undefined, askYourTsa: tspResponse, bundle, within: 365 * 86_400_000, valueDer: pkinative.encodeOctetString(message),
    };
    const tspReply = await tspResponse(pkinative.createTimeStampRequest(imprint, { nonce: 0x1234n }));
    overrides = {
        // The key modules' `pemText` is a private key, `bytes` a PKCS#12; one example decrypts under its own password.
        'src/keys/': { pemText: pkinative.encodePem('PRIVATE KEY', pkcs8), bytes: seeds.pkcs12[0], certificates: [] },
        'src/keys/key-import.ts:201': { pemText: pkinative.encodePem('ENCRYPTED PRIVATE KEY', await shroudKey(pkcs8, 'correct horse battery staple')) },
        // The TSP modules' `reply` is a fetch Response of a TimeStampResp; `token` a parsed TimeStampToken.
        'src/cms/tsp-response.ts': { reply: { arrayBuffer: async () => tspReply.buffer.slice(tspReply.byteOffset, tspReply.byteOffset + tspReply.byteLength) } },
        'src/cms/tsp-tst-info.ts': { token: pkinative.parseTimeStampToken(tokenDer) },
        // A timestamp request's nonce is a bigint (RFC 3161 §2.4.1), an OCSP request's is octets.
        'src/build/build-signed-data.ts:653': { nonce: 0x1234n },
        // The OCSP modules' `bytes` is a response; the check example names the CertID hashes and the responder.
        'src/revocation/ocsp-': { bytes: ocspDer, issuerNameHash: await sha('SHA-1', root.certificate.subject.der), issuerKeyHash: await sha('SHA-1', root.certificate.subjectPublicKeyInfo.publicKey.bytes), responder: root.certificate, yourPolicySaysSo: true },
        'src/crypto/x509-verify.ts:253': { bytes: ocspDer },
    };
    fetchStub = async (url, init) => {
        let body: Uint8Array;
        if (url.endsWith('/ocsp')) body = await makeOcspResponseNow(root, leaf.certificate, readOcspNonce(init?.body ?? new Uint8Array(0)));
        else if (url.endsWith('/tsa')) body = await tspResponse(init?.body ?? new Uint8Array(0));
        else throw new Error(`unexpected fetch of ${url}`);
        return { arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer };
    };
}, 60_000);

const IMPORT = /^import\s*\{([^}]*)\}\s*from\s*['"]pkinative['"];?\s*$/gm;
const EXPORTED_FUNCTION = /^export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/gm;
const INPUT_NAMES = new Set([...Object.keys(GUIDE_INPUTS), 'p12', 'document', 'certDer', 'signerDer', 'leafDer', 'issuerDer', 'serialNumber', 'token', 'tokenDer', 'ecDer', 'rsaDer', 'pkcs8', 'ca', 'tsaRoots', 'crl', 'privateKey', 'signer', 'spki', 'askYourTsa', 'bundle', 'within', 'valueDer', 'bytes', 'certificates', 'reply', 'content', 'request', 'report', 'issuerNameHash', 'issuerKeyHash', 'responder', 'yourPolicySaysSo']);
const declares = (code: string, name: string): boolean => new RegExp(`\\b(?:const|let|var|function|class)\\s+(?:\\{[^}]*\\b${name}\\b[^}]*\\}|\\[[^\\]]*\\b${name}\\b[^\\]]*\\]|${name}\\b)`).test(code);

/** The names a fence imports from pkinative (`type X` elided by the transpiler). */
function importedNames(code: string): string[] {
    return [...code.matchAll(IMPORT)].flatMap((m) => (m[1] ?? '').split(',').map((p) => p.trim()).filter((p) => p !== '' && !p.startsWith('type ')));
}

/**
 * The fence as one async program: imports become destructuring (a fence without its own import
 * continues the imports of the fences before it in the same file, as `check-guides.ts` compiles
 * them), inputs are bound, and a function the fence defines is called with its named arguments;
 * the program resolves to the array of those results.
 */
function programOf(fence: Fence, continued: readonly string[]): { readonly text: string; readonly params: string[] } {
    const js = ts.transpileModule(fence.code, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const own = importedNames(fence.code);
    // A guide fence without imports continues its file's; a TSDoc fence without imports is written in
    // the module's own scope and sees every export — bind them all, minus the names it declares.
    const everyExport = Object.keys(pkinative).filter((n) => /^[A-Za-z_$][\w$]*$/.test(n) && !declares(fence.code, n));
    const inTsdoc = fence.file.startsWith('src/');
    const inherited = own.length === 0 || inTsdoc
        ? `const { ${(inTsdoc ? everyExport.filter((n) => !own.includes(n)) : [...new Set(continued)]).join(', ')} } = pkinative;\n`
        : '';
    const body = inherited + js.replace(IMPORT, (_m, names: string) => `const {${names}} = pkinative;`).replace(/^export\s+/gm, '');
    const used = [...INPUT_NAMES].filter((n) => new RegExp(`\\b${n}\\b`).test(fence.code) && !declares(fence.code, n) && !(inTsdoc && own.includes(n)));
    const calls: string[] = [];
    const params: string[] = [];
    for (const m of fence.code.matchAll(EXPORTED_FUNCTION)) {
        const args = (m[2] ?? '').split(',').map((p) => p.trim()).filter((p) => p !== '').map((p) => p.replace(/[?:=].*$/s, '').trim());
        params.push(...args);
        calls.push(`__results.push(await ${m[1]}(${args.map((a) => `inputs[${JSON.stringify(a)}]`).join(', ')}));`);
    }
    const text = `return (async () => {\nconst __results = [];\n${used.map((n) => `const ${n} = inputs[${JSON.stringify(n)}];`).join('\n')}\n${body}\n${calls.join('\n')}\nreturn __results;\n})();`;
    return { text, params };
}

/** Every ```ts fence inside a TSDoc comment of src/**\/*.ts, as a Fence keyed by the file and the opening line. */
function tsdocFences(): Fence[] {
    const out: Fence[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(dir).sort()) {
            const path = join(dir, entry);
            if (statSync(path).isDirectory()) walk(path);
            else if (entry.endsWith('.ts')) {
                const lines = readFileSync(path, 'utf8').split('\n');
                for (let i = 0; i < lines.length; i++) {
                    if (!/^\s*\*\s*```ts\s*$/.test(lines[i] as string)) continue;
                    const start = i;
                    const body: string[] = [];
                    for (i++; i < lines.length && !/^\s*\*\s*```\s*$/.test(lines[i] as string); i++) body.push((lines[i] as string).replace(/^\s*\*\s?/, ''));
                    out.push({ file: relative(ROOT, path).replace(/\\/g, '/'), line: start + 1, code: body.join('\n') });
                }
            }
        }
    };
    walk(join(ROOT, 'src'));
    return out;
}

const fences = [...guideFiles(ROOT).flatMap((file) => extractTsFences(file, readFileSync(resolve(ROOT, file), 'utf8'))), ...tsdocFences()];

describe('guide and TSDoc fences, executed', () => {
    it('should name a reason for every fence it does not run, know every input a fence may use, and see every fence', () => {
        for (const [key, why] of Object.entries(NOT_RUN)) expect(why.length, key).toBeGreaterThan(10);
        for (const name of INPUT_NAMES) expect(name in inputs || Object.values(overrides).some((o) => name in o), name).toBe(true);
        for (const key of [...EXPECT_SILENT, ...Object.keys(EXPECT_RESULT), ...Object.keys(EXPECT_PRINTED)]) expect(fences.some((f) => `${f.file}:${String(f.line)}` === key), `${key} names no fence — a fence moved; update the key`).toBe(true);
        expect(fences.length).toBeGreaterThan(50);
    });

    const continuedByFile = new Map<string, string[]>();
    for (const fence of fences) {
        const key = `${fence.file}:${String(fence.line)}`;
        const continued = [...(continuedByFile.get(fence.file) ?? [])];
        continuedByFile.set(fence.file, [...continued, ...importedNames(fence.code)]);
        if (key in NOT_RUN) continue;
        it(`should run ${key} as a reader would${EXPECT_SILENT.has(key) ? ', and print nothing' : ''}${key in EXPECT_RESULT ? ', with the result the prose shows' : ''}`, async () => {
            const { text, params } = programOf(fence, continued);
            for (const p of params) expect(inputs, `${key}: the fence's function takes "${p}" — give it a value`).toHaveProperty(p);
            const printed: string[] = [];
            const collect = (...a: unknown[]): void => { printed.push(a.map(String).join(' ')); };
            const run = new Function('pkinative', 'inputs', 'console', 'fetch', 'crypto', text) as (...args: unknown[]) => Promise<unknown[]>;
            const results = await run(pkinative, { ...inputs, ...overridesFor(key), log: collect }, { log: collect, error: collect, warn: collect }, fetchStub, globalThis.crypto);
            if (EXPECT_SILENT.has(key)) {
                expect(printed, `${key} printed: ${printed.join(' | ')}`).toEqual([]);
                // A function fence's result is judged by EXPECT_RESULT; a handler fence returns a message only to say no.
                if (!(key in EXPECT_RESULT)) for (const r of results) expect(typeof r === 'string' ? r : undefined, `${key} returned a failure: ${String(r)}`).toBeUndefined();
            }
            EXPECT_RESULT[key]?.(results);
            const shown = EXPECT_PRINTED[key];
            if (shown !== undefined) expect(printed.some((line) => shown.test(line)), `${key} printed: ${printed.join(' | ')}`).toBe(true);
        }, 30_000);
    }
});
