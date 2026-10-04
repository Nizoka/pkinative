import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import * as pkinative from '../../src/index.js';
import { GUIDE_INPUTS, extractTsFences, guideFiles, type Fence } from '../../scripts/check-guides.js';
import { fuzzSeeds } from '../fuzzing/_fuzz-seeds.js';
import { DAY, issue, issueTsa, keyPair, makeOcspResponse, makeToken, rawSign, spkiOf, tstInfo, type Authority, type Holder } from '../verify/_cms-pki.js';

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

/**
 * Every ```ts fence of README.md and the guides, EXECUTED — not only compiled, which is what
 * `scripts/check-guides.ts` does. The final review of 2026-10-04 found the guide's primary
 * writer example throwing on every call while it type-checked: this suite closes that class.
 *
 * Each fence runs as the reader would run it: `import … from 'pkinative'` resolves to the
 * library, the free identifiers of `GUIDE_INPUTS` receive real values built here (a test PKI,
 * CRL, OCSP response, SignedData, PKCS#12, keys), `fetch` answers from the same PKI, and a
 * function the fence defines and does not call is called with the arguments its parameters
 * name. A fence that throws fails; a fence of `EXPECT_SILENT` — the examples that print only
 * when something is wrong — fails if it printed or returned a failure message.
 */

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

/** Fences not executed, each with its reason; the test refuses an entry without one. */
const NOT_RUN: Readonly<Record<string, string>> = {};

/** Fences whose only output is a failure: no log line, no returned string, is the proof they succeeded. */
const EXPECT_SILENT = new Set<string>([
    'README.md:67', 'docs/guides/quickstart.md:19', 'docs/guides/quickstart.md:95',
    'docs/guides/use-cases.md:178', 'docs/guides/use-cases.md:204', 'docs/guides/use-cases.md:235',
    'docs/guides/use-cases.md:266', 'docs/guides/use-cases.md:325', 'docs/guides/use-cases.md:407',
    'docs/guides/use-cases.md:528', 'docs/guides/use-cases.md:571', 'docs/guides/use-cases.md:607',
]);

type Inputs = Record<string, unknown>;
let inputs: Inputs;
let fetchStub: (url: string, init?: { body?: Uint8Array }) => Promise<{ arrayBuffer(): Promise<ArrayBuffer> }>;

/** TimeStampReq (RFC 3161 §2.4.1): the imprint's hash and the nonce, read with the decoder. */
function readTimeStampRequest(der: Uint8Array): { hash: Uint8Array; nonce: bigint | undefined } {
    const req = pkinative.decodeAsn1(der);
    const imprint = req.children?.[1];
    const hash = imprint?.children?.[1]?.content ?? new Uint8Array(0);
    const nonceNode = req.children?.find((c, i) => i >= 2 && c.tagNumber === 2 && c.tagClass === 'universal');
    return { hash, nonce: nonceNode === undefined ? undefined : pkinative.readInteger(nonceNode) };
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
    const ocspDer = await makeOcspResponse(root, leaf.certificate, 'good');
    const spki = await spkiOf(leaf.pair);
    const seeds = await fuzzSeeds();
    const bundle = [leaf.certificate, root.certificate].map((c) => pkinative.encodePem('CERTIFICATE', c.der)).join('');
    inputs = {
        // bytes and text
        der, pemText: pkinative.encodePem('CERTIFICATE', der), crlDer, baseDer: crlDer, newerDer: crlDer,
        p7s: await pkinative.createSignedData({ content: message, certificate: leaf.certificate, detached: true }, leaf.signer),
        p12Bytes: seeds.pkcs12[0], message, signedContent: message, password: 'fuzz-seed', url: 'http://127.0.0.1/ocsp', tsaUrl: 'http://127.0.0.1/tsa',
        csrDer: await pkinative.createCertificationRequest({ subject: [[{ type: '2.5.4.3', value: 'Guide Leaf' }]], subjectPublicKey: spki }, leaf.signer),
        // parsed structures
        leaf: leaf.certificate, certificate: leaf.certificate, caCertificate: root.certificate, issuer: root.certificate,
        signerCertificate: leaf.certificate, responderCertificate: root.certificate,
        chain: [leaf.certificate], candidates: [leaf.certificate, root.certificate], whateverTheServerSent: [leaf.certificate, root.certificate],
        roots: [root.certificate], yourRoots: [root.certificate], trustAnchors: [root.certificate], signatures: [],
        base: crl, newer: crl, response: pkinative.parseOcspResponse(ocspDer), nonce: crypto.getRandomValues(new Uint8Array(8)),
        // verdicts the prose says were computed
        signatureVerified: true, deltaVerified: true, responderAuthorized: true,
        // keys
        publicKey: leaf.pair.publicKey, signingKey: leaf.signer,
        // the reader's own helpers, and the arguments of the functions the fences define
        log: (): void => undefined, spki, signer: leaf.signer, bundle, within: 365 * 86_400_000, leafDer: der, issuerDer: root.certificate.der,
    };
    fetchStub = async (url, init) => {
        let body: Uint8Array;
        if (url.endsWith('/ocsp')) body = ocspDer;
        else if (url.endsWith('/tsa')) {
            const { hash, nonce } = readTimeStampRequest(init?.body ?? new Uint8Array(0));
            const token = await makeToken(tsa, tstInfo({ imprint: hash, genTime: NOW, ...(nonce === undefined ? {} : { nonce }) }));
            body = pkinative.encodeSequence([pkinative.encodeSequence([pkinative.encodeInteger(0)]), token]);
        } else throw new Error(`unexpected fetch of ${url}`);
        return { arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer };
    };
}, 60_000);

const IMPORT = /^import\s*\{([^}]*)\}\s*from\s*['"]pkinative['"];?\s*$/gm;
const DECLARED = (code: string, name: string): boolean => new RegExp(`\\b(?:const|let|var|function|class)\\s+(?:\\{[^}]*\\b${name}\\b[^}]*\\}|\\[[^\\]]*\\b${name}\\b[^\\]]*\\]|${name}\\b)`).test(code);
const EXPORTED_FUNCTION = /^export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/gm;

/** The names a fence imports from pkinative (`type X` elided by the transpiler; `as` aliases kept whole). */
function importedNames(code: string): string[] {
    return [...code.matchAll(IMPORT)].flatMap((m) => (m[1] ?? '').split(',').map((p) => p.trim()).filter((p) => p !== '' && !p.startsWith('type ')));
}

/**
 * The fence as one async program: imports become destructuring (a fence without its own import
 * continues the imports of the fences before it in the same file, as `check-guides.ts` compiles
 * them), inputs are bound, and a function the fence defines is called with its named arguments.
 */
function programOf(fence: Fence, continued: readonly string[]): { readonly text: string; readonly params: string[] } {
    const js = ts.transpileModule(fence.code, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const own = importedNames(fence.code);
    const inherited = own.length === 0 && continued.length > 0 ? `const { ${[...new Set(continued)].join(', ')} } = pkinative;\n` : '';
    const body = inherited + js.replace(IMPORT, (_m, names: string) => `const {${names}} = pkinative;`).replace(/^export\s+/gm, '');
    const used = Object.keys(GUIDE_INPUTS).filter((n) => new RegExp(`\\b${n}\\b`).test(fence.code) && !DECLARED(fence.code, n));
    const calls: string[] = [];
    const params: string[] = [];
    for (const m of fence.code.matchAll(EXPORTED_FUNCTION)) {
        const args = (m[2] ?? '').split(',').map((p) => p.trim()).filter((p) => p !== '').map((p) => p.replace(/[?:=].*$/s, '').trim());
        params.push(...args);
        calls.push(`await ${m[1]}(${args.map((a) => `inputs[${JSON.stringify(a)}]`).join(', ')});`);
    }
    const text = `return (async () => {\n${used.map((n) => `const ${n} = inputs[${JSON.stringify(n)}];`).join('\n')}\n${body}\n${calls.join('\n')}\n})();`;
    return { text, params };
}

const fences = guideFiles(ROOT).flatMap((file) => extractTsFences(file, readFileSync(resolve(ROOT, file), 'utf8')));

describe('guide fences, executed', () => {
    it('should name a reason for every fence it does not run, and know every input a fence may use', () => {
        for (const [key, why] of Object.entries(NOT_RUN)) expect(why.length, key).toBeGreaterThan(10);
        for (const name of Object.keys(GUIDE_INPUTS)) expect(inputs, name).toHaveProperty(name);
        expect(fences.length).toBeGreaterThan(20);
    });

    const continuedByFile = new Map<string, string[]>();
    for (const fence of fences) {
        const key = `${fence.file}:${String(fence.line)}`;
        const continued = [...(continuedByFile.get(fence.file) ?? [])];
        continuedByFile.set(fence.file, [...continued, ...importedNames(fence.code)]);
        if (key in NOT_RUN) continue;
        it(`should run ${key} as a reader would${EXPECT_SILENT.has(key) ? ', and print nothing' : ''}`, async () => {
            const { text, params } = programOf(fence, continued);
            for (const p of params) expect(inputs, `${key}: the fence's function takes "${p}" — give it a value`).toHaveProperty(p);
            const printed: string[] = [];
            const quiet = { log: (...a: unknown[]) => { printed.push(a.map(String).join(' ')); }, error: (...a: unknown[]) => { printed.push(a.map(String).join(' ')); }, warn: (...a: unknown[]) => { printed.push(a.map(String).join(' ')); } };
            const run = new Function('pkinative', 'inputs', 'console', 'fetch', 'crypto', text) as (...args: unknown[]) => Promise<unknown>;
            const returned = await run(pkinative, { ...inputs, log: (...a: unknown[]) => { printed.push(a.map(String).join(' ')); } }, quiet, fetchStub, globalThis.crypto);
            if (EXPECT_SILENT.has(key)) {
                expect(printed, `${key} printed: ${printed.join(' | ')}`).toEqual([]);
                expect(typeof returned === 'string' ? returned : undefined, `${key} returned a failure: ${String(returned)}`).toBeUndefined();
            }
        }, 30_000);
    }
});
