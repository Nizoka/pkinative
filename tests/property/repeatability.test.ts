import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { samples } from '../../scripts/lib/samples.js';
import type { CryptoKeyHandle } from '../../src/types/webcrypto.js';

/**
 * The writers are repeatable: the same description gives the same bytes on
 * two independent runs, and from either build of the package.
 *
 * Every signed sample uses Ed25519, deterministic by RFC 8032, so the whole
 * catalogue is a fixed point — which is also what lets `verify:samples` hold
 * it to a hash. ECDSA and RSASSA-PSS signatures are randomised by design and
 * are held to facts, not bytes, by the interop set. Then the two builds:
 * `dist/index.js` and `dist/index.cjs` are the same source bundled twice, and
 * a relying party that hashes what one wrote must get what the other wrote.
 * It needs dist/ for that half: the gate builds before the suites, and
 * GATE_REQUIRE_ARTIFACTS turns a missing build into a failure, not a skip.
 */

const ROOT = process.cwd();
const ESM = join(ROOT, 'dist', 'index.js');
const CJS = join(ROOT, 'dist', 'index.cjs');
const haveDist = existsSync(ESM) && existsSync(CJS);
if (!haveDist && process.env['GATE_REQUIRE_ARTIFACTS'] === '1') {
    throw new Error('dist/index.js or dist/index.cjs is missing but GATE_REQUIRE_ARTIFACTS=1 — run `npm run build`');
}

type Api = typeof import('../../src/index.js');

const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, i) => byte === b[i]);

describe('the sample catalogue, run twice', () => {
    it('should produce the same bytes for every sample', async () => {
        const first = await samples();
        const second = await samples();
        expect([...second.keys()]).toEqual([...first.keys()]);
        for (const [name, bytes] of first) {
            expect(same(bytes, second.get(name) ?? new Uint8Array()), name).toBe(true);
        }
    });
});

describe.skipIf(!haveDist)('the ES module and CommonJS builds, writing the same description', () => {
    /** The deterministic signer of scripts/lib/samples.ts: a fixed seed, so the two builds can be handed one key. */
    const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...new Array<number>(32).fill(0x42)]);
    const CN = '2.5.4.3';

    const load = async (): Promise<{ readonly esm: Api; readonly cjs: Api }> => ({
        esm: await import(/* @vite-ignore */ pathToFileURL(ESM).href) as Api,
        cjs: createRequire(import.meta.url)(CJS) as Api,
    });

    it('should write identical bytes for a name, an extension list, a certificate, a request and a signed message', async () => {
        const { esm, cjs } = await load();
        const key = await crypto.subtle.importKey('pkcs8', PKCS8, { name: 'Ed25519' }, false, ['sign']);
        const signer = { key: key as unknown as CryptoKeyHandle, algorithm: { name: 'Ed25519' } as const };
        const spki = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...new Array<number>(32).fill(0)]);
        const describe = (api: Api): Promise<Uint8Array[]> => Promise.all([
            Promise.resolve(api.encodeDistinguishedName([[{ type: CN, value: 'pkinative repeatability' }]])),
            Promise.resolve(api.encodeExtensions([{ oid: '2.5.29.19', critical: true, value: api.encodeBasicConstraints({ cA: false }) }])),
            api.createCertificate({
                serialNumber: 7n, subject: [[{ type: CN, value: 'pkinative repeatability' }]],
                notBefore: Date.UTC(2026, 0, 1), notAfter: Date.UTC(2027, 0, 1), subjectPublicKey: spki,
            }, signer),
            api.createCertificationRequest({ subject: [[{ type: CN, value: 'pkinative repeatability' }]], subjectPublicKey: spki }, signer),
        ]);
        const [fromEsm, fromCjs] = await Promise.all([describe(esm), describe(cjs)]);
        expect(fromCjs).toHaveLength(fromEsm.length);
        fromEsm.forEach((bytes, i) => expect(same(bytes, fromCjs[i] ?? new Uint8Array()), `artefact ${String(i)}`).toBe(true));
        const certificate = fromEsm[2] ?? new Uint8Array();
        const message = (api: Api): Promise<Uint8Array> => api.createSignedData(
            { content: new TextEncoder().encode('repeatable'), certificate: api.parseCertificate(certificate, { onDiagnostic: () => undefined }) }, signer);
        expect(same(await message(esm), await message(cjs))).toBe(true);
    });
});
