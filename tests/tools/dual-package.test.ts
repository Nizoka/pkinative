import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The dual package hazard, on the real build. package.json sends `import`
 * to dist/index.js and `require` to dist/index.cjs, so an application whose
 * dependencies use both loads two copies of every class. An error thrown by
 * one copy must still satisfy `instanceof` against the other — the errors
 * guide teaches `error instanceof PkiError` — and keep its subclass.
 *
 * It needs dist/: the gate builds before the suites, and
 * GATE_REQUIRE_ARTIFACTS turns a missing build there into a failure rather
 * than a silent skip.
 */

const ROOT = process.cwd();
const ESM = join(ROOT, 'dist', 'index.js');
const CJS = join(ROOT, 'dist', 'index.cjs');
const haveDist = existsSync(ESM) && existsSync(CJS);
if (!haveDist && process.env['GATE_REQUIRE_ARTIFACTS'] === '1') {
    throw new Error('dist/index.js or dist/index.cjs is missing but GATE_REQUIRE_ARTIFACTS=1 — run `npm run build`');
}

type Api = typeof import('../../src/index.js');

/** The first error `fn` throws. */
function thrown(fn: () => unknown): unknown {
    try {
        fn();
    } catch (error) {
        return error;
    }
    throw new Error('expected a throw');
}

describe.skipIf(!haveDist)('the ES module and CommonJS builds loaded together', () => {
    const load = async (): Promise<{ readonly esm: Api; readonly cjs: Api }> => ({
        esm: await import(/* @vite-ignore */ pathToFileURL(ESM).href) as Api,
        cjs: createRequire(import.meta.url)(CJS) as Api,
    });
    // Indefinite length under DER: a PkiEncodingError from either copy.
    const INDEFINITE = Uint8Array.of(0x30, 0x80, 0x00, 0x00);

    it('should be two copies, with two sets of classes', async () => {
        const { esm, cjs } = await load();
        expect(esm.PkiError).not.toBe(cjs.PkiError);
    });

    it('should let either copy recognise the other\'s errors, family and all', async () => {
        const { esm, cjs } = await load();
        const fromCjs = thrown(() => cjs.decodeAsn1(INDEFINITE));
        const fromEsm = thrown(() => esm.decodeAsn1(INDEFINITE));
        for (const [error, other] of [[fromCjs, esm], [fromEsm, cjs]] as const) {
            expect(error instanceof other.PkiError).toBe(true);
            expect(error instanceof other.PkiEncodingError).toBe(true);
            expect(error instanceof other.PkiCertificateError).toBe(false);
            expect(error instanceof other.PkiCryptoError).toBe(false);
            expect((error as { code?: unknown }).code).toBe('PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN');
        }
    });
});
