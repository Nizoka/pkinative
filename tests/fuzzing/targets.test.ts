import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { createPrng } from '../helpers/prng.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The ClusterFuzzLite targets, run here on a seeded corpus.
 *
 * The container is the only place Jazzer's coverage guidance exists, and
 * this repository's CI has never executed, so a target committed without a
 * local proof is a claim rather than a check. What this suite establishes is
 * the half that can be established anywhere: the modules load, the exported
 * `fuzz` is callable, it survives every truncation and mutation the seeded
 * corpus produces, and — the part that matters — it **rethrows** anything
 * that is not a `PkiError`. A target that swallowed every exception would
 * run for a week in the container and find nothing, and no coverage report
 * would say so.
 *
 * The targets resolve `pkinative` by the package's own name; vitest's alias
 * points that at `src/`, the container's self-reference points it at
 * `dist/`. Same file, two engines.
 */

type Target = { readonly fuzz: (data: Uint8Array) => void };

const TARGETS = readdirSync('fuzz').filter((f) => f.endsWith('.js')).sort();

/** Certificates, an OID, PEM text, and bytes that are none of those. */
function corpus(): Uint8Array[] {
    const seeds: Uint8Array[] = [
        sequence(
            universal(2, [0x01, 0x00, 0x01]),
            sequence(universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), universal(5, [])),
            tlv(1, true, 0, universal(12, ascii('example'))),
        ),
        universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]),
        new TextEncoder().encode('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'),
        concat([0x30, 0x80], universal(5, []), [0x00, 0x00]),
        new Uint8Array(0),
    ];
    for (const file of readdirSync('tests/fixtures/certs').filter((f) => f.endsWith('.der')).slice(0, 2)) {
        seeds.push(new Uint8Array(readFileSync(`tests/fixtures/certs/${file}`)));
    }
    return seeds;
}

describe('fuzz targets', () => {
    it('should be the set the container builds', () => {
        // build.sh names each target; a file added here and not there is a
        // target that never runs, which is worse than no target at all.
        expect(TARGETS).toEqual(['asn1.js', 'pem.js', 'x509.js']);
        const build = readFileSync('.clusterfuzzlite/build.sh', 'utf8');
        for (const target of TARGETS) expect(build, `build.sh does not name ${target}`).toContain(target);
    });

    it.each(TARGETS)('%s should survive the seeded corpus, truncated and mutated', async (file) => {
        const { fuzz } = await import(/* @vite-ignore */ `../../fuzz/${file}`) as Target;
        expect(typeof fuzz, `${file} exports no fuzz function`).toBe('function');

        const rand = createPrng(0x5ee_d100);
        for (const seed of corpus()) {
            fuzz(seed);
            for (let cut = 0; cut < seed.length; cut++) fuzz(seed.subarray(0, cut));
            for (let i = 0; i < 64; i++) {
                const mutated = Uint8Array.from(seed);
                if (mutated.length > 0) mutated[rand.int(mutated.length)] = rand.int(256);
                fuzz(mutated);
            }
        }
        for (let i = 0; i < 512; i++) {
            fuzz(Uint8Array.from({ length: rand.int(48) }, () => rand.int(256)));
        }
    });

    it.each(TARGETS)('%s should rethrow what is not a PkiError, or it finds nothing', async (file) => {
        // The one assertion that keeps a target honest, and it cannot be made
        // with real input: the library is supposed never to throw anything
        // else, so the only way to prove the target would surface it is to
        // make the library misbehave on purpose. A target whose catch had
        // been widened to `catch {}` would fuzz for a week, crash on nothing
        // and report success — and no coverage number would say so.
        vi.resetModules();
        vi.doMock('pkinative', async () => {
            const actual = await vi.importActual<Record<string, unknown>>('pkinative');
            const boom = (): never => { throw new TypeError('planted: not a PkiError'); };
            return { ...actual, decodeAsn1: boom, parseCertificate: boom, decodePem: boom, decodeOid: boom };
        });
        try {
            const { fuzz } = await import(/* @vite-ignore */ `../../fuzz/${file}`) as Target;
            expect(() => { fuzz(Uint8Array.of(0x30, 0x00)); }).toThrow('planted: not a PkiError');
        } finally {
            vi.doUnmock('pkinative');
            vi.resetModules();
        }
    });
});
