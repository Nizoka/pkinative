import { readFileSync, readdirSync } from 'node:fs';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import * as pkinative from '../../src/index.js';
import { createPrng } from '../helpers/prng.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';
import { type FuzzTarget, fuzzSeeds } from './_fuzz-seeds.js';

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
 * `dist/`. Same file, two engines. The seeds are the ones the container
 * zips (`tests/fuzzing/_fuzz-seeds.ts`), so a seed that stopped parsing
 * fails here before it starts a fuzzer outside the grammar.
 */

type Target = { readonly fuzz: (data: Uint8Array) => void };

const TARGETS = readdirSync('fuzz').filter((f) => f.endsWith('.js')).sort();
const EXPECTED: readonly FuzzTarget[] = ['asn1', 'cms', 'crl', 'ocsp', 'pem', 'pkcs12', 'tsp', 'x509'];

/** Certificates' building blocks, an OID, PEM text, and bytes that are none of those — shared by every target. */
function sharedCorpus(): Uint8Array[] {
    return [
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
}

const quiet = { onDiagnostic: (): undefined => undefined };

/** What each target's seeds must be: input its first parser reads without refusing. */
const READS: Readonly<Record<FuzzTarget, (seed: Uint8Array) => unknown>> = {
    asn1: (s) => pkinative.decodeAsn1(s, { encodingRules: 'ber' }),
    x509: (s) => pkinative.parseCertificate(s, quiet),
    pem: (s) => pkinative.decodePem(new TextDecoder().decode(s), quiet),
    cms: (s) => pkinative.parseSignedData(s, quiet),
    crl: (s) => pkinative.parseCertificateList(s, quiet),
    ocsp: (s) => pkinative.parseOcspResponse(s, quiet),
    tsp: (s) => {
        // The three nested readers, each on the layer it reads.
        for (const parse of [pkinative.parseTimeStampResponse, pkinative.parseTimeStampToken, pkinative.parseTstInfo]) {
            try { return parse(s, quiet); } catch { /* the next layer */ }
        }
        throw new Error('no timestamp reader accepts this seed');
    },
    pkcs12: (s) => {
        for (const parse of [pkinative.parsePkcs12, pkinative.parsePrivateKeyInfo, pkinative.parseEncryptedPrivateKeyInfo]) {
            try { return parse(s, quiet); } catch { /* the next container */ }
        }
        throw new Error('no PKCS#12 or PKCS#8 reader accepts this seed');
    },
};

let SEEDS: Readonly<Record<FuzzTarget, readonly Uint8Array[]>>;
beforeAll(async () => { SEEDS = await fuzzSeeds(); });

const nameOf = (file: string): FuzzTarget => file.replace(/\.js$/, '') as FuzzTarget;

describe('fuzz targets', () => {
    it('should be the set the container builds and seeds', () => {
        // build.sh names each target; a file added here and not there is a
        // target that never runs, which is worse than no target at all.
        expect(TARGETS).toEqual(EXPECTED.map((t) => `${t}.js`));
        const build = readFileSync('.clusterfuzzlite/build.sh', 'utf8');
        for (const target of TARGETS) {
            expect(build, `build.sh does not compile ${target}`).toContain(`compile_javascript_fuzzer pkinative fuzz/${target} --sync`);
        }
        expect(build, 'build.sh does not loop over every target when zipping seeds').toContain(`for target in ${EXPECTED.join(' ')}; do`);
        expect(build).toContain('npx tsx tests/fuzzing/_fuzz-seeds.ts');
    });

    it('should pin the engine to one version and every package of its tree to an integrity hash', () => {
        // An unpinned `npm install @jazzer.js/core` resolves whatever the
        // registry serves on the day of the build — a supply-chain input the
        // project's own lockfile discipline exists to refuse.
        const manifest = JSON.parse(readFileSync('.clusterfuzzlite/engine/package.json', 'utf8')) as { dependencies: Record<string, string> };
        expect(Object.keys(manifest.dependencies)).toEqual(['@jazzer.js/core']);
        const version = manifest.dependencies['@jazzer.js/core'] ?? '';
        expect(version, 'an exact version, not a range').toMatch(/^\d+\.\d+\.\d+$/);

        const lock = JSON.parse(readFileSync('.clusterfuzzlite/engine/package-lock.json', 'utf8')) as {
            lockfileVersion: number;
            packages: Record<string, { version?: string; integrity?: string; resolved?: string }>;
        };
        expect(lock.lockfileVersion).toBe(3);
        expect(lock.packages['node_modules/@jazzer.js/core']?.version).toBe(version);
        const installed = Object.entries(lock.packages).filter(([path]) => path !== '');
        expect(installed.length).toBeGreaterThan(1);
        for (const [path, entry] of installed) {
            expect(entry.integrity, `${path} has no sha512 integrity`).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);
            expect(entry.resolved, `${path} resolves outside the npm registry`).toMatch(/^https:\/\/registry\.npmjs\.org\//);
        }

        const build = readFileSync('.clusterfuzzlite/build.sh', 'utf8');
        const commands = build.split('\n').filter((line) => !line.trimStart().startsWith('#'));
        expect(commands.filter((line) => /\bnpm (install|i|add)\b/.test(line)), 'build.sh installs outside a lockfile').toEqual([]);
        expect(commands.join('\n')).toContain('(cd .clusterfuzzlite/engine && npm ci --ignore-scripts)');
        expect(readFileSync('.clusterfuzzlite/engine/.npmrc', 'utf8')).toContain('ignore-scripts=true');
    });

    it.each(EXPECTED)('the %s seeds should be read by the target\'s parser, so the fuzzer starts inside the grammar', (target) => {
        expect(SEEDS[target].length).toBeGreaterThan(0);
        for (const seed of SEEDS[target]) expect(() => READS[target](seed)).not.toThrow();
    });

    it.each(TARGETS)('%s should survive the seeded corpus, truncated and mutated', async (file) => {
        const { fuzz } = await import(/* @vite-ignore */ `../../fuzz/${file}`) as Target;
        expect(typeof fuzz, `${file} exports no fuzz function`).toBe('function');

        const rand = createPrng(0x5ee_d100);
        for (const seed of [...sharedCorpus(), ...SEEDS[nameOf(file)].slice(0, 3)]) {
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
        //
        // Every function export is planted, not a list of names: a target
        // that starts calling a new parser is covered without an edit here.
        vi.resetModules();
        vi.doMock('pkinative', async () => {
            const actual = await vi.importActual<Record<string, unknown>>('pkinative');
            const boom = (): never => { throw new TypeError('planted: not a PkiError'); };
            return Object.fromEntries(Object.entries(actual).map(([name, value]) =>
                [name, typeof value === 'function' && /^[a-z]/.test(name) ? boom : value]));
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
