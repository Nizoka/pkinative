#!/usr/bin/env tsx
/**
 * pkinative — TypeScript consumer floor check
 * ===========================================
 * ADR 0017 promises that TypeScript from the floor in `docs/assets/ecosystem.json`
 * → `contracts.support.typescript` compiles the published declaration file,
 * under every `moduleResolution` a consumer may use. This packs the build,
 * installs it next to exactly that TypeScript release in an empty project,
 * and compiles a consumer that imports every export of docs/assets/api.json
 * with `skipLibCheck: false` — so the whole of `dist/index.d.ts` and
 * `dist/index.d.cts` is type-checked by the floor compiler — four ways:
 *
 *   - `node16`  — Node's ESM resolution, the `import` condition;
 *   - `bundler` — the resolution of Vite, esbuild and webpack (TypeScript 5.0+);
 *   - `node10`  — CommonJS resolution, the `require` condition;
 *   - `nodom`   — `node16` with the ES2020 library only, no DOM types, and
 *                 `exactOptionalPropertyTypes`: the declarations name no host
 *                 type the caller's program may not have.
 *
 * It needs the npm registry to install the compiler, so it is not part of the
 * hermetic gate profiles; ADR 0017 places it in the publish profile.
 *
 * Usage:
 *   npm run build && npx tsx scripts/check-ts-floor.ts
 *   npx tsx scripts/check-ts-floor.ts --typescript 5.4.5   # another release
 *
 * Exit: 0 every configuration compiled; 1 otherwise; 2 bad usage.
 *
 * @module scripts/check-ts-floor
 */

import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** One compiler configuration of the consumer, by name. */
export interface FloorConfig {
    readonly name: string;
    readonly compilerOptions: Readonly<Record<string, unknown>>;
}

/** The four ways a consumer resolves and compiles pkinative (ADR 0017). */
export const FLOOR_CONFIGS: readonly FloorConfig[] = [
    { name: 'node16', compilerOptions: { module: 'node16', moduleResolution: 'node16', lib: ['es2020', 'dom'] } },
    { name: 'bundler', compilerOptions: { module: 'esnext', moduleResolution: 'bundler', lib: ['es2020', 'dom'] } },
    { name: 'node10', compilerOptions: { module: 'commonjs', moduleResolution: 'node', lib: ['es2020', 'dom'] } },
    { name: 'nodom', compilerOptions: { module: 'node16', moduleResolution: 'node16', lib: ['es2020'], types: [], exactOptionalPropertyTypes: true } },
];

/**
 * The consumer: every type and every value of the export surface, imported
 * by name, so that a declaration the floor compiler cannot read fails here.
 */
export function consumerSource(exports: ReadonlyArray<{ readonly name: string; readonly kind: string }>): string {
    const types = exports.filter((e) => e.kind === 'type').map((e) => e.name).sort();
    const values = exports.filter((e) => e.kind !== 'type').map((e) => e.name).sort();
    return [
        `import type { ${types.join(', ')} } from 'pkinative';`,
        `import { ${values.join(', ')} } from 'pkinative';`,
        `export type Everything = [${types.join(', ')}];`,
        `export const everything = [${values.join(', ')}] as const;`,
        '',
    ].join('\n');
}

/** The floor named in the manifest, or the one passed with `--typescript`. */
export function floorVersion(argv: readonly string[], manifest: { readonly contracts?: { readonly support?: { readonly typescript?: unknown } } }): string | null {
    const at = argv.indexOf('--typescript');
    const chosen = at >= 0 ? argv[at + 1] : manifest.contracts?.support?.typescript;
    return typeof chosen === 'string' && /^\d+\.\d+\.\d+$/.test(chosen) ? chosen : null;
}

function npm(args: readonly string[], cwd: string): SpawnSyncReturns<string> {
    const cli = process.env['npm_execpath'];
    return cli !== undefined && cli.endsWith('.js')
        ? spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', windowsHide: true })
        : spawnSync('npm', [...args], { cwd, encoding: 'utf8', windowsHide: true, shell: process.platform === 'win32' });
}

function main(): number {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'ecosystem.json'), 'utf8')) as Parameters<typeof floorVersion>[1];
    const version = floorVersion(process.argv.slice(2), manifest);
    if (version === null) {
        console.error('check-ts-floor: no TypeScript floor — set contracts.support.typescript in docs/assets/ecosystem.json, or pass --typescript X.Y.Z');
        return 2;
    }
    if (!existsSync(join(ROOT, 'dist', 'index.d.ts'))) {
        console.error('check-ts-floor: dist/ is missing — run `npm run build` first');
        return 1;
    }
    const work = mkdtempSync(join(tmpdir(), 'pkinative-ts-floor-'));
    try {
        const pack = npm(['pack', '--pack-destination', work, '--silent'], ROOT);
        if (pack.status !== 0) {
            console.error(`check-ts-floor: npm pack failed\n${pack.stderr}`);
            return 1;
        }
        const tarball = join(work, readdirSync(work).find((f) => f.endsWith('.tgz')) ?? '');
        const project = join(work, 'project');
        mkdirSync(project);
        writeFileSync(join(project, 'package.json'), '{ "name": "ts-floor", "private": true, "type": "module" }\n');
        const install = npm(['install', tarball, `typescript@${version}`, '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock'], project);
        if (install.status !== 0) {
            console.error(`check-ts-floor: npm install failed\n${install.stderr}`);
            return 1;
        }
        const api = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'api.json'), 'utf8')) as { exports: Array<{ name: string; kind: string }> };
        writeFileSync(join(project, 'consumer.ts'), consumerSource(api.exports));
        const tsc = join(project, 'node_modules', 'typescript', 'bin', 'tsc');
        let failures = 0;
        for (const config of FLOOR_CONFIGS) {
            const file = `tsconfig.${config.name}.json`;
            const options = { strict: true, target: 'es2020', noEmit: true, skipLibCheck: false, ...config.compilerOptions };
            writeFileSync(join(project, file), `${JSON.stringify({ compilerOptions: options, files: ['consumer.ts'] }, null, 2)}\n`);
            const run = spawnSync(process.execPath, [tsc, '-p', file], { cwd: project, encoding: 'utf8', windowsHide: true });
            if (run.status === 0) {
                console.log(`✓ TypeScript ${version}, ${config.name}`);
            } else {
                failures++;
                console.error(`✗ TypeScript ${version}, ${config.name}\n${(run.stdout + run.stderr).trim().split('\n').slice(0, 10).join('\n')}`);
            }
        }
        console.log(failures === 0
            ? `check-ts-floor: TypeScript ${version} compiles the declarations under ${String(FLOOR_CONFIGS.length)} configurations.`
            : `check-ts-floor: TypeScript ${version} fails ${String(failures)} of ${String(FLOOR_CONFIGS.length)} configurations — the floor ADR 0017 promises does not hold.`);
        return failures === 0 ? 0 : 1;
    } finally {
        rmSync(work, { recursive: true, force: true });
    }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
