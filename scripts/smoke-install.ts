#!/usr/bin/env tsx
/**
 * pkinative — install smoke test (`npm run smoke:install`)
 * ========================================================
 * Installs the packed tarball into an empty project, exactly as a user
 * would, and loads it both ways: `import` (ESM) and `require` (CJS) must
 * each expose every runtime export of docs/assets/api.json and parse a real
 * certificate. attw and publint check the package's shape; this checks that
 * it installs and runs. It exists because the 0.1.0 release audit found a
 * documented install command that produced a package with no code in it
 * (dist/ is git-ignored, so a git install carries none): the tarball is what
 * a release ships, and this is the proof that it works.
 *
 * Usage:
 *   npm run build && npm run smoke:install
 *   npx tsx scripts/smoke-install.ts pkinative-0.1.0.tgz   # an existing tarball
 *
 * Exit: 0 installed and loaded both ways; 1 otherwise.
 *
 * @module scripts/smoke-install
 */

import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function npm(args: readonly string[], cwd: string): SpawnSyncReturns<string> {
    const cli = process.env['npm_execpath'];
    return cli !== undefined && cli.endsWith('.js')
        ? spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', windowsHide: true })
        : spawnSync('npm', [...args], { cwd, encoding: 'utf8', windowsHide: true, shell: process.platform === 'win32' });
}

function main(): number {
    const work = mkdtempSync(join(tmpdir(), 'pkinative-smoke-'));
    try {
        let tarball = process.argv[2] === undefined ? undefined : resolve(process.argv[2]);
        if (tarball === undefined) {
            if (!existsSync(join(ROOT, 'dist', 'index.js'))) {
                console.error('smoke-install: dist/ is missing — run `npm run build` first');
                return 1;
            }
            const pack = npm(['pack', '--pack-destination', work, '--silent'], ROOT);
            if (pack.status !== 0) {
                console.error(`smoke-install: npm pack failed\n${pack.stderr}`);
                return 1;
            }
            tarball = join(work, readdirSync(work).find((f) => f.endsWith('.tgz')) ?? '');
        }
        const project = join(work, 'project');
        mkdirSync(project);
        writeFileSync(join(project, 'package.json'), '{ "name": "smoke", "private": true, "type": "module" }\n');
        const install = npm(['install', tarball, '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock'], project);
        if (install.status !== 0) {
            console.error(`smoke-install: npm install of the tarball failed\n${install.stderr}`);
            return 1;
        }

        const api = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'api.json'), 'utf8')) as { exports: Array<{ name: string; kind: string }> };
        const values = api.exports.filter((e) => e.kind !== 'type').map((e) => e.name).sort();
        const fixture = join(ROOT, 'tests', 'fixtures', 'certs', 'isrg-root-x1.der').replace(/\\/g, '/');
        const probe = (load: string): string => `${load}
const names = Object.keys(m).sort();
const cert = m.parseCertificate(new Uint8Array(require('fs').readFileSync(${JSON.stringify(fixture)})));
console.log(JSON.stringify({ names, subject: m.formatDistinguishedName(cert.subject) }));`;
        const runs: Array<[string, SpawnSyncReturns<string>]> = [
            ['ESM import', spawnSync(process.execPath, ['--input-type=module', '-e', probe("import { createRequire } from 'node:module'; const require = createRequire(import.meta.url); const m = await import('pkinative');")], { cwd: project, encoding: 'utf8' })],
            ['CJS require', spawnSync(process.execPath, ['-e', probe("const m = require('pkinative');")], { cwd: project, encoding: 'utf8' })],
        ];
        let failures = 0;
        for (const [label, run] of runs) {
            if (run.status !== 0) {
                console.error(`✗ ${label}: ${run.stderr.split('\n').find((l) => l.includes('Error')) ?? run.stderr.trim()}`);
                failures++;
                continue;
            }
            const result = JSON.parse(run.stdout) as { names: string[]; subject: string };
            const missing = values.filter((v) => !result.names.includes(v));
            if (missing.length > 0 || result.subject !== 'CN=ISRG Root X1,O=Internet Security Research Group,C=US') {
                console.error(`✗ ${label}: missing ${missing.join(', ') || 'nothing'}; subject ${result.subject}`);
                failures++;
            } else {
                console.log(`✓ ${label}: ${result.names.length} runtime exports, parsed ${result.subject}`);
            }
        }
        console.log(failures === 0 ? `smoke-install: ${tarball.split(/[\\/]/).pop() ?? ''} installs and loads as ESM and CJS.` : 'smoke-install: the packed package does not load.');
        return failures === 0 ? 0 : 1;
    } finally {
        rmSync(work, { recursive: true, force: true });
    }
}

process.exitCode = main();
