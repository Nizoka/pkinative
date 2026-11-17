/**
 * pkinative — the CLI surface snapshot (`npm run docs:cli-surface -- --from <manifest.json>`)
 * ===========================================================================================
 * Writes `docs/data/cli-surface.json`, the command surface of the published
 * pkinative-cli, from the capability manifest that CLI prints itself:
 *
 *   npx -y pkinative-cli@<version> schema manifest > manifest.json
 *   npm run docs:cli-surface -- --from manifest.json
 *
 * The snapshot keeps what a reader of this site needs — the wire form, the
 * exit codes, the error classes, the global flags and every command with its
 * subcommands, flags and operands — and drops the per-command JSON Schemas
 * the CLI serves on demand (`pkinative schema report <command>`). It is a
 * projection, never an edit: the CLI is the authority, and `cli-surface-parity`
 * holds the CLI guide and the command builder to this file, and this file to
 * `packages.pkinative-cli` of docs/assets/ecosystem.json.
 *
 * `--from` also takes a satellite surface (`docs/assets/surface.json` of a
 * pkinative-cli checkout, .claude/skills/satellite-align/surface-contract.md):
 * its `structured` half is the same projection. `scripts/satellite-sync.ts
 * --apply` calls `renderCliSurface` itself; this script stays as the manual
 * path.
 *
 * Online by nature (it needs the published CLI), so never a gate step: run it
 * when the manifest's pkinative-cli version moves.
 *
 * @module scripts/build-cli-surface
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cliManifestOf, commandOf, flagOf, normaliseSurface, type CliManifest } from './lib/satellite-surface.js';

export const CLI_SURFACE = 'docs/data/cli-surface.json';

/** The snapshot for one manifest, as the file's text. */
export function renderCliSurface(manifest: CliManifest): string {
    if (manifest.name !== 'pkinative-cli') throw new Error(`build-cli-surface: the manifest is ${manifest.name}'s, not pkinative-cli's`);
    const surface = {
        $comment: `The command surface of pkinative-cli ${manifest.version}, projected from its own capability manifest (\`pkinative schema manifest\`) by scripts/build-cli-surface.ts — never hand-edited. The per-command report and summary JSON Schemas are left out: \`pkinative schema report <command> [<sub>]\` serves them. cli-surface-parity holds the CLI guide and the command builder to this file.`,
        schemaVersion: 1,
        package: manifest.name,
        version: manifest.version,
        binary: 'pkinative',
        pkinative: manifest.pkinative,
        offline: manifest.offline,
        wire: manifest.wire,
        exitCodes: manifest.exitCodes,
        errorClasses: manifest.errorCodes.map(({ code, meaning }) => ({ code, meaning })),
        globalFlags: manifest.globalFlags.map(flagOf),
        commands: manifest.commands.map(commandOf),
    };
    return `${JSON.stringify(surface, null, 2)}\n`;
}

/** The capability manifest of a `--from` file: the manifest itself, or the one a satellite surface carries. */
export function manifestOf(parsed: unknown): CliManifest {
    if ((parsed as { kind?: unknown } | null)?.kind !== 'satellite-surface') return parsed as CliManifest;
    const manifest = cliManifestOf(normaliseSurface(parsed, 'pkinative-cli'));
    if (manifest === null) throw new Error('build-cli-surface: the surface carries no structured.commands, errorClasses and globalFlags to project');
    return manifest;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const from = process.argv[process.argv.indexOf('--from') + 1];
    if (!process.argv.includes('--from') || from === undefined) {
        console.error('usage: npm run docs:cli-surface -- --from <file written by `npx -y pkinative-cli@<version> schema manifest`, or a pkinative-cli docs/assets/surface.json>');
        process.exit(2);
    }
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    // A capture redirected from PowerShell starts with a byte-order mark.
    const text = renderCliSurface(manifestOf(JSON.parse(readFileSync(from, 'utf8').replace(/^﻿/, '')) as unknown));
    writeFileSync(join(root, CLI_SURFACE), text);
    console.error(`build-cli-surface: ${CLI_SURFACE} written`);
}
