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
 * Online by nature (it needs the published CLI), so never a gate step: run it
 * when the manifest's pkinative-cli version moves.
 *
 * @module scripts/build-cli-surface
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLI_SURFACE = 'docs/data/cli-surface.json';

interface Flag { readonly name: string; readonly alias?: string; readonly value?: string; readonly repeatable?: boolean }
interface Operands { readonly max?: number; readonly for?: readonly string[] }
interface Invocation { readonly name: string; readonly summary: string; readonly flags?: readonly Flag[]; readonly operands?: Operands }
interface Command extends Invocation { readonly group: string; readonly subcommands?: readonly Invocation[] }
interface CliManifest {
    readonly name: string;
    readonly version: string;
    readonly pkinative: string;
    readonly offline: boolean;
    readonly wire: Record<string, string>;
    readonly exitCodes: Record<string, string>;
    readonly errorCodes: ReadonlyArray<{ readonly code: string; readonly meaning: string }>;
    readonly globalFlags: readonly Flag[];
    readonly commands: readonly Command[];
}

const flagOf = (f: Flag): Flag => ({ name: f.name, ...(f.alias === undefined ? {} : { alias: f.alias }), ...(f.value === undefined ? {} : { value: f.value }), ...(f.repeatable === true ? { repeatable: true } : {}) });
const invocationOf = (i: Invocation): Invocation => ({ name: i.name, summary: i.summary, flags: (i.flags ?? []).map(flagOf), ...(i.operands === undefined ? {} : { operands: i.operands }) });

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
        commands: manifest.commands.map((c) => ({
            name: c.name,
            group: c.group,
            summary: c.summary,
            ...((c.subcommands ?? []).length === 0
                ? { flags: (c.flags ?? []).map(flagOf), ...(c.operands === undefined ? {} : { operands: c.operands }) }
                : { subcommands: (c.subcommands ?? []).map(invocationOf) }),
        })),
    };
    return `${JSON.stringify(surface, null, 2)}\n`;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const from = process.argv[process.argv.indexOf('--from') + 1];
    if (!process.argv.includes('--from') || from === undefined) {
        console.error('usage: npm run docs:cli-surface -- --from <file written by `npx -y pkinative-cli@<version> schema manifest`>');
        process.exit(2);
    }
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    const text = renderCliSurface(JSON.parse(readFileSync(from, 'utf8')) as CliManifest);
    writeFileSync(join(root, CLI_SURFACE), text);
    console.error(`build-cli-surface: ${CLI_SURFACE} written`);
}
