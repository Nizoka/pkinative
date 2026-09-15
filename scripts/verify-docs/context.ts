/**
 * pkinative — verify-docs rule context
 * =====================================
 * Every rule reads the repository through a `RuleContext`, never through
 * `node:fs` directly. The engine hands the rules a filesystem context; the
 * test suite hands them an in-memory copy of the same tree with one
 * perturbation applied, and asserts that the rule notices. A rule that
 * silently matches nothing looks identical to a rule that passes — the
 * perturbation table in tests/docs/verify-docs.test.ts is what tells them
 * apart.
 *
 * @module scripts/verify-docs/context
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '../lib/agent-config.js';

export type { Finding };

export interface RuleContext {
    readonly root: string;
    /** Whether the rules may reach the network (`--online`). */
    readonly online: boolean;
    /** File text by repository-relative POSIX path, or null when absent. */
    read(path: string): string | null;
    /** True for an existing file or directory. */
    exists(path: string): boolean;
    /** Every file under a directory (`''` for the whole tree), repository-relative, sorted. */
    list(dir: string): readonly string[];
    /** `git <args>` stdout, or null when git is unavailable or fails. */
    git(args: readonly string[]): string | null;
    /** `node --check <path>` outcome. */
    nodeCheck(path: string): { readonly status: number | null; readonly stderr: string };
}

export interface Rule {
    readonly id: string;
    /** One sentence: what the rule proves. */
    readonly summary: string;
    check(ctx: RuleContext): readonly Finding[] | Promise<readonly Finding[]>;
}

/** Directories no rule ever reads: dependencies, VCS data, build and test outputs. */
export const SKIPPED_DIRS: ReadonlySet<string> = new Set(['node_modules', '.git', 'dist', 'coverage', 'test-output']);

/** Extensions loaded as bytes, never as text. */
const BINARY_EXTENSIONS = /\.(png|ico|jpg|jpeg|gif|webp|der|cer|crt|p7b|p7c|p12|pfx|zip|gz|tgz|woff2?)$/i;

export function error(file: string, message: string, line = 1): Finding {
    return { severity: 'error', file, line, message };
}

export function warning(file: string, message: string, line = 1): Finding {
    return { severity: 'warn', file, line, message };
}

/** Line number (1-based) of a character offset. */
export function lineOf(text: string, index: number): number {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i++) {
        if (text.charCodeAt(i) === 10) line++;
    }
    return line;
}

/** 1-based line of the first line containing `needle`, or 1. */
export function lineContaining(text: string, needle: string): number {
    const at = text.indexOf(needle);
    return at < 0 ? 1 : lineOf(text, at);
}

function walk(root: string, rel: string, out: string[]): void {
    const full = rel === '' ? root : join(root, rel);
    if (!existsSync(full)) return;
    for (const entry of readdirSync(full)) {
        if (SKIPPED_DIRS.has(entry)) continue;
        const child = rel === '' ? entry : `${rel}/${entry}`;
        if (statSync(join(root, child)).isDirectory()) walk(root, child, out);
        else out.push(child);
    }
}

export function createFsContext(root: string, online = false): RuleContext {
    const listCache = new Map<string, readonly string[]>();
    return {
        root,
        online,
        read(path) {
            const full = join(root, path);
            return existsSync(full) && statSync(full).isFile() ? readFileSync(full, 'utf8') : null;
        },
        exists(path) {
            return existsSync(join(root, path));
        },
        list(dir) {
            const key = dir.replace(/\/+$/, '');
            const cached = listCache.get(key);
            if (cached) return cached;
            const out: string[] = [];
            walk(root, key, out);
            out.sort();
            listCache.set(key, out);
            return out;
        },
        git(args) {
            const r = spawnSync('git', [...args], { cwd: root, encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
            return r.status === 0 ? r.stdout : null;
        },
        nodeCheck(path) {
            const r = spawnSync(process.execPath, ['--check', join(root, path)], { encoding: 'utf8', windowsHide: true });
            return { status: r.status, stderr: r.stderr };
        },
    };
}

/** Every text file of the tree, `path → text`, for building a memory context. */
export function loadTextTree(root: string): Record<string, string> {
    const ctx = createFsContext(root);
    const out: Record<string, string> = {};
    for (const path of ctx.list('')) {
        if (BINARY_EXTENSIONS.test(path)) continue;
        const text = ctx.read(path);
        if (text !== null) out[path] = text;
    }
    return out;
}

/**
 * A context over an in-memory tree. `git ls-files --eol` is synthesised from
 * the contents (every file tracked, CRLF detected per file) and `node --check`
 * passes for any file that exists — enough for the rules that consult them.
 */
export function createMemoryContext(files: Readonly<Record<string, string>>, online = false): RuleContext {
    const paths = Object.keys(files).sort();
    return {
        root: '<memory>',
        online,
        read(path) {
            return Object.prototype.hasOwnProperty.call(files, path) ? files[path] : null;
        },
        exists(path) {
            const bare = path.replace(/\/+$/, '');
            return Object.prototype.hasOwnProperty.call(files, bare) || paths.some((p) => p.startsWith(`${bare}/`));
        },
        list(dir) {
            const bare = dir.replace(/\/+$/, '');
            return bare === '' ? paths : paths.filter((p) => p.startsWith(`${bare}/`));
        },
        git(args) {
            if (args[0] === 'ls-files' && args.includes('--eol')) {
                return paths
                    .map((p) => {
                        const text = files[p];
                        const eol = text.includes('\r\n') ? (/[^\r]\n/.test(text) ? 'mixed' : 'crlf') : 'lf';
                        return `i/${eol} w/${eol} attr/text=auto eol=lf \t${p}`;
                    })
                    .join('\n');
            }
            return null;
        },
        nodeCheck(path) {
            return Object.prototype.hasOwnProperty.call(files, path) ? { status: 0, stderr: '' } : { status: 1, stderr: 'not found' };
        },
    };
}

/** Parse a JSON file for a rule: the value, or the finding that explains why there is none. */
export function readJson<T>(ctx: RuleContext, path: string): { readonly value: T } | { readonly finding: Finding } {
    const text = ctx.read(path);
    if (text === null) return { finding: error(path, 'missing') };
    try {
        return { value: JSON.parse(text) as T };
    } catch (err) {
        return { finding: error(path, `not valid JSON — ${(err as Error).message}`) };
    }
}
