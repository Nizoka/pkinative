/**
 * pkinative — the published file list
 * ===================================
 * THE rules for what `npm pack` may put in the tarball, shared by
 * scripts/package-files.ts (which runs `npm pack --dry-run --json` inside the
 * `check:package` gate step and compares its list with the committed
 * `docs/data/package-files.json`) and by the hermetic `package-files-parity`
 * rule of verify-docs (which holds that manifest to package.json `files`, to
 * the byte budgets of `declared.bundle` and to the legal texts on disk).
 *
 * What is pinned per file, and why nothing more:
 *   - `path` and `executable` — a file added, removed or made executable is a
 *     reviewed diff;
 *   - `role` — derived from the path, so the manifest says why a file ships;
 *   - `sha256` for the `legal` role only. LICENSE and THIRD-PARTY-NOTICES.md
 *     are what a downstream redistributes verbatim, and a change to either is
 *     a decision. The generated code is held by the byte budgets and
 *     bundle-check, the documents by verify-docs, and package.json changes on
 *     every version bump and every Dependabot devDependency bump: pinning
 *     their bytes would turn each of those into a manifest regeneration and
 *     prove nothing the other checks do not.
 *
 * @module scripts/lib/package-files
 */

import { createHash } from 'node:crypto';

export const PACKAGE_FILES_MANIFEST = 'docs/data/package-files.json';
export const PACKAGE_FILES_COMMAND = 'npx tsx scripts/package-files.ts --update';

export type PackageFileRole = 'build' | 'legal' | 'doc' | 'manifest';

export interface PackageFile {
    readonly path: string;
    /**
     * Whether npm packs it with an executable bit. The bit, not the mode: a
     * checkout under umask 002 packs 0664 where CI packs 0644, and group
     * write says nothing about what a consumer installs.
     */
    readonly executable: boolean;
    readonly role: PackageFileRole;
    /** SHA-256 of the file's bytes, for the `legal` role only. */
    readonly sha256?: string;
}

export interface PackageFilesManifest {
    readonly $comment?: string;
    readonly generatedBy?: string;
    readonly files: readonly PackageFile[];
}

/** The files whose bytes are pinned: the texts a redistributor ships verbatim. */
export const LEGAL_FILES: readonly string[] = ['LICENSE', 'THIRD-PARTY-NOTICES.md'];

/**
 * Files npm puts in every tarball whatever `files` says. A manifest entry
 * outside `files` must be one of these.
 */
export const ALWAYS_PACKED: readonly string[] = ['package.json', 'README.md', 'LICENSE'];

/**
 * Never in the tarball, whatever the manifest says — defence in depth, so that
 * regenerating the manifest cannot bless a leak. Each pattern names what it
 * stops.
 */
export const FORBIDDEN: ReadonlyArray<{ readonly pattern: RegExp; readonly why: string }> = [
    { pattern: /^(src|tests?|scripts|bench|recipes|docs|examples|fuzz)\//, why: 'a source, test or tooling directory' },
    { pattern: /(^|\/)\./, why: 'a dotfile (.env, .npmrc, .github, an editor config)' },
    { pattern: /(^|\/)(node_modules|coverage|test-output|fixtures|corpora)\//, why: 'a dependency, report or fixture directory' },
    { pattern: /\.(der|pem|crt|cer|p7b|p7c|p12|pfx|key|p8|csr|crl|tgz|zip|log)$/i, why: 'key material, a certificate, an archive or a log' },
    { pattern: /\.(test|spec|bench)\.[cm]?[jt]s$/, why: 'a test or benchmark file' },
    { pattern: /\.tsbuildinfo$/, why: 'a TypeScript build cache' },
];

/** The role a path ships in, derived and never hand-written. */
export function roleOf(path: string): PackageFileRole {
    if (path.startsWith('dist/')) return 'build';
    if (LEGAL_FILES.includes(path)) return 'legal';
    if (path === 'package.json') return 'manifest';
    return 'doc';
}

export function sha256(bytes: Uint8Array | string): string {
    return createHash('sha256').update(bytes).digest('hex');
}

/** Why a path may never ship, or null. */
export function forbiddenReason(path: string): string | null {
    return FORBIDDEN.find((f) => f.pattern.test(path))?.why ?? null;
}

/**
 * The manifest entries for a packed file list, sorted by path; `readBytes`
 * supplies the bytes of each legal file.
 */
export function manifestEntries(
    packed: ReadonlyArray<{ readonly path: string; readonly mode: number }>,
    readBytes: (path: string) => Uint8Array | string | null,
): PackageFile[] {
    return [...packed]
        .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
        .map(({ path, mode }) => {
            const executable = (mode & 0o111) !== 0;
            const role = roleOf(path);
            if (role !== 'legal') return { path, executable, role };
            const bytes = readBytes(path);
            return bytes === null ? { path, executable, role } : { path, executable, role, sha256: sha256(bytes) };
        });
}

/**
 * Every rule a file list must satisfy on its own, whichever side it comes
 * from: no forbidden path, every `dist/` file budgeted and every budget
 * shipped, every other file declared by package.json `files` (or packed by npm
 * unconditionally), every `files` entry shipping something.
 */
export function listFindings(
    paths: readonly string[],
    packageJsonFiles: readonly string[],
    budgeted: readonly string[],
): string[] {
    const out: string[] = [];
    for (const path of paths) {
        const why = forbiddenReason(path);
        if (why !== null) out.push(`${path} must never ship (${why})`);
    }
    const dist = paths.filter((p) => p.startsWith('dist/'));
    for (const path of dist) {
        if (!budgeted.includes(path)) out.push(`${path} ships without a byte budget in docs/assets/ecosystem.json declared.bundle`);
    }
    for (const path of budgeted) {
        if (!dist.includes(path)) out.push(`declared.bundle budgets ${path}, which does not ship`);
    }
    const declared = (p: string): boolean => packageJsonFiles.some((f) => p === f || p.startsWith(`${f.replace(/\/+$/, '')}/`));
    for (const path of paths) {
        if (!declared(path) && !ALWAYS_PACKED.includes(path)) out.push(`${path} ships but package.json "files" does not declare it`);
    }
    for (const entry of packageJsonFiles) {
        if (!paths.some((p) => p === entry || p.startsWith(`${entry.replace(/\/+$/, '')}/`))) {
            out.push(`package.json "files" declares ${entry}, which ships nothing`);
        }
    }
    return out;
}

/** The differences between the pinned list and the packed one, one line each. */
export function compareEntries(pinned: readonly PackageFile[], actual: readonly PackageFile[]): string[] {
    const out: string[] = [];
    const byPath = new Map(pinned.map((f) => [f.path, f]));
    const actualPaths = new Set(actual.map((f) => f.path));
    for (const file of actual) {
        const pin = byPath.get(file.path);
        if (pin === undefined) {
            out.push(`added: ${file.path}`);
            continue;
        }
        if (pin.executable !== file.executable) out.push(`executable bit ${file.executable ? 'set' : 'cleared'}: ${file.path}`);
        if (pin.role !== file.role) out.push(`role changed: ${file.path} ${pin.role} → ${file.role}`);
        if (pin.sha256 !== file.sha256) out.push(`content changed: ${file.path} sha256 ${pin.sha256 ?? 'none'} → ${file.sha256 ?? 'none'}`);
    }
    for (const pin of pinned) {
        if (!actualPaths.has(pin.path)) out.push(`removed: ${pin.path}`);
    }
    return out;
}

/** The manifest's own consistency: sorted, unique, each role derived, a hash exactly on the legal files. */
export function manifestShapeFindings(files: readonly PackageFile[]): string[] {
    const out: string[] = [];
    const paths = files.map((f) => f.path);
    if (new Set(paths).size !== paths.length) out.push('a path is listed twice');
    if (paths.some((p, i) => i > 0 && (paths[i - 1] ?? '') >= p)) out.push('the files are not sorted by path');
    for (const f of files) {
        if (typeof f.path !== 'string' || typeof f.executable !== 'boolean') out.push(`an entry lacks a string path or a boolean executable: ${JSON.stringify(f)}`);
        else if (f.role !== roleOf(f.path)) out.push(`${f.path} has role ${String(f.role)}, derived role is ${roleOf(f.path)}`);
        else if ((f.role === 'legal') !== (typeof f.sha256 === 'string' && /^[0-9a-f]{64}$/.test(f.sha256))) {
            out.push(`${f.path}: a sha256 is pinned for the legal files and for them only`);
        }
    }
    return out;
}
