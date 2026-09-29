/**
 * pkinative — the published file list
 * ====================================
 * `docs/data/package-files.json` pins every file `npm pack` publishes; the
 * check:package gate step compares it with a real `npm pack --dry-run`,
 * which needs a build. This rule is the hermetic half, run on every commit:
 * the manifest against package.json `files`, against the byte budgets of
 * `declared.bundle`, and against the legal texts on disk.
 *
 * @module scripts/verify-docs/rules/package
 */

import { error, readJson, type Finding, type Rule } from '../context.js';
import {
    PACKAGE_FILES_COMMAND,
    PACKAGE_FILES_MANIFEST,
    listFindings,
    manifestShapeFindings,
    sha256,
    type PackageFilesManifest,
} from '../../lib/package-files.js';
import { MANIFEST } from './versions.js';

const packageFilesParity: Rule = {
    id: 'package-files-parity',
    summary: 'docs/data/package-files.json is sorted and derived, ships nothing forbidden, agrees with package.json "files" and with every declared.bundle budget, and pins the SHA-256 of the legal texts as they are on disk.',
    check(ctx) {
        const manifest = readJson<PackageFilesManifest>(ctx, PACKAGE_FILES_MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const pkg = readJson<{ files?: string[] }>(ctx, 'package.json');
        const eco = readJson<{ declared?: { bundle?: Record<string, unknown> } }>(ctx, MANIFEST);
        if ('finding' in pkg || 'finding' in eco) return [];
        const files = Array.isArray(manifest.value.files) ? manifest.value.files : [];
        const budgeted = Object.keys(eco.value.declared?.bundle ?? {}).filter((k) => !k.startsWith('$'));
        const out: Finding[] = [...manifestShapeFindings(files), ...listFindings(files.map((f) => f.path), pkg.value.files ?? [], budgeted)]
            .map((line) => error(PACKAGE_FILES_MANIFEST, line));
        for (const f of files) {
            if (f.sha256 === undefined) continue;
            const text = ctx.read(f.path);
            if (text === null) out.push(error(PACKAGE_FILES_MANIFEST, `${f.path} is pinned but does not exist`));
            else if (sha256(text) !== f.sha256) {
                out.push(error(f.path, `changed since ${PACKAGE_FILES_MANIFEST} pinned it — a legal text that ships is a reviewed change: run ${PACKAGE_FILES_COMMAND}`));
            }
        }
        return out;
    },
};

export const PACKAGE_RULES: readonly Rule[] = [packageFilesParity];
