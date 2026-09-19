#!/usr/bin/env tsx
/**
 * pkinative — release preparation
 * ===============================
 * Applies the mechanical part of a version bump in one pass (pdfnative
 * 1.8.0 doctrine), so the release commit reads as the bump and nothing
 * else, and `npm run verify:docs` has nothing left to catch.
 *
 * What it edits, in order (every touched file is printed):
 *   1. package.json and package-lock.json `version` (the root entries only)
 *   2. docs/assets/ecosystem.json `packages.pkinative.version` and `verifiedOn`
 *   3. docs/index.html JSON-LD `softwareVersion` and the verified-on date
 *   4. CITATION.cff `version` and `date-released`
 *   5. CHANGELOG.md `## [Unreleased]` → `## [X.Y.Z] – YYYY-MM-DD`
 *   6. release-notes/vX.Y.Z.md scaffolded from release-notes/TEMPLATE.md
 *      when it does not exist yet
 *
 * It never reserialises JSON, YAML or XML: each edit is a targeted regex on
 * the one field it owns, so formatting and key order survive. It does not
 * tag, commit, push or publish — the maintainer does (AGENT_RULES.md §5).
 * Afterwards run `npm run docs:all` (the llms index carries verifiedOn) and
 * the publish gate.
 *
 * Usage:
 *   npx tsx scripts/release-prepare.ts --version 0.1.0 [--date 2026-09-19] [--dry-run]
 *
 * Exit: 0 done (or dry run reported); 1 a file or a field the bump owns is
 * missing; 2 bad usage.
 *
 * @module scripts/release-prepare
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

interface Edit {
    readonly file: string;
    readonly what: string;
    readonly pattern: RegExp;
    readonly replace: (version: string, date: string) => string;
}

export const EDITS: readonly Edit[] = [
    { file: 'package.json', what: 'version', pattern: /("name": "pkinative",\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'package-lock.json', what: 'root version', pattern: /("name": "pkinative",\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'package-lock.json', what: 'root package version', pattern: /("packages": \{\s*\n\s*"": \{\s*\n\s*"name": "pkinative",\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'docs/assets/ecosystem.json', what: 'packages.pkinative.version', pattern: /("pkinative": \{\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'docs/assets/ecosystem.json', what: 'verifiedOn', pattern: /("verifiedOn": ")[^"]+(")/, replace: (_v, d) => `$1${d}$2` },
    { file: 'docs/index.html', what: 'JSON-LD softwareVersion', pattern: /("softwareVersion": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'docs/index.html', what: 'verified-on date', pattern: /(<time id="verified-on" datetime=")[^"]+(">)[^<]+(<\/time>)/, replace: (_v, d) => `$1${d}$2${d}$3` },
    { file: 'CITATION.cff', what: 'version', pattern: /^(version: ).+$/m, replace: (v) => `$1${v}` },
    { file: 'CITATION.cff', what: 'date-released', pattern: /^(date-released: ).+$/m, replace: (_v, d) => `$1${d}` },
    { file: 'CHANGELOG.md', what: 'Unreleased heading', pattern: /^## \[Unreleased\]$/m, replace: (v, d) => `## [${v}] – ${d}` },
];

function parseArgs(argv: readonly string[]): { version: string; date: string; dryRun: boolean } | null {
    const value = (flag: string): string | undefined => {
        const at = argv.indexOf(flag);
        return at >= 0 ? argv[at + 1] : undefined;
    };
    const version = value('--version') ?? '';
    const date = value('--date') ?? new Date().toISOString().slice(0, 10);
    if (!/^\d+\.\d+\.\d+$/.test(version) || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
    return { version, date, dryRun: argv.includes('--dry-run') };
}

function main(): number {
    const args = parseArgs(process.argv.slice(2));
    if (args === null) {
        console.error('usage: npx tsx scripts/release-prepare.ts --version X.Y.Z [--date YYYY-MM-DD] [--dry-run]');
        return 2;
    }
    const texts = new Map<string, string>();
    let failures = 0;
    for (const edit of EDITS) {
        const path = join(ROOT, edit.file);
        if (!existsSync(path)) {
            console.error(`FAIL  ${edit.file}: missing`);
            failures++;
            continue;
        }
        const before = texts.get(edit.file) ?? readFileSync(path, 'utf8');
        if (!edit.pattern.test(before)) {
            console.error(`FAIL  ${edit.file}: ${edit.what} not found`);
            failures++;
            continue;
        }
        texts.set(edit.file, before.replace(edit.pattern, edit.replace(args.version, args.date)));
        console.log(`edit  ${edit.file}: ${edit.what}`);
    }
    const note = `release-notes/v${args.version}.md`;
    if (!existsSync(join(ROOT, note))) {
        const template = readFileSync(join(ROOT, 'release-notes', 'TEMPLATE.md'), 'utf8');
        const body = /```markdown\n([\s\S]*?)\n```\n/.exec(template)?.[1] ?? '';
        texts.set(note, `${body.replace(/X\.Y\.Z/g, args.version).replace(/YYYY-MM-DD/g, args.date).replace(/\\`\\`\\`/g, '```')}\n`);
        console.log(`new   ${note} (from the template — fill it in)`);
    }
    if (failures > 0) return 1;
    if (!args.dryRun) for (const [file, text] of texts) writeFileSync(join(ROOT, file), text);
    console.log(`${args.dryRun ? 'dry run: ' : ''}${texts.size} file(s) ${args.dryRun ? 'would change' : 'changed'} for v${args.version} (${args.date}). Next: npm run docs:all, then npx tsx scripts/gate.ts --publish --require-all.`);
    return 0;
}

process.exitCode = main();
