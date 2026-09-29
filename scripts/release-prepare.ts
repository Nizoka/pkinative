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
 *   6. every documented release-tarball install URL and `gh attestation
 *      verify` file name outside release-notes/ — README.md, the agent brief,
 *      the quick start and docs/index.html (both the code block and the copy
 *      button's data-copy) — and the prose that quotes the current minor
 *      beside them
 *   7. on the bump from 0.x to 1.0.0 only: every stable-era swap of
 *      PRE_1_0_PROSE (scripts/verify-docs/rules/freeze.ts) — each sentence
 *      that says pkinative is not on npm, replaced by the text written and
 *      reviewed for it in that table. Each phrase and each span must be
 *      found exactly once, which `release-era-prose` has checked on every
 *      commit since; the table is applied after step 6, so `{version}` in a
 *      span is already the new version
 *   8. release-notes/vX.Y.Z.md and release-notes/draft/PR-vX.Y.Z.md
 *      scaffolded from their templates when they do not exist yet
 *   9. docs/assets/api.frozen.json, through scripts/build-api-frozen.ts:
 *      rebased (`--major`) when X.Y.Z is a new major — at 1.0.0 that turns
 *      the rehearsal into the stable promise, and is refused unless the
 *      rehearsal held — or ratcheted (`--ratchet`) on a stable-phase
 *      release, so the surface it ships becomes the promise. A rehearsal
 *      release writes nothing: `api-surface-frozen` is what refuses a
 *      change there. From 1.0.0 docs/data/errors.frozen.json ratchets too.
 *
 * Nothing is written while any row fails. An old release note keeps its old
 * URL: release-notes/ is deliberately not touched, and `install-url-version`
 * skips it for the same reason.
 *
 * It never reserialises JSON, YAML or XML: each edit is a targeted regex or
 * an exact span on the one field it owns, so formatting and key order
 * survive. It does not tag, commit, push or publish — the maintainer does
 * (AGENT_RULES.md §5). Afterwards run `npm run docs:all` (the llms index
 * carries verifiedOn) and the publish gate; at 1.0.0 also re-rasterise the
 * two social images whose SVG it swapped (the `todo` lines name them).
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
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseApiFrozen, planApiFrozen, releaseModeFor } from './build-api-frozen.js';
import { planErrorsFrozen } from './build-errors-frozen.js';
import { planRefusalsFrozen, releaseRefusalsMode } from './build-refusals-frozen.js';
import { parseRefusalsFrozen, REFUSALS_FROZEN } from './lib/refusals-frozen.js';
import { ERRORS_REGISTRY, FROZEN_REGISTRY } from './verify-docs/rules/registries.js';
import { PRE_1_0_PROSE, stableSwap } from './verify-docs/rules/freeze.js';
import { API_FROZEN } from './lib/api-surface.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

interface Edit {
    readonly file: string;
    readonly what: string;
    readonly pattern: RegExp;
    readonly replace: (version: string, date: string) => string;
    /**
     * The row keeps a sentence current that the 1.0.0 swap removes: it runs
     * while the version bumped from is 0.x (so on the 1.0.0 bump itself,
     * before the swap) and is skipped from then on, where it would find
     * nothing and refuse every 1.x release.
     */
    readonly pre1?: true;
}

/** Every occurrence, not the first: docs/index.html carries two. */
const TARBALL = /releases\/download\/v[0-9][^/\s]*\/pkinative-[0-9][^\s"')`]*\.tgz/g;
const ATTESTED = /gh attestation verify pkinative-[0-9][^\s]*\.tgz/g;
const tarball = (v: string): string => `releases/download/v${v}/pkinative-${v}.tgz`;
const attested = (v: string): string => `gh attestation verify pkinative-${v}.tgz`;
const minor = (v: string): string => v.split('.').slice(0, 2).join('.');
const major = (v: string): number => Number(v.split('.')[0]);

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

    // `install-url-version` requires every one of these to name the current
    // version — so before this block a bump failed verify:docs, a step of
    // every gate profile, on every single release. From 1.0.0 the README and
    // the quick start keep the attested tarball as the alternative to npm;
    // the agent brief and the landing page name npm alone, so their rows end
    // with the 0.x line. The generated pages (quickstart.html, llms-full.txt)
    // are fixed by the `npm run docs:all` that follows.
    { file: 'README.md', what: 'release tarball URL', pattern: TARBALL, replace: (v) => tarball(v) },
    { file: 'README.md', what: 'attestation tarball name', pattern: ATTESTED, replace: (v) => attested(v) },
    { file: 'docs/agent-brief.md', what: 'release tarball URL', pattern: TARBALL, replace: (v) => tarball(v), pre1: true },
    { file: 'docs/guides/quickstart.md', what: 'release tarball URL', pattern: TARBALL, replace: (v) => tarball(v) },
    { file: 'docs/guides/quickstart.md', what: 'attestation tarball name', pattern: ATTESTED, replace: (v) => attested(v) },
    { file: 'docs/index.html', what: 'install command (code and data-copy)', pattern: TARBALL, replace: (v) => tarball(v), pre1: true },

    // The fourth version site, which `surfaces-parity` owns and no list of
    // "what a bump touches" had ever mentioned. Found by the rule, on the
    // first release after the rule existed.
    { file: 'docs/data/surfaces.json', what: 'version', pattern: /("version": ")\d+\.\d+\.\d+(")/, replace: (v) => `$1${v}$2` },

    // The prose sentences that carry the current minor beside those URLs —
    // five since 0.9, when three were found still saying "0.3" at 0.8: no row
    // owned them, so no bump moved them. Three of them say "not on npm" and
    // leave at 1.0.0 through PRE_1_0_PROSE; the status line keeps its minor.
    { file: 'README.md', what: 'status line minor', pattern: /(\*\*Status: )\d+\.\d+( )/, replace: (v) => `$1${minor(v)}$2` },
    { file: 'docs/agent-brief.md', what: 'release-tarball minor', pattern: /\b\d+\.\d+( is the release tarball\b)/, replace: (v) => `${minor(v)}$1`, pre1: true },
    { file: 'README.md', what: 'install-section minor', pattern: /(pkinative )\d+\.\d+( is not on npm\.)/, replace: (v) => `$1${minor(v)}$2`, pre1: true },
    { file: 'docs/guides/quickstart.md', what: 'install-step minor', pattern: /(pkinative )\d+\.\d+( is not on npm:)/, replace: (v) => `$1${minor(v)}$2`, pre1: true },
    { file: 'docs/guides/quickstart.md', what: 'tested-version minor', pattern: /(runs on pkinative )\d+\.\d+( as it is tested)/, replace: (v) => `$1${minor(v)}$2` },
];

export interface ReleaseArgs {
    readonly version: string;
    readonly date: string;
}

/** One line of the report: `edit`, `new` and `todo` go to stdout, `FAIL` to stderr. */
export interface PlanLine {
    readonly level: 'edit' | 'new' | 'todo' | 'FAIL';
    readonly text: string;
}

export interface ReleasePlan {
    /** Every file the bump changes or creates, with its new text. */
    readonly texts: ReadonlyMap<string, string>;
    readonly lines: readonly PlanLine[];
    readonly failures: number;
}

/** Reads a repository-relative path, or null when it does not exist. */
export type TreeReader = (path: string) => string | null;

/**
 * The whole bump, planned against `read` and written nowhere: the CLI writes
 * `texts` when `failures` is zero, and a test runs it on an in-memory tree.
 */
export function planRelease(read: TreeReader, args: ReleaseArgs): ReleasePlan {
    const texts = new Map<string, string>();
    const lines: PlanLine[] = [];
    let failures = 0;
    const fail = (text: string): void => { lines.push({ level: 'FAIL', text }); failures++; };
    const current = (path: string): string | null => texts.get(path) ?? read(path);
    const from = /"version": "(\d+\.\d+\.\d+)"/.exec(read('package.json') ?? '')?.[1] ?? '0.0.0';
    for (const edit of EDITS) {
        if (edit.pre1 === true && major(from) >= 1) continue;
        const before = current(edit.file);
        if (before === null) {
            fail(`${edit.file}: missing`);
            continue;
        }
        // The tarball patterns are global AND shared by several rows, so one
        // regex object carries state across iterations. `test` advances
        // `lastIndex` on a match; `String.replace` happens to reset it for a
        // global regex, which is the only reason this works today — and is
        // one refactor away from silently skipping a file's first match.
        edit.pattern.lastIndex = 0;
        if (!edit.pattern.test(before)) {
            // Re-running a bump is the common way to land here: the CHANGELOG
            // heading is consumed by the first run, so the second finds
            // nothing, fails, and — since failures are collected before any
            // write — silently leaves every other file untouched. Saying so
            // costs three lines and saves the ten minutes of reading the
            // whole table to work out why nothing changed.
            const seen = before.includes(args.version) ? ` (the file already mentions ${args.version}: has this bump already run? nothing is written while any row fails)` : '';
            fail(`${edit.file}: ${edit.what} not found${seen}`);
            continue;
        }
        texts.set(edit.file, before.replace(edit.pattern, edit.replace(args.version, args.date)));
        lines.push({ level: 'edit', text: `${edit.file}: ${edit.what}` });
    }
    // The first npm publication: every sentence that says pkinative is not
    // on npm gives way to the text PRE_1_0_PROSE holds for it. After the
    // version rows, so a `{version}` span is matched at the new version.
    if (major(from) === 0 && major(args.version) >= 1) {
        const swapped = new Set<string>();
        for (const row of PRE_1_0_PROSE) {
            if (row.at1 !== 'absent') continue;
            const text = current(row.file);
            if (text === null) {
                fail(`${row.file}: missing — it carries ${row.why}`);
                continue;
            }
            const swap = stableSwap(text, row, args.version);
            if ('problem' in swap) {
                fail(`${row.file}: the 1.0 swap of ${row.why} — ${swap.problem} (PRE_1_0_PROSE, scripts/verify-docs/rules/freeze.ts)`);
                continue;
            }
            texts.set(row.file, swap.text);
            swapped.add(row.file);
            lines.push({ level: 'edit', text: `${row.file}: 1.0 prose — ${row.why}` });
        }
        // The one step no text edit can do: the committed PNG is the social
        // card, and `social-images` fails until it is rasterised again.
        for (const file of swapped) {
            if (file.endsWith('.svg')) lines.push({ level: 'todo', text: `${file}: re-rasterise its PNG with the command in its header comment and record the new svgSha256 in docs/assets/ecosystem.json — social-images fails until then` });
        }
    }
    // Two scaffolds, from the fenced block of their template. The release
    // note is the published artefact; the PR draft is the auditable record of
    // what the release claimed and what was run, and it is committed for
    // exactly that reason — a git-ignored scratch file proves nothing a year
    // later. Neither is overwritten if it already exists.
    const scaffolds: ReadonlyArray<readonly [target: string, template: string, what: string]> = [
        [`release-notes/v${args.version}.md`, 'release-notes/TEMPLATE.md', 'the release note'],
        [`release-notes/draft/PR-v${args.version}.md`, 'release-notes/PR_TEMPLATE.md', 'the pull-request body'],
    ];
    for (const [target, template, what] of scaffolds) {
        if (read(target) !== null) continue;
        const source = read(template) ?? '';
        const body = /```markdown\n([\s\S]*?)\n```\n/.exec(source)?.[1] ?? '';
        if (body === '') {
            fail(`${template}: no fenced \`\`\`markdown block to scaffold from`);
            continue;
        }
        texts.set(target, `${body.replace(/X\.Y\.Z/g, args.version).replace(/YYYY-MM-DD/g, args.date).replace(/\\`\\`\\`/g, '```')}\n`);
        lines.push({ level: 'new', text: `${target} (${what}, from the template — fill it in)` });
    }
    // The frozen surface moves only here, and only in the two ways a release
    // may move it: a new major rebases it, a stable-phase release ratchets it.
    const snapshotText = current(API_FROZEN);
    const mode = releaseModeFor(args.version, snapshotText === null ? null : parseApiFrozen(snapshotText));
    if (mode !== null) {
        const plan = planApiFrozen(current, args.version, mode);
        if (plan.action === 'refuse') {
            fail(`${API_FROZEN}: ${plan.message}`);
        } else if (plan.action === 'write' && plan.text !== null) {
            texts.set(API_FROZEN, plan.text);
            lines.push({ level: 'edit', text: `${API_FROZEN}: ${plan.message}` });
        }
    }
    // The error vocabulary ratchets with it: a code a 1.x release ships is a
    // promise from that release on, and the snapshot is where the rule keeps it.
    if (major(args.version) >= 1) {
        const errorsPlan = planErrorsFrozen(current(ERRORS_REGISTRY) ?? '', current(FROZEN_REGISTRY), args.version, 'ratchet');
        if (errorsPlan.action === 'refuse') {
            fail(`${FROZEN_REGISTRY}: ${errorsPlan.message}`);
        } else if (errorsPlan.action === 'write' && errorsPlan.text !== null) {
            texts.set(FROZEN_REGISTRY, errorsPlan.text);
            lines.push({ level: 'edit', text: `${FROZEN_REGISTRY}: ${errorsPlan.message}` });
        }
    }
    // And the decision surface (ADR 0014) the same two ways: a new major
    // rebases it, refused at 1.0.0 unless the rehearsal held; a stable-phase
    // release records the refusals it ships, refused over a lifted or recoded one.
    const refusalsText = current(REFUSALS_FROZEN);
    const refusalsParsed = refusalsText === null ? null : parseRefusalsFrozen(refusalsText);
    const refusalsMode = releaseRefusalsMode(args.version, refusalsParsed !== null && 'snapshot' in refusalsParsed ? refusalsParsed.snapshot : null);
    if (refusalsMode !== null) {
        const refusalsPlan = planRefusalsFrozen(current, args.version, refusalsMode);
        if (refusalsPlan.action === 'refuse') {
            fail(`${REFUSALS_FROZEN}: ${refusalsPlan.message}`);
        } else if (refusalsPlan.action === 'write' && refusalsPlan.text !== null) {
            texts.set(REFUSALS_FROZEN, refusalsPlan.text);
            lines.push({ level: 'edit', text: `${REFUSALS_FROZEN}: ${refusalsPlan.message}` });
        }
    }
    return { texts, lines, failures };
}

export function parseArgs(argv: readonly string[]): (ReleaseArgs & { readonly dryRun: boolean }) | null {
    const value = (flag: string): string | undefined => {
        const at = argv.indexOf(flag);
        return at >= 0 ? argv[at + 1] : undefined;
    };
    const version = value('--version') ?? '';
    const date = value('--date') ?? new Date().toISOString().slice(0, 10);
    if (!/^\d+\.\d+\.\d+$/.test(version) || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
    return { version, date, dryRun: argv.includes('--dry-run') };
}

function main(argv: readonly string[]): number {
    const args = parseArgs(argv);
    if (args === null) {
        console.error('usage: npx tsx scripts/release-prepare.ts --version X.Y.Z [--date YYYY-MM-DD] [--dry-run]');
        return 2;
    }
    const read: TreeReader = (path) => (existsSync(join(ROOT, path)) ? readFileSync(join(ROOT, path), 'utf8') : null);
    const plan = planRelease(read, args);
    for (const line of plan.lines) {
        const text = `${line.level.padEnd(6)}${line.text}`;
        if (line.level === 'FAIL') console.error(text);
        else console.log(text);
    }
    if (plan.failures > 0) return 1;
    if (!args.dryRun) for (const [file, text] of plan.texts) writeFileSync(join(ROOT, file), text);
    console.log(`${args.dryRun ? 'dry run: ' : ''}${plan.texts.size} file(s) ${args.dryRun ? 'would change' : 'changed'} for v${args.version} (${args.date}). Next: npm run docs:all, then npx tsx scripts/gate.ts --publish --require-all.`);
    return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    process.exitCode = main(process.argv.slice(2));
}
