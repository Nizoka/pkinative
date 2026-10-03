/**
 * pkinative — the freeze, rehearsed
 * ==================================
 * ROADMAP 0.9: "Zero new exports, zero new codes, zero new engine
 * behaviour." 1.0 turns the rehearsal into a promise; these rules land a
 * band early so that each has been proven on real commits before it counts.
 *
 * `api-surface-frozen`: the public surface against docs/assets/api.frozen.json
 * (scripts/build-api-frozen.ts), with semantics chosen by the snapshot's
 * `phase` and checked for coherence with package.json:
 *
 *   | phase       | versions      | addition | compatible change | removal / incompatible | new error or reason code |
 *   |-------------|---------------|----------|-------------------|------------------------|--------------------------|
 *   | `rehearsal` | 0.8.x – 0.9.x | fails    | fails             | fails                  | fails                    |
 *   | `stable`    | ≥ 1.0.0       | passes   | passes            | fails (semver-major)   | passes, with a newer `since` |
 *
 * Diagnostic codes are outside both columns in every phase: a diagnostic is
 * advice, and the set of things worth advising about grows.
 *
 * `release-era-prose`: the sentences that say pkinative is not on npm. Below
 * 1.0.0 each must be present where the repository states it; from 1.0.0 the
 * ones that describe the current state must be gone — a README still saying
 * "not on npm" beside `npm install pkinative` is the drift this prevents.
 * Bidirectional, so the rule bites today and not only at 1.0. Each of those
 * rows carries its stable-era replacement, which scripts/release-prepare.ts
 * applies on the 1.0.0 bump; below 1.0.0 the rule also holds the span each
 * replacement swaps out to be there exactly once, so the release commit
 * finds what the table was reviewed against.
 *
 * The npm registry itself is deliberately not a rule: verify-docs is offline
 * and deterministic. scripts/check-npm-drift.ts reads it, on a schedule.
 *
 * @module scripts/verify-docs/rules/freeze
 */

import { ADR_PATH, adrAccepted, API_FROZEN, API_JSON, currentSurface, diffSurface, reasonCodes, REASONS_JSON, type FrozenExport, type Reader } from '../../lib/api-surface.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';
import { compareSemver, ERRORS_REGISTRY, FROZEN_REGISTRY } from './registries.js';

const SEMVER = /^\d+\.\d+\.\d+$/;
const GENERATOR = 'npx tsx scripts/build-api-frozen.ts';
const major = (v: string): number => Number(v.split('.')[0]);

interface Snapshot {
    readonly frozenAt?: unknown;
    readonly phase?: unknown;
    readonly asOf?: unknown;
    readonly reasons?: unknown;
    readonly exports?: unknown;
}

const reader = (ctx: RuleContext): Reader => (path) => ctx.read(path);

function packageVersion(ctx: RuleContext): string | null {
    const pkg = readJson<{ version?: unknown }>(ctx, 'package.json');
    return 'finding' in pkg || typeof pkg.value.version !== 'string' ? null : pkg.value.version;
}

// ── api-surface-frozen ───────────────────────────────────────────────

const apiSurfaceFrozen: Rule = {
    id: 'api-surface-frozen',
    summary: 'The public surface matches docs/assets/api.frozen.json under its phase — "rehearsal" (0.8.x-0.9.x): no export, signature, error code or reason code added, removed or changed; "stable" (from 1.0.0): no removal and no incompatible signature change (semver-major), additions pass — and the phase agrees with package.json.',
    check(ctx) {
        const parsed = readJson<Snapshot>(ctx, API_FROZEN);
        if ('finding' in parsed) return [error(API_FROZEN, `missing or unreadable — generate it with \`${GENERATOR}\``)];
        const snap = parsed.value;
        const snapText = ctx.read(API_FROZEN) ?? '';
        const { frozenAt, phase, asOf } = snap;
        if (typeof frozenAt !== 'string' || !SEMVER.test(frozenAt) || typeof asOf !== 'string' || !SEMVER.test(asOf)) {
            return [error(API_FROZEN, '"frozenAt" and "asOf" must be x.y.z versions')];
        }
        if (phase !== 'rehearsal' && phase !== 'stable') return [error(API_FROZEN, '"phase" must be "rehearsal" or "stable"')];
        if (!Array.isArray(snap.exports) || !Array.isArray(snap.reasons)) return [error(API_FROZEN, '"exports" and "reasons" must be arrays')];
        const frozen = snap.exports as FrozenExport[];
        const frozenReasons = snap.reasons as string[];

        const out: Finding[] = [];
        const version = packageVersion(ctx) ?? '0.0.0';
        // Phase coherence: the snapshot must be the one this version line promises.
        if (phase === 'rehearsal' && major(version) >= 1) {
            out.push(error(API_FROZEN, `package.json is at ${version} and the snapshot is still the ${frozenAt} rehearsal — the release commit of ${String(major(version))}.0.0 rebases it: \`${GENERATOR} --major ${String(major(version))}.0.0\` (scripts/release-prepare.ts runs it)`, lineContaining(snapText, '"phase"')));
            return out;
        }
        if (phase === 'rehearsal' && major(frozenAt) >= 1) out.push(error(API_FROZEN, `a rehearsal snapshot frozen at ${frozenAt} — the rehearsal is the pre-1.0 phase; a 1.x snapshot is "stable"`, lineContaining(snapText, '"phase"')));
        if (phase === 'stable' && (major(frozenAt) < 1 || major(version) !== major(frozenAt))) {
            out.push(error(API_FROZEN, `a stable snapshot frozen at ${frozenAt} with package.json at ${version} — a stable snapshot belongs to its own major line; a new major rebases it with \`${GENERATOR} --major X.0.0\``, lineContaining(snapText, '"phase"')));
            return out;
        }
        if (compareSemver(asOf, frozenAt) < 0) out.push(error(API_FROZEN, `"asOf" ${asOf} is older than "frozenAt" ${frozenAt}`, lineContaining(snapText, '"asOf"')));
        // Every move of the snapshot names the accepted decision behind it.
        const moves: unknown = (snap as { rebaselines?: unknown }).rebaselines;
        if (moves !== undefined) {
            if (!Array.isArray(moves)) out.push(error(API_FROZEN, '"rebaselines" must be a list of { adr, asOf }', lineContaining(snapText, '"rebaselines"')));
            else for (const m of moves as Array<{ adr?: unknown; asOf?: unknown }>) {
                const adr = typeof m?.adr === 'string' ? m.adr : '';
                if (!ADR_PATH.test(adr) || !adrAccepted(ctx.read(adr)) || typeof m.asOf !== 'string' || !SEMVER.test(m.asOf)) {
                    out.push(error(API_FROZEN, `the rebaseline on "${adr}" names no accepted ADR at a version — a rehearsal snapshot moves only on a recorded decision (${GENERATOR} --rebaseline docs/adr/NNNN-slug.md)`, lineContaining(snapText, adr.length > 0 ? adr : '"rebaselines"')));
                }
            }
        }

        const released = compareSemver(version, asOf) >= 0;
        const remedy = !released
            ? `${asOf} is not released yet: a deliberate change is recorded by regenerating with \`${GENERATOR}\``
            : phase === 'rehearsal'
                ? `the pre-1.0 rehearsal admits no change (ROADMAP 0.9.x: zero new exports, zero new codes) — revert it, or record the decision in an accepted ADR and move the snapshot with \`${GENERATOR} --rebaseline docs/adr/NNNN-slug.md\``
                : 'that is semver-major — restore it (a rename keeps the old name beside the new one, deprecated), or make it part of the next major';

        const surface = currentSurface(reader(ctx));
        for (const p of surface.problems) out.push(error(p.module, `cannot fingerprint the public surface: ${p.message}`));
        const rowLine = (name: string): number => lineContaining(snapText, `"name": ${JSON.stringify(name)},`);
        const apiText = ctx.read(API_JSON) ?? '';
        for (const change of diffSurface(frozen, surface.rows)) {
            const where = change.verdict === 'added'
                ? { file: API_JSON, line: lineContaining(apiText, `"name": ${JSON.stringify(change.name)},`) }
                : { file: API_FROZEN, line: rowLine(change.name) };
            if (phase === 'stable' && (change.verdict === 'added' || change.verdict === 'compatible')) continue;
            out.push(error(where.file, `${change.detail} — the surface is frozen at ${frozenAt}: ${remedy}`, where.line));
        }

        // The two frozen vocabularies. Removals of an error code are
        // error-codes-frozen's; what the rehearsal adds is that an addition
        // fails too, whatever its "since".
        const regText = ctx.read(ERRORS_REGISTRY) ?? '';
        const reasonsText = ctx.read(REASONS_JSON) ?? '';
        if (phase === 'rehearsal') {
            const frozenCodes = readJson<{ codes?: Array<{ code?: unknown }> }>(ctx, FROZEN_REGISTRY);
            const errors = readJson<{ errors?: Array<{ code?: unknown; since?: unknown }> }>(ctx, ERRORS_REGISTRY);
            if (!('finding' in frozenCodes) && !('finding' in errors)) {
                const known = new Set((frozenCodes.value.codes ?? []).map((c) => c.code));
                for (const e of errors.value.errors ?? []) {
                    if (typeof e.code !== 'string' || known.has(e.code)) continue;
                    out.push(error(ERRORS_REGISTRY, `${e.code} (since ${String(e.since)}) is a new error code, absent from ${FROZEN_REGISTRY}: ${remedy}`, lineContaining(regText, `"${e.code}"`)));
                }
            }
        }
        const reasons = reasonCodes(reader(ctx));
        const present = new Set(reasons.map((r) => r.code));
        for (const code of frozenReasons) {
            if (!present.has(code)) out.push(error(REASONS_JSON, `${code} was frozen at ${frozenAt} and is gone from the reason registry: ${phase === 'stable' ? 'that is semver-major — a caller branching on it stops matching' : remedy}`, lineContaining(snapText, `"${code}"`)));
        }
        for (const r of reasons) {
            if (frozenReasons.includes(r.code)) continue;
            if (phase === 'stable' && r.since !== null && SEMVER.test(r.since) && compareSemver(r.since, asOf) > 0) continue;
            out.push(error(REASONS_JSON, phase === 'stable'
                ? `${r.code} is not in the ${asOf} snapshot, so it is an addition — give it the "since" of the release that adds it, newer than ${asOf}`
                : `${r.code} (since ${r.since ?? '?'}) is a new reason code: ${remedy}`, lineContaining(reasonsText, `"${r.code}"`)));
        }
        return out;
    },
};

// ── release-era-prose ────────────────────────────────────────────────

interface EraProseBase {
    readonly file: string;
    /** The words that say pkinative is not on npm: present below 1.0.0 and, for an `absent` row, gone from it. */
    readonly phrase: string;
    readonly why: string;
}

/**
 * `from` is the exact span the 1.0.0 release commit replaces — the phrase
 * and whatever around it turns false with it — and `to` is its stable-era
 * text, written and reviewed now rather than improvised in the one commit
 * that can never be amended after its tag. In both, `{version}` and
 * `{minor}` stand for the version package.json names: release-prepare.ts
 * bumps every versioned field first and swaps second, so the span it looks
 * for is the one this rule has held, release after release, to be there
 * exactly once.
 */
export interface EraProseSwap extends EraProseBase {
    readonly at1: 'absent';
    readonly from: string;
    readonly to: string;
}

export type EraProseRow = EraProseSwap | (EraProseBase & { readonly at1: 'kept' });

/**
 * Where the repository says pkinative is not on npm, and what becomes of
 * each sentence at 1.0.0. `absent`: it describes the current state and turns
 * false at the first npm publication, so it carries its replacement, which
 * scripts/release-prepare.ts applies on the 1.0.0 bump. `kept`: it states
 * the pre-1.0 policy, which stays true of those versions forever, so it must
 * be present in both eras. Generated copies (docs/llms.txt,
 * docs/guides/quickstart.html, docs/llms-full.txt) follow their sources
 * through `npm run docs:all`.
 *
 * The stable install is `npm install pkinative`, published by publish.yml
 * with `--provenance`; `npm audit signatures` checks the registry signature
 * and the provenance attestation. publish.yml's attest job still attaches
 * the attested tarball and SBOM to every 1.x GitHub release, so the README
 * and the quick start keep that path as the alternative, and
 * `install-url-version` keeps holding its URL to the current version.
 */
export const PRE_1_0_PROSE: readonly EraProseRow[] = [
    {
        file: 'SECURITY.md', phrase: '| 0.x (latest tag and its release tarball) |', at1: 'absent', why: 'the supported-versions table',
        from: [
            '| 0.x (latest tag and its release tarball) | ✅ (pre-1.0: fixes land in the next tag) |',
            '| npm `0.0.1` (name reservation, when published) | ❌ contains no code |',
        ].join('\n'),
        to: [
            '| the latest 1.x minor on npm | ✅ fixes land in its next patch or in the next minor |',
            '| any older 1.x minor | ❌ upgrade to the latest minor: under the compatibility promise below it breaks nothing |',
            '| 0.x (never tagged, never released) | ❌ |',
            '| npm `0.0.1` (name reservation, deprecated) | ❌ contains no code |',
        ].join('\n'),
    },
    {
        file: 'README.md', phrase: '| pre-1.0 (git tag) |', at1: 'absent', why: 'the comparison table',
        from: '| **pkinative** | pre-1.0 (git tag) |',
        to: '| **pkinative** | {minor} (npm) |',
    },
    {
        file: 'README.md', phrase: 'pre-1.0, not on npm', at1: 'absent', why: 'the status line',
        from: 'pre-1.0, not on npm.** Versions below 1.0.0 are git tags with an attested release tarball, and the first npm publication is 1.0.0 ([ROADMAP.md](ROADMAP.md)). It reads, builds and validates — certificates, paths with revocation, CMS signatures and timestamps, PKCS#8 and PKCS#12 — with Web Crypto doing every signature.',
        to: 'stable, on npm.** From 1.0.0 the public API, the error codes and the reason codes follow semantic versioning: a minor release only adds, and a removal or an incompatible change waits for the next major ([ROADMAP.md](ROADMAP.md)). Versions below 1.0.0 are git tags only — source snapshots of each milestone, never released on GitHub or npm.',
    },
    {
        file: 'README.md', phrase: 'is not on npm. Install the tarball attached to the GitHub release', at1: 'absent', why: 'the Installation section',
        from: [
            'pkinative {minor} is not on npm. Install the tarball attached to the GitHub release — built from the tag, run through the full gate, installed as a test and attested with Sigstore build provenance by [release-assets.yml](.github/workflows/release-assets.yml):',
            '',
            '```bash',
            'npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz',
            'gh attestation verify pkinative-{version}.tgz --repo Nizoka/pkinative   # optional: check where it was built',
            '```',
        ].join('\n'),
        to: [
            'pkinative is on npm, published by [publish.yml](.github/workflows/publish.yml) from the tagged commit, after the full gate, with npm provenance:',
            '',
            '```bash',
            'npm install pkinative',
            'npm audit signatures   # optional: verify the registry signatures and provenance of what you installed',
            '```',
            '',
            'Every GitHub release also carries that same tarball, fetched back from the registry, and a CycloneDX SBOM, both attested with Sigstore build provenance:',
            '',
            '```bash',
            'npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz',
            'gh attestation verify pkinative-{version}.tgz --repo Nizoka/pkinative   # optional: check where it was built',
            '```',
        ].join('\n'),
    },
    {
        file: 'docs/guides/quickstart.md', phrase: 'is not on npm: install the tarball attached to the GitHub release', at1: 'absent', why: 'the quick start\'s install step',
        from: [
            'pkinative {minor} is not on npm: install the tarball attached to the GitHub release, which a workflow builds, gates, installs as a test and attests:',
            '',
            '```bash',
            'npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz',
            '```',
            '',
            '`gh attestation verify pkinative-{version}.tgz --repo Nizoka/pkinative` checks where the tarball was built.',
        ].join('\n'),
        to: [
            'pkinative is on npm, published with provenance from the tagged commit after the full gate:',
            '',
            '```bash',
            'npm install pkinative',
            '```',
            '',
            '`npm audit signatures` verifies the registry signature and the provenance of what you installed. Every GitHub release also carries the tarball, attested with Sigstore build provenance: `npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz`, and `gh attestation verify pkinative-{version}.tgz --repo Nizoka/pkinative` checks where it was built.',
        ].join('\n'),
    },
    {
        file: 'llms.txt', phrase: 'Versions below 1.0 are git tags, not npm releases.', at1: 'absent', why: 'the llms.txt summary an agent reads first',
        from: 'Versions below 1.0 are git tags, not npm releases.',
        to: 'It installs from npm: `npm install pkinative`.',
    },
    {
        file: 'docs/agent-brief.md', phrase: 'Do not install pkinative from npm', at1: 'absent', why: 'the agent brief\'s install rule',
        from: 'Do not install pkinative from npm or from a git URL (a git install carries no `dist/`): {minor} is the release tarball, `npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz`.',
        to: 'Do not install pkinative from a git URL (a git install carries no `dist/`): install it from npm, `npm install pkinative`; `npm audit signatures` verifies its registry signature and provenance.',
    },
    {
        file: 'docs/index.html', phrase: '<code>npm install https://github.com/Nizoka/pkinative/releases/download/', at1: 'absent', why: 'the landing page install command',
        from: '<code>npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz</code>',
        to: '<code>npm install pkinative</code>',
    },
    {
        file: 'docs/index.html', phrase: 'data-copy="npm install https://github.com/Nizoka/pkinative/releases/download/', at1: 'absent', why: 'the landing page copy button, which hands whatever it says to anyone who clicks Copy',
        from: 'data-copy="npm install https://github.com/Nizoka/pkinative/releases/download/v{version}/pkinative-{version}.tgz"',
        to: 'data-copy="npm install pkinative"',
    },
    {
        file: 'docs/index.html', phrase: 'Pre-1.0 is a git tag, not an npm release.', at1: 'absent', why: 'the landing page hero',
        from: 'Pre-1.0 is a git tag, not an npm release. It reads, builds and validates certificates, paths, CMS signatures and PKCS#12, with Web Crypto doing every signature.',
        to: 'On npm with provenance since 1.0.0, under semantic versioning: a minor release only adds.',
    },
    {
        file: 'docs/playground/index.html', phrase: 'it is not on npm before 1.0.0', at1: 'absent', why: 'why the playground commits its engine instead of loading it from a CDN',
        from: 'pkinative cannot — it is not on npm before 1.0.0 — so the copy is committed instead.',
        to: 'pkinative commits its copy instead, so the playground runs the build of the tree this site is published from, not the last npm release.',
    },
    {
        file: 'docs/assets/ecosystem.json', phrase: '"npm": "not published;', at1: 'absent', why: 'packages.pkinative.npm',
        from: '"npm": "not published; pre-1.0 versions are git tags with an attested release tarball, the first npm publication is 1.0.0"',
        to: '"npm": "published from 1.0.0 by publish.yml, with npm provenance; no version below 1.0.0 was tagged or released"',
    },
    {
        file: 'docs/assets/ecosystem.json', phrase: 'because pkinative is not on npm before 1.0.0 and there is no CDN to load it from', at1: 'absent', why: 'the playground block\'s $comment',
        from: 'because pkinative is not on npm before 1.0.0 and there is no CDN to load it from',
        to: 'so that it runs the build of the tree the site is published from, not the last npm release',
    },
    {
        file: 'docs/assets/og-image.svg', phrase: 'pre-1.0 is a git tag, not an npm release', at1: 'absent', why: 'the social card (re-rasterise it: social-images)',
        from: 'pre-1.0 is a git tag, not an npm release',
        to: 'npm install pkinative',
    },
    {
        file: 'docs/assets/social-preview.svg', phrase: 'pre-1.0 is a git tag, not an npm release', at1: 'absent', why: 'the repository social preview (re-rasterise it: social-images)',
        from: 'pre-1.0 is a git tag, not an npm release',
        to: 'npm install pkinative',
    },
    { file: 'AGENTS.md', phrase: 'No version below 1.0.0 was ever tagged or released; `publish.yml` refuses one all the same.', at1: 'kept', why: 'the release policy agents follow' },
    { file: '.github/workflows/publish.yml', phrase: 'no version below 1.0.0 is released', at1: 'kept', why: 'the refusal step, which still guards a 0.x tag cut from an old branch' },
];

const occurrences = (text: string, needle: string): number => text.split(needle).length - 1;

/** A PRE_1_0_PROSE `from` or `to` template at `version`: `{version}` is X.Y.Z, `{minor}` is X.Y. */
export function eraText(template: string, version: string): string {
    return template.split('{version}').join(version).split('{minor}').join(version.split('.').slice(0, 2).join('.'));
}

/**
 * The 1.0.0 swap of one row on one file's text, at `version`: refused unless
 * the phrase and the span are each found exactly once, the span holds the
 * phrase and the replacement does not. release-prepare.ts applies it; below
 * 1.0.0 `release-era-prose` runs it on every commit, so a sentence edited
 * since the table was written fails the day it is edited, not on the
 * release commit.
 */
export function stableSwap(text: string, row: EraProseSwap, version: string): { readonly text: string } | { readonly problem: string } {
    const from = eraText(row.from, version);
    const to = eraText(row.to, version);
    if (!from.includes(row.phrase)) return { problem: 'its `from` span does not contain its phrase' };
    if (to.includes(row.phrase)) return { problem: 'its `to` text still contains its phrase' };
    const phrases = occurrences(text, row.phrase);
    if (phrases !== 1) return { problem: `"${row.phrase}" is found ${String(phrases)} times, not once` };
    const spans = occurrences(text, from);
    if (spans !== 1) return { problem: `the span it replaces is found ${String(spans)} times, not once — it reads ${JSON.stringify(from.length > 120 ? `${from.slice(0, 120)}…` : from)}` };
    return { text: text.replace(from, () => to) };
}

const releaseEraProse: Rule = {
    id: 'release-era-prose',
    summary: 'Below 1.0.0 every sentence of PRE_1_0_PROSE saying pkinative is not on npm is present where the repository states it, and each one that turns false at 1.0.0 still matches, exactly once, the span its stable-era replacement swaps out; from 1.0.0 those are gone and only the policy statements remain.',
    check(ctx) {
        const version = packageVersion(ctx);
        if (version === null) return [];
        const stable = major(version) >= 1;
        const out: Finding[] = [];
        for (const row of PRE_1_0_PROSE) {
            const text = ctx.read(row.file);
            if (text === null) { out.push(error(row.file, `missing — it carries ${row.why}`)); continue; }
            const has = text.includes(row.phrase);
            if (stable && row.at1 === 'absent' && has) {
                out.push(error(row.file, `still says "${row.phrase}" (${row.why}) with package.json at ${version} — from 1.0.0 pkinative is on npm; rewrite the sentence (scripts/release-prepare.ts swaps it on the 1.0.0 bump)`, lineContaining(text, row.phrase)));
            } else if ((!stable || row.at1 === 'kept') && !has) {
                out.push(error(row.file, `no longer says "${row.phrase}" (${row.why}) — ${stable ? 'this states the pre-1.0 policy, which stays true of those versions' : `below 1.0.0 (package.json: ${version}) the repository says here that pkinative is not on npm`}; restore it, or change PRE_1_0_PROSE in scripts/verify-docs/rules/freeze.ts in the same commit`));
            } else if (!stable && row.at1 === 'absent') {
                const swap = stableSwap(text, row, version);
                if ('problem' in swap) out.push(error(row.file, `the 1.0.0 swap of ${row.why} would fail: ${swap.problem} — scripts/release-prepare.ts refuses the bump on it; edit the row's \`from\` (and \`to\`) in PRE_1_0_PROSE, scripts/verify-docs/rules/freeze.ts, in the same commit as the sentence`, lineContaining(text, row.phrase)));
            }
        }
        return out;
    },
};

export const FREEZE_RULES: readonly Rule[] = [apiSurfaceFrozen, releaseEraProse];
