/**
 * pkinative — the compatibility promise, held
 * ============================================
 * ROADMAP 1.0: three promises — the export surface, the error vocabulary and
 * the decision surface — "each held by a rule, not by a sentence".
 *
 * `refusal-baseline-frozen`: the decision surface of ADR 0014. The committed
 * baseline scripts/data/limbo-refusals.json (what the engine refuses, as
 * conformance L1 verifies it against the corpus) against the snapshot
 * docs/data/refusals.frozen.json (what is promised), with semantics chosen by
 * the snapshot's `phase` and checked for coherence with package.json:
 *
 *   | phase       | versions      | refusal lifted | code changed | new refusal |
 *   |-------------|---------------|----------------|--------------|-------------|
 *   | `rehearsal` | 0.9.x         | fails          | fails        | fails       |
 *   | `stable`    | ≥ 1.0.0       | fails (major)  | fails (major)| passes; the release ratchets it in, and its note must list it |
 *
 * Offline and deterministic like every rule here: it compares two committed
 * files. The corpus half — the engine against the certificates — is L1's.
 *
 * `contracts-shape`: docs/assets/ecosystem.json → contracts.compatibility
 * names each leg's snapshot, the rules that hold it and the records that
 * decide it, and SECURITY.md §Compatibility promise names them too. Both
 * ways: a `*-frozen` rule or a `*.frozen.json` snapshot that no leg names
 * fails, because a promise held by a rule nobody lists is one a reader of
 * the machine contract cannot find.
 *
 * @module scripts/verify-docs/rules/contracts
 */

import { ADR_PATH, adrAccepted } from '../../lib/api-surface.js';
import {
    decisionSurfaceSection, diffRefusals, DECISION_SURFACE_HEADING, HASH_PREFIX, parseRefusalBaseline, parseRefusalsFrozen,
    REFUSAL_BASELINE, REFUSALS_FROZEN, REFUSALS_GENERATOR, type FrozenRefusal,
} from '../../lib/refusals-frozen.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';
import { compareSemver, ERRORS_REGISTRY, FROZEN_REGISTRY } from './registries.js';

const major = (v: string): number => Number(v.split('.')[0]);
const SEMVER = /^\d+\.\d+\.\d+$/;

function packageVersion(ctx: RuleContext): string | null {
    const pkg = readJson<{ version?: unknown }>(ctx, 'package.json');
    return 'finding' in pkg || typeof pkg.value.version !== 'string' ? null : pkg.value.version;
}

// ── refusal-baseline-frozen ──────────────────────────────────────────

const refusalBaselineFrozen: Rule = {
    id: 'refusal-baseline-frozen',
    summary: 'Every refusal of docs/data/refusals.frozen.json is still in scripts/data/limbo-refusals.json with the same code, at the same corpus commit, with a registered code; "rehearsal" (0.9.x): no refusal added either; "stable" (from 1.0.0): a new refusal passes, and one a release added is listed under "### Decision surface" in its note — and the phase agrees with package.json.',
    check(ctx) {
        const snapText = ctx.read(REFUSALS_FROZEN);
        if (snapText === null) return [error(REFUSALS_FROZEN, `missing — generate it with \`${REFUSALS_GENERATOR}\``)];
        const parsed = parseRefusalsFrozen(snapText);
        if ('problems' in parsed) return parsed.problems.map((p) => error(REFUSALS_FROZEN, p));
        const snap = parsed.snapshot;
        const { frozenAt, phase, asOf } = snap;
        const out: Finding[] = [];
        const at = (needle: string): number => lineContaining(snapText, needle);

        // Phase coherence: the snapshot must be the one this version line promises.
        const version = packageVersion(ctx) ?? '0.0.0';
        if (phase === 'rehearsal' && major(version) >= 1) {
            return [error(REFUSALS_FROZEN, `package.json is at ${version} and the snapshot is still the ${frozenAt} rehearsal — the release commit of ${String(major(version))}.0.0 rebases it: \`${REFUSALS_GENERATOR} --major ${String(major(version))}.0.0\` (scripts/release-prepare.ts runs it)`, at('"phase"'))];
        }
        if (phase === 'rehearsal' && major(frozenAt) >= 1) out.push(error(REFUSALS_FROZEN, `a rehearsal snapshot frozen at ${frozenAt} — the rehearsal is the pre-1.0 phase; a 1.x snapshot is "stable"`, at('"phase"')));
        if (phase === 'stable' && (major(frozenAt) < 1 || major(version) !== major(frozenAt))) {
            return [error(REFUSALS_FROZEN, `a stable snapshot frozen at ${frozenAt} with package.json at ${version} — a stable snapshot belongs to its own major line; a new major rebases it with \`${REFUSALS_GENERATOR} --major X.0.0\``, at('"phase"'))];
        }
        if (compareSemver(asOf, frozenAt) < 0) out.push(error(REFUSALS_FROZEN, `"asOf" ${asOf} is older than "frozenAt" ${frozenAt}`, at('"asOf"')));
        for (const row of snap.refusals) {
            if (row.since !== undefined && (compareSemver(row.since, frozenAt) <= 0 || compareSemver(row.since, asOf) > 0)) {
                out.push(error(REFUSALS_FROZEN, `${row.sha256}: "since" ${row.since} is outside (${frozenAt}, ${asOf}] — only a release after the freeze adds a refusal, and only up to the release the snapshot records`, at(row.sha256)));
            }
        }
        for (const row of snap.retired ?? []) {
            if (!ADR_PATH.test(row.adr) || !adrAccepted(ctx.read(row.adr))) {
                out.push(error(REFUSALS_FROZEN, `${row.sha256} is retired on "${row.adr}", which is not an accepted ADR — a promised refusal leaves verification only on a recorded re-pin (${REFUSALS_GENERATOR} --repin --adr docs/adr/NNNN-slug.md)`, at(row.sha256)));
            }
        }

        // The codes: a refusal is promised with a code the registry defines.
        const registry = readJson<{ errors?: Array<{ code?: unknown }> }>(ctx, ERRORS_REGISTRY);
        if ('finding' in registry) return [...out, registry.finding];
        const codes = new Set((registry.value.errors ?? []).map((e) => e.code));
        for (const row of [...snap.refusals, ...(snap.retired ?? [])]) {
            if (!codes.has(row.code)) out.push(error(REFUSALS_FROZEN, `${row.sha256} is promised with ${row.code}, which ${ERRORS_REGISTRY} does not define`, at(row.sha256)));
        }

        // The baseline, and what moved against it.
        const baselineText = ctx.read(REFUSAL_BASELINE);
        const baseline = parseRefusalBaseline(baselineText);
        if (baselineText === null || baseline === null) return [...out, error(REFUSAL_BASELINE, 'missing or not a refusal baseline (corpus, commit, refusals) — conformance L1 writes it with `npx tsx scripts/validate-certs.ts --update-baseline`')];
        if (baseline.corpus !== snap.corpus) return [...out, error(REFUSAL_BASELINE, `is a baseline of ${baseline.corpus}; the snapshot promises refusals of ${snap.corpus}`)];
        if (baseline.commit !== snap.commit) {
            return [...out, error(REFUSALS_FROZEN, `the refusals were verified at ${snap.corpus}@${snap.commit} and the baseline is at ${baseline.commit}: the corpus was re-pinned — record it with \`${REFUSALS_GENERATOR} --repin\` (and --adr, if the new corpus dropped a promised certificate), in a commit that changes no engine behaviour`, at('"commit"'))];
        }
        const released = compareSemver(version, asOf) >= 0;
        const majorRemedy = phase === 'rehearsal'
            ? (released
                ? 'the rehearsal admits no change to the decision surface (1.0.0 is the freeze itself) — revert the engine change'
                : `${asOf} is not released yet: a deliberate change is recorded by regenerating with \`${REFUSALS_GENERATOR}\``)
            : 'that is semver-major (ADR 0014) — restore the refusal and its code, or make the change part of the next major';
        const bLine = (hash: string): number => lineContaining(baselineText, hash);
        const drift = diffRefusals(snap, baseline);
        for (const row of drift.lifted) {
            out.push(error(REFUSAL_BASELINE, `${row.sha256} was promised refused with ${row.code} and the baseline no longer lists it — the certificate now parses: ${majorRemedy}`, bLine(row.sha256)));
        }
        for (const { row, now } of drift.recoded) {
            out.push(error(REFUSAL_BASELINE, `${row.sha256} was promised refused with ${row.code} and is now refused with ${now} — callers branch on the code: ${majorRemedy}`, bLine(row.sha256)));
        }
        if (phase === 'rehearsal') {
            for (const row of drift.added) {
                out.push(error(REFUSAL_BASELINE, `${row.sha256} is a new refusal (${row.code}), absent from ${REFUSALS_FROZEN}: ${released ? 'the rehearsal admits no new engine behaviour — make it after 1.0.0, where a new refusal is a recorded fix' : majorRemedy}`, bLine(row.sha256)));
            }
        }

        // Stable phase: a refusal a release added is listed in that release's note.
        const bySince = new Map<string, FrozenRefusal[]>();
        for (const row of snap.refusals) if (row.since !== undefined && SEMVER.test(row.since)) bySince.set(row.since, [...(bySince.get(row.since) ?? []), row]);
        for (const [since, rows] of bySince) {
            const notePath = `release-notes/v${since}.md`;
            const note = ctx.read(notePath);
            const section = note === null ? null : decisionSurfaceSection(note);
            if (section === null) {
                out.push(error(notePath, `${note === null ? 'is missing' : `has no "${DECISION_SURFACE_HEADING}" section`} — ${String(rows.length)} refusal(s) of ${REFUSALS_FROZEN} were added by ${since}, and a new refusal is never silent (ADR 0014): list each by the first ${String(HASH_PREFIX)} hex digits of its SHA-256, with its code and why`));
                continue;
            }
            for (const row of rows) {
                if (!section.includes(row.sha256.slice(0, HASH_PREFIX))) out.push(error(notePath, `"${DECISION_SURFACE_HEADING}" does not list ${row.sha256.slice(0, HASH_PREFIX)} (${row.code}), a refusal ${since} added`, lineContaining(note ?? '', DECISION_SURFACE_HEADING)));
            }
        }
        return out;
    },
};

// ── contracts-shape ──────────────────────────────────────────────────

const MANIFEST = 'docs/assets/ecosystem.json';
const SECURITY = 'SECURITY.md';
const GATE_SOURCE = 'scripts/validate-certs.ts';
/** The three legs of ROADMAP 1.0's compatibility promise, in its order. */
export const CONTRACT_LEGS: readonly string[] = ['export-surface', 'error-vocabulary', 'decision-surface'];
/** A rule that holds a snapshot of the promise is named `<subject>-frozen`, and a snapshot `<subject>.frozen.json`. */
const HOLDING_RULE = /-frozen$/;
const SNAPSHOT_FILE = /\.frozen\.json$/;

interface Leg {
    readonly promise?: unknown;
    readonly snapshot?: unknown;
    readonly rules?: unknown;
    readonly adrs?: unknown;
    readonly gate?: unknown;
}

interface Contracts {
    readonly runtime_dependencies?: unknown;
    readonly error_codes_frozen_since?: unknown;
    readonly compatibility?: { readonly document?: unknown; readonly section?: unknown; readonly legs?: Record<string, Leg>; readonly notPromised?: unknown };
}

const strings = (v: unknown): v is string[] => Array.isArray(v) && v.length > 0 && v.every((s) => typeof s === 'string' && s !== '');

/** The Markdown section under `## <title>`, up to the next `## `, or null. */
function h2Section(text: string, title: string): string | null {
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const start = lines.findIndex((l) => l.trim() === `## ${title}`);
    if (start < 0) return null;
    const end = lines.findIndex((l, i) => i > start && /^## /.test(l));
    return lines.slice(start + 1, end < 0 ? undefined : end).join('\n');
}

const contractsShape: Rule = {
    id: 'contracts-shape',
    summary: 'docs/assets/ecosystem.json → contracts.compatibility names exactly the three legs of the 1.0 promise, each with a snapshot that exists, the verify-docs rules and conformance levels that hold it and the accepted ADRs that decide it; SECURITY.md §Compatibility promise names every one of them; every "-frozen" rule and "*.frozen.json" snapshot belongs to a leg; and the scalar contracts agree with package.json and errors.frozen.json.',
    async check(ctx) {
        // The rule table imports this module; reading it at check time keeps the cycle harmless.
        const { RULES } = await import('./index.js');
        const manifest = readJson<{ contracts?: Contracts }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const manifestText = ctx.read(MANIFEST) ?? '';
        const mLine = (needle: string): number => lineContaining(manifestText, needle);
        const contracts = manifest.value.contracts;
        if (typeof contracts !== 'object' || contracts === null) return [error(MANIFEST, 'has no "contracts" block — the machine-readable half of SECURITY.md §Compatibility promise')];
        const out: Finding[] = [];

        // The scalar contracts, each held to the file it summarises.
        const pkg = readJson<{ dependencies?: Record<string, unknown> }>(ctx, 'package.json');
        if (!('finding' in pkg)) {
            const deps = Object.keys(pkg.value.dependencies ?? {}).length;
            if (contracts.runtime_dependencies !== deps) out.push(error(MANIFEST, `contracts.runtime_dependencies is ${String(contracts.runtime_dependencies)}; package.json declares ${String(deps)}`, mLine('"runtime_dependencies"')));
        }
        const errorsFrozen = readJson<{ frozenAt?: unknown }>(ctx, FROZEN_REGISTRY);
        if (!('finding' in errorsFrozen) && contracts.error_codes_frozen_since !== errorsFrozen.value.frozenAt) {
            out.push(error(MANIFEST, `contracts.error_codes_frozen_since is ${String(contracts.error_codes_frozen_since)}; ${FROZEN_REGISTRY} is frozen at ${String(errorsFrozen.value.frozenAt)}`, mLine('"error_codes_frozen_since"')));
        }

        const compat = contracts.compatibility;
        if (typeof compat !== 'object' || compat === null || typeof compat.legs !== 'object' || compat.legs === null) {
            return [...out, error(MANIFEST, 'contracts.compatibility.legs is missing — it names the three legs of the 1.0 promise (ADR 0014)')];
        }
        if (compat.document !== SECURITY || compat.section !== 'Compatibility promise') {
            out.push(error(MANIFEST, `contracts.compatibility must point at the prose that states the promise: "document": "${SECURITY}", "section": "Compatibility promise"`, mLine('"compatibility"')));
        }
        if (!strings(compat.notPromised)) out.push(error(MANIFEST, 'contracts.compatibility.notPromised must list what the promise leaves out — a contract that does not say where it stops reads as covering everything', mLine('"compatibility"')));
        const security = ctx.read(SECURITY) ?? '';
        const section = h2Section(security, 'Compatibility promise');
        if (section === null) out.push(error(SECURITY, 'has no "## Compatibility promise" section — the three legs, what is not promised, and what holds each'));
        const gateSource = ctx.read(GATE_SOURCE) ?? '';

        const legs = compat.legs;
        const names = Object.keys(legs);
        for (const name of CONTRACT_LEGS) if (!names.includes(name)) out.push(error(MANIFEST, `contracts.compatibility.legs lacks "${name}" — the promise has three legs (ROADMAP 1.0): ${CONTRACT_LEGS.join(', ')}`, mLine('"legs"')));
        for (const name of names) if (!CONTRACT_LEGS.includes(name)) out.push(error(MANIFEST, `contracts.compatibility.legs names "${name}", which is not a leg of the promise (${CONTRACT_LEGS.join(', ')})`, mLine(`"${name}"`)));

        const ruleIds = new Set(RULES.map((r) => r.id));
        const namedRules = new Set<string>();
        const namedSnapshots = new Set<string>();
        const inSection = (what: string, needle: string, leg: string): void => {
            if (section !== null && !section.includes(needle)) out.push(error(SECURITY, `§Compatibility promise does not name ${what} ${needle}, which holds the ${leg} leg (docs/assets/ecosystem.json → contracts.compatibility)`, lineContaining(security, '## Compatibility promise')));
        };
        for (const name of names.filter((n) => CONTRACT_LEGS.includes(n))) {
            const leg = legs[name] ?? {};
            const where = mLine(`"${name}"`);
            if (typeof leg.promise !== 'string' || leg.promise.length < 20) out.push(error(MANIFEST, `leg "${name}" needs a "promise": one sentence a satellite can quote`, where));
            if (typeof leg.snapshot !== 'string' || !SNAPSHOT_FILE.test(leg.snapshot)) {
                out.push(error(MANIFEST, `leg "${name}" needs a "snapshot": the *.frozen.json file that records what is promised`, where));
            } else {
                namedSnapshots.add(leg.snapshot);
                const snap = readJson<{ frozenAt?: unknown }>(ctx, leg.snapshot);
                if ('finding' in snap) out.push(error(MANIFEST, `leg "${name}" names ${leg.snapshot}: ${snap.finding.message}`, where));
                else if (typeof snap.value.frozenAt !== 'string' || !SEMVER.test(snap.value.frozenAt)) out.push(error(leg.snapshot, 'has no "frozenAt" version — it is not a snapshot of a promise'));
                inSection('the snapshot', leg.snapshot, name);
            }
            if (!strings(leg.rules)) out.push(error(MANIFEST, `leg "${name}" needs "rules": the verify-docs rules that hold it — a promise held by no rule is a sentence`, where));
            else for (const id of leg.rules) {
                namedRules.add(id);
                if (!ruleIds.has(id)) out.push(error(MANIFEST, `leg "${name}" is held by "${id}", which is not a verify-docs rule`, mLine(`"${id}"`)));
                inSection('the rule', `\`${id}\``, name);
            }
            if (!strings(leg.adrs)) out.push(error(MANIFEST, `leg "${name}" needs "adrs": the accepted records that decide it`, where));
            else for (const adr of leg.adrs) {
                if (!ADR_PATH.test(adr) || !adrAccepted(ctx.read(adr))) out.push(error(MANIFEST, `leg "${name}" cites ${adr}, which is not an accepted ADR`, mLine(adr)));
                else inSection('ADR', adr.slice('docs/adr/'.length, 'docs/adr/'.length + 4), name);
            }
            if (leg.gate !== undefined) {
                if (!strings(leg.gate)) out.push(error(MANIFEST, `leg "${name}": "gate" lists conformance levels, e.g. ["L1", "L2"]`, where));
                else for (const level of leg.gate) {
                    if (!/^L\d$/.test(level) || !new RegExp(`^ \\*   ${level}  `, 'm').test(gateSource)) out.push(error(MANIFEST, `leg "${name}" is verified by conformance ${level}, which ${GATE_SOURCE} does not document`, mLine(`"${level}"`)));
                }
            }
        }

        // Both ways: nothing that holds a promise goes unlisted.
        for (const rule of RULES) {
            if (HOLDING_RULE.test(rule.id) && !namedRules.has(rule.id)) out.push(error(MANIFEST, `the rule "${rule.id}" holds a frozen snapshot and no leg of contracts.compatibility names it — add it to the leg it holds, or rename it`, mLine('"legs"')));
        }
        for (const path of ctx.list('docs')) {
            if (SNAPSHOT_FILE.test(path) && !namedSnapshots.has(path)) out.push(error(MANIFEST, `${path} is a frozen snapshot no leg of contracts.compatibility names — a promise a satellite cannot find`, mLine('"legs"')));
        }
        return out;
    },
};

export const CONTRACT_RULES: readonly Rule[] = [refusalBaselineFrozen, contractsShape];
