/**
 * pkinative — public API rules
 * ============================
 * `api-json-sync`: docs/assets/api.json is what scripts/build-api-json.ts
 * produces from the current sources, byte for byte.
 * `tsdoc-complete`: every public export has a TSDoc summary, and every
 * public function documents each parameter, its return value and what it
 * throws (AGENTS.md §Conventions) — the manifest is only as honest as the
 * comments it is read from.
 * `member-tsdoc`: every member of every exported interface has a summary
 * too — most of them belong to shapes a caller only ever receives, so the
 * manifest is the only place their fields are described.
 * `export-named`, `option-fields-named`, `extension-kinds-complete` and
 * `surfaces-parity`: the mechanical half of "can an agent use this from
 * the documentation alone" — every name it must write is written somewhere
 * a human wrote, every enumeration is complete, and the machine-readable
 * surface matches the package.
 *
 * @module scripts/verify-docs/rules/api
 */

import { documentationGaps, renderApiJson, type Reader } from '../../build-api-json.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

const API_JSON = 'docs/assets/api.json';
const MANIFEST = 'docs/assets/ecosystem.json';

const reader = (ctx: RuleContext): Reader => (path) => ctx.read(path);

const apiJsonSync: Rule = {
    id: 'api-json-sync',
    summary: 'docs/assets/api.json equals, byte for byte, what scripts/build-api-json.ts produces from src/index.ts and the modules it re-exports.',
    check(ctx) {
        const current = ctx.read(API_JSON);
        if (current === null) return [error(API_JSON, 'missing — run `npm run docs:api`')];
        return current === renderApiJson(reader(ctx)) ? [] : [error(API_JSON, 'stale — run `npm run docs:api` and commit the result')];
    },
};

const tsdocComplete: Rule = {
    id: 'tsdoc-complete',
    summary: 'Every public export has a TSDoc summary, and every public function has an @param per parameter, @returns and @throws.',
    check(ctx) {
        return documentationGaps(reader(ctx)).map((gap) => error(gap.split(' › ')[0] ?? 'src/index.ts', gap));
    },
};

const memberTsdoc: Rule = {
    id: 'member-tsdoc',
    summary: 'Every interface member of docs/assets/api.json has a TSDoc summary — the 57 result-only shapes a caller never types are reached through a return value, so the manifest is the only place their fields are ever described.',
    check(ctx) {
        const api = readJson<{ exports?: ReadonlyArray<{ name?: string; module?: string; members?: ReadonlyArray<{ name?: string; summary?: unknown }> }> }>(ctx, API_JSON);
        if ('finding' in api) return [api.finding];
        return (api.value.exports ?? []).flatMap((e) =>
            (e.members ?? [])
                .filter((member) => typeof member.summary !== 'string' || member.summary === '')
                .map((member) => error(e.module ?? API_JSON, `${e.name ?? '?'}.${member.name ?? '?'} has no TSDoc summary — a caller reading docs/assets/api.json sees the field name and its type, and nothing about what it holds`)));
    },
};

// ── Can an agent use the library from the docs alone? ────────────────
//
// Four mechanical halves of that question. What is left to judgement — is
// the sentence still true, is this still the shortest path — stays with the
// release-audit skill, which is why none of these rules reads a generated
// page: a page built from api.json would make export-named prove itself.

/** One export of docs/assets/api.json, as these rules read it. */
interface ApiExport {
    readonly name?: string;
    readonly kind?: string;
    readonly module?: string;
    readonly signature?: string;
    readonly members?: ReadonlyArray<{ name?: string; type?: string }>;
}

const readExports = (ctx: RuleContext): ApiExport[] | Finding => {
    const api = readJson<{ exports?: ApiExport[] }>(ctx, API_JSON);
    return 'finding' in api ? api.finding : (api.value.exports ?? []);
};

/** The files a human writes by hand. A generated page must never be in this list. */
const HAND_WRITTEN = (ctx: RuleContext): string[] => [
    'README.md',
    'llms.txt',
    'docs/agent-brief.md',
    ...ctx.list('docs/guides').filter((p) => p.endsWith('.md')),
    ...ctx.list('recipes').filter((p) => p.endsWith('.ts')),
];

/** Every identifier that occurs in hand-written prose. */
const namedInProse = (ctx: RuleContext): Set<string> =>
    new Set(HAND_WRITTEN(ctx).flatMap((path) => (ctx.read(path) ?? '').split(/[^A-Za-z0-9_$]+/)));

const exportNamed: Rule = {
    id: 'export-named',
    summary: 'Every export a caller has to write — every function, class and constant, and every type that appears in an exported signature — is named in the README, llms.txt, the agent brief, a guide or a recipe. The result-only shapes a caller never types are deliberately exempt: their contract is docs/assets/api.json, and padding the guides with them would cost tokens and teach nothing.',
    check(ctx) {
        const exports = readExports(ctx);
        if (!Array.isArray(exports)) return [exports];
        const inSignatures = new Set(
            exports.filter((e) => e.kind === 'function' || e.kind === 'class')
                .flatMap((e) => (e.signature ?? '').split(/[^A-Za-z0-9_$]+/)));
        const named = namedInProse(ctx);
        return exports
            .filter((e) => (e.kind !== 'type' || inSignatures.has(e.name ?? '')) && !named.has(e.name ?? ''))
            .map((e) => error(API_JSON, `${e.name ?? '?'} (${e.kind ?? '?'}, ${e.module ?? '?'}) is an export a caller must be able to write, and no guide, recipe, the README, llms.txt or the agent brief names it — an agent with only the docs cannot discover it`));
    },
};

const optionFieldsNamed: Rule = {
    id: 'option-fields-named',
    summary: 'Every field of every exported options interface, and of PkiLimits, is named in hand-written prose — an option no document names is an option no caller will ever pass.',
    check(ctx) {
        const exports = readExports(ctx);
        if (!Array.isArray(exports)) return [exports];
        const named = namedInProse(ctx);
        return exports
            .filter((e) => (e.name ?? '').endsWith('Options') || e.name === 'PkiLimits')
            .flatMap((e) => (e.members ?? [])
                .filter((member) => !named.has(member.name ?? ''))
                .map((member) => error(API_JSON, `${e.name ?? '?'}.${member.name ?? '?'} is named in no guide, recipe, the README, llms.txt or the agent brief`)));
    },
};

const KIND_DOCS: readonly string[] = ['docs/guides/quickstart.md', 'docs/agent-brief.md'];

const extensionKindsComplete: Rule = {
    id: 'extension-kinds-complete',
    summary: 'The quick start and the agent brief each name every `kind` an Extension can carry, and neither names one that does not exist — the second half is what keeps an invented kind such as `subjectAlternativeName` out of the documentation.',
    check(ctx) {
        const exports = readExports(ctx);
        if (!Array.isArray(exports)) return [exports];
        const kinds = exports
            .filter((e) => /Extension$/.test(e.name ?? '') && e.members !== undefined)
            .map((e) => e.members?.find((m) => m.name === 'kind')?.type ?? '')
            .filter((type) => /^'[a-zA-Z]+'$/.test(type))
            .map((type) => type.slice(1, -1));
        if (kinds.length === 0) return [error(API_JSON, 'no Extension export declares a literal `kind`')];

        const out: Finding[] = [];
        for (const path of KIND_DOCS) {
            const text = ctx.read(path);
            if (text === null) { out.push(error(path, 'missing')); continue; }
            const words = new Set(text.split(/[^A-Za-z0-9_$]+/));
            const absent = kinds.filter((kind) => !words.has(kind));
            if (absent.length > 0) out.push(error(path, `names ${String(kinds.length - absent.length)} of the ${String(kinds.length)} extension kinds; missing ${absent.join(', ')} — a kind no document names is one an agent cannot ask for`));
            // getExtension(cert, '<kind>') spelled with a kind that does not exist.
            for (const m of text.matchAll(/getExtension\([^,)]+,\s*'([a-zA-Z]+)'/g)) {
                if (!kinds.includes(m[1] ?? '')) out.push(error(path, `calls getExtension with '${m[1] ?? ''}', which is not an extension kind`, lineContaining(text, m[0])));
            }
        }
        return out;
    },
};

const SURFACES = 'docs/data/surfaces.json';

interface Capability {
    readonly id?: string;
    readonly exports?: readonly string[];
    readonly since?: string;
}

const surfacesParity: Rule = {
    id: 'surfaces-parity',
    summary: 'docs/data/surfaces.json names only real exports, claims every runtime export in exactly one capability, carries the current version, and leaves a planned capability with no exports — the drift that makes a site advertise a surface the package does not have.',
    check(ctx) {
        const exports = readExports(ctx);
        if (!Array.isArray(exports)) return [exports];
        const surfaces = readJson<{ version?: unknown; capabilities?: Capability[] }>(ctx, SURFACES);
        if ('finding' in surfaces) return [surfaces.finding];
        const manifest = readJson<{ packages?: { pkinative?: { version?: unknown } } }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];

        const out: Finding[] = [];
        const known = new Set(exports.map((e) => e.name ?? ''));
        const claimedBy = new Map<string, string[]>();
        for (const capability of surfaces.value.capabilities ?? []) {
            const id = capability.id ?? '?';
            for (const name of capability.exports ?? []) {
                if (!known.has(name)) out.push(error(SURFACES, `capability "${id}" claims ${name}, which the package does not export`));
                claimedBy.set(name, [...(claimedBy.get(name) ?? []), id]);
            }
            if ((capability.since ?? '').includes('planned') && (capability.exports ?? []).length > 0) {
                out.push(error(SURFACES, `capability "${id}" is planned (${capability.since ?? ''}) but already claims ${(capability.exports ?? []).join(', ')}`));
            }
        }
        for (const e of exports) {
            if (e.kind === 'type') continue;
            const owners = claimedBy.get(e.name ?? '') ?? [];
            if (owners.length === 0) out.push(error(SURFACES, `${e.name ?? '?'} is exported and no capability claims it — the site would advertise a surface smaller than the package`));
            else if (owners.length > 1) out.push(error(SURFACES, `${e.name ?? '?'} is claimed by ${owners.join(' and ')}; exactly one capability owns each export`));
        }
        const version = manifest.value.packages?.pkinative?.version;
        if (surfaces.value.version !== version) out.push(error(SURFACES, `declares version ${String(surfaces.value.version)}; docs/assets/ecosystem.json says ${String(version)}`));
        return out;
    },
};

/**
 * The size of the public type surface, declared rather than discovered.
 *
 * `dist/index.d.ts` has the least headroom of anything pkinative ships,
 * and its weight is decided by how many types are exported — not by how
 * they are worded. A byte budget alone can therefore be raised release
 * after release without anyone noticing the surface doubled, which is the
 * failure this rule exists to make impossible: these two counts cannot
 * change by accident, and every change to one is a line in a diff.
 */
const typeSurfaceParity: Rule = {
    id: 'type-surface-parity',
    summary: 'declared.typeSurface of docs/assets/ecosystem.json counts exactly the exported types and values of docs/assets/api.json — the declaration file\'s byte budget can be raised, but not without the surface behind it being restated.',
    check(ctx) {
        const api = readJson<{ exports?: Array<{ kind: string }> }>(ctx, API_JSON);
        const manifest = readJson<{ declared?: { typeSurface?: { exportedTypes?: unknown; exportedValues?: unknown } } }>(ctx, MANIFEST);
        if ('finding' in api) return [api.finding];
        if ('finding' in manifest) return [manifest.finding];
        const declared = manifest.value.declared?.typeSurface;
        if (declared === undefined) return [error(MANIFEST, 'declared.typeSurface is missing — the declaration file would be budgeted in bytes alone')];

        const all = api.value.exports ?? [];
        const types = all.filter((e) => e.kind === 'type' || e.kind === 'interface').length;
        const values = all.length - types;
        const out: Finding[] = [];
        if (declared.exportedTypes !== types) out.push(error(MANIFEST, `declared.typeSurface.exportedTypes says ${String(declared.exportedTypes)}; ${API_JSON} has ${String(types)}`));
        if (declared.exportedValues !== values) out.push(error(MANIFEST, `declared.typeSurface.exportedValues says ${String(declared.exportedValues)}; ${API_JSON} has ${String(values)}`));
        return out;
    },
};

export const API_RULES: readonly Rule[] = [
    apiJsonSync, tsdocComplete, memberTsdoc, exportNamed, optionFieldsNamed, extensionKindsComplete, surfacesParity, typeSurfaceParity,
];
