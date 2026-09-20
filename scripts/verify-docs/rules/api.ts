/**
 * pkinative — public API rules
 * ============================
 * `api-json-sync`: docs/assets/api.json is what scripts/build-api-json.ts
 * produces from the current sources, byte for byte.
 * `tsdoc-complete`: every public export has a TSDoc summary, and every
 * public function documents each parameter, its return value and what it
 * throws (AGENTS.md §Conventions) — the manifest is only as honest as the
 * comments it is read from.
 * `member-tsdoc`: the interface members that still have no summary are
 * counted, and the count only ever goes down.
 *
 * @module scripts/verify-docs/rules/api
 */

import { documentationGaps, renderApiJson, type Reader } from '../../build-api-json.js';
import { error, readJson, type Rule, type RuleContext } from '../context.js';

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
    summary: 'The number of interface members of docs/assets/api.json without a TSDoc summary equals derived.undocumentedMembers in docs/assets/ecosystem.json exactly — a ratchet, so the debt can only fall, and only in a reviewed diff.',
    check(ctx) {
        const api = readJson<{ exports?: ReadonlyArray<{ members?: ReadonlyArray<{ summary?: unknown }> }> }>(ctx, API_JSON);
        if ('finding' in api) return [api.finding];
        const manifest = readJson<{ derived?: { undocumentedMembers?: unknown } }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];

        let undocumented = 0;
        for (const e of api.value.exports ?? []) {
            for (const member of e.members ?? []) if (typeof member.summary !== 'string' || member.summary === '') undocumented++;
        }
        const declared = manifest.value.derived?.undocumentedMembers;
        if (typeof declared !== 'number' || !Number.isInteger(declared) || declared < 0) {
            return [error(MANIFEST, 'derived.undocumentedMembers must be the number of interface members of api.json that have no summary')];
        }
        if (declared === undocumented) return [];
        const direction = undocumented < declared
            ? `${declared - undocumented} member(s) gained a summary — lower the count to ${undocumented} in the same commit, so the improvement is on the record`
            : `${undocumented - declared} member(s) lost one, or a new undocumented member shipped — an interface member with no summary is a field a caller cannot learn about from docs/assets/api.json`;
        return [error(MANIFEST, `derived.undocumentedMembers is ${declared}; api.json holds ${undocumented}: ${direction}`)];
    },
};

export const API_RULES: readonly Rule[] = [apiJsonSync, tsdocComplete, memberTsdoc];
