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
 *
 * @module scripts/verify-docs/rules/api
 */

import { documentationGaps, renderApiJson, type Reader } from '../../build-api-json.js';
import { error, readJson, type Rule, type RuleContext } from '../context.js';

const API_JSON = 'docs/assets/api.json';

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

export const API_RULES: readonly Rule[] = [apiJsonSync, tsdocComplete, memberTsdoc];
