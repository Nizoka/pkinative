/**
 * pkinative — public API rules
 * ============================
 * `api-json-sync`: docs/assets/api.json is what scripts/build-api-json.ts
 * produces from the current sources, byte for byte.
 * `tsdoc-complete`: every public export has a TSDoc summary, and every
 * public function documents each parameter, its return value and what it
 * throws (AGENTS.md §Conventions) — the manifest is only as honest as the
 * comments it is read from.
 *
 * @module scripts/verify-docs/rules/api
 */

import { documentationGaps, renderApiJson, type Reader } from '../../build-api-json.js';
import { error, type Rule, type RuleContext } from '../context.js';

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

export const API_RULES: readonly Rule[] = [apiJsonSync, tsdocComplete];
