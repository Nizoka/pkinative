/**
 * pkinative — the verify-docs rule table
 * =======================================
 * Every rule `scripts/verify-docs.ts` runs, in report order. Adding a rule
 * means adding its perturbation to tests/docs/verify-docs.test.ts in the same
 * commit — the suite fails on a rule without one.
 *
 * @module scripts/verify-docs/rules
 */

import type { Rule } from '../context.js';
import { GOVERNANCE_RULES } from './governance.js';
import { PROSE_RULES } from './prose.js';
import { VERSION_RULES } from './versions.js';

export const RULES: readonly Rule[] = [...VERSION_RULES, ...GOVERNANCE_RULES, ...PROSE_RULES];
