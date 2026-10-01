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
import { ADR_RULES } from './adr.js';
import { API_RULES } from './api.js';
import { BENCH_RULES } from './bench.js';
import { CONFORMANCE_RULES } from './conformance.js';
import { CONTRACT_RULES } from './contracts.js';
import { COVERAGE_RULES } from './coverage.js';
import { CVE_RULES } from './cve.js';
import { FREEZE_RULES } from './freeze.js';
import { PACKAGE_RULES } from './package.js';
import { GOVERNANCE_RULES } from './governance.js';
import { PROSE_RULES } from './prose.js';
import { REGISTRY_RULES } from './registries.js';
import { SITE_RULES } from './site.js';
import { CURRENCY_RULES } from './currency.js';
import { VERSION_RULES } from './versions.js';

export const RULES: readonly Rule[] = [...VERSION_RULES, ...GOVERNANCE_RULES, ...REGISTRY_RULES, ...API_RULES, ...FREEZE_RULES, ...CONTRACT_RULES, ...PACKAGE_RULES, ...CONFORMANCE_RULES, ...BENCH_RULES, ...COVERAGE_RULES, ...CVE_RULES, ...SITE_RULES, ...ADR_RULES, ...PROSE_RULES, ...CURRENCY_RULES];
