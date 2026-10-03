/**
 * pkinative — the schema version of the machine registries
 * ========================================================
 * Every registry under `docs/data/` carries `schemaVersion` as its first
 * field after `$comment`, so that a consumer can refuse a shape it does not
 * know before reading it. ADR 0018 §The wire form: the registries are
 * additions-only, and the version is `1` throughout 1.x — it moves only with
 * a change of meaning, which 1.x never makes. The writers of the generated
 * registries (`build-errors-frozen.ts`, `build-refusals-frozen.ts`,
 * `package-files.ts`) and the verify-docs rule `registry-schema-version`
 * share this one constant.
 *
 * @module scripts/lib/registry-schema
 */

/** The schema version of every `docs/data/*.json` registry in 1.x. */
export const REGISTRY_SCHEMA_VERSION = 1;
