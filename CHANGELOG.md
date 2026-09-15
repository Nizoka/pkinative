# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Versions below 1.0.0 are git tags and are not published to npm.

## [Unreleased]

### Added

- **feat(core): errors, limits and diagnostics** — the `PkiError` family (`PkiEncodingError`, `PkiCertificateError`, `PkiLimitError`) with a stable `code` from typed unions, registered in `docs/data/errors.json`; eleven CWE-tagged `PkiLimits` with `DEFAULT_PKI_LIMITS`, mirrored in `docs/data/limits.json` and SECURITY.md; the single diagnostics channel (`strict`, `onDiagnostic`, once-per-code `console.warn`) with one payload factory per code, registered in `docs/data/diagnostics.json`; strict UTF-8, UCS-2, UCS-4 and ASCII-subset text codecs; canonical base64. `verify:docs` gains `error-parity` (including the message prefix of every throw site), `diagnostics-parity` and `limits-parity`.

- **chore: bootstrap** — build (tsup ESM + CJS + declarations, a single entry point with `browser`, `import` and `require` conditions), three strict tsconfigs, ESLint 9, vitest 4 with coverage thresholds, the quality gate (`scripts/gate.ts`), the documentation and governance verifier (`scripts/verify-docs.ts` with one module per rule family and a perturbation test per rule), the architecture test that enforces the layer table and the syntactic conventions from the syntax tree, hardened CI on Linux and Windows, CodeQL, Scorecard, Dependency Review, weekly audit, an inert pre-1.0 publish workflow, rulesets, the human-in-the-loop AI governance policy, the Claude Code guard hook and generated rules, and the contributor documentation.

## [0.0.1] – 2026-09-15

Name reservation on npm. The package contains no code.
