# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Versions below 1.0.0 are git tags and are not published to npm.

## [Unreleased]

### Added

- **chore: bootstrap** — build (tsup ESM + CJS + declarations, a single entry point with `browser`, `import` and `require` conditions), three strict tsconfigs, ESLint 9, vitest 4 with coverage thresholds, the quality gate (`scripts/gate.ts`), the documentation and governance verifier (`scripts/verify-docs.ts` with one module per rule family and a perturbation test per rule), the architecture test that enforces the layer table and the syntactic conventions from the syntax tree, hardened CI on Linux and Windows, CodeQL, Scorecard, Dependency Review, weekly audit, an inert pre-1.0 publish workflow, rulesets, the human-in-the-loop AI governance policy, the Claude Code guard hook and generated rules, and the contributor documentation.

## [0.0.1] – 2026-09-15

Name reservation on npm. The package contains no code.
