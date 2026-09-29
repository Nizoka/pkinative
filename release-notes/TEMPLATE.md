# Release Notes Template

This directory contains release notes for each tagged version of `pkinative`.

## File naming

- One file per version: `release-notes/vMAJOR.MINOR.PATCH.md`
- Examples: `v0.1.0.md`, `v0.3.0.md`, `v1.0.0.md`

## Template

Copy the content below into a new `release-notes/vX.Y.Z.md` file and fill in the sections. Omit any section that has no entries for the release (do not leave empty sections).

```markdown
# pkinative vX.Y.Z

<!-- GitHub Release title: vX.Y.Z — short description -->

_Released YYYY-MM-DD_

<!-- One-paragraph summary: what is this release about (milestone / bugfix / feature / security) and compatibility statement (e.g. "100% backward-compatible with vX.Y.Z-1", or the pre-1.0 API changes). -->

## Highlights

<!-- 2–5 bullets calling out the most user-visible changes. Link to detailed sections below where useful. -->

- ...

## Security

<!-- CWE reference, affected versions, mitigation. Keep this section first when present. -->

- **fix(security):** ...

## Breaking Changes

<!-- Each entry must include: what changed, why, migration path. -->

- **BREAKING:** ...

## Added

<!-- New features, new public API, new error codes, new limits. Use conventional commit scopes: feat(asn1), feat(x509), feat(pem), feat(core), etc. -->

- **feat(scope):** ...

## Changed

<!-- Non-breaking behaviour changes, strictness changes, metadata updates, internal refactors with user-visible effects. -->

- **refactor(scope):** ...

## Fixed

<!-- Bug fixes. Reference GitHub issues (#NN) where applicable. -->

- **fix(scope):** ... ([#NN]).

## Deprecated

- **deprecate(scope):** `oldApi()` — use `newApi()` instead. Will be removed in vX+1.0.0.

## Removed

- **remove(scope):** ... (deprecated in vX.Y.Z).

## Performance

<!-- Benchmark deltas with measurement methodology. -->

- **perf(scope):** reduced X by N% (measured via `npm run bench` on Node 24.x, a 150-certificate CA bundle, median of 5 runs).

## Conformance

<!-- Corpus pins, counts, expectation changes and why. -->

- ...

## Documentation

- **docs(scope):** ...

## Known limitations

<!-- What this version deliberately does not do yet, and the milestone that will. -->

- ...

## Install

<!-- The registry is the install, with npm provenance; the GitHub release carries the same
     tarball, fetched back from the registry and attested by publish.yml. Never a git URL:
     a git install carries no dist/. -->

\`\`\`bash
npm install pkinative@X.Y.Z
npm audit signatures
\`\`\`

## Upgrade

<!-- Step-by-step migration if non-trivial. -->

No breaking changes. Drop-in replacement for vX.Y.Z-1.

## Downstream integration notes

<!-- Every new, removed or changed public API, error code, diagnostic, limit default or behaviour shift, and the package it affects. -->

- ...

## Contributors

Thanks to @handle1, @handle2 for contributions to this release.

## Links

- [CHANGELOG](../CHANGELOG.md)
- [Full diff](https://github.com/Nizoka/pkinative/compare/vX.Y.Z-1...vX.Y.Z)
- [Roadmap](../ROADMAP.md)
```

## Conventions

- **GitHub Release title.** Use `vX.Y.Z — short description` (3–5 words) as the GitHub Release title, not the bare version number. The H1 of this file stays `# pkinative vX.Y.Z` for direct Markdown rendering; the descriptive title is only for the GitHub Releases UI.
- **SemVer classification first.** Decide MAJOR / MINOR / PATCH before writing the note; it determines which sections apply. Before 1.0.0 a minor may change the API and says how under Downstream integration notes.
- **Mirror `CHANGELOG.md`.** Each release note must have a corresponding entry in `CHANGELOG.md`. Bullets should match (the CHANGELOG is the canonical per-line record; the release note adds narrative framing).
- **Conventional commit scopes.** Prefix bullets with `fix(scope):`, `feat(scope):`, `chore(scope):`, `perf(scope):`, etc. Common scopes: `core`, `asn1`, `pem`, `oid`, `hash`, `x509`, `conformance`, `docs`, `meta`, `build`, `ci`.
- **No emojis** in release notes (per project coding conventions).
- **Security section first** when a release contains security fixes — always include the CWE identifier and mitigation.
- **Code blocks** for install commands and migration examples only.
- **Backward-compatibility statement** in the summary paragraph for every release.
- **Install honesty.** The Install section installs from npm and names `npm audit signatures`; never a git URL, which carries no `dist/`. Versions below 1.0.0 are git tags only and have no install.

## Publication workflow

1. Draft `release-notes/vX.Y.Z.md` on the release branch.
2. Mirror the bullets into `CHANGELOG.md` under a new `## [X.Y.Z] – YYYY-MM-DD` section.
3. Bump the version (CONTRIBUTING.md §Release).
4. Open PR → merge to `main`.
5. The maintainer tags `vX.Y.Z` and publishes a GitHub Release with title `vX.Y.Z — short description`; the release note body is the Release description.
6. From 1.0.0, `publish.yml` fires on "Release published" → npm package with provenance.
