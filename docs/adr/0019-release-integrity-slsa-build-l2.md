---
status: accepted
date: 2026-10-01
since: 1.0.0
---

# Release integrity at SLSA Build L2: the job that builds cannot publish, and L3 is deferred

## Context and Problem Statement

From 1.0.0 every npm version of pkinative is built and uploaded by [.github/workflows/publish.yml](../../.github/workflows/publish.yml), through npm Trusted Publishing: the workflow's OIDC identity, not a stored token, authorises the upload and signs npm's provenance statement. Until the pre-publication audit of 1.0.0, one job did everything — it held `id-token: write`, installed the whole dev toolchain from the lockfile, ran the publish gate over it (vitest, tsup, esbuild, eslint, tsx, publint, attw), fetched the conformance corpora from three hosts, and then uploaded. The workflow called itself "SLSA Level 2+", restored the shared npm cache in both release jobs while its comment said it did not (setup-node v6 enables the cache by itself when `package.json` declares `packageManager`), and attached its files to a GitHub Release after publication — which a repository with release immutability turned on refuses.

The question is what pkinative can honestly promise about how a release is produced, and how the workflow should be shaped so that the promise is true.

## Decision Drivers

- **The level must be stated exactly.** SLSA v1.1 Build L2 asks for a hosted build platform that generates and signs the provenance itself; Build L3 asks the platform to "prevent runs from influencing one another, even within the same project" and to "prevent secret material used to sign the provenance from being accessible to the user-defined build steps" ([slsa.dev/spec/v1.1/levels](https://slsa.dev/spec/v1.1/levels)). "Level 2+" claims more than either sentence supports.
- **The publishing token must not sit next to dev-dependency code.** Under Trusted Publishing, `id-token: write` in a job is sufficient to publish pkinative. A compromised dev dependency running in that job can request the token: the npm CLI itself obtains it from the job's environment, as a plain run step.
- **The upload is irreversible.** A version, once published, can never be reused ([npm-publish](https://docs.npmjs.com/cli/v11/commands/npm-publish)). Every check that can run before the upload must run before it, and the run must not depend on a cache other workflows wrote.
- **Attested bytes must be the published bytes.** A tarball rebuilt in another job is the published one only if the build is byte-for-byte reproducible, which pkinative does not claim.
- **Immutable releases.** GitHub: "Once you publish a release as immutable, its assets can't be added, modified, or deleted", and the documented order is draft, attach, publish ([changelog, 2025-10-28](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/)).
- **One maintainer, no infrastructure.** Whatever is chosen runs on GitHub-hosted runners, with no second repository and no service to operate.

## Considered Options

1. Keep one publishing job, fix the cache and the wording only.
2. Split the release into a build job without `id-token` and a publishing job that holds it and runs no repository code, handing the tarball over with its digests; state SLSA Build L2.
3. Move build and attestation into a reusable workflow (GitHub's documented route to Build L3 with artifact attestations, [Increase security rating](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating)), or adopt the SLSA GitHub generator.

## Decision Outcome

Chosen option: **2**, and the level stated is **SLSA Build L2**.

`publish.yml` now runs four jobs. `guard` reads `package.json` and refuses a non-tag ref, a tag that disagrees with the version, and any version below 1.0.0, before any approval is asked. `build` holds `contents: read` only: it runs `npm ci --ignore-scripts`, fetches the pinned corpora, runs `scripts/gate.ts --publish --require-all`, packs the tarball once and hands it on as an artifact, with its SHA-256 and its SHA-512 integrity travelling as job outputs, outside the artifact they describe. `publish` is the only job that can mint the npm token, behind the `npm-publish` environment the Trusted Publishing entry names (`attest` also holds `id-token: write`, to sign its Sigstore attestation, but never enters that environment): it checks out `.nvmrc` and nothing else, verifies both digests and the version inside the tarball, fetches an npm client pinned by the SHA-512 of its registry tarball, and uploads that exact file (`npm publish ./pkinative-X.Y.Z.tgz --provenance`, a form [npm documents](https://docs.npmjs.com/cli/v11/commands/npm-publish): "a gzipped tarball containing (a)"). `attest` fetches the tarball back from the registry, checks it against the same digests and with `npm audit signatures`, writes the SBOMs, attests them with Sigstore build provenance and attaches them, with the Sigstore bundle, to the **draft** release, which the maintainer publishes last. No release job restores a dependency cache: every `setup-node` step says `package-manager-cache: false`. Every release job runs `harden-runner` in block mode with the hosts it reaches.

Build L3 is **not** claimed. The `build` job no longer sees the signing identity, but the provenance npm signs is still produced by a job of the same workflow, on the same runner pool, that the project's own YAML defines; GitHub documents L3 through a reusable workflow whose identity the attestation names. That is option 3, deferred, not refused.

### Consequences

- Good, because a compromised dev dependency can no longer mint the token that publishes pkinative: the code that runs the toolchain and the job that can publish are different jobs on different runners.
- Good, because the uploaded bytes are provably the gated bytes (two digests checked before upload) and provably the served bytes (the registry's integrity and the file's SHA-256 checked after), with no reproducible-build assumption.
- Good, because the release carries `pkinative-X.Y.Z.sigstore.json` next to the tarball, so the release itself is verifiable offline, and the files are attached before the release becomes immutable.
- Good, because the SBOMs say plainly what they cover: the runtime CycloneDX and SPDX documents are empty by design — pkinative has no runtime dependency — and `pkinative-X.Y.Z.toolchain.cdx.json` records the dev packages that built `dist/`. npm writes CycloneDX 1.5 and SPDX 2.3; nothing claims ECMA-424, which specifies a later CycloneDX.
- Bad, because the workflow is longer, and a release now crosses an artifact store between two jobs; the digests in job outputs are what make that crossing checkable.
- Bad, because the trigger moves from a published release to a pushed tag: the maintainer drafts the release first and publishes it after the run, one more manual step in [CONTRIBUTING.md §Release](../../CONTRIBUTING.md#release).
- Neutral, because none of this had executed when it was written: the repository had no pushed history, and the first release tag is the first run.

### Confirmation

`tests/tools/workflows.test.ts` holds the shape: four jobs in order, `id-token: write` only in `publish` and `attest`, no lockfile install, script or gate in `publish`, the effective setup-node cache behaviour computed from `package.json` rather than from the spelling `cache: npm`, the digest checks before the upload and after the registry fetch, the content-pinned npm client, the draft-only attachment without overwrite, block-mode egress with the exact host list of each release job, and the wording "SLSA Build L2". The `workflow lint` check of `ci.yml` runs zizmor and actionlint on every pull request, and CodeQL analyses the `actions` language.

## More Information

- Reaching L3 means moving `build` and `attest` into a reusable workflow called from `publish.yml`, so that the attestation names the reusable workflow's identity, and keeping the npm upload as it is. It is revisited when a second maintainer joins or when npm accepts provenance from such a workflow without loss of the Trusted Publishing binding.
- [SECURITY.md §Release integrity](../../SECURITY.md#release-integrity) is the user-facing account of the same design, with the verification commands.
- Audit findings P-01, P-04, P-10, P-15 and P-16 of the 1.0.0 pre-publication audit are what this record answers.
