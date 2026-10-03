---
status: accepted
date: 2026-10-01
since: 1.0.0
---

# Runtime and toolchain support for 1.x: Node.js LTS lines with a patched floor, TypeScript 5.0 on a two-year window, ES2020

## Context and Problem Statement

Up to 1.0.0, `package.json` declared `engines.node: ">=22"` and nothing else. No document said which Node.js lines pkinative supports, what happens when one reaches its end of life inside 1.x, which TypeScript versions can compile its declaration file, or which ECMAScript edition the build targets. Each of these becomes a promise the day 1.0.0 is installed: under the default reading of semver, a floor raised without a written policy is a breaking change.

Four facts frame the decision, each checked at its source on 2026-10-01:

- **The Node.js release schedule** ([nodejs/Release `schedule.json`](https://github.com/nodejs/Release/blob/main/schedule.json)): Node 22 reaches its end of life on **2027-04-30**, Node 24 on 2028-04-30; Node 26 enters long-term support on 2026-10-28. Node 22 therefore leaves support in the middle of the 1.x line.
- **CVE-2026-21713** ([Node.js March 2026 security releases](https://nodejs.org/en/blog/vulnerability/march-2026-security-releases)): HMAC verification in Node's Web Crypto compared the MAC with C's `memcmp`, a timing side channel (Medium); 20.x, 22.x, 24.x and 25.x were affected, and the fix shipped in **22.22.2, 24.14.1 and 25.8.2** (and 20.20.2). pkinative reaches that code: `verifyMac` in `src/crypto/webcrypto.ts` calls `subtle.verify({ name: 'HMAC' }, …)` for the RFC 9579 PBMAC1 MAC of every PKCS#12 file `openPkcs12` opens. The later Web Crypto fix of June 2026, CVE-2026-48933, is in `subtle.encrypt()`, which pkinative never calls (`KEY_OPERATION_POLICY` refuses `encrypt` forever); the July 2026 release fixed nothing in Web Crypto.
- **TypeScript**: the 1.0.0 audit compiled a consumer against `dist/index.d.ts` with `skipLibCheck: false`. TypeScript 4.7.4 to 5.9.3 compile it under `moduleResolution: node10` and `node16`; `moduleResolution: bundler` exists only from TypeScript 5.0, which [introduced it](https://devblogs.microsoft.com/typescript/announcing-typescript-5-0/) on 2023-03-16. The measurement was repeated on this tree with TypeScript 4.9.5 and 5.0.4. The [semver-ts specification](https://www.semver-ts.org/formal-spec/5-compiler-considerations.html) asks a package to "adopt and clearly specify one of two support policies: *simple majors* or *rolling support windows*".
- **Other runtimes**: the README says that browsers, Deno, Bun and Cloudflare Workers run the same build. Since the 1.0.0 audit the `runtimes` job of `.github/workflows/ci.yml` — a required check — executes the built package on Deno, Bun and headless Chromium: one parse, one signature verification per family and one PKCS#12 opened (`.github/runtime-smoke/`). Workers are executed by nothing. What is also checked is static: `scripts/lib/bundle-probe.ts` refuses a `node:` import in the bundle, and `tests/tools/architecture.test.ts` refuses `process`, `Buffer`, `Deno`, `Bun` and every other host-specific global in `src/`.

## Decision Drivers

- A floor that moves must be able to move without a major release when the upstream line it follows is gone; otherwise Node 22's end of life in April 2027 forces either 2.0 or support of an unpatched runtime.
- A security library should state the runtime it is safe on, and pkinative delegates its MAC and signature checks to the host's Web Crypto.
- A promise is worth what checks it: a supported runtime is a tested runtime.
- `engines` is advice to npm, not a lock: npm refuses an install outside the range only under `engine-strict`, and warns otherwise.
- The browsers a security-sensitive caller targets are not pkinative's to choose; the ECMAScript edition of the build is.

## Considered Options

1. **Simple majors**: every floor — Node, TypeScript, ECMAScript — is fixed for 1.x, and raising one is semver-major.
2. **Rolling windows tied to upstream support**: Node follows its LTS schedule, TypeScript a published age window, and the ECMAScript edition stays fixed; each move is a minor, announced in advance.
3. **No written policy**, as at 0.x.

## Decision Outcome

Chosen option: 2. Option 1 binds pkinative to Node 22 until 2.0, beyond its end of life, or forces a major for a change that breaks nobody still on a supported runtime. Option 3 is what the audit found missing.

### Node.js

- **Supported lines**: every Node.js line in Active LTS or Maintenance LTS on the day of a pkinative release. At 1.0.0 these are 22 and 24, and CI runs both; Node 26 joins when it enters LTS. A Current (odd-numbered or not yet LTS) line is not supported and not refused; since the amendment below it is *tested*: the advisory `node-current` workflow runs the CI gate on it, and `contracts.support.currentLines` names it.
- **Dropping a line after its end-of-life date is semver-minor.** It is announced in the Downstream integration notes of the minor before the one that drops it. The first 1.x minor after 2027-04-30 may raise the floor to Node 24.
- **The floor within a line** is the first release of that line that fixes every known vulnerability in a Web Crypto operation pkinative calls: at 1.0.0, `^22.22.2 || ^24.14.1 || >=25.8.2`, the CVE-2026-21713 fixes. Raising it for a later such vulnerability is semver-minor and names the CVE in the release note. A host vulnerability pkinative does not reach does not move the floor, and the deployer should run the latest security release of their line regardless.

### TypeScript

- **Floor: TypeScript 5.0**, the first version that compiles the declaration file under every `moduleResolution` mode a consumer may use: `node16`/`nodenext`, `bundler` and, for CommonJS, `node10`.
- **Rolling window**: a minor may raise the floor, never to a TypeScript release younger than two years on the day of the pkinative release, the window [DefinitelyTyped](https://github.com/DefinitelyTyped/DefinitelyTyped#support-window) uses; the release note announces it. A TypeScript patch release found broken may be dropped by documenting it, as semver-ts allows.

### ECMAScript and host APIs

- **The build targets ES2020** (`target: 'es2020'` in `tsup.config.ts`, `lib: ["ES2020"]` in `tsconfig.json`) for the whole of 1.x. Raising the syntax target or the library is semver-major: a browser that runs 1.0 keeps running every 1.x.
- **Host APIs**: `globalThis.crypto.subtle` for every signature, key and PKCS#12 operation (in a browser, a secure context), `globalThis.crypto` for the asynchronous digests, and `TextDecoder`. Nothing else from the host; `canVerify()` reports whether Web Crypto is there.

### Runtimes beyond Node.js

Deno, Bun and browsers are **smoke-tested, not fully tested**: the `runtimes` job runs a smoke test of the built package on Deno, Bun and headless Chromium at pinned versions, while the full suite runs on Node.js only; no version floor is promised for them. Cloudflare Workers are a **target, not a tested runtime**: the build is platform-neutral by construction and checked statically, and no gate executes it there. A defect found on any of them is a bug, fixed like any other.

### Consequences

- Good, because Node 22's end of life in April 2027 is a minor release announced in advance, not a major or an unpatched runtime.
- Good, because the floor states the runtime on which pkinative's PKCS#12 MAC check is constant-time, and a caller reading `engines` learns it.
- Good, because a TypeScript consumer can tell from one sentence whether their compiler is supported, and a check holds the floor.
- Bad, because a caller pinned to a Node line past its end of life must stay on the last 1.x minor that supported it, and gets no fix after it.
- Bad, because a patch-level `engines` floor warns users of older patch releases of a supported line at install, which some will read as noise.
- Bad, because outside Node.js only a smoke test runs, on Deno, Bun and headless Chromium, and Workers rest on static checks only; a runtime defect the smoke test does not reach is found by a user, not by the gate.

### Confirmation

- `node-pin-parity` holds `.nvmrc`, `.node-version`, every `setup-node` step and the CI matrix to the major of `engines.node`.
- `contracts-shape` holds `docs/assets/ecosystem.json` → `contracts.support` to `package.json` (`engines.node`), to `tsup.config.ts` (the target), to the CI matrix (the supported lines), to this record and to SECURITY.md §Supported runtimes and compilers.
- `npx tsx scripts/check-ts-floor.ts` packs the build, installs it next to the TypeScript floor named in `contracts.support.typescript`, and compiles a consumer of every export under `node16`, `bundler` and `node10`, and once more without the DOM library and with `exactOptionalPropertyTypes`. On the 1.0.0 tree it passes at 5.0.4 and fails at 4.9.5, under `bundler` only. It needs the registry, so it belongs to the publish profile of the gate, not to the hermetic ones.
- `scripts/lib/bundle-probe.ts` and `tests/tools/architecture.test.ts` keep the build free of Node-only imports and globals.

## More Information

- [SECURITY.md §Supported runtimes and compilers](../../SECURITY.md#supported-runtimes-and-compilers) — the policy as a user reads it.
- [ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md) — the rest of what 1.x promises.
- [Node.js releases](https://nodejs.org/en/about/previous-releases) and `https://nodejs.org/dist/index.json` — the security releases of each line.

## Amendments

- **2026-10-03, before the first publication.** Node 26 is Current until 2026-10-28 and the release note cannot wait for a calendar. The policy gains one state between "not refused" and "supported": a Current line is **tested and not promised** — the `node-current` workflow (`.github/workflows/node-current.yml`) runs the CI gate on it for every push and pull request, is required by no ruleset, and `contracts.support.currentLines` in `docs/assets/ecosystem.json` names it, so that `contracts-shape` holds the workflow, the manifest and SECURITY.md together. On its LTS date the line moves from `currentLines` to `nodeLines`, joins the `ci.yml` matrix and the required checks, and gets its floor in `engines.node` — a one-commit change with a history of green runs behind it. **The decision is unchanged:** supported means Active or Maintenance LTS, and nothing about a Current line is promised.
