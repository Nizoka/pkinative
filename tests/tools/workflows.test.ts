import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// ── Workflow, supply-chain and contributor invariants ─────────────────
//
// None of this is visible to the type checker or to the test suite proper:
// a floating action tag, a checkout that keeps the job token, a release job
// that quietly publishes a pre-1.0 version, an npm client that drifts between
// two publishes, a runtime dependency slipped into package.json. Each is
// locked here as a plain-text assertion on the files that carry it
// (pdfnative 1.8.0 doctrine).

const ROOT = process.cwd();
const WORKFLOWS = join(ROOT, '.github', 'workflows');
const workflowFiles = readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml')).sort();
/**
 * Every assertion below is a multi-line regex over file text. A working copy
 * checked out with CRLF endings would mismatch all of them silently — passing
 * for the wrong reason — so the line endings are normalised on the way in.
 */
const lf = (text: string): string => text.replace(/\r\n/g, '\n');
const readWorkflow = (f: string): string => lf(readFileSync(join(WORKFLOWS, f), 'utf8'));
const readText = (...parts: string[]): string => lf(readFileSync(join(ROOT, ...parts), 'utf8'));

const HARDEN_RUNNER = 'step-security/harden-runner@';

/** Every `- name:`/`- uses:` step block of every job, in order, keyed by job id. */
function jobSteps(text: string): Map<string, string[]> {
    const jobs = new Map<string, string[]>();
    const jobsAt = text.search(/^jobs:\s*$/m);
    if (jobsAt < 0) return jobs;
    let job: string | null = null;
    let steps: string[] | null = null;
    for (const line of text.slice(jobsAt).split('\n').slice(1)) {
        const jobHead = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
        if (jobHead) { job = jobHead[1]; steps = null; continue; }
        if (/^ {4}steps:\s*$/.test(line) && job) { steps = []; jobs.set(job, steps); continue; }
        if (steps === null) continue;
        if (/^ {6}- /.test(line)) steps.push(line);
        else if (/^ {8,}\S/.test(line) && steps.length > 0) steps[steps.length - 1] += `\n${line}`;
    }
    return jobs;
}

// ── Actions: pinned, hardened, credential-free ───────────────────────

describe('every workflow', () => {
    const allFiles = workflowFiles.map((f) => ({ label: f, text: readWorkflow(f) }));

    it('should be exactly the expected set of workflow files', () => {
        // ci.yml and docs.yml carry mutually exclusive `paths` filters: a tenth
        // workflow could shadow one of them without any other test noticing.
        expect(workflowFiles).toEqual([
            'audit.yml',
            'ci.yml',
            'codeql.yml',
            'conformance.yml',
            'dependency-review.yml',
            'docs.yml',
            'publish.yml',
            'release-assets.yml',
            'scorecard.yml',
        ]);
    });

    it('should resolve every action to a single SHA across the whole tree', () => {
        // A partially merged bump — upload-artifact v4 in ci.yml, v7 in
        // publish.yml — pins one workflow to code the others never run.
        const pins = new Map<string, Map<string, string[]>>();
        for (const { label, text } of allFiles) {
            for (const m of text.matchAll(/^\s*(?:- )?uses:\s*([^@\s]+)@([0-9a-f]{40})/gm)) {
                // The codeql-action entry points ship from one repository at one release.
                const action = m[1].startsWith('github/codeql-action/') ? 'github/codeql-action' : m[1];
                const shas = pins.get(action) ?? new Map<string, string[]>();
                shas.set(m[2], [...(shas.get(m[2]) ?? []), label]);
                pins.set(action, shas);
            }
        }
        expect(pins.size, 'no pinned action found').toBeGreaterThan(0);
        for (const [action, shas] of pins) {
            const spread = [...shas].map(([sha, where]) => `${sha} (${[...new Set(where)].join(', ')})`);
            expect(spread, `${action} is pinned to more than one SHA`).toHaveLength(1);
        }
    });

    it('should pin every action to a 40-hex commit SHA with a version comment', () => {
        for (const { label, text } of allFiles) {
            const uses = [...text.matchAll(/^\s*(?:- )?uses:\s*(\S+)[^\n]*$/gm)];
            expect(uses.length, `${label} declares no action`).toBeGreaterThan(0);
            for (const m of uses) {
                const ref = m[1];
                if (ref.startsWith('./')) continue; // local composite action
                expect(ref, `${label}: ${ref}`).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
                expect(m[0], `${label}: ${ref} lacks a "# vX.Y.Z" comment`).toMatch(/#\s*v\d+\.\d+\.\d+\s*$/);
            }
        }
    });

    it('should disable persist-credentials on every actions/checkout step', () => {
        for (const { label, text } of allFiles) {
            const re = /uses: actions\/checkout@[^\n]*\n((?:[ \t]+[^\n]*\n)*)/g;
            let m: RegExpExecArray | null;
            while ((m = re.exec(text)) !== null) {
                const block = m[1].split('\n').filter((l) => l.trim() !== '' && !/^\s+- /.test(l));
                expect(block.some((l) => /persist-credentials:\s*false/.test(l)), `${label}: checkout keeps credentials`).toBe(true);
            }
        }
    });

    it('should declare read-only workflow-level permissions (writes only at job level) and a timeout on every job', () => {
        for (const { label, text } of allFiles) {
            const top = /^permissions:[ \t]*(\S.*)?\n((?:[ \t]+\S[^\n]*\n)*)/m.exec(text);
            expect(top, `${label}: no workflow-level permissions`).not.toBeNull();
            if (top?.[1] !== undefined) {
                expect(top[1].trim(), label).toBe('read-all');
            } else {
                const grants = (top?.[2] ?? '').split('\n').map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'));
                expect(grants.length, `${label}: empty permissions block`).toBeGreaterThan(0);
                for (const grant of grants) expect(grant, `${label}: workflow-level write`).toMatch(/^[a-z-]+:\s*read$/);
            }
            for (const job of jobSteps(text).keys()) {
                const body = new RegExp(`^  ${job}:\\s*\\n([\\s\\S]*?)(?=^  [A-Za-z0-9_-]+:\\s*$|(?![\\s\\S]))`, 'm').exec(text)?.[1] ?? '';
                expect(body, `${label} › ${job}`).toMatch(/timeout-minutes:\s*\d+/);
            }
        }
    });
});

describe('every workflow job', () => {
    it('should start with harden-runner in audit mode', () => {
        for (const f of workflowFiles) {
            const jobs = jobSteps(readWorkflow(f));
            expect(jobs.size, `${f}: no job with steps`).toBeGreaterThan(0);
            for (const [job, steps] of jobs) {
                expect(steps[0], `${f} › ${job}: first step`).toContain(HARDEN_RUNNER);
                expect(steps[0], `${f} › ${job}: egress policy`).toMatch(/egress-policy:\s*audit/);
            }
        }
    });

    it('should install dependencies with --ignore-scripts', () => {
        for (const f of workflowFiles) {
            for (const m of readWorkflow(f).matchAll(/run: npm ci\b[^\n]*/g)) {
                expect(m[0], `${f}`).toContain('npm ci --ignore-scripts');
            }
        }
    });
});

// ── The gate is the only definition of green ─────────────────────────

describe('ci.yml', () => {
    const ci = readWorkflow('ci.yml');
    const ruleset = JSON.parse(readText('.github', 'rulesets', 'main.json')) as {
        rules: Array<{ type: string; parameters?: { required_status_checks?: Array<{ context: string }> } }>;
    };
    const contexts = ruleset.rules.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks?.map((c) => c.context) ?? [];

    /** Every `name:` of a matrix include — the status-check names GitHub reports. */
    const checkNames = (text: string): string[] => [...text.matchAll(/^\s+- \{ name: '?([^,']+)'?,/gm)].map((m) => m[1]);

    it('should report exactly the status checks the ruleset requires, on all three platforms', () => {
        // `name:` is what decides the check name, which is why renaming a job
        // here — or dropping the `name:` — would leave required checks pending
        // forever. Adding a platform must stay additive.
        expect(ci).toMatch(/^ {2}ci:\s*\n\s+name: \$\{\{ matrix\.name \}\}/m);
        expect(checkNames(ci).sort()).toEqual(['ci (22)', 'ci (24)', 'macos', 'windows']);
        expect(contexts).toEqual(expect.arrayContaining(['ci (22)', 'ci (24)', 'windows', 'macos']));
        for (const os of ['ubuntu-latest', 'windows-latest', 'macos-latest']) expect(ci, os).toContain(`os: ${os}`);
        expect(ci).toMatch(/node-version: 22/);
        expect(ci).toMatch(/node-version: 24/);
    });

    it('should run the gate with --require-all once, for every platform, and audit only once', () => {
        // One job now, so one gate invocation in the file — and `npm audit` is
        // guarded, because four identical network calls are four chances to go
        // red for a reason that is not this repository's.
        expect([...ci.matchAll(/run: npx tsx scripts\/gate\.ts --ci --require-all/g)]).toHaveLength(1);
        expect(ci).toMatch(/if: matrix\.audit\s*\n\s+run: npm audit --audit-level=high/);
        expect(checkNames(ci).length, 'the gate runs once per matrix entry').toBe(4);
        expect(ci).toMatch(/if: failure\(\)[\s\S]*upload-artifact[\s\S]*test-output\/\.gate\//);
    });

    it('should list no gate step by hand', () => {
        for (const step of ['typecheck:all', 'test:coverage', 'check:package', 'verify:docs', 'npm run build', 'npm run lint', 'npm test']) {
            expect(ci, step).not.toMatch(new RegExp(`run: (npm run )?${step.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm'));
        }
    });
});

describe('conformance.yml', () => {
    const conformance = readWorkflow('conformance.yml');
    const ruleset = JSON.parse(readText('.github', 'rulesets', 'main.json')) as {
        rules: Array<{ type: string; parameters?: { required_status_checks?: Array<{ context: string }> } }>;
    };
    const contexts = ruleset.rules.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks?.map((c) => c.context) ?? [];

    it('should report the checks the ruleset requires, on all three platforms, with no path filter that could leave one pending', () => {
        expect(conformance).toMatch(/^ {2}conformance:\s*\n\s+name: \$\{\{ matrix\.name \}\}/m);
        const names = [...conformance.matchAll(/^\s+- \{ name: ([a-z-]+),/gm)].map((m) => m[1]).sort();
        expect(names).toEqual(['conformance', 'conformance-macos', 'conformance-windows']);
        for (const name of names) expect(contexts, name).toContain(name);
        expect(conformance).not.toMatch(/^\s+paths(-ignore)?:/m);
    });

    it('should force bash where the step is a shell script, so the Windows runner does not use PowerShell', () => {
        const summary = conformance.indexOf('GITHUB_STEP_SUMMARY');
        expect(summary).toBeGreaterThan(0);
        expect(conformance.slice(0, summary)).toMatch(/shell: bash\s*\n\s+run: \|[^]*$/);
    });

    it('should build, fetch the pinned corpora and run the gate with --require-all', () => {
        const build = conformance.indexOf('run: npm run build');
        const fetch = conformance.indexOf('run: npm run conformance:fetch');
        const gate = conformance.indexOf('run: npx tsx scripts/validate-certs.ts --require-all');
        expect(build).toBeGreaterThan(0);
        expect(fetch).toBeGreaterThan(build);
        expect(gate).toBeGreaterThan(fetch);
    });
});

describe('release-assets.yml', () => {
    const assets = readWorkflow('release-assets.yml');

    it('should gate, pack, prove the install, attest and attach the tarball of every pre-1.0 release, in that order', () => {
        const order = [
            'does not match package.json version',
            'run: npm run conformance:fetch',
            'run: npx tsx scripts/gate.ts --publish --require-all',
            'npm sbom --sbom-format cyclonedx --omit dev --package-lock-only',
            'npx tsx scripts/smoke-install.ts',
            'uses: actions/attest-build-provenance@',
            'gh release upload "v${VERSION}"',
        ].map((needle) => assets.indexOf(needle));
        expect(order.every((i) => i >= 0)).toBe(true);
        expect([...order].sort((a, b) => a - b)).toEqual(order);
        expect(assets).not.toMatch(/gh release create|npm publish/);
    });

    it('should act only on versions below 1.0.0, which publish.yml refuses', () => {
        expect(assets).toMatch(/if \[ "\$\{VERSION%%\.\*\}" = "0" \]/);
        expect([...assets.matchAll(/if: steps\.version\.outputs\.prerelease == 'true'/g)].length).toBeGreaterThanOrEqual(7);
    });
});

describe('publish.yml', () => {
    const publish = readWorkflow('publish.yml');
    const jobs = jobSteps(publish);

    it('should mint an OIDC token and never read an NPM_TOKEN secret', () => {
        expect(publish).toMatch(/^\s*id-token:\s*write/m);
        expect(publish).not.toMatch(/secrets\.NPM_TOKEN/);
    });

    it('should publish from the npm-publish environment, one release at a time', () => {
        expect(publish).toMatch(/^\s*environment:\s*npm-publish\s*$/m);
        expect(publish).toMatch(/concurrency:\s*\n\s*group:\s*publish\s*\n\s*cancel-in-progress:\s*false/);
    });

    it('should pin the npm client to one exact 11.x release, at least 11.5.1, before publishing', () => {
        const pins = [...publish.matchAll(/npm install -g npm@(\S+)/g)].map((m) => m[1]);
        expect(pins).toHaveLength(1);
        expect(pins[0]).toMatch(/^\d+\.\d+\.\d+$/);
        const [major, minor, patch] = pins[0].split('.').map(Number);
        expect(major === 11 && (minor > 5 || (minor === 5 && patch >= 1))).toBe(true);
        expect(publish).toContain(`test "$(npm --version)" = "${pins[0]}"`);
        expect(publish.indexOf('npm install -g npm@')).toBeLessThan(publish.indexOf('run: npm publish'));
    });

    it('should build on the .nvmrc Node line and publish with provenance', () => {
        expect(publish).toMatch(/node-version-file:\s*\.nvmrc/);
        expect(publish).toMatch(/run: npm publish --provenance --access public\s*$/m);
        expect(publish).toMatch(/run: npm pack --dry-run/);
    });

    it('should verify the tag against package.json, then refuse a pre-1.0 version before anything else runs', () => {
        const steps = jobs.get('publish') ?? [];
        const index = (needle: string | RegExp): number => steps.findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));
        const tag = index('does not match package.json version');
        const pre1 = index('Refuse a pre-1.0 publication');
        const npmPin = index('npm install -g npm@');
        const gate = index('run: npx tsx scripts/gate.ts --publish --require-all');
        expect([tag, pre1, npmPin, gate].every((i) => i >= 0)).toBe(true);
        expect(tag).toBeLessThan(pre1);
        expect(pre1).toBeLessThan(npmPin);
        expect(steps[pre1]).toMatch(/\[ "\$\{MAJOR\}" = "0" \][\s\S]*exit 1/);
    });

    it('should run the publish gate with --require-all before packing and publishing, and list no gate step by hand', () => {
        const steps = jobs.get('publish') ?? [];
        const index = (needle: string | RegExp): number => steps.findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));
        const gate = index('run: npx tsx scripts/gate.ts --publish --require-all');
        const pack = index('run: npm pack --dry-run');
        const pub = index(/run: npm publish/);
        expect([gate, pack, pub].every((i) => i >= 0)).toBe(true);
        expect(gate).toBeLessThan(pack);
        expect(pack).toBeLessThan(pub);
        for (const hand of ['npm run test:coverage', 'npm run typecheck:all', 'npm run verify:docs']) {
            expect(publish, hand).not.toContain(`run: ${hand}`);
        }
    });

    it('should have an attest job with exactly three permissions that attests the tarball and the SBOM', () => {
        const attest = /^ {2}attest:\s*\n([\s\S]*?)(?=^ {2}[a-z-]+:\s*$|(?![\s\S]))/m.exec(publish);
        expect(attest).not.toBeNull();
        const body = attest?.[1] ?? '';
        expect(body).toMatch(/needs:\s*publish/);
        const perms = /permissions:\s*\n((?:\s{6}[a-z-]+:\s*\w+\s*\n)+)/.exec(body);
        expect(perms).not.toBeNull();
        const granted = (perms?.[1] ?? '').trim().split('\n').map((l) => l.trim()).sort();
        expect(granted).toEqual(['attestations: write', 'contents: write', 'id-token: write']);
        expect(body).toMatch(/npm sbom --sbom-format cyclonedx --omit dev --package-lock-only/);
        expect(body).toMatch(/uses: actions\/attest-build-provenance@[0-9a-f]{40}/);
        expect(body).toMatch(/gh release view "v\$\{VERSION\}"[\s\S]*gh release upload "v\$\{VERSION\}"[^\n]*--clobber/);
        expect(body).not.toMatch(/gh release create/);
    });

    it('should list the endpoints for the future block policy', () => {
        for (const host of ['api.github.com', 'codeload.github.com', 'registry.npmjs.org', 'raw.githubusercontent.com', 'fulcio.sigstore.dev', 'rekor.sigstore.dev', 'tuf-repo-cdn.sigstore.dev']) {
            expect(publish).toContain(host);
        }
    });
});

// ── package.json: zero runtime dependencies, one export, provenance ──

describe('package.json', () => {
    const pkg = JSON.parse(readText('package.json')) as {
        version: string;
        sideEffects?: unknown;
        exports?: Record<string, unknown>;
        publishConfig?: Record<string, unknown>;
        scripts: Record<string, string>;
        engines?: { node?: string };
        [key: string]: unknown;
    };

    it('should declare no runtime, peer, optional or bundled dependency', () => {
        for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies']) {
            expect(pkg[field], field).toBeUndefined();
        }
    });

    it('should promise no side effects and expose one entry point with browser → import → require conditions', () => {
        expect(pkg.sideEffects).toBe(false);
        expect(Object.keys(pkg.exports ?? {}).sort()).toEqual(['.', './package.json']);
        expect(Object.keys((pkg.exports?.['.'] ?? {}) as Record<string, unknown>)).toEqual(['browser', 'import', 'require']);
    });

    it('should declare public access with provenance', () => {
        expect(pkg.publishConfig).toEqual({ access: 'public', provenance: true });
    });

    it('should expose the opt-in git hooks', () => {
        expect(pkg.scripts['hooks:install']).toBe('node scripts/install-git-hooks.mjs');
        expect(pkg.scripts['hooks:uninstall']).toBe('node scripts/install-git-hooks.mjs --uninstall');
        expect(existsSync(join(ROOT, '.githooks', 'pre-commit'))).toBe(true);
        expect(existsSync(join(ROOT, '.githooks', 'pre-push'))).toBe(true);
    });
});

// ── Dependency hygiene ───────────────────────────────────────────────

describe('dependency review and audit', () => {
    it('should review every pull request for high vulnerabilities and licences', () => {
        const review = readWorkflow('dependency-review.yml');
        expect(review).toMatch(/^on:\s*\n\s*pull_request:/m);
        expect(review).toMatch(/uses: actions\/dependency-review-action@[0-9a-f]{40}/);
        expect(review).toMatch(/fail-on-severity:\s*high/);
        expect(review).toMatch(/allow-licenses:\s*MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, 0BSD, CC0-1.0, Unlicense/);
        expect(review).toMatch(/comment-summary-in-pr:\s*on-failure/);
    });

    it('should audit the lockfile weekly', () => {
        const audit = readWorkflow('audit.yml');
        expect(audit).toMatch(/schedule:\s*\n\s*- cron:/);
        expect(audit).toMatch(/workflow_dispatch:/);
        expect(audit).toMatch(/run: npm ci --ignore-scripts/);
        expect(audit).toMatch(/run: npm audit --audit-level=high/);
    });

    it('should carry the contributor defaults in .npmrc, .node-version and .gitattributes', () => {
        expect(readText('.npmrc')).toBe('ignore-scripts=true\nfund=false\naudit-level=high\n');
        expect(readText('.node-version')).toBe('22\n');
        expect(readText('.gitattributes')).toMatch(/^\* text=auto eol=lf$/m);
        expect(readText('.gitattributes')).toMatch(/^\*\.der\s+binary$/m);
    });

    it('should protect release tags with a ruleset', () => {
        const tags = JSON.parse(readText('.github', 'rulesets', 'tags.json')) as {
            target: string; conditions: { ref_name: { include: string[] } }; rules: Array<{ type: string }>;
        };
        expect(tags.target).toBe('tag');
        expect(tags.conditions.ref_name.include).toEqual(['refs/tags/v*']);
        expect(tags.rules.map((r) => r.type).sort()).toEqual(['deletion', 'non_fast_forward', 'update']);
    });
});

// ── Contributor checklist parity ─────────────────────────────────────

describe('pull request template', () => {
    it('should list the gate and the same items as CONTRIBUTING.md', () => {
        const template = readText('.github', 'pull_request_template.md');
        const contributing = readText('CONTRIBUTING.md');
        const section = /## Pull Request Checklist\s*\n([\s\S]*?)\n## /.exec(contributing);
        expect(section).not.toBeNull();
        const items = (section?.[1] ?? '').split('\n').filter((l) => l.startsWith('- [ ]'));
        expect(items.length).toBeGreaterThan(5);
        // Links are rewritten to reach CONTRIBUTING.md from .github/; the wording is identical.
        const normalise = (s: string): string => s.replace(/\]\((?:\.\.\/CONTRIBUTING\.md)?#/g, '](#');
        for (const item of items) expect(normalise(template), item.slice(0, 60)).toContain(normalise(item));
        const templateItems = template.split('\n').filter((l) => l.startsWith('- [ ]'));
        expect(templateItems.map(normalise).sort()).toEqual(items.map(normalise).sort());
        expect(template).toMatch(/`npm run gate` passes/);
        for (const mention of ['ROADMAP.md', 'release-notes/vX.Y.Z.md', 'Downstream integration notes']) {
            expect(template).toContain(mention);
        }
    });
});
