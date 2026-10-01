import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

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
        // A new workflow is a new holder of tokens and a new set of checks;
        // it must arrive with its own assertions in this file, not unseen.
        expect(workflowFiles).toEqual([
            'audit.yml',
            'bench.yml',
            'ci.yml',
            'codeql.yml',
            'conformance.yml',
            'dependency-review.yml',
            'docs.yml',
            'fuzz.yml',
            'publish.yml',
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
                // The comment must name a tag that EXISTS upstream, which is
                // why one component is allowed: ClusterFuzzLite publishes `v1`
                // and nothing else, and demanding three would force the
                // comment to invent a `v1.0.0` nobody could resolve. A
                // version comment that cannot be checked is worse than a
                // short one.
                expect(m[0], `${label}: ${ref} lacks a "# vX[.Y[.Z]]" comment`).toMatch(/#\s*v\d+(?:\.\d+){0,2}\s*$/);
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

/** The egress policy of a harden-runner step: `block` with its allow-list, or `audit` with the dated reason it is not blocked yet. */
function egressOf(step: string): { policy: 'block'; endpoints: string[] } | { policy: 'audit'; reason: string } | null {
    if (/egress-policy:\s*block\s*$/m.test(step)) {
        const list = /allowed-endpoints:\s*>\s*\n((?:[ \t]+[a-z0-9.-]+:\d+[ \t]*(?:\n|$))+)/.exec(step)?.[1] ?? '';
        return { policy: 'block', endpoints: list.split('\n').map((l) => l.trim()).filter((l) => l !== '') };
    }
    const audit = /egress-policy:\s*audit\s*#\s*(\d{4}-\d{2}-\d{2}:\s*\S.*)$/m.exec(step);
    return audit ? { policy: 'audit', reason: audit[1] } : null;
}

/**
 * The jobs whose egress is small and known, so they run in block mode
 * (audit P-06). Everything else stays in audit with a dated reason in the
 * file: the Windows and macOS legs (the vendor supports audit only there),
 * and the jobs whose hosts are not baselined yet.
 */
const BLOCKING_JOBS: Readonly<Record<string, readonly string[]>> = {
    'publish.yml': ['guard', 'build', 'publish', 'attest'],
    'audit.yml': ['audit'],
    'bench.yml': ['bench'],
    'dependency-review.yml': ['dependency-review'],
    'docs.yml': ['verify'],
};

/**
 * Workflows still carrying the macOS carve-out that the vendor README at the
 * pinned SHA contradicts (audit P-07). conformance.yml belongs to another
 * change set; once it drops the `if:`, this list empties and every assertion
 * below covers it too.
 */
const MACOS_CARVE_OUT_PENDING: readonly string[] = ['conformance.yml'];

describe('every workflow job', () => {
    it('should start with harden-runner, in block mode with an allow-list or in audit mode with a dated reason', () => {
        for (const f of workflowFiles) {
            const jobs = jobSteps(readWorkflow(f));
            expect(jobs.size, `${f}: no job with steps`).toBeGreaterThan(0);
            for (const [job, steps] of jobs) {
                expect(steps[0], `${f} › ${job}: first step`).toContain(HARDEN_RUNNER);
                if (MACOS_CARVE_OUT_PENDING.includes(f)) continue;
                const egress = egressOf(steps[0]);
                expect(egress, `${f} › ${job}: egress-policy must be "block" with allowed-endpoints, or "audit # YYYY-MM-DD: reason"`).not.toBeNull();
                if (egress?.policy === 'block') {
                    expect(egress.endpoints.length, `${f} › ${job}: block with no allowed endpoint`).toBeGreaterThan(0);
                    for (const e of egress.endpoints) expect(e, `${f} › ${job}`).toMatch(/^[a-z0-9.-]+:443$/);
                }
            }
        }
    });

    it('should block egress on every job whose endpoints are known', () => {
        for (const [f, blocking] of Object.entries(BLOCKING_JOBS)) {
            const jobs = jobSteps(readWorkflow(f));
            for (const job of blocking) {
                expect(egressOf(jobs.get(job)?.[0] ?? '')?.policy, `${f} › ${job}`).toBe('block');
            }
        }
    });

    it('should allow, in the release jobs, exactly the hosts each one reaches', () => {
        // The build job also fetches the corpora of scripts/lib/corpora.ts;
        // the publish job only uploads and signs. A host missing here breaks
        // the one run that cannot be repeated; a host added without a reason
        // is an exfiltration path next to the npm token.
        const jobs = jobSteps(readWorkflow('publish.yml'));
        const allowed = (job: string): string[] => {
            const egress = egressOf(jobs.get(job)?.[0] ?? '');
            return egress?.policy === 'block' ? [...egress.endpoints].sort() : [];
        };
        const SIGSTORE = ['fulcio.sigstore.dev:443', 'rekor.sigstore.dev:443', 'tuf-repo-cdn.sigstore.dev:443'];
        expect(allowed('guard')).toEqual(['api.github.com:443', 'github.com:443']);
        expect(allowed('build')).toEqual(['api.github.com:443', 'csrc.nist.gov:443', 'github.com:443', 'nodejs.org:443', 'raw.githubusercontent.com:443', 'registry.npmjs.org:443', 'www.rfc-editor.org:443']);
        expect(allowed('publish')).toEqual(['github.com:443', 'nodejs.org:443', 'registry.npmjs.org:443', ...SIGSTORE].sort());
        expect(allowed('attest')).toEqual(['api.github.com:443', 'github.com:443', 'nodejs.org:443', 'registry.npmjs.org:443', 'uploads.github.com:443', ...SIGSTORE].sort());
        // The corpus hosts are real: a corpus moved elsewhere must move here too.
        const corpora = readText('scripts', 'lib', 'corpora.ts');
        for (const host of ['csrc.nist.gov', 'www.rfc-editor.org', 'github.com/C2SP']) expect(corpora, host).toContain(`https://${host}/`);
    });

    it('should run harden-runner on macOS too: no platform carve-out', () => {
        // The vendor README at the pinned SHA lists GitHub-hosted Windows and
        // macOS runners as supported in audit mode (audit P-07); the former
        // "does not support macOS at all" exemption contradicted it.
        for (const f of workflowFiles.filter((x) => !MACOS_CARVE_OUT_PENDING.includes(x))) {
            const text = readWorkflow(f);
            expect(text, `${f}: harden-runner must be unconditional`).not.toMatch(/runner\.os\s*!=\s*'macOS'/);
            expect(text, f).not.toContain('does not support macOS');
            for (const [job, steps] of jobSteps(text)) expect(steps[0], `${f} › ${job}`).not.toMatch(/^\s+if:/m);
        }
        expect(readWorkflow('ci.yml')).toContain('macos-latest');
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

    it('should run on every pull request and push, with no path filter that could leave a required check pending', () => {
        // GitHub leaves the checks of a path-filtered workflow pending
        // forever, which blocks a docs-only pull request (audit P-02).
        expect(ci).not.toMatch(/^\s+paths(-ignore)?:/m);
        expect(ci).toMatch(/^on:\s*\n\s+push:\s*\n\s+branches: \[main, master\]\s*\n\s+pull_request:\s*\n\s+branches: \[main, master\]\s*$/m);
    });

    it('should report exactly the status checks the ruleset requires, on all three platforms', () => {
        // `name:` is what decides the check name, which is why renaming a job
        // here — or dropping the `name:` — would leave required checks pending
        // forever. Adding a platform must stay additive.
        expect(ci).toMatch(/^ {2}ci:\s*\n\s+name: \$\{\{ matrix\.name \}\}/m);
        expect(checkNames(ci).sort()).toEqual(['ci (22)', 'ci (24)', 'macos', 'windows']);
        expect(ci).toMatch(/^ {2}runtimes:\s*\n {4}name: runtimes\s*$/m);
        expect(ci).toMatch(/^ {2}workflow-lint:\s*\n {4}name: workflow lint\s*$/m);
        expect(contexts).toEqual(expect.arrayContaining(['ci (22)', 'ci (24)', 'windows', 'macos']));
        for (const os of ['ubuntu-latest', 'windows-latest', 'macos-latest']) expect(ci, os).toContain(`os: ${os}`);
        expect(ci).toMatch(/node-version: 22/);
        expect(ci).toMatch(/node-version: 24/);
    });

    it('should test, on Linux, the Node line the release is built and uploaded on', () => {
        // publish.yml builds and uploads on .nvmrc; CI must test that line.
        const pinned = readText('.nvmrc').trim();
        expect(ci).toMatch(new RegExp(`name: 'ci \\(${pinned}\\)', os: ubuntu-latest, node-version: ${pinned},`));
    });

    /** One job's text, from its head to the next job head. */
    const ciJob = (job: string): string =>
        new RegExp(`^  ${job}:\\s*\\n([\\s\\S]*?)(?=^  [A-Za-z0-9_-]+:\\s*$|(?![\\s\\S]))`, 'm').exec(ci)?.[1] ?? '';

    it('should smoke-test the built package on Deno, Bun and headless Chromium, with pinned runtimes', () => {
        const job = ciJob('runtimes');
        const order = ['run: npm run build', 'denoland/setup-deno@', 'oven-sh/setup-bun@', 'run: deno run .github/runtime-smoke/run.mjs', 'run: bun .github/runtime-smoke/run.mjs', 'node .github/runtime-smoke/browser.mjs']
            .map((needle) => job.indexOf(needle));
        expect(order.every((i) => i >= 0), String(order)).toBe(true);
        expect([...order].sort((a, b) => a - b)).toEqual(order);
        expect(job).toMatch(/deno-version: \d+\.\d+\.\d+\s*$/m);
        expect(job).toMatch(/bun-version: \d+\.\d+\.\d+\s*$/m);
        expect(job).toMatch(/no-cache: true/);
        for (const f of ['checks.mjs', 'run.mjs', 'browser.mjs']) expect(existsSync(join(ROOT, '.github', 'runtime-smoke', f)), f).toBe(true);
    });

    it('should lint the workflows with a pinned zizmor and a checksum-verified actionlint', () => {
        const job = ciJob('workflow-lint');
        expect(job).toMatch(/uses: zizmorcore\/zizmor-action@[0-9a-f]{40} # v\d/);
        expect(job).toMatch(/^\s+version: \d+\.\d+\.\d+\s*$/m);
        expect(job).toMatch(/min-severity: medium/);
        expect(job).toMatch(/ACTIONLINT_SHA256: [0-9a-f]{64}\s*$/m);
        const check = job.indexOf('sha256sum --check --strict');
        expect(check).toBeGreaterThan(0);
        expect(check).toBeLessThan(job.indexOf('/actionlint" -color'));
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
            expect(ciJob('ci'), step).not.toMatch(new RegExp(`run: (npm run )?${step.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm'));
        }
    });
});

describe('the main ruleset', () => {
    const ruleset = JSON.parse(readText('.github', 'rulesets', 'main.json')) as {
        rules: Array<{ type: string; parameters?: { required_status_checks?: Array<{ context: string; integration_id?: number }>; code_scanning_tools?: Array<Record<string, string>> } }>;
    };
    const contexts = ruleset.rules.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks ?? [];

    /** Every check a workflow reports: the matrix `name:` values, else the job `name:`, else the job id. */
    function reported(file: string): string[] {
        const text = readWorkflow(file);
        const out: string[] = [];
        for (const job of jobSteps(text).keys()) {
            const body = new RegExp(`^  ${job}:\\s*\\n([\\s\\S]*?)(?=^  [A-Za-z0-9_-]+:\\s*$|(?![\\s\\S]))`, 'm').exec(text)?.[1] ?? '';
            const name = /^ {4}name:\s*(.+?)\s*$/m.exec(body)?.[1] ?? job;
            if (name === '${{ matrix.name }}') out.push(...[...body.matchAll(/^\s+- \{ name: '?([^,']+)'?,/gm)].map((m) => m[1]));
            else out.push(name);
        }
        return out;
    }

    it('should require exactly the checks ci.yml, conformance.yml and dependency-review.yml report, all from GitHub Actions', () => {
        // Both directions: a required context nothing reports blocks every
        // pull request; a blocking job nobody requires is advisory in fact
        // (audit P-11: Dependency Review was described as blocking).
        const blocking = ['ci.yml', 'conformance.yml', 'dependency-review.yml'].flatMap(reported).sort();
        expect(contexts.map((c) => c.context).sort()).toEqual(blocking);
        for (const c of contexts) expect(c.integration_id, c.context).toBe(15368);
        for (const f of ['conformance.yml', 'dependency-review.yml']) expect(readWorkflow(f), f).not.toMatch(/^\s+paths(-ignore)?:/m);
    });

    it('should require CodeQL results (high security alerts and errors block), and waive signed commits in writing', () => {
        const scanning = ruleset.rules.find((r) => r.type === 'code_scanning')?.parameters?.code_scanning_tools ?? [];
        expect(scanning).toEqual([{ tool: 'CodeQL', security_alerts_threshold: 'high_or_higher', alerts_threshold: 'errors' }]);
        // Signed commits are a documented waiver, not an oversight: GitHub
        // checks every commit of the head branch, so one unsigned commit of a
        // first-time contributor would block the squash merge (audit P-14).
        expect(ruleset.rules.some((r) => r.type === 'required_signatures')).toBe(false);
        expect(readText('CONTRIBUTING.md')).toContain('**Signed commits are not required.**');
        // The code_scanning rule waits for results on every pull request and
        // its base, so CodeQL is never path-filtered; it reads the workflows
        // too (the `actions` language), not only the TypeScript.
        const codeql = readWorkflow('codeql.yml');
        expect(codeql).not.toMatch(/^\s+paths(-ignore)?:/m);
        expect(codeql).toMatch(/- \{ language: actions, build-mode: none \}/);
        expect(codeql).toMatch(/- \{ language: javascript-typescript, build-mode: none \}/);
        expect(codeql).not.toContain('autobuild');
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

/**
 * Whether a setup-node v6 step restores the npm cache, as the action decides
 * it — not whether the step happens to spell `cache: npm`. At the pinned SHA
 * the action's own input says: "By default, caching is enabled when either
 * devEngines.packageManager or the top-level packageManager field in
 * package.json specifies npm" and `package-manager-cache: false` turns it
 * off. The former test checked only for `cache: npm`, and passed while both
 * release jobs restored the cache (audit P-01).
 */
function npmCacheEnabled(step: string, pkg: { packageManager?: string; devEngines?: { packageManager?: { name?: string } } }): boolean {
    if (/^\s+cache:\s*['"]?npm['"]?\s*$/m.test(step)) return true;
    const automatic = (pkg.packageManager ?? '').startsWith('npm@') || pkg.devEngines?.packageManager?.name === 'npm';
    return automatic && !/^\s+package-manager-cache:\s*false\s*$/m.test(step);
}

describe('publish.yml', () => {
    const publish = readWorkflow('publish.yml');
    const jobs = jobSteps(publish);
    const pkg = JSON.parse(readText('package.json')) as { packageManager?: string; devEngines?: { packageManager?: { name?: string } } };

    /** The text of one job, from its head to the next job head. */
    const jobBody = (job: string): string =>
        new RegExp(`^  ${job}:\\s*\\n([\\s\\S]*?)(?=^  [A-Za-z0-9_-]+:\\s*$|(?![\\s\\S]))`, 'm').exec(publish)?.[1] ?? '';
    /** The permissions a job grants, trailing comments stripped, sorted. */
    const grants = (job: string): string[] => {
        const block = /^ {4}permissions:\s*\n((?: {6}[a-z-]+:[^\n]*\n)+)/m.exec(jobBody(job))?.[1] ?? '';
        return block.trim().split('\n').map((l) => l.replace(/#.*$/, '').trim()).sort();
    };
    /** The steps of one job, and the index of the first one containing `needle`. */
    const stepIndex = (job: string, needle: string | RegExp): number =>
        (jobs.get(job) ?? []).findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));

    it('should start from a pushed v* tag or a manual run, never from a published release', () => {
        // A published release is immutable once release immutability is on:
        // files are attached to the draft, which the maintainer publishes last.
        expect(publish).toMatch(/^on:\s*\n\s+push:\s*\n\s+tags: \['v\*'\]\s*\n\s+workflow_dispatch:\s*$/m);
        expect(publish).not.toMatch(/^\s+release:\s*$/m);
    });

    it('should mint an OIDC token and never read an NPM_TOKEN secret', () => {
        expect(publish).toMatch(/^\s*id-token:\s*write/m);
        expect(publish).not.toMatch(/secrets\.NPM_TOKEN/);
    });

    it('should run exactly four jobs: guard, then build, then publish, then attest', () => {
        expect([...jobs.keys()]).toEqual(['guard', 'build', 'publish', 'attest']);
        expect(jobBody('guard')).not.toMatch(/^\s*needs:/m);
        expect(jobBody('build')).toMatch(/^ {4}needs:\s*guard\s*$/m);
        expect(jobBody('publish')).toMatch(/^ {4}needs:\s*build\s*$/m);
        expect(jobBody('attest')).toMatch(/^ {4}needs:\s*\[build, publish\]\s*$/m);
    });

    it('should publish from the npm-publish environment, and only the publishing job, one release at a time', () => {
        expect([...publish.matchAll(/^\s*environment:/gm)]).toHaveLength(1);
        expect(jobBody('publish')).toMatch(/^ {4}environment:\s*npm-publish\s*$/m);
        expect(publish).toMatch(/concurrency:\s*\n\s*group:\s*publish\s*\n\s*cancel-in-progress:\s*false/);
    });

    it('should hold id-token: write only where nothing from the dev toolchain runs (audit P-04)', () => {
        expect(grants('guard')).toEqual(['contents: read']);
        expect(grants('build')).toEqual(['contents: read']);
        expect(grants('publish')).toEqual(['contents: read', 'id-token: write']);
        expect(grants('attest')).toEqual(['attestations: write', 'contents: write', 'id-token: write']);
        // The publishing job: no lockfile install, no repository script, no
        // gate, and a checkout of .nvmrc alone.
        const body = jobBody('publish');
        expect(body).not.toMatch(/npm ci|npm run |npx |scripts\/|npm install/);
        const checkouts = (jobs.get('publish') ?? []).filter((s) => s.includes('actions/checkout@'));
        expect(checkouts).toHaveLength(1);
        expect(checkouts[0]).toMatch(/sparse-checkout: \.nvmrc\s*$/m);
        expect(checkouts[0]).toMatch(/sparse-checkout-cone-mode: false/);
    });

    it('should refuse a pre-1.0 version in a guard job that no approval stands in front of', () => {
        // The defect this shape removes: a job carrying `environment:` asks
        // for an approval before its first step, so a refusal placed inside
        // it trained the maintainer to approve eight runs designed to fail.
        const guard = jobBody('guard');
        expect(guard).not.toMatch(/^\s*environment:/m);
        // Nothing to install and nothing to publish with: the guard reads a file.
        expect(guard).not.toMatch(/npm (ci|install|publish)|secrets\.|id-token/);
        const steps = jobs.get('guard') ?? [];
        const tag = stepIndex('guard', 'does not match package.json version');
        const pre1 = stepIndex('guard', 'Refuse a pre-1.0 publication');
        expect(steps).toHaveLength(4);
        expect([tag, pre1]).toEqual([2, 3]);
        expect(steps[pre1]).toMatch(/\[ "\$\{MAJOR\}" = "0" \][\s\S]*exit 1/);
        expect(steps[pre1]).toContain('pre-1.0 versions are git tags, never npm releases');
        expect(guard).toMatch(/^ {6}version:\s*\$\{\{ steps\.version\.outputs\.version \}\}\s*$/m);
    });

    it('should publish from a tag only: the guard refuses a branch before anything else', () => {
        const guard = jobBody('guard');
        expect(guard).toMatch(/if \[ "\$\{GITHUB_REF_TYPE\}" != "tag" \]; then\s*\n\s*echo "::error::publish runs from a v\* tag only[^\n]*\n\s*exit 1/);
        expect(guard.indexOf('!= "tag"')).toBeLessThan(guard.indexOf('Refuse a pre-1.0 publication'));
    });

    it('should restore no dependency cache in any release job — the effective setup-node behaviour, not a spelling', () => {
        const setups = [...jobs.values()].flat().filter((s) => s.includes('actions/setup-node@'));
        expect(setups.length).toBe(3);
        for (const step of setups) expect(npmCacheEnabled(step, pkg), step.split('\n')[0]).toBe(false);
        // The model itself: with packageManager naming npm, a step that is
        // silent about caching DOES restore the cache — what P-01 missed.
        expect(pkg.packageManager ?? '').toMatch(/^npm@/);
        expect(npmCacheEnabled('      - uses: actions/setup-node@x\n        with:\n          node-version-file: .nvmrc', pkg)).toBe(true);
        expect(npmCacheEnabled('      - uses: actions/setup-node@x\n        with:\n          node-version-file: .nvmrc', {})).toBe(false);
        expect(npmCacheEnabled('      - uses: actions/setup-node@x\n        with:\n          cache: npm\n          package-manager-cache: false', pkg)).toBe(true);
    });

    it('should build, test and upload on the .nvmrc Node line, the one CI tests', () => {
        for (const job of ['build', 'publish', 'attest']) {
            const setup = (jobs.get(job) ?? []).find((s) => s.includes('actions/setup-node@')) ?? '';
            expect(setup, job).toMatch(/node-version-file:\s*\.nvmrc/);
            expect(setup, job).not.toMatch(/^\s+node-version:/m);
        }
        const pinned = readText('.nvmrc').trim();
        expect(readWorkflow('ci.yml')).toMatch(new RegExp(`os: ubuntu-latest, node-version: ${pinned},`));
    });

    it('should confirm, before anything is installed, that the version it builds is the one the guard passed', () => {
        const steps = jobs.get('build') ?? [];
        const confirm = stepIndex('build', 'Confirm the guarded version');
        const install = stepIndex('build', 'run: npm ci --ignore-scripts');
        expect(confirm).toBeGreaterThanOrEqual(0);
        expect(confirm).toBeLessThan(install);
        expect(steps[confirm]).toContain('GUARDED: ${{ needs.guard.outputs.version }}');
        expect(steps[confirm]).toMatch(/\[ "\$\{VERSION\}" != "\$\{GUARDED\}" \] \|\| \[ "\$\{VERSION%%\.\*\}" = "0" \][\s\S]*exit 1/);
        expect([...jobs.values()].flat().filter((s) => s.includes('Refuse a pre-1.0 publication'))).toHaveLength(1);
    });

    it('should run the publish gate with --require-all, then pack once and hand the tarball on with its digests', () => {
        const gate = stepIndex('build', 'run: npx tsx scripts/gate.ts --publish --require-all');
        const dry = stepIndex('build', 'run: npm pack --dry-run');
        const pack = stepIndex('build', 'Pack the tarball and record its digests');
        const upload = stepIndex('build', 'actions/upload-artifact@');
        expect([gate, dry, pack, upload].every((i) => i >= 0)).toBe(true);
        expect(gate).toBeLessThan(dry);
        expect(dry).toBeLessThan(pack);
        expect(pack).toBeLessThan(upload);
        const packStep = (jobs.get('build') ?? [])[pack];
        expect(packStep).toMatch(/sha256sum "\$\{RUNNER_TEMP\}\/release\/\$\{TARBALL\}"/);
        expect(packStep).toMatch(/INTEGRITY="sha512-\$\(openssl dgst -sha512 -binary/);
        for (const out of ['tarball', 'sha256', 'integrity']) expect(jobBody('build')).toMatch(new RegExp(`^ {6}${out}: \\$\\{\\{ steps\\.pack\\.outputs\\.${out} \\}\\}\\s*$`, 'm'));
        for (const hand of ['npm run test:coverage', 'npm run typecheck:all', 'npm run verify:docs']) expect(publish, hand).not.toContain(`run: ${hand}`);
    });

    it('should upload exactly the handed-on tarball, after checking both digests and its version, with a client pinned by content', () => {
        const body = jobBody('publish');
        const receive = stepIndex('publish', 'actions/download-artifact@');
        const verify = stepIndex('publish', 'Verify the tarball against the build job');
        const client = stepIndex('publish', 'Fetch and verify the pinned npm client');
        const upload = stepIndex('publish', /publish "\.\/\$\{TARBALL\}"/);
        expect([receive, verify, client, upload].every((i) => i >= 0)).toBe(true);
        expect(receive).toBeLessThan(verify);
        expect(verify).toBeLessThan(upload);
        expect(client).toBeLessThan(upload);
        const steps = jobs.get('publish') ?? [];
        expect(steps[verify]).toContain('sha256sum --check --strict');
        expect(steps[verify]).toContain('= "${INTEGRITY}"');
        expect(steps[verify]).toMatch(/tar -xzOf "\$\{TARBALL\}" package\/package\.json/);
        expect(steps[upload]).toMatch(/run: node "\$\{RUNNER_TEMP\}\/npm-client\/package\/bin\/npm-cli\.js" publish "\.\/\$\{TARBALL\}" --provenance --access public\s*$/m);
        // The client: an exact 11.x at least 11.5.1 (Trusted Publishing),
        // whose registry tarball must equal a recorded SHA-512 before it runs.
        const version = /^ {6}NPM_CLIENT_VERSION: (\d+)\.(\d+)\.(\d+)\s*$/m.exec(body);
        expect(version).not.toBeNull();
        const [major, minor, patch] = (version ?? []).slice(1).map(Number);
        expect(major === 11 && (minor > 5 || (minor === 5 && patch >= 1))).toBe(true);
        expect(body).toMatch(/^ {6}NPM_CLIENT_INTEGRITY: sha512-[A-Za-z0-9+/]{86}==\s*$/m);
        expect(steps[client]).toMatch(/test "sha512-\$\(openssl dgst -sha512 -binary npm-client\.tgz \| base64 -w0\)" = "\$\{NPM_CLIENT_INTEGRITY\}"/);
        expect(steps[client].indexOf('NPM_CLIENT_INTEGRITY')).toBeLessThan(steps[client].indexOf('tar -xzf'));
        expect(publish).not.toMatch(/npm install -g/);
    });

    it('should attest the bytes npm serves, checked against the build digests and the registry signatures', () => {
        // Fetching the tarball back makes the attested file the published
        // file by construction; comparing it with the build job's digests
        // makes it the file the gate checked.
        const attest = jobBody('attest');
        const fetch = stepIndex('attest', 'Fetch the published tarball and check it against the build');
        const signatures = stepIndex('attest', 'npm audit signatures');
        const provenance = stepIndex('attest', 'actions/attest-build-provenance@');
        expect([fetch, signatures, provenance].every((i) => i >= 0)).toBe(true);
        expect(fetch).toBeLessThan(signatures);
        expect(signatures).toBeLessThan(provenance);
        const steps = jobs.get('attest') ?? [];
        expect(steps[fetch]).toMatch(/npm pack "pkinative@\$\{VERSION\}"/);
        expect(steps[fetch]).toContain('sha256sum --check --strict');
        expect(steps[fetch]).toMatch(/test "\$\(npm view "pkinative@\$\{VERSION\}" dist\.integrity\)" = "\$\{INTEGRITY\}"/);
        expect(attest).not.toMatch(/run: npm run build|run: npm ci/);
        expect(attest).not.toMatch(/^\s*run: npm pack\s*$/m);
    });

    it('should write the runtime SBOMs (CycloneDX and SPDX, empty by design) and the toolchain SBOM, and attest all of them', () => {
        const attest = jobBody('attest');
        expect(attest).toContain('npm sbom --sbom-format cyclonedx --omit dev --package-lock-only > "pkinative-${VERSION}.cdx.json"');
        expect(attest).toContain('npm sbom --sbom-format spdx --omit dev --package-lock-only > "pkinative-${VERSION}.spdx.json"');
        expect(attest).toContain('npm sbom --sbom-format cyclonedx --package-lock-only > "pkinative-${VERSION}.toolchain.cdx.json"');
        const subjects = /subject-path: \|\s*\n((?:\s+pkinative-[^\n]+\n?)+)/.exec(attest)?.[1].trim().split('\n').map((l) => l.trim());
        expect(subjects).toEqual(['pkinative-${{ env.VERSION }}.tgz', 'pkinative-${{ env.VERSION }}.cdx.json', 'pkinative-${{ env.VERSION }}.spdx.json', 'pkinative-${{ env.VERSION }}.toolchain.cdx.json']);
    });

    it('should attach the files and the Sigstore bundle to a DRAFT release only, never replacing an asset', () => {
        const attach = (jobs.get('attest') ?? []).find((s) => s.includes('gh release upload')) ?? '';
        expect(attach).toContain('BUNDLE: ${{ steps.attest.outputs.bundle-path }}');
        expect(attach).toContain('cp "${BUNDLE}" "pkinative-${VERSION}.sigstore.json"');
        expect(attach).toMatch(/--json isDraft --jq \.isDraft/);
        expect(attach).toMatch(/elif \[ "\$\{DRAFT\}" != "true" \]; then\s*\n\s*echo "::warning::/);
        for (const f of ['.tgz', '.cdx.json', '.spdx.json', '.toolchain.cdx.json', '.sigstore.json']) expect(attach).toContain(`"pkinative-\${VERSION}${f}"`);
        expect(publish).not.toContain('--clobber');
        expect(publish).not.toMatch(/gh release (create|edit|delete)/);
    });

    it('should state the provenance level exactly: SLSA Build L2, with L3 discussed in its ADR', () => {
        expect(publish).toContain('SLSA Build L2');
        expect(publish).not.toMatch(/SLSA Level 2\+/);
        expect(publish).toContain('docs/adr/0019-release-integrity-slsa-build-l2.md');
        expect(existsSync(join(ROOT, 'docs', 'adr', '0019-release-integrity-slsa-build-l2.md'))).toBe(true);
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

    it('should hold every Dependabot ecosystem back seven days, and move the actions as one group', () => {
        const dependabot = readText('.github', 'dependabot.yml');
        const blocks = dependabot.split(/^ {2}- package-ecosystem: /m).slice(1);
        expect(blocks.map((b) => b.split('\n')[0].trim()).sort()).toEqual(['docker', 'github-actions', 'npm']);
        for (const block of blocks) {
            const days = /cooldown:\s*\n\s+default-days: (\d+)/.exec(block)?.[1];
            expect(Number(days), block.split('\n')[0]).toBeGreaterThanOrEqual(7);
        }
        const actions = blocks.find((b) => b.startsWith('github-actions')) ?? '';
        expect(actions).toMatch(/groups:\s*\n\s+actions:\s*\n\s+patterns:\s*\n\s+- "\*"/);
        expect(blocks.find((b) => b.startsWith('docker'))).toMatch(/directory: \/\.clusterfuzzlite/);
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

// ── Runtime smoke checks ─────────────────────────────────────────────

describe('.github/runtime-smoke/checks.mjs', () => {
    type Smoke = { runChecks: (m: unknown) => Promise<string[]> };
    const load = async (): Promise<Smoke> => (await import(pathToFileURL(join(ROOT, '.github', 'runtime-smoke', 'checks.mjs')).href)) as Smoke;

    it('should pass against the sources, so a red runtimes job means the runtime, not the checks', async () => {
        // CI runs the same file against dist/ on Deno, Bun and Chromium; here
        // it runs against src/ on every gate run, the way the fuzz targets
        // are held (tests/fuzzing/targets.test.ts).
        const lines = await (await load()).runChecks(await import('../../src/index.js'));
        expect(lines).toHaveLength(5);
    });

    it('should fail loudly when the package under test misbehaves', async () => {
        const real = await import('../../src/index.js');
        await expect((await load()).runChecks({ ...real, verifySelfSignature: async () => false })).rejects.toThrow(/runtime smoke: X1/);
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
