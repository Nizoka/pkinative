/**
 * pkinative — governance rules
 * =============================
 * The rules that keep the agent-facing contract honest: the always-loaded
 * files stay within budget, the governance manifest names files that exist,
 * the Node pins agree, the rulesets require checks that real jobs report,
 * the Claude Code settings, hook and generated rules match their sources,
 * the PR template mirrors CONTRIBUTING.md, text blobs are LF, skills are
 * well-formed and the layer diagram equals the enforced layer table.
 *
 * @module scripts/verify-docs/rules/governance
 */

import { basename } from 'node:path';
import {
    INSTRUCTIONS_DIR,
    RULES_DIR,
    checkAgentConfigParity,
    checkClaudeRulesBudget,
    checkEol,
    checkNodeVersionPin,
    checkPrTemplateParity,
    checkSkillShape,
    checkTagRuleset,
    diffRules,
} from '../../lib/agent-config.js';
import { checkLayerParity } from '../../lib/architecture.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

// ── Workflow parsing (shared by node-pin-parity and ruleset-parity) ──

export interface WorkflowJob {
    readonly file: string;
    readonly id: string;
    readonly name: string | null;
    /** Matrix axis → values (quotes stripped); an `include:` contributes every key it sets. */
    readonly matrix: Readonly<Record<string, readonly string[]>>;
    /** One `include:` entry per element, as key → value. */
    readonly include: ReadonlyArray<Readonly<Record<string, string>>>;
    /** The status-check names GitHub will report for this job. */
    readonly checkNames: readonly string[];
}

const unquote = (value: string): string => value.trim().replace(/^["']|["']$/g, '');

/**
 * What GitHub calls each run of a job.
 *
 * `name:` wins over the job id, and when it interpolates a matrix key, every
 * `include:` entry supplies one name. Getting this wrong is not cosmetic: a
 * required check whose name no job reports leaves every pull request pending
 * for ever, which is the failure `ruleset-parity` exists to prevent.
 */
function checkNamesOf(job: { id: string; name: string | null; matrix: Record<string, string[]>; include: Array<Record<string, string>> }): string[] {
    const interpolated = /^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$/.exec(job.name ?? '');
    if (interpolated !== null) {
        const key = interpolated[1];
        const names = job.include.map((entry) => entry[key]).filter((v): v is string => v !== undefined);
        return names.length > 0 ? names : [];
    }
    if (job.name !== null) return [job.name];
    const axes = Object.entries(job.matrix).filter(([, values]) => values.length > 0);
    if (axes.length === 0) return [job.id];
    // GitHub joins the axis values, in declaration order: `ci (22)`.
    let combinations: string[][] = [[]];
    for (const [, values] of axes) combinations = combinations.flatMap((prefix) => values.map((v) => [...prefix, v]));
    return combinations.map((values) => `${job.id} (${values.join(', ')})`);
}

/** The jobs of a workflow file: id, optional `name:`, matrix axes and `include:` entries. */
export function workflowJobs(file: string, text: string): WorkflowJob[] {
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const start = lines.findIndex((l) => /^jobs:\s*$/.test(l));
    if (start < 0) return [];
    const jobs: Array<{ file: string; id: string; name: string | null; matrix: Record<string, string[]>; include: Array<Record<string, string>> }> = [];
    let inMatrix = false;
    for (const line of lines.slice(start + 1)) {
        const head = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
        if (head) {
            jobs.push({ file, id: head[1], name: null, matrix: {}, include: [] });
            inMatrix = false;
            continue;
        }
        const job = jobs[jobs.length - 1];
        if (!job) continue;
        const name = /^ {4}name:\s*(.+?)\s*$/.exec(line);
        if (name) job.name = unquote(name[1]);
        if (/^ {6}matrix:\s*$/.test(line)) {
            inMatrix = true;
            continue;
        }
        if (inMatrix) {
            const axis = /^ {8}([\w-]+):\s*\[(.*)\]\s*$/.exec(line);
            const entry = /^ {10}- \{(.+)\}\s*$/.exec(line);
            if (axis) job.matrix[axis[1]] = axis[2].split(',').map(unquote).filter((v) => v.length > 0);
            else if (entry) {
                // `- { name: 'ci (22)', os: ubuntu-latest, … }`. A value that
                // itself holds a comma would need a YAML parser; none does,
                // and a plain axis list is the alternative.
                const pairs: Record<string, string> = {};
                for (const pair of entry[1].split(',')) {
                    const at = pair.indexOf(':');
                    if (at < 0) continue;
                    const key = pair.slice(0, at).trim();
                    const value = unquote(pair.slice(at + 1));
                    pairs[key] = value;
                    job.matrix[key] = [...(job.matrix[key] ?? []), value];
                }
                job.include.push(pairs);
            } else if (!/^ {8,}/.test(line) && line.trim() !== '') inMatrix = false;
        }
    }
    return jobs.map((job) => ({ ...job, checkNames: checkNamesOf(job) }));
}

function workflowFiles(ctx: RuleContext): Array<{ file: string; text: string }> {
    return ctx.list('.github/workflows')
        .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
        .map((file) => ({ file, text: ctx.read(file) ?? '' }));
}

// ── Rules ────────────────────────────────────────────────────────────

const LINE_LIMIT = 240;

const claudeMdBudget: Rule = {
    id: 'claude-md-budget',
    summary: 'CLAUDE.md and AGENTS.md stay within 120 lines, CLAUDE.md imports AGENTS.md first, the Copilot file within 16 KiB, no line over 240 characters.',
    check(ctx) {
        const out: Finding[] = [];
        const claude = ctx.read('CLAUDE.md');
        const agents = ctx.read('AGENTS.md');
        const copilot = ctx.read('.github/copilot-instructions.md');
        if (claude === null) out.push(error('CLAUDE.md', 'missing — Claude Code loads it on every session'));
        if (agents === null) out.push(error('AGENTS.md', 'missing — the editor-agnostic agent guide'));
        if (copilot === null) out.push(error('.github/copilot-instructions.md', 'missing — the canonical detail AGENTS.md points to'));
        if (claude !== null && claude.replace(/\r\n/g, '\n').split('\n')[0] !== '@AGENTS.md') {
            out.push(error('CLAUDE.md', 'the first line must be `@AGENTS.md` — CLAUDE.md is an addendum to AGENTS.md, never a replacement'));
        }
        for (const [file, text] of [['CLAUDE.md', claude], ['AGENTS.md', agents]] as const) {
            if (text === null) continue;
            const count = text.replace(/\r\n/g, '\n').trimEnd().split('\n').length;
            if (count > 120) out.push(error(file, `${count} lines — the budget is 120; move detail to a scoped instruction file`));
        }
        if (copilot !== null && Buffer.byteLength(copilot, 'utf8') > 16 * 1024) {
            out.push(error('.github/copilot-instructions.md', `${Buffer.byteLength(copilot, 'utf8')} bytes — the budget is 16 KiB`));
        }
        for (const [file, text] of [['CLAUDE.md', claude], ['AGENTS.md', agents], ['.github/copilot-instructions.md', copilot]] as const) {
            if (text === null) continue;
            text.replace(/\r\n/g, '\n').split('\n').forEach((l, i) => {
                if ([...l].length > LINE_LIMIT) out.push(error(file, `line is ${[...l].length} characters — the limit is ${LINE_LIMIT}`, i + 1));
            });
        }
        return out;
    },
};

interface Governance {
    capability_manifest?: {
        sources?: string[];
        on_demand?: string[];
        claude_code?: {
            settings?: string;
            hooks?: Array<{ command?: string; tests?: string }>;
            skills?: Array<{ path?: string }>;
        };
    };
    verification?: { validator_covered_by?: string };
    references?: { zero_dependency_policy?: string; issue_templates?: string[] };
}

const governanceSources: Rule = {
    id: 'governance-sources',
    summary: 'Every path .github/ai-governance.json names exists, and the always-loaded sources stay under 16 KiB.',
    check(ctx) {
        const FILE = '.github/ai-governance.json';
        const parsed = readJson<Governance>(ctx, FILE);
        if ('finding' in parsed) return [parsed.finding];
        const gov = parsed.value;
        const text = ctx.read(FILE) ?? '';
        const out: Finding[] = [];
        const need = (path: string | undefined, what: string): void => {
            if (path === undefined || path === '') {
                out.push(error(FILE, `${what} is not declared`));
                return;
            }
            const bare = path.replace(/#.*$/, '').replace(/\/+$/, '');
            if (!ctx.exists(bare)) out.push(error(FILE, `${what} "${path}" does not exist`, lineContaining(text, `"${path}"`)));
        };
        const sources = gov.capability_manifest?.sources ?? [];
        if (sources.length === 0) out.push(error(FILE, 'capability_manifest.sources is empty'));
        let total = 0;
        for (const s of sources) {
            need(s, 'capability_manifest.sources entry');
            total += Buffer.byteLength(ctx.read(s) ?? '', 'utf8');
        }
        if (total > 16 * 1024) out.push(error(FILE, `the always-loaded sources total ${total} bytes — the budget is 16 KiB`));
        for (const s of gov.capability_manifest?.on_demand ?? []) need(s, 'capability_manifest.on_demand entry');
        const cc = gov.capability_manifest?.claude_code;
        need(cc?.settings, 'claude_code.settings');
        for (const hook of cc?.hooks ?? []) {
            need(/node\s+(\S+)/.exec(hook.command ?? '')?.[1], 'claude_code.hooks command script');
            need(hook.tests, 'claude_code.hooks tests');
        }
        for (const skill of cc?.skills ?? []) need(skill.path, 'claude_code.skills path');
        need(gov.verification?.validator_covered_by, 'verification.validator_covered_by');
        need(gov.references?.zero_dependency_policy, 'references.zero_dependency_policy');
        for (const t of gov.references?.issue_templates ?? []) need(t, 'references.issue_templates entry');
        return out;
    },
};

const nodePinParity: Rule = {
    id: 'node-pin-parity',
    summary: '.nvmrc, .node-version, engines.node and every setup-node step agree on the Node line; packageManager pins npm.',
    check(ctx) {
        const out: Finding[] = [];
        const nvmrc = ctx.read('.nvmrc');
        const pkg = readJson<{ engines?: { node?: string }; packageManager?: string }>(ctx, 'package.json');
        if ('finding' in pkg) return [pkg.finding];
        const enginesNode = pkg.value.engines?.node ?? null;
        const pinned = nvmrc === null ? null : Number(/(\d+)/.exec(nvmrc)?.[1]);
        if (nvmrc === null) out.push(error('.nvmrc', 'missing — setup-node reads the Node line from it'));
        const enginesMajor = Number(/(\d+)/.exec(enginesNode ?? '')?.[1]);
        if (pinned !== null && enginesMajor !== pinned) out.push(error('.nvmrc', `pins ${pinned} but engines.node is "${enginesNode}"`));
        if (!(pkg.value.packageManager ?? '').startsWith('npm@')) out.push(error('package.json', 'packageManager must pin npm (`npm@x.y.z`)'));
        let ciMatrix: number[] = [];
        for (const { file, text } of workflowFiles(ctx)) {
            const lines = text.replace(/\r\n/g, '\n').split('\n');
            lines.forEach((line, i) => {
                if (!/uses:\s*actions\/setup-node@/.test(line)) return;
                const block: string[] = [];
                for (let j = i + 1; j < lines.length && /^\s{8,}\S|^\s*$/.test(lines[j]) && !/^\s*- /.test(lines[j]); j++) block.push(lines[j]);
                const body = block.join('\n');
                if (/node-version-file:\s*\.nvmrc/.test(body)) return;
                if (/node-version:\s*\$\{\{\s*matrix\.node-version\s*\}\}/.test(body)) {
                    const job = workflowJobs(file, text).find((j) => j.matrix['node-version'] !== undefined);
                    const values = (job?.matrix['node-version'] ?? []).map(Number);
                    if (file.endsWith('ci.yml')) ciMatrix = values;
                    if (pinned !== null && !values.includes(pinned)) out.push(error(file, `the node-version matrix [${values.join(', ')}] does not include the pinned ${pinned}`, i + 1));
                    return;
                }
                out.push(error(file, 'setup-node must read `node-version-file: .nvmrc` (or a matrix that includes the pinned line)', i + 1));
            });
        }
        out.push(...checkNodeVersionPin({ nodeVersion: ctx.read('.node-version'), enginesNode, ciMatrix }));
        return out;
    },
};

const rulesetParity: Rule = {
    id: 'ruleset-parity',
    summary: 'Every status check the main ruleset requires is reported by a real workflow job, and the tag ruleset protects v* tags.',
    check(ctx) {
        const FILE = '.github/rulesets/main.json';
        const out: Finding[] = [];
        const parsed = readJson<{ rules?: Array<{ type?: string; parameters?: { required_status_checks?: Array<{ context?: string }> } }> }>(ctx, FILE);
        if ('finding' in parsed) return [parsed.finding, ...checkTagRuleset(ctx.read('.github/rulesets/tags.json'))];
        const text = ctx.read(FILE) ?? '';
        const contexts = (parsed.value.rules ?? [])
            .filter((r) => r.type === 'required_status_checks')
            .flatMap((r) => r.parameters?.required_status_checks ?? [])
            .map((c) => c.context)
            .filter((c): c is string => typeof c === 'string');
        if (contexts.length === 0) out.push(error(FILE, 'requires no status check — the gate must be a required check'));
        const jobs = workflowFiles(ctx).flatMap(({ file, text: t }) => workflowJobs(file, t));
        const reported = new Set(jobs.flatMap((j) => j.checkNames));
        for (const context of contexts) {
            if (!reported.has(context)) out.push(error(FILE, `required check "${context}" is reported by no workflow job — a required check that never reports blocks every pull request`, lineContaining(text, `"${context}"`)));
        }
        out.push(...checkTagRuleset(ctx.read('.github/rulesets/tags.json')));
        return out;
    },
};

const agentConfigParity: Rule = {
    id: 'agent-config-parity',
    summary: '.claude/settings.json, the guard hook and CLAUDE.md agree: no trailers, every Never Read glob denied, the HITL families denied, the hook wired and valid.',
    check(ctx) {
        const HOOK = '.claude/hooks/guard.mjs';
        const exists = ctx.exists(HOOK);
        const check = exists ? ctx.nodeCheck(HOOK) : { status: null, stderr: '' };
        return checkAgentConfigParity({
            settingsText: ctx.read('.claude/settings.json'),
            claudeMd: ctx.read('CLAUDE.md') ?? '',
            hook: { exists, checkStatus: check.status, checkStderr: check.stderr },
        });
    },
};

function filesByName(ctx: RuleContext, dir: string, suffix: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const path of ctx.list(dir)) {
        if (path.slice(dir.length + 1).includes('/') || !path.endsWith(suffix)) continue;
        out[basename(path)] = ctx.read(path) ?? '';
    }
    return out;
}

const claudeRulesSync: Rule = {
    id: 'claude-rules-sync',
    summary: '.claude/rules/*.md are exactly what npm run agents:rules renders from .github/instructions/*.instructions.md.',
    check(ctx) {
        const diff = diffRules(filesByName(ctx, INSTRUCTIONS_DIR, '.instructions.md'), filesByName(ctx, RULES_DIR, '.md'));
        return [
            ...diff.invalid.map((b) => error(`${INSTRUCTIONS_DIR}/${b.source}`, b.error)),
            ...diff.stale.map((f) => error(`${RULES_DIR}/${f}`, 'stale — edit the instruction file, then run `npm run agents:rules`')),
            ...diff.missing.map((f) => error(`${RULES_DIR}/${f}`, 'missing — run `npm run agents:rules`')),
            ...diff.extra.map((f) => error(`${RULES_DIR}/${f}`, 'has no instruction source — run `npm run agents:rules` to remove it')),
        ];
    },
};

const claudeRulesBudget: Rule = {
    id: 'claude-rules-budget',
    summary: 'CLAUDE.md, its imports and any unscoped rule stay within the 16 KiB always-loaded budget; every rule is scoped.',
    check(ctx) {
        return checkClaudeRulesBudget({
            claudeMd: ctx.read('CLAUDE.md') ?? '',
            resolveImport: (name) => ctx.read(name),
            rules: filesByName(ctx, RULES_DIR, '.md'),
        });
    },
};

const prTemplateParity: Rule = {
    id: 'pr-template-parity',
    summary: 'The pull-request template checklist is verbatim CONTRIBUTING.md §Pull Request Checklist and names the gate.',
    check(ctx) {
        return checkPrTemplateParity(ctx.read('.github/pull_request_template.md'), ctx.read('CONTRIBUTING.md') ?? '');
    },
};

const eolLf: Rule = {
    id: 'eol-lf',
    summary: 'No tracked text blob is stored with CRLF line endings.',
    check(ctx) {
        const output = ctx.git(['ls-files', '--eol']);
        return output === null ? [] : checkEol(output);
    },
};

const skillsShape: Rule = {
    id: 'skills-shape',
    summary: 'Every .claude/skills/<dir>/SKILL.md has a matching name, a description and references that exist, and is declared in .github/ai-governance.json → capability_manifest.claude_code.skills (the other direction is governance-sources).',
    check(ctx) {
        const dirs = new Set(ctx.list('.claude/skills').map((p) => p.split('/')[2]).filter((d): d is string => d !== undefined));
        const shape = [...dirs].sort().flatMap((dir) => checkSkillShape({
            dir,
            text: ctx.read(`.claude/skills/${dir}/SKILL.md`),
            existsInSkill: (name) => ctx.exists(`.claude/skills/${dir}/${name}`),
            existsInRepo: (path) => ctx.exists(path),
        }));
        // A skill the governance manifest does not declare is a capability an
        // auditor reading the manifest would never know the agents have.
        const read = readJson<Governance>(ctx, '.github/ai-governance.json');
        if ('finding' in read) return [...shape, read.finding];
        const declared = new Set((read.value.capability_manifest?.claude_code?.skills ?? []).map((s) => s.path));
        const undeclared = [...dirs].sort().filter((dir) => !declared.has(`.claude/skills/${dir}/SKILL.md`))
            .map((dir) => error('.github/ai-governance.json', `does not declare the skill .claude/skills/${dir}/SKILL.md in capability_manifest.claude_code.skills — every tracked skill is a capability the manifest must name`));
        return [...shape, ...undeclared];
    },
};

const layerParity: Rule = {
    id: 'layer-parity',
    summary: 'The layer diagram of AGENTS.md §Architecture equals LAYERS, the table tests/tools/architecture.test.ts enforces.',
    check(ctx) {
        return checkLayerParity(ctx.read('AGENTS.md'));
    },
};

export const GOVERNANCE_RULES: readonly Rule[] = [
    claudeMdBudget,
    governanceSources,
    nodePinParity,
    rulesetParity,
    agentConfigParity,
    claudeRulesSync,
    claudeRulesBudget,
    prTemplateParity,
    eolLf,
    skillsShape,
    layerParity,
];
