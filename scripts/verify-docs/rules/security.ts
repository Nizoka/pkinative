/**
 * pkinative — security metadata rules
 * ===================================
 * `security-insights-parity`: `.github/SECURITY-INSIGHTS.yml` (the OpenSSF
 * Security Insights specification, 2.0.0) carries the keys the specification
 * requires, and says the same thing as the files a human reads: the reporting
 * e-mail and private-reporting URL of `docs/.well-known/security.txt`, the
 * security policy SECURITY.md, a code-of-conduct link when the repository has
 * one, and only security tools a workflow actually runs.
 *
 * The file is read with regular expressions over its block layout, not with a
 * YAML parser: the gate has no YAML dependency, and the file is written in one
 * shape on purpose. What would drift — a contact, a policy path, a tool
 * nobody runs any more, a link to a file that moved — is what is held.
 *
 * @module scripts/verify-docs/rules/security
 */

import { error, lineContaining, readJson, type Finding, type Rule } from '../context.js';

export const SECURITY_INSIGHTS = '.github/SECURITY-INSIGHTS.yml';
const SECURITY_TXT = 'docs/.well-known/security.txt';
const MANIFEST = 'docs/assets/ecosystem.json';
const WORKFLOWS = '.github/workflows';
const DEPENDABOT = '.github/dependabot.yml';

/** Keys Security Insights 2.0.0 requires, as `indentation + key`, in the order the file is written. */
const REQUIRED_KEYS: readonly string[] = [
    'header:', '  schema-version:', '  last-updated:', '  last-reviewed:', '  url:',
    'project:', '  name:', '  administrators:', '  repositories:', '  vulnerability-reporting:', '    reports-accepted:', '    bug-bounty-available:',
    'repository:', '  url:', '  status:', '  accepts-change-request:', '  accepts-automated-change-request:', '  core-team:', '  license:', '  security:', '    assessments:', '      self:',
];
const STATUSES: ReadonlySet<string> = new Set(['active', 'abandoned', 'concept', 'inactive', 'moved', 'suspended', 'unsupported', 'WIP']);
const TOOL_TYPES: ReadonlySet<string> = new Set(['fuzzing', 'container', 'secret', 'SCA', 'SAST', 'other']);

/** The value of the first `key: value` at exactly this indentation, quotes removed. */
function scalar(text: string, indent: number, key: string): string | undefined {
    const m = new RegExp(`^ {${String(indent)}}${key}:[ \\t]*(.*)$`, 'm').exec(text);
    return m?.[1]?.trim().replace(/^'(.*)'$|^"(.*)"$/, '$1$2');
}

/** The lines of the block opened by `key:` at this indentation, up to the next line indented as little. */
function block(text: string, indent: number, key: string): string {
    const lines = text.split('\n');
    const start = lines.findIndex((l) => l.replace(/\r$/, '') === `${' '.repeat(indent)}${key}:`);
    if (start < 0) return '';
    const out: string[] = [];
    for (const raw of lines.slice(start + 1)) {
        const line = raw.replace(/\r$/, '');
        if (line.trim() !== '' && !line.startsWith('#') && line.length - line.trimStart().length <= indent) break;
        out.push(line);
    }
    return out.join('\n');
}

const securityInsightsParity: Rule = {
    id: 'security-insights-parity',
    summary: '.github/SECURITY-INSIGHTS.yml carries the keys Security Insights 2.0.0 requires, is reviewed no earlier than the manifest\'s verifiedOn, names the e-mail and private-reporting URL of security.txt and SECURITY.md as its policy, links the code of conduct when one exists and every repository file it links, and lists only security tools a workflow (or Dependabot\'s configuration) runs.',
    check(ctx) {
        const text = ctx.read(SECURITY_INSIGHTS);
        if (text === null) return [error(SECURITY_INSIGHTS, 'missing — the OpenSSF Security Insights file machines read for the reporting channel, the policy and the security tools')];
        const manifest = readJson<{ verifiedOn?: unknown; packages?: { pkinative?: { repo?: unknown } } }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const repo = String(manifest.value.packages?.pkinative?.repo ?? '');
        const txt = ctx.read(SECURITY_TXT) ?? '';
        const out: Finding[] = [];
        const at = (needle: string): number => lineContaining(text, needle);

        // The specification's required keys, in the file's one shape.
        const lines = text.split('\n').map((l) => l.replace(/\r$/, ''));
        let cursor = 0;
        for (const key of REQUIRED_KEYS) {
            const found = lines.findIndex((l, i) => i >= cursor && (l === key || l.startsWith(`${key} `)));
            if (found < 0) out.push(error(SECURITY_INSIGHTS, `lacks "${key.trim()}" (indented ${String(key.length - key.trimStart().length)}), which Security Insights 2.0.0 requires there`));
            else cursor = found + 1;
        }
        const version = scalar(text, 2, 'schema-version') ?? '';
        if (!/^2\.\d+\.\d+$/.test(version)) out.push(error(SECURITY_INSIGHTS, `declares schema-version "${version}"; this file is written to the 2.x specification`, at('schema-version')));
        const status = scalar(text, 2, 'status') ?? '';
        if (!STATUSES.has(status)) out.push(error(SECURITY_INSIGHTS, `repository status "${status}" is not one the specification defines`, at('  status:')));

        const reviewed = scalar(text, 2, 'last-reviewed') ?? '';
        const verifiedOn = typeof manifest.value.verifiedOn === 'string' ? manifest.value.verifiedOn : '';
        if (!/^\d{4}-\d{2}-\d{2}$/.test(reviewed)) out.push(error(SECURITY_INSIGHTS, `last-reviewed "${reviewed}" is not a YYYY-MM-DD date`, at('last-reviewed')));
        else if (verifiedOn !== '' && reviewed < verifiedOn) out.push(error(SECURITY_INSIGHTS, `last-reviewed ${reviewed} is older than the manifest's verifiedOn ${verifiedOn} — review this file whenever the documentation is re-verified`, at('last-reviewed')));

        // The reporting channels: the same as security.txt, which is held to SECURITY.md.
        const reporting = block(text, 2, 'vulnerability-reporting');
        const txtMails = [...txt.matchAll(/^Contact:\s*mailto:(\S+)/gm)].map((m) => m[1] ?? '');
        const mails = [...reporting.matchAll(/^\s+email:\s*(\S+)/gm)].map((m) => m[1] ?? '');
        if (mails.length === 0) out.push(error(SECURITY_INSIGHTS, 'vulnerability-reporting names no contact e-mail'));
        for (const mail of mails) if (!txtMails.includes(mail)) out.push(error(SECURITY_INSIGHTS, `names ${mail} as the reporting contact, which ${SECURITY_TXT} does not offer`, at(mail)));
        for (const mail of txtMails) if (!mails.includes(mail)) out.push(error(SECURITY_INSIGHTS, `does not name ${mail}, the reporting e-mail ${SECURITY_TXT} offers`, at('vulnerability-reporting:')));
        const advisories = `${repo}/security/advisories/new`;
        if (!reporting.includes(advisories)) out.push(error(SECURITY_INSIGHTS, `vulnerability-reporting does not name ${advisories}, the private reporting channel SECURITY.md and ${SECURITY_TXT} offer first`, at('vulnerability-reporting:')));
        const policy = scalar(reporting, 4, 'security-policy') ?? '';
        const txtPolicy = /^Policy:\s*(\S+)/m.exec(txt)?.[1] ?? '';
        if (!policy.endsWith('/SECURITY.md') || policy !== txtPolicy) out.push(error(SECURITY_INSIGHTS, `security-policy "${policy}" is not ${txtPolicy === '' ? 'SECURITY.md' : txtPolicy}, the policy ${SECURITY_TXT} names`, at('security-policy')));

        // Links into the repository resolve; the code of conduct is linked when there is one.
        for (const m of text.matchAll(new RegExp(`${repo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/blob/main/([^\\s#)]+)`, 'g'))) {
            const path = m[1] ?? '';
            if (!ctx.exists(path)) out.push(error(SECURITY_INSIGHTS, `links ${path}, which is not in the repository`, at(m[0])));
        }
        if (ctx.exists('CODE_OF_CONDUCT.md') && !/^\s+code-of-conduct:\s*\S*CODE_OF_CONDUCT\.md/m.test(text)) {
            out.push(error(SECURITY_INSIGHTS, 'does not link CODE_OF_CONDUCT.md under project.documentation.code-of-conduct'));
        }

        // Every tool listed is run: named by a workflow, or Dependabot with its configuration.
        const workflows = ctx.list(WORKFLOWS).filter((p) => /\.ya?ml$/.test(p)).map((p) => (ctx.read(p) ?? '').toLowerCase());
        const tools = block(block(text, 2, 'security'), 4, 'tools');
        const names = [...tools.matchAll(/^ {6}- name:\s*(.+)$/gm)].map((m) => (m[1] ?? '').trim());
        if (names.length === 0) out.push(error(SECURITY_INSIGHTS, 'lists no security tool under repository.security.tools'));
        for (const name of names) {
            const needle = name.toLowerCase();
            const run = needle === 'dependabot' ? ctx.exists(DEPENDABOT) : workflows.some((w) => w.includes(needle) || w.includes(needle.replace(/\s+/g, '-')));
            if (!run) out.push(error(SECURITY_INSIGHTS, `lists the tool ${name}, which no workflow under ${WORKFLOWS}/ runs`, at(`- name: ${name}`)));
        }
        for (const m of tools.matchAll(/^ {8}type:\s*(\S+)/gm)) {
            if (!TOOL_TYPES.has(m[1] ?? '')) out.push(error(SECURITY_INSIGHTS, `a tool has type "${m[1] ?? ''}", which is not one the specification defines`, at(`type: ${m[1] ?? ''}`)));
        }
        return out;
    },
};

export const SECURITY_RULES: readonly Rule[] = [securityInsightsParity];
