/**
 * pkinative — architecture decision record rules
 * ===============================================
 * `adr-index`: docs/adr/README.md lists every record of docs/adr/ exactly
 * once and nothing else, numbers run from 0001 without a gap, each row's
 * decision and status equal the record's own title and front matter, and
 * every record carries a status, a date, the version since which it holds,
 * and the MADR 4 sections in order.
 *
 * A record the index omits is a decision nobody finds; a row whose file is
 * gone is a decision somebody believes was recorded. And a record without
 * its Confirmation section is a sentence, not a decision: the section is
 * where it names the rule, test or gate that holds it.
 *
 * @module scripts/verify-docs/rules/adr
 */

import { error, lineContaining, type Finding, type Rule } from '../context.js';

export const ADR_DIR = 'docs/adr';
export const ADR_INDEX = `${ADR_DIR}/README.md`;

/** A record's file name: four digits, a kebab-case slug. */
const RECORD_NAME = /^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$/;

/** MADR 4 statuses; a superseded record names its successor. */
const STATUS = /^(?:proposed|accepted|rejected|deprecated|superseded by ADR \d{4})$/;

/** The MADR 4 sections every record carries, in this order. */
export const ADR_SECTIONS: readonly string[] = [
    '## Context and Problem Statement',
    '## Decision Drivers',
    '## Considered Options',
    '## Decision Outcome',
    '### Consequences',
    '### Confirmation',
    '## More Information',
];

/** One row of the index table: `| [0001](0001-slug.md) | Decision | status | since |`. */
const INDEX_ROW = /^\|\s*\[(\d{4})\]\(([^)]+)\)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$/;

interface FrontMatter {
    readonly fields: ReadonlyMap<string, string>;
    readonly body: string;
}

function frontMatter(text: string): FrontMatter | null {
    const m = /^---\n([\s\S]*?)\n---\n/.exec(text.replace(/\r\n/g, '\n'));
    if (m === null) return null;
    const fields = new Map<string, string>();
    for (const line of (m[1] ?? '').split('\n')) {
        const kv = /^([a-z-]+):\s*(.*?)\s*$/.exec(line);
        if (kv !== null) fields.set(kv[1] ?? '', kv[2] ?? '');
    }
    return { fields, body: text.replace(/\r\n/g, '\n').slice(m[0].length) };
}

function checkRecord(path: string, text: string): { readonly title: string | null; readonly status: string | null; readonly since: string | null; readonly findings: Finding[] } {
    const out: Finding[] = [];
    const fm = frontMatter(text);
    if (fm === null) {
        return { title: null, status: null, since: null, findings: [error(path, 'has no YAML front matter — a record opens with `---`, then `status`, `date` and `since`, then `---`')] };
    }
    const status = fm.fields.get('status') ?? null;
    const date = fm.fields.get('date') ?? null;
    const since = fm.fields.get('since') ?? null;
    if (status === null || !STATUS.test(status)) {
        out.push(error(path, `status is ${JSON.stringify(status)}; a record is proposed, accepted, rejected, deprecated or "superseded by ADR NNNN"`));
    }
    if (date === null || !/^\d{4}-\d{2}-\d{2}$/.test(date)) out.push(error(path, `date is ${JSON.stringify(date)}; write the day the record was written as YYYY-MM-DD`));
    if (since === null || !/^\d+\.\d+\.\d+$/.test(since)) out.push(error(path, `since is ${JSON.stringify(since)}; write the version from which the decision holds`));

    const title = /^# (.+)$/m.exec(fm.body)?.[1]?.trim() ?? null;
    if (title === null) out.push(error(path, 'has no `# ` title after its front matter'));

    let from = 0;
    for (const section of ADR_SECTIONS) {
        const at = fm.body.search(new RegExp(`^${section.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm'));
        if (at < 0) {
            out.push(error(path, `lacks the "${section}" section — every record carries the MADR 4 sections (docs/adr/README.md)`));
        } else if (at < from) {
            out.push(error(path, `has "${section}" out of order — the MADR 4 sections come in the order docs/adr/README.md lists them`, lineContaining(text, section)));
        } else {
            from = at;
        }
    }
    return { title, status, since, findings: out };
}

const adrIndex: Rule = {
    id: 'adr-index',
    summary: 'docs/adr/README.md lists every architecture decision record of docs/adr/ exactly once, numbered from 0001 without a gap, each row matching its record\'s title, status and version, and every record carries a status, a date, a version and the MADR 4 sections in order.',
    check(ctx) {
        const index = ctx.read(ADR_INDEX);
        if (index === null) return [error(ADR_INDEX, 'missing — the architecture decision records need an index')];
        const out: Finding[] = [];

        const records = ctx.list(ADR_DIR)
            .map((p) => p.slice(ADR_DIR.length + 1))
            .filter((name) => name !== 'README.md');
        for (const name of records) {
            if (!RECORD_NAME.test(name)) out.push(error(`${ADR_DIR}/${name}`, 'is not named NNNN-kebab-slug.md — docs/adr/ holds the index and the records, nothing else'));
        }
        const numbered = records.filter((name) => RECORD_NAME.test(name)).sort();
        numbered.forEach((name, i) => {
            const expected = String(i + 1).padStart(4, '0');
            if (!name.startsWith(`${expected}-`)) out.push(error(`${ADR_DIR}/${name}`, `is record ${name.slice(0, 4)} where ${expected} was expected — numbers run from 0001 without a gap or a repeat`));
        });

        const rows = new Map<string, { readonly number: string; readonly decision: string; readonly status: string; readonly since: string; readonly line: number }>();
        index.replace(/\r\n/g, '\n').split('\n').forEach((line, i) => {
            const m = INDEX_ROW.exec(line);
            if (m === null) return;
            const [, number = '', target = '', decision = '', status = '', since = ''] = m;
            if (rows.has(target)) out.push(error(ADR_INDEX, `lists ${target} twice`, i + 1));
            rows.set(target, { number, decision, status, since, line: i + 1 });
        });

        for (const [target, row] of rows) {
            if (!numbered.includes(target)) {
                out.push(error(ADR_INDEX, `lists ${target}, which is not a record in ${ADR_DIR}/ — a row whose file is gone is a decision somebody believes was recorded`, row.line));
            } else if (!target.startsWith(`${row.number}-`)) {
                out.push(error(ADR_INDEX, `labels ${target} as ${row.number}`, row.line));
            }
        }

        for (const name of numbered) {
            const path = `${ADR_DIR}/${name}`;
            const record = checkRecord(path, ctx.read(path) ?? '');
            out.push(...record.findings);
            const row = rows.get(name);
            if (row === undefined) {
                out.push(error(ADR_INDEX, `does not list ${name} — a record the index omits is a decision nobody finds`));
                continue;
            }
            if (record.title !== null && row.decision !== record.title) out.push(error(ADR_INDEX, `gives ${name} the decision "${row.decision}"; the record's title is "${record.title}"`, row.line));
            if (record.status !== null && row.status !== record.status) out.push(error(ADR_INDEX, `gives ${name} the status "${row.status}"; its front matter says "${record.status}"`, row.line));
            if (record.since !== null && row.since !== record.since) out.push(error(ADR_INDEX, `gives ${name} the version ${row.since}; its front matter says ${record.since}`, row.line));
        }
        return out;
    },
};

export const ADR_RULES: readonly Rule[] = [adrIndex];
