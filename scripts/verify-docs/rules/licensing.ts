/**
 * pkinative — licensing rules
 * ===========================
 * `reuse-shape`: `REUSE.toml` says who owns every file and under which
 * licence (REUSE 3.3), and it says the same thing as the rest of the
 * repository.
 *
 * `reuse lint` (the FSFE's reference tool, `pip install reuse`) proves the
 * project compliant; it is not a dependency of the gate. What this rule holds
 * hermetically is what would drift: the catch-all annotation agrees with
 * LICENSE and with package.json's `license`; every licence an annotation uses
 * has its text in LICENSES/, and every text there is used; and every foreign
 * fixture tests/fixtures/PROVENANCE.md lists is annotated as foreign, so a
 * certificate someone else published is never relicensed as pkinative's MIT
 * by the catch-all.
 *
 * @module scripts/verify-docs/rules/licensing
 */

import { error, lineContaining, readJson, type Finding, type Rule } from '../context.js';

const REUSE = 'REUSE.toml';
const PROVENANCE = 'tests/fixtures/PROVENANCE.md';

/** One `[[annotations]]` table, reduced to what the rule reads. */
interface Annotation {
    readonly paths: readonly string[];
    readonly copyright: string | null;
    readonly license: string | null;
}

/** The annotations of a REUSE.toml, in order — enough TOML for the shape this file is written in. */
export function parseAnnotations(text: string): Annotation[] {
    return text.split(/^\[\[annotations\]\]\s*$/m).slice(1).map((block) => {
        const field = (key: string): string | null => new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, 'm').exec(block)?.[1] ?? null;
        const list = /^path\s*=\s*\[([\s\S]*?)\]/m.exec(block)?.[1];
        const paths = list !== undefined ? [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? '') : [field('path') ?? ''].filter((p) => p !== '');
        return { paths, copyright: field('SPDX-FileCopyrightText'), license: field('SPDX-License-Identifier') };
    });
}

const reuseShape: Rule = {
    id: 'reuse-shape',
    summary: 'REUSE.toml annotates every file: its catch-all agrees with LICENSE and package.json, every licence it uses has its text in LICENSES/ and every text there is used, and every foreign fixture of tests/fixtures/PROVENANCE.md is annotated as foreign.',
    check(ctx) {
        const text = ctx.read(REUSE);
        if (text === null) return [error(REUSE, 'missing — the copyright and licence of every file (REUSE 3.3) live here')];
        const out: Finding[] = [];
        if (!/^version\s*=\s*1\s*$/m.test(text)) out.push(error(REUSE, 'does not declare `version = 1`, the REUSE.toml format reuse lint reads'));
        const annotations = parseAnnotations(text);
        const catchAll = annotations[0];
        if (catchAll === undefined || catchAll.paths.join() !== '**') {
            out.push(error(REUSE, 'its first annotation must cover `**`: every file pkinative writes, before the foreign ones override it'));
        } else {
            const pkg = readJson<{ license?: unknown }>(ctx, 'package.json');
            const license = 'finding' in pkg ? null : pkg.value.license;
            if (catchAll.license !== license) out.push(error(REUSE, `the catch-all licence is ${String(catchAll.license)} and package.json says ${String(license)}`, lineContaining(text, 'SPDX-License-Identifier')));
            const holder = /^Copyright \(c\) (.+)$/m.exec(ctx.read('LICENSE') ?? '')?.[1]?.trim();
            if (catchAll.copyright !== holder) out.push(error(REUSE, `the catch-all copyright is "${String(catchAll.copyright)}" and LICENSE says "${String(holder)}"`, lineContaining(text, 'SPDX-FileCopyrightText')));
        }
        const used = new Set(annotations.map((a) => a.license).filter((l): l is string => l !== null));
        const texts = new Set(ctx.list('LICENSES').map((p) => p.replace(/^LICENSES\//, '').replace(/\.txt$/, '')));
        for (const license of used) if (!texts.has(license)) out.push(error(REUSE, `uses ${license}, and LICENSES/${license}.txt does not exist`, lineContaining(text, license)));
        for (const license of texts) if (!used.has(license)) out.push(error(`LICENSES/${license}.txt`, 'no annotation of REUSE.toml uses this licence — remove the text or annotate what it covers'));
        const foreign = new Set(annotations.slice(1).flatMap((a) => a.paths));
        const provenance = ctx.read(PROVENANCE) ?? '';
        for (const m of provenance.matchAll(/^\| `([^`]+)` \|/gm)) {
            const path = `tests/fixtures/${m[1] ?? ''}`;
            if (!foreign.has(path)) out.push(error(REUSE, `does not annotate ${path}, a foreign fixture ${PROVENANCE} lists — the catch-all would relicense someone else's certificate as pkinative's`));
        }
        return out;
    },
};

export const LICENSING_RULES: readonly Rule[] = [reuseShape];
