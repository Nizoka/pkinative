/**
 * pkinative — the requirements of the RFCs pkinative implements, extracted
 * ========================================================================
 * The L5 clause table (scripts/lib/clauses.ts) says which sentences of
 * RFC 5280 pkinative diagnoses. It cannot say which it **does not**: a table
 * of 19 clauses looks exactly as complete as a table of 190. This module reads
 * the pinned text of the RFC itself (the `rfc5280` corpus of
 * scripts/lib/corpora.ts) and extracts every sentence of §4.1 and §4.2, with
 * their subsections, that carries a requirement keyword — so that
 * scripts/data/rfc5280-requirements.json can account for each one, and a
 * clause can be held to a sentence the RFC actually contains.
 *
 * The same extraction runs over every RFC of {@link RFC_INVENTORIES} — CMS
 * (RFC 5652), TSP (RFC 3161), OCSP (RFC 6960), PKCS #12 (RFC 7292) and PEM
 * (RFC 7468) — each with the sections its spec names and its own registry
 * under scripts/data/. There a sentence is held by a `test` (a named Vitest
 * case that exercises its keyword) or excluded with a reason; the rules below
 * are the same for all six, so RFC 5280's ids are what they always were.
 *
 * **The keyword set** is RFC 2119 minus its permissions: `MUST`, `MUST NOT`,
 * `SHALL`, `SHALL NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`
 * and `NOT RECOMMENDED`. `MAY` and `OPTIONAL` grant a freedom, and a
 * certificate cannot violate a freedom, so no sentence built on them alone can
 * be a clause. `SHOULD` is kept: it is a requirement with a stated escape,
 * pkinative diagnoses several of them (a profile concern is exactly what a
 * diagnostic is for), and dropping them would make the inventory silent on the
 * sentences a reader most needs a decision about. RFC 5280 §1 binds the
 * keywords to RFC 2119 in upper case only, so matching is case-sensitive:
 * "may be consistent" in an ASN.1 comment is prose, not a keyword. One RFC
 * is the exception, by its spec's `anyCase`: RFC 7292 does not cite RFC 2119
 * and writes every requirement in lower case.
 *
 * **What counts as a sentence**, deterministically:
 *
 *   1. Page furniture is removed: the `Cooper, et al. … [Page N]` footer, the
 *      form feed and the `RFC 5280 … May 2008` header, with the blank lines
 *      around them. A paragraph a page break cut in two is joined again.
 *   2. Sections are the headings in column 0 (`4.2.1.9.  Basic Constraints`;
 *      RFC 3161 puts one space after the number, `2.4.2. Response Format`).
 *      The spec's predicate picks the sections read — for RFC 5280, §4.1 and
 *      §4.2 and every subsection; §4 itself and §5 are not. An appendix is
 *      never read: its lettered headings (`B.1.`) are not numbered sections.
 *   3. A section body is split into paragraphs at blank lines. A paragraph
 *      with a `::=` in it, or whose lines are all ASN.1 syntax or comments, is
 *      a module fragment and is skipped: its three keyword comments ("If
 *      present, version MUST be v2 or v3") restate §4.1.2.1 and §4.1.2.8,
 *      whose prose sentences are extracted.
 *   4. A paragraph's lines are joined ({@link joinRfcLines}: a word wrapped
 *      at its own hyphen is rejoined, the hyphen kept) and split into
 *      sentences after a full stop (and any closing `"` or `)`) followed by
 *      two spaces, a line end or the end of the paragraph — the RFC's own
 *      typography puts two spaces between sentences — except after `e.g.`,
 *      `i.e.` and `et al.`.
 *   5. Every whitespace run is collapsed to one space ({@link normaliseRfcText}),
 *      and that is the only normalisation: no case folding, no quote folding.
 *      A clause quote is compared under the same function.
 *
 * An id is `<section>-<ordinal>-<hash>`: the ordinal is the sentence's rank
 * among the extracted sentences of its section, the hash the first eight hex
 * digits of the SHA-256 of its normalised text. The ordinal makes the id
 * sortable and readable; the hash makes a re-pinned text whose sentence
 * changed produce a different id rather than silently the same one.
 *
 * @module scripts/lib/rfc-requirements
 */

import { createHash } from 'node:crypto';

/** The RFC 2119 keywords that state a requirement, strongest first. */
export const REQUIREMENT_KEYWORDS = Object.freeze([
    'MUST NOT', 'MUST', 'SHALL NOT', 'SHALL', 'REQUIRED',
    'SHOULD NOT', 'SHOULD', 'NOT RECOMMENDED', 'RECOMMENDED',
] as const);
export type RequirementKeyword = typeof REQUIREMENT_KEYWORDS[number];

/** The keywords that make a requirement absolute (RFC 2119 §1–§2). */
export const ABSOLUTE_KEYWORDS: readonly RequirementKeyword[] = Object.freeze(['MUST NOT', 'MUST', 'SHALL NOT', 'SHALL', 'REQUIRED']);

const KEYWORD_PATTERN = /\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED|SHOULD NOT|SHOULD|NOT RECOMMENDED|RECOMMENDED)\b/g;
const KEYWORD_PATTERN_ANY_CASE = new RegExp(KEYWORD_PATTERN.source, 'gi');

/** True when `section` is one of `roots` or a subsection of one. */
function within(section: string, roots: readonly string[]): boolean {
    return roots.some((root) => section === root || section.startsWith(`${root}.`));
}

/** The sections of RFC 5280 read: §4.1, §4.2 and every subsection of either. */
export function isRequirementSection(section: string): boolean {
    return within(section, ['4.1', '4.2']);
}

/**
 * One RFC whose requirement sentences are inventoried: the pinned text it is
 * read from, the registry that accounts for each sentence, and the sections
 * read. Every field is data the runner, the fast-gate suite and verify-docs
 * share, so the three cannot disagree on which file holds which RFC.
 */
export interface RfcInventorySpec {
    /** `RFC 5652` — also the prefix of a clause section citing it (`RFC 5652 §5.3`). */
    readonly rfc: string;
    /** The corpus id in scripts/lib/corpora.ts. */
    readonly corpus: string;
    /** The file of that corpus holding the plain text. */
    readonly file: string;
    /** The repository-relative path of the reviewed inventory. */
    readonly data: string;
    /** The key under `declared` in docs/assets/ecosystem.json holding its counts. */
    readonly declared: string;
    /** The sections read, as a reader would write them: `§5, §11.1–§11.4`. */
    readonly scope: string;
    /** True for a section id (`5.3`, no trailing dot) whose sentences are read. */
    readonly sections: (id: string) => boolean;
    /**
     * Match the keywords in any case. Only for a text that does not cite
     * RFC 2119 and writes its requirements in lower case: RFC 7292 republishes
     * PKCS #12 v1.1, whose "shall" and "should" are the normative words of the
     * PKCS series, and an upper-case-only reading of it finds no sentence at all.
     */
    readonly anyCase?: boolean;
}

/** Every inventoried RFC, RFC 5280 first. */
export const RFC_INVENTORIES: readonly RfcInventorySpec[] = Object.freeze([
    {
        rfc: 'RFC 5280', corpus: 'rfc5280', file: 'rfc5280.txt', data: 'scripts/data/rfc5280-requirements.json', declared: 'rfc5280',
        scope: '§4.1–§4.2', sections: isRequirementSection,
    },
    {
        rfc: 'RFC 5652', corpus: 'rfc5652', file: 'rfc5652.txt', data: 'scripts/data/rfc5652-requirements.json', declared: 'rfc5652',
        scope: '§5, §11.1–§11.4', sections: (id: string): boolean => within(id, ['5', '11.1', '11.2', '11.3', '11.4']),
    },
    {
        rfc: 'RFC 3161', corpus: 'rfc3161', file: 'rfc3161.txt', data: 'scripts/data/rfc3161-requirements.json', declared: 'rfc3161',
        scope: '§2.3–§2.4', sections: (id: string): boolean => within(id, ['2.3', '2.4']),
    },
    {
        rfc: 'RFC 6960', corpus: 'rfc6960', file: 'rfc6960.txt', data: 'scripts/data/rfc6960-requirements.json', declared: 'rfc6960',
        scope: '§4.1–§4.2', sections: (id: string): boolean => within(id, ['4.1', '4.2']),
    },
    {
        rfc: 'RFC 7292', corpus: 'rfc7292', file: 'rfc7292.txt', data: 'scripts/data/rfc7292-requirements.json', declared: 'rfc7292',
        scope: '§4–§5', sections: (id: string): boolean => within(id, ['4', '5']), anyCase: true,
    },
    {
        rfc: 'RFC 7468', corpus: 'rfc7468', file: 'rfc7468.txt', data: 'scripts/data/rfc7468-requirements.json', declared: 'rfc7468',
        scope: '§2–§5', sections: (id: string): boolean => within(id, ['2', '3', '4', '5']),
    },
]);

/** The spec of RFC 5280 — the inventory the L5 clause table is held to. */
export const RFC5280_INVENTORY: RfcInventorySpec = RFC_INVENTORIES[0] as RfcInventorySpec;

export interface RfcSection {
    /** `4.2.1.9` — the number, without its trailing dot. */
    readonly id: string;
    readonly title: string;
    /** The body lines, page furniture removed, up to the next heading. */
    readonly lines: readonly string[];
}

export interface RfcRequirement {
    readonly id: string;
    readonly section: string;
    /** The distinct keywords in the sentence, in order of first appearance. */
    readonly keywords: readonly RequirementKeyword[];
    readonly text: string;
}

/** Collapse every whitespace run to one space and trim — the only normalisation. */
export function normaliseRfcText(text: string): string {
    return text.replace(/\s+/g, ' ').trim();
}

/** The first eight hex digits of the SHA-256 of a normalised sentence. */
export function sentenceHash(text: string): string {
    return createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 8);
}

/**
 * Remove the page furniture of an RFC in the plain-text format: the footer,
 * the form feed, the running header, and the blank lines padding them.
 */
export function stripPagination(text: string): string[] {
    const lines = text.replace(/\r\n?/g, '\n').split('\n');
    const out: string[] = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (/\[Page \d+\]\s*$/.test(line) && (lines[i + 1] ?? '').startsWith('\f')) {
            // Drop the blank padding before the footer, the footer, the form
            // feed, the header, and the blank lines after it: the paragraph on
            // either side reads on as if the page had not broken.
            while (out.length > 0 && (out[out.length - 1] ?? '').trim() === '') out.pop();
            i += 1;
            const header = (lines[i] ?? '').replace(/^\f/, '');
            if (header.trim() === '' || /^RFC \d+ /.test(header)) {
                if (header.trim() === '') i += 1;
                while (i + 1 < lines.length && (lines[i + 1] ?? '').trim() === '') i += 1;
            }
            // A break is a paragraph boundary unless it cut a sentence of
            // prose in two: the line before it ends on a word, and is not
            // ASN.1. Joining ASN.1 to the prose after it would hide the prose.
            const before = out[out.length - 1] ?? '';
            const midSentence = /^ {3,6}\S/.test(before) && /[A-Za-z0-9)",;-]$/.test(before) && !before.includes('::=') && !before.includes('--');
            if (!midSentence) out.push('');
            continue;
        }
        out.push(line);
    }
    return out;
}

/** Split the de-paginated text into numbered sections. */
export function parseSections(text: string): RfcSection[] {
    const lines = stripPagination(text);
    const sections: Array<{ id: string; title: string; lines: string[] }> = [];
    let current: { id: string; title: string; lines: string[] } | null = null;
    for (const line of lines) {
        const heading = /^(\d+(?:\.\d+)*)\. {1,2}(\S.*)$/.exec(line);
        if (heading !== null) {
            current = { id: heading[1] ?? '', title: (heading[2] ?? '').trim(), lines: [] };
            sections.push(current);
            continue;
        }
        if (/^Appendix [A-Z]\./.test(line) || /^(Authors' Addresses|Full Copyright Statement)/.test(line)) {
            current = null;
            continue;
        }
        current?.lines.push(line);
    }
    return sections;
}

/**
 * True for a paragraph of ASN.1: a definition (`::=`), a comment, a tagged
 * component, or a brace alone on its line. Prose in RFC 5280 §4 has none of
 * those; a fragment of a module cut off by a blank line always has one.
 */
export function isAsn1Paragraph(lines: readonly string[]): boolean {
    return lines.some((l) => l.includes('::=') || /(^|\s)--(\s|$)/.test(l) || /^\s*[{}]\s*$/.test(l) || /\b(IMPLICIT|EXPLICIT)\b/.test(l));
}

/** The paragraphs of a section body, each a list of its non-blank lines. */
function paragraphs(lines: readonly string[]): string[][] {
    const out: string[][] = [];
    let current: string[] = [];
    for (const line of lines) {
        if (line.trim() === '') {
            if (current.length > 0) out.push(current);
            current = [];
        } else {
            current.push(line);
        }
    }
    if (current.length > 0) out.push(current);
    return out;
}

const ABBREVIATION = /\b(e\.g|i\.e|et al)\.$/;

/**
 * Join wrapped lines: a line break becomes a newline, except after a word
 * broken at its own hyphen ("non-" / "critical"), where the two halves are one
 * word and the hyphen stays. Nothing is removed but the break itself.
 */
export function joinRfcLines(lines: readonly string[]): string {
    let out = '';
    for (const raw of lines) {
        const line = raw.trim();
        if (out === '') out = line;
        else if (/[A-Za-z]-$/.test(out) && /^[a-z]/.test(line)) out += line;
        else out += `\n${line}`;
    }
    return out;
}

/**
 * Split one paragraph into sentences, by the RFC's own typography: a full
 * stop (and any closing quote or parenthesis) followed by two spaces, a line
 * end or the end of the paragraph — never after `e.g.`, `i.e.` or `et al.`.
 * `?` and `!` are not terminators: RFC 5280 §4 uses them only inside URIs.
 */
export function splitSentences(lines: readonly string[]): string[] {
    const text = joinRfcLines(lines);
    const sentences: string[] = [];
    let start = 0;
    for (const m of text.matchAll(/\.["')]*(?= {2,}|\n|$)/g)) {
        const end = m.index + m[0].length;
        if (ABBREVIATION.test(text.slice(start, end))) continue;
        const sentence = normaliseRfcText(text.slice(start, end));
        if (sentence !== '') sentences.push(sentence);
        start = end;
    }
    const tail = normaliseRfcText(text.slice(start));
    if (tail !== '') sentences.push(tail);
    return sentences;
}

/**
 * The distinct requirement keywords of a sentence, in order of appearance.
 * Upper case only, unless `anyCase` — for a specification that does not bind
 * the RFC 2119 keywords to their capitals ({@link RfcInventorySpec.anyCase});
 * a keyword is reported in capitals either way.
 */
export function keywordsOf(sentence: string, anyCase = false): RequirementKeyword[] {
    const found: RequirementKeyword[] = [];
    for (const m of sentence.matchAll(anyCase ? KEYWORD_PATTERN_ANY_CASE : KEYWORD_PATTERN)) {
        const keyword = (m[1] ?? '').toUpperCase() as RequirementKeyword;
        if (!found.includes(keyword)) found.push(keyword);
    }
    return found;
}

/** Every requirement sentence of the sections the spec reads, in document order. */
export function extractRequirements(text: string, spec: RfcInventorySpec): RfcRequirement[] {
    const out: RfcRequirement[] = [];
    for (const section of parseSections(text)) {
        if (!spec.sections(section.id)) continue;
        let ordinal = 0;
        for (const paragraph of paragraphs(section.lines)) {
            if (isAsn1Paragraph(paragraph)) continue;
            for (const sentence of splitSentences(paragraph)) {
                const keywords = keywordsOf(sentence, spec.anyCase === true);
                if (keywords.length === 0) continue;
                ordinal += 1;
                out.push({ id: `${section.id}-${String(ordinal)}-${sentenceHash(sentence)}`, section: section.id, keywords, text: sentence });
            }
        }
    }
    return out;
}

/**
 * The normalised text of one section, with its subsections — what a clause
 * quote citing that section must be found in.
 */
export function sectionText(text: string, section: string): string | null {
    const sections = parseSections(text).filter((s) => s.id === section || s.id.startsWith(`${section}.`));
    if (sections.length === 0) return null;
    return normaliseRfcText(sections.map((s) => joinRfcLines(s.lines)).join('\n'));
}

// ── The reviewed inventory ──

/**
 * Why a requirement sentence is not a clause. A fixed vocabulary, so that the
 * exclusions can be counted and argued with as categories — and a sentence of
 * prose beside each, because the category alone never says which part of the
 * sentence put it there.
 */
export const EXCLUSION_REASONS = Object.freeze({
    'issuer-policy': 'constrains what a CA does or decides, in a way no single certificate\'s bytes can show',
    'path-validation': 'decided by RFC 5280 §6 over a chain, and scored against the corpora at L6, L7 and L8',
    'relying-party': 'constrains the application or implementation that processes certificates or messages, not the data itself',
    'not-decidable-from-bytes': 'about a certificate or message, but turns on facts outside its encoding (intent, ownership, the world)',
    'covered-elsewhere': 'enforced by pkinative outside the clause table — the sentence names the clause, error or diagnostic',
    'nothing-to-violate': 'its own MAY admits every encoding, or it says what a value means rather than which values are allowed',
    'producer-policy': 'constrains what a signer, TSA, OCSP responder or file writer does, in a way the bytes pkinative reads cannot show, or in a choice pkinative leaves to its caller',
    'not-implemented': 'belongs to a feature pkinative deliberately does not implement — the sentence names the ADR, guide or registry entry that records the decision',
} as const);
export type ExclusionReason = keyof typeof EXCLUSION_REASONS;

/**
 * True when a test file's source names `title` as the title of an `it`,
 * `test` or `describe` — the whole title or a substring of it, on the line
 * that opens the call or the line after (a title wrapped below its `it(`).
 * A title found only in a comment or an assertion does not count: a `test`
 * entry points at a case a reader can run, not at a sentence near one. Nor
 * does `it.skip`, `it.todo` or `it.only`: a case that does not run enforces
 * nothing, and one that runs alone silences the rest of its file.
 */
export function titleInSource(source: string, title: string): boolean {
    if (title.trim().length < 12) return false;
    const opens = /\b(it|test|describe)\(\s*['"`]|\)\(\s*['"`]/;
    const opensAtEnd = /(\b(it|test|describe)|\))\(\s*$/;
    const lines = source.split(/\r?\n/);
    return lines.some((line, i) => line.includes(title) && (opens.test(line) || (/^\s*['"`]/.test(line) && opensAtEnd.test(lines[i - 1] ?? ''))));
}

export type InventoryEntry =
    | { readonly section: string; readonly text: string; readonly status: 'test'; readonly file: string; readonly test: string; readonly why: string }
    | { readonly section: string; readonly text: string; readonly status: 'clause'; readonly clause: string }
    | { readonly section: string; readonly text: string; readonly status: 'excluded'; readonly reason: ExclusionReason; readonly why: string }
    | { readonly section: string; readonly text: string; readonly status: 'todo' };

export interface RequirementsInventory {
    readonly $comment: string;
    readonly rfc: string;
    /** The SHA-256 of the pinned text the inventory was reviewed against. */
    readonly sha256: string;
    readonly errata: ReadonlyArray<{ readonly id: number; readonly section: string; readonly type: string; readonly decision: string }>;
    readonly requirements: Readonly<Record<string, InventoryEntry>>;
}

/** True when a clause quote and a sentence are the same text, or one holds the other. */
export function quoteCovers(quote: string, sentence: string): boolean {
    const q = normaliseRfcText(quote);
    const s = normaliseRfcText(sentence);
    return q.includes(s) || s.includes(q);
}

/** Whether `file` holds a runnable case titled `title` — read by the caller, so the check needs no I/O here. */
export type TestExists = (file: string, title: string) => boolean;

/**
 * Everything that can be checked about the inventory without the RFC: its
 * shape, its vocabulary, that every id's hash is the hash of its own text,
 * that every `clause` entry names a clause whose quote is that sentence, and
 * that every `test` entry names a test file holding a case of that title.
 * The corpus-bound checks — every sentence present, none stale, every quote
 * in the RFC — are {@link checkInventoryAgainstRfc}.
 */
export function checkInventoryShape(
    inventory: RequirementsInventory,
    clauses: ReadonlyArray<{ readonly id: string; readonly section: string; readonly quote: string }>,
    spec: RfcInventorySpec,
    testExists: TestExists,
): string[] {
    const problems: string[] = [];
    if (inventory.rfc !== spec.rfc) problems.push(`${spec.data} names ${inventory.rfc}, not ${spec.rfc}`);
    const byId = new Map(clauses.map((c) => [c.id, c]));
    const claimed = new Set<string>();
    for (const [id, entry] of Object.entries(inventory.requirements)) {
        const m = /^(\d+(?:\.\d+)*)-(\d+)-([0-9a-f]{8})$/.exec(id);
        if (m === null) { problems.push(`${id}: not <section>-<ordinal>-<hash8>`); continue; }
        if (m[1] !== entry.section) problems.push(`${id}: the id names §${m[1] ?? ''} and the entry §${entry.section}`);
        if (!spec.sections(entry.section)) problems.push(`${id}: §${entry.section} is outside ${spec.scope}`);
        if (sentenceHash(entry.text) !== m[3]) problems.push(`${id}: the hash is not the SHA-256 of its text — the text was edited, or the id was`);
        if (keywordsOf(entry.text, spec.anyCase === true).length === 0) problems.push(`${id}: the text carries no requirement keyword`);
        if (entry.status === 'clause') {
            const clause = byId.get(entry.clause);
            claimed.add(entry.clause);
            if (clause === undefined) problems.push(`${id}: names the clause ${entry.clause}, which scripts/lib/clauses.ts does not declare`);
            else if (clause.section !== `${spec.rfc} §${entry.section}`) problems.push(`${id}: the clause ${entry.clause} cites ${clause.section}, not §${entry.section}`);
            else if (!quoteCovers(clause.quote, entry.text)) problems.push(`${id}: the clause ${entry.clause} quotes another sentence`);
        } else if (entry.status === 'test') {
            if (!/^tests\/[\w./-]+\.test\.ts$/.test(entry.file)) problems.push(`${id}: the test file ${String(entry.file)} is not a tests/**/*.test.ts path`);
            else if (!testExists(entry.file, entry.test)) problems.push(`${id}: ${entry.file} holds no it, test or describe titled "${String(entry.test)}" — the test was renamed or removed`);
            if (entry.why.trim().length < 30 || /^TODO\b/i.test(entry.why)) problems.push(`${id}: held by a test without a sentence saying what it exercises`);
        } else if (entry.status === 'excluded') {
            if (!Object.hasOwn(EXCLUSION_REASONS, entry.reason)) problems.push(`${id}: the reason ${String(entry.reason)} is not in the vocabulary (${Object.keys(EXCLUSION_REASONS).join(', ')})`);
            if (entry.why.trim().length < 30 || /^TODO\b/i.test(entry.why)) problems.push(`${id}: excluded without a sentence saying why`);
        } else if (entry.status !== 'todo') {
            problems.push(`${id}: the status ${String((entry as { status: unknown }).status)} is not clause, test, excluded or todo`);
        }
    }
    // The converse: a clause quoting a requirement of this RFC is claimed by
    // the sentence it quotes. Otherwise the inventory could exclude the very
    // sentence a clause enforces, and the two files would tell two stories.
    for (const clause of clauses) {
        if (!clause.section.startsWith(`${spec.rfc} §`) || keywordsOf(clause.quote).length === 0) continue;
        if (!claimed.has(clause.id)) problems.push(`${clause.id}: quotes a requirement of ${clause.section} that no inventory entry names as its clause`);
    }
    return problems;
}

export interface InventoryCheck {
    readonly problems: readonly string[];
    readonly todo: readonly string[];
    readonly extracted: readonly RfcRequirement[];
}

/**
 * The corpus-bound half: the pinned RFC against the inventory and the clause
 * table. Every extracted sentence has an entry, no entry points at a sentence
 * that is not extracted (stale), and every clause citing this RFC quotes text
 * found — after {@link normaliseRfcText} — in the section it cites.
 */
export function checkInventoryAgainstRfc(
    rfcText: string,
    inventory: RequirementsInventory,
    clauses: ReadonlyArray<{ readonly id: string; readonly section: string; readonly quote: string }>,
    spec: RfcInventorySpec,
): InventoryCheck {
    const problems: string[] = [];
    const extracted = extractRequirements(rfcText, spec);
    const ids = new Set(extracted.map((r) => r.id));
    for (const r of extracted) {
        const entry = inventory.requirements[r.id];
        if (entry === undefined) problems.push(`${r.id}: §${r.section} "${r.text.slice(0, 80)}…" is extracted from the RFC and not accounted for`);
        else if (entry.text !== r.text) problems.push(`${r.id}: the inventory's text differs from the RFC's`);
    }
    for (const id of Object.keys(inventory.requirements)) {
        if (!ids.has(id)) problems.push(`${id}: stale — no sentence of the pinned RFC has this id any more`);
    }
    for (const clause of clauses) {
        if (!clause.section.startsWith(`${spec.rfc} §`)) continue;
        const m = /^RFC \d+ §([\d.]+)$/.exec(clause.section);
        if (m === null) continue;
        const text = sectionText(rfcText, m[1] ?? '');
        if (text === null) problems.push(`${clause.id}: cites ${clause.section}, which the pinned RFC does not have`);
        else if (!text.includes(normaliseRfcText(clause.quote))) problems.push(`${clause.id}: "${clause.quote}" is not found in ${clause.section} — a quote the RFC does not contain is a clause someone invented`);
    }
    const todo = Object.entries(inventory.requirements).filter(([, e]) => e.status === 'todo').map(([id]) => id);
    return { problems, todo, extracted };
}
