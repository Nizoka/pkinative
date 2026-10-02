import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CLAUSES } from '../../scripts/lib/clauses.js';
import { CORPORA } from '../../scripts/lib/corpora.js';
import {
    checkInventoryAgainstRfc,
    checkInventoryShape,
    EXCLUSION_REASONS,
    extractRequirements,
    keywordsOf,
    RFC5280_INVENTORY,
    RFC_INVENTORIES,
    sentenceHash,
    titleInSource,
    type RequirementsInventory,
    type RfcInventorySpec,
} from '../../scripts/lib/rfc-requirements.js';

/**
 * The corpus-free half of L5's completeness check.
 *
 * `npm run conformance` holds the inventory to the pinned RFC — every sentence
 * present, none stale, every clause quote found verbatim. That needs the
 * downloaded text. What does not is everything a reviewer could get wrong in
 * the JSON itself: a reason outside the vocabulary, an exclusion with no
 * sentence, an id whose hash is not its text's, a clause entry pointing at a
 * clause that quotes something else. Those fail here, in the fast gate.
 *
 * The extractor is exercised on a synthetic page of RFC-formatted text, so a
 * change to its rules shows up as a named failure rather than as a changed
 * count the next time someone fetches the corpus.
 */

const ecosystem = JSON.parse(readFileSync('docs/assets/ecosystem.json', 'utf8')) as {
    declared: Record<string, { commit?: string; requirements?: number; clauses?: number; tests?: number; excluded?: number } | undefined>;
};

/** The runner's and verify-docs' check, from the file system: the file holds a runnable case of that title. */
const testExists = (file: string, title: string): boolean => existsSync(file) && titleInSource(readFileSync(file, 'utf8'), title);

const load = (spec: RfcInventorySpec): RequirementsInventory => JSON.parse(readFileSync(spec.data, 'utf8')) as RequirementsInventory;

describe.each(RFC_INVENTORIES.map((spec) => [spec.data, spec] as const))('%s', (_data, spec) => {
    const inventory = load(spec);
    const entries = Object.values(inventory.requirements);

    it('should be reviewed against the pinned text of its RFC', () => {
        expect(inventory.rfc).toBe(spec.rfc);
        expect(inventory.sha256).toBe(CORPORA.find((c) => c.id === spec.corpus)?.commit);
    });

    it('should be well formed, with every reason in the vocabulary, every clause quoting its sentence and every test present', () => {
        expect(checkInventoryShape(inventory, CLAUSES, spec, testExists)).toEqual([]);
    });

    it('should leave nothing todo', () => {
        expect(entries.filter((e) => e.status === 'todo').map((e) => e.text)).toEqual([]);
    });

    it('should account for as many sentences as ecosystem.json declares', () => {
        const declared = ecosystem.declared[spec.declared];
        expect(declared?.commit).toBe(inventory.sha256);
        expect(entries.length).toBe(declared?.requirements);
        expect(entries.filter((e) => e.status === 'clause').length).toBe(declared?.clauses);
        expect(entries.filter((e) => e.status === 'test').length).toBe(declared?.tests);
        expect(entries.filter((e) => e.status === 'excluded').length).toBe(declared?.excluded);
    });

    it('should write every exclusion and every test by hand — no two share a sentence unless their requirements do', () => {
        // Bulk assignment leaves a trace: one sentence pasted across unrelated
        // requirements. A shared "why" is allowed only where the RFC repeats
        // itself (RFC 5280 §4.2.2.1 and §4.2.2.2, the critical-flag sentences).
        const byWhy = new Map<string, Set<string>>();
        for (const e of entries) {
            if (e.status !== 'excluded' && e.status !== 'test') continue;
            byWhy.set(e.why, (byWhy.get(e.why) ?? new Set()).add(e.text));
        }
        for (const [why, texts] of byWhy) expect(texts.size, why).toBe(1);
    });

    it('should record a decision for every verified erratum it considered', () => {
        for (const erratum of inventory.errata) {
            expect(spec.sections(erratum.section), String(erratum.id)).toBe(true);
            expect(erratum.decision, String(erratum.id)).toMatch(/^Verified. .{40,}/);
        }
    });
});

describe('the exclusion vocabulary', () => {
    it('should use only reasons with a written meaning', () => {
        for (const [reason, meaning] of Object.entries(EXCLUSION_REASONS)) expect(meaning.length, reason).toBeGreaterThan(40);
    });

    it('should list RFC 5280 first, each RFC once, each with its own data file and corpus', () => {
        expect(RFC_INVENTORIES[0]).toBe(RFC5280_INVENTORY);
        for (const key of ['rfc', 'corpus', 'data', 'declared'] as const) {
            expect(new Set(RFC_INVENTORIES.map((spec) => spec[key])).size, key).toBe(RFC_INVENTORIES.length);
        }
        for (const spec of RFC_INVENTORIES) expect(CORPORA.some((c) => c.id === spec.corpus), spec.corpus).toBe(true);
    });
});

// ── The extractor, on a page it can be checked against ────────────────

const PAGE = [
    '4.1.  Basic Certificate Fields',
    '',
    '   Certificate  ::=  SEQUENCE  {',
    '        tbsCertificate       TBSCertificate }',
    '',
    '        extensions      [3]  EXPLICIT Extensions OPTIONAL',
    '                             -- If present, version MUST be v3',
    '        }',
    '',
    '4.1.2.2.  Serial Number',
    '',
    '   The serial number MUST be a positive integer (e.g., one) assigned by',
    '   the CA.  Conforming CAs MUST NOT use values longer than 20 octets.',
    '   The field MAY be long.  Readers may be lenient.  Readers SHOULD be',
    '   prepared for this, and the extension SHOULD be marked non-',
    '   critical by conforming CAs.  A value',
    '',
    '',
    '',
    'Cooper, et al.              Standards Track                    [Page 19]',
    '\f',
    'RFC 5280            PKIX Certificate and CRL Profile            May 2008',
    '',
    '',
    '   that is zero is REQUIRED to be refused.',
    '',
    '5.  CRL and CRL Extensions Profile',
    '',
    '   The CRL MUST be ignored here.',
    '',
].join('\n');

describe('extractRequirements', () => {
    const found = extractRequirements(PAGE, RFC5280_INVENTORY);

    it('should read §4.1 and §4.2 only, and skip ASN.1 with its comments', () => {
        expect(found.every((r) => r.section === '4.1.2.2')).toBe(true);
    });

    it('should split on the RFC\'s two-space typography and not after e.g.', () => {
        expect(found[0]?.text).toBe('The serial number MUST be a positive integer (e.g., one) assigned by the CA.');
        expect(found[1]?.text).toBe('Conforming CAs MUST NOT use values longer than 20 octets.');
    });

    it('should leave MAY and lower-case keywords out of the requirement set', () => {
        expect(found.map((r) => r.text)).not.toContain('The field MAY be long.');
        expect(found.map((r) => r.text)).not.toContain('Readers may be lenient.');
        expect(keywordsOf('A value MUST NOT be set and SHOULD be absent.')).toEqual(['MUST NOT', 'SHOULD']);
    });

    it('should rejoin a word wrapped at its hyphen, keeping the hyphen', () => {
        expect(found[2]?.text).toBe('Readers SHOULD be prepared for this, and the extension SHOULD be marked non-critical by conforming CAs.');
    });

    it('should join a sentence a page break cut in two and drop the page furniture', () => {
        expect(found[3]?.text).toBe('A value that is zero is REQUIRED to be refused.');
        expect(found).toHaveLength(4);
    });

    it('should give every sentence a <section>-<ordinal>-<hash> id', () => {
        expect(found.map((r) => r.id)).toEqual(found.map((r, i) => `4.1.2.2-${String(i + 1)}-${sentenceHash(r.text)}`));
    });
});

describe('checkInventoryAgainstRfc', () => {
    const complete: RequirementsInventory = {
        $comment: '',
        rfc: 'RFC 5280',
        sha256: '',
        errata: [],
        requirements: Object.fromEntries(extractRequirements(PAGE, RFC5280_INVENTORY).map((r) => [r.id, { section: r.section, text: r.text, status: 'todo' as const }])),
    };

    it('should find a quote that is in the section it cites, whatever the line wraps', () => {
        const clause = { id: 'x', section: 'RFC 5280 §4.1.2.2', quote: 'Conforming CAs MUST NOT use values longer than 20 octets.' };
        expect(checkInventoryAgainstRfc(PAGE, complete, [clause], RFC5280_INVENTORY).problems).toEqual([]);
    });

    it('should refuse a quote the RFC does not contain', () => {
        const invented = { id: 'x', section: 'RFC 5280 §4.1.2.2', quote: 'Conforming CAs MUST NOT use values longer than 21 octets.' };
        expect(checkInventoryAgainstRfc(PAGE, complete, [invented], RFC5280_INVENTORY).problems).toEqual([expect.stringContaining('someone invented')]);
    });

    it('should refuse a quote found only in another section', () => {
        const misplaced = { id: 'x', section: 'RFC 5280 §5', quote: 'Conforming CAs MUST NOT use values longer than 20 octets.' };
        expect(checkInventoryAgainstRfc(PAGE, complete, [misplaced], RFC5280_INVENTORY).problems).toHaveLength(1);
    });

    it('should report an unaccounted sentence and a stale entry', () => {
        const [first, ...rest] = Object.entries(complete.requirements);
        const stale = { ...complete, requirements: { ...Object.fromEntries(rest), '4.1.2.2-9-00000000': first?.[1] as never } };
        const problems = checkInventoryAgainstRfc(PAGE, stale, [], RFC5280_INVENTORY).problems;
        expect(problems).toEqual([expect.stringContaining('not accounted for'), expect.stringContaining('stale')]);
    });

    it('should list todo entries for the runner to weigh', () => {
        expect(checkInventoryAgainstRfc(PAGE, complete, [], RFC5280_INVENTORY).todo).toHaveLength(4);
    });
});

// ── A `test` entry, and the other RFCs' typography ────────────────────

describe('checkInventoryShape — test entries', () => {
    const [requirement] = extractRequirements(PAGE, RFC5280_INVENTORY);
    const id = requirement?.id ?? '';
    const withEntry = (entry: Record<string, unknown>): RequirementsInventory => ({
        $comment: '', rfc: 'RFC 5280', sha256: '', errata: [],
        requirements: { [id]: { section: requirement?.section, text: requirement?.text, ...entry } as never },
    });
    const always = (): boolean => true;
    const never = (): boolean => false;
    const why = 'The test builds a serial number and expects the refusal it names.';

    it('should accept a test entry whose file holds the title, with a sentence saying why', () => {
        expect(checkInventoryShape(withEntry({ status: 'test', file: 'tests/x/y.test.ts', test: 'should refuse it', why }), [], RFC5280_INVENTORY, always)).toEqual([]);
    });

    it('should refuse a test that is gone, a path outside tests/ and a missing why', () => {
        expect(checkInventoryShape(withEntry({ status: 'test', file: 'tests/x/y.test.ts', test: 'should refuse it', why }), [], RFC5280_INVENTORY, never))
            .toEqual([expect.stringContaining('renamed or removed')]);
        expect(checkInventoryShape(withEntry({ status: 'test', file: 'src/x.ts', test: 'should refuse it', why }), [], RFC5280_INVENTORY, always))
            .toEqual([expect.stringContaining('not a tests/**/*.test.ts path')]);
        expect(checkInventoryShape(withEntry({ status: 'test', file: 'tests/x/y.test.ts', test: 'should refuse it', why: 'TODO' }), [], RFC5280_INVENTORY, always))
            .toEqual([expect.stringContaining('without a sentence saying what it exercises')]);
    });

    it('should refuse an inventory filed under another RFC, and a section outside the spec', () => {
        const other = RFC_INVENTORIES.find((spec) => spec.rfc === 'RFC 3161') as RfcInventorySpec;
        const problems = checkInventoryShape(withEntry({ status: 'todo' }), [], other, always);
        expect(problems).toEqual([expect.stringContaining('names RFC 5280, not RFC 3161'), expect.stringContaining('is outside §2.3–§2.4')]);
    });
});

describe('titleInSource', () => {
    const source = [
        "describe('the parser', () => {",
        "    it('should refuse a serial of zero', () => {});",
        "    it.skip('should refuse a skipped case', () => {});",
        "    // should refuse a title found only in a comment",
        "    it.each([1, 2])(",
        "        'should refuse row %s of a table', (row) => {});",
        "    expect(x).toBe('should refuse an assertion string');",
        '});',
    ].join('\n');

    it('should find the title of an it, a describe and a wrapped it.each', () => {
        expect(titleInSource(source, 'should refuse a serial of zero')).toBe(true);
        expect(titleInSource(source, 'the parser')).toBe(false);
        expect(titleInSource(source, 'should refuse row %s of a table')).toBe(true);
    });

    it('should not count a skipped case, a comment, an assertion or a title too short to be unique', () => {
        expect(titleInSource(source, 'should refuse a skipped case')).toBe(false);
        expect(titleInSource(source, 'should refuse a title found only in a comment')).toBe(false);
        expect(titleInSource(source, 'should refuse an assertion string')).toBe(false);
        expect(titleInSource(source, 'should')).toBe(false);
    });
});

describe('extractRequirements — the other RFCs', () => {
    const TSP = [
        '2.4.2. Response Format',
        '',
        '   When the status contains the value zero, a token MUST be present.',
        '',
    ].join('\n');
    const PKCS12 = [
        '4.  PFX PDU Syntax',
        '',
        '   1.  A version indicator.  The version shall be v3 for this version',
        '       of this document.',
        '',
        'Appendix B.  Deriving Keys and IVs from Passwords and Salt',
        '',
        'B.1.  Password Formatting',
        '',
        '   The password shall be a BMPString.',
        '',
    ].join('\n');
    const spec = (rfc: string): RfcInventorySpec => RFC_INVENTORIES.find((s) => s.rfc === rfc) as RfcInventorySpec;

    it('should read a heading with one space after its number, as RFC 3161 writes them', () => {
        expect(extractRequirements(TSP, spec('RFC 3161')).map((r) => r.section)).toEqual(['2.4.2']);
    });

    it('should read lower-case keywords only where the spec says so, report them in capitals, and never read an appendix', () => {
        const found = extractRequirements(PKCS12, spec('RFC 7292'));
        expect(found.map((r) => r.text)).toEqual(['The version shall be v3 for this version of this document.']);
        expect(found[0]?.keywords).toEqual(['SHALL']);
        expect(extractRequirements(PKCS12, { ...spec('RFC 7292'), anyCase: false })).toEqual([]);
    });
});
