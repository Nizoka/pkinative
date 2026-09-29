import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CLAUSES } from '../../scripts/lib/clauses.js';
import { CORPORA } from '../../scripts/lib/corpora.js';
import {
    checkInventoryAgainstRfc,
    checkInventoryShape,
    EXCLUSION_REASONS,
    extractRequirements,
    keywordsOf,
    sentenceHash,
    type RequirementsInventory,
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

const inventory = JSON.parse(readFileSync('scripts/data/rfc5280-requirements.json', 'utf8')) as RequirementsInventory;
const ecosystem = JSON.parse(readFileSync('docs/assets/ecosystem.json', 'utf8')) as {
    declared: { rfc5280?: { commit?: string; requirements?: number; clauses?: number; excluded?: number } };
};
const entries = Object.values(inventory.requirements);

describe('scripts/data/rfc5280-requirements.json', () => {
    it('should be reviewed against the pinned text of RFC 5280', () => {
        expect(inventory.sha256).toBe(CORPORA.find((c) => c.id === 'rfc5280')?.commit);
    });

    it('should be well formed, with every reason in the vocabulary and every clause quoting its sentence', () => {
        expect(checkInventoryShape(inventory, CLAUSES)).toEqual([]);
    });

    it('should account for as many sentences as ecosystem.json declares', () => {
        const declared = ecosystem.declared.rfc5280;
        expect(entries.length).toBe(declared?.requirements);
        expect(entries.filter((e) => e.status === 'clause').length).toBe(declared?.clauses);
        expect(entries.filter((e) => e.status === 'excluded').length).toBe(declared?.excluded);
    });

    it('should write every exclusion by hand — no two share a sentence unless their requirements do', () => {
        // Bulk assignment leaves a trace: one sentence pasted across unrelated
        // requirements. A shared "why" is allowed only where the RFC repeats
        // itself (§4.2.2.1 and §4.2.2.2, the critical-flag sentences).
        const byWhy = new Map<string, Set<string>>();
        for (const e of entries) {
            if (e.status !== 'excluded') continue;
            byWhy.set(e.why, (byWhy.get(e.why) ?? new Set()).add(e.text));
        }
        for (const [why, texts] of byWhy) expect(texts.size, why).toBe(1);
    });

    it('should use only reasons with a written meaning', () => {
        for (const [reason, meaning] of Object.entries(EXCLUSION_REASONS)) expect(meaning.length, reason).toBeGreaterThan(40);
    });

    it('should record a decision for every verified erratum it considered', () => {
        for (const erratum of inventory.errata) {
            expect(erratum.section, String(erratum.id)).toMatch(/^4\.[12](\.|$)/);
            expect(erratum.decision, String(erratum.id)).toMatch(/^Verified\. .{40,}/);
        }
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
    const found = extractRequirements(PAGE);

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
        requirements: Object.fromEntries(extractRequirements(PAGE).map((r) => [r.id, { section: r.section, text: r.text, status: 'todo' as const }])),
    };

    it('should find a quote that is in the section it cites, whatever the line wraps', () => {
        const clause = { id: 'x', section: 'RFC 5280 §4.1.2.2', quote: 'Conforming CAs MUST NOT use values longer than 20 octets.' };
        expect(checkInventoryAgainstRfc(PAGE, complete, [clause]).problems).toEqual([]);
    });

    it('should refuse a quote the RFC does not contain', () => {
        const invented = { id: 'x', section: 'RFC 5280 §4.1.2.2', quote: 'Conforming CAs MUST NOT use values longer than 21 octets.' };
        expect(checkInventoryAgainstRfc(PAGE, complete, [invented]).problems).toEqual([expect.stringContaining('someone invented')]);
    });

    it('should refuse a quote found only in another section', () => {
        const misplaced = { id: 'x', section: 'RFC 5280 §5', quote: 'Conforming CAs MUST NOT use values longer than 20 octets.' };
        expect(checkInventoryAgainstRfc(PAGE, complete, [misplaced]).problems).toHaveLength(1);
    });

    it('should report an unaccounted sentence and a stale entry', () => {
        const [first, ...rest] = Object.entries(complete.requirements);
        const stale = { ...complete, requirements: { ...Object.fromEntries(rest), '4.1.2.2-9-00000000': first?.[1] as never } };
        const problems = checkInventoryAgainstRfc(PAGE, stale, []).problems;
        expect(problems).toEqual([expect.stringContaining('not accounted for'), expect.stringContaining('stale')]);
    });

    it('should list todo entries for the runner to weigh', () => {
        expect(checkInventoryAgainstRfc(PAGE, complete, []).todo).toHaveLength(4);
    });
});
