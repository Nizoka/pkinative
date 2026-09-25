import { describe, expect, it } from 'vitest';
import { CLAUSES } from '../../scripts/lib/clauses.js';
import { evaluateClauses, EVALUATED_CLAUSE_IDS } from '../../scripts/validators/rfc5280-clauses.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The clause checker, exercised on certificates built here.
 *
 * The corpus run (L5, `scripts/validate-certs.ts`) tells you how often each
 * clause fires on 30 361 real certificates; it cannot tell you that an
 * evaluator which always returns `pass` is wrong. That is what this file is
 * for: every clause gets a certificate that **violates** it and one that
 * satisfies it, built from raw DER, so an evaluator that decided nothing
 * would go red here rather than quietly reporting a clean corpus.
 *
 * It also carries the two clauses x509-limbo cannot reach — a unique
 * identifier and a multi-valued RDN — which is what their `unexercisedBy`
 * waivers point at. A waiver whose named suite did not actually exercise the
 * clause would be worse than no clause at all.
 */

// ── A minimal certificate, assembled field by field ──────────────────

const OID_CN = universal(6, [0x55, 0x04, 0x03]);
const OID_C = universal(6, [0x55, 0x04, 0x06]);

const attribute = (oid: Uint8Array, value: string): Uint8Array => sequence(oid, universal(12, ascii(value)));
const rdn = (...attributes: readonly Uint8Array[]): Uint8Array => universal(17, concat(...attributes), true);
const name = (...rdns: readonly Uint8Array[]): Uint8Array => sequence(...rdns);

const ALG_ED25519 = sequence(universal(6, [0x2b, 0x65, 0x70]));
const SPKI = sequence(ALG_ED25519, universal(3, [0x00, ...new Array<number>(32).fill(0x11)]));
const UTC = (text: string): Uint8Array => universal(23, ascii(text));
const GEN = (text: string): Uint8Array => universal(24, ascii(text));
const VALIDITY = sequence(UTC('260101000000Z'), UTC('270101000000Z'));
const SUBJECT = name(rdn(attribute(OID_CN, 'sample')));

interface Parts {
    readonly version?: Uint8Array | null;
    readonly serial?: Uint8Array;
    readonly issuer?: Uint8Array;
    readonly validity?: Uint8Array;
    readonly subject?: Uint8Array;
    readonly uniqueId?: Uint8Array;
    readonly extensions?: readonly Uint8Array[] | null;
    readonly outerAlgorithm?: Uint8Array;
}

/** A structurally complete certificate; only the fields under test vary. */
function certificate(parts: Parts = {}): Uint8Array {
    const extensions = parts.extensions === undefined ? null : parts.extensions;
    const version = parts.version === undefined
        ? (extensions === null ? null : tlv(2, true, 0, universal(2, [2])))
        : parts.version;
    const tbs = sequence(
        ...(version === null ? [] : [version]),
        parts.serial ?? universal(2, [0x01]),
        ALG_ED25519,
        parts.issuer ?? name(rdn(attribute(OID_CN, 'issuer'))),
        parts.validity ?? VALIDITY,
        parts.subject ?? SUBJECT,
        SPKI,
        ...(parts.uniqueId === undefined ? [] : [parts.uniqueId]),
        ...(extensions === null ? [] : [tlv(2, true, 3, sequence(...extensions))]),
    );
    return sequence(tbs, parts.outerAlgorithm ?? ALG_ED25519, universal(3, [0x00, 0xaa]));
}

/** An Extension, with `critical` written out only when asked. */
function extension(oid: readonly number[], value: Uint8Array, critical?: boolean): Uint8Array {
    return sequence(
        universal(6, oid),
        ...(critical === undefined ? [] : [universal(1, [critical ? 0xff : 0x00])]),
        universal(4, value),
    );
}

const BASIC_CONSTRAINTS = [0x55, 0x1d, 0x13];
const KEY_USAGE = [0x55, 0x1d, 0x0f];
const SAN = [0x55, 0x1d, 0x11];
const NAME_CONSTRAINTS = [0x55, 0x1d, 0x1e];
const CERTIFICATE_POLICIES = [0x55, 0x1d, 0x20];
const POLICY_CONSTRAINTS = [0x55, 0x1d, 0x24];
const AKI = [0x55, 0x1d, 0x23];

const verdict = (der: Uint8Array, id: string): string => evaluateClauses(der).get(id) ?? 'missing';

// ── One failing and one passing certificate per clause ───────────────

interface Case {
    readonly id: string;
    readonly fails: Uint8Array;
    readonly passes: Uint8Array;
}

const CASES: readonly Case[] = [
    {
        id: '4.1.2.2-serial-positive',
        fails: certificate({ serial: universal(2, [0x80, 0x01]) }),
        passes: certificate({ serial: universal(2, [0x01]) }),
    },
    {
        id: '4.1.2.2-serial-at-most-20-octets',
        fails: certificate({ serial: universal(2, [0x01, ...new Array<number>(20).fill(0x02)]) }),
        passes: certificate({ serial: universal(2, [0x01, ...new Array<number>(19).fill(0x02)]) }),
    },
    {
        id: '4.1.1.2-signature-algorithm-matches-tbs',
        // The outer algorithm names sha256WithRSAEncryption, the inner Ed25519.
        fails: certificate({ outerAlgorithm: sequence(universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), universal(5, [])) }),
        passes: certificate(),
    },
    {
        id: '4.1.2.1-extensions-require-v3',
        fails: certificate({ version: null, extensions: [extension(BASIC_CONSTRAINTS, sequence())] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence())] }),
    },
    {
        id: '4.1.2.8-unique-id-requires-v2',
        // x509-limbo has no such certificate; this is what its waiver names.
        fails: certificate({ version: null, uniqueId: tlv(2, false, 1, [0x00, 0xff]) }),
        passes: certificate({ version: tlv(2, true, 0, universal(2, [1])), uniqueId: tlv(2, false, 1, [0x00, 0xff]) }),
    },
    {
        id: '4.1.2.5-generalized-time-only-from-2050',
        fails: certificate({ validity: sequence(GEN('20260101000000Z'), UTC('270101000000Z')) }),
        passes: certificate({ validity: sequence(UTC('260101000000Z'), GEN('20510101000000Z')) }),
    },
    {
        id: '4.1.2.5.2-generalized-time-no-fraction',
        fails: certificate({ validity: sequence(UTC('260101000000Z'), GEN('20510101000000.5Z')) }),
        passes: certificate({ validity: sequence(UTC('260101000000Z'), GEN('20510101000000Z')) }),
    },
    {
        id: '4.1.2.4-issuer-not-empty',
        fails: certificate({ issuer: sequence() }),
        passes: certificate(),
    },
    {
        id: '4.2-critical-default-absent',
        fails: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(), false)] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(), true)] }),
    },
    {
        id: '4.2.1.9-path-len-requires-ca',
        // pathLenConstraint with cA taking its DEFAULT of FALSE.
        fails: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(universal(2, [0x00])))] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(universal(1, [0xff]), universal(2, [0x00])))] }),
    },
    {
        id: '4.2.1.3-key-usage-not-empty',
        fails: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x00]))] }),
        passes: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80]))] }),
    },
    {
        id: '4.2.1.6-alt-name-not-empty',
        fails: certificate({ extensions: [extension(SAN, sequence())] }),
        passes: certificate({ extensions: [extension(SAN, sequence(tlv(2, false, 2, ascii('a.example'))))] }),
    },
    {
        id: '4.2.1.10-name-constraints-critical',
        fails: certificate({ extensions: [extension(NAME_CONSTRAINTS, sequence())] }),
        passes: certificate({ extensions: [extension(NAME_CONSTRAINTS, sequence(), true)] }),
    },
    {
        id: '4.2.1.11-policy-constraints-not-empty',
        fails: certificate({ extensions: [extension(POLICY_CONSTRAINTS, sequence(), true)] }),
        passes: certificate({ extensions: [extension(POLICY_CONSTRAINTS, sequence(tlv(2, false, 0, [0x00])), true)] }),
    },
    {
        id: '4.2.1.4-policies-not-duplicated',
        fails: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(universal(6, [0x2a, 0x03])), sequence(universal(6, [0x2a, 0x03]))))] }),
        passes: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(universal(6, [0x2a, 0x03])), sequence(universal(6, [0x2a, 0x04]))))] }),
    },
    {
        id: '4.2.1.1-aki-issuer-and-serial-paired',
        fails: certificate({ extensions: [extension(AKI, sequence(tlv(2, true, 1, sequence())))] }),
        passes: certificate({ extensions: [extension(AKI, sequence(tlv(2, true, 1, sequence()), tlv(2, false, 2, [0x01])))] }),
    },
    {
        id: 'x690-11.6-rdn-set-sorted',
        // Two attributes in one RDN, in descending encoded order. The corpus
        // has no multi-valued RDN at all; this is what its waiver names.
        fails: certificate({ subject: name(rdn(attribute(OID_C, 'zz'), attribute(OID_CN, 'aa'))) }),
        passes: certificate({ subject: name(rdn(attribute(OID_CN, 'aa'), attribute(OID_C, 'zz'))) }),
    },
    {
        id: 'x690-11.2.2-named-bits-trimmed',
        // 0x80 0x00 with 7 unused bits: the trailing zero octet DER removes.
        fails: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80, 0x00]))] }),
        passes: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80]))] }),
    },
    {
        id: '4.1.2.6-empty-subject-requires-critical-san',
        fails: certificate({ subject: sequence(), extensions: [extension(SAN, sequence(tlv(2, false, 2, ascii('a.example'))))] }),
        passes: certificate({ subject: sequence(), extensions: [extension(SAN, sequence(tlv(2, false, 2, ascii('a.example'))), true)] }),
    },
];

describe('the RFC 5280 clause checker', () => {
    it('should have an evaluator for every clause, and a clause for every evaluator', () => {
        expect(EVALUATED_CLAUSE_IDS).toEqual([...CLAUSES.map((c) => c.id)].sort());
    });

    it('should have a failing and a passing certificate for every clause', () => {
        // Without this, a clause could be added to the table and silently
        // never tested — which is the failure mode the table exists to fix.
        expect(CASES.map((c) => c.id).sort()).toEqual([...CLAUSES.map((c) => c.id)].sort());
    });

    it.each(CASES)('$id should fail on a violating certificate', ({ id, fails }) => {
        expect(verdict(fails, id)).toBe('fail');
    });

    it.each(CASES)('$id should pass on a conforming certificate', ({ id, passes }) => {
        expect(verdict(passes, id)).toBe('pass');
    });

    it('should call a clause not-applicable rather than failed when the field is absent', () => {
        // The distinction that keeps attribution honest: a certificate with
        // no keyUsage does not violate §4.2.1.3, it is simply outside it.
        const bare = certificate();
        for (const id of ['4.2.1.3-key-usage-not-empty', '4.2.1.9-path-len-requires-ca', '4.2.1.6-alt-name-not-empty', '4.2.1.10-name-constraints-critical']) {
            expect(verdict(bare, id), id).toBe('not-applicable');
        }
    });

    it('should decide nothing at all about bytes that are not a certificate', () => {
        // L1 already judges whether these parse. A checker that reported
        // "clause violated" for unreadable bytes would attribute the wrong
        // thing to the wrong sentence.
        for (const bytes of [new Uint8Array(0), universal(2, [0x01]), sequence(universal(2, [0x01]))]) {
            const verdicts = [...evaluateClauses(bytes).values()];
            expect(verdicts.every((v) => v === 'not-applicable')).toBe(true);
        }
    });

    it('should name a suite for every clause the pinned corpus cannot exercise', () => {
        for (const clause of CLAUSES) {
            if (clause.unexercisedBy === undefined) continue;
            expect(clause.unexercisedBy.provenBy, clause.id).toBe('tests/conformance/clauses.test.ts');
            expect(clause.unexercisedBy.reason.length, clause.id).toBeGreaterThan(40);
            expect(CASES.some((c) => c.id === clause.id), `${clause.id} is waived but not exercised here`).toBe(true);
        }
    });

    it('should quote a normative sentence, not a paraphrase, for every clause', () => {
        for (const clause of CLAUSES) {
            expect(clause.quote, clause.id).toMatch(/\b(MUST|SHOULD|shall|MAY)\b/);
            expect(clause.section, clause.id).toMatch(/^(RFC \d+|ITU-T X\.\d+) §[\d.]+$/);
            if (clause.diagnostic === null) expect(clause.waiver, clause.id).toBeTruthy();
        }
    });
});
