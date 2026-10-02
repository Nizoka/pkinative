import { describe, expect, it } from 'vitest';
import { checkServerName, matchDnsName, type ServerIdentity } from '../../src/path/path-server-name.js';
import type { Certificate, GeneralName, GeneralSubtree } from '../../src/types/x509-types.js';

/**
 * RFC 6125 server identity matching.
 *
 * This is the most CVE-dense function in the library, so the table below is
 * mostly negatives: every row asserting `false` is a certificate some
 * implementation has accepted for a host it was not issued for. A verified
 * chain says a CA vouched for a certificate; it says nothing about which host
 * the certificate is *for*, and the gap between those two is the whole reason
 * this file exists.
 */

const dns = (value: string): GeneralName => ({ kind: 'dNSName', value, der: new Uint8Array(0) });
const ip = (bytes: readonly number[], address = 'x'): GeneralName =>
    ({ kind: 'iPAddress', version: bytes.length > 4 ? 6 : 4, address, mask: undefined, bytes: Uint8Array.from(bytes), der: new Uint8Array(0) });
const email = (value: string): GeneralName => ({ kind: 'rfc822Name', value, der: new Uint8Array(0) });

/** A certificate with the given SAN entries and commonNames, and nothing else. */
function certificate(options: { names?: readonly GeneralName[]; commonNames?: readonly string[] } = {}): Certificate {
    const rdns = (options.commonNames ?? []).map((value) => [{
        type: '2.5.4.3',
        value: { stringType: 'utf8', value, raw: new Uint8Array(0) },
        valueDer: new Uint8Array(0),
    }]);
    const extensions = options.names === undefined
        ? []
        : [{ kind: 'subjectAltName', oid: '2.5.29.17', critical: false, valueDer: new Uint8Array(0), names: options.names }];
    return { der: Uint8Array.of(serial++), subject: { rdns, der: new Uint8Array(0) }, extensions } as unknown as Certificate;
}

let serial = 1;

/** A CA carrying the given nameConstraints, and nothing else. */
function constrainedCa(permitted: readonly GeneralName[] | undefined, excluded: readonly GeneralName[] | undefined = undefined): Certificate {
    const subtrees = (names: readonly GeneralName[] | undefined): readonly GeneralSubtree[] | undefined => names?.map((base) => ({ base, minimum: 0, maximum: undefined }));
    return {
        der: Uint8Array.of(serial++),
        subject: { rdns: [], der: new Uint8Array(0) },
        extensions: [{ kind: 'nameConstraints', oid: '2.5.29.30', critical: true, valueDer: new Uint8Array(0), permittedSubtrees: subtrees(permitted), excludedSubtrees: subtrees(excluded) }],
    } as unknown as Certificate;
}

/** The fallback, with a path that constrains nothing. */
const FALLBACK = { allowCommonNameFallback: true, path: [] };

const host = (value: string): ServerIdentity => ({ kind: 'dns', value });
const address = (...bytes: readonly number[]): ServerIdentity => ({ kind: 'ip', value: Uint8Array.from(bytes) });

const codes = (reasons: readonly { code: string }[]): string[] => reasons.map((r) => r.code);

describe('matchDnsName — RFC 6125 §6.4', () => {
    it.each([
        // ── Exact ──
        { presented: 'example.com', reference: 'example.com', expected: true },
        { presented: 'EXAMPLE.com', reference: 'example.COM', expected: true },
        { presented: 'a.b.example.com', reference: 'a.b.example.com', expected: true },
        // One trailing dot is an absolute name, not a different one.
        { presented: 'example.com.', reference: 'example.com', expected: true },
        { presented: 'example.com', reference: 'example.com.', expected: true },
        // ── Wildcards that work ──
        { presented: '*.example.com', reference: 'host.example.com', expected: true },
        { presented: '*.EXAMPLE.com', reference: 'HOST.example.com', expected: true },
        // ── Wildcards that must not ──
        // A wildcard consumes exactly one label, so it never matches the parent.
        { presented: '*.example.com', reference: 'example.com', expected: false },
        // …nor two labels.
        { presented: '*.example.com', reference: 'a.b.example.com', expected: false },
        // Partial wildcards: RFC 6125 §6.4.3 once allowed them, browsers do not.
        { presented: 'f*.example.com', reference: 'foo.example.com', expected: false },
        { presented: '*o.example.com', reference: 'foo.example.com', expected: false },
        // Not leftmost.
        { presented: 'a.*.example.com', reference: 'a.b.example.com', expected: false },
        // A second star is refused even against a reference that spells one.
        { presented: '*.*.example.com', reference: 'a.*.example.com', expected: false },
        // An empty presented name identifies nothing, even against the root,
        // which its trailing-dot rule would otherwise make it equal to.
        { presented: '', reference: '.', expected: false },
        { presented: '.', reference: '', expected: false },
        { presented: 'example.*', reference: 'example.com', expected: false },
        // Two wildcards.
        { presented: '*.*.example.com', reference: 'a.b.example.com', expected: false },
        // Bare, and registry-level: the correct test is a public suffix list,
        // which this library will not carry stale, so fewer than three labels
        // is refused outright.
        { presented: '*', reference: 'example.com', expected: false },
        { presented: '*.com', reference: 'example.com', expected: false },
        { presented: '*.', reference: 'a.', expected: false },
        // An empty label on either side identifies nothing.
        { presented: '*..com', reference: 'a..com', expected: false },
        { presented: '*.example.com', reference: '.example.com', expected: false },
        // ── The classic suffix bypass ──
        { presented: 'example.com', reference: 'notexample.com', expected: false },
        { presented: 'example.com', reference: 'example.com.evil.test', expected: false },
        { presented: 'host.example.com', reference: 'example.com', expected: false },
        // ── Embedded NUL: CVE-2009-2408's whole mechanism ──
        { presented: 'bank.example\u0000.evil.test', reference: 'bank.example', expected: false },
        { presented: 'bank.example', reference: 'bank.example\u0000.evil.test', expected: false },
        { presented: '', reference: '', expected: false },
        { presented: '', reference: 'example.com', expected: false },
    ])('$presented vs $reference → $expected', ({ presented, reference, expected }) => {
        expect(matchDnsName(presented, reference)).toBe(expected);
    });

    it('should refuse every wildcard when wildcards are turned off', () => {
        expect(matchDnsName('*.example.com', 'host.example.com', { allowWildcards: false })).toBe(false);
        expect(matchDnsName('example.com', 'example.com', { allowWildcards: false })).toBe(true);
    });
});

describe('checkServerName — subjectAltName', () => {
    it('should match a DNS name', () => {
        expect(checkServerName(certificate({ names: [dns('bank.example')] }), host('bank.example'))).toEqual([]);
    });

    it('should match one entry among several', () => {
        const cert = certificate({ names: [dns('a.example'), dns('bank.example'), dns('c.example')] });
        expect(checkServerName(cert, host('bank.example'))).toEqual([]);
    });

    it('should report a mismatch naming both what was wanted and what is there', () => {
        // A bare "name mismatch" tells a reader nothing about whether they have
        // the wrong certificate, the wrong host, or a misissued SAN.
        const reasons = checkServerName(certificate({ names: [dns('other.example')] }), host('bank.example'));
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('bank.example');
        expect(reasons[0]?.message).toContain('other.example');
    });

    it('should match an IP address by bytes', () => {
        expect(checkServerName(certificate({ names: [ip([192, 0, 2, 1], '192.0.2.1')] }), address(192, 0, 2, 1))).toEqual([]);
        expect(codes(checkServerName(certificate({ names: [ip([192, 0, 2, 1])] }), address(192, 0, 2, 2)))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should never let an address match a dNSName, or a host match an iPAddress', () => {
        // `1.2.3.4` written as a DNS name is a whole class of bypass.
        expect(codes(checkServerName(certificate({ names: [dns('192.0.2.1')] }), address(192, 0, 2, 1)))).toEqual(['PKI_REASON_NAME_MISMATCH']);
        // A host name never matches an iPAddress; a `dns` reference that spells
        // an address is an address, and its own block below holds it.
        expect(codes(checkServerName(certificate({ names: [ip([192, 0, 2, 1])] }), host('bank.example')))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should never match an IPv4 address against an IPv6 SAN', () => {
        const mapped = ip([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]);
        expect(codes(checkServerName(certificate({ names: [mapped] }), address(192, 0, 2, 1)))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should make the SAN authoritative even when nothing in it matches', () => {
        // §6.4.4. A certificate with a SAN and a matching CN is a certificate
        // for the SAN's hosts only — reading the CN there would be matching a
        // field no issuer has controlled since 2017.
        const cert = certificate({ names: [dns('other.example')], commonNames: ['bank.example'] });
        expect(codes(checkServerName(cert, host('bank.example'), FALLBACK))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should quote an IPv6 identity as hex rather than as dotted quad', () => {
        // 2001:db8::1. A report that printed 16 octets as `32.1.13.184.0.…`
        // would be unreadable, and a reader comparing it to their own address
        // would conclude the library had mangled it.
        const wanted = Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        const reasons = checkServerName(certificate({ names: [ip([192, 0, 2, 1], '192.0.2.1')] }), { kind: 'ip', value: wanted });
        expect(reasons[0]?.message).toContain('20010db8000000000000000000000001');
    });

    it('should quote an IPv4 identity as a dotted quad', () => {
        const reasons = checkServerName(certificate({ names: [ip([192, 0, 2, 1], '192.0.2.1')] }), address(198, 51, 100, 7));
        expect(reasons[0]?.message).toContain('the address 198.51.100.7');
    });

    it('should not match an address whose octets merely begin like the identity', () => {
        // 192.0.2.1 against an IPv6 address starting with the same four octets.
        const wide = ip([192, 0, 2, 1, ...Array.from({ length: 12 }, () => 0)], 'c000:201::');
        expect(codes(checkServerName(certificate({ names: [wide] }), address(192, 0, 2, 1)))).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(codes(checkServerName(certificate({ names: [ip([192, 0, 2, 1], '192.0.2.1')] }), { kind: 'ip', value: Uint8Array.from([192, 0, 2, 1, ...Array.from({ length: 12 }, () => 0)]) })))
            .toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should refuse a SAN of other forms without the fallback, and say which of the two cases it is', () => {
        // Distinct from "no subjectAltName at all": here the extension is
        // present and simply names no host, which is a different mistake for
        // the reader to fix.
        const reasons = checkServerName(certificate({ names: [email('a@bank.example')], commonNames: ['bank.example'] }), host('bank.example'));
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('carries no dNSName and no iPAddress');
    });

    it('should fall through to the CN rule when the SAN holds no dNSName or iPAddress', () => {
        // The one case RFC 6125 leaves open: a SAN of other forms is not
        // authoritative for a host name.
        const cert = certificate({ names: [email('a@bank.example')], commonNames: ['bank.example'] });
        expect(checkServerName(cert, host('bank.example'), FALLBACK)).toEqual([]);
    });
});

describe('checkServerName — a dns reference that spells an address (RFC 2818 §3.1)', () => {
    const V4 = [192, 0, 2, 1];
    const V6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const MAPPED = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];
    const LEAD = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    it('should never match a dNSName spelling the same digits', () => {
        // The finding: an address passed as a DNS name matched a dNSName
        // "192.0.2.1", which no CA validates as a host.
        expect(codes(checkServerName(certificate({ names: [dns('192.0.2.1')] }), host('192.0.2.1')))).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(codes(checkServerName(certificate({ names: [dns('2001:db8::1')] }), host('2001:db8::1')))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should never match a commonName either', () => {
        expect(codes(checkServerName(certificate({ commonNames: ['192.0.2.1'] }), host('192.0.2.1'), FALLBACK))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it.each([
        // ── IPv4, the one canonical spelling ──
        { reference: '192.0.2.1', san: V4, expected: true },
        { reference: '192.0.2.1.', san: V4, expected: true },
        { reference: '255.255.255.255', san: [255, 255, 255, 255], expected: true },
        { reference: '192.0.2.2', san: V4, expected: false },
        { reference: '192.000.2.1', san: V4, expected: false },
        { reference: '3221225985', san: V4, expected: false },
        { reference: '0xc0.0.2.1', san: V4, expected: false },
        { reference: '192.0.2', san: V4, expected: false },
        { reference: '256.0.2.1', san: V4, expected: false },
        // ── IPv6, RFC 4291 §2.2 ──
        { reference: '2001:db8::1', san: V6, expected: true },
        { reference: '[2001:db8::1]', san: V6, expected: true },
        { reference: '2001:DB8:0:0:0:0:0:1', san: V6, expected: true },
        { reference: '2001:db8::0:1', san: V6, expected: true },
        { reference: '::ffff:192.0.2.1', san: MAPPED, expected: true },
        { reference: '0:0:0:0:0:ffff:192.0.2.1', san: MAPPED, expected: true },
        { reference: '0000:0000:0000:0000:0000:ffff:192.0.2.1', san: MAPPED, expected: true },
        { reference: '1::', san: LEAD, expected: true },
        { reference: '::', san: new Array<number>(16).fill(0), expected: true },
        { reference: '0000:0000:0000:0000:0000:ffff:255.255.255.255', san: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 255, 255, 255, 255], expected: true },
        { reference: '::ffff:192.0.2.1', san: V4, expected: false },
        { reference: '2001:db8::1%eth0', san: V6, expected: false },
        { reference: '2001:db8:::1', san: V6, expected: false },
        { reference: '2001::db8::1', san: V6, expected: false },
        { reference: '2001:db8:0:0:0:0:1', san: V6, expected: false },
        { reference: '2001:db8::0:0:0:0:0:1', san: V6, expected: false },
        { reference: '2001:db8:0:0:0:0:0:0:1', san: V6, expected: false },
        { reference: '192.0.2.1::', san: MAPPED, expected: false },
        { reference: ':2001:db8::1', san: V6, expected: false },
        { reference: '2001:db8::1:', san: V6, expected: false },
        { reference: '12345::', san: LEAD, expected: false },
    ])('should read "$reference" as an address: matches=$expected', ({ reference, san, expected }) => {
        const reasons = checkServerName(certificate({ names: [ip(san), dns(reference)] }), host(reference));
        expect(codes(reasons)).toEqual(expected ? [] : ['PKI_REASON_NAME_MISMATCH']);
    });

    it('should leave a host name with numeric labels that is not numeric at the end alone', () => {
        expect(checkServerName(certificate({ names: [dns('1.2.3.example')] }), host('1.2.3.example'))).toEqual([]);
        expect(codes(checkServerName(certificate({ names: [dns('example.123')] }), host('example.123')))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should match nothing for a reference that carries a wildcard', () => {
        expect(matchDnsName('*.example.com', '*.example.com')).toBe(false);
        expect(codes(checkServerName(certificate({ names: [dns('*.example.com')] }), host('*.example.com')))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });
});

describe('checkServerName — the commonName fallback', () => {
    it('should be off by default, and say so', () => {
        const reasons = checkServerName(certificate({ commonNames: ['bank.example'] }), host('bank.example'));
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('commonName fallback was not asked for');
    });

    it('should match a commonName when explicitly asked', () => {
        expect(checkServerName(certificate({ commonNames: ['bank.example'] }), host('bank.example'), FALLBACK)).toEqual([]);
    });

    it('should honour a wildcard commonName under the same rules', () => {
        const cert = certificate({ commonNames: ['*.bank.example'] });
        expect(checkServerName(cert, host('www.bank.example'), FALLBACK)).toEqual([]);
        expect(codes(checkServerName(cert, host('bank.example'), FALLBACK))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should never match an address against a commonName', () => {
        // An IP in a CN is text, and comparing an address to text is how a
        // certificate for "127.0.0.1" the string gets accepted for the host.
        const cert = certificate({ commonNames: ['192.0.2.1'] });
        expect(codes(checkServerName(cert, address(192, 0, 2, 1), FALLBACK))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should try every commonName of a multi-CN subject', () => {
        const cert = certificate({ commonNames: ['a.example', 'bank.example'] });
        expect(checkServerName(cert, host('bank.example'), FALLBACK)).toEqual([]);
    });

    it('should report the commonNames it did find', () => {
        const reasons = checkServerName(certificate({ commonNames: ['other.example'] }), host('bank.example'), FALLBACK);
        expect(reasons[0]?.message).toContain('other.example');
        expect(reasons[0]?.path).toBe('certificate.subject');
    });

    it('should ignore a commonName that is not a character string', () => {
        // `AttributeTypeAndValue.value` is `undefined` when the value is of any
        // other ASN.1 type — an OID, an INTEGER, a SEQUENCE. A certificate whose
        // commonName is not text names no host, and reading its raw DER as one
        // would be inventing a name the issuer never wrote.
        const cert = {
            subject: { rdns: [[{ type: '2.5.4.3', value: undefined, valueDer: new Uint8Array(0) }]], der: new Uint8Array(0) },
            extensions: [],
        } as unknown as Certificate;
        const reasons = checkServerName(cert, host('bank.example'), FALLBACK);
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('(none)');
    });

    it('should report "(none)" rather than nothing for a subject with no commonName', () => {
        const reasons = checkServerName(certificate({ commonNames: [] }), host('bank.example'), FALLBACK);
        expect(reasons[0]?.message).toContain('(none)');
    });

    it('should refuse the fallback without the validated path, and say what it needs', () => {
        // A commonName read as a host is held to the path's dNSName
        // constraints, and without the path there is nothing to hold it to.
        const reasons = checkServerName(certificate({ commonNames: ['bank.example'] }), host('bank.example'), { allowCommonNameFallback: true });
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('needs options.path');
    });

    it('should hold a commonName to the dNSName constraints of the CAs that issued it', () => {
        // The audit's chain: an intermediate permitting only example.com, a
        // CN-only leaf for www.evil.test. OpenSSL refuses it (error 47); a
        // fallback that did not would be the one route around the constraint.
        const leaf = certificate({ commonNames: ['www.evil.test'] });
        const ica = constrainedCa([dns('.example.com'), dns('example.com')]);
        const reasons = checkServerName(leaf, host('www.evil.test'), { allowCommonNameFallback: true, path: [leaf, ica] });
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_NOT_PERMITTED']);
        expect(reasons[0]?.path).toBe('certificate.subject');
        expect(reasons[0]?.message).toContain('www.evil.test');

        const inside = certificate({ commonNames: ['www.example.com'] });
        expect(checkServerName(inside, host('www.example.com'), { allowCommonNameFallback: true, path: [inside, ica, certificate()] })).toEqual([]);
    });

    it('should apply an exclusion anywhere above, and never the constraints of the certificate itself', () => {
        const leaf = certificate({ commonNames: ['www.evil.test'] });
        const root = constrainedCa(undefined, [dns('evil.test')]);
        const ica = constrainedCa([dns('evil.test'), dns('example.com')]);
        expect(codes(checkServerName(leaf, host('www.evil.test'), { allowCommonNameFallback: true, path: [leaf, ica, root] })))
            .toEqual(['PKI_REASON_NAME_EXCLUDED']);
        // Accumulated from the anchor down: the intermediate's wider permission
        // does not widen the root's narrower one.
        const narrow = constrainedCa([dns('example.com')]);
        const wide = constrainedCa([dns('evil.test'), dns('example.com')]);
        expect(codes(checkServerName(leaf, host('www.evil.test'), { allowCommonNameFallback: true, path: [leaf, wide, narrow] })))
            .toEqual(['PKI_REASON_NAME_NOT_PERMITTED']);
        // A path given without the leaf is all issuers; a constraint on the
        // leaf itself binds only what it would issue.
        expect(checkServerName(leaf, host('www.evil.test'), { allowCommonNameFallback: true, path: [wide] })).toEqual([]);
        const selfConstrained = { ...leaf, extensions: constrainedCa([dns('example.com')]).extensions } as Certificate;
        expect(checkServerName(selfConstrained, host('www.evil.test'), { allowCommonNameFallback: true, path: [selfConstrained] })).toEqual([]);
    });

    it('should say the certificate has no subjectAltName at all when it has none', () => {
        const reasons = checkServerName(certificate(), host('bank.example'));
        expect(reasons[0]?.message).toContain('no subjectAltName at all');
    });
});

describe('checkServerName — wildcards off', () => {
    it('should refuse a wildcard SAN when the caller turned wildcards off', () => {
        // The right setting for an internal PKI that issues none.
        const cert = certificate({ names: [dns('*.bank.example')] });
        expect(checkServerName(cert, host('www.bank.example'))).toEqual([]);
        expect(codes(checkServerName(cert, host('www.bank.example'), { allowWildcards: false }))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should still match an exact SAN with wildcards off', () => {
        const cert = certificate({ names: [dns('www.bank.example')] });
        expect(checkServerName(cert, host('www.bank.example'), { allowWildcards: false })).toEqual([]);
    });
});

describe('checkServerName — never throws', () => {
    it('should answer rather than throw for any identity', () => {
        expect(() => checkServerName(certificate(), host(''))).not.toThrow();
        expect(() => checkServerName(certificate(), address())).not.toThrow();
    });

    it('should list at most eight names and say how many more there are', () => {
        const many = Array.from({ length: 12 }, (_, i) => dns(`h${String(i)}.example`));
        const reasons = checkServerName(certificate({ names: many }), host('bank.example'));
        const firstEight = many.slice(0, 8).map((n) => JSON.stringify((n as { value: string }).value)).join(', ');
        expect(reasons[0]?.message).toContain(`it names ${firstEight}, and 4 more`);
        const eight = checkServerName(certificate({ names: many.slice(0, 8) }), host('bank.example'));
        expect(eight[0]?.message).toContain(`it names ${firstEight}`);
        expect(eight[0]?.message).not.toContain('more');
        const nine = checkServerName(certificate({ names: many.slice(0, 9) }), host('bank.example'));
        expect(nine[0]?.message).toContain(`it names ${firstEight}, and 1 more`);
    });

    it('should count only the host-bearing forms in the overflow, and list neither address nor host it lacks', () => {
        // Ten hosts beside forty e-mail addresses is "and 2 more", not "and 42
        // more": a count that included forms it never listed would send a
        // reader looking for hosts the certificate does not have.
        const names = [
            ...Array.from({ length: 10 }, (_, i) => dns(`h${String(i)}.example`)),
            ...Array.from({ length: 40 }, (_, i) => email(`a${String(i)}@bank.example`)),
        ];
        const reasons = checkServerName(certificate({ names }), host('bank.example'));
        expect(reasons[0]?.message).toContain('and 2 more');
        expect(reasons[0]?.message).not.toContain('@bank.example');
    });
});
