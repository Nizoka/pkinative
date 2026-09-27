import { describe, expect, it } from 'vitest';
import {
    accumulateNameConstraints,
    checkName,
    directoryMatches,
    dnsMatches,
    emailMatches,
    initialNameConstraints,
    ipMatches,
    nameText,
    subtreeCovers,
    uriHost,
    uriMatches,
    subtreeCoversWildcard,
    wellFormedName,
    wildcardMeetsSubtree,
    type NameConstraintState,
} from '../../src/path/path-name-constraints.js';
import type { DistinguishedName, GeneralName, GeneralSubtree } from '../../src/types/x509-types.js';

/**
 * RFC 5280 §4.2.1.10 matching, and §6.1.4 (g) accumulation.
 *
 * The negative cases are the point of this file. A name-constraint checker
 * that is merely *usually* right is a bypass: every row below asserting
 * `false` is a certificate a permissive implementation would have accepted,
 * and each one has been a real finding somewhere.
 */

const dns = (value: string): GeneralName => ({ kind: 'dNSName', value, der: new Uint8Array(0) });
const email = (value: string): GeneralName => ({ kind: 'rfc822Name', value, der: new Uint8Array(0) });
const uri = (value: string): GeneralName => ({ kind: 'uniformResourceIdentifier', value, der: new Uint8Array(0) });
const ip = (bytes: readonly number[], address = 'x'): GeneralName => ({ kind: 'iPAddress', version: bytes.length > 4 ? 6 : 4, address, mask: undefined, bytes: Uint8Array.from(bytes), der: new Uint8Array(0) });

const attribute = (type: string, value: string): { type: string; value: undefined; valueDer: Uint8Array } =>
    ({ type, value: undefined, valueDer: new TextEncoder().encode(value) });
const name = (...parts: ReadonlyArray<readonly [string, string]>): DistinguishedName =>
    ({ rdns: parts.map(([t, v]) => [attribute(t, v)]), der: new Uint8Array(0) }) as unknown as DistinguishedName;
const directory = (dn: DistinguishedName): GeneralName => ({ kind: 'directoryName', name: dn, der: new Uint8Array(0) });

const subtree = (base: GeneralName): GeneralSubtree => ({ base, minimum: 0, maximum: undefined });

describe('dnsMatches — §4.2.1.10', () => {
    it.each([
        { constraint: 'example.com', name: 'example.com', expected: true },
        { constraint: 'example.com', name: 'host.example.com', expected: true },
        { constraint: 'example.com', name: 'a.b.example.com', expected: true },
        { constraint: '.example.com', name: 'host.example.com', expected: true },
        { constraint: 'EXAMPLE.com', name: 'host.example.COM', expected: true },
        { constraint: '', name: 'anything', expected: true },
        // The bypass every naive implementation has: a suffix test without a
        // label boundary makes `example.com` match `notexample.com`.
        { constraint: 'example.com', name: 'notexample.com', expected: false },
        { constraint: 'example.com', name: 'example.com.evil.test', expected: false },
        // A dotted constraint does NOT match the bare name (§4.2.1.10).
        { constraint: '.example.com', name: 'example.com', expected: false },
        { constraint: 'host.example.com', name: 'example.com', expected: false },
    ])('$constraint vs $name → $expected', ({ constraint, name: n, expected }) => {
        expect(dnsMatches(constraint, n)).toBe(expected);
    });
});

describe('emailMatches — §4.2.1.10', () => {
    it.each([
        { constraint: 'a@example.com', name: 'a@example.com', expected: true },
        { constraint: 'example.com', name: 'anyone@example.com', expected: true },
        { constraint: '.example.com', name: 'a@host.example.com', expected: true },
        { constraint: 'example.com', name: 'example.com', expected: true },
        { constraint: 'A@EXAMPLE.com', name: 'a@example.COM', expected: true },
        { constraint: '', name: 'anyone@anywhere.test', expected: true },
        // A full mailbox constraint matches nothing but itself.
        { constraint: 'a@example.com', name: 'b@example.com', expected: false },
        // A bare host does not match a subdomain; only a dotted one does.
        { constraint: 'example.com', name: 'a@host.example.com', expected: false },
        { constraint: '.example.com', name: 'a@example.com', expected: false },
        { constraint: 'example.com', name: 'a@notexample.com', expected: false },
        // The `@` in the local part must not be mistaken for the separator.
        { constraint: 'example.com', name: 'a@b@example.com', expected: true },
    ])('$constraint vs $name → $expected', ({ constraint, name: n, expected }) => {
        expect(emailMatches(constraint, n)).toBe(expected);
    });
});

describe('uriHost and uriMatches — §4.2.1.10', () => {
    it.each([
        { uri: 'https://host.example.com/path', host: 'host.example.com' },
        { uri: 'https://host.example.com:8443/', host: 'host.example.com' },
        { uri: 'https://user:pass@host.example.com/', host: 'host.example.com' },
        { uri: 'https://host.example.com?q=1', host: 'host.example.com' },
        { uri: 'https://host.example.com#frag', host: 'host.example.com' },
        { uri: 'https://[2001:db8::1]:443/', host: '[2001:db8::1]' },
        // No authority to constrain, so nothing to compare.
        { uri: 'mailto:a@example.com', host: null },
        { uri: 'https://', host: null },
        { uri: 'not a uri', host: null },
        // An unterminated IPv6 literal has no host anyone can agree on, and
        // guessing one is how a constraint gets evaluated against the wrong
        // string.
        { uri: 'https://[2001:db8::1/path', host: null },
    ])('$uri → $host', ({ uri: u, host }) => {
        expect(uriHost(u)).toBe(host);
    });

    it('should treat a constraint without a leading period as ONE host, not a domain', () => {
        // The asymmetry the RFC spells out and that this code got wrong until
        // x509-limbo scored it: "When the constraint does not begin with a
        // period, it specifies a host." So the same string permits subdomains
        // as a dNSName constraint and does not as a URI constraint, and routing
        // URIs through the dNSName rule lets a CA constrained to one host issue
        // for every subdomain of it.
        expect(uriMatches('example.com', 'https://example.com/x')).toBe(true);
        expect(uriMatches('example.com', 'https://host.example.com/x')).toBe(false);
        expect(uriMatches('example.com', 'https://notexample.com/x')).toBe(false);
        // A leading period is how a URI constraint names a domain — and it does
        // not match the domain itself.
        expect(uriMatches('.example.com', 'https://host.example.com/x')).toBe(true);
        expect(uriMatches('.example.com', 'https://deep.host.example.com/x')).toBe(true);
        expect(uriMatches('.example.com', 'https://example.com/x')).toBe(false);
    });

    it('should let an empty constraint match every URI that has a host', () => {
        // An empty base constrains the form without narrowing it, which is how
        // a CA says "URIs, but only URIs" — and it still needs a host, because
        // a constraint that cannot be evaluated is not one that is satisfied.
        expect(uriMatches('', 'https://anything.test/x')).toBe(true);
    });

    it('should refuse a URI whose host it cannot find, rather than accept it', () => {
        // A constraint that cannot be evaluated is not a constraint that is
        // satisfied. The permissive choice here is a bypass.
        expect(uriMatches('example.com', 'mailto:a@example.com')).toBe(false);
        expect(uriMatches('', 'mailto:a@example.com')).toBe(false);
    });

    it('should not let an IPv6 literal be split on its colons', () => {
        expect(uriMatches('db8', 'https://[2001:db8::1]:443/')).toBe(false);
    });
});

describe('ipMatches — §4.2.1.10', () => {
    it('should match an IPv4 address inside its /24', () => {
        expect(ipMatches(Uint8Array.of(192, 0, 2, 0, 255, 255, 255, 0), Uint8Array.of(192, 0, 2, 7))).toBe(true);
        expect(ipMatches(Uint8Array.of(192, 0, 2, 0, 255, 255, 255, 0), Uint8Array.of(192, 0, 3, 7))).toBe(false);
    });

    it('should match everything under a zero mask, and only itself under a full one', () => {
        expect(ipMatches(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0), Uint8Array.of(8, 8, 8, 8))).toBe(true);
        expect(ipMatches(Uint8Array.of(192, 0, 2, 1, 255, 255, 255, 255), Uint8Array.of(192, 0, 2, 1))).toBe(true);
        expect(ipMatches(Uint8Array.of(192, 0, 2, 1, 255, 255, 255, 255), Uint8Array.of(192, 0, 2, 2))).toBe(false);
    });

    it('should refuse a width mismatch rather than treat it as a match', () => {
        // An IPv4 name against an IPv6 constraint is outside it, not inside.
        expect(ipMatches(new Uint8Array(32), Uint8Array.of(192, 0, 2, 1))).toBe(false);
        expect(ipMatches(Uint8Array.of(192, 0, 2, 0, 255, 255, 255, 0), new Uint8Array(16))).toBe(false);
    });

    it('should handle an IPv6 prefix', () => {
        const constraint = new Uint8Array(32);
        constraint.set([0x20, 0x01, 0x0d, 0xb8], 0);
        constraint.set([0xff, 0xff, 0xff, 0xff], 16);
        const inside = new Uint8Array(16);
        inside.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 0);
        const outside = new Uint8Array(16);
        outside.set([0x20, 0x01, 0x0d, 0xb9], 0);
        expect(ipMatches(constraint, inside)).toBe(true);
        expect(ipMatches(constraint, outside)).toBe(false);
    });
});

describe('directoryMatches — §4.2.1.10', () => {
    const base = name(['2.5.4.6', 'US'], ['2.5.4.10', 'Example']);

    it('should match when the constraint is a prefix of the RDN sequence', () => {
        expect(directoryMatches(base, name(['2.5.4.6', 'US'], ['2.5.4.10', 'Example'], ['2.5.4.3', 'host']))).toBe(true);
        expect(directoryMatches(base, base)).toBe(true);
    });

    it('should refuse a name shorter than the constraint', () => {
        expect(directoryMatches(base, name(['2.5.4.6', 'US']))).toBe(false);
    });

    it('should refuse a name that differs in any RDN of the prefix', () => {
        expect(directoryMatches(base, name(['2.5.4.6', 'FR'], ['2.5.4.10', 'Example']))).toBe(false);
        expect(directoryMatches(base, name(['2.5.4.6', 'US'], ['2.5.4.11', 'Example']))).toBe(false);
    });

    it('should compare on encoded bytes, so a suffix is not a prefix', () => {
        // Two names that render alike and encode differently are two names.
        expect(directoryMatches(name(['2.5.4.3', 'a']), name(['2.5.4.3', 'ab']))).toBe(false);
    });

    it('should require the same number of attributes in a multi-valued RDN', () => {
        const multi = { rdns: [[attribute('2.5.4.6', 'US'), attribute('2.5.4.3', 'x')]], der: new Uint8Array(0) } as unknown as DistinguishedName;
        expect(directoryMatches(multi, name(['2.5.4.6', 'US']))).toBe(false);
        expect(directoryMatches(name(['2.5.4.6', 'US']), multi)).toBe(false);
    });
});

describe('subtreeCovers', () => {
    it('should never match across forms', () => {
        expect(subtreeCovers(subtree(dns('example.com')), email('a@example.com'))).toBe(false);
        expect(subtreeCovers(subtree(email('example.com')), dns('example.com'))).toBe(false);
    });

    it('should refuse a subtree that asserts minimum or maximum', () => {
        // RFC 5280 §4.2.1.10 fixes minimum to 0 and forbids maximum. A
        // subtree asserting otherwise is not one this code can honour, and
        // answering "covered" would be the permissive mistake.
        expect(subtreeCovers({ base: dns('example.com'), minimum: 1, maximum: undefined }, dns('example.com'))).toBe(false);
        expect(subtreeCovers({ base: dns('example.com'), minimum: 0, maximum: 3 }, dns('example.com'))).toBe(false);
    });

    it('should carry a form it has no rule for as not covered', () => {
        const rid: GeneralName = { kind: 'registeredID', oid: '1.2.3', der: new Uint8Array(0) };
        expect(subtreeCovers({ base: rid, minimum: 0, maximum: undefined }, rid)).toBe(false);
    });

    it('should cover every form it does have a rule for', () => {
        expect(subtreeCovers(subtree(dns('example.com')), dns('host.example.com'))).toBe(true);
        expect(subtreeCovers(subtree(email('example.com')), email('a@example.com'))).toBe(true);
        // `.example.com`, not `example.com`: a URI constraint without a leading
        // period specifies one host (§4.2.1.10), unlike the dNSName rule above.
        expect(subtreeCovers(subtree(uri('.example.com')), uri('https://host.example.com/'))).toBe(true);
        expect(subtreeCovers(subtree(uri('example.com')), uri('https://example.com/'))).toBe(true);
        expect(subtreeCovers(subtree(ip([192, 0, 2, 0, 255, 255, 255, 0])), ip([192, 0, 2, 7]))).toBe(true);
        expect(subtreeCovers(subtree(directory(name(['2.5.4.6', 'US']))), directory(name(['2.5.4.6', 'US'], ['2.5.4.3', 'h'])))).toBe(true);
    });
});

describe('accumulateNameConstraints — §6.1.4 (g)', () => {
    it('should start with no opinion on any form', () => {
        const state = initialNameConstraints();
        expect(state.permitted.dNSName).toBeNull();
        expect(checkName(state, dns('anything.test'))).toBeNull();
    });

    it('should adopt the first CA’s permitted subtrees for a form', () => {
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], undefined);
        expect(checkName(state, dns('host.example.com'))).toBeNull();
        expect(checkName(state, dns('evil.test'))?.why).toBe('not-permitted');
    });

    it('should leave other forms untouched when one form is constrained', () => {
        // The reason the state is per form: constraining DNS must not silently
        // forbid every email address, nor permit one.
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], undefined);
        expect(state.permitted.rfc822Name).toBeNull();
        expect(checkName(state, email('a@anywhere.test'))).toBeNull();
    });

    it('should narrow on intersection, never widen', () => {
        // A sub-CA cannot grant itself names its issuer withheld — the whole
        // security property of §6.1.4 (g)(1).
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], undefined);
        accumulateNameConstraints(state, [subtree(dns('sub.example.com')), subtree(dns('other.test'))], undefined);
        expect(checkName(state, dns('a.sub.example.com'))).toBeNull();
        expect(checkName(state, dns('a.other.test'))?.why).toBe('not-permitted');
        expect(checkName(state, dns('a.example.com'))?.why).toBe('not-permitted');
    });

    it('should make a form unusable when the intersection comes out empty', () => {
        // `[]` and `null` are different answers: empty means nothing of this
        // form is acceptable, absent means no opinion. Collapsing them makes a
        // validator either refuse everything or permit everything.
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], undefined);
        accumulateNameConstraints(state, [subtree(dns('unrelated.test'))], undefined);
        expect(state.permitted.dNSName).toEqual([]);
        expect(checkName(state, dns('example.com'))?.why).toBe('not-permitted');
        expect(checkName(state, dns('unrelated.test'))?.why).toBe('not-permitted');
    });

    it('should union exclusions rather than intersect them', () => {
        const state = initialNameConstraints();
        accumulateNameConstraints(state, undefined, [subtree(dns('bad.test'))]);
        accumulateNameConstraints(state, undefined, [subtree(dns('worse.test'))]);
        expect(checkName(state, dns('a.bad.test'))?.why).toBe('excluded');
        expect(checkName(state, dns('a.worse.test'))?.why).toBe('excluded');
    });

    it('should let an exclusion win over a permission', () => {
        // §6.1.3 (c). Checking permission first would make the order of two
        // CAs' constraints decide the answer.
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], [subtree(dns('secret.example.com'))]);
        expect(checkName(state, dns('host.example.com'))).toBeNull();
        expect(checkName(state, dns('a.secret.example.com'))?.why).toBe('excluded');
    });

    it('should refuse a name of a constrained form it cannot process, rather than ignore it', () => {
        // §4.2.1.10 leaves no third option: process every constrained form or
        // reject the certificate. Skipping the constraint — which this code did
        // until x509-limbo scored it — answers "unconstrained" to a CA that
        // said "forbidden". The five forms with rules stay untouched, which is
        // the other half: one unprocessable form must not refuse the rest.
        const state = initialNameConstraints();
        const rid: GeneralName = { kind: 'registeredID', oid: '1.2.3', der: new Uint8Array(0) };
        accumulateNameConstraints(state, [{ base: rid, minimum: 0, maximum: undefined }], [{ base: rid, minimum: 0, maximum: undefined }]);
        for (const form of ['dNSName', 'rfc822Name', 'uniformResourceIdentifier', 'iPAddress', 'directoryName'] as const) {
            expect(state.permitted[form], form).toBeNull();
            expect(state.excluded[form], form).toEqual([]);
        }
        expect(state.unprocessed.has('registeredID')).toBe(true);
        expect(checkName(state, rid)?.why).toBe('not-permitted');
        expect(checkName(state, rid)?.text).toContain('does not process');
        // A name of a form nobody constrained is still unconstrained.
        expect(checkName(state, { kind: 'otherName', typeId: '1.2.4', value: new Uint8Array(0), der: new Uint8Array(0) } as unknown as GeneralName)).toBeNull();
        expect(checkName(state, dns('anything.test'))).toBeNull();
    });

    it('should report the form and the value, so the reason can be acted on', () => {
        const state: NameConstraintState = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], undefined);
        const verdict = checkName(state, dns('evil.test'));
        expect(verdict?.form).toBe('dNSName');
        expect(verdict?.text).toBe('evil.test');
    });
});

describe('every form can be excluded, not only permitted', () => {
    // §6.1.3 (c) applies to every form, and an exclusion path that is only
    // ever exercised for dNSName is four forms of untested code.
    it.each([
        { form: 'dNSName', subtree: subtree(dns('bad.test')), name: dns('a.bad.test') },
        { form: 'rfc822Name', subtree: subtree(email('bad.test')), name: email('a@bad.test') },
        { form: 'uniformResourceIdentifier', subtree: subtree(uri('.bad.test')), name: uri('https://a.bad.test/') },
        { form: 'iPAddress', subtree: subtree(ip([10, 0, 0, 0, 255, 0, 0, 0])), name: ip([10, 1, 2, 3]) },
        { form: 'directoryName', subtree: subtree(directory(name(['2.5.4.6', 'XX']))), name: directory(name(['2.5.4.6', 'XX'], ['2.5.4.3', 'h'])) },
    ])('$form', ({ subtree: s, name: n }) => {
        const state = initialNameConstraints();
        accumulateNameConstraints(state, undefined, [s]);
        expect(checkName(state, n)?.why).toBe('excluded');
    });
});

describe('a malformed name is not inside any namespace', () => {
    // §6.1.3 (b) requires every name to be LOCATED WITHIN the permitted
    // subtrees. `.example.com` ends with `example.com`, so plain suffix
    // matching calls it permitted — and a CA constrained to one domain has
    // issued for a name no two parsers read the same way (CWE-436).
    it.each([
        { what: 'a DNS name with a leading period', subtree: subtree(dns('example.com')), name: dns('.example.com') },
        { what: 'a DNS name with an empty inner label', subtree: subtree(dns('example.com')), name: dns('a..example.com') },
        { what: 'a mailbox with two @', subtree: subtree(email('example.com')), name: email('invalid@address@example.com') },
        { what: 'a mailbox with no local part', subtree: subtree(email('example.com')), name: email('@example.com') },
        { what: 'a URI with no authority', subtree: subtree(uri('example.com')), name: uri('mailto:a@example.com') },
        { what: 'an address of no known width', subtree: subtree(ip([192, 0, 2, 0, 255, 255, 255, 0])), name: ip([192, 0, 2]) },
    ])('$what', ({ subtree: s, name: n }) => {
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [s], undefined);
        expect(checkName(state, n)?.why).toBe('not-permitted');
    });

    it('should not police a name of a form nobody constrained', () => {
        // §6 judges relations. The syntax of a name no CA constrained is a
        // profile concern, which the parser already diagnosed on the object.
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(email('example.com'))], undefined);
        expect(checkName(state, dns('.example.com'))).toBeNull();
    });

    it('should refuse a trailing dot rather than let it match nothing', () => {
        // A trailing dot is a query-time spelling; §4.2.1.10's rules do not
        // strip it, so `host.example.com.` matches the constraint
        // `example.com` under no rule. Silently matching nothing reads as
        // "unconstrained", so the name is refused where a constraint applies.
        const state = initialNameConstraints();
        accumulateNameConstraints(state, [subtree(dns('example.com'))], undefined);
        expect(checkName(state, dns('host.example.com.'))?.why).toBe('not-permitted');
    });
});

describe('a wildcard name denotes a set (CVE-2025-61727)', () => {
    const constrained = (permitted: readonly GeneralName[] | undefined, excluded: readonly GeneralName[] | undefined): NameConstraintState => {
        const state = initialNameConstraints();
        accumulateNameConstraints(state, permitted?.map((b) => subtree(b)), excluded?.map((b) => subtree(b)));
        return state;
    };

    it('should refuse a wildcard when one name it denotes is excluded', () => {
        // `*.example.com` denotes `bar.example.com`, which the CA forbade. The
        // two strings do not match; the sets intersect, and that is the
        // question. This is the CVE.
        expect(checkName(constrained(undefined, [dns('bar.example.com')]), dns('*.example.com'))?.why).toBe('excluded');
    });

    it('should refuse a wildcard whose whole parent domain is excluded', () => {
        expect(checkName(constrained(undefined, [dns('example.com')]), dns('*.example.com'))?.why).toBe('excluded');
        expect(checkName(constrained(undefined, [dns('.example.com')]), dns('*.example.com'))?.why).toBe('excluded');
    });

    it('should allow a wildcard whose set cannot reach the exclusion', () => {
        // One label is consumed, so a base two labels deeper is unreachable…
        expect(checkName(constrained(undefined, [dns('a.b.example.com')]), dns('*.example.com'))).toBeNull();
        // …and `.bar.example.com` names only what is BELOW bar, never a
        // single-label host under example.com.
        expect(checkName(constrained(undefined, [dns('.bar.example.com')]), dns('*.example.com'))).toBeNull();
        expect(checkName(constrained(undefined, [dns('other.test')]), dns('*.example.com'))).toBeNull();
    });

    it('should require a permission to cover the whole set, not one member', () => {
        // Covering the parent covers every member.
        expect(checkName(constrained([dns('example.com')], undefined), dns('*.example.com'))).toBeNull();
        expect(checkName(constrained([dns('.example.com')], undefined), dns('*.example.com'))).toBeNull();
        // Permitting one member permits one member: the wildcard denotes
        // others, and accepting it would grant every one of them.
        expect(checkName(constrained([dns('bar.example.com')], undefined), dns('*.example.com'))?.why).toBe('not-permitted');
        expect(checkName(constrained([dns('other.test')], undefined), dns('*.example.com'))?.why).toBe('not-permitted');
    });

    it('should leave a wildcard alone when no CA constrained dNSName', () => {
        expect(checkName(initialNameConstraints(), dns('*.example.com'))).toBeNull();
    });

    it('should treat a partial wildcard as a set too, not as a literal string', () => {
        // No relying party should honour `w*.example.com`, but one lenient
        // enough to would expand it onto `wbar.example.com`. Treating the whole
        // starred label as unknown over-approximates the set, and an
        // over-approximation can only refuse, never permit.
        expect(checkName(constrained(undefined, [dns('wbar.example.com')]), dns('w*.example.com'))?.why).toBe('excluded');
        expect(checkName(constrained([dns('example.com')], undefined), dns('w*.example.com'))).toBeNull();
    });

    it('should take the domain below the LAST starred label as the parent', () => {
        // `a.*.example.com` stands in for two labels, so a base two labels
        // below `example.com` is a member and one label below is not.
        expect(checkName(constrained(undefined, [dns('a.b.example.com')]), dns('a.*.example.com'))?.why).toBe('excluded');
        expect(checkName(constrained(undefined, [dns('b.example.com')]), dns('a.*.example.com'))).toBeNull();
        expect(checkName(constrained([dns('example.com')], undefined), dns('a.*.example.com'))).toBeNull();
    });

    it('should refuse a starred name whose parent is not a domain', () => {
        // `*.` and `*` leave nothing to compare, so there is no set and the
        // name is judged literally — matching no constraint.
        const state = constrained([dns('example.com')], undefined);
        expect(checkName(state, dns('*.'))?.why).toBe('not-permitted');
        expect(checkName(state, dns('*'))?.why).toBe('not-permitted');
    });

    it('should fold case on both sides of the set comparison', () => {
        expect(checkName(constrained(undefined, [dns('BAR.Example.COM')]), dns('*.EXAMPLE.com'))?.why).toBe('excluded');
    });

    it('should ignore an exclusion carrying a minimum or a maximum', () => {
        // §4.2.1.10 fixes minimum to 0 and forbids maximum, so a subtree
        // asserting otherwise is not one this code can honour — and saying
        // "excluded" on a constraint it cannot read would be guessing.
        const state = initialNameConstraints();
        accumulateNameConstraints(state, undefined, [{ base: dns('bar.example.com'), minimum: 1, maximum: undefined }]);
        expect(checkName(state, dns('*.example.com'))).toBeNull();
    });
});

describe('wildcardMeetsSubtree and subtreeCoversWildcard', () => {
    it.each([
        // Covers the whole set, so it also meets it.
        { base: 'example.com', parent: 'example.com', meets: true, covers: true },
        { base: '.example.com', parent: 'example.com', meets: true, covers: true },
        { base: 'example.com', parent: 'sub.example.com', meets: true, covers: true },
        { base: '', parent: 'example.com', meets: true, covers: true },
        // Meets it without covering it: the base IS one member.
        { base: 'bar.example.com', parent: 'example.com', meets: true, covers: false },
        // Neither. A base two labels down is out of a one-label set's reach…
        { base: 'a.b.example.com', parent: 'example.com', meets: false, covers: false },
        // …and a leading period holds only what lies below it, so it holds no
        // single-label member of its own.
        { base: '.bar.example.com', parent: 'example.com', meets: false, covers: false },
        { base: 'notexample.com', parent: 'example.com', meets: false, covers: false },
    ])('$base vs *.$parent → meets $meets, covers $covers', ({ base, parent, meets, covers }) => {
        expect(wildcardMeetsSubtree(base, parent)).toBe(meets);
        expect(subtreeCoversWildcard(base, parent)).toBe(covers);
    });

    it('should count the labels the stars stand in for', () => {
        expect(wildcardMeetsSubtree('a.b.example.com', 'example.com', 2)).toBe(true);
        expect(wildcardMeetsSubtree('b.example.com', 'example.com', 2)).toBe(false);
    });
});

describe('wellFormedName', () => {
    it('should judge only what the matching rules rest on', () => {
        expect(wellFormedName(dns('a.example.com'))).toBe(true);
        expect(wellFormedName(dns(''))).toBe(false);
        // A trailing dot matches no constraint under §4.2.1.10's rules, so
        // calling it well formed would leave it silently unconstrained.
        expect(wellFormedName(dns('a.example.com.'))).toBe(false);
        expect(wellFormedName(email('a@b.test'))).toBe(true);
        expect(wellFormedName(uri('https://a.test/x'))).toBe(true);
        // A bracketed IPv6 authority is an address, not a host name, and the
        // host-label rules do not apply to it.
        expect(wellFormedName(uri('https://[2001:db8::1]:443/'))).toBe(true);
        expect(wellFormedName(ip([1, 2, 3, 4]))).toBe(true);
        expect(wellFormedName(ip(Array.from({ length: 16 }, () => 0)))).toBe(true);
        // A directoryName has no malformed spelling: the decoder either
        // produced a name or threw.
        expect(wellFormedName(directory(name(['2.5.4.3', 'x'])))).toBe(true);
        expect(wellFormedName({ kind: 'registeredID', oid: '1.2.3', der: new Uint8Array(0) })).toBe(true);
    });
});

describe('nameText', () => {
    it('should quote each form in one spelling', () => {
        expect(nameText(dns('a.test'))).toBe('a.test');
        expect(nameText(email('a@test'))).toBe('a@test');
        expect(nameText(uri('https://a.test/'))).toBe('https://a.test/');
        expect(nameText(ip([1, 2, 3, 4], '1.2.3.4'))).toBe('1.2.3.4');
        expect(nameText(directory(name(['2.5.4.3', 'x'])))).toBe('directoryName with 1 RDN(s)');
        expect(nameText({ kind: 'registeredID', oid: '1.2.3', der: new Uint8Array(0) })).toBe('registeredID');
    });
});
