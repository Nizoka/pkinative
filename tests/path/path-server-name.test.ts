import { describe, expect, it } from 'vitest';
import { checkServerName, dnsMatches, type ServerIdentity } from '../../src/path/path-server-name.js';
import type { Certificate, GeneralName } from '../../src/types/x509-types.js';

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
    return { subject: { rdns, der: new Uint8Array(0) }, extensions } as unknown as Certificate;
}

const host = (value: string): ServerIdentity => ({ kind: 'dns', value });
const address = (...bytes: readonly number[]): ServerIdentity => ({ kind: 'ip', value: Uint8Array.from(bytes) });

const codes = (reasons: readonly { code: string }[]): string[] => reasons.map((r) => r.code);

describe('dnsMatches — RFC 6125 §6.4', () => {
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
        expect(dnsMatches(presented, reference)).toBe(expected);
    });

    it('should refuse every wildcard when wildcards are turned off', () => {
        expect(dnsMatches('*.example.com', 'host.example.com', false)).toBe(false);
        expect(dnsMatches('example.com', 'example.com', false)).toBe(true);
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
        expect(codes(checkServerName(certificate({ names: [ip([192, 0, 2, 1])] }), host('192.0.2.1')))).toEqual(['PKI_REASON_NAME_MISMATCH']);
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
        expect(codes(checkServerName(cert, host('bank.example'), { allowCommonNameFallback: true }))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should quote an IPv6 identity as hex rather than as dotted quad', () => {
        // 2001:db8::1. A report that printed 16 octets as `32.1.13.184.0.…`
        // would be unreadable, and a reader comparing it to their own address
        // would conclude the library had mangled it.
        const wanted = Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        const reasons = checkServerName(certificate({ names: [ip([192, 0, 2, 1], '192.0.2.1')] }), { kind: 'ip', value: wanted });
        expect(reasons[0]?.message).toContain('20010db8000000000000000000000001');
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
        expect(checkServerName(cert, host('bank.example'), { allowCommonNameFallback: true })).toEqual([]);
    });
});

describe('checkServerName — the commonName fallback', () => {
    it('should be off by default, and say so', () => {
        const reasons = checkServerName(certificate({ commonNames: ['bank.example'] }), host('bank.example'));
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('commonName fallback was not asked for');
    });

    it('should match a commonName when explicitly asked', () => {
        expect(checkServerName(certificate({ commonNames: ['bank.example'] }), host('bank.example'), { allowCommonNameFallback: true })).toEqual([]);
    });

    it('should honour a wildcard commonName under the same rules', () => {
        const cert = certificate({ commonNames: ['*.bank.example'] });
        expect(checkServerName(cert, host('www.bank.example'), { allowCommonNameFallback: true })).toEqual([]);
        expect(codes(checkServerName(cert, host('bank.example'), { allowCommonNameFallback: true }))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should never match an address against a commonName', () => {
        // An IP in a CN is text, and comparing an address to text is how a
        // certificate for "127.0.0.1" the string gets accepted for the host.
        const cert = certificate({ commonNames: ['192.0.2.1'] });
        expect(codes(checkServerName(cert, address(192, 0, 2, 1), { allowCommonNameFallback: true }))).toEqual(['PKI_REASON_NAME_MISMATCH']);
    });

    it('should try every commonName of a multi-CN subject', () => {
        const cert = certificate({ commonNames: ['a.example', 'bank.example'] });
        expect(checkServerName(cert, host('bank.example'), { allowCommonNameFallback: true })).toEqual([]);
    });

    it('should report the commonNames it did find', () => {
        const reasons = checkServerName(certificate({ commonNames: ['other.example'] }), host('bank.example'), { allowCommonNameFallback: true });
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
        const reasons = checkServerName(cert, host('bank.example'), { allowCommonNameFallback: true });
        expect(codes(reasons)).toEqual(['PKI_REASON_NAME_MISMATCH']);
        expect(reasons[0]?.message).toContain('(none)');
    });

    it('should report "(none)" rather than nothing for a subject with no commonName', () => {
        const reasons = checkServerName(certificate({ commonNames: [] }), host('bank.example'), { allowCommonNameFallback: true });
        expect(reasons[0]?.message).toContain('(none)');
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
        expect(reasons[0]?.message).toContain('and 4 more');
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
