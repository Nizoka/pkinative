import { describe, expect, it } from 'vitest';
import { isFqdn, isFqdnOrIpHost, isHttpOrLdapUri, isUri, ldapUrlFields, uriAuthorityHost, uriScheme } from '../../src/core/uri.js';

describe('isUri — RFC 3986 §3', () => {
    it.each([
        'http://example.com',
        'http://example.com/',
        'https://user:pass@host.example.com:8443/a/b;c?q=1&r=/?#frag/?',
        'HTTP://Example.COM/',
        'urn:ietf:rfc:5280',
        'urn:',
        'mailto:a@example.com',
        'file:///etc/hosts',
        'ldap://ldap.example.com/cn=CA,dc=example?cACertificate;binary',
        'a+b-c.d:x',
        'http://%41b.example/%7e',
        'http://[2001:db8::1]/',
        'http://[2001:db8::1]:80/',
        'http://[::]/',
        'http://[::1]',
        'http://[1:2:3:4:5:6:7:8]/',
        'http://[1:2:3:4:5:6:7::]/',
        'http://[::2:3:4:5:6:7:8]/',
        'http://[::ffff:192.0.2.1]/',
        'http://[1:2:3:4:5:6:192.0.2.1]/',
        'http://[v1.fe80:x]/',
        'http://[V1F.a]/',
        'http://192.0.2.1:/',
        'http://host:65536/',
        'http://:80/',
        'http:/absolute/path',
        'http:rootless/path',
        'x:?only=query',
        'x:#only-fragment',
        "x://a!$&'()*+,;=b/",
    ])('should accept %s', (text) => {
        expect(isUri(text)).toBe(true);
    });

    it.each([
        // Relative references: no scheme (§4.2).
        '//example.com/path',
        '/relative/path',
        'relative',
        '',
        // A scheme starts with a letter and holds no other punctuation.
        '1http://example.com',
        '_x:y',
        'ht~tp://example.com',
        // Characters the grammar does not allow where they are.
        'http://example.com/a b',
        'http://example.com/a\\b',
        'http://example.com/a"b',
        'http://example.com/?q=a b',
        'http://example.com/#a b',
        'http://example.com/#a#b',
        'http://example.com/[x]',
        'http://example.com/?[x]',
        'http://example.com/#[x]',
        'http://exa mple.com/',
        'http://exa[mple.com/',
        'http://us er@example.com/',
        'http://a@b@example.com/',
        'http://example.com:8x/',
        'http://example.com:-1/',
        // Percent-encoding.
        'http://example.com/%',
        'http://example.com/%4',
        'http://example.com/%zz',
        'http://example.com/?%g0',
        'http://%zz.example/',
        'http://us%zzer@example.com/',
        // IP literals.
        'http://[2001:db8::1/',
        'http://[2001:db8::1]x/',
        'http://[2001:db8::1]x',
        'http://[]/',
        'http://[/',
        'http://[1:2:3:4:5:6:7:8:9]/',
        'http://[1:2:3:4:5:6:7]/',
        'http://[1::2::3]/',
        'http://[12345::]/',
        'http://[:1:2:3:4:5:6:7]/',
        'http://[1:2:3:4:5:6:7:]/',
        'http://[g::]/',
        'http://[1:2:3:4:5:6:7:8::]/',
        'http://[::1.2.3]/',
        'http://[::256.1.1.1]/',
        'http://[1.2.3.4]/',
        'http://[1:2:3:4:5:6:7:1.2.3.4]/',
        'http://[fe80::1%25eth0]/',
        'http://[v.x]/',
        'http://[v1.]/',
        'http://[v1x]/',
        'http://[w1.x]/',
        'http://[v1.x/y]/',
    ])('should refuse %s', (text) => {
        expect(isUri(text)).toBe(false);
    });
});

describe('uriScheme', () => {
    it.each([
        { text: 'http://example.com', expected: { scheme: 'http', specific: '//example.com' } },
        { text: 'URN:', expected: { scheme: 'URN', specific: '' } },
        { text: 'a1+.-:x', expected: { scheme: 'a1+.-', specific: 'x' } },
        { text: '//example.com', expected: null },
        { text: 'no colon', expected: null },
        { text: ':x', expected: null },
        { text: '1a:x', expected: null },
        { text: ' http:x', expected: null },
    ])('$text → $expected', ({ text, expected }) => {
        expect(uriScheme(text)).toEqual(expected);
    });
});

describe('isFqdn — RFC 1034 §3.5 as RFC 1123 §2.1 relaxes it', () => {
    it.each([
        ['example.com', true],
        ['EXAMPLE.com', true],
        ['localhost', true],
        ['1.example', true],
        ['123', true],
        ['a-b.example', true],
        ['a--b.example', true],
        [`${'a'.repeat(63)}.example`, true],
        [`${'a'.repeat(64)}.example`, false],
        [Array.from({ length: 4 }, () => 'a'.repeat(61)).join('.') + '.abcde', true],
        [Array.from({ length: 4 }, () => 'a'.repeat(61)).join('.') + '.abcdef', false],
        ['', false],
        ['.example.com', false],
        ['example.com.', false],
        ['a..example', false],
        ['-a.example', false],
        ['a-.example', false],
        ['under_score.example', false],
        ['*.example.com', false],
        ['exa mple.com', false],
        ['b\u00fccher.example', false],
    ])('%s → %s', (host, expected) => {
        expect(isFqdn(host)).toBe(expected);
    });
});

describe('uriAuthorityHost and isFqdnOrIpHost — RFC 5280 §4.2.1.6', () => {
    it.each([
        { uri: 'https://host.example.com/path', host: 'host.example.com' },
        { uri: 'https://user:pw@host.example.com:8443/x?y#z', host: 'host.example.com' },
        { uri: 'https://host.example.com?q', host: 'host.example.com' },
        { uri: 'https://host.example.com#f', host: 'host.example.com' },
        { uri: 'https://[2001:db8::1]:443/', host: '[2001:db8::1]' },
        { uri: 'https://[2001:db8::1]', host: '[2001:db8::1]' },
        { uri: 'https://[2001:db8::1/', host: '[2001:db8::1' },
        { uri: 'https://[2001:db8::1]x/', host: '[2001:db8::1]x' },
        { uri: 'file:///etc/hosts', host: '' },
        { uri: 'https://a@b@host/', host: 'b@host' },
        { uri: 'https://exa mple.com/a b', host: 'exa mple.com' },
        { uri: 'mailto:a@example.com', host: null },
        { uri: 'urn:x', host: null },
        { uri: 'http:/x', host: null },
        { uri: '//host.example.com/', host: null },
    ])('$uri → $host', ({ uri, host }) => {
        expect(uriAuthorityHost(uri)).toBe(host);
    });

    it.each([
        ['host.example.com', true],
        ['192.0.2.1', true],
        ['255.255.255.255', true],
        ['0.0.0.0', true],
        ['[2001:db8::1]', true],
        ['[::ffff:192.0.2.1]', true],
        ['', false],
        ['under_score.example', false],
        ['%41.example', false],
        ['[2001:db8::1', false],
        ['2001:db8::1]', false],
        ['[2001:db8::1]x', false],
        ['[v1.fe80]', false],
        ['[fe80::1%25eth0]', false],
        ['b@host', false],
    ])('%s → %s', (host, expected) => {
        expect(isFqdnOrIpHost(host)).toBe(expected);
    });
});

describe('ldapUrlFields — RFC 4516 §2', () => {
    it.each([
        { text: 'ldap://ldap.example.com/cn=CA,dc=example?certificateRevocationList;binary', expected: { dn: 'cn=CA,dc=example', attributes: 'certificateRevocationList;binary' } },
        { text: 'LDAP://ldap.example.com/cn=CA?a,b?base', expected: { dn: 'cn=CA', attributes: 'a,b' } },
        { text: 'ldap:///cn=CA?a', expected: { dn: 'cn=CA', attributes: 'a' } },
        { text: 'ldap://ldap.example.com/cn=CA', expected: { dn: 'cn=CA', attributes: undefined } },
        { text: 'ldap://ldap.example.com/?a', expected: { dn: '', attributes: 'a' } },
        { text: 'ldap://ldap.example.com/cn=CA?', expected: { dn: 'cn=CA', attributes: '' } },
        { text: 'ldap://ldap.example.com', expected: { dn: undefined, attributes: undefined } },
        { text: 'ldap://ldap.example.com?cn=CA', expected: { dn: undefined, attributes: undefined } },
        { text: 'ldap:cn=CA?a', expected: null },
        { text: 'ldap:/cn=CA?a', expected: null },
        { text: 'ldaps://ldap.example.com/cn=CA?a', expected: null },
        { text: 'http://ldap.example.com/cn=CA?a', expected: null },
        { text: 'not a uri', expected: null },
    ])('$text', ({ text, expected }) => {
        expect(ldapUrlFields(text)).toEqual(expected);
    });
});

describe('isHttpOrLdapUri', () => {
    it.each([
        ['http://crl.example.com/a.crl', true],
        ['HTTP://crl.example.com/a.crl', true],
        ['ldap://ldap.example.com/cn=CA?x', true],
        ['LdAp:x', true],
        ['https://crl.example.com/a.crl', false],
        ['ldaps://ldap.example.com/', false],
        ['ftp://ftp.example.com/a.crl', false],
        ['httpx://example.com/', false],
        ['//crl.example.com/a.crl', false],
        ['', false],
    ])('%s → %s', (text, expected) => {
        expect(isHttpOrLdapUri(text)).toBe(expected);
    });
});
