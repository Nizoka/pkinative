/**
 * Recipe: does this certificate name the host you connected to? (RFC 6125)
 *
 * A validated path says a CA vouched for a certificate. It says nothing about
 * which host the certificate is **for**, and the gap between those two is where
 * a perfectly valid certificate for `attacker.example` gets accepted as one for
 * `bank.example`. `validateCertificatePath` will never close it — RFC 5280 §6
 * has no notion of the name you asked for — so both calls are needed, and a
 * caller doing only one of them has either a certificate from nobody in
 * particular or a certificate for somebody else.
 *
 * Every line below that refuses is a shape some implementation has accepted.
 */
import { checkServerName, dnsMatches, parseCertificate, type Certificate, type CheckServerNameOptions, type ServerIdentity } from 'pkinative';
import { fixture } from './_fixtures.js';

const leaf: Certificate = parseCertificate(fixture('letsencrypt-org-leaf'), { onDiagnostic: (): undefined => undefined });

/** `''` when the certificate is for that identity, the reason code otherwise. */
const check = (identity: ServerIdentity, options?: CheckServerNameOptions): string =>
    checkServerName(leaf, identity, options).map((reason) => reason.code).join(',') || 'match';

const host = (value: string): ServerIdentity => ({ kind: 'dns', value });

export default function run(): Record<string, string> {
    return {
        // The fixture names ten hosts; any one of them matches.
        named: check(host('www.letsencrypt.org')),
        // Case is not part of a host name, and one trailing dot is the same
        // absolute name rather than a different one.
        folded: check(host('WWW.LetsEncrypt.ORG.')),

        // ── The refusals, which are the reason this function exists ──
        // A suffix is not a match. `letsencrypt.org.evil.test` is a domain the
        // attacker owns, and reading the certificate's name as a suffix of the
        // host you asked for is the oldest bypass there is.
        suffix: check(host('letsencrypt.org.evil.test')),
        // …and neither is a prefix: `notletsencrypt.org` is somebody else.
        prefix: check(host('notletsencrypt.org')),
        // An embedded NUL truncates the name in a C parser and not in a JS one,
        // which is the entire mechanism of CVE-2009-2408.
        nulByte: check(host('www.letsencrypt.org\u0000.evil.test')),
        // A DNS name is never an address, whatever it looks like: a certificate
        // naming "192.0.2.1" as a dNSName is not a certificate for that host.
        addressIsNotAName: check({ kind: 'ip', value: Uint8Array.of(192, 0, 2, 1) }),

        // ── Wildcards ──
        // One whole leftmost label, and nothing else. Partial wildcards
        // (`f*.example.com`), a wildcard that is not leftmost, and a wildcard
        // matching two labels are all refused; `*.example.com` does not match
        // `example.com`. `*.com` is refused outright, because the correct test
        // is a public suffix list and pkinative will not carry one stale.
        wildcardOneLabel: String(dnsMatches('*.bank.example', 'www.bank.example')),
        wildcardNotTheParent: String(dnsMatches('*.bank.example', 'bank.example')),
        wildcardNotTwoLabels: String(dnsMatches('*.bank.example', 'a.b.bank.example')),
        wildcardNotPartial: String(dnsMatches('w*.bank.example', 'www.bank.example')),
        wildcardNotRegistry: String(dnsMatches('*.example', 'bank.example')),
        // An internal PKI that issues no wildcards should accept none, which is
        // what `allowWildcards: false` is for. It is the one option here whose
        // default is permissive, because the public web runs on wildcards.
        wildcardsOff: String(dnsMatches('*.bank.example', 'www.bank.example', false)),
        exactStillMatchesWithWildcardsOff: check(host('www.letsencrypt.org'), { allowWildcards: false }),

        // ── The commonName fallback rescues nothing here ──
        // A certificate carrying any dNSName or iPAddress makes its SAN
        // authoritative, so the commonName is never consulted — even when the
        // caller sets `allowCommonNameFallback: true`, and even when the CN
        // would have matched. This fixture's CN is `letsencrypt.org`, which its
        // SAN also lists, so the recipe cannot exhibit a CN-only certificate;
        // tests/path/path-server-name.test.ts does, on a synthetic one.
        //
        // The option is off by default because CA/Browser Forum BR 7.1.4.2.2
        // has forbidden CN-only certificates since 2017 and browsers stopped
        // reading CN years before that. It exists for an internal PKI nobody
        // has reissued, and turning it on is accepting a certificate no modern
        // relying party would.
        fallbackRescuesNothing: checkServerName(leaf, host('api.letsencrypt.org'), { allowCommonNameFallback: true })
            .map((reason) => reason.code).join(',') || 'match',
    };
}
