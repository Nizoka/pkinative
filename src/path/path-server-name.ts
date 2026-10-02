/**
 * pkinative — RFC 6125 server identity matching
 * =============================================
 * Does this certificate name the host you connected to?
 *
 * A verified chain says a CA vouched for a certificate. It does not say the
 * certificate is *for* the host in your URL, and the gap between those two is
 * where a valid certificate for `attacker.example` gets accepted as one for
 * `bank.example`. This module closes it, and it is deliberately separate from
 * §6: RFC 5280 path validation has no notion of the name you asked for.
 *
 * ## The rules, and why each one is written the strict way
 *
 * **subjectAltName wins absolutely.** If the certificate carries any `dNSName`
 * or `iPAddress`, the `commonName` is never consulted — RFC 6125 §6.4.4, and
 * every modern browser. CA/Browser Forum BR 7.1.4.2.2 has forbidden CN-only
 * certificates since 2017, so the fallback is **off by default** here and has
 * to be asked for; a library that read CN when a SAN was present would be
 * matching a field no issuer has controlled for a decade. When it is asked
 * for, the `commonName` it reads is a host name and is held to the `dNSName`
 * name constraints of the path that issued it, which is why it also needs the
 * validated path: §6 constrains the subjectAltName and the subject DN, never
 * a CN read as a host, so without this the fallback is a route around them.
 *
 * **A wildcard is one whole leftmost label, and nothing else.** Not
 * `f*.example.com` (browsers refuse partial wildcards, whatever RFC 6125 §6.4.3
 * once allowed), not `a.*.example.com`, not `*` alone, and `*.example.com` does
 * **not** match `example.com`. Each of those has been someone's bypass.
 *
 * **A wildcard needs at least three labels.** `*.com` is refused. The correct
 * test is a public suffix list, and pkinative will not embed one: it is data
 * that changes weekly, and a parsing library carrying a stale copy of it is
 * worse than a library that says it does not know. Requiring three labels
 * stops the obvious case and leaves registry-level policy to the caller, which
 * is where the list actually lives.
 *
 * **An address is bytes, never text.** `iPAddress` matching compares octets,
 * for the same reason `encodeSubjectAltName` takes bytes: `::ffff:127.0.0.1`,
 * `127.0.0.1` and `2130706433` are spellings a text parser has to choose
 * between, and a certificate accepted for the wrong address because a parser
 * chose differently is not a bug anyone finds quickly. An IP reference never
 * matches a `dNSName`, and a DNS reference never matches an `iPAddress`.
 *
 * **A `dns` reference that is an address is an address.** `192.0.2.1` or
 * `[2001:db8::1]` passed as a DNS name is what a caller holding a URL host
 * has, and RFC 2818 §3.1 is explicit: *"the iPAddress subjectAltName must be
 * present in the certificate and must exactly match the IP in the URI"*. So
 * it is read as one — only the canonical spellings (RFC 3986 §3.2.2:
 * dotted-quad without leading zeros, RFC 4291 §2.2 for IPv6) — and compared
 * with `iPAddress` entries only, never with a `dNSName` that happens to
 * spell the same digits. Any other text ending in a numeric label
 * (`2130706433`, `0x7f.1`, `010.0.0.1`) is no host name a CA can vouch
 * for and matches nothing. A reference carrying `*` matches nothing either:
 * a wildcard is something a certificate presents, never something asked for.
 *
 * @module path/path-server-name
 */

import { bytesEqual } from '../core/bytes.js';
import { nameExcludedReason, nameMismatchReason, nameNotPermittedReason } from '../core/pki-reasons.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate, GeneralName } from '../types/x509-types.js';
import { getExtension } from '../x509/x509-extensions.js';
import { accumulateNameConstraints, checkName, initialNameConstraints, type NameVerdict } from './path-name-constraints.js';

/** The host or address a caller connected to. */
export type ServerIdentity =
    /** A DNS name, as it appeared in the URL. One trailing dot is ignored. */
    | { readonly kind: 'dns'; readonly value: string }
    /**
     * An address in **network byte order** — 4 octets for IPv4, 16 for IPv6.
     * Bytes rather than text, because one address has several spellings and a
     * certificate accepted for the wrong one is not a bug anyone finds quickly.
     */
    | { readonly kind: 'ip'; readonly value: Uint8Array };

/** Options of {@link checkServerName}. */
export interface CheckServerNameOptions {
    /**
     * Fall back to `commonName` when the certificate carries no `dNSName` and
     * no `iPAddress`. **Off by default.** CA/Browser Forum BR 7.1.4.2.2 has
     * forbidden CN-only certificates since 2017 and browsers stopped reading CN
     * years before that; turning this on is accepting a certificate no modern
     * relying party would.
     *
     * The fallback also needs {@link CheckServerNameOptions.path}: a
     * `commonName` read as a host name is held to the `dNSName` name
     * constraints of the CAs that issued it, as a `dNSName` in the
     * subjectAltName is by path validation — otherwise a CA constrained to
     * `.example.com` could vouch for `www.evil.test` by leaving the SAN out.
     * Without `path` the fallback refuses.
     */
    readonly allowCommonNameFallback?: boolean | undefined;
    /**
     * The validated certification path, leaf first, as `validateCertificatePath`
     * and `verifyCertificateChain` report it in `path`. Read only by the
     * `commonName` fallback, which applies the `dNSName` subtrees of every
     * `nameConstraints` on it — every certificate but this one, accumulated
     * from the anchor down as RFC 5280 §6.1.4 (g) does — to the `commonName`
     * it matched. OpenSSL applies them to such a name during verification.
     */
    readonly path?: readonly Certificate[] | undefined;
    /**
     * Accept a wildcard certificate at all. On by default, because the public
     * web runs on them. Off is the right setting for an internal PKI that
     * issues none.
     */
    readonly allowWildcards?: boolean | undefined;
}

/** Options of {@link matchDnsName}. */
export interface MatchDnsNameOptions {
    /**
     * Let a wildcard match at all. On by default, as in
     * {@link CheckServerNameOptions}; `false` refuses every presented name
     * that carries a `*`.
     */
    readonly allowWildcards?: boolean | undefined;
}

/** `2.5.4.3`, commonName. */
const OID_COMMON_NAME = '2.5.4.3';

/** One dotted-quad octet without a leading zero — RFC 3986 §3.2.2 `dec-octet`. */
const DEC_OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
/** RFC 3986 §3.2.2 `IPv4address`: the one spelling of an IPv4 address read here. */
const IPV4_ADDRESS = new RegExp(`^${DEC_OCTET}(?:\\.${DEC_OCTET}){3}$`);
/** A last label that makes a name numeric rather than a host (WHATWG URL "ends in a number"). */
const NUMERIC_LABEL = /^(?:0x[0-9a-f]*|[0-9]+)$/i;
/** One IPv6 group, RFC 4291 §2.2. */
const IPV6_GROUP = /^[0-9a-f]{1,4}$/i;
/** The longest IPv6 text form, `INET6_ADDRSTRLEN` less its NUL: the bound on the group loop below. */
const MAX_IPV6_TEXT = 45;

/**
 * Check that a certificate names the host or address the caller asked about.
 *
 * ```ts
 * import { checkServerName } from 'pkinative';
 *
 * const reasons = checkServerName(certificate, { kind: 'dns', value: 'bank.example' });
 * if (reasons.length > 0) return 'this certificate is not for that host';
 * ```
 *
 * This is **not** part of RFC 5280 §6 and is not done by
 * `validateCertificatePath`: path validation has no notion of the name you
 * asked for. Both are needed, and a caller doing only one of them has either a
 * certificate from nobody in particular or a certificate for somebody else.
 *
 * @param certificate The end-entity certificate presented.
 * @param reference   The host or address the caller connected to; a `dns` value that spells an address is read as one.
 * @param options     See {@link CheckServerNameOptions}.
 * @returns `PKI_REASON_NAME_MISMATCH` when nothing matches; empty when
 *   something does.
 * @throws Never — a mismatch is an answer, and every input shape is one of the
 *   two `ServerIdentity` members.
 */
export function checkServerName(
    certificate: Certificate,
    reference: ServerIdentity,
    options?: CheckServerNameOptions,
): readonly PkiReason[] {
    const identity = asAddress(reference);
    const san = getExtension(certificate, 'subjectAltName');
    const names = san?.names ?? [];
    // §6.4.4: the presence of ANY dNSName or iPAddress makes the SAN
    // authoritative, even when none of them matches. A certificate with a SAN
    // full of other forms falls through to the CN rule, which is the only case
    // RFC 6125 leaves it open.
    const sanIsAuthoritative = names.some((name) => name.kind === 'dNSName' || name.kind === 'iPAddress');

    const dns: MatchDnsNameOptions = { allowWildcards: options?.allowWildcards !== false };
    if (sanIsAuthoritative) {
        for (const name of names) {
            if (matches(name, identity, dns)) return [];
        }
        return [nameMismatchReason('certificate.subjectAltName', identityText(reference), listed(names))];
    }

    if (options?.allowCommonNameFallback !== true) {
        return [nameMismatchReason('certificate.subjectAltName',
            identityText(reference),
            names.length === 0
                ? 'the certificate carries no subjectAltName at all, and the deprecated commonName fallback was not asked for'
                : 'the subjectAltName carries no dNSName and no iPAddress, and the deprecated commonName fallback was not asked for')];
    }

    const common = commonNames(certificate);
    const matched = identity.kind === 'dns' ? common.find((cn) => matchDnsName(cn, identity.value, dns)) : undefined;
    if (matched === undefined) {
        return [nameMismatchReason('certificate.subject', identityText(reference), `commonName ${common.map((c) => JSON.stringify(c)).join(', ') || '(none)'}`)];
    }
    // A commonName used as a host name is a host name, and the CAs above it
    // constrained host names: the fallback must not be the one route around
    // their dNSName subtrees. Without the path nothing says what they were.
    if (options.path === undefined) {
        return [nameMismatchReason('certificate.subject', identityText(reference),
            `commonName ${JSON.stringify(matched)} matches, but the commonName fallback needs options.path — the validated path — so that the dNSName name constraints of the CAs that issued the certificate apply to it`)];
    }
    const verdict = constrainedCommonName(certificate, options.path, matched);
    if (verdict === null) return [];
    return [verdict.why === 'excluded'
        ? nameExcludedReason('certificate.subject', 'dNSName', verdict.text)
        : nameNotPermittedReason('certificate.subject', 'dNSName', verdict.text)];
}

/**
 * A `commonName` against the `dNSName` constraints of the path that issued the
 * certificate: every `nameConstraints` but the certificate's own, accumulated
 * from the anchor down as RFC 5280 §6.1.4 (g) does, then tested as §6.1.3 (b)
 * and (c) test a `dNSName`.
 */
function constrainedCommonName(certificate: Certificate, path: readonly Certificate[], commonName: string): NameVerdict {
    const state = initialNameConstraints();
    // Bounded by the caller's path, which validation already bounded by maxChainLength.
    for (const issuer of path.filter((candidate) => !bytesEqual(candidate.der, certificate.der)).reverse()) {
        const constraints = getExtension(issuer, 'nameConstraints');
        if (constraints !== undefined) accumulateNameConstraints(state, constraints.permittedSubtrees, constraints.excludedSubtrees);
    }
    return checkName(state, { kind: 'dNSName', value: commonName, der: new Uint8Array(0) });
}

/**
 * A `dns` reference that spells an address, as the `ip` identity it is.
 *
 * An address literal comes back as `ip`; text ending in a numeric label that
 * is no canonical address comes back as an `ip` identity of zero octets,
 * which no `iPAddress` entry (4 or 16 octets, or 8 or 32 in a constraint)
 * equals — so it matches nothing; anything else is a host name and is left
 * alone.
 */
function asAddress(identity: ServerIdentity): ServerIdentity {
    if (identity.kind === 'ip') return identity;
    const text = identity.value.startsWith('[') && identity.value.endsWith(']') ? identity.value.slice(1, -1) : identity.value;
    if (text.includes(':')) return { kind: 'ip', value: ipv6Octets(text) ?? new Uint8Array(0) };
    const host = stripTrailingDot(text);
    if (!NUMERIC_LABEL.test(host.slice(host.lastIndexOf('.') + 1))) return identity;
    return { kind: 'ip', value: IPV4_ADDRESS.test(host) ? Uint8Array.from(host.split('.'), Number) : new Uint8Array(0) };
}

/**
 * RFC 4291 §2.2 text to sixteen octets, or null when it is not one: eight
 * groups, or fewer around one `::`, the last two optionally a dotted quad.
 * A zone index (`%eth0`) is not part of an address and fails the group test.
 */
function ipv6Octets(text: string): Uint8Array | null {
    if (text.length > MAX_IPV6_TEXT) return null;
    const halves = text.split('::');
    if (halves.length > 2) return null;
    const compressed = halves.length === 2;
    const head = ipv6Words(halves[0] as string, !compressed);
    const tail = compressed ? ipv6Words(halves[1] as string, true) : [];
    if (head === null || tail === null) return null;
    // `::` stands for at least one group (RFC 4291 §2.2 (2)).
    if (compressed ? head.length + tail.length > 7 : head.length !== 8) return null;
    const words = [...head, ...Array.from({ length: 8 - head.length - tail.length }, () => 0), ...tail];
    return Uint8Array.from(words.flatMap((word) => [word >> 8, word & 0xff]));
}

/** The 16-bit words of one side of `::`; `last` admits a dotted-quad final group. Bounded by MAX_IPV6_TEXT. */
function ipv6Words(half: string, last: boolean): number[] | null {
    if (half === '') return [];
    const out: number[] = [];
    const groups = half.split(':');
    for (const [index, group] of groups.entries()) {
        if (last && index === groups.length - 1 && IPV4_ADDRESS.test(group)) {
            const [a, b, c, d] = group.split('.').map(Number) as [number, number, number, number];
            out.push(a * 256 + b, c * 256 + d);
        } else if (IPV6_GROUP.test(group)) {
            out.push(Number.parseInt(group, 16));
        } else {
            return null;
        }
    }
    return out;
}

/** One GeneralName against the identity. Forms never cross. */
function matches(name: GeneralName, identity: ServerIdentity, dns: MatchDnsNameOptions): boolean {
    if (identity.kind === 'dns') {
        // An IP reference never matches a dNSName and a DNS reference never
        // matches an iPAddress: `1.2.3.4` written as a DNS name is a whole
        // class of bypass.
        return name.kind === 'dNSName' && matchDnsName(name.value, identity.value, dns);
    }
    return name.kind === 'iPAddress' && bytesEqual(name.bytes, identity.value);
}

/** Case-folded over ASCII only: a host name is not a locale. */
function fold(text: string): string {
    return text.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/**
 * RFC 6125 §6.4: a presented `dNSName` against a reference host name.
 *
 * @param presented The certificate's name, possibly a wildcard.
 * @param reference The host the caller asked about.
 * @param options   `allowWildcards: false` refuses every wildcard; on by default.
 * @returns Whether they identify the same host.
 * @throws Never — every string is either a match or not one.
 */
export function matchDnsName(presented: string, reference: string, options?: MatchDnsNameOptions): boolean {
    // An empty or NUL-bearing name identifies nothing. Exact comparison would
    // already refuse them, but saying so here makes the intent explicit — a
    // NUL in a certificate name is CVE-2009-2408's whole mechanism.
    if (presented === '' || presented.includes('\0') || reference === '' || reference.includes('\0')) return false;
    // A wildcard is presented, never asked for: `*.example.com` as the
    // reference names no host, and must not match the pattern it copies.
    if (reference.includes('*')) return false;

    const host = fold(stripTrailingDot(reference));
    const pattern = fold(stripTrailingDot(presented));
    if (!pattern.includes('*')) return pattern === host;
    if (options?.allowWildcards === false) return false;

    const labels = pattern.split('.');
    const first = labels[0] as string;
    // One whole leftmost label, and nothing else. `f*.example.com`,
    // `a.*.example.com` and a second `*` anywhere are all refused, whatever
    // RFC 6125 §6.4.3 once permitted — browsers refuse them and each has been
    // somebody's bypass.
    if (first !== '*') return false;
    if (labels.slice(1).some((label) => label.includes('*'))) return false;
    // `*.com` is refused: the correct test is a public suffix list, which is
    // data that changes weekly and which this library will not carry stale.
    if (labels.length < 3) return false;
    if (labels.includes('')) return false;

    const suffix = labels.slice(1).join('.');
    const hostLabels = host.split('.');
    // Exactly one label is consumed, and it must exist: `*.example.com` does
    // not match `example.com`. The suffix comparison below holds the label
    // count (equal joins have equal labels), and split always yields index 0 —
    // no `?? ''` here, because a fallback for a case that cannot happen is a
    // branch no test can ever reach.
    if (hostLabels[0] === '') return false;
    return hostLabels.slice(1).join('.') === suffix;
}

/** RFC 6125 §6.4.1: one trailing dot is an absolute name, not a different one. */
function stripTrailingDot(name: string): string {
    return name.endsWith('.') ? name.slice(0, -1) : name;
}

/** Every `commonName` of the subject, in encoded order. */
function commonNames(certificate: Certificate): string[] {
    const out: string[] = [];
    for (const rdn of certificate.subject.rdns) {
        for (const attribute of rdn) {
            if (attribute.type === OID_COMMON_NAME && attribute.value !== undefined) out.push(attribute.value.value);
        }
    }
    return out;
}

/**
 * The identity as the report quotes it.
 *
 * Named `identityText` rather than `describe` because the `bundle-check` gate
 * step greps the built package for `describe(` — a guard against test code
 * shipping — and a private helper with that name trips it. The guard is right
 * to be suspicious, and the clearer name was the better answer anyway.
 */
function identityText(identity: ServerIdentity): string {
    if (identity.kind === 'dns') return `the DNS name "${identity.value}"`;
    const bytes = identity.value;
    const text = bytes.length === 4
        ? Array.from(bytes, (b) => String(b)).join('.')
        : Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return `the address ${text}`;
}

/**
 * What the certificate does name, so the report can be acted on.
 *
 * Only the two host-bearing forms are listed, and the overflow count counts
 * those and not every entry: a SAN of ten `dNSName`s beside forty `rfc822Name`s
 * would otherwise report "and 42 more" hosts it never had.
 */
function listed(names: readonly GeneralName[]): string {
    const hosts: string[] = [];
    for (const name of names) {
        if (name.kind === 'dNSName') hosts.push(JSON.stringify(name.value));
        else if (name.kind === 'iPAddress') hosts.push(name.address);
    }
    const more = hosts.length > 8 ? `, and ${String(hosts.length - 8)} more` : '';
    return `it names ${hosts.slice(0, 8).join(', ')}${more}`;
}
