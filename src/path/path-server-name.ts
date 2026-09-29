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
 * matching a field no issuer has controlled for a decade.
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
 * @module path/path-server-name
 */

import { nameMismatchReason } from '../core/pki-reasons.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate, GeneralName } from '../types/x509-types.js';
import { getExtension } from '../x509/x509-extensions.js';

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
     */
    readonly allowCommonNameFallback?: boolean | undefined;
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
 * @param identity    The host or address the caller connected to.
 * @param options     See {@link CheckServerNameOptions}.
 * @returns `PKI_REASON_NAME_MISMATCH` when nothing matches; empty when
 *   something does.
 * @throws Never — a mismatch is an answer, and every input shape is one of the
 *   two `ServerIdentity` members.
 */
export function checkServerName(
    certificate: Certificate,
    identity: ServerIdentity,
    options?: CheckServerNameOptions,
): readonly PkiReason[] {
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
        return [nameMismatchReason('certificate.subjectAltName', identityText(identity), listed(names))];
    }

    if (options?.allowCommonNameFallback !== true) {
        return [nameMismatchReason('certificate.subjectAltName',
            identityText(identity),
            names.length === 0
                ? 'the certificate carries no subjectAltName at all, and the deprecated commonName fallback was not asked for'
                : 'the subjectAltName carries no dNSName and no iPAddress, and the deprecated commonName fallback was not asked for')];
    }

    for (const common of commonNames(certificate)) {
        if (identity.kind === 'dns' && matchDnsName(common, identity.value, dns)) return [];
    }
    return [nameMismatchReason('certificate.subject', identityText(identity), `commonName ${commonNames(certificate).map((c) => JSON.stringify(c)).join(', ') || '(none)'}`)];
}

/** One GeneralName against the identity. Forms never cross. */
function matches(name: GeneralName, identity: ServerIdentity, dns: MatchDnsNameOptions): boolean {
    if (identity.kind === 'dns') {
        // An IP reference never matches a dNSName and a DNS reference never
        // matches an iPAddress: `1.2.3.4` written as a DNS name is a whole
        // class of bypass.
        return name.kind === 'dNSName' && matchDnsName(name.value, identity.value, dns);
    }
    return name.kind === 'iPAddress' && sameBytes(name.bytes, identity.value);
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
    if (labels.slice(1).some((label) => label === '')) return false;

    const suffix = labels.slice(1).join('.');
    const hostLabels = host.split('.');
    // Exactly one label is consumed, and it must exist: `*.example.com` does
    // not match `example.com`. The length check above has already established
    // that `hostLabels` has at least three entries, so index 0 is present —
    // no `?? ''` here, because a fallback for a case that cannot happen is a
    // branch no test can ever reach.
    if (hostLabels.length !== labels.length) return false;
    if (hostLabels[0] === '') return false;
    return hostLabels.slice(1).join('.') === suffix;
}

/** RFC 6125 §6.4.1: one trailing dot is an absolute name, not a different one. */
function stripTrailingDot(name: string): string {
    return name.endsWith('.') ? name.slice(0, -1) : name;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
    return true;
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
