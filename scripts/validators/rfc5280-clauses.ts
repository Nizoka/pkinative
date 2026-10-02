/**
 * pkinative — the RFC 5280 clause checker (conformance level L5)
 * ==============================================================
 * A second, separately written reading of the same certificate, clause by
 * clause. It reaches bytes only through `scripts/lib/raw-der.ts` and **never
 * imports `src/`** — the same rule L2's boundary checks follow, for the same
 * reason: two readings that share a decoder cannot disagree, so a shared bug
 * would make both of them green.
 *
 * The table it enforces is `scripts/lib/clauses.ts`, where every entry quotes
 * its normative sentence. This file answers only *"does this certificate
 * violate that sentence"*, from the bytes, with no reference to what
 * pkinative thinks. The comparison happens afterwards, in the runner, which
 * is what makes it evidence rather than a tautology.
 *
 * @module scripts/validators/rfc5280-clauses
 */

import { CLAUSES, type Verdict } from '../lib/clauses.js';
import { isIPv4, isIPv6 } from 'node:net';
import { childrenOf, certificateBounds, readTlv, type RawTlv } from '../lib/raw-der.js';

const NA: Verdict = 'not-applicable';

// ── Locating the fields, without the engine ──────────────────────────

interface Tbs {
    readonly version: number;
    /** The `[0] EXPLICIT` wrapper, when the field is present at all. */
    readonly versionTlv: RawTlv | null;
    readonly serial: RawTlv;
    readonly signature: RawTlv;
    readonly issuer: RawTlv;
    readonly validity: RawTlv;
    readonly subject: RawTlv;
    readonly uniqueIds: readonly RawTlv[];
    readonly extensions: readonly Extension[];
    /** True when the `[3]` field is present, even if it holds an empty SEQUENCE. */
    readonly hasExtensionsField: boolean;
}

interface Extension {
    readonly oid: string;
    /** The BOOLEAN TLV when written out, `null` when it takes its DEFAULT. */
    readonly criticalTlv: RawTlv | null;
    readonly critical: boolean;
    /** The OCTET STRING's content, parsed as a TLV. `null` when it is not one. */
    readonly value: RawTlv | null;
    readonly valueBytes: Uint8Array;
}

function oidText(bytes: Uint8Array, tlv: RawTlv): string {
    const content = bytes.subarray(tlv.offset + tlv.headerLength, tlv.end);
    if (content.length === 0) return '';
    const first = content[0] as number;
    const arcs: string[] = first < 80 ? [String(Math.floor(first / 40)), String(first % 40)] : ['2', String(first - 80)];
    let acc = 0n;
    for (const octet of content.subarray(1)) {
        acc = (acc << 7n) | BigInt(octet & 0x7f);
        if ((octet & 0x80) === 0) { arcs.push(acc.toString()); acc = 0n; }
    }
    return arcs.join('.');
}

/** The tbsCertificate's fields, positionally, with the optional ones detected by tag. */
function readTbs(der: Uint8Array): Tbs {
    const { tbs } = certificateBounds(der);
    const parts = childrenOf(der, tbs);
    let at = 0;
    const isContext = (t: RawTlv | undefined, n: number): boolean => t !== undefined && t.tagClass === 2 && t.tagNumber === n;

    let versionTlv: RawTlv | null = null;
    let version = 0;
    if (isContext(parts[at], 0)) {
        versionTlv = parts[at] as RawTlv;
        at += 1;
        const inner = childrenOf(der, versionTlv)[0];
        // A version field whose content is not a single-octet INTEGER is
        // structurally broken; leave it at v1 and let the other clauses speak.
        version = inner !== undefined && inner.length === 1 ? (der[inner.offset + inner.headerLength] as number) : 0;
    }
    const take = (): RawTlv => {
        const t = parts[at];
        if (t === undefined) throw new Error('raw-der: tbsCertificate is shorter than RFC 5280 requires');
        at += 1;
        return t;
    };
    const serial = take();
    const signature = take();
    const issuer = take();
    const validity = take();
    const subject = take();
    take(); // subjectPublicKeyInfo, not read by any clause here

    const uniqueIds: RawTlv[] = [];
    let extensionsField: RawTlv | null = null;
    for (; at < parts.length; at += 1) {
        const t = parts[at] as RawTlv;
        if (isContext(t, 1) || isContext(t, 2)) uniqueIds.push(t);
        else if (isContext(t, 3)) extensionsField = t;
    }

    const extensions: Extension[] = [];
    if (extensionsField !== null) {
        const seq = childrenOf(der, extensionsField)[0];
        if (seq !== undefined) {
            for (const ext of childrenOf(der, seq)) {
                const fields = childrenOf(der, ext);
                const [oidTlv, second, third] = fields;
                if (oidTlv === undefined) continue;
                const criticalTlv = second !== undefined && second.tagClass === 0 && second.tagNumber === 1 ? second : null;
                const valueTlv = criticalTlv === null ? second : third;
                const valueBytes = valueTlv === undefined ? new Uint8Array(0) : der.subarray(valueTlv.offset + valueTlv.headerLength, valueTlv.end);
                let value: RawTlv | null = null;
                try {
                    value = valueBytes.length === 0 ? null : readTlv(valueBytes, 0);
                } catch { value = null; }
                extensions.push({
                    oid: oidText(der, oidTlv),
                    criticalTlv,
                    critical: criticalTlv !== null && der[criticalTlv.offset + criticalTlv.headerLength] !== 0x00,
                    value,
                    valueBytes,
                });
            }
        }
    }

    return { version, versionTlv, serial, signature, issuer, validity, subject, uniqueIds, extensions, hasExtensionsField: extensionsField !== null };
}

// ── Small readers the clauses share ──────────────────────────────────

const content = (bytes: Uint8Array, t: RawTlv): Uint8Array => bytes.subarray(t.offset + t.headerLength, t.end);
const slice = (bytes: Uint8Array, t: RawTlv): Uint8Array => bytes.subarray(t.offset, t.end);
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

/** Compare two encodings the way X.690 §11.6 orders a SET OF. */
function ascending(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
        const d = (a[i] as number) - (b[i] as number);
        if (d !== 0) return d;
    }
    // The shorter encoding sorts first, its missing octets treated as absent
    // rather than as zero (X.690 §11.6, "as if padded with zero octets" applies
    // to the *value* octets of equal-length components only).
    return a.length - b.length;
}

const ext = (tbs: Tbs, oid: string): Extension | undefined => tbs.extensions.find((e) => e.oid === oid);

/**
 * True when basicConstraints is present and asserts cA — RFC 5280's own
 * definition of a CA certificate (§4.2.1.2: "all certificates including the
 * basic constraints extension … where the value of cA is TRUE").
 */
function assertsCa(tbs: Tbs): boolean {
    const bc = ext(tbs, '2.5.29.19');
    if (bc?.value === undefined || bc.value === null) return false;
    const first = childrenOf(bc.valueBytes, bc.value)[0];
    return first !== undefined && first.tagClass === 0 && first.tagNumber === 1 && bc.valueBytes[first.offset + first.headerLength] !== 0x00;
}

// ── Readers for the §4.2.1.4–§4.2.2 clauses (since 1.0) ──────────────
//
// Written against RFC 3986 Appendix B and RFC 4516 §2 directly, and against
// `node:net` for the address forms, so that they share nothing with
// src/core/uri.ts but the standards both read.

/** The children of an extension's value, or [] when it has none to read. */
const valueChildren = (e: Extension | undefined): RawTlv[] => (e?.value === undefined || e.value === null ? [] : childrenOf(e.valueBytes, e.value));
const isContext = (t: RawTlv, n: number): boolean => t.tagClass === 2 && t.tagNumber === n;
const latin1 = (bytes: Uint8Array): string => String.fromCharCode(...bytes);

/** Every GeneralName of subjectAltName and issuerAltName, with the bytes it lives in. */
function altNames(tbs: Tbs): Array<{ readonly bytes: Uint8Array; readonly name: RawTlv }> {
    return [ext(tbs, '2.5.29.17'), ext(tbs, '2.5.29.18')].flatMap((e) => valueChildren(e).map((name) => ({ bytes: (e as Extension).valueBytes, name })));
}

/** The uniformResourceIdentifier strings of subjectAltName and issuerAltName. */
const altNameUris = (tbs: Tbs): string[] => altNames(tbs).filter(({ name }) => isContext(name, 6)).map(({ bytes, name }) => latin1(content(bytes, name)));

/** RFC 3986 Appendix B, the regular expression the RFC itself gives for splitting a URI reference. */
const APPENDIX_B = /^(([^:/?#]+):)?(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$/s;
const PCT_OR = (chars: string): RegExp => new RegExp(`^(?:[${chars}]|%[0-9A-Fa-f]{2})*$`);
const SEGMENTS = PCT_OR("A-Za-z0-9\\-._~!$&'()*+,;=:@/");
const QUERY_OR_FRAGMENT = PCT_OR("A-Za-z0-9\\-._~!$&'()*+,;=:@/?");
const USERINFO = PCT_OR("A-Za-z0-9\\-._~!$&'()*+,;=:");
const REG_NAME = PCT_OR("A-Za-z0-9\\-._~!$&'()*+,;=");
const FQDN = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** An IPv6 address as `node:net` reads one, without the zone identifier RFC 3986 has no room for. */
const ipv6 = (text: string): boolean => !text.includes('%') && isIPv6(text);

/** The host an authority names: after the userinfo, before the port, an IP literal with its brackets. */
function hostOf(authority: string): { readonly userinfo: string | null; readonly host: string; readonly port: string | null } {
    const at = authority.indexOf('@');
    const userinfo = at < 0 ? null : authority.slice(0, at);
    const rest = authority.slice(at + 1);
    const literal = /^(\[[^\]]*\])(?::(.*))?$/s.exec(rest);
    if (rest.startsWith('[')) return literal === null ? { userinfo, host: rest, port: null } : { userinfo, host: literal[1] as string, port: literal[2] ?? null };
    const colon = rest.indexOf(':');
    return colon < 0 ? { userinfo, host: rest, port: null } : { userinfo, host: rest.slice(0, colon), port: rest.slice(colon + 1) };
}

/** RFC 3986 §3: the whole string is a `URI` — a scheme, and every part of it in its own alphabet. */
function isAbsoluteUri(text: string): boolean {
    const m = APPENDIX_B.exec(text);
    if (m?.[2] === undefined || !/^[A-Za-z][A-Za-z0-9+.-]*$/.test(m[2])) return false;
    if (!SEGMENTS.test(m[5] ?? '') || !QUERY_OR_FRAGMENT.test(m[7] ?? '') || !QUERY_OR_FRAGMENT.test(m[9] ?? '')) return false;
    if (m[4] === undefined) return true;
    const { userinfo, host, port } = hostOf(m[4]);
    if ((userinfo !== null && !USERINFO.test(userinfo)) || (port !== null && !/^[0-9]*$/.test(port))) return false;
    if (!host.startsWith('[')) return REG_NAME.test(host);
    const inside = host.slice(1, -1);
    return host.endsWith(']') && (ipv6(inside) || /^v[0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+$/i.test(inside));
}

/** The authority of a URI with a scheme, or null when it has none. */
function authorityOf(text: string): string | null {
    const m = APPENDIX_B.exec(text);
    return m?.[2] === undefined || !/^[A-Za-z][A-Za-z0-9+.-]*$/.test(m[2]) ? null : (m[4] ?? null);
}

/** RFC 5280 §4.2.1.6: a fully qualified domain name, or an IPv4 address, or an IPv6 literal. */
function fqdnOrIp(host: string): boolean {
    if (host.startsWith('[') && host.endsWith(']')) return ipv6(host.slice(1, -1));
    return isIPv4(host) || FQDN.test(host);
}

/** RFC 4516 §2 `<dn>` and `<attributes>` of an `ldap://` URL; null for any other string. */
function ldapParts(text: string): { readonly dn: string | null; readonly attributes: string | null } | null {
    const m = /^ldap:\/\/[^/]*(?:\/([^?]*)(?:\?([^?]*))?)?/is.exec(text);
    if (m === null) return null;
    return { dn: m[1] ?? null, attributes: m[2] ?? null };
}

const httpOrLdap = (text: string): boolean => /^(?:http|ldap):/i.test(text);

/** The DistributionPoints of cRLDistributionPoints and freshestCRL, each with its context fields. */
function distributionPoints(tbs: Tbs): Array<{ readonly bytes: Uint8Array; readonly fields: readonly RawTlv[] }> {
    return [ext(tbs, '2.5.29.31'), ext(tbs, '2.5.29.46')].flatMap((e) =>
        valueChildren(e).map((dp) => ({ bytes: (e as Extension).valueBytes, fields: childrenOf((e as Extension).valueBytes, dp) })));
}

/** The DistributionPointName CHOICE inside a point's explicit `[0]`, when there is one. */
function pointName(bytes: Uint8Array, fields: readonly RawTlv[]): RawTlv | undefined {
    const wrapper = fields.find((f) => isContext(f, 0));
    return wrapper === undefined ? undefined : childrenOf(bytes, wrapper)[0];
}

/** The `fullName` URIs of one point. */
function fullNameUris(bytes: Uint8Array, fields: readonly RawTlv[]): string[] {
    const choice = pointName(bytes, fields);
    if (choice === undefined || !isContext(choice, 0)) return [];
    return childrenOf(bytes, choice).filter((n) => isContext(n, 6)).map((n) => latin1(content(bytes, n)));
}

/** The URI access locations of one access method in authorityInfoAccess or subjectInfoAccess, and whether the method appears. */
function accessLocations(e: Extension | undefined, method: string): { readonly listed: boolean; readonly uris: string[] } {
    let listed = false;
    const uris: string[] = [];
    for (const description of valueChildren(e)) {
        const [m, location] = childrenOf((e as Extension).valueBytes, description);
        if (m === undefined || oidText((e as Extension).valueBytes, m) !== method) continue;
        listed = true;
        if (location !== undefined && isContext(location, 6)) uris.push(latin1(content((e as Extension).valueBytes, location)));
    }
    return { listed, uris };
}

/** The explicitText strings of every user notice of certificatePolicies, with their universal tag. */
function explicitTexts(tbs: Tbs): Array<{ readonly tag: number; readonly bytes: Uint8Array }> {
    const cp = ext(tbs, '2.5.29.32');
    const out: Array<{ readonly tag: number; readonly bytes: Uint8Array }> = [];
    for (const info of valueChildren(cp)) {
        const qualifiers = childrenOf((cp as Extension).valueBytes, info)[1];
        if (qualifiers === undefined) continue;
        for (const q of childrenOf((cp as Extension).valueBytes, qualifiers)) {
            const [id, notice] = childrenOf((cp as Extension).valueBytes, q);
            if (id === undefined || notice === undefined || oidText((cp as Extension).valueBytes, id) !== '1.3.6.1.5.5.7.2.2') continue;
            for (const part of childrenOf((cp as Extension).valueBytes, notice)) {
                if (part.tagClass === 0 && part.tagNumber !== 16) out.push({ tag: part.tagNumber, bytes: content((cp as Extension).valueBytes, part) });
            }
        }
    }
    return out;
}

/** An explicitText as the characters it spells, by its string type. */
function textOf(tag: number, bytes: Uint8Array): string {
    if (tag === 12) return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (tag === 30) return new TextDecoder('utf-16be', { fatal: true }).decode(bytes);
    return latin1(bytes);
}

/** Every user notice qualifier's content — the SEQUENCE of its optional noticeRef and explicitText. */
function userNotices(tbs: Tbs): RawTlv[] {
    const cp = ext(tbs, '2.5.29.32');
    const bytes = cp?.valueBytes ?? new Uint8Array(0);
    return valueChildren(cp).flatMap((info) => {
        const qualifiers = childrenOf(bytes, info)[1];
        return qualifiers === undefined ? [] : childrenOf(bytes, qualifiers)
            .map((q) => childrenOf(bytes, q))
            .filter(([id]) => id !== undefined && oidText(bytes, id) === '1.3.6.1.5.5.7.2.2')
            .flatMap(([, notice]) => (notice === undefined ? [] : [notice]));
    });
}

/** A verdict from "does the clause apply" and "is it broken". */
const judge = (applicable: boolean, broken: boolean): Verdict => (!applicable ? NA : broken ? 'fail' : 'pass');

/** The criticality clauses: applicable when the extension is present. */
const mustBe = (oid: string, critical: boolean) => (_der: Uint8Array, tbs: Tbs): Verdict => {
    const e = ext(tbs, oid);
    return judge(e !== undefined, e?.critical !== critical);
};

// ── The clauses ──────────────────────────────────────────────────────

type Evaluator = (der: Uint8Array, tbs: Tbs) => Verdict;

const EVALUATORS: Readonly<Record<string, Evaluator>> = {
    '4.1.2.2-serial-positive': (der, tbs) => {
        const c = content(der, tbs.serial);
        if (c.length === 0) return NA;
        const negative = ((c[0] as number) & 0x80) !== 0;
        const zero = c.every((b) => b === 0);
        return negative || zero ? 'fail' : 'pass';
    },

    '4.1.2.2-serial-at-most-20-octets': (der, tbs) => (content(der, tbs.serial).length > 20 ? 'fail' : 'pass'),

    '4.1.1.2-signature-algorithm-matches-tbs': (der) => {
        const { signatureAlgorithm } = certificateBounds(der);
        const tbsSignature = readTbs(der).signature;
        return sameBytes(slice(der, tbsSignature), slice(der, signatureAlgorithm)) ? 'pass' : 'fail';
    },

    '4.1.2.1-extensions-require-v3': (_der, tbs) => {
        if (!tbs.hasExtensionsField) return NA;
        return tbs.version === 2 ? 'pass' : 'fail';
    },

    '4.1.2.8-unique-id-requires-v2': (_der, tbs) => {
        if (tbs.uniqueIds.length === 0) return NA;
        return tbs.version >= 1 ? 'pass' : 'fail';
    },

    '4.1.2.5-generalized-time-only-from-2050': (der, tbs) => {
        const times = childrenOf(der, tbs.validity);
        const generalized = times.filter((t) => t.tagNumber === 24 && t.tagClass === 0);
        if (generalized.length === 0) return NA;
        for (const t of generalized) {
            const text = String.fromCharCode(...content(der, t));
            const year = Number(text.slice(0, 4));
            if (Number.isFinite(year) && year < 2050) return 'fail';
        }
        return 'pass';
    },

    '4.1.2.5.2-generalized-time-no-fraction': (der, tbs) => {
        const times = childrenOf(der, tbs.validity).filter((t) => t.tagNumber === 24 && t.tagClass === 0);
        if (times.length === 0) return NA;
        for (const t of times) {
            const text = String.fromCharCode(...content(der, t));
            if (text.includes('.') || text.includes(',')) return 'fail';
        }
        return 'pass';
    },

    '4.1.2.4-issuer-not-empty': (der, tbs) => (childrenOf(der, tbs.issuer).length === 0 ? 'fail' : 'pass'),

    '4.2-critical-default-absent': (der, tbs) => {
        if (tbs.extensions.length === 0) return NA;
        for (const e of tbs.extensions) {
            // DER omits a DEFAULT. A BOOLEAN written as FALSE is the DEFAULT
            // spelled out; a BOOLEAN written as TRUE is required.
            if (e.criticalTlv !== null && der[e.criticalTlv.offset + e.criticalTlv.headerLength] === 0x00) return 'fail';
        }
        return 'pass';
    },

    '4.2.1.9-path-len-requires-ca': (_der, tbs) => {
        const bc = ext(tbs, '2.5.29.19');
        if (bc?.value === undefined || bc.value === null) return NA;
        const fields = childrenOf(bc.valueBytes, bc.value);
        const [first, second] = fields;
        const caTlv = first !== undefined && first.tagClass === 0 && first.tagNumber === 1 ? first : null;
        const pathLen = caTlv === null ? first : second;
        if (pathLen === undefined || pathLen.tagNumber !== 2 || pathLen.tagClass !== 0) return NA;
        const ca = caTlv !== null && bc.valueBytes[caTlv.offset + caTlv.headerLength] !== 0x00;
        return ca ? 'pass' : 'fail';
    },

    '4.2.1.3-key-usage-not-empty': (_der, tbs) => {
        const ku = ext(tbs, '2.5.29.15');
        if (ku?.value === undefined || ku.value === null || ku.value.tagNumber !== 3) return NA;
        const bits = content(ku.valueBytes, ku.value);
        if (bits.length === 0) return NA;
        return bits.subarray(1).some((b) => b !== 0) ? 'pass' : 'fail';
    },

    '4.2.1.6-alt-name-not-empty': (_der, tbs) => {
        const names = [ext(tbs, '2.5.29.17'), ext(tbs, '2.5.29.18')].filter((e): e is Extension => e !== undefined);
        const decodable = names.filter((e) => e.value !== null);
        if (decodable.length === 0) return NA;
        for (const e of decodable) {
            if (childrenOf(e.valueBytes, e.value as RawTlv).length === 0) return 'fail';
        }
        return 'pass';
    },

    '4.2.1.10-name-constraints-critical': (_der, tbs) => {
        const nc = ext(tbs, '2.5.29.30');
        if (nc === undefined) return NA;
        return nc.critical ? 'pass' : 'fail';
    },

    '4.2.1.11-policy-constraints-not-empty': (_der, tbs) => {
        const pc = ext(tbs, '2.5.29.36');
        if (pc?.value === undefined || pc.value === null) return NA;
        return childrenOf(pc.valueBytes, pc.value).length === 0 ? 'fail' : 'pass';
    },

    '4.2.1.4-policies-not-duplicated': (_der, tbs) => {
        const cp = ext(tbs, '2.5.29.32');
        if (cp?.value === undefined || cp.value === null) return NA;
        const seen = new Set<string>();
        for (const info of childrenOf(cp.valueBytes, cp.value)) {
            const oidTlv = childrenOf(cp.valueBytes, info)[0];
            if (oidTlv === undefined) continue;
            const oid = oidText(cp.valueBytes, oidTlv);
            if (seen.has(oid)) return 'fail';
            seen.add(oid);
        }
        return 'pass';
    },

    '4.2.1.1-aki-issuer-and-serial-paired': (_der, tbs) => {
        const aki = ext(tbs, '2.5.29.35');
        if (aki?.value === undefined || aki.value === null) return NA;
        const fields = childrenOf(aki.valueBytes, aki.value);
        const hasIssuer = fields.some((f) => f.tagClass === 2 && f.tagNumber === 1);
        const hasSerial = fields.some((f) => f.tagClass === 2 && f.tagNumber === 2);
        if (!hasIssuer && !hasSerial) return NA;
        return hasIssuer === hasSerial ? 'pass' : 'fail';
    },

    'x690-11.6-rdn-set-sorted': (der, tbs) => {
        let applicable = false;
        for (const name of [tbs.issuer, tbs.subject]) {
            for (const rdn of childrenOf(der, name)) {
                const attributes = childrenOf(der, rdn);
                if (attributes.length < 2) continue;
                applicable = true;
                for (let i = 1; i < attributes.length; i += 1) {
                    if (ascending(slice(der, attributes[i - 1] as RawTlv), slice(der, attributes[i] as RawTlv)) > 0) return 'fail';
                }
            }
        }
        return applicable ? 'pass' : NA;
    },

    'x690-11.2.2-named-bits-trimmed': (_der, tbs) => {
        const ku = ext(tbs, '2.5.29.15');
        if (ku?.value === undefined || ku.value === null || ku.value.tagNumber !== 3) return NA;
        const bits = content(ku.valueBytes, ku.value);
        // 03 01 00 — no bit at all — is the correct DER for an empty named bit
        // list, not a trailing-zero violation. Clause 4.2.1.3 judges that one.
        if (bits.length < 2) return NA;
        const unused = bits[0] as number;
        const last = bits[bits.length - 1] as number;
        if (last === 0) return 'fail';
        return ((last >> unused) & 1) === 1 ? 'pass' : 'fail';
    },

    '4.1.2.6-empty-subject-requires-critical-san': (der, tbs) => {
        if (childrenOf(der, tbs.subject).length !== 0) return NA;
        const san = ext(tbs, '2.5.29.17');
        return san !== undefined && san.critical ? 'pass' : 'fail';
    },

    '4.2.1.9-basic-constraints-critical-in-ca': (_der, tbs) => {
        if (!assertsCa(tbs)) return NA;
        return ext(tbs, '2.5.29.19')?.critical === true ? 'pass' : 'fail';
    },

    '4.2.1.11-policy-constraints-critical': (_der, tbs) => {
        const pc = ext(tbs, '2.5.29.36');
        if (pc === undefined) return NA;
        return pc.critical ? 'pass' : 'fail';
    },

    '4.2.1.3-key-cert-sign-requires-ca': (_der, tbs) => {
        const ku = ext(tbs, '2.5.29.15');
        if (ku?.value === undefined || ku.value === null || ku.value.tagNumber !== 3) return NA;
        const bits = content(ku.valueBytes, ku.value);
        // keyCertSign is named bit 5: the sixth bit of the first content
        // octet after the unused-bits count.
        if (bits.length < 2 || (((bits[1] as number) >> 2) & 1) === 0) return NA;
        return assertsCa(tbs) ? 'pass' : 'fail';
    },

    '4.2.1.10-name-constraints-only-in-ca': (_der, tbs) => {
        if (ext(tbs, '2.5.29.30') === undefined) return NA;
        return assertsCa(tbs) ? 'pass' : 'fail';
    },

    '4.2.1.1-aki-key-identifier-present': (der, tbs) => {
        // A certificate with no extensions field at all has nowhere to put
        // the identifier; only a v3 certificate is asked for it here.
        if (tbs.version !== 2) return NA;
        // The self-signed exemption, seen the way a reader without a key
        // operation can see it: the issuer names the subject, byte for byte.
        if (sameBytes(slice(der, tbs.issuer), slice(der, tbs.subject))) return NA;
        const aki = ext(tbs, '2.5.29.35');
        if (aki === undefined) return 'fail';
        if (aki.value === null) return NA;
        const fields = childrenOf(aki.valueBytes, aki.value);
        return fields.some((f) => f.tagClass === 2 && f.tagNumber === 0) ? 'pass' : 'fail';
    },

    '4.2.1.2-ski-present-in-ca': (_der, tbs) => {
        if (tbs.version !== 2 || !assertsCa(tbs)) return NA;
        return ext(tbs, '2.5.29.14') === undefined ? 'fail' : 'pass';
    },

    // ── Since 1.0: the 36 sentences recorded as not-diagnosed until then ──

    // Every certificate is one a conforming CA generated, so every one is judged.
    '4.1.2.8-no-unique-ids': (_der, tbs) => judge(true, tbs.uniqueIds.length > 0),

    '4.2.1.1-aki-not-critical': mustBe('2.5.29.35', false),

    '4.2.1.2-ski-in-end-entity': (_der, tbs) => judge(tbs.version === 2 && !assertsCa(tbs), ext(tbs, '2.5.29.14') === undefined),

    '4.2.1.2-ski-not-critical': mustBe('2.5.29.14', false),

    '4.2.1.3-key-usage-critical': mustBe('2.5.29.15', true),

    '4.2.1.4-any-policy-qualifiers': (_der, tbs) => {
        const cp = ext(tbs, '2.5.29.32');
        const bytes = cp?.valueBytes ?? new Uint8Array(0);
        const ids = valueChildren(cp)
            .map((info) => childrenOf(bytes, info))
            .filter(([policy, qualifiers]) => policy !== undefined && qualifiers !== undefined && oidText(bytes, policy) === '2.5.29.32.0')
            .flatMap(([, qualifiers]) => childrenOf(bytes, qualifiers as RawTlv).map((q) => oidText(bytes, childrenOf(bytes, q)[0] as RawTlv)));
        return judge(ids.length > 0, ids.some((id) => id !== '1.3.6.1.5.5.7.2.1' && id !== '1.3.6.1.5.5.7.2.2'));
    },

    '4.2.1.4-no-notice-ref': (_der, tbs) => {
        const notices = userNotices(tbs);
        const bytes = ext(tbs, '2.5.29.32')?.valueBytes ?? new Uint8Array(0);
        return judge(notices.length > 0, notices.some((n) => childrenOf(bytes, n)[0]?.tagNumber === 16));
    },

    // One fact, two sentences: DisplayText offers IA5String, VisibleString,
    // BMPString and UTF8String, and the only two that break "SHOULD use
    // UTF8String, but MAY use IA5String" are the two "MUST NOT" names.
    '4.2.1.4-explicit-text-utf8': (_der, tbs) => {
        const texts = explicitTexts(tbs);
        return judge(texts.length > 0, texts.some((t) => t.tag !== 12 && t.tag !== 22));
    },

    '4.2.1.4-explicit-text-not-visible-or-bmp': (_der, tbs) => {
        const texts = explicitTexts(tbs);
        return judge(texts.length > 0, texts.some((t) => t.tag === 26 || t.tag === 30));
    },

    '4.2.1.4-explicit-text-no-control': (_der, tbs) => {
        const texts = explicitTexts(tbs);
        return judge(texts.length > 0, texts.some((t) => [...textOf(t.tag, t.bytes)].some((c) => {
            const code = c.charCodeAt(0);
            return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
        })));
    },

    '4.2.1.4-explicit-text-nfc': (_der, tbs) => {
        const texts = explicitTexts(tbs).filter((t) => t.tag === 12).map((t) => textOf(t.tag, t.bytes));
        return judge(texts.length > 0, texts.some((t) => t.normalize('NFC') !== t));
    },

    '4.2.1.5-mapped-policy-asserted': (_der, tbs) => {
        const pm = ext(tbs, '2.5.29.33');
        if (pm === undefined) return NA;
        const cp = ext(tbs, '2.5.29.32');
        const asserted = new Set(valueChildren(cp).map((info) => oidText((cp as Extension).valueBytes, childrenOf((cp as Extension).valueBytes, info)[0] as RawTlv)));
        const issuerDomain = valueChildren(pm).map((m) => oidText(pm.valueBytes, childrenOf(pm.valueBytes, m)[0] as RawTlv));
        return judge(true, issuerDomain.some((oid) => !asserted.has(oid)));
    },

    '4.2.1.5-policy-mappings-critical': mustBe('2.5.29.33', true),

    '4.2.1.6-san-not-critical-with-subject': (der, tbs) => {
        const san = ext(tbs, '2.5.29.17');
        return judge(san !== undefined && childrenOf(der, tbs.subject).length > 0, san?.critical === true);
    },

    '4.2.1.6-uri-absolute': (_der, tbs) => {
        const uris = altNameUris(tbs);
        return judge(uris.length > 0, uris.some((u) => !isAbsoluteUri(u)));
    },

    '4.2.1.6-uri-scheme-and-part': (_der, tbs) => {
        const uris = altNameUris(tbs);
        return judge(uris.length > 0, uris.some((u) => {
            const m = /^[A-Za-z][A-Za-z0-9+.-]*:/.exec(u);
            return m === null || u.length === m[0].length;
        }));
    },

    '4.2.1.6-uri-host-fqdn-or-ip': (_der, tbs) => {
        const authorities = altNameUris(tbs).map(authorityOf).filter((a): a is string => a !== null);
        return judge(authorities.length > 0, authorities.some((a) => !fqdnOrIp(hostOf(a).host)));
    },

    '4.2.1.6-no-empty-general-name': (_der, tbs) => {
        const names = altNames(tbs);
        return judge(names.length > 0, names.some(({ bytes, name }) => {
            if (name.tagClass !== 2) return false;
            if (name.tagNumber === 4) return childrenOf(bytes, childrenOf(bytes, name)[0] as RawTlv).length === 0;
            return [1, 2, 3, 5, 6].includes(name.tagNumber) && name.length === 0;
        }));
    },

    '4.2.1.7-ian-not-critical': mustBe('2.5.29.18', false),

    '4.2.1.10-no-min-max': (_der, tbs) => {
        const nc = ext(tbs, '2.5.29.30');
        const bytes = nc?.valueBytes ?? new Uint8Array(0);
        const subtrees = valueChildren(nc).flatMap((list) => childrenOf(bytes, list));
        return judge(subtrees.length > 0, subtrees.some((s) => childrenOf(bytes, s).slice(1).some((bound) =>
            isContext(bound, 1) || (isContext(bound, 0) && content(bytes, bound).some((b) => b !== 0)))));
    },

    '4.2.1.10-uri-constraint-fqdn': (_der, tbs) => {
        const nc = ext(tbs, '2.5.29.30');
        const bytes = nc?.valueBytes ?? new Uint8Array(0);
        const constraints = valueChildren(nc)
            .flatMap((list) => childrenOf(bytes, list))
            .map((s) => childrenOf(bytes, s)[0])
            .filter((base): base is RawTlv => base !== undefined && isContext(base, 6))
            .map((base) => latin1(content(bytes, base)));
        // "MAY specify a host or a domain": a domain is written with one leading period.
        return judge(constraints.length > 0, constraints.some((c) => !FQDN.test(c.replace(/^\./, ''))));
    },

    '4.2.1.12-any-eku-not-critical': (_der, tbs) => {
        const eku = ext(tbs, '2.5.29.37');
        const any = valueChildren(eku).some((p) => oidText((eku as Extension).valueBytes, p) === '2.5.29.37.0');
        return judge(any, eku?.critical === true);
    },

    '4.2.1.13-crl-dp-not-critical': mustBe('2.5.29.31', false),

    '4.2.1.13-dp-not-reasons-only': (_der, tbs) => {
        const points = distributionPoints(tbs);
        return judge(points.length > 0, points.some(({ fields }) => !fields.some((f) => isContext(f, 0) || isContext(f, 2))));
    },

    '4.2.1.13-ldap-uri-dn-and-attrdesc': (_der, tbs) => {
        const ldap = distributionPoints(tbs).flatMap(({ bytes, fields }) => fullNameUris(bytes, fields)).map(ldapParts).filter((p) => p !== null);
        return judge(ldap.length > 0, ldap.some((p) => !p.dn || !p.attributes || p.attributes.includes(',')));
    },

    '4.2.1.13-http-or-ldap-uri': (_der, tbs) => {
        const named = distributionPoints(tbs).filter(({ bytes, fields }) => pointName(bytes, fields) !== undefined);
        return judge(named.length > 0, named.some(({ bytes, fields }) => !fullNameUris(bytes, fields).some(httpOrLdap)));
    },

    '4.2.1.13-no-relative-name': (_der, tbs) => {
        const names = distributionPoints(tbs).map(({ bytes, fields }) => pointName(bytes, fields)).filter((n) => n !== undefined);
        return judge(names.length > 0, names.some((n) => isContext(n, 1)));
    },

    '4.2.1.13-relative-name-one-issuer': (_der, tbs) => {
        const relative = distributionPoints(tbs).filter(({ bytes, fields }) => {
            const n = pointName(bytes, fields);
            return n !== undefined && isContext(n, 1);
        });
        return judge(relative.length > 0, relative.some(({ bytes, fields }) => {
            const issuer = fields.find((f) => isContext(f, 2));
            return issuer !== undefined && childrenOf(bytes, issuer).filter((n) => isContext(n, 4)).length > 1;
        }));
    },

    '4.2.1.14-inhibit-any-policy-critical': mustBe('2.5.29.54', true),

    '4.2.1.15-freshest-crl-not-critical': mustBe('2.5.29.46', false),

    '4.2.2.1-aia-not-critical': mustBe('1.3.6.1.5.5.7.1.1', false),

    '4.2.2.1-ldap-uri-dn-and-attributes': (_der, tbs) => {
        const ldap = accessLocations(ext(tbs, '1.3.6.1.5.5.7.1.1'), '1.3.6.1.5.5.7.48.2').uris.map(ldapParts).filter((p) => p !== null);
        return judge(ldap.length > 0, ldap.some((p) => !p.dn || !p.attributes));
    },

    '4.2.2.1-ca-issuers-http-or-ldap': (_der, tbs) => {
        const { listed, uris } = accessLocations(ext(tbs, '1.3.6.1.5.5.7.1.1'), '1.3.6.1.5.5.7.48.2');
        return judge(listed, !uris.some(httpOrLdap));
    },

    '4.2.2.2-sia-not-critical': mustBe('1.3.6.1.5.5.7.1.11', false),

    '4.2.2.2-ldap-uri-dn-and-attributes': (_der, tbs) => {
        const ldap = accessLocations(ext(tbs, '1.3.6.1.5.5.7.1.11'), '1.3.6.1.5.5.7.48.5').uris.map(ldapParts).filter((p) => p !== null);
        return judge(ldap.length > 0, ldap.some((p) => !p.dn || !p.attributes));
    },

    '4.2.2.2-ca-repository-http-or-ldap': (_der, tbs) => {
        const { listed, uris } = accessLocations(ext(tbs, '1.3.6.1.5.5.7.1.11'), '1.3.6.1.5.5.7.48.5');
        return judge(listed, !uris.some(httpOrLdap));
    },
};

/**
 * Evaluate every clause against one certificate.
 *
 * A clause that throws while reading a structurally broken certificate is
 * `not-applicable`, not a failure: L1 already decides whether those bytes
 * parse at all, and a checker that reported "clause violated" for a
 * certificate nobody can read would be attributing the wrong thing.
 *
 * @param der A complete Certificate.
 * @returns One verdict per clause id.
 */
export function evaluateClauses(der: Uint8Array): Map<string, Verdict> {
    const out = new Map<string, Verdict>();
    let tbs: Tbs;
    try {
        tbs = readTbs(der);
    } catch {
        for (const clause of CLAUSES) out.set(clause.id, NA);
        return out;
    }
    for (const clause of CLAUSES) {
        const evaluate = EVALUATORS[clause.id];
        if (evaluate === undefined) {
            throw new Error(`rfc5280-clauses: the clause table declares ${clause.id} and this file has no evaluator for it`);
        }
        try {
            out.set(clause.id, evaluate(der, tbs));
        } catch {
            out.set(clause.id, NA);
        }
    }
    return out;
}

/** Every clause id this file can evaluate — the completeness rule reads it. */
export const EVALUATED_CLAUSE_IDS: readonly string[] = Object.keys(EVALUATORS).sort();
