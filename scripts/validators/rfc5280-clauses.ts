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
