/**
 * pkinative — RFC 5280 name constraints
 * =====================================
 * The check whose absence is the classic cross-signing attack: a CA
 * constrained to `.example.com` issuing for `bank.example` and nobody
 * noticing. §6.1.4 (g) accumulates the constraints walking down the path,
 * §6.1.3 (b) and (c) test each certificate against what has accumulated.
 *
 * Three things about the shape, each of which matters more than it looks:
 *
 * **The state is per name form, not one list.** RFC 5280 §6.1.4 (g)(1)
 * intersects permitted subtrees *within each form* and leaves the others
 * alone. Keeping one list and filtering by kind at comparison time gets the
 * intersection wrong the moment two CAs constrain different forms, which is
 * exactly the case a hierarchy with an email-only sub-CA produces.
 *
 * **An empty permitted set for a form means "nothing is permitted", and an
 * absent one means "no opinion".** `null` and `[]` are different answers, and
 * collapsing them is how a validator either refuses everything or permits
 * everything. §6.1.4 (g)(1) is explicit: an intersection that comes out empty
 * makes the form unusable, and every certificate carrying that form is
 * refused from then on.
 *
 * **Matching is textual and by suffix, never by parsing a hostname.** The
 * rules in §4.2.1.10 are byte rules on a lowercased form, and a validator
 * that normalised through URL parsing would inherit whatever that parser
 * thinks about trailing dots, IDNA and userinfo — which is how name
 * constraint bypasses get written.
 *
 * @module path/path-name-constraints
 */

import type { DistinguishedName, GeneralName, GeneralSubtree, RelativeDistinguishedName } from '../types/x509-types.js';

/** The name forms this module constrains. Every other form is opaque here. */
export type ConstrainedForm = 'dNSName' | 'rfc822Name' | 'uniformResourceIdentifier' | 'iPAddress' | 'directoryName';

const FORMS: readonly ConstrainedForm[] = ['dNSName', 'rfc822Name', 'uniformResourceIdentifier', 'iPAddress', 'directoryName'];

/**
 * What has accumulated walking down the path.
 *
 * `permitted[form] === null` means no CA has restricted that form yet;
 * `permitted[form] === []` means the intersection came out empty and nothing
 * of that form is acceptable any more.
 */
export interface NameConstraintState {
    permitted: Record<ConstrainedForm, GeneralSubtree[] | null>;
    excluded: Record<ConstrainedForm, GeneralSubtree[]>;
}

/** A state with no constraint at all — the value §6.1.2 starts from. */
export function initialNameConstraints(): NameConstraintState {
    const permitted = {} as Record<ConstrainedForm, GeneralSubtree[] | null>;
    const excluded = {} as Record<ConstrainedForm, GeneralSubtree[]>;
    for (const form of FORMS) {
        permitted[form] = null;
        excluded[form] = [];
    }
    return { permitted, excluded };
}

/** The form a subtree's base constrains, or null when this module has no rule for it. */
function formOf(base: GeneralName): ConstrainedForm | null {
    return FORMS.includes(base.kind as ConstrainedForm) ? base.kind as ConstrainedForm : null;
}

// ── Matching, one function per form (RFC 5280 §4.2.1.10) ─────────────

/** Case-folded, and only over ASCII: a name constraint is not a locale. */
const fold = (text: string): string => text.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

/**
 * §4.2.1.10, dNSName: *"the constraint `example.com` is satisfied by both
 * `host.example.com` and `example.com`"*, and a constraint beginning with a
 * dot matches only below it.
 *
 * The left boundary is checked on a **label**, never on a substring: without
 * that, the constraint `example.com` would match `notexample.com`, which is
 * the whole attack.
 */
export function dnsMatches(constraint: string, name: string): boolean {
    const c = fold(constraint);
    const n = fold(name);
    if (c === '') return true; // An empty constraint matches every name of the form.
    if (c.startsWith('.')) return n.endsWith(c);
    return n === c || n.endsWith(`.${c}`);
}

/**
 * §4.2.1.10, rfc822Name: a full mailbox matches itself; a bare host matches
 * every mailbox at that host; a host beginning with a dot matches every
 * mailbox below it.
 */
export function emailMatches(constraint: string, name: string): boolean {
    const c = fold(constraint);
    const n = fold(name);
    if (c === '') return true;
    const at = n.lastIndexOf('@');
    if (c.includes('@')) return n === c;
    const host = at >= 0 ? n.slice(at + 1) : n;
    if (c.startsWith('.')) return host.endsWith(c);
    return host === c;
}

/**
 * §4.2.1.10, uniformResourceIdentifier: the constraint applies to the
 * **host** of the URI, by the dNSName rules.
 *
 * The host is taken by cutting the string, not by parsing a URL. A URI whose
 * authority this cannot find is refused rather than accepted: a constraint
 * that cannot be evaluated is not a constraint that is satisfied.
 */
export function uriMatches(constraint: string, uri: string): boolean {
    const host = uriHost(uri);
    if (host === null) return false;
    return dnsMatches(constraint, host);
}

/** The host of a URI, or null when there is no authority to constrain. */
export function uriHost(uri: string): string | null {
    const schemeEnd = uri.indexOf('://');
    if (schemeEnd < 0) return null;
    let authority = uri.slice(schemeEnd + 3);
    for (const stop of ['/', '?', '#']) {
        const at = authority.indexOf(stop);
        if (at >= 0) authority = authority.slice(0, at);
    }
    // Drop userinfo, then a port. An IPv6 literal keeps its brackets, which
    // never match a dNSName constraint and must not be split on its colons.
    const at = authority.lastIndexOf('@');
    if (at >= 0) authority = authority.slice(at + 1);
    if (authority.startsWith('[')) {
        // An IPv6 literal keeps its brackets and must not be split on its own
        // colons — but the port after the closing bracket still goes.
        const close = authority.indexOf(']');
        if (close < 0) return null;
        authority = authority.slice(0, close + 1);
    } else {
        const colon = authority.indexOf(':');
        if (colon >= 0) authority = authority.slice(0, colon);
    }
    return authority === '' ? null : authority;
}

/**
 * §4.2.1.10, iPAddress: the constraint is an address followed by a mask of
 * the same width, and the address matches when every masked bit agrees.
 *
 * A width mismatch is **not** a match: an IPv4 name against an IPv6
 * constraint is outside that constraint, not inside it.
 */
export function ipMatches(constraintBytes: Uint8Array, nameBytes: Uint8Array): boolean {
    const width = nameBytes.length;
    if (constraintBytes.length !== width * 2) return false;
    for (let i = 0; i < width; i += 1) {
        const mask = constraintBytes[width + i] as number;
        if (((nameBytes[i] as number) & mask) !== ((constraintBytes[i] as number) & mask)) return false;
    }
    return true;
}

/**
 * §4.2.1.10, directoryName: the constraint matches when it is a **prefix of
 * the RDN sequence**, compared RDN by RDN on the encoded bytes.
 *
 * Encoded bytes rather than rendered text, for the reason every name
 * comparison in this library uses them: two names that print the same and
 * encode differently are two names, and a constraint checker that could not
 * tell them apart would be the place to attack.
 */
export function directoryMatches(constraint: DistinguishedName, name: DistinguishedName): boolean {
    if (constraint.rdns.length > name.rdns.length) return false;
    // `entries()` rather than an index, so there is no `undefined` case to
    // guard and no unreachable branch to justify: the iterator only yields
    // elements that exist, and `name.rdns[i]` is in range because the length
    // check above says so.
    return constraint.rdns.every((rdn, i) => _sameRdn(rdn, name.rdns[i] as RelativeDistinguishedName));
}

function _sameRdn(a: RelativeDistinguishedName, b: RelativeDistinguishedName): boolean {
    if (a.length !== b.length) return false;
    return a.every((x, i) => {
        const y = b[i] as RelativeDistinguishedName[number];
        return x.type === y.type && x.valueDer.length === y.valueDer.length && x.valueDer.every((byte, k) => byte === y.valueDer[k]);
    });
}

/**
 * Whether one subtree covers one name. Both must be the same form; a
 * different form is not covered, which is what makes the per-form state
 * above the right structure.
 *
 * @param subtree The constraint.
 * @param name    The name under test.
 * @returns Whether the constraint covers the name.
 */
export function subtreeCovers(subtree: GeneralSubtree, name: GeneralName): boolean {
    const base = subtree.base;
    if (base.kind !== name.kind) return false;
    // RFC 5280 §4.2.1.10 fixes minimum to 0 and forbids maximum. A subtree
    // asserting otherwise is not a subtree this code can honour, and saying
    // "covered" would be the permissive mistake.
    if (subtree.minimum !== 0 || subtree.maximum !== undefined) return false;
    switch (base.kind) {
        case 'dNSName': return name.kind === 'dNSName' && dnsMatches(base.value, name.value);
        case 'rfc822Name': return name.kind === 'rfc822Name' && emailMatches(base.value, name.value);
        case 'uniformResourceIdentifier': return name.kind === 'uniformResourceIdentifier' && uriMatches(base.value, name.value);
        case 'iPAddress': return name.kind === 'iPAddress' && ipMatches(base.bytes, name.bytes);
        case 'directoryName': return name.kind === 'directoryName' && directoryMatches(base.name, name.name);
        default: return false;
    }
}

// ── §6.1.4 (g) — accumulating down the path ─────────────────────────

/**
 * Fold one certificate's `nameConstraints` into the walk's state.
 *
 * Permitted subtrees **intersect** per form, and the intersection is
 * conservative: a subtree survives only if some existing subtree of the same
 * form covers it, or if the form had no opinion yet. Excluded subtrees
 * **union**, because an exclusion anywhere on the path is an exclusion.
 *
 * @param state    The walk's state, updated in place.
 * @param permitted The certificate's `permittedSubtrees`, or undefined.
 * @param excluded  The certificate's `excludedSubtrees`, or undefined.
 * @returns Nothing; `state` carries the result.
 */
export function accumulateNameConstraints(
    state: NameConstraintState,
    permitted: readonly GeneralSubtree[] | undefined,
    excluded: readonly GeneralSubtree[] | undefined,
): void {
    if (permitted !== undefined) {
        const byForm = new Map<ConstrainedForm, GeneralSubtree[]>();
        for (const subtree of permitted) {
            const form = formOf(subtree.base);
            if (form === null) continue;
            byForm.set(form, [...(byForm.get(form) ?? []), subtree]);
        }
        for (const [form, subtrees] of byForm) {
            const existing = state.permitted[form];
            if (existing === null) {
                state.permitted[form] = subtrees;
                continue;
            }
            // The intersection: keep a new subtree only where an existing one
            // already covers it. Narrowing only, never widening — a sub-CA
            // cannot grant itself names its issuer withheld.
            state.permitted[form] = subtrees.filter((subtree) => existing.some((outer) => subtreeCovers(outer, subtree.base)));
        }
    }
    for (const subtree of excluded ?? []) {
        const form = formOf(subtree.base);
        if (form === null) continue;
        state.excluded[form] = [...state.excluded[form], subtree];
    }
}

// ── §6.1.3 (b), (c) — testing one certificate ───────────────────────

/** Why a name is outside the constraints. `null` when it is inside them. */
export type NameVerdict = { readonly form: ConstrainedForm; readonly text: string; readonly why: 'excluded' | 'not-permitted' } | null;

/**
 * Test one GeneralName against the accumulated state.
 *
 * Exclusion wins over permission, as §6.1.3 (c) requires: a name that is both
 * permitted and excluded is excluded, and checking permission first would
 * make the order of two CAs' constraints decide the answer.
 *
 * @param state The accumulated constraints.
 * @param name  The name under test.
 * @returns The verdict, or null when the name is acceptable.
 */
export function checkName(state: NameConstraintState, name: GeneralName): NameVerdict {
    const form = formOf(name);
    if (form === null) return null; // No rule here for this form.
    const text = nameText(name);
    for (const subtree of state.excluded[form]) {
        if (subtreeCovers(subtree, name)) return { form, text, why: 'excluded' };
    }
    const permitted = state.permitted[form];
    if (permitted === null) return null;
    if (permitted.some((subtree) => subtreeCovers(subtree, name))) return null;
    return { form, text, why: 'not-permitted' };
}

/** A name in the one spelling the report quotes. */
export function nameText(name: GeneralName): string {
    switch (name.kind) {
        case 'dNSName':
        case 'rfc822Name':
        case 'uniformResourceIdentifier':
            return name.value;
        case 'iPAddress':
            return name.address;
        case 'directoryName':
            return `directoryName with ${String(name.name.rdns.length)} RDN(s)`;
        default:
            return name.kind;
    }
}
