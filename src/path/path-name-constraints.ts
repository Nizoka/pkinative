/**
 * pkinative — RFC 5280 name constraints
 * =====================================
 * The check whose absence is the classic cross-signing attack: a CA
 * constrained to `.example.com` issuing for `bank.example` and nobody
 * noticing. §6.1.4 (g) accumulates the constraints walking down the path,
 * §6.1.3 (b) and (c) test each certificate against what has accumulated.
 *
 * Four things about the shape, each of which matters more than it looks:
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
 * **Exclusion is tested at least as broadly as permission.** A directoryName
 * is compared by encoded bytes (ADR 0005), and for a permitted subtree a miss
 * is a refusal. For an excluded one a miss is an acceptance, so an exclusion
 * also matches after RFC 5280 §7.1 preparation: re-spelling a name in another
 * case or string type does not escape it.
 *
 * ## Three ways a name escapes a constraint, and none of them is a match
 *
 * Every one of these was found by scoring x509-limbo, and each let a
 * constrained CA issue a name its issuer had withheld:
 *
 * **A malformed name is not inside the permitted namespace.** `.example.com`
 * is not a host name, and `invalid@address@example.com` is not a mailbox.
 * §6.1.3 (b) says every name MUST be *located within* the permitted subtrees,
 * and a name that cannot be located is not within them. Suffix-matching such a
 * name against `example.com` says "permitted", which is how a CA constrained to
 * one domain issues for a name no parser agrees on (CWE-436).
 *
 * **A wildcard is a set, not a string.** `*.example.com` denotes every
 * single-label host under `example.com`, so an exclusion of
 * `bar.example.com` — one of its members — must refuse it, and a permission
 * must cover the whole set rather than one spelling of it. Comparing the
 * literal text `*.example.com` finds neither. This is CVE-2025-61727.
 *
 * **A constraint on a form this module does not process must refuse, not be
 * ignored.** §4.2.1.10 is explicit: an implementation either processes every
 * constrained form or rejects the certificate. Skipping an `otherName`
 * constraint silently is answering "unconstrained" to a CA that said
 * "forbidden".
 *
 * @module path/path-name-constraints
 */

import { toHex } from '../core/bytes.js';
import type { Asn1StringType } from '../types/asn1-types.js';
import type { AttributeTypeAndValue, DistinguishedName, GeneralName, GeneralSubtree, RelativeDistinguishedName } from '../types/x509-types.js';

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
    /**
     * `GeneralName.kind`s some CA constrained and this module does not process
     * — `otherName`, `x400Address`, `ediPartyName`, `registeredID`.
     *
     * RFC 5280 §4.2.1.10 leaves no third option: *"If a name constraints
     * extension that is marked as critical imposes constraints on a particular
     * name form, and an instance of that name form appears in the subject field
     * or subjectAltName extension of a subsequent certificate, then the
     * application MUST either process the constraint or reject the
     * certificate."* Ignoring the constraint answers "unconstrained" to a CA
     * that said "forbidden", so the kind is remembered here and a name of that
     * kind is refused below.
     */
    readonly unprocessed: Set<string>;
}

/** A state with no constraint at all — the value §6.1.2 starts from. */
export function initialNameConstraints(): NameConstraintState {
    const permitted = {} as Record<ConstrainedForm, GeneralSubtree[] | null>;
    const excluded = {} as Record<ConstrainedForm, GeneralSubtree[]>;
    for (const form of FORMS) {
        permitted[form] = null;
        excluded[form] = [];
    }
    return { permitted, excluded, unprocessed: new Set<string>() };
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
export function dnsConstraintCovers(constraint: string, name: string): boolean {
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
 * §4.2.1.10, uniformResourceIdentifier: the constraint applies to the **host**
 * of the URI, and — unlike a dNSName constraint — a constraint that does not
 * begin with a period **specifies one host, not a domain**.
 *
 * The RFC spells out the asymmetry: *"When the constraint does not begin with a
 * period, it specifies a host."* So `example.com` as a dNSName constraint
 * permits `sub.example.com`, and the same string as a URI constraint does not.
 * Routing URIs through the dNSName rule — which this function did until
 * x509-limbo scored it — lets a CA constrained to one host issue for every
 * subdomain of it.
 *
 * The host is taken by cutting the string, not by parsing a URL. A URI whose
 * authority this cannot find is refused rather than accepted: a constraint
 * that cannot be evaluated is not a constraint that is satisfied.
 */
export function uriMatches(constraint: string, uri: string): boolean {
    const host = uriHost(uri);
    if (host === null) return false;
    const c = fold(constraint);
    const h = fold(host);
    if (c === '') return true;
    if (c.startsWith('.')) return h.endsWith(c);
    return h === c;
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
 * tell them apart would be the place to attack. That is the whole rule for a
 * **permitted** subtree, where a miss is a refusal; an **excluded** subtree is
 * also tested after §7.1 preparation (`directoryMatchesPrepared`), because
 * there a miss is an acceptance (ADR 0005).
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

// ── Excluded directoryName subtrees: §7.1 preparation, fail-closed ───

/**
 * The string types whose decoded text is compared after preparation: the five
 * DirectoryString choices of RFC 5280 Appendix A, and IA5String, which carries
 * `domainComponent` and `emailAddress`. A value of any other type — or one the
 * name reader kept undecoded — is compared by its encoding only.
 */
const PREPARED_STRING_TYPES: ReadonlySet<Asn1StringType> = /*#__PURE__*/ new Set<Asn1StringType>(['printable', 'utf8', 'teletex', 'bmp', 'universal', 'ia5']);

/**
 * RFC 4518 §2.2 maps these to SPACE before §2.6.1 decides which spaces are
 * insignificant: the C0 whitespace controls, NEXT LINE, and every separator.
 */
const MAPPED_TO_SPACE = /[\t\n\v\f\r\u0085\p{Zs}\u2028\u2029]+/gu;

/**
 * A character string prepared for an equality test after RFC 4518, as RFC 5280
 * §7.1 asks: compatibility-normalised (NFKC), case folded, and with
 * insignificant spaces removed (§2.6.1 — leading and trailing spaces dropped,
 * every internal run of them one space).
 *
 * The fold is `toUpperCase().toLowerCase()`, re-normalised: locale-independent
 * in JavaScript, and the round trip reaches one form from both cases of the
 * characters that do not fold one-to-one (`ß` and `SS` both become `ss`). It
 * is not RFC 3454 table B.2 to the letter, and the rest is not RFC 4518 to the
 * letter either: no character is prohibited, and none is mapped to nothing.
 * Where that makes two strings equal that a strict §7.1 validator keeps apart,
 * the result is one more exclusion; where it keeps apart two strings §7.1
 * would equate, the result is what byte comparison already answered, which the
 * caller tests first. This function is only ever consulted to **add** an
 * exclusion, so any imprecision here errs toward refusal.
 */
function _prepareString(text: string): string {
    const folded = text.normalize('NFKC').toUpperCase().toLowerCase().normalize('NFKC');
    return folded.replace(MAPPED_TO_SPACE, ' ').replace(/^ | $/g, '');
}

/**
 * One attribute as a comparison key: its type and its prepared value, or its
 * type and its encoding when the value is not a string this module prepares.
 * The two prefixes differ, so a prepared value never equals an encoding.
 */
function _attributeKey(attribute: AttributeTypeAndValue): string {
    const value = attribute.value;
    return value !== undefined && PREPARED_STRING_TYPES.has(value.stringType)
        ? `p:${attribute.type}:${_prepareString(value.value)}`
        : `b:${attribute.type}:${toHex(attribute.valueDer)}`;
}

/**
 * Two RDNs equal after preparation: the same attribute types, each value equal
 * after `_prepareString`, and a multi-valued RDN compared **as the set** X.501
 * makes it, so an issuer that emitted its SET OF out of DER order still
 * matches. Sorting the keys compares the two multisets in n log n.
 */
function _samePreparedRdn(a: RelativeDistinguishedName, b: RelativeDistinguishedName): boolean {
    if (a.length !== b.length) return false;
    const left = a.map(_attributeKey).sort();
    const right = b.map(_attributeKey).sort();
    return left.every((key, i) => key === right[i]);
}

/**
 * §4.2.1.10 directoryName under the RFC 5280 §7.1 comparison: the constraint
 * is a prefix of the name's RDN sequence, RDN by RDN, after preparation.
 *
 * **For excluded subtrees only, and only in addition to `directoryMatches`.**
 * Byte comparison (ADR 0005) errs toward refusal everywhere except in an
 * exclusion: a name that does not byte-match an excluded subtree is a name
 * *not excluded*, so `CN=Excluded` would escape an exclusion of `CN=excluded`,
 * and a UTF8String subject would escape the same name excluded as a
 * PrintableString. Testing both comparisons can only add exclusions, which
 * is the fail-closed direction; permitted subtrees stay byte-exact, where a
 * miss is a refusal.
 *
 * Every array walked here came out of the name reader, which bounds the
 * attributes of each name by `maxNameAttributes`; every string is bounded by
 * the input it was decoded from.
 *
 * @param constraint The excluded subtree's name.
 * @param name       The name under test.
 * @returns Whether the constraint is a prefix of the name after preparation.
 */
export function directoryMatchesPrepared(constraint: DistinguishedName, name: DistinguishedName): boolean {
    if (constraint.rdns.length > name.rdns.length) return false;
    return constraint.rdns.every((rdn, i) => _samePreparedRdn(rdn, name.rdns[i] as RelativeDistinguishedName));
}

/**
 * Whether an **excluded** subtree covers a name: `subtreeCovers`, and for a
 * directoryName the prepared comparison as well. Never used for a permitted
 * subtree, nor for the intersection of permitted subtrees.
 *
 * @param subtree The excluded subtree.
 * @param name    The name under test.
 * @returns Whether the exclusion applies to the name.
 */
export function excludedCovers(subtree: GeneralSubtree, name: GeneralName): boolean {
    if (subtreeCovers(subtree, name)) return true;
    const base = subtree.base;
    // The same refusal of a minimum or a maximum as `subtreeCovers` makes.
    if (subtree.minimum !== 0 || subtree.maximum !== undefined) return false;
    return base.kind === 'directoryName' && name.kind === 'directoryName' && directoryMatchesPrepared(base.name, name.name);
}

// ── Well-formedness: a name that cannot be located is not inside ─────

/**
 * Whether a name is well enough formed to be *located* within a namespace.
 *
 * §6.1.3 (b) requires every name to be **within** the permitted subtrees. A
 * name that no two parsers would read the same way is not within anything, and
 * suffix-matching it anyway is the permissive mistake: `.example.com` ends with
 * `example.com`, so a constraint permitting that domain would accept a name
 * that is not a host name at all.
 *
 * Only the forms this module constrains are judged, and only for the shapes
 * §4.2.1.10 relies on — an empty label, a missing or repeated `@`, an address
 * of the wrong width. This is not a hostname validator: it answers whether the
 * matching rules below can be trusted on this string, and nothing more.
 *
 * @param name The name under test.
 * @returns Whether the matching rules can be applied to it.
 */
export function wellFormedName(name: GeneralName): boolean {
    switch (name.kind) {
        case 'dNSName':
            return _wellFormedHost(name.value);
        case 'rfc822Name': {
            const at = name.value.indexOf('@');
            // Exactly one `@`, a non-empty local part, and a host that is a
            // host: `invalid@address@example.com` is not a mailbox, and reading
            // only the last `@` makes it look like one on `example.com`.
            return at > 0 && name.value.indexOf('@', at + 1) < 0 && _wellFormedHost(name.value.slice(at + 1));
        }
        case 'uniformResourceIdentifier': {
            const host = uriHost(name.value);
            return host !== null && (host.startsWith('[') || _wellFormedHost(host));
        }
        case 'iPAddress':
            return name.bytes.length === 4 || name.bytes.length === 16;
        default:
            // A directoryName is compared on encoded RDNs, which have no
            // malformed spelling: the decoder either produced a name or threw.
            return true;
    }
}

/**
 * No empty label, and **no trailing dot**.
 *
 * A trailing dot is a query-time spelling of an absolute name; in a certificate
 * it is outside the preferred name syntax RFC 5280 §4.2.1.6 asks for, and the
 * matching rules do not strip it. Calling it well formed would leave a name that
 * silently matches no constraint, which reads as "unconstrained" — so it is
 * refused where a constraint applies, and diagnosed at parse time where none
 * does.
 */
function _wellFormedHost(host: string): boolean {
    if (host === '' || host.endsWith('.')) return false;
    return host.split('.').every((label) => label !== '');
}

// ── Wildcards: a name that denotes a set (§4.2.1.10 against RFC 9525) ─

/**
 * What a starred name denotes: the domain below every starred label, and how
 * many labels the stars stand in for. `null` when there is no star.
 *
 * Any star counts, not only a leading `*.`: `w*.example.com` denotes every host
 * under `example.com` whose label begins with `w`, and a matcher lenient enough
 * to honour a partial wildcard could expand it onto an excluded name. Treating
 * the whole label as unknown over-approximates the set, which is the safe
 * direction — the over-approximation can only refuse, never permit.
 */
function _starredSet(value: string): { readonly parent: string; readonly labels: number } | null {
    if (!value.includes('*')) return null;
    const labels = fold(value).split('.');
    let last = -1;
    for (const [index, label] of labels.entries()) if (label.includes('*')) last = index;
    const parent = labels.slice(last + 1).join('.');
    return _wellFormedHost(parent) ? { parent, labels: last + 1 } : null;
}

/**
 * Whether a dNSName subtree **covers every name** a starred name denotes.
 *
 * True when the subtree covers the parent domain, because a subtree that covers
 * a domain covers everything below it. This is the question permission asks:
 * accepting a starred name grants every name it denotes, so one member being
 * permitted is not enough.
 *
 * @param base   The constraint's dNSName.
 * @param parent The starred name's parent domain, already folded.
 * @returns Whether the subtree contains the whole set.
 */
export function subtreeCoversWildcard(base: string, parent: string): boolean {
    const b = fold(base);
    if (b === '') return true;
    // A leading period names what is strictly below: it covers the whole set
    // when the parent is at or below that domain, since every member sits one
    // further label down.
    if (b.startsWith('.')) return parent === b.slice(1) || parent.endsWith(b);
    return dnsConstraintCovers(b, parent);
}

/**
 * Whether a dNSName subtree **intersects** the set a starred name denotes.
 *
 * `*.example.com` is every single-label host under `example.com`. An exclusion
 * of `bar.example.com` names one of its members, so the starred name must be
 * refused even though the two strings do not match — CVE-2025-61727, and the
 * reason this function exists rather than a string comparison.
 *
 * The set meets the subtree when the subtree covers the whole set, **or** when
 * the subtree's base is itself a member: as many labels below the parent as
 * there are starred labels, and not a leading-period base, which denotes only
 * what lies further below and so holds no member of its own.
 *
 * @param base   The constraint's dNSName.
 * @param parent The starred name's parent domain, already folded.
 * @param labels How many labels the stars stand in for.
 * @returns Whether some name the starred name denotes falls inside the subtree.
 */
export function wildcardMeetsSubtree(base: string, parent: string, labels = 1): boolean {
    if (subtreeCoversWildcard(base, parent)) return true;
    const b = fold(base);
    if (b.startsWith('.') || !b.endsWith(`.${parent}`)) return false;
    return b.slice(0, b.length - parent.length - 1).split('.').length === labels;
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
        case 'dNSName': return name.kind === 'dNSName' && dnsConstraintCovers(base.value, name.value);
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
            if (form === null) {
                state.unprocessed.add(subtree.base.kind);
                continue;
            }
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
        if (form === null) {
            state.unprocessed.add(subtree.base.kind);
            continue;
        }
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
    if (form === null) {
        // §4.2.1.10: process every constrained form or reject. A CA constrained
        // this form and this module cannot evaluate it, so the answer is no —
        // never "unconstrained", which is what skipping it would say.
        return state.unprocessed.has(name.kind)
            ? { form: 'directoryName', text: `${name.kind} — a constrained name form this validator does not process`, why: 'not-permitted' }
            : null;
    }
    const text = nameText(name);
    const constrained = state.permitted[form] !== null || state.excluded[form].length > 0;

    // A starred name denotes a set, so both questions are about the set: any
    // member inside an exclusion refuses it, and permission must cover every
    // member. A subtree carrying a minimum or a maximum is skipped for the same
    // reason `subtreeCovers` refuses it — §4.2.1.10 fixes minimum to 0 and
    // forbids maximum, so such a subtree is not one this code can honour.
    const set = name.kind === 'dNSName' ? _starredSet(name.value) : null;
    if (set !== null) {
        const usable = (subtree: GeneralSubtree): boolean =>
            subtree.base.kind === 'dNSName' && subtree.minimum === 0 && subtree.maximum === undefined;
        for (const subtree of state.excluded[form]) {
            if (usable(subtree) && wildcardMeetsSubtree((subtree.base as { value: string }).value, set.parent, set.labels)) {
                return { form, text, why: 'excluded' };
            }
        }
        const permitted = state.permitted[form];
        if (permitted === null) return null;
        const whole = permitted.some((subtree) => usable(subtree)
            && subtreeCoversWildcard((subtree.base as { value: string }).value, set.parent));
        return whole ? null : { form, text, why: 'not-permitted' };
    }

    // A malformed name is not located within any namespace. Only reported when
    // some CA did constrain the form: §6 judges relations, and the syntax of a
    // name nobody constrained is a profile concern the parser already diagnosed.
    if (constrained && !wellFormedName(name)) return { form, text, why: 'not-permitted' };

    // Exclusion alone also compares directoryNames after §7.1 preparation:
    // `excludedCovers` says why that asymmetry is the fail-closed one.
    for (const subtree of state.excluded[form]) {
        if (excludedCovers(subtree, name)) return { form, text, why: 'excluded' };
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
