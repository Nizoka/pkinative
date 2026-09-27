/**
 * pkinative — RFC 5280 certificate policy processing
 * ==================================================
 * The `valid_policy_tree` of §6.1, and the three counters that decide whether
 * anyone has to care about it. This is the hardest part of RFC 5280, and most
 * of the difficulty is in the data structure rather than the rules.
 *
 * **Flat levels, children by index, no parent pointers, and nothing is ever
 * removed — only marked dead.** That one decision makes tractable the three
 * operations that break every naive design:
 *
 *   - *"prune the nodes with no children"* (§6.1.3 (d)(2), §6.1.4 (a)) is a
 *     single backward pass over the levels, because a node's children are
 *     right there as indices and a dead child is just a dead entry;
 *   - *"the nodes at depth i"* is `levels[i]`, an index rather than a walk;
 *   - `maxPolicyNodes` is a counter over live entries, checked where they are
 *     created — and the policy tree is the part of §6 that actually explodes
 *     combinatorially, which is why x509-limbo has cases written for it.
 *
 * A design that spliced nodes out of arrays would invalidate every index it
 * had just handed out. Marking instead of compacting costs a boolean and buys
 * stable indices for the whole walk.
 *
 * **What this module does not do is interpret a qualifier.** Qualifiers are
 * carried through the tree because §6.1.5 (b) returns them, and a CPS URI or
 * a user notice is for a human to read. Acting on one would be inventing
 * policy.
 *
 * @module path/path-policies
 */

import type { PolicyInformation, PolicyMapping, PolicyQualifier } from '../types/x509-types.js';

/** `anyPolicy`, RFC 5280 §4.2.1.4. */
export const ANY_POLICY = '2.5.29.32.0';

/**
 * One node of the `valid_policy_tree`.
 *
 * `children` are indices into the **next** level. `alive` is how pruning
 * works without moving anything: a pruned node stays in place so that every
 * index already handed out keeps pointing at what it pointed at.
 */
export interface PolicyNode {
    readonly validPolicy: string;
    readonly qualifiers: readonly PolicyQualifier[];
    /** `expected_policy_set`: the policies of the child certificate that map here. */
    expectedPolicySet: string[];
    children: number[];
    alive: boolean;
}

/**
 * `valid_policy_tree`, plus the three counters §6.1.2 initialises and
 * §6.1.4 decrements.
 *
 * `levels` is `null` when the tree has been set to NULL — §6.1.3 (e), a
 * certificate with no `certificatePolicies` kills it — which is a different
 * state from an empty tree and must not be confused with one.
 */
export interface PolicyState {
    levels: PolicyNode[][] | null;
    explicitPolicy: number;
    policyMapping: number;
    inhibitAnyPolicy: number;
    /** Live nodes created so far, for `maxPolicyNodes`. */
    nodeCount: number;
}

/**
 * §6.1.2 (a)–(e): the tree starts as a single `anyPolicy` node, and each
 * counter starts at `n + 1` unless the caller asked for it to be on from the
 * start.
 *
 * `user-initial-policy-set` is **not** a parameter here: §6.1.5 (g) is where
 * the intersection happens, and applying it at initialisation would prune a
 * branch a later policy mapping was going to rename into the set.
 *
 * @param n               The number of certificates in the path.
 * @param requireExplicit `initial-explicit-policy`.
 * @param inhibitMapping  `initial-policy-mapping-inhibit`.
 * @param inhibitAny      `initial-any-policy-inhibit`.
 * @returns The initial state.
 */
export function initialPolicyState(
    n: number,
    requireExplicit: boolean,
    inhibitMapping: boolean,
    inhibitAny: boolean,
): PolicyState {
    const root: PolicyNode = {
        validPolicy: ANY_POLICY,
        qualifiers: [],
        expectedPolicySet: [ANY_POLICY],
        children: [],
        alive: true,
    };
    return {
        levels: [[root]],
        explicitPolicy: requireExplicit ? 0 : n + 1,
        policyMapping: inhibitMapping ? 0 : n + 1,
        inhibitAnyPolicy: inhibitAny ? 0 : n + 1,
        nodeCount: 1,
    };
}

const live = (level: readonly PolicyNode[]): PolicyNode[] => level.filter((node) => node.alive);

/**
 * The deepest level, or null when the tree is NULL.
 *
 * `levels` is never an empty array: it is created with one level and from then
 * on only grows or becomes `null`, so the last element always exists. Saying
 * that with a cast rather than a `?? null` keeps an unreachable branch out of
 * the coverage report instead of justifying one.
 */
function deepest(state: PolicyState): PolicyNode[] | null {
    return state.levels === null ? null : state.levels[state.levels.length - 1] as PolicyNode[];
}

/**
 * §6.1.3 (d)(2) and §6.1.4 (a): drop every node with no live child, working
 * from the leaves upwards, and set the tree to NULL when the root dies.
 *
 * Upwards is the only order that terminates in one pass: removing a node at
 * depth *i* can orphan its parent at *i − 1*, never the other way round.
 */
export function prunePolicyTree(state: PolicyState): void {
    const levels = state.levels;
    if (levels === null) return;
    for (let depth = levels.length - 2; depth >= 0; depth -= 1) {
        const level = levels[depth] as PolicyNode[];
        const below = levels[depth + 1] as PolicyNode[];
        for (const node of level) {
            if (!node.alive) continue;
            node.children = node.children.filter((index) => below[index]?.alive === true);
            if (node.children.length === 0) node.alive = false;
        }
    }
    if (live(levels[0] as PolicyNode[]).length === 0) state.levels = null;
}

/** How many live nodes the tree holds — the number `maxPolicyNodes` bounds. */
export function countPolicyNodes(state: PolicyState): number {
    return state.levels === null ? 0 : state.levels.reduce((total, level) => total + live(level).length, 0);
}

/**
 * §6.1.3 (d)(1): grow the tree by one level from one certificate's
 * `certificatePolicies`.
 *
 * Two rules do the work, and the second is the one implementations get wrong.
 * A policy *P* becomes a child of every node whose `expected_policy_set`
 * contains *P*. If **no** node matched and some node's set contains
 * `anyPolicy`, *P* becomes a child of that node instead — that fallback is
 * what lets a CA that asserted `anyPolicy` still validate a specific policy
 * below it, and omitting it refuses most real hierarchies.
 *
 * @param state    The walk's policy state.
 * @param policies The certificate's `certificatePolicies`.
 * @param maxNodes The `maxPolicyNodes` bound.
 * @returns `'ok'`, or `'limit'` when the bound stopped the growth.
 */
export function growPolicyTree(state: PolicyState, policies: readonly PolicyInformation[], maxNodes: number): 'ok' | 'limit' {
    const levels = state.levels;
    const parents = deepest(state);
    if (levels === null || parents === null) return 'ok';

    const next: PolicyNode[] = [];
    const push = (node: PolicyNode, parentIndex: number): boolean => {
        if (state.nodeCount >= maxNodes) return false;
        parents[parentIndex]?.children.push(next.length);
        next.push(node);
        state.nodeCount += 1;
        return true;
    };

    const asserted = policies.filter((policy) => policy.policyIdentifier !== ANY_POLICY);
    for (const policy of asserted) {
        const id = policy.policyIdentifier;
        let matched = false;
        for (const [index, parent] of parents.entries()) {
            if (!parent.alive || !parent.expectedPolicySet.includes(id)) continue;
            if (!push({ validPolicy: id, qualifiers: policy.qualifiers, expectedPolicySet: [id], children: [], alive: true }, index)) return 'limit';
            matched = true;
        }
        if (matched) continue;
        for (const [index, parent] of parents.entries()) {
            if (!parent.alive || !parent.expectedPolicySet.includes(ANY_POLICY)) continue;
            if (!push({ validPolicy: id, qualifiers: policy.qualifiers, expectedPolicySet: [id], children: [], alive: true }, index)) return 'limit';
        }
    }

    // §6.1.3 (d)(2): the certificate asserting anyPolicy, and the walk still
    // allowing it, copies every parent's expected set down unchanged.
    const any = policies.find((policy) => policy.policyIdentifier === ANY_POLICY);
    if (any !== undefined && state.inhibitAnyPolicy > 0) {
        for (const [index, parent] of parents.entries()) {
            if (!parent.alive) continue;
            for (const expected of parent.expectedPolicySet) {
                if (next.some((node, i) => node.validPolicy === expected && parent.children.includes(i))) continue;
                if (!push({ validPolicy: expected, qualifiers: any.qualifiers, expectedPolicySet: [expected], children: [], alive: true }, index)) return 'limit';
            }
        }
    }

    levels.push(next);
    prunePolicyTree(state);
    return 'ok';
}

/** §6.1.3 (e): a certificate with no `certificatePolicies` sets the tree to NULL. */
export function killPolicyTree(state: PolicyState): void {
    state.levels = null;
}

/**
 * §6.1.4 (b): apply `policyMappings`.
 *
 * With mapping still allowed, a node's `expected_policy_set` becomes the
 * subject-domain policies its issuer-domain policy maps to. With mapping
 * inhibited, the mapped node is **deleted** instead — §6.1.4 (b)(2) — which
 * is the stricter reading and the one that refuses a CA trying to rename a
 * policy after being told not to.
 *
 * A mapping to or from `anyPolicy` is forbidden by §6.1.4 (a) and is reported
 * by the caller; this function ignores it rather than honouring it.
 *
 * @param state    The walk's policy state.
 * @param mappings The certificate's `policyMappings`.
 */
export function applyPolicyMappings(state: PolicyState, mappings: readonly PolicyMapping[]): void {
    const level = deepest(state);
    if (level === null) return;
    const usable = mappings.filter((m) => m.issuerDomainPolicy !== ANY_POLICY && m.subjectDomainPolicy !== ANY_POLICY);
    const byIssuer = new Map<string, string[]>();
    for (const mapping of usable) {
        byIssuer.set(mapping.issuerDomainPolicy, [...(byIssuer.get(mapping.issuerDomainPolicy) ?? []), mapping.subjectDomainPolicy]);
    }
    for (const node of level) {
        if (!node.alive) continue;
        const mapped = byIssuer.get(node.validPolicy);
        if (mapped === undefined) continue;
        if (state.policyMapping > 0) node.expectedPolicySet = mapped;
        else node.alive = false;
    }
    if (state.policyMapping === 0) prunePolicyTree(state);
}

/**
 * §6.1.4 (h), (i), (j): decrement the counters, then let this certificate
 * tighten them.
 *
 * The order is the rule: a certificate's own `policyConstraints` take effect
 * **after** the decrement, so `requireExplicitPolicy: 0` in a CA means every
 * certificate below it needs an explicit policy, including the next one.
 *
 * @param state          The walk's policy state.
 * @param selfIssued     Whether the certificate is self-issued (§6.1.4 (h) skips it).
 * @param requireExplicit `policyConstraints.requireExplicitPolicy`, or undefined.
 * @param inhibitMapping  `policyConstraints.inhibitPolicyMapping`, or undefined.
 * @param inhibitAny      `inhibitAnyPolicy.skipCerts`, or undefined.
 */
export function advancePolicyCounters(
    state: PolicyState,
    selfIssued: boolean,
    requireExplicit: number | undefined,
    inhibitMapping: number | undefined,
    inhibitAny: number | undefined,
): void {
    if (!selfIssued) {
        if (state.explicitPolicy > 0) state.explicitPolicy -= 1;
        if (state.policyMapping > 0) state.policyMapping -= 1;
        if (state.inhibitAnyPolicy > 0) state.inhibitAnyPolicy -= 1;
    }
    if (requireExplicit !== undefined && requireExplicit < state.explicitPolicy) state.explicitPolicy = requireExplicit;
    if (inhibitMapping !== undefined && inhibitMapping < state.policyMapping) state.policyMapping = inhibitMapping;
    if (inhibitAny !== undefined && inhibitAny < state.inhibitAnyPolicy) state.inhibitAnyPolicy = inhibitAny;
}

/**
 * §6.1.5 (a), (b) and §6.1.5 (g): the wrap-up.
 *
 * Returns the authorities-constrained policy set, or `null` when no policy
 * survives **and** an explicit policy was required — which is the only
 * condition under which policy processing rejects a path at all. A tree that
 * came out empty while nobody asked for an explicit policy is not a failure:
 * it means the question was never asked.
 *
 * @param state            The walk's policy state after the last certificate.
 * @param initialPolicySet `user-initial-policy-set`.
 * @returns The surviving policies, or null when the path must be rejected.
 */
export function wrapUpPolicies(state: PolicyState, initialPolicySet: readonly string[]): readonly string[] | null {
    const anyRequested = initialPolicySet.length === 0 || initialPolicySet.includes(ANY_POLICY);
    const surviving = new Set<string>();
    const level = deepest(state);
    for (const node of level ?? []) {
        if (node.alive) surviving.add(node.validPolicy);
    }
    const intersected = anyRequested ? [...surviving] : [...surviving].filter((policy) => initialPolicySet.includes(policy));

    // §6.1.5 (g), literally: *"if either the value of the explicit_policy
    // variable is greater than zero or the valid_policy_tree is not NULL,
    // then path processing has succeeded"*. The intersection with
    // `user-initial-policy-set` happens first and can itself empty the tree,
    // which is the only way it affects the verdict.
    const treeSurvives = state.levels !== null && intersected.length > 0;
    return state.explicitPolicy > 0 || treeSurvives ? intersected : null;
}
