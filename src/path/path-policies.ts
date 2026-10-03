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
        if (state.nodeCount >= maxNodes) {
            // The level the bound stopped is never added, so no parent may keep
            // an index into it: the deepest level has no children before it
            // grows, and a stale index left here made the §6.1.5 (g)(iii)
            // intersection walk into a level that does not exist — a TypeError
            // out of a call that promises a report.
            for (const parent of parents) parent.children = [];
            return false;
        }
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
    // On a copy: the caller's state is the walk's record, and the same state
    // may be wrapped up against several user sets.
    const tree = anyRequested || state.levels === null ? state : _intersectWithUserSet(state, initialPolicySet);

    const surviving = new Set<string>();
    for (const node of deepest(tree) ?? []) {
        if (node.alive) surviving.add(node.validPolicy);
    }

    // §6.1.5 (g), literally: *"if either the value of the explicit_policy
    // variable is greater than zero or the valid_policy_tree is not NULL,
    // then path processing has succeeded"*. The intersection with
    // `user-initial-policy-set` happens first and can itself empty the tree,
    // which is the only way it affects the verdict.
    const treeSurvives = tree.levels !== null && surviving.size > 0;
    return state.explicitPolicy > 0 || treeSurvives ? [...surviving] : null;
}

/**
 * §6.1.5 (g)(iii): the intersection of the tree with `user-initial-policy-set`.
 *
 * **In the anchor's domain, not the leaf's.** The user names the policies in
 * the vocabulary of the trust anchor, and a policy mapping renames them on the
 * way down: a CA that maps P1 → P2 issues under P2 a certificate the user
 * asked for as P1. So the set is applied to the nodes *whose parent is
 * anyPolicy* — the first named policies under the root, where the anchor's
 * vocabulary is still spoken — and every subtree under a node the user did not
 * ask for dies with it. Intersecting the deepest level instead reversed the
 * NIST PKITS 4.10.1 verdicts: it refused the P1 the user asked for and accepted
 * the P2 nobody did.
 *
 * Step 3 then replaces an `anyPolicy` node of depth *n* by one node per
 * requested policy not already present, so a leaf under anyPolicy satisfies
 * any user set; step 4 prunes what was orphaned.
 */
function _intersectWithUserSet(state: PolicyState, initialPolicySet: readonly string[]): PolicyState {
    const levels = (state.levels as PolicyNode[][]).map((level) => level.map((node) => ({ ...node, children: [...node.children] })));
    const copy: PolicyState = { ...state, levels };
    // Children indices always name a node of the next level: the tree is built
    // level by level and only ever marked, never spliced, so the casts here
    // state an invariant rather than guard against one.
    const kill = (depth: number, index: number): void => {
        const node = (levels[depth] as PolicyNode[])[index] as PolicyNode;
        node.alive = false;
        for (const child of node.children) kill(depth + 1, child);
    };

    // (1) and (2): the nodes whose parent is anyPolicy, and the ones among
    // them the user did not ask for — gone, with everything below them.
    const named = new Set<string>();
    for (const [depth, level] of levels.entries()) {
        if (depth === levels.length - 1) break;
        for (const parent of level) {
            if (!parent.alive || parent.validPolicy !== ANY_POLICY) continue;
            // A parent's children are live on entry — every kill so far ended
            // in a prune — and a kill below marks a subtree no other parent
            // reaches, so no child is met twice.
            for (const index of parent.children) {
                const child = (levels[depth + 1] as PolicyNode[])[index] as PolicyNode;
                if (child.validPolicy !== ANY_POLICY && !initialPolicySet.includes(child.validPolicy)) kill(depth + 1, index);
                else named.add(child.validPolicy);
            }
        }
    }

    // (3): an anyPolicy leaf stands for every policy the user asked for.
    const last = levels.length - 1;
    const bottom = levels[last] as PolicyNode[];
    const wild = bottom.findIndex((node) => node.alive && node.validPolicy === ANY_POLICY);
    if (wild >= 0 && last > 0) {
        const node = bottom[wild] as PolicyNode;
        const parentLevel = levels[last - 1] as PolicyNode[];
        // A live node has a live parent: pruning works upwards and never
        // leaves a child whose parent is gone.
        const parent = parentLevel.find((candidate) => candidate.alive && candidate.children.includes(wild)) as PolicyNode;
        for (const policy of initialPolicySet) {
            if (named.has(policy)) continue;
            bottom.push({ validPolicy: policy, qualifiers: node.qualifiers, expectedPolicySet: [policy], children: [], alive: true });
            parent.children.push(bottom.length - 1);
        }
        node.alive = false;
    }

    // (4): a node left without a live child is gone too, up to the root.
    prunePolicyTree(copy);
    return copy;
}
