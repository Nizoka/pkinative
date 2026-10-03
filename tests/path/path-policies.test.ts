import { describe, expect, it } from 'vitest';
import {
    advancePolicyCounters,
    ANY_POLICY,
    applyPolicyMappings,
    countPolicyNodes,
    growPolicyTree,
    initialPolicyState,
    killPolicyTree,
    prunePolicyTree,
    wrapUpPolicies,
    type PolicyState,
} from '../../src/path/path-policies.js';
import type { PolicyInformation } from '../../src/types/x509-types.js';

/**
 * RFC 5280 §6.1 policy processing, step by step.
 *
 * Each step function is exported so it can be exercised against its clause on
 * a synthetic state, which is the only way a PKITS §4.8–4.10 case becomes a
 * short test. The flat-levels design is what makes that possible: a tree with
 * parent pointers and spliced arrays could only be built by running a whole
 * chain through it.
 */

const P1 = '1.3.6.1.4.1.1';
const P2 = '1.3.6.1.4.1.2';
const P3 = '1.3.6.1.4.1.3';

const policy = (id: string): PolicyInformation => ({ policyIdentifier: id, qualifiers: [] });
const MAX = 4096;

/** The live `validPolicy` values at the deepest level. */
const leaves = (state: PolicyState): string[] => {
    const levels = state.levels;
    if (levels === null) return [];
    return (levels[levels.length - 1] ?? []).filter((n) => n.alive).map((n) => n.validPolicy).sort();
};

const fresh = (n = 3): PolicyState => initialPolicyState(n, false, false, false);

describe('initialPolicyState — §6.1.2', () => {
    it('should start as one anyPolicy node expecting anyPolicy', () => {
        const state = fresh();
        expect(leaves(state)).toEqual([ANY_POLICY]);
        expect(state.levels?.[0]?.[0]?.expectedPolicySet).toEqual([ANY_POLICY]);
        expect(countPolicyNodes(state)).toBe(1);
    });

    it('should start every counter at n + 1 by default', () => {
        const state = initialPolicyState(4, false, false, false);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([5, 5, 5]);
    });

    it('should start a counter at 0 when the caller asked for it', () => {
        const state = initialPolicyState(4, true, true, true);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([0, 0, 0]);
    });
});

describe('growPolicyTree — §6.1.3 (d)', () => {
    it('should make a policy a child of the anyPolicy root', () => {
        const state = fresh();
        expect(growPolicyTree(state, [policy(P1), policy(P2)], MAX)).toBe('ok');
        expect(leaves(state)).toEqual([P1, P2].sort());
    });

    it('should carry a matching policy down two levels', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        growPolicyTree(state, [policy(P1)], MAX);
        expect(leaves(state)).toEqual([P1]);
    });

    it('should prune the branch whose policy is not asserted below it', () => {
        // P2 exists at depth 1 and nothing below claims it, so its branch dies
        // — §6.1.3 (d)(2) pruning, done as one backward pass.
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        growPolicyTree(state, [policy(P1)], MAX);
        const depth1 = state.levels?.[1] ?? [];
        expect(depth1.filter((n) => n.alive).map((n) => n.validPolicy)).toEqual([P1]);
        expect(depth1.some((n) => !n.alive && n.validPolicy === P2)).toBe(true);
    });

    it('should set the tree to NULL when no branch survives', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        growPolicyTree(state, [policy(P3)], MAX);
        expect(state.levels).toBeNull();
        expect(countPolicyNodes(state)).toBe(0);
    });

    it('should let a specific policy descend from an anyPolicy assertion', () => {
        // The fallback implementations get wrong: with no exact match, a
        // parent whose expected set holds anyPolicy adopts the policy anyway.
        // Omitting this refuses most real hierarchies.
        const state = fresh();
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        growPolicyTree(state, [policy(P1)], MAX);
        expect(leaves(state)).toEqual([P1]);
    });

    it('should copy the parent’s expected set down for an anyPolicy assertion', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(leaves(state)).toEqual([P1, P2].sort());
    });

    it('should ignore an anyPolicy assertion once anyPolicy is inhibited', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        state.inhibitAnyPolicy = 0;
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(state.levels).toBeNull();
    });

    it('should do nothing at all once the tree is NULL', () => {
        const state = fresh();
        killPolicyTree(state);
        expect(growPolicyTree(state, [policy(P1)], MAX)).toBe('ok');
        expect(state.levels).toBeNull();
    });

    it('should stop at maxPolicyNodes rather than grow without bound', () => {
        // The policy tree is the part of §6 that actually explodes
        // combinatorially; this is the bound that makes it safe to walk.
        const state = fresh();
        const many = Array.from({ length: 50 }, (_, i) => policy(`1.3.6.1.4.1.${String(i)}`));
        expect(growPolicyTree(state, many, 10)).toBe('limit');
        expect(countPolicyNodes(state)).toBeLessThanOrEqual(10);
    });

    it('should allow exactly maxPolicyNodes nodes, the root included, and stop at the one past it', () => {
        const exact = fresh();
        expect(growPolicyTree(exact, [policy(P1), policy(P2)], 3)).toBe('ok');
        expect(exact.nodeCount).toBe(3);
        expect(countPolicyNodes(exact)).toBe(3);
        const over = fresh();
        expect(growPolicyTree(over, [policy(P1), policy(P2)], 2)).toBe('limit');
        expect(over.nodeCount).toBe(2);
    });

    it('should leave no parent pointing into a level the bound stopped', () => {
        // The level is never added, so an index into it names nothing; the
        // §6.1.5 (g)(iii) intersection used to follow one into a level that
        // does not exist and throw a TypeError.
        const state = initialPolicyState(2, true, false, false);
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        expect(growPolicyTree(state, [policy(P1), policy(P2), policy(P3)], 4)).toBe('limit');
        expect(state.levels).toHaveLength(2);
        expect((state.levels?.[1] ?? []).map((n) => n.children)).toEqual([[], []]);
        expect(wrapUpPolicies(state, [P2])).toEqual([P2]);
    });

    it('should not also hang an exactly matched policy under an anyPolicy sibling (§6.1.3 (d)(1)(ii))', () => {
        // Certificate 1 asserts P1 and anyPolicy, certificate 2 only P1. The
        // fallback to an anyPolicy parent is for a policy NO node expects; P1
        // has its own parent, so the anyPolicy node gets no child and dies.
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(ANY_POLICY)], MAX);
        growPolicyTree(state, [policy(P1)], MAX);
        expect(leaves(state)).toEqual([P1]);
        expect((state.levels?.[1] ?? []).filter((n) => n.alive).map((n) => n.validPolicy)).toEqual([P1]);
        expect(countPolicyNodes(state)).toBe(3);
    });

    it('should still honour an anyPolicy assertion while inhibitAnyPolicy is 1', () => {
        // §6.1.3 (d)(2): "inhibit_anyPolicy is greater than 0" — 1 is the last
        // certificate that may still use it.
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        state.inhibitAnyPolicy = 1;
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(leaves(state)).toEqual([P1]);
    });
});

describe('growPolicyTree over a tree that has already been pruned', () => {
    // Dead nodes stay in place so every index handed out keeps pointing at
    // what it pointed at. Growing again therefore walks past them, and a loop
    // that forgot to skip them would resurrect a branch the RFC pruned.
    const partlyPruned = (): PolicyState => {
        const state = fresh(4);
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        growPolicyTree(state, [policy(P1)], MAX);   // P2's branch dies at depth 1
        return state;
    };

    it('should not grow from a pruned parent', () => {
        const state = partlyPruned();
        expect((state.levels?.[1] ?? []).some((n) => !n.alive)).toBe(true);
        growPolicyTree(state, [policy(P1)], MAX);
        expect(leaves(state)).toEqual([P1]);
    });

    it('should not grow from a pruned parent through the anyPolicy fallback either', () => {
        const state = partlyPruned();
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(leaves(state)).toEqual([P1]);
    });

    it('should not prune a dead node’s children a second time', () => {
        const state = partlyPruned();
        const before = countPolicyNodes(state);
        prunePolicyTree(state);
        expect(countPolicyNodes(state)).toBe(before);
    });

    it('should not map a pruned node', () => {
        const state = partlyPruned();
        applyPolicyMappings(state, [{ issuerDomainPolicy: P2, subjectDomainPolicy: P3 }]);
        // P2 is dead at depth 1 and nothing at the deepest level carries it,
        // so the mapping changes nothing.
        expect(leaves(state)).toEqual([P1]);
    });
});

describe('the anyPolicy fallback and the node bound together', () => {
    it('should stop at the bound while descending from an anyPolicy parent', () => {
        // The second push site: a parent expecting anyPolicy adopting several
        // specific policies, with the bound reached part way through.
        const state = fresh();
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        const many = Array.from({ length: 20 }, (_, i) => policy(`1.3.6.1.4.1.${String(100 + i)}`));
        expect(growPolicyTree(state, many, 4)).toBe('limit');
    });

    it('should stop at the bound while copying an anyPolicy assertion down', () => {
        // The third push site: an anyPolicy certificate copying a wide
        // expected set down, with the bound reached part way through.
        const state = fresh();
        const many = Array.from({ length: 6 }, (_, i) => policy(`1.3.6.1.4.1.${String(200 + i)}`));
        growPolicyTree(state, many, MAX);
        expect(growPolicyTree(state, [policy(ANY_POLICY)], 8)).toBe('limit');
    });

    it('should stop at the bound while descending from an exact match', () => {
        // The first push site: parents that each expect their own policy, and
        // the bound reached part way through matching them.
        const state = fresh();
        const many = Array.from({ length: 8 }, (_, i) => policy(`1.3.6.1.4.1.${String(300 + i)}`));
        growPolicyTree(state, many, MAX);
        expect(growPolicyTree(state, many, countPolicyNodes(state) + 2)).toBe('limit');
    });

    it('should not create the same child twice for one parent', () => {
        // A certificate asserting both a specific policy and anyPolicy must
        // not get two identical children: the specific one already exists.
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        growPolicyTree(state, [policy(P1), policy(ANY_POLICY)], MAX);
        expect(leaves(state)).toEqual([P1]);
        expect((state.levels?.[2] ?? []).filter((n) => n.alive)).toHaveLength(1);
    });
});

describe('a node killed at the deepest level', () => {
    /**
     * Inhibited policy mapping is the one thing that kills a node at the
     * **deepest** level — pruning only ever touches the levels above it. Every
     * loop that walks the deepest level therefore has to skip dead entries,
     * and these are the cases where that matters.
     */
    const withDeadLeaf = (): PolicyState => {
        const state = fresh(4);
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        state.policyMapping = 0;
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P3 }]);
        return state;
    };

    it('should leave one live sibling behind', () => {
        const state = withDeadLeaf();
        expect(leaves(state)).toEqual([P2]);
        expect((state.levels?.[1] ?? []).some((n) => !n.alive)).toBe(true);
    });

    it('should not copy an anyPolicy assertion down from it', () => {
        const state = withDeadLeaf();
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(leaves(state)).toEqual([P2]);
    });

    it('should not be mapped again by a later certificate', () => {
        const state = withDeadLeaf();
        state.policyMapping = 2;
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P3 }]);
        // P1's node is dead, so nothing adopts the mapping; P2 is untouched.
        expect((state.levels?.[1] ?? []).filter((n) => n.alive).map((n) => n.expectedPolicySet)).toEqual([[P2]]);
    });
});

describe('prunePolicyTree', () => {
    it('should be idempotent on a healthy tree', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        const before = countPolicyNodes(state);
        prunePolicyTree(state);
        prunePolicyTree(state);
        expect(countPolicyNodes(state)).toBe(before);
    });

    it('should do nothing on a NULL tree', () => {
        const state = fresh();
        killPolicyTree(state);
        expect(() => { prunePolicyTree(state); }).not.toThrow();
        expect(state.levels).toBeNull();
    });

    it('should propagate a death upwards through several levels', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        growPolicyTree(state, [policy(P1)], MAX);
        // Kill the deepest node by hand; every ancestor must follow, and the
        // root dying sets the tree to NULL.
        const deepest = state.levels?.[2] ?? [];
        for (const node of deepest) node.alive = false;
        prunePolicyTree(state);
        expect(state.levels).toBeNull();
    });
});

describe('applyPolicyMappings — §6.1.4 (a), (b)', () => {
    it('should replace a node’s expected set with what the policy maps to', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }]);
        expect(state.levels?.[1]?.[0]?.expectedPolicySet).toEqual([P2]);
        growPolicyTree(state, [policy(P2)], MAX);
        expect(leaves(state)).toEqual([P2]);
    });

    it('should delete the mapped node when mapping is inhibited', () => {
        // §6.1.4 (b)(2): the stricter reading, and the one that refuses a CA
        // renaming a policy after being told not to.
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        state.policyMapping = 0;
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }]);
        expect(state.levels).toBeNull();
    });

    it('should ignore a mapping that names anyPolicy rather than honour it', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        applyPolicyMappings(state, [{ issuerDomainPolicy: ANY_POLICY, subjectDomainPolicy: P2 }, { issuerDomainPolicy: P1, subjectDomainPolicy: ANY_POLICY }]);
        expect(state.levels?.[1]?.[0]?.expectedPolicySet).toEqual([P1]);
    });

    it('should collect several subject policies for one issuer policy', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }, { issuerDomainPolicy: P1, subjectDomainPolicy: P3 }]);
        expect(state.levels?.[1]?.[0]?.expectedPolicySet).toEqual([P2, P3]);
    });

    it('should do nothing on a NULL tree', () => {
        const state = fresh();
        killPolicyTree(state);
        expect(() => { applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }]); }).not.toThrow();
    });

    it('should still map while policyMapping is 1', () => {
        // §6.1.4 (b)(1): "policy_mapping is greater than 0" — 1 is the last
        // certificate that may still map.
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        state.policyMapping = 1;
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }]);
        expect(state.levels?.[1]?.[0]).toMatchObject({ alive: true, expectedPolicySet: [P2] });
    });

    it('should leave a node no mapping names alone', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        applyPolicyMappings(state, [{ issuerDomainPolicy: P3, subjectDomainPolicy: P2 }]);
        expect(state.levels?.[1]?.[0]?.expectedPolicySet).toEqual([P1]);
    });
});

describe('advancePolicyCounters — §6.1.4 (h), (i), (j)', () => {
    it('should decrement every counter for a non-self-issued certificate', () => {
        const state = initialPolicyState(3, false, false, false);
        advancePolicyCounters(state, false, undefined, undefined, undefined);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([3, 3, 3]);
    });

    it('should not spend a step on a self-issued certificate', () => {
        // §6.1.4 (h). A CA re-keying itself must not consume anyone's budget.
        const state = initialPolicyState(3, false, false, false);
        advancePolicyCounters(state, true, undefined, undefined, undefined);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([4, 4, 4]);
    });

    it('should take every counter from 1 to 0', () => {
        // n = 0 starts every counter at 1: the next certificate spends the last step.
        const state = initialPolicyState(0, false, false, false);
        advancePolicyCounters(state, false, undefined, undefined, undefined);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([0, 0, 0]);
    });

    it('should never go below zero', () => {
        const state = initialPolicyState(0, true, true, true);
        advancePolicyCounters(state, false, undefined, undefined, undefined);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([0, 0, 0]);
    });

    it('should let a certificate tighten a counter, never loosen it', () => {
        const state = initialPolicyState(9, false, false, false);
        advancePolicyCounters(state, false, 0, 1, 2);
        expect([state.explicitPolicy, state.policyMapping, state.inhibitAnyPolicy]).toEqual([0, 1, 2]);
        advancePolicyCounters(state, false, 8, 8, 8);
        // Already at 0/0/1 after the second decrement; an 8 cannot raise them.
        expect(state.explicitPolicy).toBe(0);
        expect(state.policyMapping).toBe(0);
        expect(state.inhibitAnyPolicy).toBe(1);
    });

    it('should apply its own constraint after the decrement, so it binds the next certificate', () => {
        const state = initialPolicyState(5, false, false, false);
        advancePolicyCounters(state, false, 0, undefined, undefined);
        expect(state.explicitPolicy).toBe(0);
    });
});

describe('wrapUpPolicies — §6.1.5', () => {
    it('should return the surviving policies when one is established', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        expect([...(wrapUpPolicies(state, []) ?? [])].sort()).toEqual([P1, P2].sort());
    });

    it('should intersect with the caller’s initial policy set', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        expect(wrapUpPolicies(state, [P2])).toEqual([P2]);
    });

    it('should treat anyPolicy in the initial set as "any"', () => {
        const state = fresh();
        growPolicyTree(state, [policy(P1)], MAX);
        expect(wrapUpPolicies(state, [ANY_POLICY])).toEqual([P1]);
    });

    it('should accept a path with no policy when nobody required one', () => {
        // §6.1.5 (a). An empty tree with explicitPolicy still positive means
        // the question was never asked — not that the answer was no.
        const state = fresh();
        killPolicyTree(state);
        expect(wrapUpPolicies(state, [])).toEqual([]);
    });

    it('should reject a path with no policy when an explicit policy was required', () => {
        const state = initialPolicyState(2, true, false, false);
        killPolicyTree(state);
        expect(wrapUpPolicies(state, [])).toBeNull();
    });

    it('should ignore a node that policy mapping killed at the deepest level', () => {
        // applyPolicyMappings with mapping inhibited marks deepest-level nodes
        // dead in place. Wrap-up must not count them, and the surviving
        // sibling must still carry the path.
        const state = fresh();
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        state.policyMapping = 0;
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P3 }]);
        expect(state.levels).not.toBeNull();
        expect(wrapUpPolicies(state, [])).toEqual([P2]);
    });

    it('should reject when an explicit policy was required and the intersection is empty', () => {
        const state = initialPolicyState(2, true, false, false);
        growPolicyTree(state, [policy(P1)], MAX);
        expect(wrapUpPolicies(state, [P3])).toBeNull();
        expect(wrapUpPolicies(state, [P1])).toEqual([P1]);
    });

    it('should intersect user-initial-policy-set in the anchor\'s domain, across a policy mapping (PKITS 4.10.1)', () => {
        // Root → CA asserting P1 and mapping P1 → P2 → leaf asserting P2. The
        // user speaks the anchor's vocabulary: asking for P1 is what this chain
        // satisfies, and asking for P2 — a name only the CA's domain uses — is
        // not. Intersecting at the leaf said the opposite.
        const state = initialPolicyState(2, true, false, false);
        growPolicyTree(state, [policy(P1)], MAX);
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }]);
        growPolicyTree(state, [policy(P2)], MAX);
        expect(wrapUpPolicies(state, [P1])).toEqual([P2]);
        expect(wrapUpPolicies(state, [P2])).toBeNull();
        // Wrapping up is pure: the same state answers both, and the whole tree is still there.
        expect(wrapUpPolicies(state, [])).toEqual([P2]);
    });

    it('should let an anyPolicy leaf stand for every policy the user asked for (§6.1.5 (g)(iii)(3))', () => {
        const state = initialPolicyState(2, true, false, false);
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(wrapUpPolicies(state, [P1, P3])).toEqual([P1, P3]);
        expect(wrapUpPolicies(state, [])).toEqual([ANY_POLICY]);
    });

    it('should not add a user policy the anyPolicy node already stands beside', () => {
        // Certificate 1 asserts P1 and anyPolicy, certificate 2 only anyPolicy:
        // the bottom holds P1 (under P1) and anyPolicy (under anyPolicy). The
        // user's P1 is already named under the root, so only P3 is added when
        // the anyPolicy leaf is replaced.
        const state = initialPolicyState(2, true, false, false);
        growPolicyTree(state, [policy(P1), policy(ANY_POLICY)], MAX);
        growPolicyTree(state, [policy(ANY_POLICY)], MAX);
        expect(wrapUpPolicies(state, [P1, P3])).toEqual([P1, P3]);
    });

    it('should intersect a tree a mapping kill has pruned, judging only the live sibling', () => {
        // Mapping inhibited: applyPolicyMappings kills the mapped node and
        // prunes, so the root's children hold the live sibling alone and the
        // intersection judges that one.
        const state = initialPolicyState(1, true, false, false);
        growPolicyTree(state, [policy(P1), policy(P2)], MAX);
        state.policyMapping = 0;
        applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P3 }]);
        expect(wrapUpPolicies(state, [P2])).toEqual([P2]);
        expect(wrapUpPolicies(state, [P1])).toBeNull();
    });

    describe.each([true, false])('§6.1.5 (g)(iii) shapes, requireExplicitPolicy %s', (requireExplicit) => {
        it('should replace an anyPolicy leaf at depth 1 — a one-certificate path', () => {
            const state = initialPolicyState(1, requireExplicit, false, false);
            growPolicyTree(state, [policy(ANY_POLICY)], MAX);
            expect(wrapUpPolicies(state, [P1])).toEqual([P1]);
        });

        it('should hang a single requested policy under the anyPolicy leaf\'s parent, so that it survives the prune', () => {
            // One policy is the case where the new node is the parent's only
            // live child: link it anywhere else and the parent, then the
            // root, are pruned.
            const state = initialPolicyState(2, requireExplicit, false, false);
            growPolicyTree(state, [policy(ANY_POLICY)], MAX);
            growPolicyTree(state, [policy(ANY_POLICY)], MAX);
            expect(wrapUpPolicies(state, [P1])).toEqual([P1]);
        });

        it('should not add a policy named under the root that a mapping renamed below it', () => {
            // Certificate 1 asserts P1 and anyPolicy and maps P1 → P2;
            // certificate 2 asserts P2 and anyPolicy. The user's P1 is a node
            // whose parent is anyPolicy, and the chain satisfies it as P2:
            // the anyPolicy leaf stands for nothing more, and adding P1 at the
            // leaf would report a policy the leaf's domain never asserted.
            const state = initialPolicyState(2, requireExplicit, false, false);
            growPolicyTree(state, [policy(P1), policy(ANY_POLICY)], MAX);
            applyPolicyMappings(state, [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }]);
            growPolicyTree(state, [policy(P2), policy(ANY_POLICY)], MAX);
            expect(wrapUpPolicies(state, [P1])).toEqual([P2]);
            // A policy nobody named under the root is what the anyPolicy leaf stands for.
            expect(wrapUpPolicies(state, [P3])).toEqual([P3]);
        });
    });
});
