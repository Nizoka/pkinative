import { describe, expect, it } from 'vitest';
import { ANY_EXTENDED_KEY_USAGE, checkExtendedKeyUsage, KEY_PURPOSES } from '../../src/path/path-purpose.js';
import type { Certificate } from '../../src/types/x509-types.js';

/**
 * RFC 5280 §4.2.1.12 along a path.
 *
 * The question this answers is the one a validated chain does not: a chain can
 * be perfectly sound and be sound *for something else*. The interesting rows
 * below are the ones about a **CA's** extKeyUsage, because that rule is not in
 * RFC 5280 at all — every Web PKI validator enforces it, and it is what makes a
 * technically-constrained sub-CA constrained.
 */

/** A certificate carrying the given purposes, or none when `purposes` is null. */
function certificate(purposes: readonly string[] | null): Certificate {
    const extensions = purposes === null
        ? []
        : [{ kind: 'extendedKeyUsage', oid: '2.5.29.37', critical: false, valueDer: new Uint8Array(0), purposes }];
    return { extensions } as unknown as Certificate;
}

const codes = (reasons: readonly { code: string }[]): string[] => reasons.map((r) => r.code);
const { serverAuth, clientAuth, emailProtection } = KEY_PURPOSES;

describe('checkExtendedKeyUsage — the end entity', () => {
    it('should accept a certificate that names the purpose', () => {
        expect(checkExtendedKeyUsage([certificate([serverAuth])], serverAuth)).toEqual([]);
    });

    it('should accept one purpose among several', () => {
        expect(checkExtendedKeyUsage([certificate([clientAuth, serverAuth])], serverAuth)).toEqual([]);
    });

    it('should refuse a certificate that names other purposes, saying which', () => {
        const reasons = checkExtendedKeyUsage([certificate([emailProtection])], serverAuth);
        expect(codes(reasons)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
        expect(reasons[0]?.message).toContain(serverAuth);
        expect(reasons[0]?.message).toContain(emailProtection);
        expect(reasons[0]?.path).toBe('path[0].extKeyUsage');
    });

    it('should treat anyExtendedKeyUsage as every purpose', () => {
        // §4.2.1.12 defines it that way. A relying party that refuses it on an
        // end entity is taking a policy this module does not take, and one
        // comparison on `purposes` is all that takes.
        expect(checkExtendedKeyUsage([certificate([ANY_EXTENDED_KEY_USAGE])], serverAuth)).toEqual([]);
        expect(ANY_EXTENDED_KEY_USAGE).toBe('2.5.29.37.0');
    });

    it('should treat an absent extension as unrestricted', () => {
        // §4.2.1.12 makes it optional, and its absence restricts nothing. A
        // validator that required it would refuse a large part of every internal
        // PKI ever issued.
        expect(checkExtendedKeyUsage([certificate(null)], serverAuth)).toEqual([]);
    });

    it('should refuse an absent extension when the caller asked for explicitness', () => {
        // The stricter Web PKI reading, where a server certificate that does not
        // say serverAuth is not a server certificate. The reason distinguishes
        // absent from naming-something-else, because the two call for different
        // conversations with the CA.
        const reasons = checkExtendedKeyUsage([certificate(null)], serverAuth, { requireExplicit: true });
        expect(codes(reasons)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
        expect(reasons[0]?.message).toContain('carries no extKeyUsage');
        expect(reasons[0]?.path).toBe('path[0]');
    });

    it('should refuse an empty extKeyUsage, which permits nothing', () => {
        const reasons = checkExtendedKeyUsage([certificate([])], serverAuth);
        expect(codes(reasons)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
        expect(reasons[0]?.message).toContain('none');
    });
});

describe('checkExtendedKeyUsage — a CA restricts what it issued', () => {
    it('should refuse a chain whose intermediate names another purpose', () => {
        // The rule no sentence of RFC 5280 states and every Web PKI validator
        // applies: a sub-CA restricted to emailProtection issuing a serverAuth
        // leaf is exactly what restricting it was for. x509-limbo's bettertls
        // path-building cases are built on this shape.
        const path = [certificate([serverAuth]), certificate([emailProtection])];
        const reasons = checkExtendedKeyUsage(path, serverAuth);
        expect(codes(reasons)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
        expect(reasons[0]?.path).toBe('path[1].extKeyUsage');
    });

    it('should accept a chain whose CAs are silent about purpose', () => {
        // Which is the everyday case: almost no public root carries extKeyUsage.
        const path = [certificate([serverAuth]), certificate(null), certificate(null)];
        expect(checkExtendedKeyUsage(path, serverAuth)).toEqual([]);
    });

    it('should never require a CA to name the purpose, even under requireExplicit', () => {
        // Requiring every CA above the leaf to enumerate the purposes of
        // everything it may ever issue is not a reading anyone holds, so the
        // option applies to the end entity alone.
        const path = [certificate([serverAuth]), certificate(null)];
        expect(checkExtendedKeyUsage(path, serverAuth, { requireExplicit: true })).toEqual([]);
    });

    it('should report every certificate that forbids the purpose, not just the first', () => {
        const path = [certificate([emailProtection]), certificate([emailProtection]), certificate([clientAuth])];
        const reasons = checkExtendedKeyUsage(path, serverAuth);
        expect(reasons).toHaveLength(3);
        expect(reasons.map((r) => r.path)).toEqual(['path[0].extKeyUsage', 'path[1].extKeyUsage', 'path[2].extKeyUsage']);
    });

    it('should honour anyExtendedKeyUsage on a CA', () => {
        const path = [certificate([serverAuth]), certificate([ANY_EXTENDED_KEY_USAGE])];
        expect(checkExtendedKeyUsage(path, serverAuth)).toEqual([]);
    });

    it('should judge the end entity alone when restrictIssuers is off', () => {
        // The literal-RFC reading, for an internal PKI that puts a purpose on a
        // CA as documentation rather than as a constraint.
        const path = [certificate([serverAuth]), certificate([emailProtection])];
        expect(checkExtendedKeyUsage(path, serverAuth, { restrictIssuers: false })).toEqual([]);
        // …and it still judges the leaf.
        const wrongLeaf = [certificate([emailProtection]), certificate([emailProtection])];
        expect(codes(checkExtendedKeyUsage(wrongLeaf, serverAuth, { restrictIssuers: false }))).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
    });
});

describe('checkExtendedKeyUsage — edges', () => {
    it('should accept any OID, because the purpose registry is open', () => {
        const private_ = '1.3.6.1.4.1.311.10.3.12';
        expect(checkExtendedKeyUsage([certificate([private_])], private_)).toEqual([]);
    });

    it('should answer rather than throw for an empty path', () => {
        expect(checkExtendedKeyUsage([], serverAuth)).toEqual([]);
    });

    it('should name the six purposes RFC 5280 §4.2.1.12 names', () => {
        expect(KEY_PURPOSES).toEqual({
            serverAuth: '1.3.6.1.5.5.7.3.1',
            clientAuth: '1.3.6.1.5.5.7.3.2',
            codeSigning: '1.3.6.1.5.5.7.3.3',
            emailProtection: '1.3.6.1.5.5.7.3.4',
            timeStamping: '1.3.6.1.5.5.7.3.8',
            ocspSigning: '1.3.6.1.5.5.7.3.9',
        });
        expect(Object.isFrozen(KEY_PURPOSES)).toBe(true);
    });
});
