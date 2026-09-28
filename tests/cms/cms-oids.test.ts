import { describe, expect, it } from 'vitest';
import * as oids from '../../src/cms/cms-oids.js';

/**
 * The CMS and TSP object identifiers.
 *
 * One table exists so that a parser, a builder and a verifier compare against
 * the same strings. What that table must never do is carry two names for one
 * OID, or an OID that is not one — both are typos that make two modules
 * silently disagree, and neither is caught by any other test until a real
 * message fails to verify.
 */

const named: Array<readonly [string, string]> = Object.entries(oids).flatMap(([name, value]) => (typeof value === 'string' ? [[name, value] as const] : []));

describe('CMS and TSP object identifiers', () => {
    it('should all be well-formed dotted OIDs', () => {
        for (const [name, oid] of named) expect(oid, name).toMatch(/^[0-2](\.(0|[1-9]\d*))+$/);
    });

    it('should name each OID once', () => {
        expect(new Set(named.map(([, oid]) => oid)).size).toBe(named.length);
    });

    it('should hold the values the RFCs assign', () => {
        // Spot-checked against the ASN.1 modules rather than against this file:
        // RFC 5652 §12.1, RFC 3161 Appendix C, RFC 5035 Appendix A.
        expect(oids.OID_SIGNED_DATA).toBe('1.2.840.113549.1.7.2');
        expect(oids.OID_TST_INFO).toBe('1.2.840.113549.1.9.16.1.4');
        expect(oids.OID_ATTR_MESSAGE_DIGEST).toBe('1.2.840.113549.1.9.4');
        expect(oids.OID_ATTR_SIGNING_CERTIFICATE_V2).toBe('1.2.840.113549.1.9.16.2.47');
        expect(oids.OID_KP_TIMESTAMPING).toBe('1.3.6.1.5.5.7.3.8');
    });

    it('should treat as signed-only exactly the attributes the RFCs forbid in unsignedAttrs', () => {
        // RFC 5652 §11.1–§11.3, RFC 5035 §3, RFC 6211 §2. The countersignature
        // and the timestamp token are the opposite: unsigned by definition.
        expect([...oids.SIGNED_ONLY_ATTRIBUTES].sort()).toEqual([
            oids.OID_ATTR_ALGORITHM_PROTECTION,
            oids.OID_ATTR_CONTENT_TYPE,
            oids.OID_ATTR_MESSAGE_DIGEST,
            oids.OID_ATTR_SIGNING_CERTIFICATE,
            oids.OID_ATTR_SIGNING_CERTIFICATE_V2,
            oids.OID_ATTR_SIGNING_TIME,
        ].sort());
        expect(oids.SIGNED_ONLY_ATTRIBUTES.has(oids.OID_ATTR_COUNTERSIGNATURE)).toBe(false);
        expect(oids.SIGNED_ONLY_ATTRIBUTES.has(oids.OID_ATTR_TIMESTAMP_TOKEN)).toBe(false);
    });
});
