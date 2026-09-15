import { describe, it, expect } from 'vitest';
import { OID_REGISTRY } from '../../src/oid/oid-registry.js';
import { getOidName } from '../../src/oid/oid-names.js';
import { decodeOid, encodeOid, isValidOid } from '../../src/asn1/asn1-oid.js';

describe('OID_REGISTRY', () => {
    it('should list a registry of useful size', () => {
        expect(OID_REGISTRY.length).toBeGreaterThanOrEqual(300);
    });

    it('should register every OID once', () => {
        const seen = new Set<string>();
        const duplicates = OID_REGISTRY.filter((e) => seen.has(e.oid) || !seen.add(e.oid)).map((e) => e.oid);
        expect(duplicates).toEqual([]);
    });

    it('should register every name once', () => {
        const seen = new Set<string>();
        const duplicates = OID_REGISTRY.filter((e) => seen.has(e.name) || !seen.add(e.name)).map((e) => e.name);
        expect(duplicates).toEqual([]);
    });

    it('should hold only OIDs X.660 allows, which the codec round-trips', () => {
        const invalid = OID_REGISTRY.filter((e) => !isValidOid(e.oid) || decodeOid(encodeOid(e.oid)) !== e.oid);
        expect(invalid).toEqual([]);
    });

    it('should hold identifier-shaped names and a named standard on every entry', () => {
        const malformed = OID_REGISTRY.filter((e) => !/^[A-Za-z][A-Za-z0-9-]*$/.test(e.name) || e.standard.trim().length === 0);
        expect(malformed).toEqual([]);
    });

    it('should be frozen, entries included', () => {
        expect(Object.isFrozen(OID_REGISTRY)).toBe(true);
        expect(OID_REGISTRY.every((e) => Object.isFrozen(e))).toBe(true);
    });
});

describe('getOidName', () => {
    it.each([
        ['2.5.4.3', 'commonName'],
        ['2.5.29.17', 'subjectAltName'],
        ['2.5.29.32.0', 'anyPolicy'],
        ['1.3.6.1.5.5.7.3.1', 'serverAuth'],
        ['1.3.6.1.5.5.7.48.3', 'id-ad-timeStamping'],
        ['1.2.840.113549.1.1.11', 'sha256WithRSAEncryption'],
        ['1.2.840.10045.3.1.7', 'secp256r1'],
        ['1.3.101.112', 'Ed25519'],
        ['2.16.840.1.101.3.4.3.18', 'ml-dsa-65'],
        ['1.3.6.1.4.1.11129.2.4.2', 'signedCertificateTimestampList'],
    ])('should name %s %s', (oid, name) => {
        expect(getOidName(oid)).toBe(name);
    });

    it('should return undefined for an OID the registry does not list', () => {
        expect(getOidName('1.2.3.4.5')).toBeUndefined();
        expect(getOidName('2.5.29')).toBeUndefined();
        expect(getOidName('')).toBeUndefined();
    });

    it('should never resolve an object property as a name (CWE-1321)', () => {
        for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
            expect(getOidName(key)).toBeUndefined();
        }
    });

    it('should return undefined for an argument that is not a string', () => {
        for (const value of [undefined, null, 2529, ['2.5.29.17'], { oid: '2.5.29.17' }]) {
            expect(getOidName(value as unknown as string)).toBeUndefined();
        }
    });
});
