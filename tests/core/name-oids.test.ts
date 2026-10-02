import { describe, expect, it } from 'vitest';
import { NAME_ATTRIBUTE_SYNTAX, OID_COUNTRY_NAME, type NameAttributeSyntax } from '../../src/core/name-oids.js';

/**
 * The naming-attribute syntax table.
 *
 * The name builder writes what this table says and the name reader checks
 * what it says, so a wrong bound here is a wrong bound on both sides at
 * once — the one kind of error that a build → parse round trip can never
 * catch. The expected rows are copied from RFC 5280 Appendix A.1 (the
 * attribute types and their value syntaxes) and Appendix A.2 (the `ub-*`
 * upper bounds), not from the module under test.
 */

const RFC_5280_APPENDIX_A: ReadonlyArray<readonly [string, NameAttributeSyntax]> = [
    // X520name ::= CHOICE { … SIZE (1..ub-name) }, ub-name INTEGER ::= 32768
    ['2.5.4.41', { name: 'name', syntax: 'directory', min: 1, max: 32768 }],
    ['2.5.4.4', { name: 'surname', syntax: 'directory', min: 1, max: 32768 }],
    ['2.5.4.42', { name: 'givenName', syntax: 'directory', min: 1, max: 32768 }],
    ['2.5.4.43', { name: 'initials', syntax: 'directory', min: 1, max: 32768 }],
    ['2.5.4.44', { name: 'generationQualifier', syntax: 'directory', min: 1, max: 32768 }],
    // ub-common-name 64, ub-locality-name 128, ub-state-name 128,
    // ub-organization-name 64, ub-organizational-unit-name 64, ub-title 64,
    // ub-pseudonym 128
    ['2.5.4.3', { name: 'commonName', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.7', { name: 'localityName', syntax: 'directory', min: 1, max: 128 }],
    ['2.5.4.8', { name: 'stateOrProvinceName', syntax: 'directory', min: 1, max: 128 }],
    ['2.5.4.10', { name: 'organizationName', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.11', { name: 'organizationalUnitName', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.12', { name: 'title', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.65', { name: 'pseudonym', syntax: 'directory', min: 1, max: 128 }],
    // X520dnQualifier ::= PrintableString (no SIZE);
    // X520countryName ::= PrintableString (SIZE (2)), ub-country-name-alpha-length 2;
    // X520SerialNumber ::= PrintableString (SIZE (1..ub-serial-number)), 64
    ['2.5.4.46', { name: 'dnQualifier', syntax: 'printable', min: 0, max: undefined }],
    ['2.5.4.6', { name: 'countryName', syntax: 'printable', min: 2, max: 2 }],
    ['2.5.4.5', { name: 'serialNumber', syntax: 'printable', min: 1, max: 64 }],
    // DomainComponent ::= IA5String (no SIZE);
    // EmailAddress ::= IA5String (SIZE (1..ub-emailaddress-length)), 255
    ['0.9.2342.19200300.100.1.25', { name: 'domainComponent', syntax: 'ia5', min: 0, max: undefined }],
    ['1.2.840.113549.1.9.1', { name: 'emailAddress', syntax: 'ia5', min: 1, max: 255 }],
];

describe('NAME_ATTRIBUTE_SYNTAX', () => {
    it.each(RFC_5280_APPENDIX_A)('should give %s the syntax and SIZE bounds of RFC 5280 Appendix A', (oid, expected) => {
        expect(NAME_ATTRIBUTE_SYNTAX.get(oid)).toEqual(expected);
    });

    it('should hold exactly the attributes of RFC 5280 Appendix A.1, no more', () => {
        expect([...NAME_ATTRIBUTE_SYNTAX.keys()].sort()).toEqual(RFC_5280_APPENDIX_A.map(([oid]) => oid).sort());
    });

    it('should name id-at-countryName (RFC 5280 Appendix A.1: id-at 6)', () => {
        expect(OID_COUNTRY_NAME).toBe('2.5.4.6');
    });
});
