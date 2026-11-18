import { describe, expect, it } from 'vitest';
import { PkiCertificateError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiDiagnosticCode, PkiLimits } from '../../src/types/pki-types.js';
import type { AttributeCertificateAttribute } from '../../src/types/attribute-certificate-types.js';
import { parseAttributeCertificate } from '../../src/x509/x509-attribute-certificate.js';
import { bitString, context, explicit, integer, octetString, oid, set, utf8 } from '../helpers/cert-builder.js';
import {
    OID_ACCESS_IDENTITY,
    OID_AUTHENTICATION_INFO,
    OID_CHARGING_IDENTITY,
    OID_CLEARANCE,
    OID_GROUP,
    OID_ROLE,
    ROLE_ATTRIBUTE,
    acWithAttributes,
    attribute,
    attributeCertificate,
    clearance,
    dnsName,
    ietfAttrSyntax,
    implicitSequence,
    roleSyntax,
    securityCategory,
    serviceAuthInfo,
    uriName,
} from '../helpers/attribute-certificate-builder.js';
import { sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The attributes of an RFC 5755 attribute certificate (§4.2.7) and the six
 * types of §4.4, each against attributes assembled from first principles: the
 * decoded value, the refusal of a value that does not match its syntax
 * (`PKI_X509_ATTRIBUTE_MALFORMED`), and the profile concern its syntax admits
 * (`PKI_DIAG_AC_ATTRIBUTE_PROFILE`).
 */

function read(...attributes: Uint8Array[]): { attributes: readonly AttributeCertificateAttribute[]; diagnostics: PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const ac = parseAttributeCertificate(acWithAttributes(...attributes), { onDiagnostic: (d) => diagnostics.push(d) });
    return { attributes: ac.attributes, diagnostics };
}

const codes = (...attributes: Uint8Array[]): PkiDiagnosticCode[] => read(...attributes).diagnostics.map((d) => d.code);
const first = (...attributes: Uint8Array[]): AttributeCertificateAttribute => read(...attributes).attributes[0] as AttributeCertificateAttribute;

function refuses(code: string, ...attributes: Uint8Array[]): void {
    const der = acWithAttributes(...attributes);
    expect(() => parseAttributeCertificate(der, { onDiagnostic: () => undefined })).toThrow(expect.objectContaining({ code }));
    expect(() => parseAttributeCertificate(der, { onDiagnostic: () => undefined })).toThrow(PkiCertificateError);
}

function strictRefuses(...attributes: Uint8Array[]): void {
    expect(() => parseAttributeCertificate(acWithAttributes(...attributes), { strict: true })).toThrow(expect.objectContaining({ code: 'PKI_STRICT_DIAGNOSTIC' }));
}

function limitTrips(der: Uint8Array, limits: Partial<PkiLimits>, limit: keyof PkiLimits): void {
    let caught: unknown;
    try {
        parseAttributeCertificate(der, { limits, onDiagnostic: () => undefined });
    } catch (error) {
        caught = error;
    }
    expect(caught).toBeInstanceOf(PkiLimitError);
    expect(caught).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit });
}

describe('the attributes field (RFC 5755 §4.2.7)', () => {
    it('should keep every value as its DER and the Attribute as encoded', () => {
        const value = roleSyntax();
        const encoded = attribute(OID_ROLE, value);
        const role = first(encoded);
        expect(role.oid).toBe(OID_ROLE);
        expect(role.values).toEqual([value]);
        expect(role.der).toEqual(encoded);
        expect(Object.isFrozen(role)).toBe(true);
    });

    it('should keep an attribute of any other type as unknown — the RFC 3281 clearance OID among them', () => {
        for (const type of ['1.2.3.4', '2.5.1.5.55']) {
            const unknown = first(attribute(type, utf8('x'), integer([1])));
            expect(unknown.kind).toBe('unknown');
            expect(unknown.values).toEqual([utf8('x'), integer([1])]);
        }
    });

    it('should diagnose an empty attributes SEQUENCE as PKI_DIAG_AC_ATTRIBUTES_EMPTY', () => {
        const der = attributeCertificate({ attributes: sequence() });
        const found: PkiDiagnostic[] = [];
        expect(parseAttributeCertificate(der, { onDiagnostic: (d) => found.push(d) }).attributes).toEqual([]);
        expect(found.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_ATTRIBUTES_EMPTY', 'acinfo.attributes']]);
        expect(() => parseAttributeCertificate(der, { strict: true })).toThrow(expect.objectContaining({ code: 'PKI_STRICT_DIAGNOSTIC' }));
    });

    it('should diagnose a repeated attribute type as PKI_DIAG_AC_ATTRIBUTE_DUPLICATE, and return both', () => {
        const { attributes, diagnostics } = read(ROLE_ATTRIBUTE, attribute('1.2.3.4', utf8('x')), ROLE_ATTRIBUTE);
        expect(diagnostics.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_ATTRIBUTE_DUPLICATE', 'acinfo.attributes[2]']]);
        expect(attributes.map((a) => a.kind)).toEqual(['role', 'unknown', 'role']);
        strictRefuses(ROLE_ATTRIBUTE, ROLE_ATTRIBUTE);
    });

    it('should refuse an attributes field that is not a SEQUENCE OF Attribute', () => {
        expect(() => parseAttributeCertificate(attributeCertificate({ attributes: set(ROLE_ATTRIBUTE) }), { onDiagnostic: () => undefined }))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
        refuses('PKI_X509_STRUCTURE_INVALID', integer([1]));
        refuses('PKI_X509_STRUCTURE_INVALID', sequence(oid(OID_ROLE)));
        refuses('PKI_X509_STRUCTURE_INVALID', sequence(oid(OID_ROLE), set(roleSyntax()), integer([1])));
        refuses('PKI_X509_STRUCTURE_INVALID', sequence(integer([1]), set(roleSyntax())));
        refuses('PKI_X509_STRUCTURE_INVALID', sequence(oid(OID_ROLE), sequence(roleSyntax())));
        refuses('PKI_X509_STRUCTURE_INVALID', sequence(oid(OID_ROLE), set()));
    });

    it('should stop at maxAttributes, for the attributes and for the values of each', () => {
        const two = acWithAttributes(attribute('1.2.3.4', utf8('x')), attribute('1.2.3.5', utf8('y')));
        limitTrips(two, { maxAttributes: 1 }, 'maxAttributes');
        expect(parseAttributeCertificate(two, { limits: { maxAttributes: 2 } }).attributes).toHaveLength(2);
        const values = acWithAttributes(attribute('1.2.3.4', utf8('x'), utf8('y')));
        limitTrips(values, { maxAttributes: 1 }, 'maxAttributes');
        expect(parseAttributeCertificate(values, { limits: { maxAttributes: 2 } }).attributes[0]?.values).toHaveLength(2);
    });
});

describe('authenticationInfo and accessIdentity (RFC 5755 §4.4.1, §4.4.2)', () => {
    it('should read a SvceAuthInfo with and without authInfo', () => {
        const auth = first(attribute(OID_AUTHENTICATION_INFO, serviceAuthInfo([1, 2, 3]), serviceAuthInfo()));
        expect(auth.kind).toBe('authenticationInfo');
        const infos = auth.kind === 'authenticationInfo' ? auth.infos : [];
        expect(infos[0]?.service.kind).toBe('uniformResourceIdentifier');
        expect(infos[0]?.ident.kind).toBe('rfc822Name');
        expect(infos[0]?.authInfo).toEqual(Uint8Array.of(1, 2, 3));
        expect(infos[1]?.authInfo).toBeUndefined();
        expect(codes(attribute(OID_AUTHENTICATION_INFO, serviceAuthInfo([1])))).toEqual([]);
    });

    it('should read an accessIdentity, and diagnose one that carries authInfo', () => {
        const access = first(attribute(OID_ACCESS_IDENTITY, serviceAuthInfo()));
        expect(access.kind === 'accessIdentity' && access.identities[0]?.ident.kind).toBe('rfc822Name');
        expect(codes(attribute(OID_ACCESS_IDENTITY, serviceAuthInfo()))).toEqual([]);
        const found = read(attribute(OID_ACCESS_IDENTITY, serviceAuthInfo(), serviceAuthInfo([9]))).diagnostics;
        expect(found.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_ATTRIBUTE_PROFILE', 'acinfo.attributes[0].values[1].authInfo']]);
        expect(found[0]?.message).toContain('§4.4.2');
        strictRefuses(attribute(OID_ACCESS_IDENTITY, serviceAuthInfo([9])));
    });

    it('should refuse a SvceAuthInfo that does not match its syntax', () => {
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_AUTHENTICATION_INFO, integer([1])));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_AUTHENTICATION_INFO, sequence(uriName('https://a.example/'))));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_AUTHENTICATION_INFO, sequence(uriName('https://a.example/'), dnsName('a'), octetString([1]), octetString([2]))));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_ACCESS_IDENTITY, sequence(uriName('https://a.example/'), dnsName('a'), integer([1]))));
        refuses('PKI_X509_GENERAL_NAME_INVALID', attribute(OID_ACCESS_IDENTITY, sequence(integer([1]), dnsName('a'))));
        refuses('PKI_X509_GENERAL_NAME_INVALID', attribute(OID_ACCESS_IDENTITY, sequence(dnsName('a'), integer([1]))));
    });
});

describe('chargingIdentity and group: IetfAttrSyntax (RFC 5755 §4.4, §4.4.3, §4.4.4)', () => {
    it('should refuse an empty roleAuthority: GeneralNames holds at least one name (RFC 5280 §4.2.1.6)', () => {
        refuses('PKI_X509_STRUCTURE_INVALID', attribute(OID_ROLE, roleSyntax(undefined, [])));
    });

    it('should refuse an empty policyAuthority', () => {
        refuses('PKI_X509_STRUCTURE_INVALID', attribute(OID_GROUP, ietfAttrSyntax([utf8('admins')], [])));
    });

    it('should read the three value choices and a policyAuthority', () => {
        const group = first(attribute(OID_GROUP, ietfAttrSyntax([utf8('admins'), utf8('ops')], [uriName('urn:authority')])));
        expect(group.kind).toBe('group');
        const syntax = group.kind === 'group' ? group.syntaxes[0] : undefined;
        expect(syntax?.policyAuthority?.map((n) => n.kind)).toEqual(['uniformResourceIdentifier']);
        expect(syntax?.values).toEqual([{ kind: 'string', value: 'admins' }, { kind: 'string', value: 'ops' }]);
        const charging = first(attribute(OID_CHARGING_IDENTITY, ietfAttrSyntax([octetString([1, 2])])));
        expect(charging.kind === 'chargingIdentity' && charging.syntaxes[0]?.values).toEqual([{ kind: 'octets', value: Uint8Array.of(1, 2) }]);
        expect(charging.kind === 'chargingIdentity' && charging.syntaxes[0]?.policyAuthority).toBeUndefined();
        const oids = first(attribute(OID_GROUP, ietfAttrSyntax([oid('1.2.3'), oid('1.2.4')])));
        expect(oids.kind === 'group' && oids.syntaxes[0]?.values).toEqual([{ kind: 'oid', value: '1.2.3' }, { kind: 'oid', value: '1.2.4' }]);
        expect(codes(attribute(OID_GROUP, ietfAttrSyntax([oid('1.2.3'), oid('1.2.4')])))).toEqual([]);
    });

    it('should diagnose values that mix their choices', () => {
        const found = read(attribute(OID_GROUP, ietfAttrSyntax([utf8('admins'), oid('1.2.3')]))).diagnostics;
        expect(found.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_ATTRIBUTE_PROFILE', 'acinfo.attributes[0].values[0].values']]);
        strictRefuses(attribute(OID_GROUP, ietfAttrSyntax([octetString([1]), utf8('x')])));
    });

    it.each([[OID_CHARGING_IDENTITY], [OID_GROUP]])('should diagnose %s with two attribute values, and read both', (type) => {
        const { attributes, diagnostics } = read(attribute(type, ietfAttrSyntax([utf8('a')]), ietfAttrSyntax([utf8('b')])));
        expect(diagnostics.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_ATTRIBUTE_PROFILE', 'acinfo.attributes[0].values']]);
        const decoded = attributes[0];
        expect(decoded !== undefined && 'syntaxes' in decoded && decoded.syntaxes).toHaveLength(2);
    });

    it('should refuse an IetfAttrSyntax that does not match its syntax', () => {
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, integer([1])));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, sequence()));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, sequence(sequence(utf8('a')), sequence(utf8('b')))));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, sequence(implicitSequence(0, uriName('urn:a')))));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, sequence(implicitSequence(1, uriName('urn:a')), sequence(utf8('a')))));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, sequence(integer([1]))));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, ietfAttrSyntax([integer([1])])));
        refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_GROUP, ietfAttrSyntax([context(4, false, [1])])));
        refuses('PKI_X509_GENERAL_NAME_INVALID', attribute(OID_GROUP, sequence(context(0, false, [1]), sequence(utf8('a')))));
    });

    it('should stop at maxAttributes in the values of an IetfAttrSyntax', () => {
        const der = acWithAttributes(attribute(OID_GROUP, ietfAttrSyntax([utf8('a'), utf8('b'), utf8('c')])));
        limitTrips(der, { maxAttributes: 2 }, 'maxAttributes');
        expect(parseAttributeCertificate(der, { limits: { maxAttributes: 3 } }).attributes).toHaveLength(1);
    });
});

describe('role (RFC 5755 §4.4.5)', () => {
    it('should read a roleName and a roleAuthority', () => {
        const role = first(attribute(OID_ROLE, roleSyntax(uriName('urn:admin'), [uriName('urn:baltimore')]), roleSyntax()));
        const roles = role.kind === 'role' ? role.roles : [];
        expect(roles[0]?.roleName).toMatchObject({ kind: 'uniformResourceIdentifier', value: 'urn:admin' });
        expect(roles[0]?.roleAuthority?.map((n) => n.kind)).toEqual(['uniformResourceIdentifier']);
        expect(roles[1]?.roleAuthority).toBeUndefined();
    });

    it('should diagnose a roleName that is not a URI', () => {
        const found = read(attribute(OID_ROLE, roleSyntax(dnsName('admin.example')))).diagnostics;
        expect(found.map((d) => [d.code, d.path])).toEqual([['PKI_DIAG_AC_ATTRIBUTE_PROFILE', 'acinfo.attributes[0].values[0].roleName']]);
        expect(found[0]?.message).toContain('§4.4.5');
        strictRefuses(attribute(OID_ROLE, roleSyntax(dnsName('admin.example'))));
    });

    it('should refuse a RoleSyntax that does not match its syntax', () => {
        for (const value of [
            integer([1]),
            sequence(),
            sequence(implicitSequence(0, uriName('urn:a'))),
            sequence(implicitSequence(2, uriName('urn:a')), explicit(1, uriName('urn:b'))),
            sequence(implicitSequence(0, uriName('urn:a')), explicit(1, uriName('urn:b')), explicit(2, uriName('urn:c'))),
            sequence(explicit(0, uriName('urn:b'))),
            sequence(context(1, false, [1])),
            sequence(explicit(1, uriName('urn:b'), uriName('urn:c'))),
            sequence(explicit(1)),
        ]) {
            refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_ROLE, value));
        }
        refuses('PKI_X509_GENERAL_NAME_INVALID', attribute(OID_ROLE, sequence(explicit(1, integer([1])))));
    });
});

describe('clearance (RFC 5755 §4.4.6, the X.501 (1997) syntax)', () => {
    const clearanceOf = (...values: Uint8Array[]): ReturnType<typeof read> => read(attribute(OID_CLEARANCE, ...values));

    it('should read a policyId alone with the DEFAULT classList {unclassified}', () => {
        const { attributes, diagnostics } = clearanceOf(clearance());
        expect(diagnostics).toEqual([]);
        const value = attributes[0]?.kind === 'clearance' ? attributes[0].clearances[0] : undefined;
        expect(value?.policyId).toBe('1.2.3.4');
        expect(value?.classList).toEqual(['unclassified']);
        expect(value?.classListBits).toBeUndefined();
        expect(value?.securityCategories).toBeUndefined();
    });

    it('should read the named classes of a classList and keep its bits', () => {
        // unmarked (0), restricted (2), topSecret (5): 1010 01.. — six bits, two unused.
        const { attributes, diagnostics } = clearanceOf(clearance('1.2.3.4', bitString([0xa4], 2)));
        expect(diagnostics).toEqual([]);
        const value = attributes[0]?.kind === 'clearance' ? attributes[0].clearances[0] : undefined;
        expect(value?.classList).toEqual(['unmarked', 'restricted', 'topSecret']);
        expect(value?.classListBits).toEqual({ bytes: Uint8Array.of(0xa4), unusedBits: 2 });
    });

    it('should keep a policy-defined class beyond bit 5 in the bits only', () => {
        // confidential (3) and bit 9: 0001 0000 01.. ....
        const value = clearanceOf(clearance('1.2.3.4', bitString([0x10, 0x40], 6))).attributes[0];
        expect(value?.kind === 'clearance' && value.clearances[0]?.classList).toEqual(['confidential']);
    });

    it('should read every named class', () => {
        const value = clearanceOf(clearance('1.2.3.4', bitString([0xfc], 2))).attributes[0];
        expect(value?.kind === 'clearance' && value.clearances[0]?.classList).toEqual(['unmarked', 'unclassified', 'restricted', 'confidential', 'secret', 'topSecret']);
    });

    it('should read an empty classList as no class, with no diagnostic', () => {
        const { attributes, diagnostics } = clearanceOf(clearance('1.2.3.4', bitString([])));
        const value = attributes[0];
        expect(value?.kind === 'clearance' && value.clearances[0]?.classList).toEqual([]);
        expect(diagnostics).toEqual([]);
    });

    it('should diagnose a one-bit classList whose only bit is zero as a trailing zero', () => {
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x00], 7))).diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_NAMED_BITS_TRAILING_ZERO']);
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x80], 7))).diagnostics).toEqual([]);
    });

    it('should not read the padding bits of a BER classList as classes', () => {
        // secret (4) set; the three padding bits are 1 under BER.
        const der = acWithAttributes(attribute(OID_CLEARANCE, clearance('1.2.3.4', bitString([0x0f], 3))));
        const ac = parseAttributeCertificate(der, { encodingRules: 'ber', onDiagnostic: () => undefined });
        const value = ac.attributes[0];
        expect(value?.kind === 'clearance' && value.clearances[0]?.classList).toEqual(['secret']);
    });

    it('should diagnose a classList with trailing zero bits, and one that encodes its DEFAULT', () => {
        // {unclassified} with its six trailing zero bits kept: both DER rules broken.
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x40], 0))).diagnostics.map((d) => [d.code, d.path])).toEqual([
            ['PKI_DIAG_NAMED_BITS_TRAILING_ZERO', 'acinfo.attributes[0].values[0].classList'],
            ['PKI_DIAG_DEFAULT_ENCODED', 'acinfo.attributes[0].values[0].classList'],
        ]);
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x60], 1))).diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_NAMED_BITS_TRAILING_ZERO']);
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x40], 6))).diagnostics.map((d) => [d.code, d.path]))
            .toEqual([['PKI_DIAG_DEFAULT_ENCODED', 'acinfo.attributes[0].values[0].classList']]);
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x20], 5))).diagnostics).toEqual([]);
        expect(clearanceOf(clearance('1.2.3.4', bitString([0x40, 0x00], 6))).diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_NAMED_BITS_TRAILING_ZERO']);
    });

    it('should read security categories, with and without a classList', () => {
        const categories = set(securityCategory(), securityCategory('1.2.3.6', integer([5])));
        for (const value of [clearance('1.2.3.4', undefined, categories), clearance('1.2.3.4', bitString([0x20], 5), categories)]) {
            const { attributes, diagnostics } = clearanceOf(value);
            expect(diagnostics).toEqual([]);
            const decoded = attributes[0]?.kind === 'clearance' ? attributes[0].clearances[0] : undefined;
            expect(decoded?.securityCategories).toEqual([{ type: '1.2.3.5', value: utf8('need-to-know') }, { type: '1.2.3.6', value: integer([5]) }]);
        }
    });

    it('should refuse a Clearance that does not match its syntax', () => {
        for (const value of [
            integer([1]),
            sequence(),
            sequence(integer([1])),
            sequence(oid('1.2.3.4'), bitString([0x20], 5), set(securityCategory()), integer([1])),
            sequence(oid('1.2.3.4'), integer([1])),
            sequence(oid('1.2.3.4'), set(securityCategory()), set(securityCategory())),
            clearance('1.2.3.4', undefined, set(integer([1]))),
            clearance('1.2.3.4', undefined, set(sequence(context(0, false, [0x2a])))),
            clearance('1.2.3.4', undefined, set(sequence(oid('1.2.3'), explicit(1, utf8('x'))))),
            clearance('1.2.3.4', undefined, set(sequence(context(1, false, [0x2a]), explicit(1, utf8('x'))))),
            clearance('1.2.3.4', undefined, set(sequence(context(0, false, [0x2a]), context(1, false, [1])))),
            clearance('1.2.3.4', undefined, set(sequence(context(0, false, [0x2a]), explicit(2, utf8('x'))))),
            clearance('1.2.3.4', undefined, set(sequence(context(0, false, [0x2a]), explicit(1, utf8('x'), utf8('y'))))),
            clearance('1.2.3.4', undefined, set(sequence(context(0, false, [0x2a]), explicit(1)))),
            clearance('1.2.3.4', undefined, set(sequence(context(0, false, [0x2a]), explicit(1, utf8('x')), utf8('z')))),
        ]) {
            refuses('PKI_X509_ATTRIBUTE_MALFORMED', attribute(OID_CLEARANCE, value));
        }
    });

    it('should stop at maxAttributes in the security categories', () => {
        const der = acWithAttributes(attribute(OID_CLEARANCE, clearance('1.2.3.4', undefined, set(securityCategory(), securityCategory('1.2.3.7')))));
        limitTrips(der, { maxAttributes: 1 }, 'maxAttributes');
        expect(parseAttributeCertificate(der, { limits: { maxAttributes: 2 } }).attributes).toHaveLength(1);
    });

    it('should refuse a security category type that is not an OBJECT IDENTIFIER in primitive form', () => {
        const der = acWithAttributes(attribute(OID_CLEARANCE, clearance('1.2.3.4', undefined, set(sequence(tlv(2, true, 0, universal(6, [0x2a])), explicit(1, utf8('x')))))));
        expect(() => parseAttributeCertificate(der, { onDiagnostic: () => undefined })).toThrow(expect.objectContaining({ code: 'PKI_ASN1_CONSTRUCTED_FORM_INVALID' }));
    });
});
