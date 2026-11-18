/**
 * Synthetic RFC 5755 attribute certificates, built TLV by TLV on
 * raw-der-builder.ts and the field helpers of cert-builder.ts. It NEVER
 * imports src/: a reader tested only against its own encoder proves nothing.
 * Every part can be replaced to build the hostile variant a test needs; the
 * defaults form a well-formed, diagnostic-free v2 AC — a holder by
 * baseCertificateID, a v2Form issuer naming one directoryName, one role
 * attribute, an authorityKeyIdentifier and a critical targetInformation.
 *
 * Tagging follows the RFC 5755 Appendix B module, DEFINITIONS IMPLICIT TAGS:
 * a tagged SEQUENCE drops its universal tag, a tagged CHOICE (GeneralName)
 * keeps it under an explicit tag.
 */

import {
    algorithm,
    bitString,
    context,
    ECDSA_SHA256,
    explicit,
    extension,
    generalizedTime,
    integer,
    name,
    nullValue,
    octetString,
    oid,
    printable,
    set,
    utf8,
} from './cert-builder.js';
import { ascii, concat, sequence, tlv, universal } from './raw-der-builder.js';

export const OID_ROLE = '2.5.4.72';
export const OID_CLEARANCE = '2.5.4.55';
export const OID_AUTHENTICATION_INFO = '1.3.6.1.5.5.7.10.1';
export const OID_ACCESS_IDENTITY = '1.3.6.1.5.5.7.10.2';
export const OID_CHARGING_IDENTITY = '1.3.6.1.5.5.7.10.3';
export const OID_GROUP = '1.3.6.1.5.5.7.10.4';
export const OID_AUDIT_IDENTITY = '1.3.6.1.5.5.7.1.4';
export const OID_TARGET_INFORMATION = '2.5.29.55';
export const OID_NO_REV_AVAIL = '2.5.29.56';

/** The constructed context tag of an implicitly tagged SEQUENCE: its components, without the universal SEQUENCE header. */
export const implicitSequence = (tagNumber: number, ...components: ReadonlyArray<ArrayLike<number>>): Uint8Array => tlv(2, true, tagNumber, concat(...components));

// ── GeneralName ──────────────────────────────────────────────────────

export const dnsName = (text: string): Uint8Array => context(2, false, ascii(text));
export const uriName = (text: string): Uint8Array => context(6, false, ascii(text));
export const rfc822Name = (text: string): Uint8Array => context(1, false, ascii(text));
/** A directoryName: a Name under the explicit [4] tag (a Name is a CHOICE). */
export const directoryName = (encodedName: Uint8Array): Uint8Array => explicit(4, encodedName);
/** GeneralNames: a SEQUENCE OF GeneralName. */
export const generalNames = (...names: ReadonlyArray<ArrayLike<number>>): Uint8Array => sequence(...names);

export const ISSUER_NAME = name([['2.5.4.6', printable('US')]], [['2.5.4.10', utf8('pkinative test')]], [['2.5.4.3', utf8('AC Issuer')]]);
export const CA_NAME = name([['2.5.4.6', printable('US')]], [['2.5.4.3', utf8('Test Root')]]);

// ── Holder, issuer, references ───────────────────────────────────────

/** The components of an IssuerSerial: issuer GeneralNames, serial and an optional issuerUID. */
export function issuerSerialComponents(issuer: Uint8Array = generalNames(directoryName(CA_NAME)), serial: Uint8Array = integer([0x10]), issuerUid?: Uint8Array): Uint8Array[] {
    return issuerUid === undefined ? [issuer, serial] : [issuer, serial, issuerUid];
}

/** The components of an ObjectDigestInfo: an ENUMERATED type, an optional OID, the digest algorithm and the digest. */
export function objectDigestComponents(type = 0, otherType?: string): Uint8Array[] {
    const parts = [universal(10, [type])];
    if (otherType !== undefined) parts.push(oid(otherType));
    parts.push(algorithm('2.16.840.1.101.3.4.2.1'), bitString(Array.from({ length: 32 }, (_, i) => i)));
    return parts;
}

export const holderByCertificate = (...components: Uint8Array[]): Uint8Array =>
    sequence(implicitSequence(0, ...(components.length === 0 ? issuerSerialComponents() : components)));

export const holderByName = (...names: Uint8Array[]): Uint8Array =>
    sequence(implicitSequence(1, ...(names.length === 0 ? [rfc822Name('alice@example.com')] : names)));

export const holderByDigest = (...components: Uint8Array[]): Uint8Array =>
    sequence(implicitSequence(2, ...(components.length === 0 ? objectDigestComponents() : components)));

/** A v2Form issuer: `[0]` over issuerName and the optional `[0]` baseCertificateID and `[1]` objectDigestInfo. */
export const v2Form = (...components: Uint8Array[]): Uint8Array =>
    implicitSequence(0, ...(components.length === 0 ? [generalNames(directoryName(ISSUER_NAME))] : components));

// ── Attributes ───────────────────────────────────────────────────────

export const attribute = (dotted: string, ...values: Uint8Array[]): Uint8Array => sequence(oid(dotted), set(...values));

/** RoleSyntax: an optional roleAuthority [0] GeneralNames and roleName [1] GeneralName (explicit). */
export function roleSyntax(roleName: Uint8Array = uriName('urn:role:administrator'), authority?: Uint8Array[]): Uint8Array {
    return authority === undefined ? sequence(explicit(1, roleName)) : sequence(implicitSequence(0, ...authority), explicit(1, roleName));
}

export const ROLE_ATTRIBUTE = attribute(OID_ROLE, roleSyntax());

/** SvceAuthInfo: service, ident and an optional authInfo. */
export function serviceAuthInfo(authInfo?: number[]): Uint8Array {
    const parts = [uriName('https://service.example/'), rfc822Name('alice@example.com')];
    if (authInfo !== undefined) parts.push(octetString(authInfo));
    return sequence(...parts);
}

/** IetfAttrSyntax: an optional policyAuthority [0] and the SEQUENCE OF values. */
export function ietfAttrSyntax(values: Uint8Array[], authority?: Uint8Array[]): Uint8Array {
    return authority === undefined ? sequence(sequence(...values)) : sequence(implicitSequence(0, ...authority), sequence(...values));
}

/** Clearance (X.501 1997): policyId, an optional classList and optional securityCategories. */
export function clearance(policy = '1.2.3.4', classList?: Uint8Array, categories?: Uint8Array): Uint8Array {
    const parts = [oid(policy)];
    if (classList !== undefined) parts.push(classList);
    if (categories !== undefined) parts.push(categories);
    return sequence(...parts);
}

/** SecurityCategory: type [0] IMPLICIT OBJECT IDENTIFIER, value [1] EXPLICIT. */
export function securityCategory(type = '1.2.3.5', value: Uint8Array = utf8('need-to-know')): Uint8Array {
    const encoded = oid(type);
    return sequence(context(0, false, encoded.subarray(2)), explicit(1, value));
}

// ── Extensions ───────────────────────────────────────────────────────

export const AUTHORITY_KEY_ID = extension('2.5.29.35', sequence(context(0, false, [0x0a, 0x0b, 0x0c, 0x0d])));
export const targetName = (generalName: Uint8Array): Uint8Array => explicit(0, generalName);
export const targetGroup = (generalName: Uint8Array): Uint8Array => explicit(1, generalName);
export const TARGET_INFORMATION = extension(OID_TARGET_INFORMATION, sequence(sequence(targetName(dnsName('server.example')))), true);
export const NO_REV_AVAIL = extension(OID_NO_REV_AVAIL, nullValue());

// ── The attribute certificate ────────────────────────────────────────

export interface AcInfoParts {
    /** `null` omits the field. */
    readonly version?: Uint8Array | null;
    readonly holder?: Uint8Array;
    readonly issuer?: Uint8Array;
    readonly signature?: Uint8Array;
    readonly serialNumber?: Uint8Array;
    readonly validity?: Uint8Array;
    readonly attributes?: Uint8Array;
    /** Everything after the attributes: the issuerUniqueID and the extensions. */
    readonly trailing?: readonly Uint8Array[];
}

export const VALIDITY = sequence(generalizedTime('20260101000000Z'), generalizedTime('20270101000000Z'));
export const EXTENSIONS = sequence(AUTHORITY_KEY_ID, TARGET_INFORMATION);

export function acInfo(parts: AcInfoParts = {}): Uint8Array {
    const fields: Uint8Array[] = [];
    const version = parts.version === undefined ? integer([1]) : parts.version;
    if (version !== null) fields.push(version);
    fields.push(
        parts.holder ?? holderByCertificate(),
        parts.issuer ?? v2Form(),
        parts.signature ?? algorithm(ECDSA_SHA256),
        parts.serialNumber ?? integer([0x01, 0x23]),
        parts.validity ?? VALIDITY,
        parts.attributes ?? sequence(ROLE_ATTRIBUTE),
        ...(parts.trailing ?? [EXTENSIONS]),
    );
    return sequence(...fields);
}

export interface AttributeCertificateParts extends AcInfoParts {
    readonly info?: Uint8Array;
    readonly signatureAlgorithm?: Uint8Array;
    readonly signatureValue?: Uint8Array;
}

export function attributeCertificate(parts: AttributeCertificateParts = {}): Uint8Array {
    return sequence(
        parts.info ?? acInfo(parts),
        parts.signatureAlgorithm ?? algorithm(ECDSA_SHA256),
        parts.signatureValue ?? bitString([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
    );
}

/** An AC whose acinfo carries one extra attribute list, for the attribute suites. */
export const acWithAttributes = (...attributes: Uint8Array[]): Uint8Array => attributeCertificate({ attributes: sequence(...attributes) });
