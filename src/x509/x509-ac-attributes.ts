/**
 * pkinative — Attribute certificate attributes
 * ============================================
 * The `attributes` of an RFC 5755 attribute certificate (§4.2.7) and the six
 * attribute types of §4.4: authenticationInfo, accessIdentity,
 * chargingIdentity, group, role and clearance. The walk follows the one of
 * subjectDirectoryAttributes — a SEQUENCE OF Attribute, each a type and a
 * non-empty SET OF values, both bounded by `maxAttributes` (ADR 0027) — and
 * keeps every value's DER. A recognised attribute whose value does not match
 * its syntax throws `PKI_X509_ATTRIBUTE_MALFORMED`; what its syntax admits and
 * its profile forbids is `PKI_DIAG_AC_ATTRIBUTE_PROFILE`. Any other type is
 * kept as `kind: 'unknown'` — the RFC 3281 clearance (2.5.1.5.55) among them
 * (ADR 0028).
 *
 * @module x509/x509-ac-attributes
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readOctetString, _readString } from '../asn1/asn1-read.js';
import { TAG_BIT_STRING, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, TAG_UTF8_STRING, tagLabel } from '../asn1/asn1-tags.js';
import {
    acAttributeDuplicateDiagnostic,
    acAttributeProfileDiagnostic,
    acAttributesEmptyDiagnostic,
    defaultEncodedDiagnostic,
    namedBitsTrailingZeroDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, BitString } from '../types/asn1-types.js';
import type {
    AttributeCertificateAttribute,
    ClassListName,
    Clearance,
    IetfAttrSyntax,
    IetfAttrValue,
    RoleSyntax,
    SecurityCategory,
    ServiceAuthInfo,
} from '../types/attribute-certificate-types.js';
import type { PkiCertificateError } from '../types/pki-errors.js';
import { certificateError, expectUniversalField } from './x509-fields.js';
import { _readGeneralName, _readGeneralNameList } from './x509-general-name.js';

const MALFORMED = 'PKI_X509_ATTRIBUTE_MALFORMED';
const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';

const OID_AUTHENTICATION_INFO = '1.3.6.1.5.5.7.10.1';
const OID_ACCESS_IDENTITY = '1.3.6.1.5.5.7.10.2';
const OID_CHARGING_IDENTITY = '1.3.6.1.5.5.7.10.3';
const OID_GROUP = '1.3.6.1.5.5.7.10.4';
const OID_ROLE = '2.5.4.72';
const OID_CLEARANCE = '2.5.4.55';

/** ClassList, bits 0 to 5 (RFC 5755 §4.4.6). */
const CLASS_NAMES: readonly ClassListName[] = /*#__PURE__*/ Object.freeze(['unmarked', 'unclassified', 'restricted', 'confidential', 'secret', 'topSecret']);
const DEFAULT_CLASS_LIST: readonly ClassListName[] = /*#__PURE__*/ Object.freeze<ClassListName[]>(['unclassified']);

function malformed(path: string, offset: number, why: string): PkiCertificateError {
    return certificateError(MALFORMED, path, offset, why);
}

function expectField(node: Asn1Node | undefined, tag: number, path: string, parentOffset: number): Asn1Node {
    return expectUniversalField(node, tag, path, MALFORMED, parentOffset);
}

// ── SvceAuthInfo (§4.4.1, §4.4.2) ────────────────────────────────────

function readServiceAuthInfo(node: Asn1Node, ctx: Asn1Context, path: string): ServiceAuthInfo {
    const seq = expectField(node, TAG_SEQUENCE, path, node.offset);
    if (seq.children.length < 2 || seq.children.length > 3) {
        throw malformed(path, seq.offset, `holds ${String(seq.children.length)} values; SvceAuthInfo is service, ident and an optional authInfo`);
    }
    const service = _readGeneralName(seq.children[0] as Asn1Node, ctx, `${path}.service`, false);
    const ident = _readGeneralName(seq.children[1] as Asn1Node, ctx, `${path}.ident`, false);
    const authNode = seq.children[2];
    const authInfo = authNode === undefined ? undefined : _readOctetString(expectField(authNode, TAG_OCTET_STRING, `${path}.authInfo`, seq.offset), ctx);
    const info: ServiceAuthInfo = { service, ident, authInfo };
    return Object.freeze(info);
}

// ── IetfAttrSyntax (§4.4) ────────────────────────────────────────────

function readIetfAttrValue(node: Asn1Node, ctx: Asn1Context, path: string): IetfAttrValue {
    if (node.tagClass === 'universal') {
        if (node.tagNumber === TAG_OCTET_STRING) return Object.freeze({ kind: 'octets', value: _readOctetString(node, ctx) });
        if (node.tagNumber === TAG_OID) return Object.freeze({ kind: 'oid', value: _readObjectIdentifier(node, ctx) });
        if (node.tagNumber === TAG_UTF8_STRING) return Object.freeze({ kind: 'string', value: _readString(node, ctx, undefined, path).value });
    }
    throw malformed(path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; an IetfAttrSyntax value is an OCTET STRING, an OBJECT IDENTIFIER or a UTF8String`);
}

function readIetfAttrSyntax(node: Asn1Node, ctx: Asn1Context, path: string): IetfAttrSyntax {
    const seq = expectField(node, TAG_SEQUENCE, path, node.offset);
    const first = seq.children[0];
    const hasAuthority = first !== undefined && first.tagClass === 'context' && first.tagNumber === 0;
    if (seq.children.length !== (hasAuthority ? 2 : 1)) {
        throw malformed(path, seq.offset, `holds ${String(seq.children.length)} values; IetfAttrSyntax is an optional policyAuthority [0] and the values`);
    }
    const policyAuthority = hasAuthority ? _readGeneralNameList(first, ctx, `${path}.policyAuthority`, false) : undefined;
    const list = expectField(seq.children[hasAuthority ? 1 : 0], TAG_SEQUENCE, `${path}.values`, seq.offset);
    enforceLimit(ctx.limits, 'maxAttributes', list.children.length, `the values of ${path}`);
    const values: IetfAttrValue[] = [];
    for (let i = 0; i < list.children.length; i++) values.push(readIetfAttrValue(list.children[i] as Asn1Node, ctx, `${path}.values[${String(i)}]`));
    // §4.4: "each value MUST use the same choice of value syntax".
    if (new Set(values.map((v) => v.kind)).size > 1) {
        ctx.emitter.emit(acAttributeProfileDiagnostic('the IetfAttrSyntax values mix the octets, oid and string choices', '§4.4', `${path}.values`, list.offset));
    }
    const syntax: IetfAttrSyntax = { policyAuthority, values: Object.freeze(values) };
    return Object.freeze(syntax);
}

// ── RoleSyntax (§4.4.5) ──────────────────────────────────────────────

function readRoleSyntax(node: Asn1Node, ctx: Asn1Context, path: string): RoleSyntax {
    const seq = expectField(node, TAG_SEQUENCE, path, node.offset);
    const [authorityNode, nameNode] = seq.children.length === 1 ? [undefined, seq.children[0]] : seq.children;
    if (seq.children.length > 2 || (authorityNode !== undefined && (authorityNode.tagClass !== 'context' || authorityNode.tagNumber !== 0))) {
        throw malformed(path, seq.offset, 'is not RoleSyntax: an optional roleAuthority [0] followed by roleName [1]');
    }
    if (nameNode === undefined || nameNode.tagClass !== 'context' || nameNode.tagNumber !== 1 || !nameNode.constructed || nameNode.children.length !== 1) {
        throw malformed(`${path}.roleName`, seq.offset, 'is missing or is not one GeneralName under the explicit [1] tag');
    }
    const roleAuthority = authorityNode === undefined ? undefined : _readGeneralNameList(authorityNode, ctx, `${path}.roleAuthority`, false);
    const roleName = _readGeneralName(nameNode.children[0] as Asn1Node, ctx, `${path}.roleName`, false);
    if (roleName.kind !== 'uniformResourceIdentifier') {
        ctx.emitter.emit(acAttributeProfileDiagnostic(`the roleName is a ${roleName.kind}, not a uniformResourceIdentifier`, '§4.4.5', `${path}.roleName`, nameNode.offset));
    }
    const role: RoleSyntax = { roleAuthority, roleName };
    return Object.freeze(role);
}

// ── Clearance (§4.4.6) ───────────────────────────────────────────────

/** The named classes of bits 0 to 5; a class a policy defines beyond them stays in `classListBits`. */
function readClassList(bits: BitString, ctx: Asn1Context, path: string, offset: number): readonly ClassListName[] {
    const total = bits.bytes.length * 8 - bits.unusedBits;
    const first = bits.bytes[0] ?? 0;
    const classes = CLASS_NAMES.filter((_, i) => i < total && ((first >> (7 - i)) & 1) === 1);
    // X.690 §11.2.2: a named bit list drops its trailing zero bits under DER.
    const last = bits.bytes[bits.bytes.length - 1] ?? 0;
    if (total > 0 && ((last >> bits.unusedBits) & 1) === 0) ctx.emitter.emit(namedBitsTrailingZeroDiagnostic(path, offset));
    return Object.freeze(classes);
}

function readSecurityCategories(node: Asn1Node, ctx: Asn1Context, path: string): readonly SecurityCategory[] {
    enforceLimit(ctx.limits, 'maxAttributes', node.children.length, `the security categories of ${path}`);
    const categories: SecurityCategory[] = [];
    for (let i = 0; i < node.children.length; i++) {
        const at = `${path}[${String(i)}]`;
        const seq = expectField(node.children[i], TAG_SEQUENCE, at, node.offset);
        const [typeNode, valueNode] = seq.children;
        if (seq.children.length !== 2 || typeNode?.tagClass !== 'context' || typeNode.tagNumber !== 0) {
            throw malformed(at, seq.offset, 'is not a SecurityCategory: type [0] and value [1]');
        }
        if (valueNode?.tagClass !== 'context' || valueNode.tagNumber !== 1 || !valueNode.constructed || valueNode.children.length !== 1) {
            throw malformed(`${at}.value`, seq.offset, 'is not one value under the explicit [1] tag');
        }
        categories.push(Object.freeze({ type: _readObjectIdentifier(typeNode, ctx), value: (valueNode.children[0] as Asn1Node).bytes }));
    }
    return Object.freeze(categories);
}

function readClearance(node: Asn1Node, ctx: Asn1Context, path: string): Clearance {
    const seq = expectField(node, TAG_SEQUENCE, path, node.offset);
    const policyId = _readObjectIdentifier(expectField(seq.children[0], TAG_OID, `${path}.policyId`, seq.offset), ctx);
    let index = 1;
    let classList = DEFAULT_CLASS_LIST;
    let classListBits: BitString | undefined;
    const bitsNode = seq.children[index];
    if (bitsNode !== undefined && bitsNode.tagClass === 'universal' && bitsNode.tagNumber === TAG_BIT_STRING) {
        classListBits = _readBitString(bitsNode, ctx);
        classList = readClassList(classListBits, ctx, `${path}.classList`, bitsNode.offset);
        // X.690 §11.5: DER omits a value equal to its DEFAULT, {unclassified}.
        if (classListBits.bytes.length === 1 && classListBits.bytes[0] === 0x40) ctx.emitter.emit(defaultEncodedDiagnostic(`${path}.classList`, '{unclassified}', bitsNode.offset));
        index++;
    }
    let securityCategories: readonly SecurityCategory[] | undefined;
    if (index < seq.children.length) {
        securityCategories = readSecurityCategories(expectField(seq.children[index], TAG_SET, `${path}.securityCategories`, seq.offset), ctx, `${path}.securityCategories`);
        index++;
    }
    if (index !== seq.children.length) {
        throw malformed(path, seq.offset, `holds ${String(seq.children.length)} values; Clearance is policyId, an optional classList and optional securityCategories`);
    }
    const clearance: Clearance = { policyId, classList, classListBits, securityCategories };
    return Object.freeze(clearance);
}

// ── Attributes ───────────────────────────────────────────────────────

/** One decoded attribute value, from its node, under its `values[i]` path. */
type ValueDecoder<T> = (node: Asn1Node, ctx: Asn1Context, path: string) => T;

function decodeEach<T>(values: readonly Asn1Node[], ctx: Asn1Context, path: string, decode: ValueDecoder<T>): readonly T[] {
    return Object.freeze(values.map((value, i) => decode(value, ctx, `${path}.values[${String(i)}]`)));
}

/** §4.4.3, §4.4.4: "One Attribute value only; multiple values within the IetfAttrSyntax". */
function singleValued(values: readonly Asn1Node[], ctx: Asn1Context, path: string, name: string, clause: string, offset: number): void {
    if (values.length > 1) ctx.emitter.emit(acAttributeProfileDiagnostic(`${name} carries ${String(values.length)} attribute values; it allows one`, clause, `${path}.values`, offset));
}

function decodeAttribute(oid: string, attribute: Asn1Node, values: Asn1Node, ctx: Asn1Context, path: string): AttributeCertificateAttribute {
    const base = { oid, values: Object.freeze(values.children.map((v) => v.bytes)), der: attribute.bytes };
    switch (oid) {
        case OID_AUTHENTICATION_INFO:
            return Object.freeze({ ...base, kind: 'authenticationInfo', infos: decodeEach(values.children, ctx, path, readServiceAuthInfo) });
        case OID_ACCESS_IDENTITY: {
            const identities = decodeEach(values.children, ctx, path, readServiceAuthInfo);
            identities.forEach((identity, i) => {
                if (identity.authInfo !== undefined) {
                    ctx.emitter.emit(acAttributeProfileDiagnostic('an accessIdentity carries authInfo', '§4.4.2', `${path}.values[${String(i)}].authInfo`, (values.children[i] as Asn1Node).offset));
                }
            });
            return Object.freeze({ ...base, kind: 'accessIdentity', identities });
        }
        case OID_CHARGING_IDENTITY:
            singleValued(values.children, ctx, path, 'chargingIdentity', '§4.4.3', values.offset);
            return Object.freeze({ ...base, kind: 'chargingIdentity', syntaxes: decodeEach(values.children, ctx, path, readIetfAttrSyntax) });
        case OID_GROUP:
            singleValued(values.children, ctx, path, 'group', '§4.4.4', values.offset);
            return Object.freeze({ ...base, kind: 'group', syntaxes: decodeEach(values.children, ctx, path, readIetfAttrSyntax) });
        case OID_ROLE:
            return Object.freeze({ ...base, kind: 'role', roles: decodeEach(values.children, ctx, path, readRoleSyntax) });
        case OID_CLEARANCE:
            return Object.freeze({ ...base, kind: 'clearance', clearances: decodeEach(values.children, ctx, path, readClearance) });
        default:
            return Object.freeze({ ...base, kind: 'unknown' });
    }
}

/**
 * The `attributes` SEQUENCE OF Attribute of an AttributeCertificateInfo
 * (RFC 5755 §4.1, §4.2.7).
 *
 * @internal
 */
export function _readAcAttributes(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): readonly AttributeCertificateAttribute[] {
    const path = 'acinfo.attributes';
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, STRUCTURE, parentOffset);
    if (seq.children.length === 0) ctx.emitter.emit(acAttributesEmptyDiagnostic(seq.offset));
    enforceLimit(ctx.limits, 'maxAttributes', seq.children.length, `the attributes of ${path}`);
    const seen = new Set<string>();
    const attributes: AttributeCertificateAttribute[] = [];
    for (let i = 0; i < seq.children.length; i++) {
        const at = `${path}[${String(i)}]`;
        const attribute = expectUniversalField(seq.children[i], TAG_SEQUENCE, at, STRUCTURE, seq.offset);
        if (attribute.children.length !== 2) {
            throw certificateError(STRUCTURE, at, attribute.offset, `holds ${String(attribute.children.length)} values; an Attribute is a type and a SET of values`);
        }
        const oid = _readObjectIdentifier(expectUniversalField(attribute.children[0], TAG_OID, `${at}.type`, STRUCTURE, attribute.offset), ctx);
        const values = expectUniversalField(attribute.children[1], TAG_SET, `${at}.values`, STRUCTURE, attribute.offset);
        // RFC 5755 §4.1: "at least one value is required".
        if (values.children.length === 0) throw certificateError(STRUCTURE, `${at}.values`, values.offset, 'is empty; an attribute carries at least one value');
        enforceLimit(ctx.limits, 'maxAttributes', values.children.length, `the values of ${at}`);
        if (seen.has(oid)) ctx.emitter.emit(acAttributeDuplicateDiagnostic(oid, at, attribute.offset));
        seen.add(oid);
        attributes.push(decodeAttribute(oid, attribute, values, ctx, at));
    }
    return Object.freeze(attributes);
}
