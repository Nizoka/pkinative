/**
 * pkinative — Policy extensions
 * =============================
 * certificatePolicies with CPS and user notice qualifiers, and
 * policyMappings (RFC 5280 §4.2.1.4, §4.2.1.5). A policy listed twice is a
 * diagnostic; qualifiers of other types are kept undecoded.
 *
 * @module x509/x509-ext-policies
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readInteger, _readString } from '../asn1/asn1-read.js';
import { TAG_INTEGER, TAG_OID, TAG_SEQUENCE, stringTypeOfTag, tagLabel } from '../asn1/asn1-tags.js';
import { policyDuplicateDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, Asn1String, Asn1StringType } from '../types/asn1-types.js';
import type {
    CertificatePoliciesExtension,
    CpsQualifier,
    NoticeReference,
    PolicyInformation,
    PolicyMapping,
    PolicyMappingsExtension,
    PolicyQualifier,
    UnknownPolicyQualifier,
    UserNoticeQualifier,
} from '../types/x509-types.js';
import { MALFORMED, baseOf, expectNonEmpty, expectSequence, malformed, type ExtensionInput } from './x509-ext-shared.js';
import { expectUniversalField } from './x509-fields.js';

const OID_CPS = '1.3.6.1.5.5.7.2.1';
const OID_USER_NOTICE = '1.3.6.1.5.5.7.2.2';
const DISPLAY_TEXT: ReadonlySet<Asn1StringType> = /*#__PURE__*/ new Set<Asn1StringType>(['ia5', 'visible', 'bmp', 'utf8']);

function readOid(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): string {
    return _readObjectIdentifier(expectUniversalField(node, TAG_OID, path, MALFORMED, parentOffset), ctx);
}

function readText(node: Asn1Node, ctx: Asn1Context, path: string, allowed: ReadonlySet<Asn1StringType>, what: string): Asn1String {
    if (node.tagClass !== 'universal' || stringTypeOfTag(node.tagNumber) === undefined) {
        throw malformed(path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; expected ${what}`);
    }
    const text = _readString(node, ctx, undefined, path);
    if (!allowed.has(text.stringType)) throw malformed(path, node.offset, `is a ${text.stringType} string; expected ${what}`);
    return text;
}

const displayText = (node: Asn1Node, ctx: Asn1Context, path: string): Asn1String =>
    readText(node, ctx, path, DISPLAY_TEXT, 'DisplayText: an IA5String, VisibleString, BMPString or UTF8String');

function readNoticeReference(node: Asn1Node, ctx: Asn1Context, path: string): NoticeReference {
    const seq = expectSequence(node, path, node.offset);
    if (seq.children.length !== 2) throw malformed(path, seq.offset, `holds ${seq.children.length} values; a NoticeReference is an organization and its notice numbers`);
    const organization = displayText(seq.children[0] as Asn1Node, ctx, `${path}.organization`);
    const numbers = expectSequence(seq.children[1], `${path}.noticeNumbers`, seq.offset);
    enforceLimit(ctx.limits, 'maxPolicies', numbers.children.length, `the notice numbers of ${path}`);
    const noticeNumbers = numbers.children.map((child, i) => _readInteger(expectUniversalField(child, TAG_INTEGER, `${path}.noticeNumbers[${i}]`, MALFORMED, numbers.offset), ctx));
    const reference: NoticeReference = { organization, noticeNumbers: Object.freeze(noticeNumbers) };
    return Object.freeze(reference);
}

function readUserNotice(oid: string, node: Asn1Node, ctx: Asn1Context, path: string): UserNoticeQualifier {
    const seq = expectSequence(node, path, node.offset);
    let index = 0;
    let noticeRef: NoticeReference | undefined;
    const first = seq.children[0];
    if (first !== undefined && first.tagClass === 'universal' && first.tagNumber === TAG_SEQUENCE) {
        noticeRef = readNoticeReference(first, ctx, `${path}.noticeRef`);
        index = 1;
    }
    let explicitText: Asn1String | undefined;
    const text = seq.children[index];
    if (text !== undefined) {
        explicitText = displayText(text, ctx, `${path}.explicitText`);
        index++;
    }
    if (index !== seq.children.length) throw malformed(path, seq.offset, `holds ${seq.children.length} values; a UserNotice is an optional noticeRef and an optional explicitText`);
    const qualifier: UserNoticeQualifier = { kind: 'userNotice', oid, noticeRef, explicitText };
    return Object.freeze(qualifier);
}

function readQualifier(node: Asn1Node, ctx: Asn1Context, path: string): PolicyQualifier {
    const seq = expectSequence(node, path, node.offset);
    if (seq.children.length !== 2) throw malformed(path, seq.offset, `holds ${seq.children.length} values; a PolicyQualifierInfo is a qualifier OID and its qualifier`);
    const oid = readOid(seq.children[0], ctx, `${path}.policyQualifierId`, seq.offset);
    const value = seq.children[1] as Asn1Node;
    if (oid === OID_CPS) {
        const uri = readText(value, ctx, `${path}.qualifier`, new Set<Asn1StringType>(['ia5']), 'a CPSuri IA5String').value;
        const qualifier: CpsQualifier = { kind: 'cps', oid, uri };
        return Object.freeze(qualifier);
    }
    if (oid === OID_USER_NOTICE) return readUserNotice(oid, value, ctx, `${path}.qualifier`);
    const qualifier: UnknownPolicyQualifier = { kind: 'unknown', oid, qualifier: value };
    return Object.freeze(qualifier);
}

function readPolicy(node: Asn1Node, ctx: Asn1Context, path: string): PolicyInformation {
    const seq = expectSequence(node, path, node.offset);
    if (seq.children.length < 1 || seq.children.length > 2) {
        throw malformed(path, seq.offset, `holds ${seq.children.length} values; a PolicyInformation is a policy OID and optional qualifiers`);
    }
    const policyIdentifier = readOid(seq.children[0], ctx, `${path}.policyIdentifier`, seq.offset);
    let qualifiers: readonly PolicyQualifier[] = [];
    const qualifiersNode = seq.children[1];
    if (qualifiersNode !== undefined) {
        const qualifiersPath = `${path}.policyQualifiers`;
        const list = expectSequence(qualifiersNode, qualifiersPath, seq.offset);
        expectNonEmpty(list, qualifiersPath, 'PolicyQualifierInfo');
        enforceLimit(ctx.limits, 'maxPolicies', list.children.length, `the qualifiers of ${path}`);
        qualifiers = list.children.map((child, i) => readQualifier(child, ctx, `${qualifiersPath}[${i}]`));
    }
    const policy: PolicyInformation = { policyIdentifier, qualifiers: Object.freeze(qualifiers) };
    return Object.freeze(policy);
}

/** @internal */
export function decodeCertificatePolicies(input: ExtensionInput): CertificatePoliciesExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    expectNonEmpty(seq, path, 'PolicyInformation');
    enforceLimit(ctx.limits, 'maxPolicies', seq.children.length, `the policies of ${path}`);
    const policies = seq.children.map((child, i) => readPolicy(child, ctx, `${path}[${i}]`));
    const seen = new Set<string>();
    for (const policy of policies) {
        if (seen.has(policy.policyIdentifier)) ctx.emitter.emit(policyDuplicateDiagnostic(policy.policyIdentifier));
        seen.add(policy.policyIdentifier);
    }
    const extension: CertificatePoliciesExtension = { ...baseOf(input), kind: 'certificatePolicies', policies: Object.freeze(policies) };
    return Object.freeze(extension);
}

/** @internal */
export function decodePolicyMappings(input: ExtensionInput): PolicyMappingsExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    expectNonEmpty(seq, path, 'policy mapping');
    enforceLimit(ctx.limits, 'maxPolicies', seq.children.length, `the mappings of ${path}`);
    const mappings = seq.children.map((child, i): PolicyMapping => {
        const mappingPath = `${path}[${i}]`;
        const pair = expectSequence(child, mappingPath, seq.offset);
        if (pair.children.length !== 2) throw malformed(mappingPath, pair.offset, `holds ${pair.children.length} values; a mapping is an issuerDomainPolicy and a subjectDomainPolicy`);
        return Object.freeze({
            issuerDomainPolicy: readOid(pair.children[0], ctx, `${mappingPath}.issuerDomainPolicy`, pair.offset),
            subjectDomainPolicy: readOid(pair.children[1], ctx, `${mappingPath}.subjectDomainPolicy`, pair.offset),
        });
    });
    const extension: PolicyMappingsExtension = { ...baseOf(input), kind: 'policyMappings', mappings: Object.freeze(mappings) };
    return Object.freeze(extension);
}
