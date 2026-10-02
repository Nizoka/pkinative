/**
 * pkinative — Distribution and access extensions
 * ==============================================
 * cRLDistributionPoints and freshestCRL (RFC 5280 §4.2.1.13, §4.2.1.15),
 * authorityInfoAccess and subjectInfoAccess (§4.2.2.1, §4.2.2.2).
 *
 * @module x509/x509-ext-distribution
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString } from '../asn1/asn1-read.js';
import { TAG_OID } from '../asn1/asn1-tags.js';
import {
    aiaCriticalDiagnostic,
    caIssuersNoHttpOrLdapUriDiagnostic,
    caRepositoryNoHttpOrLdapUriDiagnostic,
    crlDistributionPointsCriticalDiagnostic,
    distributionPointLdapUriIncompleteDiagnostic,
    distributionPointNoHttpOrLdapUriDiagnostic,
    distributionPointRelativeNameAmbiguousDiagnostic,
    distributionPointRelativeNameDiagnostic,
    distributionPointWithoutNameDiagnostic,
    freshestCrlCriticalDiagnostic,
    infoAccessLdapUriIncompleteDiagnostic,
    siaCriticalDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import { isHttpOrLdapUri, ldapUrlFields } from '../core/uri.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type {
    AccessDescription,
    AuthorityInfoAccessExtension,
    CrlDistributionPointsExtension,
    DistributionPoint,
    FreshestCrlExtension,
    GeneralName,
    ReasonFlag,
    RelativeDistinguishedName,
    SubjectInfoAccessExtension,
} from '../types/x509-types.js';
import {
    MALFORMED,
    baseOf,
    contextFields,
    expectNonEmpty,
    expectSequence,
    malformed,
    readNamedBits,
    type ExtensionInput,
} from './x509-ext-shared.js';
import { expectUniversalField } from './x509-fields.js';
import { _readGeneralName, _readGeneralNameList } from './x509-general-name.js';
import { _readRelativeDistinguishedName } from './x509-name.js';

const OID_CA_ISSUERS = '1.3.6.1.5.5.7.48.2';
const OID_CA_REPOSITORY = '1.3.6.1.5.5.7.48.5';

/**
 * The `ReasonFlags` bit names of RFC 5280 §4.2.1.13, shared with the
 * `onlySomeReasons` field of a CRL's `issuingDistributionPoint` (§5.2.5): one
 * table, because two copies of a nine-entry bit order is two chances to shift
 * it by one.
 *
 * @internal
 */
export const _REASON_FLAGS: readonly ReasonFlag[] = Object.freeze([
    'unused',
    'keyCompromise',
    'cACompromise',
    'affiliationChanged',
    'superseded',
    'cessationOfOperation',
    'certificateHold',
    'privilegeWithdrawn',
    'aACompromise',
]);

/** One decoded `DistributionPointName`, both alternatives, at most one set. */
export interface _DistributionPointName {
    readonly fullName: readonly GeneralName[] | undefined;
    readonly nameRelativeToCRLIssuer: RelativeDistinguishedName | undefined;
}

/**
 * `DistributionPointName ::= CHOICE { fullName [0] GeneralNames,
 * nameRelativeToCRLIssuer [1] RelativeDistinguishedName }`, under the explicit
 * `[0]` its two users both wrap it in — `DistributionPoint.distributionPoint`
 * here, and `IssuingDistributionPoint.distributionPoint` in `revocation/`. The
 * two names are compared against each other by RFC 5280 §6.3.3 (b)(2), so they
 * must be read by the same code or the comparison is between two dialects.
 *
 * @internal
 */
export function _readDistributionPointName(nameNode: Asn1Node, ctx: Asn1Context, namePath: string): _DistributionPointName {
    const choice = nameNode.constructed && nameNode.children.length === 1 ? nameNode.children[0] as Asn1Node : undefined;
    if (choice?.tagClass === 'context' && choice.tagNumber === 0) {
        return { fullName: _readGeneralNameList(choice, ctx, `${namePath}.fullName`, false), nameRelativeToCRLIssuer: undefined };
    }
    if (choice?.tagClass === 'context' && choice.tagNumber === 1) {
        return { fullName: undefined, nameRelativeToCRLIssuer: _readRelativeDistinguishedName(choice, ctx, `${namePath}.nameRelativeToCRLIssuer`) };
    }
    throw malformed(namePath, nameNode.offset, 'is not one DistributionPointName — fullName [0] or nameRelativeToCRLIssuer [1] — under an explicit [0] tag');
}

function readDistributionPoint(node: Asn1Node, ctx: Asn1Context, path: string): DistributionPoint {
    const seq = expectSequence(node, path, node.offset);
    const [nameNode, reasonsNode, issuerNode] = contextFields(seq.children, 2, path);
    const name: _DistributionPointName = nameNode === undefined
        ? { fullName: undefined, nameRelativeToCRLIssuer: undefined }
        : _readDistributionPointName(nameNode, ctx, `${path}.distributionPoint`);
    let reasons: readonly ReasonFlag[] | undefined;
    if (reasonsNode !== undefined) {
        reasons = Object.freeze(readNamedBits(_readBitString(reasonsNode, ctx), _REASON_FLAGS, ctx, `${path}.reasons`, reasonsNode.offset));
    }
    const point: DistributionPoint = {
        fullName: name.fullName,
        nameRelativeToCRLIssuer: name.nameRelativeToCRLIssuer,
        reasons,
        cRLIssuer: issuerNode === undefined ? undefined : _readGeneralNameList(issuerNode, ctx, `${path}.cRLIssuer`, false),
    };
    return Object.freeze(point);
}

function readDistributionPoints(input: ExtensionInput): readonly DistributionPoint[] {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    expectNonEmpty(seq, path, 'DistributionPoint');
    enforceLimit(ctx.limits, 'maxGeneralNames', seq.children.length, `the distribution points of ${path}`);
    return Object.freeze(seq.children.map((child, i) => readDistributionPoint(child, ctx, `${path}[${i}]`)));
}

/**
 * RFC 5280 §4.2.1.13 on each DistributionPoint — of cRLDistributionPoints,
 * and of freshestCRL, whose syntax §4.2.1.15 makes the same: a name or a CRL
 * issuer to locate the CRL by; an LDAP URI with its `<dn>` and one
 * `<attrdesc>`; an http or ldap URI among the names; and no
 * nameRelativeToCRLIssuer, least of all beside several CRL issuers.
 */
function emitDistributionPointDiagnostics(ctx: Asn1Context, points: readonly DistributionPoint[], extension: string): void {
    points.forEach((point, i) => {
        const at = `tbsCertificate.extensions.${extension}[${String(i)}]`;
        const named = point.fullName !== undefined || point.nameRelativeToCRLIssuer !== undefined;
        if (!named && point.cRLIssuer === undefined) ctx.emitter.emit(distributionPointWithoutNameDiagnostic(at));
        if (!named) return;
        const namePath = `${at}.distributionPoint`;
        const fullName = point.fullName ?? [];
        fullName.forEach((name, k) => {
            if (name.kind !== 'uniformResourceIdentifier') return;
            const ldap = ldapUrlFields(name.value);
            if (ldap === null) return;
            const attributes = ldap.attributes ?? '';
            if (ldap.dn === undefined || ldap.dn === '' || attributes === '' || attributes.includes(',')) {
                ctx.emitter.emit(distributionPointLdapUriIncompleteDiagnostic(name.value, `${namePath}.fullName[${String(k)}]`));
            }
        });
        if (!fullName.some((name) => name.kind === 'uniformResourceIdentifier' && isHttpOrLdapUri(name.value))) {
            ctx.emitter.emit(distributionPointNoHttpOrLdapUriDiagnostic(namePath));
        }
        if (point.nameRelativeToCRLIssuer === undefined) return;
        ctx.emitter.emit(distributionPointRelativeNameDiagnostic(namePath));
        const issuers = (point.cRLIssuer ?? []).filter((name) => name.kind === 'directoryName').length;
        if (issuers > 1) ctx.emitter.emit(distributionPointRelativeNameAmbiguousDiagnostic(at));
    });
}

/** @internal */
export function decodeCrlDistributionPoints(input: ExtensionInput): CrlDistributionPointsExtension {
    const points = readDistributionPoints(input);
    emitDistributionPointDiagnostics(input.ctx, points, 'cRLDistributionPoints');
    if (input.critical) input.ctx.emitter.emit(crlDistributionPointsCriticalDiagnostic());
    const extension: CrlDistributionPointsExtension = { ...baseOf(input), kind: 'crlDistributionPoints', points };
    return Object.freeze(extension);
}

/** @internal */
export function decodeFreshestCrl(input: ExtensionInput): FreshestCrlExtension {
    const points = readDistributionPoints(input);
    emitDistributionPointDiagnostics(input.ctx, points, 'freshestCRL');
    if (input.critical) input.ctx.emitter.emit(freshestCrlCriticalDiagnostic());
    const extension: FreshestCrlExtension = { ...baseOf(input), kind: 'freshestCRL', points };
    return Object.freeze(extension);
}

function readAccessDescriptions(input: ExtensionInput): readonly AccessDescription[] {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    expectNonEmpty(seq, path, 'AccessDescription');
    enforceLimit(ctx.limits, 'maxGeneralNames', seq.children.length, `the access descriptions of ${path}`);
    return Object.freeze(seq.children.map((child, i): AccessDescription => {
        const descriptionPath = `${path}[${i}]`;
        const pair = expectSequence(child, descriptionPath, seq.offset);
        if (pair.children.length !== 2) {
            throw malformed(descriptionPath, pair.offset, `holds ${pair.children.length} values; an AccessDescription is an accessMethod and an accessLocation`);
        }
        const methodNode = expectUniversalField(pair.children[0], TAG_OID, `${descriptionPath}.accessMethod`, MALFORMED, pair.offset);
        return Object.freeze({
            accessMethod: _readObjectIdentifier(methodNode, ctx),
            accessLocation: _readGeneralName(pair.children[1] as Asn1Node, ctx, `${descriptionPath}.accessLocation`, false),
        });
    }));
}

/**
 * RFC 5280 §4.2.2.1 for `id-ad-caIssuers` and §4.2.2.2 for
 * `id-ad-caRepository`, in the same words: an LDAP URI names its `<dn>` and
 * its `<attributes>`, and at least one location is an http or ldap URI.
 *
 * @returns False when `method` appears and none of its locations is an http
 *   or ldap URI — the SHOULD of both sections — and true otherwise.
 */
function emitAccessLocationDiagnostics(ctx: Asn1Context, descriptions: readonly AccessDescription[], method: string, extension: string): boolean {
    let listed = false;
    let fetchable = false;
    for (let i = 0; i < descriptions.length; i++) {
        const description = descriptions[i] as AccessDescription;
        if (description.accessMethod !== method) continue;
        listed = true;
        const location = description.accessLocation;
        if (location.kind !== 'uniformResourceIdentifier') continue;
        if (isHttpOrLdapUri(location.value)) fetchable = true;
        const ldap = ldapUrlFields(location.value);
        if (ldap !== null && (ldap.dn === undefined || ldap.dn === '' || ldap.attributes === undefined || ldap.attributes === '')) {
            ctx.emitter.emit(infoAccessLdapUriIncompleteDiagnostic(location.value, `tbsCertificate.extensions.${extension}[${String(i)}].accessLocation`));
        }
    }
    return fetchable || !listed;
}

/** @internal */
export function decodeAuthorityInfoAccess(input: ExtensionInput): AuthorityInfoAccessExtension {
    const descriptions = readAccessDescriptions(input);
    if (!emitAccessLocationDiagnostics(input.ctx, descriptions, OID_CA_ISSUERS, 'authorityInfoAccess')) input.ctx.emitter.emit(caIssuersNoHttpOrLdapUriDiagnostic());
    if (input.critical) input.ctx.emitter.emit(aiaCriticalDiagnostic());
    const extension: AuthorityInfoAccessExtension = { ...baseOf(input), kind: 'authorityInfoAccess', descriptions };
    return Object.freeze(extension);
}

/** @internal */
export function decodeSubjectInfoAccess(input: ExtensionInput): SubjectInfoAccessExtension {
    const descriptions = readAccessDescriptions(input);
    if (!emitAccessLocationDiagnostics(input.ctx, descriptions, OID_CA_REPOSITORY, 'subjectInfoAccess')) input.ctx.emitter.emit(caRepositoryNoHttpOrLdapUriDiagnostic());
    if (input.critical) input.ctx.emitter.emit(siaCriticalDiagnostic());
    const extension: SubjectInfoAccessExtension = { ...baseOf(input), kind: 'subjectInfoAccess', descriptions };
    return Object.freeze(extension);
}
