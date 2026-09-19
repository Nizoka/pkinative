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
import { enforceLimit } from '../core/pki-limits.js';
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

const REASONS: readonly ReasonFlag[] = [
    'unused',
    'keyCompromise',
    'cACompromise',
    'affiliationChanged',
    'superseded',
    'cessationOfOperation',
    'certificateHold',
    'privilegeWithdrawn',
    'aACompromise',
];

function readDistributionPoint(node: Asn1Node, ctx: Asn1Context, path: string): DistributionPoint {
    const seq = expectSequence(node, path, node.offset);
    const [nameNode, reasonsNode, issuerNode] = contextFields(seq.children, 2, path);
    let fullName: readonly GeneralName[] | undefined;
    let nameRelativeToCRLIssuer: RelativeDistinguishedName | undefined;
    if (nameNode !== undefined) {
        const namePath = `${path}.distributionPoint`;
        const choice = nameNode.constructed && nameNode.children.length === 1 ? nameNode.children[0] as Asn1Node : undefined;
        if (choice?.tagClass === 'context' && choice.tagNumber === 0) {
            fullName = _readGeneralNameList(choice, ctx, `${namePath}.fullName`, false);
        } else if (choice?.tagClass === 'context' && choice.tagNumber === 1) {
            nameRelativeToCRLIssuer = _readRelativeDistinguishedName(choice, ctx, `${namePath}.nameRelativeToCRLIssuer`);
        } else {
            throw malformed(namePath, nameNode.offset, 'is not one DistributionPointName — fullName [0] or nameRelativeToCRLIssuer [1] — under an explicit [0] tag');
        }
    }
    let reasons: readonly ReasonFlag[] | undefined;
    if (reasonsNode !== undefined) {
        reasons = Object.freeze(readNamedBits(_readBitString(reasonsNode, ctx), REASONS, ctx, `${path}.reasons`, reasonsNode.offset));
    }
    const point: DistributionPoint = {
        fullName,
        nameRelativeToCRLIssuer,
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

/** @internal */
export function decodeCrlDistributionPoints(input: ExtensionInput): CrlDistributionPointsExtension {
    const extension: CrlDistributionPointsExtension = { ...baseOf(input), kind: 'crlDistributionPoints', points: readDistributionPoints(input) };
    return Object.freeze(extension);
}

/** @internal */
export function decodeFreshestCrl(input: ExtensionInput): FreshestCrlExtension {
    const extension: FreshestCrlExtension = { ...baseOf(input), kind: 'freshestCRL', points: readDistributionPoints(input) };
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

/** @internal */
export function decodeAuthorityInfoAccess(input: ExtensionInput): AuthorityInfoAccessExtension {
    const extension: AuthorityInfoAccessExtension = { ...baseOf(input), kind: 'authorityInfoAccess', descriptions: readAccessDescriptions(input) };
    return Object.freeze(extension);
}

/** @internal */
export function decodeSubjectInfoAccess(input: ExtensionInput): SubjectInfoAccessExtension {
    const extension: SubjectInfoAccessExtension = { ...baseOf(input), kind: 'subjectInfoAccess', descriptions: readAccessDescriptions(input) };
    return Object.freeze(extension);
}
