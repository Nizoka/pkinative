/**
 * pkinative — Constraint and usage extensions
 * ===========================================
 * basicConstraints, keyUsage, extKeyUsage, nameConstraints,
 * policyConstraints and inhibitAnyPolicy (RFC 5280 §4.2.1).
 *
 * @module x509/x509-ext-constraints
 */

import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readBoolean } from '../asn1/asn1-read.js';
import { TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OID } from '../asn1/asn1-tags.js';
import type { Asn1Context } from '../asn1/asn1-context.js';
import {
    defaultEncodedDiagnostic,
    basicConstraintsNotCriticalDiagnostic,
    ekuAnyCriticalDiagnostic,
    inhibitAnyPolicyNotCriticalDiagnostic,
    keyUsageEmptyDiagnostic,
    keyUsageNotCriticalDiagnostic,
    nameConstraintsMinMaxDiagnostic,
    nameConstraintsNotCriticalDiagnostic,
    nameConstraintsUriNotFqdnDiagnostic,
    policyConstraintsNotCriticalDiagnostic,
    pathLenWithoutCaDiagnostic,
    policyConstraintsEmptyDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import { isFqdn } from '../core/uri.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type {
    BasicConstraintsExtension,
    ExtendedKeyUsageExtension,
    GeneralSubtree,
    InhibitAnyPolicyExtension,
    KeyUsageExtension,
    KeyUsageName,
    NameConstraintsExtension,
    PolicyConstraintsExtension,
} from '../types/x509-types.js';
import {
    MALFORMED,
    baseOf,
    contextFields,
    expectNonEmpty,
    expectSequence,
    malformed,
    readCount,
    readNamedBits,
    type ExtensionInput,
} from './x509-ext-shared.js';
import { expectUniversalField } from './x509-fields.js';
import { _readGeneralName } from './x509-general-name.js';

const OID_ANY_EXTENDED_KEY_USAGE = '2.5.29.37.0';

const KEY_USAGES: readonly KeyUsageName[] = [
    'digitalSignature',
    'nonRepudiation',
    'keyEncipherment',
    'dataEncipherment',
    'keyAgreement',
    'keyCertSign',
    'cRLSign',
    'encipherOnly',
    'decipherOnly',
];

/** DER omits a DEFAULT value; an explicit one reads the same and is reported. */
function defaultEncoded(ctx: Asn1Context, path: string, offset: number, value: string): void {
    ctx.emitter.emit(defaultEncodedDiagnostic(path, value, offset));
}

/** @internal */
export function decodeBasicConstraints(input: ExtensionInput): BasicConstraintsExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    let index = 0;
    let cA = false;
    const first = seq.children[0];
    if (first !== undefined && first.tagClass === 'universal' && first.tagNumber === TAG_BOOLEAN) {
        cA = _readBoolean(first, ctx);
        if (!cA) defaultEncoded(ctx, `${path}.cA`, first.offset, 'FALSE');
        index = 1;
    }
    let pathLenConstraint: number | undefined;
    const second = seq.children[index];
    if (second !== undefined) {
        const lengthPath = `${path}.pathLenConstraint`;
        pathLenConstraint = readCount(expectUniversalField(second, TAG_INTEGER, lengthPath, MALFORMED, seq.offset), ctx, lengthPath);
        index++;
    }
    if (index !== seq.children.length) {
        throw malformed(path, seq.offset, `holds ${seq.children.length} values; BasicConstraints is an optional cA flag and an optional pathLenConstraint`);
    }
    if (pathLenConstraint !== undefined && !cA) ctx.emitter.emit(pathLenWithoutCaDiagnostic());
    // `MUST mark the extension as critical` addresses the issuing CA, not the
    // verifier: pkinative reads it either way, which is the safe direction, and
    // says so rather than deciding for the caller.
    if (cA && !input.critical) ctx.emitter.emit(basicConstraintsNotCriticalDiagnostic());
    const extension: BasicConstraintsExtension = { ...baseOf(input), kind: 'basicConstraints', cA, pathLenConstraint };
    return Object.freeze(extension);
}

/** @internal */
export function decodeKeyUsage(input: ExtensionInput): KeyUsageExtension {
    const { node, ctx, path } = input;
    const bitsNode = expectUniversalField(node, TAG_BIT_STRING, path, MALFORMED, node.offset);
    const bits = _readBitString(bitsNode, ctx);
    const usages = readNamedBits(bits, KEY_USAGES, ctx, path, bitsNode.offset);
    if (usages.length === 0) ctx.emitter.emit(keyUsageEmptyDiagnostic());
    if (!input.critical) ctx.emitter.emit(keyUsageNotCriticalDiagnostic());
    const extension: KeyUsageExtension = { ...baseOf(input), kind: 'keyUsage', usages: Object.freeze(usages), bits };
    return Object.freeze(extension);
}

/** @internal */
export function decodeExtendedKeyUsage(input: ExtensionInput): ExtendedKeyUsageExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    expectNonEmpty(seq, path, 'KeyPurposeId');
    const purposes = seq.children.map((child, i) => _readObjectIdentifier(expectUniversalField(child, TAG_OID, `${path}[${i}]`, MALFORMED, seq.offset), ctx));
    if (input.critical && purposes.includes(OID_ANY_EXTENDED_KEY_USAGE)) ctx.emitter.emit(ekuAnyCriticalDiagnostic());
    const extension: ExtendedKeyUsageExtension = { ...baseOf(input), kind: 'extendedKeyUsage', purposes: Object.freeze(purposes) };
    return Object.freeze(extension);
}

function readSubtree(node: Asn1Node, ctx: Asn1Context, path: string): GeneralSubtree {
    const seq = expectSequence(node, path, node.offset);
    const baseNode = seq.children[0];
    if (baseNode === undefined) throw malformed(path, seq.offset, 'holds no base; a GeneralSubtree is a GeneralName and optional bounds');
    const base = _readGeneralName(baseNode, ctx, `${path}.base`, true);
    const [minimumNode, maximumNode] = contextFields(seq.children.slice(1), 1, path);
    let minimum = 0;
    if (minimumNode !== undefined) {
        minimum = readCount(minimumNode, ctx, `${path}.minimum`);
        if (minimum === 0) defaultEncoded(ctx, `${path}.minimum`, minimumNode.offset, '0');
    }
    const maximum = maximumNode === undefined ? undefined : readCount(maximumNode, ctx, `${path}.maximum`);
    const subtree: GeneralSubtree = { base, minimum, maximum };
    return Object.freeze(subtree);
}

function readSubtrees(node: Asn1Node | undefined, ctx: Asn1Context, path: string): readonly GeneralSubtree[] | undefined {
    if (node === undefined) return undefined;
    if (!node.constructed || node.children.length === 0) {
        throw malformed(path, node.offset, 'is not a non-empty SEQUENCE OF GeneralSubtree under its implicit tag');
    }
    enforceLimit(ctx.limits, 'maxGeneralNames', node.children.length, `the subtrees of ${path}`);
    return Object.freeze(node.children.map((child, i) => readSubtree(child, ctx, `${path}[${i}]`)));
}

/** @internal */
export function decodeNameConstraints(input: ExtensionInput): NameConstraintsExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    const [permitted, excluded] = contextFields(seq.children, 1, path);
    const permittedSubtrees = readSubtrees(permitted, ctx, `${path}.permittedSubtrees`);
    const excludedSubtrees = readSubtrees(excluded, ctx, `${path}.excludedSubtrees`);
    // RFC 5280 §4.2.1.10: *"Conforming CAs MUST NOT issue certificates where
    // name constraints is an empty sequence."* An extension that constrains
    // nothing while looking as though it constrains everything is the worst
    // shape available here — a verifier reading it as "no opinion" accepts what
    // the CA meant to forbid, and one reading it as "nothing permitted" refuses
    // what it meant to allow. Two readings of one encoding is what DER exists to
    // remove, so this is a structural refusal rather than a diagnostic.
    if (permittedSubtrees === undefined && excludedSubtrees === undefined) {
        throw malformed(path, node.offset, 'holds neither permittedSubtrees nor excludedSubtrees; RFC 5280 §4.2.1.10 forbids an empty name-constraints extension, and one that constrains nothing while appearing to constrain everything is read two ways by two verifiers');
    }
    const extension: NameConstraintsExtension = {
        ...baseOf(input),
        kind: 'nameConstraints',
        permittedSubtrees,
        excludedSubtrees,
    };
    if (!input.critical) ctx.emitter.emit(nameConstraintsNotCriticalDiagnostic());
    emitSubtreeDiagnostics(ctx, permittedSubtrees, 'permittedSubtrees');
    emitSubtreeDiagnostics(ctx, excludedSubtrees, 'excludedSubtrees');
    return Object.freeze(extension);
}

/**
 * RFC 5280 §4.2.1.10 on each GeneralSubtree: no bounds, and a URI constraint
 * that is a fully qualified domain name — a host, or a domain written with
 * one leading period. Path validation already refuses to let a bounded
 * subtree cover a name, and matches a URI constraint against the host as
 * written; these report what the issuer wrote.
 */
function emitSubtreeDiagnostics(ctx: Asn1Context, subtrees: readonly GeneralSubtree[] | undefined, field: string): void {
    if (subtrees === undefined) return;
    for (let i = 0; i < subtrees.length; i++) {
        const subtree = subtrees[i] as GeneralSubtree;
        const at = `tbsCertificate.extensions.nameConstraints.${field}[${String(i)}]`;
        if (subtree.minimum !== 0 || subtree.maximum !== undefined) ctx.emitter.emit(nameConstraintsMinMaxDiagnostic(at));
        const base = subtree.base;
        if (base.kind === 'uniformResourceIdentifier' && !isFqdn(base.value.startsWith('.') ? base.value.slice(1) : base.value)) {
            ctx.emitter.emit(nameConstraintsUriNotFqdnDiagnostic(base.value, `${at}.base`));
        }
    }
}

/** @internal */
export function decodePolicyConstraints(input: ExtensionInput): PolicyConstraintsExtension {
    const { node, ctx, path } = input;
    const seq = expectSequence(node, path, node.offset);
    const [requireNode, inhibitNode] = contextFields(seq.children, 1, path);
    const extension: PolicyConstraintsExtension = {
        ...baseOf(input),
        kind: 'policyConstraints',
        requireExplicitPolicy: requireNode === undefined ? undefined : readCount(requireNode, ctx, `${path}.requireExplicitPolicy`),
        inhibitPolicyMapping: inhibitNode === undefined ? undefined : readCount(inhibitNode, ctx, `${path}.inhibitPolicyMapping`),
    };
    if (requireNode === undefined && inhibitNode === undefined) ctx.emitter.emit(policyConstraintsEmptyDiagnostic());
    // §4.2.1.11 requires conforming CAs to mark it critical. pkinative enforces
    // it either way — ignoring it would grant a path the policy the CA withheld
    // — and reports the profile violation rather than refusing the certificate.
    if (!input.critical) ctx.emitter.emit(policyConstraintsNotCriticalDiagnostic());
    return Object.freeze(extension);
}

/** @internal */
export function decodeInhibitAnyPolicy(input: ExtensionInput): InhibitAnyPolicyExtension {
    const { node, ctx, path } = input;
    const skipCerts = readCount(expectUniversalField(node, TAG_INTEGER, path, MALFORMED, node.offset), ctx, path);
    // §4.2.1.14 requires it critical; pkinative enforces it either way.
    if (!input.critical) ctx.emitter.emit(inhibitAnyPolicyNotCriticalDiagnostic());
    const extension: InhibitAnyPolicyExtension = { ...baseOf(input), kind: 'inhibitAnyPolicy', skipCerts };
    return Object.freeze(extension);
}
