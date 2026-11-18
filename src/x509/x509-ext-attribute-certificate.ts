/**
 * pkinative — Attribute certificate extensions
 * ============================================
 * The three extensions RFC 5755 §4.3 defines for attribute certificates that
 * a public-key certificate never carries: auditIdentity (§4.3.1),
 * targetInformation (§4.3.2) and noRevAvail (§4.3.6). They are handed to the
 * shared extension reader by `parseAttributeCertificate` only, so
 * `parseCertificate` and `decodeExtensionValue` keep them `unknown` (ADR 0028).
 * A value that does not match its definition throws
 * `PKI_X509_EXTENSION_MALFORMED`, as for every recognised extension; the
 * criticality and the profile of §4.3 are diagnostics.
 *
 * @module x509/x509-ext-attribute-certificate
 */

import { _readOctetString } from '../asn1/asn1-read.js';
import { TAG_NULL, TAG_OCTET_STRING } from '../asn1/asn1-tags.js';
import { acExtensionCriticalityDiagnostic, acExtensionProfileDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type {
    AttributeCertificateTarget,
    AuditIdentityExtension,
    NoRevAvailExtension,
    TargetInformationExtension,
} from '../types/attribute-certificate-types.js';
import { MALFORMED, baseOf, expectSequence, malformed, type ExtensionInput } from './x509-ext-shared.js';
import type { ExtraExtensionDecoders } from './x509-extensions.js';
import { expectUniversalField } from './x509-fields.js';
import { _readGeneralName } from './x509-general-name.js';

/** RFC 5755 §4.3.1: "MUST NOT be longer than 20 octets". */
const AUDIT_IDENTITY_MAX_OCTETS = 20;

/** @internal */
export function decodeAuditIdentity(input: ExtensionInput): AuditIdentityExtension {
    const { node, ctx, path } = input;
    const identity = _readOctetString(expectUniversalField(node, TAG_OCTET_STRING, path, MALFORMED, node.offset), ctx);
    if (identity.length === 0 || identity.length > AUDIT_IDENTITY_MAX_OCTETS) {
        ctx.emitter.emit(acExtensionProfileDiagnostic(`the audit identity is ${String(identity.length)} octets long; it is 1 to 20`, '§4.3.1', path, node.offset));
    }
    if (!input.critical) ctx.emitter.emit(acExtensionCriticalityDiagnostic('auditIdentity', 'critical', path));
    const extension: AuditIdentityExtension = { ...baseOf(input), kind: 'auditIdentity', identity };
    return Object.freeze(extension);
}

function readTarget(node: Asn1Node, input: ExtensionInput, path: string): AttributeCertificateTarget {
    if (node.tagClass === 'context' && node.tagNumber === 2 && node.constructed) {
        input.ctx.emitter.emit(acExtensionProfileDiagnostic('a target is a targetCert, which the profile forbids', '§4.3.2', path, node.offset));
        return Object.freeze({ kind: 'targetCert', der: node.bytes });
    }
    if (node.tagClass !== 'context' || (node.tagNumber !== 0 && node.tagNumber !== 1) || !node.constructed || node.children.length !== 1) {
        throw malformed(path, node.offset, 'is not a Target: one GeneralName under the explicit [0] (targetName) or [1] (targetGroup) tag, or a targetCert [2]');
    }
    const name = _readGeneralName(node.children[0] as Asn1Node, input.ctx, path, false);
    return Object.freeze({ kind: node.tagNumber === 0 ? 'targetName' : 'targetGroup', name });
}

/**
 * targetInformation: `SEQUENCE OF Targets`, each a `SEQUENCE OF Target`. Every
 * Target of every Targets element is returned in one list, as §4.3.2 tells a
 * reader to treat them, and their total is bounded by `maxGeneralNames` — a
 * target is a name (ADR 0027).
 *
 * @internal
 */
export function decodeTargetInformation(input: ExtensionInput): TargetInformationExtension {
    const { node, ctx, path } = input;
    const outer = expectSequence(node, path, node.offset);
    enforceLimit(ctx.limits, 'maxGeneralNames', outer.children.length, `the Targets elements of ${path}`);
    if (outer.children.length > 1) {
        ctx.emitter.emit(acExtensionProfileDiagnostic(`the extension holds ${String(outer.children.length)} Targets elements; an AC issuer produces one`, '§4.3.2', path, outer.offset));
    }
    const targets: AttributeCertificateTarget[] = [];
    for (let i = 0; i < outer.children.length; i++) {
        const list = expectSequence(outer.children[i], `${path}[${String(i)}]`, outer.offset);
        enforceLimit(ctx.limits, 'maxGeneralNames', targets.length + list.children.length, `the targets of ${path}`);
        for (let j = 0; j < list.children.length; j++) targets.push(readTarget(list.children[j] as Asn1Node, input, `${path}[${String(i)}][${String(j)}]`));
    }
    if (!input.critical) ctx.emitter.emit(acExtensionCriticalityDiagnostic('targetInformation', 'critical', path));
    const extension: TargetInformationExtension = { ...baseOf(input), kind: 'targetInformation', targets: Object.freeze(targets) };
    return Object.freeze(extension);
}

/** @internal */
export function decodeNoRevAvail(input: ExtensionInput): NoRevAvailExtension {
    const { node, path } = input;
    const value = expectUniversalField(node, TAG_NULL, path, MALFORMED, node.offset);
    if (value.contentLength !== 0) throw malformed(path, value.offset, `is a NULL with ${String(value.contentLength)} content octets; X.690 §8.8.2 allows none`);
    if (input.critical) input.ctx.emitter.emit(acExtensionCriticalityDiagnostic('noRevAvail', 'non-critical', path));
    const extension: NoRevAvailExtension = { ...baseOf(input), kind: 'noRevAvail' };
    return Object.freeze(extension);
}

type AcOnlyExtension = AuditIdentityExtension | TargetInformationExtension | NoRevAvailExtension;

/**
 * The decoders `parseAttributeCertificate` adds to the shared ones.
 *
 * @internal
 */
export const AC_EXTENSION_DECODERS: ExtraExtensionDecoders<AcOnlyExtension> = /*#__PURE__*/ new Map<string, (input: ExtensionInput) => AcOnlyExtension>([
    ['1.3.6.1.5.5.7.1.4', decodeAuditIdentity],
    ['2.5.29.55', decodeTargetInformation],
    ['2.5.29.56', decodeNoRevAvail],
]);
