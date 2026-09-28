/**
 * pkinative — GeneralName
 * =======================
 * RFC 5280 §4.2.1.6, under the implicit tagging of the PKIX1Implicit88
 * module. IA5String names must be ASCII: internationalized names are not
 * converted before 0.5, so non-ASCII octets are refused rather than guessed.
 * An iPAddress is 4 or 16 octets, and 8 or 32 (address and mask) in name
 * constraints (§4.2.1.10).
 *
 * @module x509/x509-general-name
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { stringContent } from '../asn1/asn1-read.js';
import { TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, tagLabel } from '../asn1/asn1-tags.js';
import { byteView } from '../core/bytes.js';
import { dnsNameNotPreferredSyntaxDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import { decodeAsciiSubset, isIa5Octet } from '../core/text.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type {
    DirectoryGeneralName,
    GeneralName,
    IpAddressGeneralName,
    OpaqueGeneralName,
    OtherGeneralName,
    RegisteredIdGeneralName,
    TextGeneralName,
} from '../types/x509-types.js';
import { certificateError, expectUniversalField } from './x509-fields.js';
import { _readName } from './x509-name.js';

const CODE = 'PKI_X509_GENERAL_NAME_INVALID';

/**
 * RFC 1034 §3.5 preferred name syntax: labels of letters, digits and hyphens,
 * none empty, none beginning or ending with a hyphen.
 *
 * A leading `*` label is accepted here, because a wildcard certificate is the
 * everyday case and RFC 9525 gives it its own grammar. Judged only to *report*:
 * nothing downstream normalises a name, and the matching rules compare it
 * literally, so a name outside the syntax simply matches fewer hosts.
 */
function isPreferredName(value: string): boolean {
    // No guard for the empty string: `''.split('.')` is `['']`, whose single
    // empty label the rule below already refuses. A separate check would be a
    // branch no certificate can reach.
    const labels = value.split('.');
    return labels.every((label, index) => {
        if (label === '*' && index === 0) return true;
        if (label === '' || label.startsWith('-') || label.endsWith('-')) return false;
        return /^[A-Za-z0-9-]+$/.test(label);
    });
}

function formatIpv4(bytes: Uint8Array): string {
    // readIpAddress has already refused anything but exactly four octets here.
    return bytes.join('.');
}

/** RFC 5952 §4: lowercase, no leading zeros, the first longest run of two or more zero groups as `::`. */
function formatIpv6(bytes: Uint8Array): string {
    const groups: number[] = [];
    // Exactly sixteen octets here, and getUint16 is big-endian, as the address is.
    const view = byteView(bytes);
    for (let i = 0; i < 16; i += 2) groups.push(view.getUint16(i));
    let bestStart = 0;
    let bestLength = 0;
    for (let i = 0; i < 8;) {
        if (groups[i] !== 0) {
            i++;
            continue;
        }
        let j = i;
        while (j < 8 && groups[j] === 0) j++;
        if (j - i > bestLength) {
            bestStart = i;
            bestLength = j - i;
        }
        i = j;
    }
    const hex = groups.map((g) => g.toString(16));
    if (bestLength < 2) return hex.join(':');
    return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
}

function readIpAddress(node: Asn1Node, ctx: Asn1Context, path: string, inNameConstraints: boolean): IpAddressGeneralName {
    const bytes = stringContent(node, ctx, TAG_OCTET_STRING, 'OCTET STRING');
    const half = inNameConstraints ? bytes.length / 2 : bytes.length;
    if (half !== 4 && half !== 16 || (inNameConstraints && bytes.length % 2 !== 0)) {
        throw certificateError(CODE, path, node.offset, inNameConstraints
            ? `is an iPAddress of ${bytes.length} octets; in name constraints it is 8 (IPv4 and mask) or 32 (IPv6 and mask)`
            : `is an iPAddress of ${bytes.length} octets; it is 4 (IPv4) or 16 (IPv6)`);
    }
    const format = half === 4 ? formatIpv4 : formatIpv6;
    const name: IpAddressGeneralName = {
        kind: 'iPAddress',
        version: half === 4 ? 4 : 6,
        address: format(bytes.subarray(0, half)),
        mask: inNameConstraints ? format(bytes.subarray(half)) : undefined,
        bytes,
        der: node.bytes,
    };
    return Object.freeze(name);
}

/**
 * Read one GeneralName.
 *
 * @internal
 */
export function _readGeneralName(node: Asn1Node, ctx: Asn1Context, path: string, inNameConstraints: boolean): GeneralName {
    if (node.tagClass !== 'context') {
        throw certificateError(CODE, path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; a GeneralName carries a context-specific tag [0] to [8]`);
    }
    const der = node.bytes;
    switch (node.tagNumber) {
        case 0: {
            if (!node.constructed || node.children.length !== 2) {
                throw certificateError(CODE, path, node.offset, 'is not an otherName: a type-id OID followed by a value under an explicit [0] tag');
            }
            const typeNode = node.children[0] as Asn1Node;
            const wrapper = node.children[1] as Asn1Node;
            if (typeNode.tagClass !== 'universal' || typeNode.tagNumber !== TAG_OID) {
                throw certificateError(CODE, `${path}.typeId`, typeNode.offset, `is ${tagLabel(typeNode.tagClass, typeNode.tagNumber)}; expected OBJECT IDENTIFIER`);
            }
            if (wrapper.tagClass !== 'context' || wrapper.tagNumber !== 0 || !wrapper.constructed || wrapper.children.length !== 1) {
                throw certificateError(CODE, `${path}.value`, wrapper.offset, 'is not one value under an explicit [0] tag');
            }
            const name: OtherGeneralName = { kind: 'otherName', typeId: _readObjectIdentifier(typeNode, ctx), value: wrapper.children[0] as Asn1Node, der };
            return Object.freeze(name);
        }
        case 1:
        case 2:
        case 6: {
            const value = decodeAsciiSubset(stringContent(node, ctx, TAG_OCTET_STRING, 'IA5String'), isIa5Octet);
            if (value === null) {
                throw certificateError(CODE, path, node.offset, 'contains an octet above 0x7F; IA5String names are ASCII, and internationalized names are not decoded before 0.5');
            }
            const kind: TextGeneralName['kind'] = node.tagNumber === 1 ? 'rfc822Name' : node.tagNumber === 2 ? 'dNSName' : 'uniformResourceIdentifier';
            // §4.2.1.6 asks a dNSName to use RFC 1034's preferred name syntax.
            // Real certificates carry underscores, which DNS resolves, so this is
            // a diagnostic and not a refusal — and nothing normalises the name, so
            // it can only ever match a host asked for with the same spelling.
            if (kind === 'dNSName' && !isPreferredName(value)) ctx.emitter.emit(dnsNameNotPreferredSyntaxDiagnostic(value, path));
            const name: TextGeneralName = { kind, value, der };
            return Object.freeze(name);
        }
        case 3:
        case 5: {
            const kind: OpaqueGeneralName['kind'] = node.tagNumber === 3 ? 'x400Address' : 'ediPartyName';
            if (!node.constructed) throw certificateError(CODE, path, node.offset, `is primitive; ${kind} is a constructed type`);
            const name: OpaqueGeneralName = { kind, value: node, der };
            return Object.freeze(name);
        }
        case 4: {
            if (!node.constructed || node.children.length !== 1) {
                throw certificateError(CODE, path, node.offset, 'is not a directoryName: one Name under an explicit [4] tag');
            }
            const name: DirectoryGeneralName = { kind: 'directoryName', name: _readName(node.children[0], ctx, `${path}.directoryName`, node.offset), der };
            return Object.freeze(name);
        }
        case 7:
            return readIpAddress(node, ctx, path, inNameConstraints);
        case 8: {
            if (node.constructed) throw certificateError(CODE, path, node.offset, 'is constructed; a registeredID is a primitive OBJECT IDENTIFIER');
            const name: RegisteredIdGeneralName = { kind: 'registeredID', oid: _readObjectIdentifier(node, ctx), der };
            return Object.freeze(name);
        }
        default:
            throw certificateError(CODE, path, node.offset, `carries the tag [${node.tagNumber}]; GeneralName defines [0] to [8]`);
    }
}

/**
 * Read a GeneralNames SEQUENCE. An empty sequence is returned as such: the
 * extension that holds it decides whether that is a diagnostic.
 *
 * @internal
 */
export function _readGeneralNames(node: Asn1Node, ctx: Asn1Context, path: string, inNameConstraints: boolean): readonly GeneralName[] {
    return _readGeneralNameList(expectUniversalField(node, TAG_SEQUENCE, path, CODE, node.offset), ctx, path, inNameConstraints);
}

/**
 * Read the GeneralName children of a constructed value: a GeneralNames
 * SEQUENCE, or one under an implicit tag (`authorityCertIssuer [1]`,
 * `fullName [0]`, `cRLIssuer [2]`).
 *
 * @internal
 */
export function _readGeneralNameList(container: Asn1Node, ctx: Asn1Context, path: string, inNameConstraints: boolean): readonly GeneralName[] {
    if (!container.constructed) {
        throw certificateError(CODE, path, container.offset, 'is primitive; GeneralNames is a constructed SEQUENCE OF GeneralName');
    }
    enforceLimit(ctx.limits, 'maxGeneralNames', container.children.length, `the names of ${path}`);
    const names: GeneralName[] = [];
    for (let i = 0; i < container.children.length; i++) {
        names.push(_readGeneralName(container.children[i] as Asn1Node, ctx, `${path}[${i}]`, inNameConstraints));
    }
    return Object.freeze(names);
}
