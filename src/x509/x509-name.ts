/**
 * pkinative — Distinguished names
 * ===============================
 * RFC 5280 §4.1.2.4: a SEQUENCE OF RelativeDistinguishedName, each a
 * non-empty SET OF AttributeTypeAndValue. Character string values are
 * decoded; values of any other type are kept as their encoding. A
 * multi-valued RDN out of DER SET OF order is a diagnostic: real issuers
 * emit it, and byte-wise name comparison is what it breaks.
 *
 * @module x509/x509-name
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readString } from '../asn1/asn1-read.js';
import { TAG_OID, TAG_SEQUENCE, TAG_SET, stringTypeOfTag } from '../asn1/asn1-tags.js';
import { rdnSetNotSortedDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type { AttributeTypeAndValue, DistinguishedName, RelativeDistinguishedName } from '../types/x509-types.js';
import { certificateError, expectUniversalField } from './x509-fields.js';

const CODE = 'PKI_X509_NAME_INVALID';

/** X.690 §11.6: encodings compared as octet strings, the shorter padded with trailing zero octets. */
function inDerSetOrder(elements: readonly Asn1Node[]): boolean {
    for (let k = 1; k < elements.length; k++) {
        const a = (elements[k - 1] as Asn1Node).bytes;
        const b = (elements[k] as Asn1Node).bytes;
        const length = Math.max(a.length, b.length);
        for (let i = 0; i < length; i++) {
            const d = (a[i] ?? 0) - (b[i] ?? 0);
            if (d < 0) break;
            if (d > 0) return false;
        }
    }
    return true;
}

/**
 * Read a Name under the operation context.
 *
 * @internal
 */
export function _readName(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): DistinguishedName {
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, CODE, parentOffset);
    const rdns: RelativeDistinguishedName[] = [];
    let attributes = 0;
    for (let i = 0; i < seq.children.length; i++) {
        const rdnPath = `${path}.rdns[${i}]`;
        const set = expectUniversalField(seq.children[i], TAG_SET, rdnPath, CODE, seq.offset);
        if (set.children.length === 0) {
            throw certificateError(CODE, rdnPath, set.offset, 'is an empty relative distinguished name; RFC 5280 requires at least one attribute');
        }
        const atvs: AttributeTypeAndValue[] = [];
        for (let j = 0; j < set.children.length; j++) {
            attributes++;
            enforceLimit(ctx.limits, 'maxNameAttributes', attributes, `the attributes of ${path}`);
            const atvPath = `${rdnPath}[${j}]`;
            const atv = expectUniversalField(set.children[j], TAG_SEQUENCE, atvPath, CODE, set.offset);
            if (atv.children.length !== 2) {
                throw certificateError(CODE, atvPath, atv.offset, `holds ${atv.children.length} values; an AttributeTypeAndValue is a type OID and one value`);
            }
            const type = _readObjectIdentifier(expectUniversalField(atv.children[0], TAG_OID, `${atvPath}.type`, CODE, atv.offset), ctx);
            const valueNode = atv.children[1] as Asn1Node;
            const value = valueNode.tagClass === 'universal' && stringTypeOfTag(valueNode.tagNumber) !== undefined
                ? _readString(valueNode, ctx, undefined, `${atvPath}.value`)
                : undefined;
            const attribute: AttributeTypeAndValue = { type, value, valueDer: valueNode.bytes };
            atvs.push(Object.freeze(attribute));
        }
        if (!inDerSetOrder(set.children)) ctx.emitter.emit(rdnSetNotSortedDiagnostic(rdnPath, set.offset));
        rdns.push(Object.freeze(atvs));
    }
    const name: DistinguishedName = { rdns: Object.freeze(rdns), der: seq.bytes };
    return Object.freeze(name);
}
