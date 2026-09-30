/**
 * pkinative — Distinguished names
 * ===============================
 * RFC 5280 §4.1.2.4: a SEQUENCE OF RelativeDistinguishedName, each a
 * non-empty SET OF AttributeTypeAndValue. Character string values are
 * decoded; values of any other type are kept as their encoding. A
 * multi-valued RDN out of DER SET OF order is a diagnostic: real issuers
 * emit it, and byte-wise name comparison is what it breaks. So is an
 * attribute RFC 5280 Appendix A.1 defines, encoded outside its syntax — a
 * UTF8String `countryName`, a `countryName` of other than two characters:
 * the value is read all the same, and a strict reader refuses the name.
 *
 * @module x509/x509-name
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readString } from '../asn1/asn1-read.js';
import { TAG_BMP_STRING, TAG_IA5_STRING, TAG_OID, TAG_PRINTABLE_STRING, TAG_SEQUENCE, TAG_SET, TAG_TELETEX_STRING, TAG_UNIVERSAL_STRING, TAG_UTF8_STRING, stringTypeOfTag, tagLabel } from '../asn1/asn1-tags.js';
import { NAME_ATTRIBUTE_SYNTAX, OID_COUNTRY_NAME } from '../core/name-oids.js';
import { countryNameSizeDiagnostic, nameAttributeStringTypeDiagnostic, rdnSetNotSortedDiagnostic } from '../core/pki-diagnostics.js';
import { compareOctets } from '../core/bytes.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, Asn1String } from '../types/asn1-types.js';
import type { AttributeTypeAndValue, DistinguishedName, RelativeDistinguishedName } from '../types/x509-types.js';
import { certificateError, expectUniversalField } from './x509-fields.js';

const CODE = 'PKI_X509_NAME_INVALID';

/**
 * X.690 §11.6 order over the component encodings, shared with `encodeSetOf`.
 *
 * The zero padding §11.6 prescribes is unreachable here: two complete TLVs are
 * never a strict prefix of one another, because a difference in total length
 * shows up in the length octets before the content is reached.
 */
function inDerSetOrder(elements: readonly Asn1Node[]): boolean {
    for (let k = 1; k < elements.length; k++) {
        if (compareOctets((elements[k - 1] as Asn1Node).bytes, (elements[k] as Asn1Node).bytes) > 0) return false;
    }
    return true;
}

/** The universal tags each Appendix A.1 syntax admits. */
const SYNTAX_TAGS: Readonly<Record<'directory' | 'printable' | 'ia5', readonly number[]>> = {
    directory: [TAG_TELETEX_STRING, TAG_PRINTABLE_STRING, TAG_UNIVERSAL_STRING, TAG_UTF8_STRING, TAG_BMP_STRING],
    printable: [TAG_PRINTABLE_STRING],
    ia5: [TAG_IA5_STRING],
};

const SYNTAX_LABELS: Readonly<Record<'directory' | 'printable' | 'ia5', string>> = {
    directory: 'a DirectoryString (TeletexString, PrintableString, UniversalString, UTF8String or BMPString)',
    printable: 'a PrintableString',
    ia5: 'an IA5String',
};

/** Diagnose a value RFC 5280 Appendix A.1 defines another way; never refuse it. */
function checkAttributeSyntax(type: string, valueNode: Asn1Node, value: Asn1String | undefined, ctx: Asn1Context, path: string): void {
    const spec = NAME_ATTRIBUTE_SYNTAX.get(type);
    if (spec === undefined) return;
    if (valueNode.tagClass !== 'universal' || !SYNTAX_TAGS[spec.syntax].includes(valueNode.tagNumber)) {
        ctx.emitter.emit(nameAttributeStringTypeDiagnostic(path, spec.name, tagLabel(valueNode.tagClass, valueNode.tagNumber), SYNTAX_LABELS[spec.syntax], valueNode.offset));
    }
    if (type === OID_COUNTRY_NAME && value !== undefined) {
        const characters = [...value.value].length;
        if (characters !== 2) ctx.emitter.emit(countryNameSizeDiagnostic(path, characters, valueNode.offset));
    }
}

/** The attribute count of one name, against `maxNameAttributes`. */
interface AttributeBudget {
    count: number;
    readonly scope: string;
}

/** The attributes of one RDN: `set` is a SET, or an implicitly tagged one. */
function readRdn(set: Asn1Node, ctx: Asn1Context, rdnPath: string, budget: AttributeBudget): RelativeDistinguishedName {
    if (!set.constructed || set.children.length === 0) {
        throw certificateError(CODE, rdnPath, set.offset, 'is an empty relative distinguished name; RFC 5280 requires at least one attribute');
    }
    const atvs: AttributeTypeAndValue[] = [];
    for (let j = 0; j < set.children.length; j++) {
        budget.count++;
        enforceLimit(ctx.limits, 'maxNameAttributes', budget.count, `the attributes of ${budget.scope}`);
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
        checkAttributeSyntax(type, valueNode, value, ctx, `${atvPath}.value`);
        const attribute: AttributeTypeAndValue = { type, value, valueDer: valueNode.bytes };
        atvs.push(Object.freeze(attribute));
    }
    if (!inDerSetOrder(set.children)) ctx.emitter.emit(rdnSetNotSortedDiagnostic(rdnPath, set.offset));
    return Object.freeze(atvs);
}

/**
 * Read a Name under the operation context.
 *
 * @internal
 */
export function _readName(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): DistinguishedName {
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, CODE, parentOffset);
    const rdns: RelativeDistinguishedName[] = [];
    const budget: AttributeBudget = { count: 0, scope: path };
    for (let i = 0; i < seq.children.length; i++) {
        const rdnPath = `${path}.rdns[${i}]`;
        rdns.push(readRdn(expectUniversalField(seq.children[i], TAG_SET, rdnPath, CODE, seq.offset), ctx, rdnPath, budget));
    }
    const name: DistinguishedName = { rdns: Object.freeze(rdns), der: seq.bytes };
    return Object.freeze(name);
}

/**
 * Read one RelativeDistinguishedName carried under an implicit tag
 * (`nameRelativeToCRLIssuer`, RFC 5280 §4.2.1.13).
 *
 * @internal
 */
export function _readRelativeDistinguishedName(node: Asn1Node, ctx: Asn1Context, path: string): RelativeDistinguishedName {
    return readRdn(node, ctx, path, { count: 0, scope: path });
}
