/**
 * pkinative — Distinguished-name attribute syntaxes
 * =================================================
 * The value syntax RFC 5280 Appendix A.1 gives each naming attribute it
 * defines, in one table, so that the name builder writes what the name
 * reader checks and the two cannot disagree.
 *
 * Three syntaxes. Most attributes are a `DirectoryString` — a CHOICE of
 * TeletexString, PrintableString, UniversalString, UTF8String and BMPString —
 * of which RFC 5280 §4.1.2.4 lets a conforming CA write only PrintableString
 * or UTF8String. Five are fixed: `countryName`, `serialNumber` and
 * `dnQualifier` are a PrintableString, `domainComponent` and the legacy
 * `emailAddress` an IA5String. The SIZE bounds are the `ub-*` constants of
 * Appendix A.2, counted in characters.
 *
 * It lives in `core` because two layers read it — `build` writes names and
 * `x509` reads them — and `build` does not import `x509` (AGENTS.md
 * §Architecture), the same reason `cms-oids` lives here.
 *
 * @module core/name-oids
 */

/** How RFC 5280 Appendix A.1 defines one naming attribute's value. */
export interface NameAttributeSyntax {
    /** The attribute's name in RFC 5280, for messages. */
    readonly name: string;
    /** `'directory'`: a DirectoryString. `'printable'` and `'ia5'`: that one string type, and no other. */
    readonly syntax: 'directory' | 'printable' | 'ia5';
    /** The lower SIZE bound in characters; 0 when Appendix A gives none. */
    readonly min: number;
    /** The upper SIZE bound in characters (the `ub-*` constant); `undefined` when Appendix A gives none. */
    readonly max: number | undefined;
}

/** `ub-name`: the bound of X520name, which the five naming attributes of a person share. */
const UB_NAME = 32768;

/** Every naming attribute RFC 5280 Appendix A.1 defines, by type OID. */
export const NAME_ATTRIBUTE_SYNTAX: ReadonlyMap<string, NameAttributeSyntax> = /*#__PURE__*/ new Map<string, NameAttributeSyntax>([
    ['2.5.4.41', { name: 'name', syntax: 'directory', min: 1, max: UB_NAME }],
    ['2.5.4.4', { name: 'surname', syntax: 'directory', min: 1, max: UB_NAME }],
    ['2.5.4.42', { name: 'givenName', syntax: 'directory', min: 1, max: UB_NAME }],
    ['2.5.4.43', { name: 'initials', syntax: 'directory', min: 1, max: UB_NAME }],
    ['2.5.4.44', { name: 'generationQualifier', syntax: 'directory', min: 1, max: UB_NAME }],
    ['2.5.4.3', { name: 'commonName', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.7', { name: 'localityName', syntax: 'directory', min: 1, max: 128 }],
    ['2.5.4.8', { name: 'stateOrProvinceName', syntax: 'directory', min: 1, max: 128 }],
    ['2.5.4.10', { name: 'organizationName', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.11', { name: 'organizationalUnitName', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.12', { name: 'title', syntax: 'directory', min: 1, max: 64 }],
    ['2.5.4.65', { name: 'pseudonym', syntax: 'directory', min: 1, max: 128 }],
    ['2.5.4.46', { name: 'dnQualifier', syntax: 'printable', min: 0, max: undefined }],
    ['2.5.4.6', { name: 'countryName', syntax: 'printable', min: 2, max: 2 }],
    ['2.5.4.5', { name: 'serialNumber', syntax: 'printable', min: 1, max: 64 }],
    ['0.9.2342.19200300.100.1.25', { name: 'domainComponent', syntax: 'ia5', min: 0, max: undefined }],
    ['1.2.840.113549.1.9.1', { name: 'emailAddress', syntax: 'ia5', min: 1, max: 255 }],
]);

/** `id-at-countryName`, the one attribute whose size is exact: an ISO 3166 alpha-2 code. */
export const OID_COUNTRY_NAME = '2.5.4.6';
