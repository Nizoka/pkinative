/**
 * pkinative — ISO 3166-1 alpha-2 country codes
 * ============================================
 * The 249 officially assigned codes of ISO 3166-1:2020, as the ISO 3166
 * Maintenance Agency publishes them, for the `countryName` reader to hold a
 * value to: X.520 defines `countryName` as a two-letter ISO 3166 code, and
 * RFC 5280 Appendix A.1 fixes its size at two. The user-assigned range —
 * AA, QM to QZ, XA to XZ, ZZ (ISO 3166-1 §8.1.3) — is admitted without
 * comment: a private agreement may use it (XK for Kosovo is the usual one),
 * and a reader that does not know the agreement cannot call it wrong.
 * Codes the standard only reserves — transitionally (AN, CS, YU), or
 * exceptionally (UK, EU) — are not here: a certificate naming one does not
 * name an assigned country.
 *
 * Lower-case letters are not a code: the standard writes the alpha-2 codes
 * in capitals, and so does every certificate profile built on it.
 *
 * @module x509/iso3166
 */

/** ISO 3166-1 alpha-2, officially assigned: 249 codes, sorted, space-separated. */
const ASSIGNED = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ '
    + 'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR '
    + 'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP '
    + 'KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT '
    + 'MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW '
    + 'SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ '
    + 'UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW';

/**
 * The officially assigned ISO 3166-1 alpha-2 codes.
 *
 * @internal
 */
export const ISO_3166_1_ALPHA2: ReadonlySet<string> = /*#__PURE__*/ new Set(ASSIGNED.split(' '));

/** ISO 3166-1 §8.1.3: the codes left to users — AA, QM to QZ, XA to XZ and ZZ. */
const USER_ASSIGNED = /^(?:AA|Q[M-Z]|X[A-Z]|ZZ)$/;

/**
 * Whether a two-character `countryName` is an ISO 3166-1 alpha-2 code a
 * reader can accept: officially assigned, or in the user-assigned range.
 *
 * @internal
 */
export function isCountryCode(value: string): boolean {
    return ISO_3166_1_ALPHA2.has(value) || USER_ASSIGNED.test(value);
}
