import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { decodeExtensionValue } from '../../src/x509/x509-extensions.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import {
    AUTHORITY_KEY_ID,
    BASIC_CONSTRAINTS_CA,
    SUBJECT_KEY_ID,
    bitString,
    certificate,
    context,
    explicit,
    extension,
    integer,
    name,
    oid,
    utf8,
} from '../helpers/cert-builder.js';
import { ascii, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * The 36 requirement sentences of RFC 5280 §4.1–§4.2 that the inventory
 * (scripts/data/rfc5280-requirements.json) recorded as `not-diagnosed` until
 * 1.0, each now a diagnostic. One row per code: a certificate that breaks the
 * sentence and its twin that keeps it, both otherwise diagnostic-free, built
 * TLV by TLV — so the row locks the code, its path, that the certificate
 * still parses, that the twin is silent, and that `strict: true` refuses it.
 */

const OID = {
    ski: '2.5.29.14',
    keyUsage: '2.5.29.15',
    san: '2.5.29.17',
    ian: '2.5.29.18',
    nameConstraints: '2.5.29.30',
    crlDp: '2.5.29.31',
    policies: '2.5.29.32',
    mappings: '2.5.29.33',
    aki: '2.5.29.35',
    eku: '2.5.29.37',
    freshest: '2.5.29.46',
    inhibitAny: '2.5.29.54',
    aia: '1.3.6.1.5.5.7.1.1',
    sia: '1.3.6.1.5.5.7.1.11',
} as const;

const DV = '2.23.140.1.2.1';
const OV = '2.23.140.1.2.2';
const ANY_POLICY = '2.5.29.32.0';
const CPS = '1.3.6.1.5.5.7.2.1';
const USER_NOTICE = '1.3.6.1.5.5.7.2.2';
const CA_ISSUERS = '1.3.6.1.5.5.7.48.2';
const CA_REPOSITORY = '1.3.6.1.5.5.7.48.5';
const OCSP = '1.3.6.1.5.5.7.48.1';
const CN = '2.5.4.3';

const bmp = (text: string): Uint8Array => universal(30, [...text].flatMap((c) => [c.charCodeAt(0) >> 8, c.charCodeAt(0) & 0xff]));
const visible = (text: string): Uint8Array => universal(26, ascii(text));
const uri = (text: string): Uint8Array => context(6, false, ascii(text));
const dns = (text: string): Uint8Array => context(2, false, ascii(text));
const directoryName = (cn: string): Uint8Array => context(4, true, name([[CN, utf8(cn)]]));

/** A CA certificate with the default extensions and `extra` after them. */
const ca = (...extra: readonly Uint8Array[]): Uint8Array =>
    certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID, AUTHORITY_KEY_ID, ...extra))] });

const policies = (...infos: readonly Uint8Array[]): Uint8Array => extension(OID.policies, sequence(...infos));
const userNotice = (...parts: readonly Uint8Array[]): Uint8Array => sequence(oid(DV), sequence(sequence(oid(USER_NOTICE), sequence(...parts))));
const noticeRef = sequence(utf8('Example CA'), sequence(integer([1])));

/** DistributionPoint { distributionPoint [0] { fullName [0] GeneralNames } … }. */
const fullName = (...names: readonly Uint8Array[]): Uint8Array => context(0, true, context(0, true, sequence(...names).subarray(2)));
const relativeName = context(0, true, context(1, true, sequence(oid(CN), utf8('crl'))));
const crlIssuer = (...names: readonly Uint8Array[]): Uint8Array => context(2, true, sequence(...names).subarray(2));
const points = (...dps: readonly Uint8Array[]): Uint8Array => extension(OID.crlDp, sequence(...dps.map((dp) => sequence(dp))));
const point = (...fields: readonly Uint8Array[]): Uint8Array => sequence(...fields);
const crlDp = (critical: boolean | undefined, ...dps: readonly Uint8Array[]): Uint8Array => extension(OID.crlDp, sequence(...dps), critical);
const access = (extnOid: string, method: string, location: string, critical?: boolean): Uint8Array =>
    extension(extnOid, sequence(sequence(oid(method), uri(location))), critical);

const subtree = (base: Uint8Array, ...bounds: readonly Uint8Array[]): Uint8Array =>
    extension(OID.nameConstraints, sequence(context(0, true, sequence(base, ...bounds))), true);

function diagnostics(der: Uint8Array): PkiDiagnostic[] {
    const seen: PkiDiagnostic[] = [];
    parseCertificate(der, { onDiagnostic: (d) => { seen.push(d); } });
    return seen;
}

interface Row {
    /** The inventory ids the code answers. */
    readonly ids: string;
    readonly code: string;
    readonly path: string;
    readonly fails: Uint8Array;
    readonly passes: Uint8Array;
    /** Other new codes the failing certificate also raises, in emission order, before `code`. */
    readonly before?: readonly string[];
}

const LDAP_CRL = 'ldap://ldap.example.com/cn=Example%20CA,dc=example,dc=com?certificateRevocationList;binary';
const LDAP_CERTS = 'ldap://ldap.example.com/cn=Example%20CA,dc=example,dc=com?cACertificate;binary,crossCertificatePair;binary';

/** Severity by code, from the registry: what `strict` refuses is a warning, what it reports is an info. */
const SEVERITY = new Map((JSON.parse(readFileSync('docs/data/diagnostics.json', 'utf8')) as { diagnostics: Array<{ code: string; severity: string }> }).diagnostics.map((d) => [d.code, d.severity]));

const ROWS: readonly Row[] = [
    {
        ids: '4.1.2.8-3',
        code: 'PKI_DIAG_UNIQUE_ID_PRESENT',
        path: 'tbsCertificate.subjectUniqueID',
        fails: certificate({ trailing: [context(2, false, [0x00, 0xaa]), explicit(3, sequence(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID, AUTHORITY_KEY_ID))] }),
        passes: ca(),
    },
    {
        ids: '4.2.1.1-4',
        code: 'PKI_DIAG_AKI_CRITICAL',
        path: 'tbsCertificate.extensions.authorityKeyIdentifier',
        fails: certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID, extension(OID.aki, sequence(context(0, false, [0x0a])), true)))] }),
        passes: certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, SUBJECT_KEY_ID, extension(OID.aki, sequence(context(0, false, [0x0a])))))] }),
    },
    {
        ids: '4.2.1.2-7',
        code: 'PKI_DIAG_SKI_CRITICAL',
        path: 'tbsCertificate.extensions.subjectKeyIdentifier',
        fails: certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, extension(OID.ski, universal(4, [1, 2]), true), AUTHORITY_KEY_ID))] }),
        passes: ca(),
    },
    {
        ids: '4.2.1.2-4',
        code: 'PKI_DIAG_SKI_MISSING_END_ENTITY',
        path: 'tbsCertificate.extensions',
        fails: certificate({ trailing: [explicit(3, sequence(AUTHORITY_KEY_ID))] }),
        passes: certificate({ trailing: [explicit(3, sequence(SUBJECT_KEY_ID, AUTHORITY_KEY_ID))] }),
    },
    {
        ids: '4.2.1.3-2',
        code: 'PKI_DIAG_KEY_USAGE_NOT_CRITICAL',
        path: 'tbsCertificate.extensions.keyUsage',
        fails: ca(extension(OID.keyUsage, bitString([0x06], 1))),
        passes: ca(extension(OID.keyUsage, bitString([0x06], 1), true)),
    },
    {
        ids: '4.2.1.4-3',
        code: 'PKI_DIAG_ANY_POLICY_QUALIFIER',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0]',
        fails: ca(policies(sequence(oid(ANY_POLICY), sequence(sequence(oid('1.2.3.4'), utf8('x')))))),
        // The same unknown qualifier under another policy is outside the sentence.
        passes: ca(policies(sequence(oid(DV), sequence(sequence(oid('1.2.3.4'), utf8('x')))), sequence(oid(ANY_POLICY), sequence(sequence(oid(CPS), universal(22, ascii('http://cps.example/'))))))),
    },
    {
        ids: '4.2.1.4-5',
        code: 'PKI_DIAG_NOTICE_REF_USED',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0].noticeRef',
        fails: ca(policies(userNotice(noticeRef, utf8('Notice')))),
        passes: ca(policies(userNotice(utf8('Notice')))),
    },
    {
        ids: '4.2.1.4-6, 4.2.1.4-7',
        code: 'PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0].explicitText',
        fails: ca(policies(userNotice(bmp('Notice')))),
        // IA5String is the sentence's own MAY.
        passes: ca(policies(userNotice(universal(22, ascii('Notice'))))),
    },
    {
        ids: '4.2.1.4-7',
        code: 'PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0].explicitText',
        fails: ca(policies(userNotice(visible('Notice')))),
        passes: ca(policies(userNotice(utf8('Notice')))),
    },
    {
        ids: '4.2.1.4-8',
        code: 'PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0].explicitText',
        fails: ca(policies(userNotice(utf8('Not\u0085ice')))),
        passes: ca(policies(userNotice(utf8('Not ice')))),
    },
    {
        ids: '4.2.1.4-8',
        code: 'PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0].explicitText',
        fails: ca(policies(userNotice(utf8('Not\u007fice')))),
        passes: ca(policies(userNotice(utf8('Not ice')))),
    },
    {
        ids: '4.2.1.4-9',
        code: 'PKI_DIAG_EXPLICIT_TEXT_NOT_NFC',
        path: 'tbsCertificate.extensions.certificatePolicies[0].policyQualifiers[0].explicitText',
        fails: ca(policies(userNotice(utf8('Café')))),
        passes: ca(policies(userNotice(utf8('Café')))),
    },
    {
        ids: '4.2.1.5-1',
        code: 'PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED',
        path: 'tbsCertificate.extensions.policyMappings',
        fails: ca(policies(sequence(oid(OV))), extension(OID.mappings, sequence(sequence(oid(DV), oid(OV))), true)),
        passes: ca(policies(sequence(oid(DV))), extension(OID.mappings, sequence(sequence(oid(DV), oid(OV))), true)),
    },
    {
        ids: '4.2.1.5-3',
        code: 'PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL',
        path: 'tbsCertificate.extensions.policyMappings',
        fails: ca(policies(sequence(oid(DV))), extension(OID.mappings, sequence(sequence(oid(DV), oid(OV))))),
        passes: ca(policies(sequence(oid(DV))), extension(OID.mappings, sequence(sequence(oid(DV), oid(OV))), true)),
    },
    {
        ids: '4.2.1.6-5',
        code: 'PKI_DIAG_SAN_CRITICAL',
        path: 'tbsCertificate.extensions.subjectAltName',
        fails: ca(extension(OID.san, sequence(dns('leaf.example')), true)),
        passes: ca(extension(OID.san, sequence(dns('leaf.example')))),
    },
    {
        ids: '4.2.1.6-15',
        code: 'PKI_DIAG_ALT_NAME_URI_INVALID',
        path: 'tbsCertificate.extensions.subjectAltName[0]',
        fails: ca(extension(OID.san, sequence(uri('https://host.example/a b')))),
        passes: ca(extension(OID.san, sequence(uri('https://host.example/a%20b')))),
    },
    {
        ids: '4.2.1.6-15, 4.2.1.6-16',
        code: 'PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING',
        path: 'tbsCertificate.extensions.subjectAltName[0]',
        // A relative reference breaks both sentences.
        fails: ca(extension(OID.san, sequence(uri('//host.example/path')))),
        passes: ca(extension(OID.san, sequence(uri('https://host.example/path')))),
        before: ['PKI_DIAG_ALT_NAME_URI_INVALID'],
    },
    {
        ids: '4.2.1.6-16',
        code: 'PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING',
        path: 'tbsCertificate.extensions.issuerAltName[1]',
        fails: ca(extension(OID.ian, sequence(dns('ca.example'), uri('urn:')))),
        passes: ca(extension(OID.ian, sequence(dns('ca.example'), uri('urn:example:ca')))),
    },
    {
        ids: '4.2.1.6-17',
        code: 'PKI_DIAG_ALT_NAME_URI_HOST_INVALID',
        path: 'tbsCertificate.extensions.subjectAltName[0]',
        fails: ca(extension(OID.san, sequence(uri('https://under_score.example/')))),
        passes: ca(extension(OID.san, sequence(uri('https://[2001:db8::1]:8443/'), uri('https://192.0.2.1/'), uri('mailto:a@b.example')))),
    },
    {
        ids: '4.2.1.6-20',
        code: 'PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY',
        path: 'tbsCertificate.extensions.subjectAltName[1]',
        fails: ca(extension(OID.san, sequence(context(1, false, ascii('a@example.com')), context(1, false, [])))),
        passes: ca(extension(OID.san, sequence(context(1, false, ascii('a@example.com'))))),
    },
    {
        ids: '4.2.1.6-20',
        code: 'PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY',
        path: 'tbsCertificate.extensions.subjectAltName[0]',
        fails: ca(extension(OID.san, sequence(context(4, true, sequence())))),
        passes: ca(extension(OID.san, sequence(directoryName('leaf')))),
    },
    {
        ids: '4.2.1.6-20',
        code: 'PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY',
        path: 'tbsCertificate.extensions.issuerAltName[0]',
        fails: ca(extension(OID.ian, sequence(context(5, true, [])))),
        passes: ca(extension(OID.ian, sequence(context(5, true, context(1, true, utf8('party')))))),
    },
    {
        ids: '4.2.1.7-2',
        code: 'PKI_DIAG_ISSUER_ALT_NAME_CRITICAL',
        path: 'tbsCertificate.extensions.issuerAltName',
        fails: ca(extension(OID.ian, sequence(dns('ca.example')), true)),
        passes: ca(extension(OID.ian, sequence(dns('ca.example')))),
    },
    {
        ids: '4.2.1.10-7',
        code: 'PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX',
        path: 'tbsCertificate.extensions.nameConstraints.permittedSubtrees[0]',
        fails: ca(subtree(dns('example.com'), context(1, false, [0x05]))),
        passes: ca(subtree(dns('example.com'))),
    },
    {
        ids: '4.2.1.10-7',
        code: 'PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX',
        path: 'tbsCertificate.extensions.nameConstraints.permittedSubtrees[0]',
        fails: ca(subtree(dns('example.com'), context(0, false, [0x01]))),
        passes: ca(subtree(dns('example.com'))),
    },
    {
        ids: '4.2.1.10-9',
        code: 'PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN',
        path: 'tbsCertificate.extensions.nameConstraints.permittedSubtrees[0].base',
        fails: ca(subtree(uri('https://host.example.com/'))),
        passes: ca(subtree(uri('.example.com'))),
    },
    {
        ids: '4.2.1.12-3',
        code: 'PKI_DIAG_EKU_ANY_CRITICAL',
        path: 'tbsCertificate.extensions.extKeyUsage',
        fails: ca(extension(OID.eku, sequence(oid('1.3.6.1.5.5.7.3.1'), oid('2.5.29.37.0')), true)),
        passes: ca(extension(OID.eku, sequence(oid('1.3.6.1.5.5.7.3.1'), oid('2.5.29.37.0')))),
    },
    {
        ids: '4.2.1.13-1',
        code: 'PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL',
        path: 'tbsCertificate.extensions.cRLDistributionPoints',
        fails: ca(crlDp(true, point(fullName(uri('http://crl.example/ca.crl'))))),
        passes: ca(points(fullName(uri('http://crl.example/ca.crl')))),
    },
    {
        ids: '4.2.1.13-2',
        code: 'PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME',
        path: 'tbsCertificate.extensions.cRLDistributionPoints[0]',
        fails: ca(crlDp(undefined, point(context(1, false, [0x06, 0x40])))),
        passes: ca(crlDp(undefined, point(context(1, false, [0x06, 0x40]), crlIssuer(directoryName('CRL issuer'))))),
    },
    {
        ids: '4.2.1.13-8',
        code: 'PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE',
        path: 'tbsCertificate.extensions.cRLDistributionPoints[0].distributionPoint.fullName[0]',
        // Two attribute descriptions where the sentence asks for a single one.
        fails: ca(points(fullName(uri('ldap://ldap.example.com/cn=CA?certificateRevocationList;binary,authorityRevocationList;binary')))),
        passes: ca(points(fullName(uri(LDAP_CRL)))),
    },
    {
        ids: '4.2.1.13-8',
        code: 'PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE',
        path: 'tbsCertificate.extensions.freshestCRL[0].distributionPoint.fullName[1]',
        fails: ca(extension(OID.freshest, sequence(sequence(fullName(uri('http://crl.example/delta.crl'), uri('ldap://ldap.example.com/?deltaRevocationList;binary')))))),
        passes: ca(extension(OID.freshest, sequence(sequence(fullName(uri('http://crl.example/delta.crl'), uri('ldap://ldap.example.com/cn=CA?deltaRevocationList;binary')))))),
    },
    {
        ids: '4.2.1.13-9',
        code: 'PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI',
        path: 'tbsCertificate.extensions.cRLDistributionPoints[0].distributionPoint',
        fails: ca(points(fullName(uri('https://crl.example/ca.crl'), directoryName('CRL')))),
        passes: ca(points(fullName(uri('https://crl.example/ca.crl'), uri('HTTP://crl.example/ca.crl')))),
    },
    {
        ids: '4.2.1.13-10',
        code: 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME',
        path: 'tbsCertificate.extensions.cRLDistributionPoints[0].distributionPoint',
        fails: ca(crlDp(undefined, point(relativeName, crlIssuer(directoryName('CRL issuer'))))),
        passes: ca(crlDp(undefined, point(fullName(uri(LDAP_CRL)), crlIssuer(directoryName('CRL issuer'))))),
        // A relative name holds no URI, which is the SHOULD of 4.2.1.13-9 too.
        before: ['PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI'],
    },
    {
        ids: '4.2.1.13-11',
        code: 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS',
        path: 'tbsCertificate.extensions.cRLDistributionPoints[0]',
        fails: ca(crlDp(undefined, point(relativeName, crlIssuer(directoryName('CRL A'), dns('crl.example'), directoryName('CRL B'))))),
        passes: ca(crlDp(undefined, point(fullName(uri(LDAP_CRL)), crlIssuer(directoryName('CRL A'), directoryName('CRL B'))))),
        before: ['PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI', 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME'],
    },
    {
        ids: '4.2.1.14-1',
        code: 'PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL',
        path: 'tbsCertificate.extensions.inhibitAnyPolicy',
        fails: ca(extension(OID.inhibitAny, integer([0]))),
        passes: ca(extension(OID.inhibitAny, integer([0]), true)),
    },
    {
        ids: '4.2.1.15-1',
        code: 'PKI_DIAG_FRESHEST_CRL_CRITICAL',
        path: 'tbsCertificate.extensions.freshestCRL',
        fails: ca(extension(OID.freshest, sequence(sequence(fullName(uri('http://crl.example/delta.crl')))), true)),
        passes: ca(extension(OID.freshest, sequence(sequence(fullName(uri('http://crl.example/delta.crl')))))),
    },
    {
        ids: '4.2.2.1-1',
        code: 'PKI_DIAG_AIA_CRITICAL',
        path: 'tbsCertificate.extensions.authorityInfoAccess',
        fails: ca(access(OID.aia, CA_ISSUERS, 'http://ca.example/ca.cer', true)),
        passes: ca(access(OID.aia, CA_ISSUERS, 'http://ca.example/ca.cer')),
    },
    {
        ids: '4.2.2.1-3',
        code: 'PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE',
        path: 'tbsCertificate.extensions.authorityInfoAccess[0].accessLocation',
        fails: ca(access(OID.aia, CA_ISSUERS, 'ldap://ldap.example.com/cn=CA')),
        passes: ca(access(OID.aia, CA_ISSUERS, LDAP_CERTS)),
    },
    {
        ids: '4.2.2.1-3',
        code: 'PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE',
        path: 'tbsCertificate.extensions.authorityInfoAccess[0].accessLocation',
        fails: ca(access(OID.aia, CA_ISSUERS, 'ldap://ldap.example.com')),
        // An LDAP OCSP location is outside the caIssuers paragraph.
        passes: ca(access(OID.aia, OCSP, 'ldap://ldap.example.com')),
    },
    {
        ids: '4.2.2.1-8',
        code: 'PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI',
        path: 'tbsCertificate.extensions.authorityInfoAccess',
        fails: ca(access(OID.aia, CA_ISSUERS, 'https://ca.example/ca.cer')),
        passes: ca(extension(OID.aia, sequence(sequence(oid(CA_ISSUERS), uri('https://ca.example/ca.cer')), sequence(oid(CA_ISSUERS), uri('http://ca.example/ca.cer'))))),
    },
    {
        ids: '4.2.2.1-8',
        code: 'PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI',
        path: 'tbsCertificate.extensions.authorityInfoAccess',
        fails: ca(extension(OID.aia, sequence(sequence(oid(OCSP), uri('http://ocsp.example/')), sequence(oid(CA_ISSUERS), directoryName('CA'))))),
        passes: ca(access(OID.aia, OCSP, 'https://ocsp.example/')),
    },
    {
        ids: '4.2.2.2-1',
        code: 'PKI_DIAG_SIA_CRITICAL',
        path: 'tbsCertificate.extensions.subjectInfoAccess',
        fails: ca(access(OID.sia, CA_REPOSITORY, 'http://ca.example/repo.p7c', true)),
        passes: ca(access(OID.sia, CA_REPOSITORY, 'http://ca.example/repo.p7c')),
    },
    {
        ids: '4.2.2.2-3',
        code: 'PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE',
        path: 'tbsCertificate.extensions.subjectInfoAccess[0].accessLocation',
        fails: ca(access(OID.sia, CA_REPOSITORY, 'ldap://ldap.example.com/cn=CA?')),
        passes: ca(access(OID.sia, CA_REPOSITORY, LDAP_CERTS)),
    },
    {
        ids: '4.2.2.2-8',
        code: 'PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI',
        path: 'tbsCertificate.extensions.subjectInfoAccess',
        fails: ca(access(OID.sia, CA_REPOSITORY, 'ldaps://ldap.example.com/cn=CA?cACertificate')),
        passes: ca(access(OID.sia, CA_REPOSITORY, LDAP_CERTS)),
    },
];

describe('the RFC 5280 §4.1–§4.2 profile diagnostics', () => {
    it.each(ROWS)('$code ($ids): reported at $path, and the certificate still parses', ({ code, path, fails, before }) => {
        const seen = diagnostics(fails);
        expect(seen.map((d) => d.code)).toEqual([...(before ?? []), code]);
        expect(seen.at(-1)?.path).toBe(path);
    });

    it.each(ROWS)('$code ($ids): silent on the twin that keeps the sentence', ({ passes }) => {
        expect(diagnostics(passes).map((d) => d.code)).toEqual([]);
    });

    it.each(ROWS)('$code ($ids): under strict: true a warning refuses and an info is only reported', ({ code, fails, before }) => {
        // `strict` refuses the first MUST the certificate broke; a SHOULD it did
        // not follow is advice to the issuer, delivered and never thrown.
        const emitted = [...(before ?? []), code];
        const firstWarning = emitted.find((c) => SEVERITY.get(c) === 'warning');
        if (firstWarning === undefined) {
            const seen: string[] = [];
            parseCertificate(fails, { strict: true, onDiagnostic: (d) => { seen.push(d.code); } });
            expect(seen).toEqual(emitted);
            return;
        }
        let caught: unknown;
        try {
            parseCertificate(fails, { strict: true });
        } catch (error) {
            caught = error;
        }
        expect(caught).toBeInstanceOf(PkiError);
        expect(caught).toMatchObject({ code: 'PKI_STRICT_DIAGNOSTIC' });
        expect((caught as PkiError).message).toContain(`[${firstWarning}]`);
    });

    it('should give a MUST a warning and a SHOULD an info', () => {
        const severities = new Map(ROWS.map((row) => [row.code, diagnostics(row.fails).at(-1)?.severity]));
        const info = [...severities].filter(([, s]) => s === 'info').map(([c]) => c).sort();
        expect(info).toEqual([
            'PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI',
            'PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI',
            'PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL',
            'PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI',
            'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME',
            'PKI_DIAG_EKU_ANY_CRITICAL',
            'PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER',
            'PKI_DIAG_EXPLICIT_TEXT_NOT_NFC',
            'PKI_DIAG_ISSUER_ALT_NAME_CRITICAL',
            'PKI_DIAG_KEY_USAGE_NOT_CRITICAL',
            'PKI_DIAG_NOTICE_REF_USED',
            'PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL',
            'PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED',
            'PKI_DIAG_SAN_CRITICAL',
            'PKI_DIAG_SKI_MISSING_END_ENTITY',
        ]);
        expect(severities.size).toBe(34);
    });

    it('should report a URI three ways when it is empty, and an empty dNSName beside its preferred-syntax diagnostic', () => {
        expect(diagnostics(ca(extension(OID.san, sequence(uri(''))))).map((d) => d.code))
            .toEqual(['PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY', 'PKI_DIAG_ALT_NAME_URI_INVALID', 'PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING']);
        expect(diagnostics(ca(extension(OID.san, sequence(dns(''))))).map((d) => d.code))
            .toEqual(['PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX', 'PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY', 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN']);
    });

    it('should report every mapped issuer-domain policy once, and none when certificatePolicies is left undecoded', () => {
        const mapped = ca(extension(OID.mappings, sequence(sequence(oid(DV), oid(OV)), sequence(oid(DV), oid('2.23.140.1.2.3')), sequence(oid(OV), oid(DV))), true));
        expect(diagnostics(mapped).map((d) => d.code)).toEqual(['PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED', 'PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED']);
        const raw: string[] = [];
        parseCertificate(mapped, { decodeExtensions: false, onDiagnostic: (d) => { raw.push(d.code); } });
        expect(raw).toEqual([]);
    });

    it('should judge the end-entity identifier only against a decoded basicConstraints', () => {
        // Undecoded, basicConstraints says nothing about cA: neither the CA
        // nor the end-entity rule applies.
        const caWithoutSki = certificate({ trailing: [explicit(3, sequence(BASIC_CONSTRAINTS_CA, AUTHORITY_KEY_ID))] });
        const raw: string[] = [];
        parseCertificate(caWithoutSki, { decodeExtensions: false, onDiagnostic: (d) => { raw.push(d.code); } });
        expect(raw).toEqual([]);
        expect(diagnostics(caWithoutSki).map((d) => d.code)).toEqual(['PKI_DIAG_SKI_MISSING']);
        // An explicit cA FALSE is an end entity.
        const endEntity = certificate({ trailing: [explicit(3, sequence(extension('2.5.29.19', sequence(), true), AUTHORITY_KEY_ID))] });
        expect(diagnostics(endEntity).map((d) => d.code)).toEqual(['PKI_DIAG_SKI_MISSING_END_ENTITY']);
        // A v1 certificate has no field to carry it in.
        expect(diagnostics(certificate({ version: null, trailing: [] })).map((d) => d.code)).toEqual([]);
    });

    it('should report the criticality sentences through decodeExtensionValue as well, from its critical option', () => {
        const seen: string[] = [];
        const onDiagnostic = (d: PkiDiagnostic): void => { seen.push(d.code); };
        decodeExtensionValue(OID.aki, sequence(context(0, false, [0x0a])), { critical: true, onDiagnostic });
        decodeExtensionValue(OID.ski, universal(4, [0x01]), { critical: true, onDiagnostic });
        decodeExtensionValue(OID.inhibitAny, integer([1]), { onDiagnostic });
        decodeExtensionValue(OID.sia, sequence(sequence(oid(CA_REPOSITORY), uri('http://a.example/'))), { critical: true, onDiagnostic });
        expect(seen).toEqual(['PKI_DIAG_AKI_CRITICAL', 'PKI_DIAG_SKI_CRITICAL', 'PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL', 'PKI_DIAG_SIA_CRITICAL']);
    });

    it('should leave the anyPolicy CPS and user notice qualifiers, and a policy without qualifiers, alone', () => {
        const der = ca(policies(
            sequence(oid(ANY_POLICY), sequence(sequence(oid(CPS), universal(22, ascii('http://cps.example/'))), sequence(oid(USER_NOTICE), sequence(utf8('ok'))))),
            sequence(oid(DV)),
            sequence(oid(OV), sequence(sequence(oid(USER_NOTICE), sequence()))),
        ));
        expect(diagnostics(der)).toEqual([]);
    });

    it('should not hold a dNSName or an IP-address URI constraint to the URI rule, nor bounds of 0', () => {
        expect(diagnostics(ca(subtree(uri('host.example.com'))))).toEqual([]);
        expect(diagnostics(ca(subtree(context(7, false, [192, 0, 2, 0, 255, 255, 255, 0]))))).toEqual([]);
        expect(diagnostics(ca(subtree(uri('..example.com')))).map((d) => d.code)).toEqual(['PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN']);
        expect(diagnostics(ca(subtree(uri('')))).map((d) => d.code)).toEqual(['PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN']);
        const excluded = ca(extension(OID.nameConstraints, sequence(context(1, true, sequence(uri('https://x.example/'), context(1, false, [0x01])))), true));
        expect(diagnostics(excluded).map((d) => [d.code, d.path])).toEqual([
            ['PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX', 'tbsCertificate.extensions.nameConstraints.excludedSubtrees[0]'],
            ['PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN', 'tbsCertificate.extensions.nameConstraints.excludedSubtrees[0].base'],
        ]);
    });

    it('should report an LDAP CRL URI without a dn, without attributes, and with an empty attribute', () => {
        for (const text of ['ldap://ldap.example.com', 'ldap://ldap.example.com/cn=CA', 'ldap://ldap.example.com/cn=CA?', 'ldap://ldap.example.com/?x']) {
            expect(diagnostics(ca(points(fullName(uri(text))))).map((d) => d.code), text).toEqual(['PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE']);
        }
        // A non-LDAP scheme is not an LDAP URI to judge, an ldaps one neither.
        expect(diagnostics(ca(points(fullName(uri('http://crl.example/'), uri('ldaps://ldap.example.com')))))).toEqual([]);
    });

    it.each([
        ['\u001f', true], [' ', false], ['~', false], ['\u007f', true], ['\u009f', true], [' ', false],
    ])('should hold the control-character range of §4.2.1.4 to its ends: %j → %s', (character, reported) => {
        const seen: string[] = [];
        decodeExtensionValue(OID.policies, sequence(userNotice(utf8(`a${character}b`))), { onDiagnostic: (d) => { seen.push(d.code); } });
        expect(seen).toEqual(reported ? ['PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER'] : []);
    });

    it('should report an id-ad-caIssuers LDAP URI whose dn is empty', () => {
        expect(diagnostics(ca(access(OID.aia, CA_ISSUERS, 'ldap://ldap.example.com/?cACertificate'))).map((d) => d.code))
            .toEqual(['PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE']);
    });

    it('should count only directoryNames as the distinguished names of cRLIssuer', () => {
        const der = ca(crlDp(undefined, point(relativeName, crlIssuer(directoryName('CRL A'), dns('crl.example'), uri('http://crl.example/')))));
        expect(diagnostics(der).map((d) => d.code)).toEqual(['PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI', 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME']);
    });
});
