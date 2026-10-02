import { describe, expect, it } from 'vitest';
import { CLAUSES } from '../../scripts/lib/clauses.js';
import { evaluateClauses, EVALUATED_CLAUSE_IDS } from '../../scripts/validators/rfc5280-clauses.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The clause checker, exercised on certificates built here.
 *
 * The corpus run (L5, `scripts/validate-certs.ts`) tells you how often each
 * clause fires on 30 361 real certificates; it cannot tell you that an
 * evaluator which always returns `pass` is wrong. That is what this file is
 * for: every clause gets a certificate that **violates** it and one that
 * satisfies it, built from raw DER, so an evaluator that decided nothing
 * would go red here rather than quietly reporting a clean corpus.
 *
 * It also carries the two clauses x509-limbo cannot reach — a unique
 * identifier and a multi-valued RDN — which is what their `unexercisedBy`
 * waivers point at. A waiver whose named suite did not actually exercise the
 * clause would be worse than no clause at all.
 */

// ── A minimal certificate, assembled field by field ──────────────────

const OID_CN = universal(6, [0x55, 0x04, 0x03]);
const OID_C = universal(6, [0x55, 0x04, 0x06]);

const attribute = (oid: Uint8Array, value: string): Uint8Array => sequence(oid, universal(12, ascii(value)));
const rdn = (...attributes: readonly Uint8Array[]): Uint8Array => universal(17, concat(...attributes), true);
const name = (...rdns: readonly Uint8Array[]): Uint8Array => sequence(...rdns);

const ALG_ED25519 = sequence(universal(6, [0x2b, 0x65, 0x70]));
const SPKI = sequence(ALG_ED25519, universal(3, [0x00, ...new Array<number>(32).fill(0x11)]));
const UTC = (text: string): Uint8Array => universal(23, ascii(text));
const GEN = (text: string): Uint8Array => universal(24, ascii(text));
const VALIDITY = sequence(UTC('260101000000Z'), UTC('270101000000Z'));
const SUBJECT = name(rdn(attribute(OID_CN, 'sample')));

interface Parts {
    readonly version?: Uint8Array | null;
    readonly serial?: Uint8Array;
    readonly issuer?: Uint8Array;
    readonly validity?: Uint8Array;
    readonly subject?: Uint8Array;
    readonly uniqueId?: Uint8Array;
    readonly extensions?: readonly Uint8Array[] | null;
    readonly outerAlgorithm?: Uint8Array;
}

/** A structurally complete certificate; only the fields under test vary. */
function certificate(parts: Parts = {}): Uint8Array {
    const extensions = parts.extensions === undefined ? null : parts.extensions;
    const version = parts.version === undefined
        ? (extensions === null ? null : tlv(2, true, 0, universal(2, [2])))
        : parts.version;
    const tbs = sequence(
        ...(version === null ? [] : [version]),
        parts.serial ?? universal(2, [0x01]),
        ALG_ED25519,
        parts.issuer ?? name(rdn(attribute(OID_CN, 'issuer'))),
        parts.validity ?? VALIDITY,
        parts.subject ?? SUBJECT,
        SPKI,
        ...(parts.uniqueId === undefined ? [] : [parts.uniqueId]),
        ...(extensions === null ? [] : [tlv(2, true, 3, sequence(...extensions))]),
    );
    return sequence(tbs, parts.outerAlgorithm ?? ALG_ED25519, universal(3, [0x00, 0xaa]));
}

/** An Extension, with `critical` written out only when asked. */
function extension(oid: readonly number[], value: Uint8Array, critical?: boolean): Uint8Array {
    return sequence(
        universal(6, oid),
        ...(critical === undefined ? [] : [universal(1, [critical ? 0xff : 0x00])]),
        universal(4, value),
    );
}

const BASIC_CONSTRAINTS = [0x55, 0x1d, 0x13];
const KEY_USAGE = [0x55, 0x1d, 0x0f];
const SAN = [0x55, 0x1d, 0x11];
const NAME_CONSTRAINTS = [0x55, 0x1d, 0x1e];
const CERTIFICATE_POLICIES = [0x55, 0x1d, 0x20];
const POLICY_CONSTRAINTS = [0x55, 0x1d, 0x24];
const AKI = [0x55, 0x1d, 0x23];
const SKI = [0x55, 0x1d, 0x0e];

const IAN = [0x55, 0x1d, 0x12];
const CRL_DP = [0x55, 0x1d, 0x1f];
const POLICY_MAPPINGS = [0x55, 0x1d, 0x21];
const EKU = [0x55, 0x1d, 0x25];
const FRESHEST_CRL = [0x55, 0x1d, 0x2e];
const INHIBIT_ANY_POLICY = [0x55, 0x1d, 0x36];
const AIA = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const SIA = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b];
const ANY_POLICY = universal(6, [0x55, 0x1d, 0x20, 0x00]);
const POLICY_A = universal(6, [0x2a, 0x03]);
const POLICY_B = universal(6, [0x2a, 0x04]);
const QUALIFIER_CPS = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01]);
const QUALIFIER_UNOTICE = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02]);
const CA_ISSUERS = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);
const CA_REPOSITORY = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05]);
const ANY_EKU = universal(6, [0x55, 0x1d, 0x25, 0x00]);
const SERVER_AUTH = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]);

const uri = (text: string): Uint8Array => tlv(2, false, 6, ascii(text));
const dnsName = (text: string): Uint8Array => tlv(2, false, 2, ascii(text));
const directory = (cn: string): Uint8Array => tlv(2, true, 4, name(rdn(attribute(OID_CN, cn))));
/** certificatePolicies holding one policy with one user notice of the given parts. */
const notice = (...parts: readonly Uint8Array[]): Uint8Array =>
    extension(CERTIFICATE_POLICIES, sequence(sequence(POLICY_A, sequence(sequence(QUALIFIER_UNOTICE, sequence(...parts))))));
/** A DistributionPoint naming its CRL by fullName. */
const byFullName = (...names: readonly Uint8Array[]): Uint8Array => sequence(tlv(2, true, 0, tlv(2, true, 0, concat(...names))));
const RELATIVE = tlv(2, true, 0, tlv(2, true, 1, sequence(OID_CN, universal(12, ascii('crl')))));
const crlIssuers = (...names: readonly Uint8Array[]): Uint8Array => tlv(2, true, 2, concat(...names));
const access = (method: Uint8Array, location: string): Uint8Array => sequence(sequence(method, uri(location)));
const subtree = (base: Uint8Array, ...bounds: readonly Uint8Array[]): Uint8Array => sequence(tlv(2, true, 0, sequence(base, ...bounds)));
const bmp = (text: string): Uint8Array => universal(30, [...text].flatMap((c) => [0, c.charCodeAt(0)]));
const utf8Text = (text: string): Uint8Array => universal(12, new TextEncoder().encode(text));

/** BasicConstraints { cA TRUE }. */
const CA_TRUE = sequence(universal(1, [0xff]));
/** NameConstraints { permittedSubtrees [0] { GeneralSubtree { dNSName "example.com" } } }. */
const PERMIT_EXAMPLE = sequence(tlv(2, true, 0, sequence(tlv(2, false, 2, ascii('example.com')))));

const verdict = (der: Uint8Array, id: string): string => evaluateClauses(der).get(id) ?? 'missing';

// ── One failing and one passing certificate per clause ───────────────

interface Case {
    readonly id: string;
    readonly fails: Uint8Array;
    readonly passes: Uint8Array;
}

const CASES: readonly Case[] = [
    {
        id: '4.1.2.2-serial-positive',
        fails: certificate({ serial: universal(2, [0x80, 0x01]) }),
        passes: certificate({ serial: universal(2, [0x01]) }),
    },
    {
        id: '4.1.2.2-serial-at-most-20-octets',
        fails: certificate({ serial: universal(2, [0x01, ...new Array<number>(20).fill(0x02)]) }),
        passes: certificate({ serial: universal(2, [0x01, ...new Array<number>(19).fill(0x02)]) }),
    },
    {
        id: '4.1.1.2-signature-algorithm-matches-tbs',
        // The outer algorithm names sha256WithRSAEncryption, the inner Ed25519.
        fails: certificate({ outerAlgorithm: sequence(universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), universal(5, [])) }),
        passes: certificate(),
    },
    {
        id: '4.1.2.1-extensions-require-v3',
        fails: certificate({ version: null, extensions: [extension(BASIC_CONSTRAINTS, sequence())] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence())] }),
    },
    {
        id: '4.1.2.8-unique-id-requires-v2',
        // x509-limbo has no such certificate; this is what its waiver names.
        fails: certificate({ version: null, uniqueId: tlv(2, false, 1, [0x00, 0xff]) }),
        passes: certificate({ version: tlv(2, true, 0, universal(2, [1])), uniqueId: tlv(2, false, 1, [0x00, 0xff]) }),
    },
    {
        id: '4.1.2.5-generalized-time-only-from-2050',
        fails: certificate({ validity: sequence(GEN('20260101000000Z'), UTC('270101000000Z')) }),
        passes: certificate({ validity: sequence(UTC('260101000000Z'), GEN('20510101000000Z')) }),
    },
    {
        id: '4.1.2.5.2-generalized-time-no-fraction',
        fails: certificate({ validity: sequence(UTC('260101000000Z'), GEN('20510101000000.5Z')) }),
        passes: certificate({ validity: sequence(UTC('260101000000Z'), GEN('20510101000000Z')) }),
    },
    {
        id: '4.1.2.4-issuer-not-empty',
        fails: certificate({ issuer: sequence() }),
        passes: certificate(),
    },
    {
        id: '4.2-critical-default-absent',
        fails: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(), false)] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(), true)] }),
    },
    {
        id: '4.2.1.9-path-len-requires-ca',
        // pathLenConstraint with cA taking its DEFAULT of FALSE.
        fails: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(universal(2, [0x00])))] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, sequence(universal(1, [0xff]), universal(2, [0x00])))] }),
    },
    {
        id: '4.2.1.3-key-usage-not-empty',
        fails: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x00]))] }),
        passes: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80]))] }),
    },
    {
        id: '4.2.1.6-alt-name-not-empty',
        fails: certificate({ extensions: [extension(SAN, sequence())] }),
        passes: certificate({ extensions: [extension(SAN, sequence(tlv(2, false, 2, ascii('a.example'))))] }),
    },
    {
        id: '4.2.1.10-name-constraints-critical',
        fails: certificate({ extensions: [extension(NAME_CONSTRAINTS, sequence())] }),
        passes: certificate({ extensions: [extension(NAME_CONSTRAINTS, sequence(), true)] }),
    },
    {
        id: '4.2.1.11-policy-constraints-not-empty',
        fails: certificate({ extensions: [extension(POLICY_CONSTRAINTS, sequence(), true)] }),
        passes: certificate({ extensions: [extension(POLICY_CONSTRAINTS, sequence(tlv(2, false, 0, [0x00])), true)] }),
    },
    {
        id: '4.2.1.4-policies-not-duplicated',
        fails: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(universal(6, [0x2a, 0x03])), sequence(universal(6, [0x2a, 0x03]))))] }),
        passes: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(universal(6, [0x2a, 0x03])), sequence(universal(6, [0x2a, 0x04]))))] }),
    },
    {
        id: '4.2.1.1-aki-issuer-and-serial-paired',
        fails: certificate({ extensions: [extension(AKI, sequence(tlv(2, true, 1, sequence())))] }),
        passes: certificate({ extensions: [extension(AKI, sequence(tlv(2, true, 1, sequence()), tlv(2, false, 2, [0x01])))] }),
    },
    {
        id: 'x690-11.6-rdn-set-sorted',
        // Two attributes in one RDN, in descending encoded order. The corpus
        // has no multi-valued RDN at all; this is what its waiver names.
        fails: certificate({ subject: name(rdn(attribute(OID_C, 'zz'), attribute(OID_CN, 'aa'))) }),
        passes: certificate({ subject: name(rdn(attribute(OID_CN, 'aa'), attribute(OID_C, 'zz'))) }),
    },
    {
        id: 'x690-11.2.2-named-bits-trimmed',
        // 0x80 0x00 with 7 unused bits: the trailing zero octet DER removes.
        fails: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80, 0x00]))] }),
        passes: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80]))] }),
    },
    {
        id: '4.1.2.6-empty-subject-requires-critical-san',
        fails: certificate({ subject: sequence(), extensions: [extension(SAN, sequence(tlv(2, false, 2, ascii('a.example'))))] }),
        passes: certificate({ subject: sequence(), extensions: [extension(SAN, sequence(tlv(2, false, 2, ascii('a.example'))), true)] }),
    },
    {
        id: '4.2.1.9-basic-constraints-critical-in-ca',
        fails: certificate({ extensions: [extension(BASIC_CONSTRAINTS, CA_TRUE)] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, CA_TRUE, true)] }),
    },
    {
        id: '4.2.1.11-policy-constraints-critical',
        fails: certificate({ extensions: [extension(POLICY_CONSTRAINTS, sequence(tlv(2, false, 0, [0x00])))] }),
        passes: certificate({ extensions: [extension(POLICY_CONSTRAINTS, sequence(tlv(2, false, 0, [0x00])), true)] }),
    },
    {
        id: '4.2.1.3-key-cert-sign-requires-ca',
        // 03 02 02 04: keyCertSign (bit 5) alone, two unused bits.
        fails: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x02, 0x04]), true)] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, CA_TRUE, true), extension(KEY_USAGE, universal(3, [0x02, 0x04]), true)] }),
    },
    {
        id: '4.2.1.10-name-constraints-only-in-ca',
        fails: certificate({ extensions: [extension(NAME_CONSTRAINTS, PERMIT_EXAMPLE, true)] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, CA_TRUE, true), extension(NAME_CONSTRAINTS, PERMIT_EXAMPLE, true)] }),
    },
    {
        id: '4.2.1.1-aki-key-identifier-present',
        // The issuer and subject differ, so the self-signed exemption does
        // not apply; an authorityKeyIdentifier naming only issuer and serial
        // fails the sentence as surely as no extension at all.
        fails: certificate({ extensions: [extension(AKI, sequence(tlv(2, true, 1, sequence()), tlv(2, false, 2, [0x01])))] }),
        passes: certificate({ extensions: [extension(AKI, sequence(tlv(2, false, 0, [0x01, 0x02, 0x03])))] }),
    },
    {
        id: '4.2.1.2-ski-present-in-ca',
        fails: certificate({ extensions: [extension(BASIC_CONSTRAINTS, CA_TRUE, true)] }),
        passes: certificate({ extensions: [extension(BASIC_CONSTRAINTS, CA_TRUE, true), extension(SKI, universal(4, [0x01, 0x02, 0x03]))] }),
    },

    // ── Since 1.0: the sentences recorded as not-diagnosed until then ──
    {
        id: '4.1.2.8-no-unique-ids',
        // A unique identifier at v2 is well placed and still forbidden.
        fails: certificate({ version: tlv(2, true, 0, universal(2, [1])), uniqueId: tlv(2, false, 2, [0x00, 0xff]) }),
        passes: certificate(),
    },
    {
        id: '4.2.1.1-aki-not-critical',
        fails: certificate({ extensions: [extension(AKI, sequence(tlv(2, false, 0, [0x01])), true)] }),
        passes: certificate({ extensions: [extension(AKI, sequence(tlv(2, false, 0, [0x01])))] }),
    },
    {
        id: '4.2.1.2-ski-in-end-entity',
        fails: certificate({ extensions: [extension(AKI, sequence(tlv(2, false, 0, [0x01])))] }),
        passes: certificate({ extensions: [extension(SKI, universal(4, [0x01]))] }),
    },
    {
        id: '4.2.1.2-ski-not-critical',
        fails: certificate({ extensions: [extension(SKI, universal(4, [0x01]), true)] }),
        passes: certificate({ extensions: [extension(SKI, universal(4, [0x01]))] }),
    },
    {
        id: '4.2.1.3-key-usage-critical',
        fails: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80]))] }),
        passes: certificate({ extensions: [extension(KEY_USAGE, universal(3, [0x07, 0x80]), true)] }),
    },
    {
        id: '4.2.1.4-any-policy-qualifiers',
        fails: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(ANY_POLICY, sequence(sequence(universal(6, [0x2a, 0x05]), universal(12, ascii('x')))))))] }),
        passes: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(ANY_POLICY, sequence(sequence(QUALIFIER_CPS, universal(22, ascii('http://cps.example/')))))))] }),
    },
    {
        id: '4.2.1.4-no-notice-ref',
        fails: certificate({ extensions: [notice(sequence(utf8Text('Org'), sequence(universal(2, [1]))), utf8Text('text'))] }),
        passes: certificate({ extensions: [notice(utf8Text('text'))] }),
    },
    {
        id: '4.2.1.4-explicit-text-utf8',
        fails: certificate({ extensions: [notice(bmp('text'))] }),
        passes: certificate({ extensions: [notice(universal(22, ascii('text')))] }),
    },
    {
        id: '4.2.1.4-explicit-text-not-visible-or-bmp',
        fails: certificate({ extensions: [notice(universal(26, ascii('text')))] }),
        passes: certificate({ extensions: [notice(utf8Text('text'))] }),
    },
    {
        id: '4.2.1.4-explicit-text-no-control',
        fails: certificate({ extensions: [notice(utf8Text('te\u0085xt'))] }),
        passes: certificate({ extensions: [notice(utf8Text('te xt'))] }),
    },
    {
        id: '4.2.1.4-explicit-text-nfc',
        fails: certificate({ extensions: [notice(utf8Text('é'))] }),
        passes: certificate({ extensions: [notice(utf8Text('é'))] }),
    },
    {
        id: '4.2.1.5-mapped-policy-asserted',
        fails: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(POLICY_B))), extension(POLICY_MAPPINGS, sequence(sequence(POLICY_A, POLICY_B)), true)] }),
        passes: certificate({ extensions: [extension(CERTIFICATE_POLICIES, sequence(sequence(POLICY_A))), extension(POLICY_MAPPINGS, sequence(sequence(POLICY_A, POLICY_B)), true)] }),
    },
    {
        id: '4.2.1.5-policy-mappings-critical',
        fails: certificate({ extensions: [extension(POLICY_MAPPINGS, sequence(sequence(POLICY_A, POLICY_B)))] }),
        passes: certificate({ extensions: [extension(POLICY_MAPPINGS, sequence(sequence(POLICY_A, POLICY_B)), true)] }),
    },
    {
        id: '4.2.1.6-san-not-critical-with-subject',
        fails: certificate({ extensions: [extension(SAN, sequence(dnsName('a.example')), true)] }),
        passes: certificate({ extensions: [extension(SAN, sequence(dnsName('a.example')))] }),
    },
    {
        id: '4.2.1.6-uri-absolute',
        fails: certificate({ extensions: [extension(SAN, sequence(uri('https://a.example/x y')))] }),
        passes: certificate({ extensions: [extension(IAN, sequence(uri('https://[2001:db8::1]:8443/x%20y?q#f')))] }),
    },
    {
        id: '4.2.1.6-uri-scheme-and-part',
        fails: certificate({ extensions: [extension(IAN, sequence(uri('urn:')))] }),
        passes: certificate({ extensions: [extension(SAN, sequence(uri('urn:x')))] }),
    },
    {
        id: '4.2.1.6-uri-host-fqdn-or-ip',
        fails: certificate({ extensions: [extension(SAN, sequence(uri('https://under_score.example/')))] }),
        passes: certificate({ extensions: [extension(SAN, sequence(uri('https://192.0.2.1/'), uri('https://a.example:8443/')))] }),
    },
    {
        id: '4.2.1.6-no-empty-general-name',
        fails: certificate({ extensions: [extension(SAN, sequence(dnsName('a.example'), tlv(2, true, 4, sequence())))] }),
        passes: certificate({ extensions: [extension(SAN, sequence(dnsName('a.example'), directory('a')))] }),
    },
    {
        id: '4.2.1.7-ian-not-critical',
        fails: certificate({ extensions: [extension(IAN, sequence(dnsName('a.example')), true)] }),
        passes: certificate({ extensions: [extension(IAN, sequence(dnsName('a.example')))] }),
    },
    {
        id: '4.2.1.10-no-min-max',
        fails: certificate({ extensions: [extension(NAME_CONSTRAINTS, subtree(dnsName('example.com'), tlv(2, false, 1, [0x02])), true)] }),
        passes: certificate({ extensions: [extension(NAME_CONSTRAINTS, subtree(dnsName('example.com')), true)] }),
    },
    {
        id: '4.2.1.10-uri-constraint-fqdn',
        fails: certificate({ extensions: [extension(NAME_CONSTRAINTS, subtree(uri('https://example.com/')), true)] }),
        passes: certificate({ extensions: [extension(NAME_CONSTRAINTS, subtree(uri('.example.com')), true)] }),
    },
    {
        id: '4.2.1.12-any-eku-not-critical',
        fails: certificate({ extensions: [extension(EKU, sequence(SERVER_AUTH, ANY_EKU), true)] }),
        passes: certificate({ extensions: [extension(EKU, sequence(SERVER_AUTH, ANY_EKU))] }),
    },
    {
        id: '4.2.1.13-crl-dp-not-critical',
        fails: certificate({ extensions: [extension(CRL_DP, sequence(byFullName(uri('http://crl.example/a.crl'))), true)] }),
        passes: certificate({ extensions: [extension(CRL_DP, sequence(byFullName(uri('http://crl.example/a.crl'))))] }),
    },
    {
        id: '4.2.1.13-dp-not-reasons-only',
        fails: certificate({ extensions: [extension(CRL_DP, sequence(sequence(tlv(2, false, 1, [0x06, 0x40]))))] }),
        passes: certificate({ extensions: [extension(CRL_DP, sequence(sequence(tlv(2, false, 1, [0x06, 0x40]), crlIssuers(directory('crl')))))] }),
    },
    {
        id: '4.2.1.13-ldap-uri-dn-and-attrdesc',
        fails: certificate({ extensions: [extension(FRESHEST_CRL, sequence(byFullName(uri('ldap://ldap.example/cn=CA?a,b'))))] }),
        passes: certificate({ extensions: [extension(CRL_DP, sequence(byFullName(uri('ldap://ldap.example/cn=CA?certificateRevocationList;binary'))))] }),
    },
    {
        id: '4.2.1.13-http-or-ldap-uri',
        fails: certificate({ extensions: [extension(CRL_DP, sequence(byFullName(uri('https://crl.example/a.crl'))))] }),
        passes: certificate({ extensions: [extension(CRL_DP, sequence(byFullName(uri('HTTP://crl.example/a.crl'))))] }),
    },
    {
        id: '4.2.1.13-no-relative-name',
        fails: certificate({ extensions: [extension(CRL_DP, sequence(sequence(RELATIVE, crlIssuers(directory('crl')))))] }),
        passes: certificate({ extensions: [extension(CRL_DP, sequence(byFullName(uri('http://crl.example/a.crl'))))] }),
    },
    {
        id: '4.2.1.13-relative-name-one-issuer',
        fails: certificate({ extensions: [extension(CRL_DP, sequence(sequence(RELATIVE, crlIssuers(directory('a'), directory('b')))))] }),
        passes: certificate({ extensions: [extension(CRL_DP, sequence(sequence(RELATIVE, crlIssuers(directory('a'), dnsName('b.example')))))] }),
    },
    {
        id: '4.2.1.14-inhibit-any-policy-critical',
        fails: certificate({ extensions: [extension(INHIBIT_ANY_POLICY, universal(2, [0x00]))] }),
        passes: certificate({ extensions: [extension(INHIBIT_ANY_POLICY, universal(2, [0x00]), true)] }),
    },
    {
        id: '4.2.1.15-freshest-crl-not-critical',
        fails: certificate({ extensions: [extension(FRESHEST_CRL, sequence(byFullName(uri('http://crl.example/d.crl'))), true)] }),
        passes: certificate({ extensions: [extension(FRESHEST_CRL, sequence(byFullName(uri('http://crl.example/d.crl'))))] }),
    },
    {
        id: '4.2.2.1-aia-not-critical',
        fails: certificate({ extensions: [extension(AIA, access(CA_ISSUERS, 'http://ca.example/ca.cer'), true)] }),
        passes: certificate({ extensions: [extension(AIA, access(CA_ISSUERS, 'http://ca.example/ca.cer'))] }),
    },
    {
        id: '4.2.2.1-ldap-uri-dn-and-attributes',
        fails: certificate({ extensions: [extension(AIA, access(CA_ISSUERS, 'ldap://ldap.example/cn=CA'))] }),
        passes: certificate({ extensions: [extension(AIA, access(CA_ISSUERS, 'ldap://ldap.example/cn=CA?cACertificate;binary,crossCertificatePair;binary'))] }),
    },
    {
        id: '4.2.2.1-ca-issuers-http-or-ldap',
        fails: certificate({ extensions: [extension(AIA, access(CA_ISSUERS, 'https://ca.example/ca.cer'))] }),
        passes: certificate({ extensions: [extension(AIA, access(CA_ISSUERS, 'http://ca.example/ca.cer'))] }),
    },
    {
        id: '4.2.2.2-sia-not-critical',
        fails: certificate({ extensions: [extension(SIA, access(CA_REPOSITORY, 'http://ca.example/r.p7c'), true)] }),
        passes: certificate({ extensions: [extension(SIA, access(CA_REPOSITORY, 'http://ca.example/r.p7c'))] }),
    },
    {
        id: '4.2.2.2-ldap-uri-dn-and-attributes',
        fails: certificate({ extensions: [extension(SIA, access(CA_REPOSITORY, 'ldap://ldap.example/?cACertificate'))] }),
        passes: certificate({ extensions: [extension(SIA, access(CA_REPOSITORY, 'ldap://ldap.example/cn=CA?cACertificate'))] }),
    },
    {
        id: '4.2.2.2-ca-repository-http-or-ldap',
        fails: certificate({ extensions: [extension(SIA, access(CA_REPOSITORY, 'ldaps://ldap.example/cn=CA?cACertificate'))] }),
        passes: certificate({ extensions: [extension(SIA, access(CA_REPOSITORY, 'ldap://ldap.example/cn=CA?cACertificate'))] }),
    },
];

describe('the RFC 5280 clause checker', () => {
    it('should have an evaluator for every clause, and a clause for every evaluator', () => {
        expect(EVALUATED_CLAUSE_IDS).toEqual([...CLAUSES.map((c) => c.id)].sort());
    });

    it('should have a failing and a passing certificate for every clause', () => {
        // Without this, a clause could be added to the table and silently
        // never tested — which is the failure mode the table exists to fix.
        expect(CASES.map((c) => c.id).sort()).toEqual([...CLAUSES.map((c) => c.id)].sort());
    });

    it.each(CASES)('$id should fail on a violating certificate', ({ id, fails }) => {
        expect(verdict(fails, id)).toBe('fail');
    });

    it.each(CASES)('$id should pass on a conforming certificate', ({ id, passes }) => {
        expect(verdict(passes, id)).toBe('pass');
    });

    it('should call a clause not-applicable rather than failed when the field is absent', () => {
        // The distinction that keeps attribution honest: a certificate with
        // no keyUsage does not violate §4.2.1.3, it is simply outside it.
        const bare = certificate();
        for (const id of ['4.2.1.3-key-usage-not-empty', '4.2.1.9-path-len-requires-ca', '4.2.1.6-alt-name-not-empty', '4.2.1.10-name-constraints-critical']) {
            expect(verdict(bare, id), id).toBe('not-applicable');
        }
    });

    it('should decide nothing at all about bytes that are not a certificate', () => {
        // L1 already judges whether these parse. A checker that reported
        // "clause violated" for unreadable bytes would attribute the wrong
        // thing to the wrong sentence.
        for (const bytes of [new Uint8Array(0), universal(2, [0x01]), sequence(universal(2, [0x01]))]) {
            const verdicts = [...evaluateClauses(bytes).values()];
            expect(verdicts.every((v) => v === 'not-applicable')).toBe(true);
        }
    });

    it('should name a suite for every clause the pinned corpus cannot exercise', () => {
        for (const clause of CLAUSES) {
            if (clause.unexercisedBy === undefined) continue;
            expect(clause.unexercisedBy.provenBy, clause.id).toBe('tests/conformance/clauses.test.ts');
            expect(clause.unexercisedBy.reason.length, clause.id).toBeGreaterThan(40);
            expect(CASES.some((c) => c.id === clause.id), `${clause.id} is waived but not exercised here`).toBe(true);
        }
    });

    it('should quote a normative sentence, not a paraphrase, for every clause', () => {
        for (const clause of CLAUSES) {
            expect(clause.quote, clause.id).toMatch(/\b(MUST|SHOULD|shall|MAY)\b/);
            expect(clause.section, clause.id).toMatch(/^(RFC \d+|ITU-T X\.\d+) §[\d.]+$/);
            if (clause.diagnostic === null) expect(clause.waiver, clause.id).toBeTruthy();
        }
    });

    it('should quote ITU-T X.690 (02/2021) word for word, whole sentences, for the clauses L5 cannot check against a pinned text', () => {
        // The RFC 5280 quotes are checked against the pinned RFC at L5. X.690
        // is published only as a PDF, so these three were compared by hand
        // with §11.2.2, §11.5 and §11.6 of the 02/2021 edition; a paraphrase
        // (an older edition's word order, a sentence cut at its first comma)
        // is what this test exists to refuse.
        const x690 = Object.fromEntries(CLAUSES.filter((c) => c.section.startsWith('ITU-T X.690')).map((c) => [c.section, c.quote]));
        expect(x690).toEqual({
            'ITU-T X.690 §11.2.2': 'Where Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.7, applies, the bitstring shall have all trailing 0 bits removed before it is encoded.',
            'ITU-T X.690 §11.5': 'The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.',
            'ITU-T X.690 §11.6': 'The encodings of the component values of a set-of value shall appear in ascending order, the encodings being compared as octet strings with the shorter components being padded at their trailing end with 0-octets.',
        });
    });
});
