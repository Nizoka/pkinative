import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints } from '../../src/build/build-structures.js';
import { checkRevocation } from '../../src/revocation/crl-check.js';
import { findRevocation, parseCertificateList } from '../../src/revocation/crl-parse.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 5280 §5.2.5 `issuingDistributionPoint`, §5.3.3 `certificateIssuer`, and
 * §6.3.3 (b) — what a revocation list is *about*.
 *
 * Everything here defends one direction of one mistake. A CRL is evidence of
 * absence: the serial is not on it. Evidence of absence is worth exactly what
 * the list's declared scope says it is worth, and a verifier that ignores the
 * declaration reads "I am not about this certificate" as "this certificate is
 * not revoked". That is how a revoked sub-CA is accepted by a validator holding
 * the CA's own, correctly published, end-entity list.
 *
 * So every assertion below that expects a refusal is asserting the *safe*
 * direction, and the two that expect acceptance are the canaries against a
 * scope check that simply refuses everything.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const AT = Date.UTC(2026, 2, 1);
const DAY = 86_400_000;

const ALG = sequence(universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), universal(5, []));
const CN_OID = universal(6, [0x55, 0x04, 0x03]);
const O_OID = universal(6, [0x55, 0x04, 0x0a]);
/** One `AttributeTypeAndValue`, which is also the content of an implicitly tagged RDN. */
const attribute = (type: Uint8Array, value: string): Uint8Array => sequence(type, universal(12, ascii(value)));
/** One `RelativeDistinguishedName`: a SET OF the above. */
const rdnOf = (type: Uint8Array, value: string): Uint8Array => universal(17, attribute(type, value), true);
/** A `Name` from its RDNs, in encoded order — least significant first. */
const dnOf = (...rdns: readonly Uint8Array[]): Uint8Array => sequence(...rdns);
const nameOf = (value: string): Uint8Array => dnOf(rdnOf(CN_OID, value));
const utc = (text: string): Uint8Array => universal(23, ascii(text));
const int = (...bytes: readonly number[]): Uint8Array => universal(2, bytes);

const OID_IDP = [0x55, 0x1d, 0x1c];
const OID_CERTIFICATE_ISSUER = [0x55, 0x1d, 0x1d];
const OID_CDP = '2.5.29.31';

// ── GeneralName and DistributionPointName, by hand ───────────────────

/** `uniformResourceIdentifier [6] IA5String`. */
const uri = (text: string): Uint8Array => tlv(2, false, 6, ascii(text));
/** `directoryName [4] Name` — EXPLICIT, because Name is itself a CHOICE. */
const directoryName = (value: string): Uint8Array => tlv(2, true, 4, nameOf(value));
/** `[0] DistributionPointName` wrapping `fullName [0] GeneralNames`. */
const fullName = (...names: readonly Uint8Array[]): Uint8Array => tlv(2, true, 0, tlv(2, true, 0, concat(...names)));

/** One `DistributionPoint`, for a certificate's `cRLDistributionPoints`. */
function distributionPoint(options: { readonly at?: string; readonly name?: Uint8Array; readonly issuedBy?: string } = {}): Uint8Array {
    return sequence(
        ...(options.at === undefined ? [] : [fullName(uri(options.at))]),
        ...(options.name === undefined ? [] : [fullName(options.name)]),
        ...(options.issuedBy === undefined ? [] : [tlv(2, true, 2, directoryName(options.issuedBy))]),
    );
}

interface IdpOptions {
    readonly at?: string;
    /** `fullName` from already-encoded GeneralNames, for the directory forms. */
    readonly names?: readonly Uint8Array[];
    readonly onlyUserCerts?: boolean;
    readonly onlyCACerts?: boolean;
    readonly onlySomeReasons?: readonly number[];
    readonly indirect?: boolean;
    readonly onlyAttributeCerts?: boolean;
}

/** An `IssuingDistributionPoint` value, in encoded field order. */
function idp(options: IdpOptions): Uint8Array {
    return sequence(
        ...(options.at === undefined ? [] : [fullName(uri(options.at))]),
        ...(options.names === undefined ? [] : [fullName(...options.names)]),
        ...(options.onlyUserCerts === true ? [tlv(2, false, 1, [0xff])] : []),
        ...(options.onlyCACerts === true ? [tlv(2, false, 2, [0xff])] : []),
        ...(options.onlySomeReasons === undefined ? [] : [tlv(2, false, 3, options.onlySomeReasons)]),
        ...(options.indirect === true ? [tlv(2, false, 4, [0xff])] : []),
        ...(options.onlyAttributeCerts === true ? [tlv(2, false, 5, [0xff])] : []),
    );
}

const extension = (oid: readonly number[], value: Uint8Array, critical = true): Uint8Array =>
    sequence(universal(6, oid), universal(1, [critical ? 0xff : 0x00]), universal(4, value));

const entry = (serial: readonly number[], ...extensions: readonly Uint8Array[]): Uint8Array =>
    sequence(int(...serial), utc('260201000000Z'), ...(extensions.length === 0 ? [] : [sequence(...extensions)]));

interface CrlOptions {
    readonly issuer?: string;
    /** A multi-RDN issuer, for the names composed relative to it. */
    readonly issuerDer?: Uint8Array;
    readonly entries?: readonly Uint8Array[];
    readonly extensions?: readonly Uint8Array[];
}

function buildCrl(options: CrlOptions = {}): Uint8Array {
    const extensions = options.extensions ?? [];
    const tbs = sequence(
        int(0x01),
        ALG,
        options.issuerDer ?? nameOf(options.issuer ?? 'Example CA'),
        utc('260101000000Z'),
        utc('260701000000Z'),
        sequence(...(options.entries ?? [entry([0x07])])),
        ...(extensions.length === 0 ? [] : [tlv(2, true, 0, sequence(...extensions))]),
    );
    return sequence(tbs, ALG, universal(3, [0x00, 0xaa]));
}

// ── Certificates ─────────────────────────────────────────────────────

interface CertOptions {
    readonly serial?: bigint;
    readonly issuer?: string;
    readonly issuerDer?: Uint8Array;
    readonly cA?: boolean;
    readonly points?: readonly Uint8Array[];
}

async function certificate(options: CertOptions = {}): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const points = options.points ?? [];
    const der = await createCertificate({
        serialNumber: options.serial ?? 7n,
        issuerDer: options.issuerDer ?? nameOf(options.issuer ?? 'Example CA'),
        subject: [[{ type: '2.5.4.3', value: 'host.example' }]],
        notBefore: AT - DAY,
        notAfter: AT + DAY,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: options.cA ?? false }) },
            ...(points.length === 0 ? [] : [{ oid: OID_CDP, critical: false, value: sequence(...points) }]),
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

/** The scope decision alone: a verified, current list, so nothing else can speak. */
function codesFor(cert: Certificate, crlDer: Uint8Array): readonly string[] {
    const crl = parseCertificateList(crlDer, quiet);
    return checkRevocation({ certificate: cert, crl, crlDer, at: AT, signatureVerified: true, options: quiet })
        .map((reason) => reason.code);
}

const EE = await certificate({ serial: 9n });
const CA = await certificate({ serial: 9n, cA: true });

describe('issuingDistributionPoint, decoded', () => {
    it('should read every field of a fully populated IssuingDistributionPoint', () => {
        const value = idp({ at: 'http://crl.example/a.crl', onlyUserCerts: true, onlySomeReasons: [0x01, 0x60], indirect: true });
        const list = parseCertificateList(buildCrl({ extensions: [extension(OID_IDP, value)] }), quiet);
        const point = list.issuingDistributionPoint;
        expect(point?.onlyContainsUserCerts).toBe(true);
        expect(point?.onlyContainsCACerts).toBe(false);
        expect(point?.indirectCRL).toBe(true);
        expect(point?.onlyContainsAttributeCerts).toBe(false);
        expect(point?.onlySomeReasons).toEqual(['keyCompromise', 'cACompromise']);
        expect(point?.fullName?.[0]).toMatchObject({ kind: 'uniformResourceIdentifier', value: 'http://crl.example/a.crl' });
    });

    it('should leave issuingDistributionPoint undefined when the list carries none', () => {
        expect(parseCertificateList(buildCrl(), quiet).issuingDistributionPoint).toBeUndefined();
    });

    it('should not call its own critical extensions unknown', () => {
        // §5.2.5 requires the extension to be critical. Passing it to the
        // certificate decoder — which has never heard of it — put
        // PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION on every correctly formed CRL.
        const diagnostics: string[] = [];
        const list = parseCertificateList(buildCrl({ extensions: [extension(OID_IDP, idp({ onlyUserCerts: true }))] }),
            { onDiagnostic: (d): void => { diagnostics.push(d.code); } });
        expect(list.issuingDistributionPoint?.onlyContainsUserCerts).toBe(true);
        expect(diagnostics).toEqual([]);
    });

    it('should refuse the whole list when the extension cannot be read', () => {
        // Not shrugged off the way a malformed cRLNumber is. An unreadable IDP
        // leaves the list's scope unknown, and an unknown scope read as
        // "unrestricted" is the exact misreading this extension prevents.
        const broken = buildCrl({ extensions: [extension(OID_IDP, universal(2, [0x01]))] });
        expect(() => parseCertificateList(broken, quiet)).toThrow(expect.objectContaining({ code: 'PKI_X509_EXTENSION_MALFORMED' }));
    });

    it('should read a field written out as FALSE the same as an absent one', () => {
        // Every boolean is DEFAULT FALSE, so DER says not to encode it — but
        // encoders do, and a reader that took "present" for "true" would read
        // an unrestricted list as covering nothing.
        const spelled = sequence(
            tlv(2, false, 1, [0x00]),
            tlv(2, false, 2, [0x00]),
            tlv(2, false, 4, [0x00]),
            tlv(2, false, 5, [0x00]),
        );
        const point = parseCertificateList(buildCrl({ extensions: [extension(OID_IDP, spelled)] }), quiet).issuingDistributionPoint;
        expect(point).toMatchObject({
            onlyContainsUserCerts: false,
            onlyContainsCACerts: false,
            indirectCRL: false,
            onlyContainsAttributeCerts: false,
        });
    });

    it('should refuse an IssuingDistributionPoint whose fields are out of order', () => {
        const outOfOrder = sequence(tlv(2, false, 4, [0xff]), tlv(2, false, 1, [0xff]));
        expect(() => parseCertificateList(buildCrl({ extensions: [extension(OID_IDP, outOfOrder)] }), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_EXTENSION_MALFORMED' }));
    });
});

describe('the kind of certificate a list is about (RFC 5280 §5.2.5)', () => {
    it('should refuse to answer for a CA from a list of end-entity certificates', () => {
        // The one that matters: the CA's list is real, signed, current and does
        // not mention the sub-CA — because it never covered it.
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlyUserCerts: true }))] });
        expect(codesFor(CA, crl)).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should answer for an end-entity certificate from that same list', () => {
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlyUserCerts: true }))] });
        expect(codesFor(EE, crl)).toEqual([]);
    });

    it('should refuse to answer for an end-entity certificate from a CA-only list', () => {
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlyCACerts: true }))] });
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should answer for a CA from that same list', () => {
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlyCACerts: true }))] });
        expect(codesFor(CA, crl)).toEqual([]);
    });

    it('should never answer for a public-key certificate from an attribute-certificate list', () => {
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlyAttributeCerts: true }))] });
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
        expect(codesFor(CA, crl)).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should still report the revocation when a listed serial is on an out-of-scope list', async () => {
        // Scope decides what silence means, not what a hit means. A CA that
        // says "revoked" about a certificate it also says it does not cover is
        // confused, and burying the revocation would be the wrong half to keep.
        const listed = await certificate({ serial: 7n, cA: true });
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlyUserCerts: true }))] });
        expect(codesFor(listed, crl)).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE', 'PKI_REASON_REVOKED']);
    });
});

describe('the distribution point a list is published at (RFC 5280 §6.3.3 (b)(2))', () => {
    const POINT = 'http://crl.example/one.crl';
    const OTHER = 'http://crl.example/two.crl';

    it('should answer when the certificate names the point the list declares', async () => {
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ at: POINT })] });
        expect(codesFor(cert, buildCrl({ extensions: [extension(OID_IDP, idp({ at: POINT }))] }))).toEqual([]);
    });

    it('should refuse a list published at a point the certificate does not name', async () => {
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ at: POINT })] });
        expect(codesFor(cert, buildCrl({ extensions: [extension(OID_IDP, idp({ at: OTHER }))] })))
            .toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a scoped list when the certificate names no distribution point at all', () => {
        // Nothing in the certificate connects it to that point, and assuming it
        // does is precisely the assumption the extension exists to forbid.
        expect(codesFor(EE, buildCrl({ extensions: [extension(OID_IDP, idp({ at: POINT }))] })))
            .toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should answer from an unscoped list however many points the certificate names', async () => {
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ at: POINT }), distributionPoint({ at: OTHER })] });
        expect(codesFor(cert, buildCrl())).toEqual([]);
    });

    it('should try every point the certificate names, not only the first', async () => {
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ at: OTHER }), distributionPoint({ at: POINT })] });
        expect(codesFor(cert, buildCrl({ extensions: [extension(OID_IDP, idp({ at: POINT }))] }))).toEqual([]);
    });

    it('should report a wrong issuer for a list from another CA, distribution points or not', async () => {
        // A point that delegates to nobody delegates to nobody: naming where a
        // list is published never widens who may publish it.
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ at: POINT })] });
        expect(codesFor(cert, buildCrl({ issuer: 'Somebody Else' }))).toEqual(['PKI_REASON_REVOCATION_WRONG_ISSUER']);
    });

    it('should refuse a relatively named point for a certificate that names none either', () => {
        const relative = sequence(tlv(2, true, 0, tlv(2, true, 1, sequence(CN_OID, universal(12, ascii('crl'))))));
        expect(codesFor(EE, buildCrl({ extensions: [extension(OID_IDP, relative)] })))
            .toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a scoped list against a distribution point that names nothing to compare', async () => {
        // `DistributionPoint` has three optional fields and no required one, so
        // an empty one is legal DER and names neither a point nor a cRLIssuer.
        // There is nothing to match the list's own name against, and matching
        // nothing must not come out as matching everything.
        const cert = await certificate({ serial: 9n, points: [sequence()] });
        expect(codesFor(cert, buildCrl({ extensions: [extension(OID_IDP, idp({ at: POINT }))] })))
            .toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a distribution point named relative to the CRL issuer rather than guess', async () => {
        // `nameRelativeToCRLIssuer [1] RelativeDistinguishedName`: the implicit
        // [1] *replaces* the SET tag, so the AttributeTypeAndValue sequences sit
        // directly inside it. Wrapping one more level is the standing mistake.
        const relative = sequence(tlv(2, true, 0, tlv(2, true, 1, sequence(CN_OID, universal(12, ascii('crl'))))));
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ at: POINT })] });
        expect(codesFor(cert, buildCrl({ extensions: [extension(OID_IDP, relative)] })))
            .toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });
});

describe('indirect CRLs (RFC 5280 §5.2.5, §5.3.3)', () => {
    const DELEGATE = 'Indirect CRL Issuer';

    it('should accept a delegated list when the certificate names the cRLIssuer and the list asserts indirectCRL', async () => {
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ issuedBy: DELEGATE })] });
        const crl = buildCrl({ issuer: DELEGATE, extensions: [extension(OID_IDP, idp({ indirect: true }))] });
        expect(codesFor(cert, crl)).toEqual([]);
    });

    it('should refuse a delegated list that does not assert indirectCRL', async () => {
        // Without the assertion, any CA named in any cRLIssuer field could
        // answer for certificates it never issued and never claimed to cover.
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ issuedBy: DELEGATE })] });
        expect(codesFor(cert, buildCrl({ issuer: DELEGATE }))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should report a wrong issuer, not a wrong scope, for a list from a CA the certificate never named', async () => {
        const cert = await certificate({ serial: 9n, points: [distributionPoint({ issuedBy: DELEGATE })] });
        const crl = buildCrl({ issuer: 'Somebody Else', extensions: [extension(OID_IDP, idp({ indirect: true }))] });
        expect(codesFor(cert, crl)).toEqual(['PKI_REASON_REVOCATION_WRONG_ISSUER']);
    });

    it('should attribute an entry to the CA its certificateIssuer names', async () => {
        const cert = await certificate({ serial: 7n, issuer: 'Example CA', points: [distributionPoint({ issuedBy: DELEGATE })] });
        const crl = buildCrl({
            issuer: DELEGATE,
            extensions: [extension(OID_IDP, idp({ indirect: true }))],
            entries: [entry([0x07], extension(OID_CERTIFICATE_ISSUER, sequence(directoryName('Example CA'))))],
        });
        expect(codesFor(cert, crl)).toEqual(['PKI_REASON_REVOKED']);
    });

    it('should not attribute an entry to a CA other than the one it names', async () => {
        // Two CAs issue the same serial all the time. On an indirect list the
        // serial alone is not an identity, and treating it as one revokes an
        // innocent certificate — the false positive this state exists to stop.
        const cert = await certificate({ serial: 7n, issuer: 'Example CA', points: [distributionPoint({ issuedBy: DELEGATE })] });
        const crl = buildCrl({
            issuer: DELEGATE,
            extensions: [extension(OID_IDP, idp({ indirect: true }))],
            entries: [entry([0x07], extension(OID_CERTIFICATE_ISSUER, sequence(directoryName('Another CA'))))],
        });
        expect(codesFor(cert, crl)).toEqual([]);
    });

    it('should carry certificateIssuer forward to the entries that follow it', () => {
        // §5.3.3: an entry without the extension belongs to the last CA named
        // before it. Reading the state only on a serial hit would mis-attribute
        // every entry after the first one that sets it.
        const crl = buildCrl({
            issuer: 'Indirect CRL Issuer',
            extensions: [extension(OID_IDP, idp({ indirect: true }))],
            entries: [
                entry([0x01], extension(OID_CERTIFICATE_ISSUER, sequence(directoryName('Example CA')))),
                entry([0x02]),
            ],
        });
        const wanted = { issuerDer: nameOf('Example CA'), ...quiet };
        expect(findRevocation(crl, Uint8Array.of(0x02), wanted)?.serialNumber.hex).toBe('02');
        expect(findRevocation(crl, Uint8Array.of(0x02), { issuerDer: nameOf('Another CA'), ...quiet })).toBeUndefined();
    });

    it('should default an entry before any certificateIssuer to the CRL issuer', () => {
        const crl = buildCrl({
            issuer: 'Example CA',
            extensions: [extension(OID_IDP, idp({ indirect: true }))],
            entries: [entry([0x05]), entry([0x06], extension(OID_CERTIFICATE_ISSUER, sequence(directoryName('Another CA'))))],
        });
        expect(findRevocation(crl, Uint8Array.of(0x05), { issuerDer: nameOf('Example CA'), ...quiet })?.serialNumber.hex).toBe('05');
        expect(findRevocation(crl, Uint8Array.of(0x06), { issuerDer: nameOf('Example CA'), ...quiet })).toBeUndefined();
    });

    it('should answer for the CRL issuer when an indirect list is asked without one', () => {
        // §5.3.3's own default, and the honest answer to "revoked by whom?"
        // when the caller did not say whose certificate they are asking about.
        const crl = buildCrl({
            issuer: 'Example CA',
            extensions: [extension(OID_IDP, idp({ indirect: true }))],
            entries: [entry([0x07]), entry([0x08], extension(OID_CERTIFICATE_ISSUER, sequence(directoryName('Another CA'))))],
        });
        expect(findRevocation(crl, Uint8Array.of(0x07), quiet)?.serialNumber.hex).toBe('07');
        expect(findRevocation(crl, Uint8Array.of(0x08), quiet)).toBeUndefined();
    });

    it('should ignore issuerDer on a list that is not indirect', () => {
        // The fast path: a direct CRL is walked without decoding one entry
        // extension, and every entry is about its own issuer by definition.
        const crl = buildCrl({ entries: [entry([0x07])] });
        expect(findRevocation(crl, Uint8Array.of(0x07), { issuerDer: nameOf('Anything At All'), ...quiet })?.serialNumber.hex).toBe('07');
    });

    it('should take a certificateIssuer that names no directoryName as naming nothing', () => {
        // A GeneralNames of URIs attributes the entry to something this library
        // cannot compare an issuer against, so the running state is unchanged —
        // which leaves the entry with the previous CA, never with everyone.
        const crl = buildCrl({
            issuer: 'Example CA',
            extensions: [extension(OID_IDP, idp({ indirect: true }))],
            entries: [entry([0x07], extension(OID_CERTIFICATE_ISSUER, sequence(uri('http://ca.example'))))],
        });
        expect(findRevocation(crl, Uint8Array.of(0x07), { issuerDer: nameOf('Example CA'), ...quiet })?.serialNumber.hex).toBe('07');
    });
});

describe('a point named relative to the CRL issuer (RFC 5280 §4.2.1.13)', () => {
    // A two-RDN CA, so that composition has something to compose with: a name
    // is a sequence of RDNs, and appending one to a single-RDN issuer would
    // pass a length test that means nothing.
    const CA = dnOf(rdnOf(O_OID, 'Example Org'), rdnOf(CN_OID, 'Example CA'));
    const composed = (value: string): Uint8Array => tlv(2, true, 4, dnOf(rdnOf(O_OID, 'Example Org'), rdnOf(CN_OID, 'Example CA'), rdnOf(CN_OID, value)));
    /** `[0] DistributionPointName` wrapping `nameRelativeToCRLIssuer [1]`, whose implicit tag replaces the SET. */
    const relative = (type: Uint8Array, value: string): Uint8Array => tlv(2, true, 0, tlv(2, true, 1, attribute(type, value)));
    const relativePoint = (type: Uint8Array, value: string): Uint8Array => sequence(relative(type, value));
    const relativeIdp = (type: Uint8Array, value: string): Uint8Array => sequence(relative(type, value));

    const certFor = async (...points: readonly Uint8Array[]): Promise<Certificate> =>
        certificate({ serial: 9n, issuerDer: CA, points });
    const crlWith = (value: Uint8Array): Uint8Array => buildCrl({ issuerDer: CA, extensions: [extension(OID_IDP, value)] });

    it('should compose the certificate side against a fullName the list declares', async () => {
        // NIST builds four tests on this form. A first version refused it
        // rather than compose, which turned four valid paths into unproven
        // ones — the safe direction, and still the wrong answer.
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        expect(codesFor(cert, crlWith(idp({ names: [composed('CRL1')] })))).toEqual([]);
    });

    it('should compose the list side against a fullName the certificate declares', async () => {
        const cert = await certFor(distributionPoint({ name: composed('CRL1') }));
        expect(codesFor(cert, crlWith(relativeIdp(CN_OID, 'CRL1')))).toEqual([]);
    });

    it('should match two relative names against each other', async () => {
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        expect(codesFor(cert, crlWith(relativeIdp(CN_OID, 'CRL1')))).toEqual([]);
    });

    it('should refuse two relative names that differ', async () => {
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        expect(codesFor(cert, crlWith(relativeIdp(CN_OID, 'CRL2')))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a composed name whose last RDN differs', async () => {
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        expect(codesFor(cert, crlWith(idp({ names: [composed('CRL2')] })))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a composed name whose attribute type differs', async () => {
        // Same text, different attribute. Comparing the rendered string would
        // call these one name; comparing type and encoded value does not.
        const cert = await certFor(relativePoint(O_OID, 'CRL1'));
        expect(codesFor(cert, crlWith(idp({ names: [composed('CRL1')] })))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a name that is not one RDN longer than the issuer', async () => {
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        const tooShort = tlv(2, true, 4, dnOf(rdnOf(O_OID, 'Example Org'), rdnOf(CN_OID, 'CRL1')));
        expect(codesFor(cert, crlWith(idp({ names: [tooShort] })))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a name whose prefix is not the CRL issuer', async () => {
        // The right length and the right last RDN, under somebody else's name.
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        const elsewhere = tlv(2, true, 4, dnOf(rdnOf(O_OID, 'Other Org'), rdnOf(CN_OID, 'Example CA'), rdnOf(CN_OID, 'CRL1')));
        expect(codesFor(cert, crlWith(idp({ names: [elsewhere] })))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a relative name holding more attributes than the one it is compared with', async () => {
        // A multi-valued RDN — `CN=CRL1+O=Example Org` — against a composed
        // name whose last RDN holds one attribute. Same first attribute, and
        // not the same name.
        const cert = await certFor(sequence(tlv(2, true, 0, tlv(2, true, 1, concat(attribute(CN_OID, 'CRL1'), attribute(O_OID, 'Example Org'))))));
        expect(codesFor(cert, crlWith(idp({ names: [composed('CRL1')] })))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should refuse a relative name against a list naming only a URI', async () => {
        // Nothing to compose against: a URI is not a directory name.
        const cert = await certFor(relativePoint(CN_OID, 'CRL1'));
        expect(codesFor(cert, crlWith(idp({ at: 'http://crl.example/one.crl' })))).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });
});

describe('a list this implementation only half understands (RFC 5280 §6.3.3)', () => {
    const OID_DELTA = [0x55, 0x1d, 0x1b];

    it('should not answer from a delta CRL', () => {
        // A delta lists what *changed*. Read as complete it reports every
        // certificate absent from it — nearly all of them — as unrevoked, which
        // is the one misreading that turns a revocation list into a blanket
        // clearance. §5.2.4 applies one properly; until then it answers nothing.
        const crl = buildCrl({ extensions: [extension(OID_DELTA, int(0x02))] });
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_REVOCATION_OUT_OF_SCOPE']);
    });

    it('should say a delta is a delta rather than call it unrecognised', () => {
        // `deltaCRLIndicator` is critical and is not in the processed set, so
        // the generic rule below would catch it first and report a list nobody
        // understands. This library understands it exactly well enough to know
        // it must not answer from it, and that is a different sentence.
        const crlDer = buildCrl({ extensions: [extension(OID_DELTA, int(0x02))] });
        const crl = parseCertificateList(crlDer, quiet);
        const [reason] = checkRevocation({ certificate: EE, crl, crlDer, at: AT, signatureVerified: true, options: quiet });
        expect(reason?.message).toContain('delta CRL');
    });

    it('should not read a removeFromCRL entry as a revocation', async () => {
        // The one entry reason that means the opposite of the list it sits on.
        // Only a delta may carry it, and it says the base list's revocation has
        // been lifted — so "revoked (reason: removeFromCRL)" would be a sentence
        // that is wrong in both halves.
        const OID_REASON = [0x55, 0x1d, 0x15];
        const listed = await certificate({ serial: 7n });
        const reasoned = (code: number): Uint8Array =>
            buildCrl({ entries: [entry([0x07], extension(OID_REASON, universal(10, [code])))] });
        // 1 is keyCompromise: the same entry, the same serial, the same shape —
        // so that the assertion below is about the reason and nothing else.
        expect(codesFor(listed, reasoned(0x01))).toEqual(['PKI_REASON_REVOKED']);
        expect(codesFor(listed, reasoned(0x08))).toEqual([]);
    });

    it('should refuse to use a list carrying a critical extension it cannot process', () => {
        const crl = buildCrl({ extensions: [extension([0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x8d, 0x1f, 0x01], universal(5, []))] });
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION']);
    });

    it('should tolerate the same extension when it is not critical', () => {
        // Non-critical is the issuer saying "ignore this if you like", and
        // refusing anyway would make every CRL with a vendor extension unusable.
        const crl = buildCrl({ extensions: [extension([0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x8d, 0x1f, 0x01], universal(5, []), false)] });
        expect(codesFor(EE, crl)).toEqual([]);
    });

    it('should not raise the question at all for a list about another CA', () => {
        // Both rules are facts about the list alone, so asking them first would
        // report every unreadable list a caller happens to hold, about any CA,
        // against every certificate. A list that is not about this certificate
        // raises no question about this certificate.
        const crl = buildCrl({ issuer: 'Somebody Else', extensions: [extension([0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x8d, 0x1f, 0x01], universal(5, []))] });
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_REVOCATION_WRONG_ISSUER']);
    });
});

describe('onlySomeReasons (RFC 5280 §5.2.5)', () => {
    it('should report what a partial list actually ruled out, and no more', () => {
        // keyCompromise only. The serial's absence rules out keyCompromise and
        // nothing else, and reporting that as "not revoked" is the same mistake
        // as ignoring the scope, one step finer.
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlySomeReasons: [0x06, 0x40] }))] });
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_REVOCATION_PARTIAL']);
    });

    it('should say which reasons the list did cover', () => {
        const crlDer = buildCrl({ extensions: [extension(OID_IDP, idp({ onlySomeReasons: [0x06, 0x40] }))] });
        const crl = parseCertificateList(crlDer, quiet);
        const [reason] = checkRevocation({ certificate: EE, crl, crlDer, at: AT, signatureVerified: true, options: quiet });
        expect(reason?.message).toContain('keyCompromise');
    });

    it('should report a partial answer for a list that covers no reason at all', () => {
        // An empty ReasonFlags rules out nothing, so the list is evidence of
        // nothing — and it still has to say so rather than come back clean.
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlySomeReasons: [0x00] }))] });
        const parsed = parseCertificateList(crl, quiet);
        expect(parsed.issuingDistributionPoint?.onlySomeReasons).toEqual([]);
        expect(codesFor(EE, crl)).toEqual(['PKI_REASON_REVOCATION_PARTIAL']);
    });

    it('should not add a partial answer when the certificate is on the list', async () => {
        const listed = await certificate({ serial: 7n });
        const crl = buildCrl({ extensions: [extension(OID_IDP, idp({ onlySomeReasons: [0x06, 0x40] }))] });
        expect(codesFor(listed, crl)).toEqual(['PKI_REASON_REVOKED']);
    });
});
