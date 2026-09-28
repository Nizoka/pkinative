import { describe, expect, it } from 'vitest';
import { encodeTlv } from '../../src/asn1/asn1-encode.js';
import { addTimeStampToken, createSignedData, type CreateSignedDataInput } from '../../src/build/build-signed-data.js';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import { KEY_PURPOSES } from '../../src/path/path-purpose.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { verifySignedData, type VerifySignedDataInput } from '../../src/verify/verify-signed-data.js';
import {
    alg,
    attribute,
    CONTENT as HELLO,
    contentInfo,
    octets,
    oid,
    OIDS,
    set,
    signedData as signedDataOf,
    signerInfo,
    sorted,
    subjectKeyIdentifier,
} from '../helpers/cms-signed-data-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';
import {
    AT,
    type Authority,
    codes,
    DAY,
    eku,
    type Family,
    flipLastOctetOf,
    type Holder,
    issue,
    issueTsa,
    keyPair,
    makeCrl,
    makeRoot,
    makeToken,
    OID,
    rawSign,
    sha,
    signerInfosOf,
    tstInfo,
    withCertificates,
    withSigners,
} from './_cms-pki.js';

/**
 * `verifySignedData`: RFC 5652 §5.6 for every signer, its timestamps, and its
 * chain, in one call that reports rather than throws.
 *
 * Every signature is real. The messages are written by `createSignedData`
 * where it can write them, and field by field with the engine-independent
 * CMS builder where it cannot — a signer without signed attributes, a SHA-1
 * signer, an algorithm pair that contradicts itself.
 */

const CONTENT = new TextEncoder().encode('a PDF byte range, or an e-mail body');
const SKI = Uint8Array.of(0x5c, 0x1d, 0x00, 0x01);

interface World {
    readonly root: Authority;
    readonly signer: Holder;
}

async function world(options: Parameters<typeof issue>[1] = {}): Promise<World> {
    const root = await makeRoot();
    return { root, signer: await issue(root, options) };
}

const sign = async (w: World, extra: Partial<CreateSignedDataInput> = {}): Promise<Uint8Array> =>
    createSignedData({ content: CONTENT, certificate: w.signer.certificate, ...extra }, w.signer.signer);

const verify = async (w: World, signedData: Uint8Array, extra: Partial<VerifySignedDataInput> = {}): ReturnType<typeof verifySignedData> =>
    verifySignedData({ signedData, trustAnchors: [w.root.certificate], at: AT, ...extra });

const paths = (report: { readonly reasons: ReadonlyArray<{ readonly path: string }> }): string[] => report.reasons.map((r) => r.path);

/** The `IssuerAndSerialNumber` of a certificate, built by hand. */
const sidOf = (certificate: Certificate): Uint8Array =>
    sequence(certificate.issuer.der, encodeTlv('universal', 2, false, certificate.serialNumber.bytes));

describe('verifySignedData', () => {
    describe('a signer that is what it claims', () => {
        it.each(['ECDSA', 'RSA', 'Ed25519'] as const)('should accept a %s signer with its content attached', async (family: Family) => {
            const w = await world({ family });
            const report = await verify(w, await sign(w));
            expect(codes(report)).toEqual([]);
            expect(report.valid).toBe(true);
            const [signer] = report.signers;
            expect(signer?.index).toBe(0);
            expect(signer?.valid).toBe(true);
            expect(signer?.intact).toBe(true);
            expect(signer?.certificate?.der).toEqual(w.signer.certificate.der);
            expect(signer?.chain?.valid).toBe(true);
            expect(signer?.timeStamps).toEqual([]);
            expect(signer?.signingTime).toBeUndefined();
            expect(report.signedData?.content).toEqual(CONTENT);
            // The signer's signature, and the root's over the signer's certificate.
            expect(report.verified).toBe(2);
        });

        it('should accept detached content passed alongside', async () => {
            const w = await world();
            expect(codes(await verify(w, await sign(w, { detached: true }), { content: CONTENT }))).toEqual([]);
        });

        it('should accept the digest of detached content instead of the content — the PDF case', async () => {
            const w = await world();
            const digest = await sha('SHA-256', CONTENT);
            const p7s = await sign(w, { content: undefined, contentDigest: digest });
            expect(codes(await verify(w, p7s, { contentDigest: digest }))).toEqual([]);
        });

        it('should report the time the signer claims, and not rely on it', async () => {
            const w = await world();
            const report = await verify(w, await sign(w, { signingTime: AT }));
            expect(report.signers[0]?.signingTime?.epochMilliseconds).toBe(AT);
            expect(report.valid).toBe(true);
        });

        it('should find a signer named by subjectKeyIdentifier', async () => {
            const w = await world({ ski: SKI });
            expect(codes(await verify(w, await sign(w, { sid: 'subjectKeyIdentifier' })))).toEqual([]);
        });

        it('should find a signer the message does not carry among the certificates passed', async () => {
            const w = await world();
            const bare = withCertificates(await sign(w), []);
            expect(codes(await verify(w, bare, { certificates: [w.signer.certificate] }))).toEqual([]);
        });

        it('should ignore trailing bytes only when allowTrailingData says so — the zero padding of a PDF /Contents', async () => {
            const w = await world();
            const p7s = await sign(w);
            const padded = new Uint8Array(p7s.length + 64);
            padded.set(p7s);
            const refused = await verify(w, padded);
            expect(codes(refused)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
            expect(refused.reasons[0]?.errorCode).toBe('PKI_ASN1_TRAILING_DATA');
            expect(codes(await verify(w, padded, { allowTrailingData: true }))).toEqual([]);
        });

        it('should read a message under BER when asked', async () => {
            const w = await world();
            expect(codes(await verify(w, await sign(w), { encodingRules: 'ber' }))).toEqual([]);
        });

        it('should judge each signer of a multi-signer message, and call the message valid only when every one is', async () => {
            const w = await world();
            const other = await issue(w.root, { family: 'Ed25519', serial: 7n, subject: 'Second Signer' });
            const good = signerInfosOf(await sign(w))[0] as Uint8Array;
            // A second signer that signed other content.
            const bad = signerInfosOf(await createSignedData({ content: HELLO, certificate: other.certificate }, other.signer))[0] as Uint8Array;
            const infos = [good, bad].sort((a, b) => Buffer.compare(a, b));
            const message = withCertificates(withSigners(await sign(w), infos), [w.signer.certificate.der, other.certificate.der]);

            const report = await verify(w, message);
            expect(report.valid).toBe(false);
            expect(report.signers).toHaveLength(2);
            const badIndex = infos.indexOf(bad);
            expect(report.signers[1 - badIndex]?.valid).toBe(true);
            expect(report.signers[badIndex]?.valid).toBe(false);
            expect(codes(report)).toEqual(['PKI_REASON_CMS_DIGEST_MISMATCH']);
            expect(paths(report)).toEqual([`signerInfos[${String(badIndex)}].signedAttrs.messageDigest`]);
        }, 30_000);
    });

    describe('the input', () => {
        it('should throw PKI_API_MISUSE for both the content and its digest', async () => {
            const w = await world();
            const call = verify(w, await sign(w, { detached: true }), { content: CONTENT, contentDigest: new Uint8Array(32) });
            await expect(call).rejects.toBeInstanceOf(PkiError);
            await expect(call).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
        });

        it.each([
            ['the content', { content: CONTENT }],
            ['a digest', { contentDigest: new Uint8Array(32) }],
        ])('should throw PKI_API_MISUSE for %s passed with a message that carries its own', async (_label, extra) => {
            const w = await world();
            await expect(verify(w, await sign(w), extra)).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
        });

        it('should report bytes that are not a SignedData as INPUT_MALFORMED, with the error that would have been thrown', async () => {
            const w = await world();
            const report = await verify(w, Uint8Array.of(0x30, 0x05, 0x06));
            expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
            expect(report.reasons[0]?.path).toBe('signedData');
            expect(report.reasons[0]?.errorCode).toMatch(/^PKI_ASN1_/);
            expect(report.signedData).toBeUndefined();
            expect(report.signers).toEqual([]);
            expect(report.verified).toBe(0);
        });

        it('should report a message past the caller\'s limits as INPUT_MALFORMED carrying PKI_LIMIT_EXCEEDED', async () => {
            const w = await world();
            const report = await verify(w, await sign(w), { limits: { maxInputBytes: 16 } });
            expect(report.reasons[0]?.errorCode).toBe('PKI_LIMIT_EXCEEDED');
        });

        it('should report a message with no signer as CMS_NO_SIGNERS — a certificate bundle is not a signature', async () => {
            const w = await world();
            const report = await verify(w, withSigners(await sign(w), []));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_NO_SIGNERS']);
            expect(report.reasons[0]?.path).toBe('signerInfos');
            expect(report.valid).toBe(false);
            expect(report.signedData).toBeDefined();
            expect(report.signers).toEqual([]);
        });
    });

    describe('the content', () => {
        it('should report detached content that was not supplied as CMS_CONTENT_MISSING, and still judge the rest', async () => {
            const w = await world();
            const report = await verify(w, await sign(w, { detached: true }));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_CONTENT_MISSING']);
            expect(paths(report)).toEqual(['signerInfos[0]']);
            // The signed attributes were still verified, and the chain judged.
            expect(report.signers[0]?.intact).toBe(false);
            expect(report.signers[0]?.certificate?.der).toEqual(w.signer.certificate.der);
            expect(report.signers[0]?.chain?.valid).toBe(true);
        });

        it('should report altered content as CMS_DIGEST_MISMATCH', async () => {
            const w = await world();
            const report = await verify(w, await sign(w, { detached: true }), { content: new TextEncoder().encode('tampered') });
            expect(codes(report)).toEqual(['PKI_REASON_CMS_DIGEST_MISMATCH']);
            expect(paths(report)).toEqual(['signerInfos[0].signedAttrs.messageDigest']);
            expect(report.signers[0]?.intact).toBe(false);
        });

        it('should report a digest of other content as CMS_DIGEST_MISMATCH', async () => {
            const w = await world();
            const report = await verify(w, await sign(w, { detached: true }), { contentDigest: new Uint8Array(32) });
            expect(codes(report)).toEqual(['PKI_REASON_CMS_DIGEST_MISMATCH']);
        });
    });

    describe('the signature and the certificate that made it', () => {
        it('should report an altered signature as SIGNATURE_INVALID, with no certificate and no chain', async () => {
            const w = await world({ family: 'Ed25519' });
            const p7s = await sign(w);
            const report = await verify(w, flipLastOctetOf(p7s, parseSignedData(p7s).signerInfos[0]?.signature as Uint8Array));
            expect(codes(report)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
            expect(paths(report)).toEqual(['signerInfos[0].signature']);
            expect(report.signers[0]?.certificate).toBeUndefined();
            expect(report.signers[0]?.chain).toBeUndefined();
            expect(report.signers[0]?.intact).toBe(false);
        });

        it('should report a signer named by issuerAndSerialNumber whose certificate is nowhere as CMS_SIGNER_NOT_FOUND', async () => {
            const w = await world();
            const report = await verify(w, withCertificates(await sign(w), []));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_SIGNER_NOT_FOUND']);
            expect(paths(report)).toEqual(['signerInfos[0].sid']);
            expect(report.signers[0]?.chain).toBeUndefined();
            expect(report.verified).toBe(0);
        });

        it('should report a signer named by subjectKeyIdentifier whose certificate is nowhere as CMS_SIGNER_NOT_FOUND', async () => {
            const w = await world({ ski: SKI });
            const report = await verify(w, withCertificates(await sign(w, { sid: 'subjectKeyIdentifier' }), [w.root.certificate.der]));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_SIGNER_NOT_FOUND']);
        });

        it('should count the certificates of the message it could not read when the signer is not found', async () => {
            const w = await world();
            const junk = sequence(Uint8Array.of(0x02, 0x01, 0x01));
            const report = await verify(w, withCertificates(await sign(w), [junk]));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_SIGNER_NOT_FOUND']);
            expect(report.reasons[0]?.message).toContain('1 certificate(s) in the message could not be read');
        });

        describe('two certificates for one key (RFC 5035 §2)', () => {
            async function twins(): Promise<{ w: World; twin: Certificate }> {
                const w = await world();
                // Same issuer, same serial, same key: the sid cannot tell them apart.
                const twin = await issue(w.root, { pair: w.signer.pair, subject: 'Same Key, Other Name' });
                return { w, twin: twin.certificate };
            }

            it('should choose the certificate the signer committed to, whichever comes first', async () => {
                const { w, twin } = await twins();
                const p7s = await sign(w);
                for (const bag of [[twin.der, w.signer.certificate.der], [w.signer.certificate.der, twin.der]]) {
                    const report = await verify(w, withCertificates(p7s, bag));
                    expect(codes(report)).toEqual([]);
                    expect(report.signers[0]?.certificate?.der).toEqual(w.signer.certificate.der);
                    // Both certificates hold the key, so both were tried.
                    expect(report.verified).toBe(3);
                }
            });

            it('should report CMS_SIGNING_CERTIFICATE_MISMATCH when only the other certificate is there', async () => {
                const { w, twin } = await twins();
                const report = await verify(w, withCertificates(await sign(w), [twin.der]));
                expect(codes(report)).toEqual(['PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH']);
                expect(report.signers[0]?.certificate).toBeUndefined();
                expect(report.signers[0]?.chain).toBeUndefined();
            });
        });

        it('should require a signing-certificate attribute with requireSigningCertificate', async () => {
            const w = await world();
            const p7s = await sign(w, { signingCertificateV2: false });
            expect(codes(await verify(w, p7s))).toEqual([]);
            const report = await verify(w, p7s, { requireSigningCertificate: true });
            expect(codes(report)).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
            expect(paths(report)).toEqual(['signerInfos[0].signedAttrs.signingCertificate']);
            // Everything else held: the signer is intact in all but that.
            expect(report.signers[0]?.certificate).toBeDefined();
            expect(codes(await verify(w, await sign(w), { requireSigningCertificate: true }))).toEqual([]);
        });

        it('should require CMSAlgorithmProtection with requireAlgorithmProtection (RFC 6211)', async () => {
            const w = await world();
            const p7s = await sign(w, { algorithmProtection: false });
            expect(codes(await verify(w, p7s))).toEqual([]);
            expect(codes(await verify(w, p7s, { requireAlgorithmProtection: true }))).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
            expect(codes(await verify(w, await sign(w), { requireAlgorithmProtection: true }))).toEqual([]);
        });
    });

    describe('messages written field by field', () => {
        /** A message the builder helper assembles around one hand-made SignerInfo, carrying `certificate`. */
        const message = (certificate: Certificate, info: Uint8Array, digest: string, attached: boolean): Uint8Array =>
            contentInfo(signedDataOf({ digestAlgorithms: [alg(digest)], eContent: attached ? octets(HELLO) : null, certificates: [certificate.der], signers: [info] }));

        it('should report an algorithm pair that contradicts itself as CMS_ALGORITHM_MISMATCH before any signature is checked', async () => {
            const w = await world();
            // ecdsa-with-SHA256 beside a SHA-384 digestAlgorithm.
            const info = signerInfo({ sid: sidOf(w.signer.certificate), digestAlgorithm: alg(OIDS.sha384), signatureAlgorithm: alg('1.2.840.10045.4.3.2', null) });
            const report = await verify(w, message(w.signer.certificate, info, OIDS.sha384, true));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_ALGORITHM_MISMATCH']);
            expect(paths(report)).toEqual(['signerInfos[0].signatureAlgorithm']);
            expect(report.verified).toBe(0);
        });

        it('should report a content digest pkinative does not compute as SIGNATURE_NOT_CHECKED, never as a mismatch', async () => {
            const w = await world();
            // SHA-224: named by no refusal, computed by no code here.
            const info = signerInfo({ sid: sidOf(w.signer.certificate), digestAlgorithm: alg(OID.sha224), signatureAlgorithm: alg('1.2.840.10045.4.3.1', null) });
            const report = await verify(w, message(w.signer.certificate, info, OID.sha224, true));
            expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', path: 'signerInfos[0].digestAlgorithm', errorCode: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' });
            expect(codes(report)).not.toContain('PKI_REASON_CMS_DIGEST_MISMATCH');
            expect(report.valid).toBe(false);
        });

        describe('a signer without signed attributes, whose signature is over the content itself', () => {
            async function unattributed(attached: boolean): Promise<{ w: World; p7s: Uint8Array }> {
                const w = await world({ family: 'Ed25519' });
                const signature = await rawSign({ name: 'Ed25519' }, w.signer.pair.privateKey, HELLO);
                const info = signerInfo({
                    sid: sidOf(w.signer.certificate), digestAlgorithm: alg(OIDS.sha512), signedAttrs: null,
                    signatureAlgorithm: alg('1.3.101.112', null), signature: octets(signature),
                });
                return { w, p7s: message(w.signer.certificate, info, OIDS.sha512, attached) };
            }

            it('should verify it over the attached content', async () => {
                const { w, p7s } = await unattributed(true);
                expect(codes(await verify(w, p7s))).toEqual([]);
            });

            it('should verify it over detached content passed alongside', async () => {
                const { w, p7s } = await unattributed(false);
                expect(codes(await verify(w, p7s, { content: HELLO }))).toEqual([]);
                const altered = await verify(w, p7s, { content: CONTENT });
                expect(codes(altered)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
            });

            it('should report it as SIGNATURE_NOT_CHECKED from a digest alone — Web Crypto hashes what it is handed', async () => {
                const { w, p7s } = await unattributed(false);
                const report = await verify(w, p7s, { contentDigest: await sha('SHA-512', HELLO) });
                expect(report.reasons).toHaveLength(1);
                expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', path: 'signerInfos[0]', errorCode: 'PKI_API_MISUSE' });
                expect(report.signers[0]?.certificate).toBeUndefined();
            });

            it('should report it as naming no signing certificate under requireSigningCertificate', async () => {
                const { w, p7s } = await unattributed(true);
                const report = await verify(w, p7s, { requireSigningCertificate: true });
                expect(codes(report)).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
                expect(paths(report)).toEqual(['signerInfos[0].signedAttrs.signingCertificate']);
            });

            it('should report it as CMS_CONTENT_MISSING without content, having nothing else to check', async () => {
                const { w, p7s } = await unattributed(false);
                const report = await verify(w, p7s);
                expect(codes(report)).toEqual(['PKI_REASON_CMS_CONTENT_MISSING']);
                expect(report.signers[0]?.certificate).toBeUndefined();
                expect(report.verified).toBe(0);
            });
        });

        describe('a SHA-1 signer', () => {
            async function sha1Signed(): Promise<{ w: World; p7s: Uint8Array }> {
                const root = await makeRoot();
                const pair = await keyPair('RSA', { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-1' });
                const signer = await issue(root, { family: 'RSA', pair });
                const attributes = sorted([
                    attribute(OIDS.contentType, oid(OIDS.data)),
                    attribute(OIDS.messageDigest, octets(await sha('SHA-1', HELLO))),
                ]);
                const signature = await rawSign({ name: 'RSASSA-PKCS1-v1_5' }, pair.privateKey, set(...attributes));
                const info = signerInfo({
                    sid: sidOf(signer.certificate), digestAlgorithm: alg(OIDS.sha1), signedAttrs: attributes,
                    signatureAlgorithm: alg('1.2.840.113549.1.1.5'), signature: octets(signature),
                });
                return { w: { root, signer }, p7s: message(signer.certificate, info, OIDS.sha1, true) };
            }

            it('should report it as SIGNATURE_NOT_CHECKED, the refusal kept apart from a false', async () => {
                const { w, p7s } = await sha1Signed();
                const report = await verify(w, p7s);
                expect(report.reasons).toHaveLength(1);
                expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', path: 'signerInfos[0].signature', errorCode: 'PKI_CRYPTO_ALGORITHM_REFUSED' });
            });

            it('should accept it with allowSha1', async () => {
                const { w, p7s } = await sha1Signed();
                expect(codes(await verify(w, p7s, { allowSha1: true }))).toEqual([]);
            });
        });

        it('should accept a signer named by a subjectKeyIdentifier written by hand', async () => {
            const w = await world({ family: 'Ed25519', ski: SKI });
            const signature = await rawSign({ name: 'Ed25519' }, w.signer.pair.privateKey, HELLO);
            const info = signerInfo({
                version: Uint8Array.of(0x02, 0x01, 0x03), sid: subjectKeyIdentifier(SKI), digestAlgorithm: alg(OIDS.sha512),
                signedAttrs: null, signatureAlgorithm: alg('1.3.101.112', null), signature: octets(signature),
            });
            const p7s = contentInfo(signedDataOf({ version: Uint8Array.of(0x02, 0x01, 0x03), digestAlgorithms: [alg(OIDS.sha512)], certificates: [w.signer.certificate.der], signers: [info] }));
            expect(codes(await verify(w, p7s))).toEqual([]);
        });
    });

    describe('trust', () => {
        it('should call a signer that chains to no trusted anchor invalid, and still intact', async () => {
            const w = await world();
            const stranger = await makeRoot('Somebody Else');
            const report = await verify(w, await sign(w, { certificates: [w.root.certificate.der] }), { trustAnchors: [stranger.certificate] });
            expect(report.valid).toBe(false);
            expect(report.signers[0]?.intact).toBe(true);
            expect(codes(report)).toContain('PKI_REASON_NO_TRUST_ANCHOR');
            expect(paths(report).every((path) => path.startsWith('signerInfos[0].chain.'))).toBe(true);
        });

        it('should require the purposes asked for of each signer\'s chain', async () => {
            const w = await world({ extensions: [eku([OID.codeSigning])] });
            const report = await verify(w, await sign(w), { purposes: [KEY_PURPOSES.emailProtection] });
            expect(codes(report)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
            expect(paths(report)[0]?.startsWith('signerInfos[0].chain.')).toBe(true);
            const mail = await world({ extensions: [eku([OID.emailProtection])] });
            expect(codes(await verify(mail, await sign(mail), { purposes: [KEY_PURPOSES.emailProtection] }))).toEqual([]);
        });

        it('should report a signer revoked by a CRL the caller passes, or one the message carries', async () => {
            const w = await world();
            const crl = await makeCrl(w.root, [w.signer.certificate]);
            expect(codes(await verify(w, await sign(w), { crls: [crl] }))).toEqual(['PKI_REASON_REVOKED']);
            expect(codes(await verify(w, await sign(w, { crls: [crl] })))).toEqual(['PKI_REASON_REVOKED']);
        });

        it('should report unknown revocation with requireRevocation, and accept a CRL that covers the signer', async () => {
            const w = await world();
            const p7s = await sign(w);
            expect(codes(await verify(w, p7s, { requireRevocation: true, ocsp: [] }))).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
            expect(codes(await verify(w, p7s, { requireRevocation: true, crls: [await makeCrl(w.root)] }))).toEqual([]);
        });

        it('should judge the chain at `at`', async () => {
            const w = await world();
            const report = await verify(w, await sign(w), { at: AT + 2 * DAY });
            expect(codes(report)).toEqual(['PKI_REASON_EXPIRED']);
            expect(report.signers[0]?.intact).toBe(true);
        });

        it('should judge the chain now when `at` is not given', async () => {
            const w = await world();
            // Every certificate here expired in early 2026.
            const report = await verifySignedData({ signedData: await sign(w), trustAnchors: [w.root.certificate] });
            expect(codes(report)).toContain('PKI_REASON_EXPIRED');
        });
    });

    describe('timestamps over a signature (CAdES-T, PAdES B-T)', () => {
        interface Stamped { readonly w: World; readonly tsa: Holder; readonly p7s: Uint8Array; readonly imprint: Uint8Array }

        /** A signed message, and a TSA ready to stamp its signature value. */
        async function stampable(): Promise<Stamped> {
            const w = await world();
            const tsa = await issueTsa(w.root);
            const p7s = await sign(w);
            const imprint = await sha('SHA-256', parseSignedData(p7s).signerInfos[0]?.signature as Uint8Array);
            return { w, tsa, p7s, imprint };
        }

        const stamp = async (s: Stamped, genTime: number, imprint = s.imprint): Promise<Uint8Array> =>
            makeToken(s.tsa, tstInfo({ imprint, genTime }));

        it('should verify each timestamp and report it, the signer staying valid', async () => {
            const s = await stampable();
            const report = await verify(s.w, addTimeStampToken(s.p7s, 0, await stamp(s, AT)));
            expect(codes(report)).toEqual([]);
            const [verdict] = report.signers[0]?.timeStamps ?? [];
            expect(verdict?.valid).toBe(true);
            expect(verdict?.genTime?.epochMilliseconds).toBe(AT);
            // Signer, its link; the TSA's signature, its link.
            expect(report.verified).toBe(4);
        });

        it('should accept a signer whose certificate has since expired with atTimeStamp, and report EXPIRED without', async () => {
            const s = await stampable();
            const stamped = addTimeStampToken(s.p7s, 0, await stamp(s, AT));
            const later = AT + 5 * DAY;
            expect(codes(await verify(s.w, stamped, { at: later, atTimeStamp: true }))).toEqual([]);
            const plain = await verify(s.w, stamped, { at: later });
            expect(codes(plain)).toEqual(['PKI_REASON_EXPIRED']);
            expect(paths(plain)[0]?.startsWith('signerInfos[0].chain.')).toBe(true);
            // With atTimeStamp and no timestamp at all, it is judged at `at`.
            expect(codes(await verify(s.w, s.p7s, { at: later, atTimeStamp: true }))).toEqual(['PKI_REASON_EXPIRED']);
        });

        it('should judge at the earliest proof when several timestamps are valid', async () => {
            const s = await stampable();
            // The second stamp is after the signer's certificate expired; the first proves it was good.
            const stamped = addTimeStampToken(addTimeStampToken(s.p7s, 0, await stamp(s, AT + 2 * DAY)), 0, await stamp(s, AT));
            const report = await verify(s.w, stamped, { at: AT + 5 * DAY, atTimeStamp: true });
            expect(codes(report)).toEqual([]);
            expect(report.signers[0]?.timeStamps).toHaveLength(2);
        });

        it('should make the signer invalid when a timestamp stamps something else, and not use its time', async () => {
            const s = await stampable();
            const stamped = addTimeStampToken(s.p7s, 0, await stamp(s, AT, await sha('SHA-256', CONTENT)));
            const report = await verify(s.w, stamped, { at: AT + 5 * DAY, atTimeStamp: true });
            expect(codes(report)).toEqual(['PKI_REASON_TSP_IMPRINT_MISMATCH', 'PKI_REASON_EXPIRED']);
            expect(paths(report)[0]).toBe('signerInfos[0].unsignedAttrs.timeStampToken[0].token.tstInfo.messageImprint');
            expect(report.signers[0]?.intact).toBe(true);
        });

        it('should judge the timestamps now when `at` is not given, as it judges the signer', async () => {
            const s = await stampable();
            const report = await verifySignedData({ signedData: addTimeStampToken(s.p7s, 0, await stamp(s, AT)), trustAnchors: [s.w.root.certificate] });
            // Every certificate here expired in early 2026: the TSA's too.
            expect(report.signers[0]?.timeStamps[0]?.valid).toBe(false);
            expect(codes(report.signers[0]?.timeStamps[0] ?? { reasons: [] })).toContain('PKI_REASON_EXPIRED');
        });

        it('should hand the caller\'s CRLs, OCSP responses, SHA-1 policy and limits on to each timestamp', async () => {
            const s = await stampable();
            const stamped = addTimeStampToken(s.p7s, 0, await stamp(s, AT));
            const options = { ocsp: [], allowSha1: false, limits: { maxInputBytes: 1 << 20 } };
            expect(codes(await verify(s.w, stamped, options))).toEqual([]);
            const report = await verify(s.w, stamped, { ...options, crls: [await makeCrl(s.w.root, [s.tsa.certificate])] });
            expect(codes(report)).toEqual(['PKI_REASON_REVOKED']);
            expect(paths(report)[0]?.startsWith('signerInfos[0].unsignedAttrs.timeStampToken[0].token.tsaChain.')).toBe(true);
            expect(report.signers[0]?.timeStamps[0]?.valid).toBe(false);
        });
    });
});
