import { afterEach, describe, expect, it } from 'vitest';
import { verifyCertificateChain, verifyCertificationRequest, verifySignedData, verifyTimeStampToken } from '../../src/index.js';
import type { PkiReason } from '../../src/types/pki-reasons.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { parseCertificationRequest } from '../../src/x509/x509-csr.js';
import { ML_DSA_AT, ML_DSA_CONTENT, ML_DSA_SETS, acceptMlDsa, hostImportsMlDsa, mlDsaBytes, mlDsaCertificate, refuseMlDsa } from './_ml-dsa.js';

/**
 * ML-DSA verdicts through the one-call reports (ADR 0026): a certificate
 * chain, its CRL and its OCSP response, a certification request, two CMS
 * messages and a timestamp token — all signed by OpenSSL 3.5, none by this
 * repository (tests/fixtures/PROVENANCE.md).
 *
 * Each is asked on the real host (positive under `runIf(HOST_HAS_ML_DSA)`,
 * refusal under the complementary condition) and on a host stubbed each way,
 * so the suite says the same thing wherever it runs. See `_ml-dsa.ts`.
 */

const HOST_HAS_ML_DSA = await hostImportsMlDsa();

const root = mlDsaCertificate('root-ml-dsa-65');
const leaf = mlDsaCertificate('leaf-ml-dsa-44');
const at = ML_DSA_AT;

const codes = (reasons: readonly PkiReason[]): string[] => reasons.map((reason) => reason.code);
/** The one reason a host without ML-DSA leaves: not checked, with the primitive's code — never a verdict on the signature. */
const notChecked = (path: string): unknown =>
    expect.objectContaining({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', errorCode: 'PKI_CRYPTO_KEY_UNSUPPORTED', path });

/** A copy with its last octet flipped: the end of the signature of a certificate, a request, or the last SignerInfo. */
const flipLast = (bytes: Uint8Array): Uint8Array => {
    const copy = Uint8Array.from(bytes);
    copy[copy.length - 1] = (copy[copy.length - 1] as number) ^ 0xff;
    return copy;
};

let restore: (() => void) | undefined;
afterEach(() => {
    restore?.();
    restore = undefined;
});

describe('an ML-DSA certificate chain (RFC 9881 §3)', () => {
    const chain = (leafCertificate = leaf): ReturnType<typeof verifyCertificateChain> => verifyCertificateChain({ leaf: leafCertificate, trustAnchors: [root], at });

    it.runIf(HOST_HAS_ML_DSA)('should be valid on this host, which verifies ML-DSA', async () => {
        const report = await chain();
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
    });

    it.runIf(HOST_HAS_ML_DSA)('should be SIGNATURE_INVALID on this host once the signature is altered', async () => {
        const report = await chain(parseCertificate(flipLast(mlDsaBytes('leaf-ml-dsa-44')), { onDiagnostic: () => undefined }));
        expect(codes(report.reasons)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
    });

    it.runIf(!HOST_HAS_ML_DSA)('should be reported not checked on this host, which has no ML-DSA — never invalid', async () => {
        const report = await chain();
        expect(report.reasons).toEqual([notChecked('path[0]')]);
        expect(report.valid).toBe(false);
    });

    it('should be SIGNATURE_NOT_CHECKED with PKI_CRYPTO_KEY_UNSUPPORTED on a host that refuses the key, as an Ed448 chain is on Bun', async () => {
        restore = refuseMlDsa();
        const report = await chain();
        expect(report.reasons).toEqual([notChecked('path[0]')]);
        expect(report.valid).toBe(false);
    });

    it('should hand an accepting host the issuer key, the signature and the tbsCertificate under the name ML-DSA-65, and be valid', async () => {
        const host = acceptMlDsa();
        restore = host.restore;
        const report = await chain();
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        expect(host.verifications).toHaveLength(1);
        const [asked] = host.verifications;
        // Pure ML-DSA with the empty context string: the name is all the host is told.
        expect(asked).toMatchObject({ importName: 'ML-DSA-65', format: 'spki', extractable: false, usages: ['verify'], verifyParams: { name: 'ML-DSA-65' } });
        expect(Object.keys(asked?.verifyParams as object)).toEqual(['name']);
        expect(asked?.spki).toEqual(root.subjectPublicKeyInfo.der);
        expect(asked?.signature).toEqual(leaf.signatureValue.bytes);
        expect(asked?.signature).toHaveLength(3309);
        expect(asked?.data).toEqual(leaf.tbsDer);
    });

    it('should be SIGNATURE_INVALID when the host answers no', async () => {
        const host = acceptMlDsa(false);
        restore = host.restore;
        expect(codes((await chain()).reasons)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
    });

    it.each(ML_DSA_SETS)('should build no path from %s to an anchor of another parameter set without asking the host', async (name, kind) => {
        // The RFC 9881 examples share one name ("O=IETF, CN=LAMPS WG"), so each
        // is a candidate issuer of the others by name — and by name only.
        const host = acceptMlDsa();
        restore = host.restore;
        const others = ML_DSA_SETS.filter(([, otherKind]) => otherKind !== kind).map(([other]) => mlDsaCertificate(other));
        const report = await verifyCertificateChain({ leaf: mlDsaCertificate(name), trustAnchors: others, at: Date.UTC(2026, 0, 1) });
        expect(report.valid).toBe(false);
        expect(host.verifications).toEqual([]);
    });
});

describe('revocation evidence signed with ML-DSA-65', () => {
    const withCrl = (): ReturnType<typeof verifyCertificateChain> =>
        verifyCertificateChain({ leaf, trustAnchors: [root], at, crls: [mlDsaBytes('crl-ml-dsa-65')], requireRevocation: true });
    const withOcsp = (): ReturnType<typeof verifyCertificateChain> =>
        verifyCertificateChain({ leaf, trustAnchors: [root], at, ocspResponses: [mlDsaBytes('ocsp-ml-dsa-65')], requireRevocation: true });

    it.runIf(HOST_HAS_ML_DSA)('should accept the CRL and the OCSP response on this host', async () => {
        expect((await withCrl()).reasons).toEqual([]);
        expect((await withOcsp()).reasons).toEqual([]);
    });

    it.each([['the CRL', withCrl], ['the OCSP response', withOcsp]] as const)('should accept %s on an accepting host: thisUpdate, scope and CertID all hold', async (_what, run) => {
        const host = acceptMlDsa();
        restore = host.restore;
        const report = await run();
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        // The certificate's signature, then the evidence's: both by the root's ML-DSA-65 key.
        expect(host.verifications.map((v) => v.importName)).toEqual(['ML-DSA-65', 'ML-DSA-65']);
        expect(host.verifications.every((v) => v.signature.length === 3309)).toBe(true);
    });

    it.each([['the CRL', withCrl, 'crls[0]'], ['the OCSP response', withOcsp, 'ocspResponses[0]']] as const)(
        'should leave %s unverified on a host that refuses the key: the status is unknown, never good and never revoked',
        async (_what, run, path) => {
            restore = refuseMlDsa();
            const report = await run();
            expect(report.valid).toBe(false);
            expect(report.reasons[0]).toEqual(notChecked('path[0]'));
            expect(new Set(codes(report.reasons))).toEqual(new Set(['PKI_REASON_SIGNATURE_NOT_CHECKED', 'PKI_REASON_REVOCATION_UNKNOWN']));
            expect(report.reasons.slice(1).every((reason) => reason.path === path)).toBe(true);
        },
    );
});

describe('an ML-DSA certification request', () => {
    const request = mlDsaBytes('csr-ml-dsa-44');

    it.runIf(HOST_HAS_ML_DSA)('should be valid on this host, and SIGNATURE_INVALID once altered', async () => {
        expect((await verifyCertificationRequest(request)).reasons).toEqual([]);
        expect(codes((await verifyCertificationRequest(flipLast(request))).reasons)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
    });

    it.runIf(!HOST_HAS_ML_DSA)('should be reported not checked on this host', async () => {
        expect((await verifyCertificationRequest(request)).reasons).toEqual([notChecked('certificationRequest.signature')]);
    });

    it('should be SIGNATURE_NOT_CHECKED with PKI_CRYPTO_KEY_UNSUPPORTED on a host that refuses the key', async () => {
        restore = refuseMlDsa();
        const report = await verifyCertificationRequest(request);
        expect(report.reasons).toEqual([notChecked('certificationRequest.signature')]);
        expect(report.valid).toBe(false);
    });

    it('should hand an accepting host the request\'s own key and its certificationRequestInfo, and be valid', async () => {
        const host = acceptMlDsa();
        restore = host.restore;
        const report = await verifyCertificationRequest(request);
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        const parsed = parseCertificationRequest(request, { onDiagnostic: () => undefined });
        expect(host.verifications).toHaveLength(1);
        expect(host.verifications[0]).toMatchObject({ importName: 'ML-DSA-44', verifyParams: { name: 'ML-DSA-44' } });
        expect(host.verifications[0]?.spki).toEqual(parsed.subjectPublicKeyInfo.der);
        expect(host.verifications[0]?.signature).toHaveLength(2420);
    });
});

describe.each([
    ['SHA-512, the digest RFC 9882 §3.3 makes mandatory to support', 'cms-ml-dsa-44-sha512'],
    ['SHAKE256 with a 512-bit output, the digest it recommends', 'cms-ml-dsa-44-shake256'],
])('an ML-DSA-44 CMS signer over %s', (_digest, name) => {
    const message = mlDsaBytes(name);
    const verify = (signedData = message): ReturnType<typeof verifySignedData> => verifySignedData({ signedData, certificates: [leaf], trustAnchors: [root], at });

    it.runIf(HOST_HAS_ML_DSA)('should be valid on this host, with the content attached', async () => {
        const report = await verify();
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        expect(report.signedData?.content).toEqual(ML_DSA_CONTENT);
    });

    it.runIf(HOST_HAS_ML_DSA)('should be SIGNATURE_INVALID on this host once the signature is altered', async () => {
        expect(codes((await verify(flipLast(message))).reasons)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
    });

    it.runIf(!HOST_HAS_ML_DSA)('should be reported not checked on this host', async () => {
        expect((await verify()).reasons).toEqual([notChecked('signerInfos[0].signature')]);
    });

    it('should be SIGNATURE_NOT_CHECKED with PKI_CRYPTO_KEY_UNSUPPORTED on a host that refuses the key, as an Ed448 signer is', async () => {
        restore = refuseMlDsa();
        const report = await verify();
        expect(report.reasons).toEqual([notChecked('signerInfos[0].signature')]);
        expect(report.valid).toBe(false);
        expect(report.signers[0]?.certificate).toBeUndefined();
    });

    it('should be valid on an accepting host: the digest pkinative computes equals messageDigest, and the signer is its certificate', async () => {
        const host = acceptMlDsa();
        restore = host.restore;
        const report = await verify();
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        expect(report.signedData?.content).toEqual(ML_DSA_CONTENT);
        // The signer under the leaf's ML-DSA-44 key, then the leaf under the root's ML-DSA-65 key.
        expect(host.verifications.map((v) => [v.importName, v.signature.length])).toEqual([['ML-DSA-44', 2420], ['ML-DSA-65', 3309]]);
        expect(host.verifications[0]?.spki).toEqual(leaf.subjectPublicKeyInfo.der);
        // What is signed is the SET OF signed attributes, tag 0x31 (RFC 5652 §5.4, RFC 9882 §3.2).
        expect(host.verifications[0]?.data[0]).toBe(0x31);
    });
});

describe('the RFC 9882 §3.3 digest rule, in a report', () => {
    /** id-sha512 → id-sha224, same length: outside every row of Table 1, and what the signature covers is untouched. */
    const underSha224 = (message: Uint8Array): Uint8Array => {
        const sha512 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        const copy = Uint8Array.from(message);
        let found = 0;
        for (let i = 0; i + sha512.length <= copy.length; i++) {
            if (sha512.every((octet, j) => copy[i + j] === octet)) {
                copy[i + sha512.length - 1] = 0x04;
                found += 1;
            }
        }
        // SignedData.digestAlgorithms and SignerInfo.digestAlgorithm; the signed attributes hold no digest OID.
        expect(found).toBe(2);
        return copy;
    };

    it('should report CMS_ALGORITHM_MISMATCH for an ML-DSA signer whose digest is outside its row of Table 1, before any host is asked', async () => {
        const host = acceptMlDsa();
        restore = host.restore;
        const report = await verifySignedData({ signedData: underSha224(mlDsaBytes('cms-ml-dsa-44-sha512')), certificates: [leaf], trustAnchors: [root], at });
        expect(report.reasons).toHaveLength(1);
        expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_CMS_ALGORITHM_MISMATCH', path: 'signerInfos[0].signatureAlgorithm' });
        expect(host.verifications).toEqual([]);
    });
});

describe('an RFC 3161 timestamp token signed with ML-DSA-44', () => {
    const token = mlDsaBytes('tst-ml-dsa-44');
    const verify = (bytes = token): ReturnType<typeof verifyTimeStampToken> => verifyTimeStampToken({ token: bytes, data: ML_DSA_CONTENT, trustAnchors: [root], at });

    it.runIf(HOST_HAS_ML_DSA)('should be valid on this host, and SIGNATURE_INVALID once altered', async () => {
        const report = await verify();
        expect(report.reasons).toEqual([]);
        expect(report.genTime?.text).toBe('20261117220000Z');
        expect(codes((await verify(flipLast(token))).reasons)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
    });

    it.runIf(!HOST_HAS_ML_DSA)('should be reported not checked on this host', async () => {
        expect((await verify()).reasons).toEqual([notChecked('token.signerInfos[0].signature')]);
    });

    it('should be SIGNATURE_NOT_CHECKED with PKI_CRYPTO_KEY_UNSUPPORTED on a host that refuses the key', async () => {
        restore = refuseMlDsa();
        const report = await verify();
        expect(report.reasons).toEqual([notChecked('token.signerInfos[0].signature')]);
        expect(report.valid).toBe(false);
    });

    it('should be valid on an accepting host: the imprint, the signing certificate and the timeStamping purpose all hold', async () => {
        const host = acceptMlDsa();
        restore = host.restore;
        const report = await verify();
        expect(report.reasons).toEqual([]);
        expect(report.valid).toBe(true);
        expect(report.genTime?.text).toBe('20261117220000Z');
        expect(host.verifications.map((v) => v.importName)).toEqual(['ML-DSA-44', 'ML-DSA-65']);
    });
});
