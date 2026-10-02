import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
    cmsAlgorithmMismatchReason,
    cmsAttributeInvalidReason,
    cmsContentMissingReason,
    cmsDigestMismatchReason,
    cmsNoSignersReason,
    cmsSignerNotFoundReason,
    cmsSigningCertificateMismatchReason,
    tspImprintMismatchReason,
    tspNotGrantedReason,
    tspRequestMismatchReason,
    pkcs12DecryptionFailedReason,
    pkcs12EncryptionUnsupportedReason,
    pkcs12IntegrityUnverifiedReason,
    pkcs12KeyUnmatchedReason,
    pkcs12KeyUnsupportedReason,
    pkcs12MacMismatchReason,
    pkcs12RsaSchemeUnspecifiedReason,
    tspTokenInvalidReason,
    expiredReason,
    inputMalformedReason,
    issuerNotFoundReason,
    limitExceededReason,
    nameExcludedReason,
    nameMismatchReason,
    nameNotPermittedReason,
    noTrustAnchorReason,
    notACaReason,
    noValidPolicyReason,
    policyMappingInvalidReason,
    purposeNotPermittedReason,
    notYetValidReason,
    pathLoopsReason,
    pathTooLongReason,
    revocationMismatchReason,
    revocationOutOfScopeReason,
    revocationPartialReason,
    revocationStaleReason,
    revocationUnknownReason,
    revocationWrongIssuerReason,
    revokedReason,
    signatureInvalidReason,
    signatureNotCheckedReason,
    unknownCriticalExtensionReason,
} from '../../src/core/pki-reasons.js';
import type { PkiReason, PkiReasonCode } from '../../src/types/pki-reasons.js';

/**
 * The third vocabulary's contract, locked here rather than only described.
 *
 * Three properties matter more than any individual message, because each is a
 * way the distinction between the three registries could quietly collapse:
 * a reason must never carry the thrown-error prefix, a reason must never be
 * the whole answer when the answer is "I could not check", and
 * `PKI_REASON_INPUT_MALFORMED` must carry the error code it wraps — that
 * field is what keeps 47 encoding codes out of a second vocabulary.
 */

const AT = Date.UTC(2026, 5, 1);

const ALL: ReadonlyArray<{ readonly code: PkiReasonCode; readonly reason: PkiReason }> = [
    { code: 'PKI_REASON_INPUT_MALFORMED', reason: inputMalformedReason('PKI_ASN1_TRUNCATED', 'pkinative: the value runs past the input', 'path[1]') },
    { code: 'PKI_REASON_NOT_YET_VALID', reason: notYetValidReason('path[0].validity', Date.UTC(2027, 0, 1), AT) },
    { code: 'PKI_REASON_EXPIRED', reason: expiredReason('path[0].validity', Date.UTC(2025, 0, 1), AT) },
    { code: 'PKI_REASON_UNKNOWN_CRITICAL_EXTENSION', reason: unknownCriticalExtensionReason('path[0].extensions', '1.3.6.1.4.1.99999.7') },
    { code: 'PKI_REASON_NAME_NOT_PERMITTED', reason: nameNotPermittedReason('path[0].subjectAltName', 'dNSName', 'evil.test') },
    { code: 'PKI_REASON_NAME_EXCLUDED', reason: nameExcludedReason('path[0].subjectAltName', 'dNSName', 'secret.example.com') },
    { code: 'PKI_REASON_PURPOSE_NOT_PERMITTED', reason: purposeNotPermittedReason('path[1].extKeyUsage', '1.3.6.1.5.5.7.3.1', ['1.3.6.1.5.5.7.3.4']) },
    { code: 'PKI_REASON_NAME_MISMATCH', reason: nameMismatchReason('certificate.subjectAltName', 'the DNS name "bank.example"', 'it names "other.example"') },
    { code: 'PKI_REASON_REVOKED', reason: revokedReason('crl', Date.UTC(2026, 1, 1), 'keyCompromise') },
    { code: 'PKI_REASON_REVOCATION_STALE', reason: revocationStaleReason('crl', Date.UTC(2026, 0, 1), AT) },
    { code: 'PKI_REASON_REVOCATION_WRONG_ISSUER', reason: revocationWrongIssuerReason('crl') },
    { code: 'PKI_REASON_REVOCATION_OUT_OF_SCOPE', reason: revocationOutOfScopeReason('crl', 'it declares onlyContainsCACerts') },
    { code: 'PKI_REASON_REVOCATION_PARTIAL', reason: revocationPartialReason('crl', ['keyCompromise']) },
    { code: 'PKI_REASON_REVOCATION_UNKNOWN', reason: revocationUnknownReason('crl', 'no list was supplied at all') },
    { code: 'PKI_REASON_REVOCATION_MISMATCH', reason: revocationMismatchReason('ocsp', 'it answers about serial 2b') },
    { code: 'PKI_REASON_CMS_NO_SIGNERS', reason: cmsNoSignersReason('signerInfos') },
    { code: 'PKI_REASON_CMS_SIGNER_NOT_FOUND', reason: cmsSignerNotFoundReason('signerInfos[0].sid', 'issuer CN=Example CA, serial 2b') },
    { code: 'PKI_REASON_CMS_CONTENT_MISSING', reason: cmsContentMissingReason('encapContentInfo') },
    { code: 'PKI_REASON_CMS_DIGEST_MISMATCH', reason: cmsDigestMismatchReason('signerInfos[0].messageDigest') },
    { code: 'PKI_REASON_CMS_ATTRIBUTE_INVALID', reason: cmsAttributeInvalidReason('signerInfos[0].signedAttrs', 'the contentType attribute is missing') },
    { code: 'PKI_REASON_CMS_ALGORITHM_MISMATCH', reason: cmsAlgorithmMismatchReason('signerInfos[0].signatureAlgorithm', 'ecdsa-with-SHA384 over a SHA-256 digestAlgorithm') },
    { code: 'PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH', reason: cmsSigningCertificateMismatchReason('signerInfos[0].signingCertificate', 'the certHash names another certificate') },
    { code: 'PKI_REASON_TSP_NOT_GRANTED', reason: tspNotGrantedReason('status', 'rejection', ['unsupported algorithm'], ['badAlg']) },
    { code: 'PKI_REASON_TSP_TOKEN_INVALID', reason: tspTokenInvalidReason('token', 'the token carries two signers') },
    { code: 'PKI_REASON_TSP_IMPRINT_MISMATCH', reason: tspImprintMismatchReason('tstInfo.messageImprint') },
    { code: 'PKI_REASON_TSP_REQUEST_MISMATCH', reason: tspRequestMismatchReason('tstInfo.nonce', 'the nonce 17 was sent and 18 came back') },
    { code: 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED', reason: pkcs12EncryptionUnsupportedReason('authSafe[0]', 'pbeWithSHAAnd40BitRC2-CBC') },
    { code: 'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED', reason: pkcs12IntegrityUnverifiedReason('macData', 'pkcs12-kdf') },
    { code: 'PKI_REASON_PKCS12_MAC_MISMATCH', reason: pkcs12MacMismatchReason('macData') },
    { code: 'PKI_REASON_PKCS12_DECRYPTION_FAILED', reason: pkcs12DecryptionFailedReason('authSafe[1].bags[0]') },
    { code: 'PKI_REASON_PKCS12_KEY_UNMATCHED', reason: pkcs12KeyUnmatchedReason('authSafe[1].bags[0]') },
    { code: 'PKI_REASON_PKCS12_KEY_UNSUPPORTED', reason: pkcs12KeyUnsupportedReason('authSafe[1].bags[0]', 'a DSA key has no Web Crypto form') },
    { code: 'PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED', reason: pkcs12RsaSchemeUnspecifiedReason('authSafe[1].bags[0]') },
    { code: 'PKI_REASON_NO_VALID_POLICY', reason: noValidPolicyReason('path') },
    { code: 'PKI_REASON_POLICY_MAPPING_INVALID', reason: policyMappingInvalidReason('path[1].policyMappings', '2.5.29.32.0', '1.3.6.1.4.1.1') },
    { code: 'PKI_REASON_ISSUER_NOT_FOUND', reason: issuerNotFoundReason('path[0]', 'CN=Example Root') },
    { code: 'PKI_REASON_SIGNATURE_INVALID', reason: signatureInvalidReason('path[0]') },
    { code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', reason: signatureNotCheckedReason('path[0]', 'PKI_CRYPTO_KEY_UNSUPPORTED', 'pkinative: this runtime refused Ed448') },
    { code: 'PKI_REASON_NO_TRUST_ANCHOR', reason: noTrustAnchorReason('path[2]') },
    { code: 'PKI_REASON_NOT_A_CA', reason: notACaReason('path[1]', 'basicConstraints') },
    { code: 'PKI_REASON_PATH_TOO_LONG', reason: pathTooLongReason('path[3]', 0) },
    { code: 'PKI_REASON_PATH_LOOPS', reason: pathLoopsReason('path[2]') },
    { code: 'PKI_REASON_LIMIT_EXCEEDED', reason: limitExceededReason('path', 'maxPathsExplored', 1000) },
];

const REGISTRY = JSON.parse(readFileSync('docs/data/reasons.json', 'utf8')) as { reasons: Array<{ code: string; standard: string }> };

describe('validation reasons', () => {
    it('should exercise every code in the registry', () => {
        // Without this, a code could be added to the union and the registry
        // and never built — so its message would first be written, wrongly,
        // by whoever needed it in production.
        expect(ALL.map((r) => r.code).sort()).toEqual(REGISTRY.reasons.map((r) => r.code).sort());
    });

    it('should tell a scheme pkinative refuses from one this runtime lacks', () => {
        const policy = pkcs12EncryptionUnsupportedReason('authSafe[0]', 'pbeWithSHAAnd40BitRC2-CBC').message;
        const runtime = pkcs12EncryptionUnsupportedReason('authSafe[0]', 'PBES2 (PBKDF2 with HMAC-SHA-256, AES-192-CBC)', true).message;
        expect(policy).toContain('Appendix B');
        expect(runtime).toContain('another runtime');
        expect(runtime).not.toContain('Appendix B');
    });

    it('should say why a PKCS#12 could not be vouched for, and say it differently for each cause', () => {
        // Four causes, four remedies: re-export with PBMAC1, add a MAC at all,
        // leave public-key mode, or use a runtime with the HMAC. One sentence
        // for all four would send the caller to the wrong one.
        const messages = (['pkcs12-kdf', 'absent', 'public-key', 'pbmac1-unsupported'] as const).map((why) => pkcs12IntegrityUnverifiedReason('macData', why).message);
        expect(new Set(messages).size).toBe(4);
        expect(messages[0]).toContain('Appendix B');
    });

    it.each(ALL)('$code should carry its own code, a path, a standard and a message', ({ code, reason }) => {
        expect(reason.code).toBe(code);
        expect(reason.path.length).toBeGreaterThan(0);
        expect(reason.standard.length).toBeGreaterThan(0);
        expect(reason.message.length).toBeGreaterThan(20);
    });

    it.each(ALL)('$code should not carry the thrown-error prefix', ({ reason }) => {
        // `pkinative: ` marks what is thrown. Keeping it exclusive is what
        // lets a log reader tell an exception from a verdict, and it is why
        // the two factories that quote a parser's message strip it.
        expect(reason.message.startsWith('pkinative: ')).toBe(false);
        expect(reason.message).not.toContain('pkinative: ');
    });

    it.each(ALL)('$code should cite the same standard as the registry', ({ code, reason }) => {
        const entry = REGISTRY.reasons.find((r) => r.code === code);
        expect(entry?.standard).toBe(reason.standard);
    });

    it('should wrap an error code rather than duplicate the error registry', () => {
        const reason = inputMalformedReason('PKI_ASN1_TRUNCATED', 'pkinative: the value runs past the input', 'path[1]');
        expect(reason.errorCode).toBe('PKI_ASN1_TRUNCATED');
        // The parser's own detail survives, minus the prefix: a caller that
        // wants the specifics has them without catching anything.
        expect(reason.message).toContain('the value runs past the input');
        expect(reason.message).toContain('PKI_ASN1_TRUNCATED');
    });

    it('should tell "could not check" apart from "invalid", and say so in the message', () => {
        // The single most expensive confusion in this vocabulary: a runtime
        // without Ed448 says nothing about whether a signature is good, and
        // reporting that as SIGNATURE_INVALID turns "ask me elsewhere" into
        // "this certificate is bad".
        const notChecked = signatureNotCheckedReason('path[0]', 'PKI_CRYPTO_UNAVAILABLE', 'pkinative: no crypto.subtle here');
        expect(notChecked.code).toBe('PKI_REASON_SIGNATURE_NOT_CHECKED');
        expect(notChecked.errorCode).toBe('PKI_CRYPTO_UNAVAILABLE');
        expect(notChecked.message).toContain('says nothing about whether the signature is valid');
        expect(signatureInvalidReason('path[0]').errorCode).toBeUndefined();
    });

    it('should name the limit that stopped the search', () => {
        const reason = limitExceededReason('path', 'maxPolicyNodes', 4096);
        expect(reason.limit).toBe('maxPolicyNodes');
        expect(reason.message).toContain('maxPolicyNodes');
        expect(reason.message).toContain('4096');
    });

    it('should distinguish the three ways a certificate may not issue', () => {
        expect(notACaReason('path[1]', 'basicConstraints').message).toContain('cA in basicConstraints');
        expect(notACaReason('path[1]', 'keyUsage').message).toContain('keyCertSign in keyUsage');
        expect(notACaReason('path[1]', 'version').message).toContain('version 1 or 2');
    });

    it('should say which RFC 3161 rule a TSA certificate broke, under the same code', () => {
        // A TSA's extKeyUsage must be critical and must name timestamping
        // alone. It is the same fact as any other purpose refusal — this
        // certificate may not be used for this — so it is the same code, with
        // the sentence and the clause that say which rule it broke.
        const TSA = '1.3.6.1.5.5.7.3.8';
        const critical = purposeNotPermittedReason('tsa.extKeyUsage', TSA, [TSA], 'critical');
        const exclusive = purposeNotPermittedReason('tsa.extKeyUsage', TSA, [TSA, '1.3.6.1.5.5.7.3.4'], 'exclusive');
        const ordinary = purposeNotPermittedReason('tsa.extKeyUsage', TSA, ['1.3.6.1.5.5.7.3.4']);
        expect([critical.code, exclusive.code, ordinary.code]).toEqual(Array(3).fill('PKI_REASON_PURPOSE_NOT_PERMITTED'));
        expect([critical.standard, exclusive.standard, ordinary.standard]).toEqual(['RFC 3161 §2.3', 'RFC 3161 §2.3', 'RFC 5280 §4.2.1.12']);
        expect(critical.message).toContain('not critical');
        expect(exclusive.message).toContain('1.3.6.1.5.5.7.3.4');
    });

    it('should say what a TSA declined with, and stay quiet about what it did not say', () => {
        expect(tspNotGrantedReason('status', 'waiting', [], []).message).not.toContain('It said');
        expect(tspNotGrantedReason('status', 'rejection', ['no'], ['badAlg']).message).toContain('badAlg');
        // RFC 3161 §2.4.2: statusString and failInfo are both OPTIONAL. Each absent
        // one leaves no trace — no empty quotation, no empty failure list.
        expect(tspNotGrantedReason('status', 'waiting', [], []).message).toBe('the timestamp authority answered waiting and issued no token.');
        expect(tspNotGrantedReason('status', 'rejection', ['no'], []).message).toBe('the timestamp authority answered rejection and issued no token. It said: "no".');
        expect(tspNotGrantedReason('status', 'rejection', [], ['badAlg']).message).toBe('the timestamp authority answered rejection and issued no token. Failure: badAlg.');
    });

    it('should be frozen, so a report cannot be edited after it is returned', () => {
        const reason = expiredReason('path[0]', Date.UTC(2025, 0, 1), AT);
        expect(Object.isFrozen(reason)).toBe(true);
    });

    it('should never be thrown by anything in src/', () => {
        // The rule the whole vocabulary rests on: primitives return and
        // throw, compositions report, and exactly one layer converts. A
        // reason inside a throw changes what every caller's try block means.
        // `reason-parity` enforces this from the syntax tree across src/;
        // this is the locking assertion for the factories themselves.
        const source = readFileSync('src/core/pki-reasons.ts', 'utf8');
        expect(source).not.toMatch(/\bthrow\b/);
    });
});
