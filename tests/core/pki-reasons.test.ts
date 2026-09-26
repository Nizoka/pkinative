import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
    expiredReason,
    inputMalformedReason,
    issuerNotFoundReason,
    limitExceededReason,
    nameExcludedReason,
    nameNotPermittedReason,
    noTrustAnchorReason,
    notACaReason,
    notYetValidReason,
    pathLoopsReason,
    pathTooLongReason,
    signatureInvalidReason,
    signatureNotCheckedReason,
    unrecognisedCriticalExtensionReason,
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
    { code: 'PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION', reason: unrecognisedCriticalExtensionReason('path[0].extensions', '1.3.6.1.4.1.99999.7') },
    { code: 'PKI_REASON_NAME_NOT_PERMITTED', reason: nameNotPermittedReason('path[0].subjectAltName', 'dNSName', 'evil.test') },
    { code: 'PKI_REASON_NAME_EXCLUDED', reason: nameExcludedReason('path[0].subjectAltName', 'dNSName', 'secret.example.com') },
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

    it('should distinguish the two ways a certificate may not issue', () => {
        expect(notACaReason('path[1]', 'basicConstraints').message).toContain('cA in basicConstraints');
        expect(notACaReason('path[1]', 'keyUsage').message).toContain('keyCertSign in keyUsage');
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
