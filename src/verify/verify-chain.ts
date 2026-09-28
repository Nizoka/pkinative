/**
 * pkinative — the one call that asks every question
 * =================================================
 * Is this certificate one I should accept, for this host, for this purpose,
 * right now?
 *
 * Every layer below answers exactly one question and is deliberately blind to
 * the others. RFC 5280 §6 judges a chain and has no notion of the host you
 * connected to. `checkServerName` reads one certificate and knows nothing about
 * trust. `checkExtendedKeyUsage` reads a path and knows nothing about time.
 * Revocation takes a signature verdict it did not compute. That separation is
 * what keeps each of them synchronous, pure, fuzzable and small — and it leaves
 * somebody with the job of putting them in the right order.
 *
 * **If that somebody is every caller, every caller gets it slightly wrong.** So
 * it is here, once:
 *
 *   1. every signature the search could need, verified **in parallel**, before
 *      anything is decided;
 *   2. the path built with those verdicts and with the purpose already in hand,
 *      because a builder that does not know what a path is for will return one
 *      that fails the purpose check while an acceptable path existed;
 *   3. the host name, which §6 never asks about;
 *   4. revocation, against the lists you supplied.
 *
 * ## The one place that catches
 *
 * The rule this library runs on is *primitives return and throw, compositions
 * report, and exactly one layer converts.* This is that layer, and it is the
 * only module of `src/` allowed to catch a `PkiError`. A malformed CRL comes
 * back as `PKI_REASON_INPUT_MALFORMED` carrying the `PkiErrorCode` that would
 * have been thrown — which is how the promise *"a report never throws for bad
 * input"* is kept without copying the encoding vocabulary into the reason
 * registry.
 *
 * ## What it still does not do
 *
 * It does not fetch. Not a CRL, not an OCSP response, not a missing
 * intermediate. A verifier that reached the network would be a verifier an
 * attacker can point at a host of their choosing, and deciding *which* anchors
 * to trust is not a library's call either.
 *
 * @module verify/verify-chain
 */

import { inputMalformedReason, revocationUnknownReason } from '../core/pki-reasons.js';
import { verifyCertificateSignature, verifyCrlSignature, verifyOcspSignature } from '../crypto/x509-verify.js';
import { buildCertificatePath } from '../path/path-build.js';
import { checkExtendedKeyUsage } from '../path/path-purpose.js';
import { checkServerName, type ServerIdentity } from '../path/path-server-name.js';
import { computeKeyIdentifier } from '../hash/key-identifier.js';
import { sha1 } from '../hash/sha1.js';
import { sha256 } from '../hash/sha256.js';
import { checkRevocation } from '../revocation/crl-check.js';
import { checkOcspStatus } from '../revocation/ocsp-check.js';
import { parseOcspResponse } from '../revocation/ocsp-response.js';
import { parseCertificateList } from '../revocation/crl-parse.js';
import { PkiError } from '../types/pki-errors.js';
import type { PathBuildReport } from '../path/path-build.js';
import type { SignatureResult } from '../types/path-types.js';
import type { PkiLimits } from '../types/pki-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate } from '../types/x509-types.js';
import type { CertificateList } from '../types/crl-types.js';
import type { OcspBasicResponse } from '../types/ocsp-types.js';
import { parseCertificate } from '../x509/x509-certificate.js';
import { getExtension } from '../x509/x509-extensions.js';

/** What to accept, and everything needed to decide it. */
export interface VerifyChainInput {
    /** The certificate presented — the end entity. */
    readonly leaf: Certificate;
    /**
     * Every other certificate that may appear in the path, in any order. A TLS
     * handshake's `certificate_list` can be handed over whole; duplicates and
     * irrelevant entries are fine.
     */
    readonly candidates?: readonly Certificate[] | undefined;
    /**
     * The certificates you trust a priori. An empty list is accepted and always
     * produces `PKI_REASON_NO_TRUST_ANCHOR`: a chain with no anchor is not
     * valid, and refusing to run would hide that answer behind an exception.
     */
    readonly trustAnchors: readonly Certificate[];
    /** The instant to decide at, epoch milliseconds. Defaults to now. */
    readonly at?: number | undefined;
    /**
     * The host or address you connected to (RFC 6125). Omit it only when there
     * is genuinely no name to check — validating an archived chain, or one that
     * identifies something other than a network peer. **Omitting it for a TLS
     * peer is accepting a certificate issued for somebody else.**
     */
    readonly serverName?: ServerIdentity | undefined;
    /**
     * KeyPurposeId OIDs the chain must permit — `KEY_PURPOSES.serverAuth` for a
     * TLS server. Taken into the path search, not applied after it.
     */
    readonly purposes?: readonly string[] | undefined;
    /**
     * CRLs, as the DER you downloaded. Each is parsed here, matched to the
     * certificate it covers by encoded issuer name, and its signature checked
     * against the issuer in the path — a list nobody in the path signed is not
     * evidence, and it is reported rather than silently ignored.
     *
     * pkinative fetches nothing: which lists cover this chain, and getting
     * them, are yours.
     */
    readonly crls?: readonly Uint8Array[] | undefined;
    /**
     * OCSP responses, as the DER a responder returned or a TLS server stapled.
     *
     * Each is matched to the end-entity certificate by **all three** `CertID`
     * fields — an answer about somebody else's serial is a mismatch, not a
     * status — and the responder is authorised the way RFC 6960 §4.2.2.2 sets
     * out: either the CA that issued the certificate signed the response
     * itself, or it signed a certificate that carries `id-kp-OCSPSigning` and
     * that certificate signed the response. A responder nobody authorised is a
     * responder anyone can be, so nothing else counts — the certificates a
     * response *attaches* are a convenience for path building, never a claim of
     * authority.
     */
    readonly ocsp?: readonly Uint8Array[] | undefined;
    /**
     * The nonce you put in the request, so a replayed answer can be caught. A
     * different one coming back is always a mismatch; a **missing** echo is
     * reported only when `requireOcspNonce` asks, because the CA/Browser Forum
     * discourages nonces so responses stay cacheable and most public responders
     * omit it.
     */
    readonly ocspNonce?: Uint8Array | undefined;
    /** Treat a missing nonce echo as a mismatch. Off by default; see `ocspNonce`. */
    readonly requireOcspNonce?: boolean | undefined;
    /**
     * Report `PKI_REASON_REVOCATION_UNKNOWN` when no usable list covered the
     * end-entity certificate. **Off by default**, which is soft-fail — and the
     * default is off because the alternative is a library that refuses every
     * chain for which the caller happened not to download a list, which is a
     * library callers route around. On is the right setting wherever you can
     * actually obtain the lists.
     */
    readonly requireRevocation?: boolean | undefined;
    /**
     * Treat SHA-1 signatures as evidence. Default `false`, in which case they
     * are reported as `PKI_REASON_SIGNATURE_NOT_CHECKED` rather than believed —
     * a chosen-prefix collision has been practical since 2017, so such a
     * signature does not bind the bytes it covers.
     */
    readonly allowSha1?: boolean | undefined;
    /** `user-initial-policy-set` (RFC 5280 §6.1.1 (c)). */
    readonly initialPolicySet?: readonly string[] | undefined;
    /** `initial-explicit-policy` (§6.1.1 (e)). */
    readonly requireExplicitPolicy?: boolean | undefined;
    /** `initial-policy-mapping-inhibit` (§6.1.1 (f)). */
    readonly inhibitPolicyMapping?: boolean | undefined;
    /** `initial-any-policy-inhibit` (§6.1.1 (g)). */
    readonly inhibitAnyPolicy?: boolean | undefined;
    /** Overrides for any subset of `DEFAULT_PKI_LIMITS`. */
    readonly limits?: Partial<PkiLimits> | undefined;
}

/** The verdict, every reason behind it, and the path that was judged. */
export interface VerifyChainReport extends PathBuildReport {
    /**
     * How many signature verifications were performed. Worth logging: it is the
     * cost of the call, and a number far above the path length means the bag
     * held many plausible issuers — which is what cross-signing looks like, and
     * what a caller passing a whole trust store will see.
     */
    readonly verified: number;
}

/**
 * The `PkiError` a layer below threw, or a rethrow.
 *
 * This is the only module allowed to catch, and catching in JavaScript catches
 * *everything* — so the one thing it must not do is turn a programming error
 * into a verdict. A `PkiReason` built from a `TypeError` would carry
 * `errorCode: undefined` and read like a statement about the certificate.
 */
function _pkiError(error: unknown): PkiError {
    /* v8 ignore next -- unreachable: every layer below promises that only a PkiError subclass escapes for an input reason, and tests/tools/architecture.test.ts holds the shape that makes that true. The rethrow exists so that a breach of that promise reaches the caller as the bug it is instead of being reported as a fact about their certificate; no input can reach it. */
    if (!(error instanceof PkiError)) throw error;
    return error;
}

/** `id-kp-OCSPSigning`, the only purpose that makes a delegate a responder. */
const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

const _hex = (bytes: Uint8Array): string => {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
};

/**
 * Verify a certificate the whole way: chain, name, purpose and revocation.
 *
 * ```ts
 * import { verifyCertificateChain, KEY_PURPOSES } from 'pkinative';
 *
 * const report = await verifyCertificateChain({
 *     leaf, candidates: whateverTheServerSent, trustAnchors: yourRoots,
 *     serverName: { kind: 'dns', value: 'bank.example' },
 *     purposes: [KEY_PURPOSES.serverAuth],
 * });
 * if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
 * ```
 *
 * **It never throws for a verification issue**, and it never throws for bad
 * input either: a malformed CRL is `PKI_REASON_INPUT_MALFORMED`, carrying in
 * `errorCode` the `PkiErrorCode` that would have been thrown. The only thing
 * that throws is misusing the API — an unknown key in `limits`, or a `leaf`
 * that is not a parsed certificate.
 *
 * @param input See {@link VerifyChainInput}.
 * @returns The verdict, every reason behind it, the path judged, how many
 *   candidate paths were explored and how many signatures were verified.
 * @throws {PkiError} `PKI_INVALID_OPTION` for an unknown key in `limits`,
 *   `PKI_INVALID_INPUT` when a certificate is not one `parseCertificate`
 *   produced.
 */
export async function verifyCertificateChain(input: VerifyChainInput): Promise<VerifyChainReport> {
    const at = input.at ?? Date.now();
    const candidates = input.candidates ?? [];
    const all = [input.leaf, ...candidates, ...input.trustAnchors];

    // Index by encoded subject name, then keep only what a name chain from the
    // leaf can reach: the search walks nothing else, so a pair outside that
    // closure cannot change an answer, and a trust store of hundreds costs the
    // handful of verifications that name the right subjects.
    const bySubject = new Map<string, Certificate[]>();
    for (const certificate of all) {
        const key = _hex(certificate.subject.der);
        bySubject.set(key, [...(bySubject.get(key) ?? []), certificate]);
    }
    const pairs: Array<readonly [Certificate, Certificate]> = [];
    const walked = new Set<Certificate>();
    const queue: Certificate[] = [input.leaf];
    while (queue.length > 0) {
        const subject = queue.pop() as Certificate;
        if (walked.has(subject)) continue;
        walked.add(subject);
        for (const issuer of bySubject.get(_hex(subject.issuer.der)) ?? []) {
            // A self-signed certificate is not a link: §6 does not check a trust
            // anchor's own signature, and following the edge would loop.
            if (issuer === subject) continue;
            pairs.push([subject, issuer]);
            queue.push(issuer);
        }
    }

    // In parallel, and before anything is decided — which is the whole reason
    // §6 takes verdicts rather than keys.
    const signatures: SignatureResult[] = await Promise.all(pairs.map(async ([subject, issuer]) => {
        const options = { allowSha1: input.allowSha1 === true };
        try {
            const valid = await verifyCertificateSignature(subject, issuer, options);
            return { certificate: subject, issuer, verdict: valid ? 'valid' as const : 'invalid' as const };
        } catch (error) {
            // A runtime that cannot decide says nothing about the signature, and
            // so does a SHA-1 refusal. `not-checked` keeps that apart from
            // `invalid` all the way into the report.
            const refused = _pkiError(error);
            return { certificate: subject, issuer, verdict: 'not-checked' as const, errorCode: refused.code, detail: refused.message };
        }
    }));

    const report = buildCertificatePath({
        leaf: input.leaf,
        candidates,
        trustAnchors: input.trustAnchors,
        at,
        signatures,
        ...(input.purposes === undefined ? {} : { requiredPurposes: input.purposes }),
        ...(input.initialPolicySet === undefined ? {} : { initialPolicySet: input.initialPolicySet }),
        ...(input.requireExplicitPolicy === undefined ? {} : { requireExplicitPolicy: input.requireExplicitPolicy }),
        ...(input.inhibitPolicyMapping === undefined ? {} : { inhibitPolicyMapping: input.inhibitPolicyMapping }),
        ...(input.inhibitAnyPolicy === undefined ? {} : { inhibitAnyPolicy: input.inhibitAnyPolicy }),
        ...(input.limits === undefined ? {} : { limits: input.limits }),
    });

    const reasons: PkiReason[] = [...report.reasons];

    // The host name is judged whatever §6 decided: a chain that fails for one
    // reason and is also for the wrong host has two things wrong with it, and a
    // caller fixing one per round trip is a caller the report failed.
    if (input.serverName !== undefined) reasons.push(...checkServerName(input.leaf, input.serverName));

    // The purpose is restated on the path that was walked, whenever that path
    // reached an anchor — not only when §6 accepted it. An expired certificate
    // that is also for the wrong purpose has two things wrong with it, and the
    // caller who is about to ask their CA for a renewal needs both in the same
    // report. The anchor is the condition because without one there is no path
    // to judge: `report.path` is then the deepest attempt, and reasons about
    // certificates on no accepted path are noise.
    //
    // `buildCertificatePath` already refused any path the purpose forbade, so
    // this repeats rather than decides — which is why it cannot contradict it.
    // …and it is skipped when the search already refused *for* the purpose,
    // which is the one case where repeating it would say the same thing twice.
    const anchored = !report.reasons.some((reason) => reason.code === 'PKI_REASON_NO_TRUST_ANCHOR');
    const alreadySaid = report.reasons.some((reason) => reason.code === 'PKI_REASON_PURPOSE_NOT_PERMITTED');
    if (input.purposes !== undefined && anchored && !alreadySaid && report.path.length > 0) {
        for (const purpose of input.purposes) reasons.push(...checkExtendedKeyUsage(report.path, purpose));
    }

    reasons.push(...await _checkRevocation(input, report.path, at));

    return { valid: reasons.length === 0, reasons, path: report.path, explored: report.explored, verified: pairs.length };
}

/**
 * Whether that key signed that list, or `undefined` when the question could not
 * be put — a runtime without Web Crypto, or a digest this library will not treat
 * as evidence. `checkRevocation` words those two differently, and collapsing
 * them would turn *"ask me elsewhere"* into *"this list is forged"*.
 */
async function _crlSignature(crl: CertificateList, issuer: Certificate, allowSha1: boolean): Promise<boolean | undefined> {
    try {
        return await verifyCrlSignature(crl, issuer, { allowSha1 });
    } catch (error) {
        _pkiError(error);
        return undefined;
    }
}

/**
 * The end-entity certificate against the lists the caller supplied.
 *
 * Only the leaf is checked. Revoking an intermediate is real and matters, and
 * answering it properly means one list per CA and a policy for what to do when
 * some of them are missing — which is a decision, not a default. Checking only
 * what the caller can actually supply a list for is the honest half, and
 * `checkRevocation` is exported for the rest.
 */
async function _checkRevocation(input: VerifyChainInput, path: readonly Certificate[], at: number): Promise<PkiReason[]> {
    const out: PkiReason[] = [];
    const lists = input.crls ?? [];
    const stapled = input.ocsp ?? [];
    if (lists.length === 0 && stapled.length === 0) {
        if (input.requireRevocation === true) {
            out.push(revocationUnknownReason('path[0]', 'no revocation list and no OCSP response were supplied for this certificate'));
        }
        return out;
    }

    // One options object for both readers: the limits are the caller's, and a
    // CRL's profile concerns are not this report's business — a caller who
    // wants them calls parseCertificateList themselves.
    const reading = { limits: input.limits ?? {}, onDiagnostic: (): undefined => undefined };
    const issuer = path[1];
    let covered = false;
    for (const [index, der] of lists.entries()) {
        const where = `crl[${String(index)}]`;
        try {
            const crl = parseCertificateList(der, reading);
            // A list is about one CA, and it covers this certificate when it
            // names the CA that issued it — encoded names, as everywhere else,
            // because two names that print the same and encode differently are
            // two names. A list about somebody else is skipped in silence: a
            // caller handing over every list they hold is the ordinary case,
            // and `PKI_REASON_REVOCATION_WRONG_ISSUER` is for a list they
            // *meant* to apply, which is what checkRevocation answers.
            if (_hex(crl.issuer.der) !== _hex(input.leaf.issuer.der)) continue;
            covered = true;
            // Whether the CA that issued the certificate also signed the list.
            // `undefined` and `false` are different answers and checkRevocation
            // words them differently: never checked, versus checked and wrong.
            let signatureVerified: boolean | undefined;
            if (issuer !== undefined) {
                // "Entitled" is the operative word, and it is two questions.
                // RFC 5280 §4.2.1.3: a CA that issues CRLs MUST assert
                // `cRLSign`, so a CA whose keyUsage omits it is not entitled
                // whatever its key computes — accepting its list would let a CA
                // constrained to signing certificates revoke them instead.
                // Absent keyUsage asserts nothing and constrains nothing, which
                // is the same reading §6.1.4 (n) takes of `keyCertSign`.
                const usage = getExtension(issuer, 'keyUsage');
                signatureVerified = usage !== undefined && !usage.usages.includes('cRLSign')
                    ? false
                    : await _crlSignature(crl, issuer, input.allowSha1 === true);
            }
            out.push(...checkRevocation({
                certificate: input.leaf,
                crl,
                crlDer: der,
                at,
                ...(signatureVerified === undefined ? {} : { signatureVerified }),
                options: reading,
            }));
        } catch (error) {
            // **The one catch this library allows**, and the reason the reason
            // registry wraps the error registry instead of copying it: the code
            // that would have been thrown travels in `errorCode`, so a report
            // can promise never to throw for bad input without a second frozen
            // vocabulary of encoding failures.
            const refused = _pkiError(error);
            out.push(inputMalformedReason(refused.code, refused.message, where));
        }
    }
    for (const [index, der] of stapled.entries()) {
        const where = `ocsp[${String(index)}]`;
        try {
            const response = parseOcspResponse(der, reading);
            const basic = response.basicResponse;
            // A response that is not `successful` carries no body — the protocol
            // has nowhere to put one — so there is nothing to match against and
            // `checkOcspStatus` reports the status the responder gave.
            if (basic === undefined) {
                out.push(...checkOcspStatus({ response, expected: _certId(input.leaf, issuer, 'SHA-1'), at }));
                continue;
            }
            // The digest the responder used, taken from its answer about **our**
            // serial: a response may carry several, and computing the expected
            // CertID under the wrong algorithm turns every answer into a
            // mismatch. When no answer names our serial, any algorithm gives the
            // same verdict, so the first one keeps the comparison well formed.
            const mine = basic.responses.find((one) => _hex(one.certId.serialNumber.bytes) === _hex(input.leaf.serialNumber.bytes));
            const algorithm = _digestOf(mine?.certId.hashAlgorithm.oid ?? basic.responses[0]?.certId.hashAlgorithm.oid);
            const authorised = issuer === undefined
                ? undefined
                : await _ocspSigner(basic, issuer, at, input.allowSha1 === true, reading);
            covered = true;
            out.push(...checkOcspStatus({
                response,
                expected: _certId(input.leaf, issuer, algorithm),
                at,
                ...(authorised === undefined ? {} : { signatureVerified: authorised.signed, responderAuthorised: authorised.authorised }),
                ...(input.ocspNonce === undefined ? {} : { nonce: input.ocspNonce }),
                ...(input.requireOcspNonce === undefined ? {} : { requireNonce: input.requireOcspNonce }),
            }));
        } catch (error) {
            const refused = _pkiError(error);
            out.push(inputMalformedReason(refused.code, refused.message, where));
        }
    }

    if (!covered && input.requireRevocation === true) {
        out.push(revocationUnknownReason('path[0]', 'nothing supplied answers for this certificate\'s CA'));
    }
    return out;
}

/** The three values RFC 6960 §4.1.1 binds an answer to, under one digest. */
function _certId(certificate: Certificate, issuer: Certificate | undefined, algorithm: 'SHA-1' | 'SHA-256'): {
    issuerNameHash: Uint8Array;
    issuerKeyHash: Uint8Array;
    serialNumber: Uint8Array;
} {
    const digest = algorithm === 'SHA-256' ? sha256 : sha1;
    // With no issuer in the path there is nothing to hash, and empty expected
    // values make every answer a mismatch — which is the right verdict: an OCSP
    // answer about a certificate whose CA we never established is not evidence.
    return {
        issuerNameHash: issuer === undefined ? new Uint8Array(0) : digest(issuer.subject.der),
        issuerKeyHash: issuer === undefined ? new Uint8Array(0) : computeKeyIdentifier(issuer.subjectPublicKeyInfo.publicKey.bytes, algorithm),
        serialNumber: certificate.serialNumber.bytes,
    };
}

/** `SHA-256` when the responder said so, `SHA-1` otherwise — RFC 6960 §4.3's default. */
function _digestOf(oid: string | undefined): 'SHA-1' | 'SHA-256' {
    return oid === '2.16.840.1.101.3.4.2.1' ? 'SHA-256' : 'SHA-1';
}

/**
 * Who signed this response, and whether they were allowed to (RFC 6960
 * §4.2.2.2).
 *
 * Exactly two things count. **The CA signed it itself** — the simple case, and
 * the only one needing no extra certificate. Or **the CA delegated**: it issued
 * a certificate carrying `id-kp-OCSPSigning`, and that certificate signed this
 * response. The third route the RFC allows, a responder the client trusts out
 * of band, is a decision no library can take for a caller, so it is not taken
 * here.
 *
 * The certificates a response **attaches** are a convenience for reaching the
 * delegate, never a claim of authority: each is checked to have been issued by
 * this CA, to carry the purpose, and to be valid now, before its signature
 * counts for anything. A client that skipped those would let the responder
 * nominate itself, which is what §4.2.2.2 exists to prevent.
 */
async function _ocspSigner(
    basic: OcspBasicResponse,
    issuer: Certificate,
    at: number,
    allowSha1: boolean,
    reading: { limits: Partial<PkiLimits>; onDiagnostic: () => undefined },
): Promise<{ signed: boolean | undefined; authorised: boolean }> {
    const direct = await _ocspSignature(basic, issuer);
    if (direct === true) return { signed: true, authorised: true };

    for (const der of basic.certificates) {
        let delegate: Certificate;
        try {
            delegate = parseCertificate(der, reading);
        } catch (error) {
            // An attached certificate nobody can read is not a reason to refuse
            // the response: it was a hint, and the hint was unusable.
            _pkiError(error);
            continue;
        }
        if (_hex(delegate.issuer.der) !== _hex(issuer.subject.der)) continue;
        const purposes = getExtension(delegate, 'extendedKeyUsage')?.purposes ?? [];
        if (!purposes.includes(OCSP_SIGNING)) continue;
        if (at < delegate.validity.notBefore.epochMilliseconds || at > delegate.validity.notAfter.epochMilliseconds) continue;
        // The CA must actually have issued it, not merely be named by it.
        let issued: boolean;
        try {
            issued = await verifyCertificateSignature(delegate, issuer, { allowSha1 });
        } catch (error) {
            _pkiError(error);
            continue;
        }
        if (!issued) continue;
        const signed = await _ocspSignature(basic, delegate);
        if (signed === true) return { signed: true, authorised: true };
    }
    // Nobody authorised signed it. `signed` carries the direct attempt's answer
    // so that "checked and wrong" stays apart from "never checked".
    return { signed: direct, authorised: false };
}

/**
 * One signature attempt, with a refusal reported as "could not be put".
 *
 * No `allowSha1` here, and that is deliberate rather than an omission:
 * `verifyOcspSignature` refuses SHA-1 outright because a revocation answer is a
 * live authentication decision and has no archival reading to make room for.
 */
async function _ocspSignature(basic: OcspBasicResponse, signer: Certificate): Promise<boolean | undefined> {
    try {
        return await verifyOcspSignature(basic, signer);
    } catch (error) {
        _pkiError(error);
        return undefined;
    }
}
