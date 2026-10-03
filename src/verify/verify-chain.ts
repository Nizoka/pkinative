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
 *   1. every signature the path search is about to rely on, verified **the
 *      moment it is about to be tried and never twice** — the search is replayed
 *      ahead of the builder (`_searchVerdicts`), so a bag of forty certificates
 *      under one name costs forty verifications only when all forty have to be
 *      tried, and the builder itself stays synchronous and pure;
 *   2. the path built with exactly those verdicts and with the purpose already
 *      in hand, because a builder that does not know what a path is for will
 *      return one that fails the purpose check while an acceptable path existed;
 *   3. the host name, which §6 never asks about;
 *   4. revocation, against the lists you supplied.
 *
 * ## The one place that catches
 *
 * The rule this library runs on is *primitives return and throw, compositions
 * report, and exactly one layer converts.* This is that layer, and it is the
 * only one of `src/` that turns a `PkiError` into a reason. A malformed CRL comes
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

import { inputMalformedReason, revocationUnknownReason, unknownCriticalExtensionReason } from '../core/pki-reasons.js';
import { verifyCertificateSignature, verifyCrlSignature, verifyOcspSignature } from '../crypto/x509-verify.js';
import { buildCertificatePath } from '../path/path-build.js';
import { checkExtendedKeyUsage } from '../path/path-purpose.js';
import { checkServerName, type ServerIdentity } from '../path/path-server-name.js';
import { _validateIndexed, type SignatureEntry } from '../path/path-validate.js';
import { computeKeyIdentifier } from '../hash/key-identifier.js';
import { sha1 } from '../hash/sha1.js';
import { sha256 } from '../hash/sha256.js';
import { checkRevocation } from '../revocation/crl-check.js';
import type { DeltaCrlInput, CheckRevocationInput } from '../revocation/crl-check.js';
import { checkOcspStatus } from '../revocation/ocsp-check.js';
import { parseOcspResponse } from '../revocation/ocsp-response.js';
import { parseCertificateList } from '../revocation/crl-parse.js';
import { _crlScopeProblem, _deltaApplies, _interimReasons } from '../revocation/crl-scope.js';
import { createAsn1Context } from '../asn1/asn1-context.js';
import { assertBytes, bytesEqual, isBytes } from '../core/bytes.js';
import { _pkiError } from '../core/pki-error-guard.js';
import { resolveLimits } from '../core/pki-limits.js';
import { PkiError } from '../types/pki-errors.js';
import type { BuildCertificatePathInput, BuildCertificatePathReport } from '../path/path-build.js';
import type { SignatureResult } from '../types/path-types.js';
import type { PkiDiagnosticHandler, PkiLimits, PkiParseOptions } from '../types/pki-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate, ReasonFlag } from '../types/x509-types.js';
import type { CertificateList } from '../types/crl-types.js';
import type { OcspBasicResponse } from '../types/ocsp-types.js';
import { parseCertificate } from '../x509/x509-certificate.js';
import { getExtension } from '../x509/x509-extensions.js';

/** What to accept, and everything needed to decide it. */
export interface VerifyCertificateChainInput {
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
    readonly ocspResponses?: readonly Uint8Array[] | undefined;
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
    /**
     * Receive every diagnostic this verification raises or reads: what the
     * CRLs, the OCSP responses and the responders' certificates say about
     * themselves that their RFCs ask them not to, and what only this call can
     * decide — an OCSP `responderID` that does not name the signer, answers
     * about certificates nobody asked about. None of it changes the verdict;
     * the report carries the verdict. **Without it, nothing is reported**: a
     * verdict call does not warn on the console, and never throws for a
     * diagnostic (`strict` is not an input here).
     */
    readonly onDiagnostic?: PkiDiagnosticHandler | undefined;
}

/** The verdict, every reason behind it, and the path that was judged. */
export interface VerifyCertificateChainReport extends BuildCertificatePathReport {
    /**
     * How many signature verifications were performed. Worth logging: it is the
     * cost of the call, and a number far above the path length means the bag
     * held many plausible issuers — which is what cross-signing looks like, and
     * what a caller passing a whole trust store will see.
     */
    readonly signatureVerifications: number;
}

/**
 * The `PkiError` a layer below threw, or a rethrow — the core guard, re-exported
 * under the name every composition in `verify/` already uses.
 *
 * @internal
 */
export { _pkiError };

/**
 * Refuse, before anything is read, what is not a certificate `parseCertificate`
 * made.
 *
 * The other half of the promise *"a report throws only for API misuse"*. A
 * composition that catches has to decide misuse up front, because once inside
 * the catch a `PKI_INVALID_INPUT` from a layer below reads exactly like a fact
 * about the input — and an object that is not a certificate otherwise reaches
 * `certificate.subject.der` and escapes as a `TypeError`.
 *
 * @internal
 */
export function _assertCertificates(values: readonly unknown[], what: string): void {
    for (const [index, value] of values.entries()) {
        const candidate = value as Partial<Certificate> | null;
        if (typeof value !== 'object' || candidate === null
            || !isBytes(candidate.der)
            || !isBytes(candidate.subject?.der)
            || !isBytes(candidate.issuer?.der)
            || !Array.isArray(candidate.extensions)) {
            throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what}[${String(index)}] must be a certificate from parseCertificate — pass the parsed value, not its DER`);
        }
    }
}

/**
 * Refuse byte inputs of the wrong type, and malformed reading options, before
 * anything is read — for the same reason as {@link _assertCertificates}: past
 * this point every `PkiError` is converted into a reason about the input.
 *
 * @internal
 */
export function _assertArguments(bytes: ReadonlyArray<readonly [string, unknown]>, reading: PkiParseOptions): void {
    for (const [what, value] of bytes) if (value !== undefined) assertBytes(value, what);
    createAsn1Context(reading);
}

/** `id-kp-OCSPSigning`, the only purpose that makes a delegate a responder. */
const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

const _hex = (bytes: Uint8Array): string => {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
};

/**
 * Each distinct DER once, with the position the caller first gave it.
 *
 * The same list arrives twice more often than not — a signed message carries
 * the CRL its signer relied on, and the caller passes the one they downloaded
 * — and a list is one piece of evidence however many copies of it there are.
 * Reading every copy reported every revocation once per copy. Identity is the
 * encoding, not the parsed content: two lists that differ in a byte are two
 * statements, and both are judged.
 */
function _firstOfEach(ders: readonly Uint8Array[]): Array<[number, Uint8Array]> {
    const seen = new Set<string>();
    const out: Array<[number, Uint8Array]> = [];
    for (const [index, der] of ders.entries()) {
        const key = _hex(der);
        if (seen.has(key)) continue;
        seen.add(key);
        out.push([index, der]);
    }
    return out;
}

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
 * @param input See {@link VerifyCertificateChainInput}.
 * @returns The verdict, every reason behind it, the path judged, how many
 *   candidate paths were explored and how many signatures were verified.
 * @throws {PkiError} `PKI_LIMIT_INVALID` for an unknown or non-positive key in `limits`,
 *   `PKI_INVALID_INPUT` when a certificate is not one `parseCertificate`
 *   produced.
 */
export async function verifyCertificateChain(input: VerifyCertificateChainInput): Promise<VerifyCertificateChainReport> {
    _assertCertificates([input.leaf], 'leaf');
    _assertCertificates(input.candidates ?? [], 'candidates');
    _assertCertificates(input.trustAnchors, 'trustAnchors');
    _assertArguments([
        ...(input.crls ?? []).map((der, index) => [`crls[${String(index)}]`, der] as const),
        ...(input.ocspResponses ?? []).map((der, index) => [`ocspResponses[${String(index)}]`, der] as const),
        ['ocspNonce', input.ocspNonce],
    ], { limits: input.limits ?? {} });
    const at = input.at ?? Date.now();
    const candidates = input.candidates ?? [];

    // Every link the search is about to rely on, verified then and once —
    // which is the whole reason §6 takes verdicts rather than keys. The memo
    // outlives the search: a CRL issuer off the path is judged later with its
    // own links added (`_signerStillGood`), from the same memo.
    const verdicts: VerdictMemo = {
        allowSha1: input.allowSha1 === true,
        pending: new Map(),
        settled: [],
        index: new Map(),
    };
    const search: SearchInput = {
        leaf: input.leaf,
        candidates,
        trustAnchors: input.trustAnchors,
        at,
        ...(input.purposes === undefined ? {} : { purposes: input.purposes }),
        ...(input.initialPolicySet === undefined ? {} : { initialPolicySet: input.initialPolicySet }),
        ...(input.requireExplicitPolicy === undefined ? {} : { requireExplicitPolicy: input.requireExplicitPolicy }),
        ...(input.inhibitPolicyMapping === undefined ? {} : { inhibitPolicyMapping: input.inhibitPolicyMapping }),
        ...(input.inhibitAnyPolicy === undefined ? {} : { inhibitAnyPolicy: input.inhibitAnyPolicy }),
        ...(input.limits === undefined ? {} : { limits: input.limits }),
    };
    await _searchVerdicts(search, verdicts);
    const report = buildCertificatePath({ ...search, signatures: [...verdicts.settled] });

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

    reasons.push(...await _checkRevocation(input, report.path, at, verdicts));

    return { valid: reasons.length === 0, reasons, path: report.path, explored: report.explored, signatureVerifications: verdicts.settled.length };
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
 * Whether a key **entitled** to sign this list did, trying every certificate
 * that could hold one.
 *
 * A CA is a name, not a key. It may hold several — a rollover leaves two live
 * at once, and NIST PKITS has a test where the CA signs certificates with one
 * key and its lists with another. So the signer is looked for among every
 * certificate in the path and in the candidate bag whose **subject** is the
 * list's issuer, and the first one that verifies settles it. Trying only the
 * certificate that happens to sit above the leaf in the path asks about one of
 * the CA's keys and calls a `false` an answer about the CA.
 *
 * "Entitled" is three questions, not one. RFC 5280 §4.2.1.3 requires a CA that
 * issues CRLs to assert `cRLSign`, so a certificate whose keyUsage omits it is
 * refused before its key is asked — accepting its list would let a CA
 * constrained to signing certificates revoke them instead. Absent keyUsage
 * asserts nothing and constrains nothing, which is the reading §6.1.4 (n) takes
 * of `keyCertSign`. When the list names a key in its own
 * `authorityKeyIdentifier`, that is the CA saying **which** of its keys revokes
 * (`_designated`). And a key delegated the job must still hold a good
 * certificate itself (`_signerStillGood`), or withdrawing a compromised
 * CRL-signing key would mean nothing.
 */
async function _crlSigner(ctx: CrlSignerContext, crl: CertificateList, about: string, pathOnly = false): Promise<boolean | undefined> {
    const { input, path } = ctx;
    let answer: boolean | undefined;
    const named = _namedKeyIdentifier(crl);
    // `pathOnly` is the rank cut, asked from `_signerStillGood`: judging a
    // delegated signer needs a list, and the only lists that may judge one are
    // those the path itself vouches for. Every candidate in that pool is a path
    // certificate, for which `_signerStillGood` answers immediately — so there
    // is no second level and nothing to terminate.
    const pool = pathOnly
        ? [...path, ...input.trustAnchors]
        : [...path, ...(input.candidates ?? []), ...input.trustAnchors];
    for (const candidate of pool) {
        if (_hex(candidate.subject.der) !== about) continue;
        if (!_designated(named, candidate)) continue;
        const usage = getExtension(candidate, 'keyUsage');
        if (usage !== undefined && !usage.usages.includes('cRLSign')) { answer ??= false; continue; }
        // A key that may revoke is a key whose own certificate is still good.
        if (!await _signerStillGood(ctx, candidate)) { answer ??= false; continue; }
        const verified = await _crlSignature(crl, candidate, input.allowSha1 === true);
        if (verified === true) return true;
        // "Checked and wrong" outranks "never checked": a caller reading the
        // report should hear the strongest thing that was actually established.
        if (verified === false) answer = false;
    }
    return answer;
}

/**
 * Whether a **delegated** CRL signer's own certificate is still good — in date,
 * and not revoked.
 *
 * This is what makes revoking a compromised CRL-signing key mean anything. A CA
 * that hands the job to a separate certificate and then withdraws it has said
 * that key may no longer speak; a verifier that kept believing its lists would
 * let whoever holds that key publish "nothing is revoked" for as long as the
 * certificate's validity period runs. NIST PKITS builds
 * `InvalidSeparateCertificateandCRLKeysTest21` on exactly that.
 *
 * **Delegated only, and that is the same rank argument twice.** A certificate
 * on the path is not asked about here at all: §6 already judged its validity
 * and the main loop already checks its revocation, so repeating either would
 * report one fact as two findings. It is also what cuts the recursion — the
 * list that may disqualify a delegate is asked for with `pathOnly`, whose
 * candidates are all path certificates, and every one of those returns from the
 * line below without asking anything further.
 */
async function _signerStillGood(ctx: CrlSignerContext, candidate: Certificate): Promise<boolean> {
    const mine = _hex(candidate.der);
    if (ctx.path.some((c) => _hex(c.der) === mine) || ctx.input.trustAnchors.some((c) => _hex(c.der) === mine)) return true;
    if (ctx.at < candidate.validity.notBefore.epochMilliseconds || ctx.at > candidate.validity.notAfter.epochMilliseconds) return false;
    // RFC 5280 §6.3.3 (f): a CRL issuer that is not on the path is believed
    // only once *its* certificate has been validated under the same anchors.
    // The bag is the sender's — a TLS server's, a CMS signer's — so a
    // self-signed certificate copying the CA's name and asserting cRLSign is
    // exactly what an attacker who holds a revoked key would put there, with
    // a list that clears it. Its links are verified here, on demand: an
    // indirect CRL issuer (§5.2.5, PKITS 4.14) is a name the leaf's own chain
    // never reaches, and a signer nobody vouched for is not believed.
    // A candidate off the path and not an anchor came from the bag, so the bag
    // exists; `reading.limits` is set where `reading` is built.
    const bag = ctx.input.candidates as readonly Certificate[];
    const search: SearchInput = { leaf: candidate, candidates: bag, trustAnchors: ctx.input.trustAnchors, at: ctx.at, limits: ctx.reading.limits as Partial<PkiLimits> };
    await _searchVerdicts(search, ctx.verdicts);
    const own = buildCertificatePath({ ...search, signatures: [...ctx.verdicts.settled] });
    if (!own.valid) return false;
    return await _unrevokedOnLists(ctx, candidate);
}

/**
 * Whether no list the path vouches for says this delegate is revoked — the
 * revocation half of `_signerStillGood`, shared with the delegated OCSP
 * responder, whose certificate the CA issued and may since have withdrawn.
 *
 * Only a list signed by a key the path itself vouches for (`pathOnly`) may
 * judge a delegate, which is what keeps the question one level deep. No such
 * list about the delegate is no evidence against it, as for a CRL signer.
 */
async function _unrevokedOnLists(ctx: CrlSignerContext, candidate: Certificate): Promise<boolean> {
    for (const { der, crl } of ctx.lists) {
        const problem = _crlScopeProblem({ certificate: candidate, crl });
        if (problem !== null && problem.kind !== 'unusable') continue;
        if (await _crlSigner(ctx, crl, _hex(crl.issuer.der), true) !== true) continue;
        const reasons = _judged({ certificate: candidate, crl, crlDer: der, at: ctx.at, signatureVerified: true, limits: ctx.reading.limits, onDiagnostic: ctx.reading.onDiagnostic }, 'crl');
        // A list its CA signed and nobody can walk — or may use, for a
        // critical extension on it or on any entry (RFC 5280 §5.3, §6.3.3) —
        // has not said the delegate is unrevoked, so the delegate is not
        // believed: fail closed.
        if (reasons.some((reason) => STILL_GOOD_REFUSALS.has(reason.code))) return false;
    }
    return true;
}

/**
 * The signature verdicts one report has asked for, each link once.
 *
 * `pending` is keyed exactly as `_signatureIndex` keys a verdict with an
 * issuer, `hex(subject.der)|hex(issuer.der)`, so a link asked for twice —
 * by the leaf's search and again by a delegated signer's — is verified once.
 * `settled` is what `buildCertificatePath` receives, in the order the links
 * were tried, and `index` is the same set in the shape `_validateIndexed`
 * reads, kept incrementally so the search judges a path without re-indexing
 * every verdict so far.
 */
interface VerdictMemo {
    readonly allowSha1: boolean;
    readonly pending: Map<string, Promise<SignatureResult>>;
    readonly settled: SignatureResult[];
    readonly index: Map<string, SignatureEntry>;
}

/** `buildCertificatePath`'s input, minus the verdicts the search is about to collect for it. */
type SearchInput = Omit<BuildCertificatePathInput, 'signatures'>;

/**
 * The verdict of one link, asked once. A runtime that cannot decide says
 * nothing about the signature, and so does a SHA-1 refusal: `not-checked`
 * keeps that apart from `invalid` all the way into the report.
 */
function _verdict(memo: VerdictMemo, subject: Certificate, issuer: Certificate): Promise<SignatureResult> {
    const key = `${_hex(subject.der)}|${_hex(issuer.der)}`;
    let pending = memo.pending.get(key);
    if (pending === undefined) {
        pending = (async (): Promise<SignatureResult> => {
            let result: SignatureResult;
            try {
                const valid = await verifyCertificateSignature(subject, issuer, { allowSha1: memo.allowSha1 });
                result = { certificate: subject, issuer, verdict: valid ? 'valid' : 'invalid' };
            } catch (error) {
                const refused = _pkiError(error);
                result = { certificate: subject, issuer, verdict: 'not-checked', errorCode: refused.code, detail: refused.message };
            }
            memo.settled.push(result);
            memo.index.set(key, { verdict: result.verdict, errorCode: result.errorCode, detail: result.detail });
            return result;
        })();
        memo.pending.set(key, pending);
    }
    return pending;
}

/**
 * Every verdict `buildCertificatePath` is about to ask for, and no other: the
 * search replayed ahead of the builder, each link's signature verified the
 * moment the search is about to rely on it.
 *
 * This mirrors `extend` in path-build.ts step for step — the same index by
 * encoded subject, the same candidate order, the same `maxChainLength` and
 * `maxPathsExplored` cuts, the same stop at the first path that §6 and the
 * purposes accept — because the links the builder tries are exactly the
 * signatures worth verifying. A bag of N certificates under one name then
 * costs N verifications only when all N have to be tried, where verifying
 * every name-plausible pair up front cost N² before the search began. The
 * builder itself stays synchronous and pure, as the decision layer requires;
 * the laziness lives here, where the Web Crypto door is reachable. Judged
 * with the verdicts so far, a path through a link not yet verified is
 * refused, which is why nothing here can accept a path the builder will not:
 * the builder receives the whole memo and replays the same enumeration.
 *
 * A change to the builder's enumeration is a change here too;
 * `tests/verify/verify-chain.test.ts` holds the two to the same report on
 * every shape of bag, and to a verification count no higher than the links
 * the builder tried.
 */
async function _searchVerdicts(input: SearchInput, memo: VerdictMemo): Promise<void> {
    const limits = resolveLimits(input.limits);
    const anchors = new Set(input.trustAnchors.map((c) => _hex(c.der)));
    const anchorKey = (c: Certificate): string => `${_hex(c.subject.der)}|${_hex(c.subjectPublicKeyInfo.der)}`;
    const anchorKeys = new Set(input.trustAnchors.map(anchorKey));
    const bySubject = new Map<string, Certificate[]>();
    for (const candidate of input.candidates) {
        const key = _hex(candidate.subject.der);
        bySubject.set(key, [...(bySubject.get(key) ?? []), candidate]);
    }
    for (const anchor of input.trustAnchors) {
        const key = _hex(anchor.subject.der);
        const existing = bySubject.get(key) ?? [];
        if (!existing.some((c) => bytesEqual(c.der, anchor.der))) bySubject.set(key, [...existing, anchor]);
    }

    /**
     * Whether §6 and the purposes accept this path under the verdicts so far —
     * where the builder stops. §6.1.1 (a) takes the anchor as a separate input,
     * so a chain that stops one short of its root is judged against the first
     * anchor that bears its last issuer's name, a link the walk never extends
     * into: that signature is asked for here, as the validator is about to.
     */
    const accepted = async (path: readonly Certificate[]): Promise<boolean> => {
        const last = path[path.length - 1] as Certificate;
        if (!anchorKeys.has(anchorKey(last))) {
            const wanted = _hex(last.issuer.der);
            const anchor = input.trustAnchors.find((candidate) => _hex(candidate.subject.der) === wanted);
            if (anchor !== undefined) await _verdict(memo, last, anchor);
        }
        const report = _validateIndexed({ ...input, path }, memo.index);
        if (!report.valid || input.purposes === undefined) return report.valid;
        return input.purposes.every((purpose) => [...checkExtendedKeyUsage(report.path, purpose)].length === 0);
    };

    if (await accepted([input.leaf])) return;
    let explored = 1;
    let limitHit = false;

    const extend = async (chain: readonly Certificate[], seen: ReadonlySet<string>): Promise<boolean> => {
        if (chain.length >= limits.maxChainLength) return false;
        const last = chain[chain.length - 1] as Certificate;
        if (anchors.has(_hex(last.der)) || anchorKeys.has(anchorKey(last))) return false;

        for (const issuer of bySubject.get(_hex(last.issuer.der)) ?? []) {
            const key = _hex(issuer.der);
            if (seen.has(key)) continue;
            if (explored >= limits.maxPathsExplored) { limitHit = true; return false; }
            explored += 1;

            // The one line the builder does not have: the link is about to be
            // judged, so its signature is asked for now.
            await _verdict(memo, last, issuer);
            const next = [...chain, issuer];
            if (await accepted(next)) return true;

            if (await extend(next, new Set([...seen, key]))) return true;
            if (limitHit) return false;
        }
        return false;
    };

    await extend([input.leaf], new Set([_hex(input.leaf.der)]));
}

/** What a list about a delegated CRL signer can say that stops it being believed. */
const STILL_GOOD_REFUSALS: ReadonlySet<string> = /*#__PURE__*/ new Set([
    'PKI_REASON_REVOKED',
    'PKI_REASON_INPUT_MALFORMED',
    'PKI_REASON_UNKNOWN_CRITICAL_EXTENSION',
]);

/** Everything `_crlSigner` needs to decide who was entitled to sign a list. */
interface CrlSignerContext {
    readonly input: VerifyCertificateChainInput;
    readonly path: readonly Certificate[];
    readonly at: number;
    /** Every list the caller supplied, parsed — a delegated signer may be revoked on one of them. */
    readonly lists: readonly ParsedCrl[];
    readonly reading: PkiParseOptions;
    /** The signature verdicts so far, each link once; a signer off the path adds its own links (RFC 5280 §6.3.3 (f)). */
    readonly verdicts: VerdictMemo;
}

/** The `keyIdentifier` a list names in its own `authorityKeyIdentifier`, if any. */
function _namedKeyIdentifier(crl: CertificateList): Uint8Array | undefined {
    for (const extension of crl.extensions) {
        if (extension.kind === 'authorityKeyIdentifier') return extension.keyIdentifier;
    }
    return undefined;
}

/**
 * Whether this certificate is the key the list says signed it.
 *
 * A CA holding several keys under one name can say which of them revokes, and
 * `authorityKeyIdentifier` on the list is where it says so (RFC 5280 §5.2.1).
 * Without this, *any* certificate carrying the CA's name and `cRLSign` will do
 * — which is exactly what makes a key rollover work, and exactly what cannot
 * tell a designated CRL signer from an undesignated sibling. NIST PKITS builds
 * `InvalidSeparateCertificateandCRLKeysTest21` on that difference.
 *
 * **Only a candidate that states its own identifier is ever refused.** The
 * comparison is against `subjectKeyIdentifier`, which is the CA's own assertion
 * of what its key is called; computing one instead would pick RFC 5280 §4.2.1.2
 * method 1 and refuse every CA that used method 2 or anything else. A candidate
 * that names no identifier is left to the signature to settle — the rule is
 * here to break a tie between siblings, not to add a second way to fail.
 */
function _designated(named: Uint8Array | undefined, candidate: Certificate): boolean {
    if (named === undefined) return true;
    const mine = getExtension(candidate, 'subjectKeyIdentifier')?.keyIdentifier;
    return mine === undefined || _hex(mine) === _hex(named);
}

/**
 * Every revocation reason RFC 5280 §5.3.1 defines, `unused` excepted.
 *
 * Bit 0 is named `unused` and means nothing, so a CA that partitions the real
 * reasons across two lists without setting it has still covered everything. A
 * completeness test that demanded it would refuse a correct pair of lists over
 * a bit whose own name says it carries no meaning.
 */
const EVERY_REASON: readonly ReasonFlag[] = [
    'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded',
    'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn', 'aACompromise',
];

function _coversEveryReason(reasons: ReadonlySet<ReasonFlag>): boolean {
    return EVERY_REASON.every((reason) => reasons.has(reason));
}

/** One parsed list, with the bytes `findRevocation` still needs to walk it. */
interface ParsedCrl {
    readonly der: Uint8Array;
    readonly crl: CertificateList;
    /** Where the caller put it in `crls` — what every reason about it names, whatever came before it. */
    readonly index: number;
}

/**
 * The delta CRL that applies to this base for this certificate, if the caller
 * supplied one (RFC 5280 §5.2.4).
 *
 * The **first** applicable delta wins rather than the newest. `_deltaApplies`
 * already bounds the pair on both sides — the base's `cRLNumber` is at least
 * the delta's `BaseCRLNumber` and below the delta's own — so two deltas that
 * both apply to one base describe overlapping windows of the same changes, and
 * a CA that publishes such a pair has published the same withdrawal twice.
 * Ordering them would spend a sort on a distinction that does not exist.
 */
async function _deltaFor(
    ctx: CrlSignerContext,
    subject: Certificate,
    base: CertificateList,
    signed: Map<number, boolean | undefined>,
): Promise<DeltaCrlInput | undefined> {
    for (const { der, crl, index } of ctx.lists) {
        if (!_deltaApplies(base, crl)) continue;
        if (_crlScopeProblem({ certificate: subject, crl, asDelta: true }) !== null) continue;
        if (!signed.has(index)) signed.set(index, await _crlSigner(ctx, crl, _hex(crl.issuer.der)));
        const signatureVerified = signed.get(index);
        return { crl, crlDer: der, ...(signatureVerified === undefined ? {} : { signatureVerified }) };
    }
    return undefined;
}

/**
 * The path against the lists and responses the caller supplied.
 *
 * **Per certificate, not per list**, which is what makes two of the answers
 * possible at all: which lists cover one certificate is a fact about that
 * certificate, and so is the §6.3.3 reason mask they add up to. A loop over
 * lists can compute neither without keeping a map on the side.
 *
 * Checked on every certificate of the path except the anchor, and **required**
 * only at the leaf. Those are two questions and collapsing them gets one of
 * them wrong: checking everywhere costs nothing and catches a revoked CA,
 * while requiring a list for every CA would refuse most real chains, because
 * the Web PKI handles intermediates out of band — CRLSets, OneCRL — which is
 * not a decision a library gets to make for its caller.
 */
async function _checkRevocation(input: VerifyCertificateChainInput, path: readonly Certificate[], at: number, verdicts: VerdictMemo): Promise<PkiReason[]> {
    const out: PkiReason[] = [];
    const lists = input.crls ?? [];
    const stapled = input.ocspResponses ?? [];
    if (lists.length === 0 && stapled.length === 0) {
        if (input.requireRevocation === true) {
            out.push(revocationUnknownReason('path[0]', 'no revocation list and no OCSP response were supplied for this certificate'));
        }
        return out;
    }

    // One options object for both readers: the limits are the caller's, and
    // what the lists and responses say about themselves goes to the caller's
    // handler when there is one — and nowhere otherwise, because a verdict call
    // reports in its report and does not warn on the console.
    const reading = { limits: input.limits ?? {}, onDiagnostic: input.onDiagnostic ?? ((): undefined => undefined) };

    // **Every certificate on the path, not only the leaf.** A revoked
    // intermediate is a revoked chain: the CA whose key signed the leaf has had
    // that key withdrawn, and a verifier that asked only about the leaf would
    // accept everything below a CA its own issuer had disowned. NIST PKITS has
    // that test — `InvalidRevokedCATest2` — and it is the shape a compromised
    // sub-CA takes in the real world.
    //
    // The anchor is not checked: it is trusted a priori, and a list it issued
    // about itself revokes nothing. Everything else is, whether or not its own
    // issuer ended up in the path — whether a list covers a certificate is
    // decided from the certificate and the list alone (§5.2.5, §6.3.3 (b)), and
    // neither of them depends on how the search happened to end.
    const anchors = new Set(input.trustAnchors.map((c) => _hex(c.der)));
    const covered = new Set<number>();

    // Parsed first, then applied — because the loop below runs **per
    // certificate**, and the reason mask of §6.3.3 is a fact about one
    // certificate and every list that covers it.
    const parsed: ParsedCrl[] = [];
    for (const [index, der] of _firstOfEach(lists)) {
        try {
            parsed.push({ der, crl: parseCertificateList(der, reading), index });
        } catch (error) {
            // **The one catch this library allows**, and the reason the reason
            // registry wraps the error registry instead of copying it: the code
            // that would have been thrown travels in `errorCode`, so a report
            // can promise never to throw for bad input without a second frozen
            // vocabulary of encoding failures.
            const refused = _pkiError(error);
            out.push(inputMalformedReason(refused.code, refused.message, `crls[${String(index)}]`));
        }
    }
    const signing: CrlSignerContext = { input, path, at, lists: parsed, reading, verdicts };
    // Whether a key entitled to sign a list did. Asked once per list rather than
    // once per certificate, because the answer is a property of the list.
    // `undefined` and `false` are different answers and `checkRevocation` words
    // them differently: never checked, versus checked and wrong.
    const signed = new Map<number, boolean | undefined>();

    for (const [position, subject] of path.entries()) {
        if (anchors.has(_hex(subject.der))) continue;
        const mine: PkiReason[] = [];
        const reasons = new Set<ReasonFlag>();
        let complete = false;
        for (const { der, crl, index } of parsed) {
            // **Selection, not judgement.** Which of the caller's lists covers
            // which certificate is decided here by the same §5.2.5 and §6.3.3
            // (b) rules `checkRevocation` applies — but a list that does not
            // cover this certificate is skipped in silence rather than
            // reported. A caller handing over every list they hold is the
            // ordinary case, and a CA that publishes one list per distribution
            // point makes it the *normal* case: reporting each non-covering
            // list would turn a correct verification into a page of reasons.
            // `checkRevocation` still reports scope for a caller who hands it
            // one list deliberately, which is the whole difference between a
            // primitive and a composition.
            //
            // **`unusable` is the exception, and it is not a detail.** A list
            // that would cover this certificate and carries a critical
            // extension nothing here understands is not "somebody else's list":
            // RFC 5280 §6.3.3 says it MUST NOT be used, and a validator that
            // silently moved on would have used nothing *and said nothing* —
            // reporting the certificate unchecked exactly as if the CA had
            // published no list at all.
            const problem = _crlScopeProblem({ certificate: subject, crl });
            if (problem !== null && problem.kind !== 'unusable') continue;
            if (problem !== null) {
                mine.push(unknownCriticalExtensionReason(`crls[${String(index)}]`, problem.oid, 'revocation list'));
                continue;
            }
            if (!signed.has(index)) signed.set(index, await _crlSigner(signing, crl, _hex(crl.issuer.der)));
            const signatureVerified = signed.get(index);
            // The delta that belongs to **this** base, for **this** certificate
            // (RFC 5280 §5.2.4). Pairing is the composition's job because only
            // it holds both lists, and `checkRevocation` owns what the pair
            // means — the caller never merges two answers, because there is
            // only ever one.
            const delta = await _deltaFor(signing, subject, crl, signed);
            const judged = _judged({
                certificate: subject,
                crl,
                crlDer: der,
                at,
                ...(signatureVerified === undefined ? {} : { signatureVerified }),
                ...(delta === undefined ? {} : { delta }),
                limits: reading.limits,
                onDiagnostic: reading.onDiagnostic,
            }, `crls[${String(index)}]`);
            // **An entry can make the list unusable as well** (RFC 5280 §5.3: a
            // critical entry extension nothing here processes, on *any* entry),
            // and only the walk inside `checkRevocation` reaches the entries.
            // Such a list then covers nothing and adds nothing to the mask, and
            // that is all that is said about it — exactly the list-level case
            // above, so the two read the same in a report.
            const unusable = judged.filter((reason) => reason.code === 'PKI_REASON_UNKNOWN_CRITICAL_EXTENSION');
            if (unusable.length > 0) {
                mine.push(...unusable);
                continue;
            }
            covered.add(position);
            // §6.3.3 (d): the list's onlySomeReasons, intersected with the
            // reasons of the certificate's own distribution point it answers.
            const only = _interimReasons({ certificate: subject, crl });
            if (only === undefined) complete = true;
            else for (const reason of only) reasons.add(reason);
            mine.push(...judged);
        }
        // §6.3.3's `reasons_mask`, which only the composition can see: a CA that
        // publishes a keyCompromise list and a second list for everything else
        // has answered completely, and each of them says so on its own. Adding
        // them up is the whole reason `PKI_REASON_REVOCATION_PARTIAL` is not
        // just a wording of `UNKNOWN`.
        out.push(...(complete || _coversEveryReason(reasons)
            ? mine.filter((reason) => reason.code !== 'PKI_REASON_REVOCATION_PARTIAL')
            : mine));
    }

    // OCSP answers about the end-entity certificate only: that is what a
    // stapled response is for, and RFC 6960 has no notion of asking about a
    // chain. The issuer is path[1], the CA whose CertID the answer binds to.
    const issuer = path[1];
    for (const [index, der] of _firstOfEach(stapled)) {
        const where = `ocspResponses[${String(index)}]`;
        try {
            const response = parseOcspResponse(der, reading);
            const basic = response.basicResponse;
            // A response that is not `successful` carries no body — the protocol
            // has nowhere to put one — so there is nothing to match against and
            // `checkOcspStatus` reports the status the responder gave.
            if (basic === undefined) {
                out.push(...checkOcspStatus({ response, expected: _certId(input.leaf, issuer, 'SHA-1'), at }).map((reason) => _rooted(reason, 'ocsp', where)));
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
                : await _ocspSigner(basic, issuer, signing);
            covered.add(0);
            out.push(...checkOcspStatus({
                response,
                expected: _certId(input.leaf, issuer, algorithm),
                at,
                onDiagnostic: reading.onDiagnostic,
                ...(authorised === undefined ? {} : { signatureVerified: authorised.signed, responderAuthorized: authorised.authorised }),
                // The one certificate that both signed and was entitled to:
                // what `responderID` must name (RFC 6960 §4.2.2.3).
                ...(authorised?.certificate === undefined ? {} : { signer: authorised.certificate }),
                ...(input.ocspNonce === undefined ? {} : { nonce: input.ocspNonce }),
                ...(input.requireOcspNonce === undefined ? {} : { requireNonce: input.requireOcspNonce }),
            }).map((reason) => _rooted(reason, 'ocsp', where)));
        } catch (error) {
            const refused = _pkiError(error);
            out.push(inputMalformedReason(refused.code, refused.message, where));
        }
    }

    // **Checked everywhere, required at the leaf.** Those are two questions and
    // collapsing them gets one of them wrong.
    //
    // Checking every certificate costs nothing and catches a revoked CA, which
    // is a chain nobody should accept. *Requiring* an answer about every
    // certificate would be a different rule and an unusable one: a stapled OCSP
    // response answers about the end entity and nothing else, nobody fetches a
    // CRL for an intermediate on the connection path, and the Web PKI handles
    // intermediates out of band — CRLSets, OneCRL — which is not a decision a
    // verifier can make per connection. So the demand stops at the certificate
    // the caller can actually obtain an answer about.
    if (input.requireRevocation === true && !covered.has(0)) {
        out.push(revocationUnknownReason('path[0]', 'nothing supplied answers about this certificate'));
    }
    return out;
}

/**
 * `checkRevocation`, with a malformed entry reported rather than thrown.
 *
 * `parseCertificateList` reads the envelope and counts the entries, but an
 * entry's fields are read only when `findRevocation` walks them — so a list
 * whose envelope is sound and whose entry is not (a single field, a matching
 * serial with an unreadable date, entry extensions that are not Extensions)
 * throws here, after the parse this composition already caught. The code that
 * would have been thrown travels in `errorCode`, as it does for a list that
 * does not parse at all. When a delta is paired with the base, the walk that
 * failed may be the delta's; the thrown message names the field either way.
 *
 * Every verdict is re-rooted at `where` too: `checkRevocation` names its one
 * input `crl`, and a report over several lists has to say which.
 */
function _judged(check: CheckRevocationInput, where: string): readonly PkiReason[] {
    try {
        return checkRevocation(check).map((reason) => _rooted(reason, 'crl', where));
    } catch (error) {
        const refused = _pkiError(error);
        return [inputMalformedReason(refused.code, refused.message, where)];
    }
}

/**
 * A reason a primitive rooted at its own single input — `crl` for
 * `checkRevocation`, `ocsp` for `checkOcspStatus` — re-rooted at the member
 * of the caller's input it is about (`crls[2]`, `ocspResponses[0]`), any
 * suffix kept. A new frozen reason: the primitive's own is frozen, and a
 * caller holding several lists needs to know which one spoke.
 */
function _rooted(reason: PkiReason, from: 'crl' | 'ocsp', to: string): PkiReason {
    // Both primitives root every reason at their input, so the prefix is always there.
    return Object.freeze({ ...reason, path: `${to}${reason.path.slice(from.length)}` });
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
 * this CA, to carry the purpose, to allow `digitalSignature` when it states a
 * keyUsage, and to be valid now, before its signature counts for anything. A
 * client that skipped those would let the responder nominate itself, which is
 * what §4.2.2.2 exists to prevent.
 *
 * And a delegate is a key the CA can withdraw. RFC 6960 §4.2.2.2.1 lets the CA
 * say how its revocation is to be checked: `id-pkix-ocsp-nocheck` means not
 * at all — the CA keeps such certificates short-lived instead — and without
 * it the delegate is judged against the caller's lists exactly as a delegated
 * CRL signer is (`_unrevokedOnLists`). A revoked responder signing `good`
 * is the case this exists for.
 */
async function _ocspSigner(
    basic: OcspBasicResponse,
    issuer: Certificate,
    ctx: CrlSignerContext,
): Promise<{ signed: boolean | undefined; authorised: boolean; certificate: Certificate | undefined }> {
    const { at, reading } = ctx;
    const allowSha1 = ctx.input.allowSha1 === true;
    const direct = await _ocspSignature(basic, issuer);
    if (direct === true) return { signed: true, authorised: true, certificate: issuer };

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
        // Valid now, and valid when it spoke: RFC 6960 §4.2.2.2 makes the
        // response's authority rest on the responder's certificate, and a
        // certificate that had expired — or had not yet begun — at `producedAt`
        // vouched for nothing at the moment the signature was made. Both
        // instants are asked, because a delegate good then and withdrawn by
        // expiry since is a key the CA no longer stands behind.
        const { notBefore, notAfter } = delegate.validity;
        const produced = basic.producedAt.epochMilliseconds;
        if (at < notBefore.epochMilliseconds || at > notAfter.epochMilliseconds) continue;
        if (produced < notBefore.epochMilliseconds || produced > notAfter.epochMilliseconds) continue;
        // The CA must actually have issued it, not merely be named by it.
        let issued: boolean;
        try {
            issued = await verifyCertificateSignature(delegate, issuer, { allowSha1 });
        } catch (error) {
            _pkiError(error);
            continue;
        }
        if (!issued) continue;
        // RFC 5280 §4.2.1.3: a key that signs anything but certificates and
        // lists asserts digitalSignature, when the certificate states usages.
        const usage = getExtension(delegate, 'keyUsage');
        if (usage !== undefined && !usage.usages.includes('digitalSignature')) continue;
        const signed = await _ocspSignature(basic, delegate);
        if (signed !== true) continue;
        // Asked last, of the one delegate that did sign: a list walk is the
        // most expensive question here, and only its answer is at stake.
        if (getExtension(delegate, 'ocspNoCheck') !== undefined || await _unrevokedOnLists(ctx, delegate)) return { signed: true, authorised: true, certificate: delegate };
    }
    // Nobody authorised signed it. `signed` carries the direct attempt's answer
    // so that "checked and wrong" stays apart from "never checked"; no
    // certificate, because none both signed and was entitled to.
    return { signed: direct, authorised: false, certificate: undefined };
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
