/**
 * pkinative — Validation reason factories
 * =======================================
 * One factory per `PkiReasonCode`, the mirror of `core/pki-diagnostics.ts`,
 * and for the same purpose: the message that reaches a caller is written
 * once, here, rather than assembled at each call site where it would drift.
 *
 * Unlike a diagnostic, a reason is never emitted, never escalated and never
 * printed. It is **returned**, inside a report the caller reads. Nothing in
 * this module touches `console`, and nothing in it throws — a module whose
 * job is to explain a "no" must not be able to produce one of its own.
 *
 * The messages do not carry the `pkinative: ` prefix. That prefix marks what
 * is thrown, `reason-parity` refuses it here, and keeping it exclusive is
 * what lets a log reader tell an exception from a verdict.
 *
 * @module core/pki-reasons
 */

import type { PkiReason, PkiReasonCode } from '../types/pki-reasons.js';

function _reason(code: PkiReasonCode, standard: string, message: string, path: string, extra?: { errorCode?: string; limit?: string }): PkiReason {
    return Object.freeze({ code, message, standard, path, errorCode: extra?.errorCode, limit: extra?.limit });
}

/**
 * The bytes are not the structure they claim to be.
 *
 * This is the one factory that reaches into the error vocabulary, and it is
 * how a non-throwing report stays honest without a second copy of 47
 * encoding codes: the `PkiErrorCode` that *would* have been thrown travels
 * in `errorCode`, so a caller who wants the detail has it, and a caller who
 * only wants a verdict is not made to catch anything.
 *
 * @param errorCode The `PkiError.code` the parser raised.
 * @param detail    The parser's own message, already specific.
 * @param path      Where in the input, e.g. `path[1]`.
 * @returns The reason.
 */
export function inputMalformedReason(errorCode: string, detail: string, path: string): PkiReason {
    return _reason('PKI_REASON_INPUT_MALFORMED', 'ITU-T X.690',
        `the input could not be read as the structure it claims to be (${errorCode}): ${detail.replace(/^pkinative: /, '')}`,
        path, { errorCode });
}

/** The validation instant is before `notBefore`. */
export function notYetValidReason(path: string, notBefore: number, at: number): PkiReason {
    return _reason('PKI_REASON_NOT_YET_VALID', 'RFC 5280 §6.1.3 (a)(2)',
        `the certificate is not valid until ${new Date(notBefore).toISOString()}, and validation was asked for ${new Date(at).toISOString()}`,
        path);
}

/** The validation instant is after `notAfter`. */
export function expiredReason(path: string, notAfter: number, at: number): PkiReason {
    return _reason('PKI_REASON_EXPIRED', 'RFC 5280 §6.1.3 (a)(2)',
        `the certificate expired on ${new Date(notAfter).toISOString()}, and validation was asked for ${new Date(at).toISOString()}`,
        path);
}

/**
 * A critical extension nothing here recognises. RFC 5280 requires refusal, not
 * tolerance.
 *
 * One code for two objects, because it is one rule: §6.1.3 (f) states it for a
 * certificate and §6.3.3 states it again for a revocation list, in the same
 * words and for the same reason — a critical marking is the issuer saying *"if
 * you do not understand this, you do not understand what this object means"*.
 * `what` only decides the noun and the section cited; a reader who wants to
 * know which object it was has `path`.
 */
export function unknownCriticalExtensionReason(path: string, oid: string, what: 'certificate' | 'revocation list' = 'certificate'): PkiReason {
    return _reason('PKI_REASON_UNKNOWN_CRITICAL_EXTENSION',
        what === 'certificate' ? 'RFC 5280 §6.1.3 (f)' : 'RFC 5280 §6.3.3',
        `the ${what} carries the critical extension ${oid}, which this implementation does not recognise; a verifier must refuse rather than ignore it`,
        path);
}

/**
 * A name falls outside what a CA above this certificate permitted.
 *
 * The message names the form and the value, because "a name is not
 * permitted" without saying which name is a report nobody can act on — and
 * the whole point of a name constraint is that one specific name is wrong.
 */
export function nameNotPermittedReason(path: string, form: string, text: string): PkiReason {
    return _reason('PKI_REASON_NAME_NOT_PERMITTED', 'RFC 5280 §6.1.3 (b)',
        `the ${form} "${text}" falls outside the permitted subtrees a CA above this certificate set; a sub-CA cannot issue for names its issuer withheld`,
        path);
}

/** A name falls inside a subtree a CA above this certificate excluded. */
export function nameExcludedReason(path: string, form: string, text: string): PkiReason {
    return _reason('PKI_REASON_NAME_EXCLUDED', 'RFC 5280 §6.1.3 (c)',
        `the ${form} "${text}" falls inside an excluded subtree; an exclusion anywhere on the path wins over every permission`,
        path);
}

/**
 * The certificate is listed in a revocation list that covers it and is
 * authenticated, or an authorised OCSP responder's verified answer says so —
 * never on the say-so of an unverified list, a response nobody authorised, or
 * another CA's list (RFC 5280 §6.3.3, RFC 6960 §3.2).
 *
 * The date is in the message because "revoked" without one is unanswerable: a
 * signature made before the revocation instant may still be good, and a caller
 * deciding that needs the date to decide it with.
 */
export function revokedReason(path: string, at: number, reason: string | undefined): PkiReason {
    const why = reason === undefined ? 'no reason given' : `reason: ${reason}`;
    return _reason('PKI_REASON_REVOKED', 'RFC 5280 §5.1',
        `the certificate was revoked on ${new Date(at).toISOString()} (${why}); a signature made before that instant may still be good, which is why the date is here`,
        path);
}

/**
 * The revocation list is not current enough to answer with.
 *
 * Reported rather than ignored: an out-of-date list says what was revoked
 * *then*, and treating it as current is how a certificate revoked yesterday is
 * accepted today.
 */
export function revocationStaleReason(path: string, nextUpdate: number | undefined, at: number): PkiReason {
    const when = nextUpdate === undefined
        ? 'the list declares no nextUpdate, so nothing says it is still current'
        : `the list expected a successor by ${new Date(nextUpdate).toISOString()}`;
    return _reason('PKI_REASON_REVOCATION_STALE', 'RFC 5280 §5.1.2.5',
        `${when}, and the question was asked for ${new Date(at).toISOString()}`,
        path);
}

/** The revocation list was not issued by the certificate's issuer. */
export function revocationWrongIssuerReason(path: string): PkiReason {
    return _reason('PKI_REASON_REVOCATION_WRONG_ISSUER', 'RFC 5280 §6.3.3',
        'the revocation list names a different issuer from the certificate, compared by encoded name; a list from another CA says nothing about this certificate',
        path);
}

/**
 * The list is from the right CA, and says it is not about this certificate.
 *
 * Its own code rather than a flavour of `WRONG_ISSUER`, because the two point
 * at different mistakes and at different fixes. A wrong issuer means the caller
 * fetched somebody else's list. Out of scope means they fetched *a* list of the
 * right CA's — the CA publishes several, marked by `issuingDistributionPoint`,
 * and this one covers other certificates. The fix is another fetch from the
 * point the certificate names, and a report that could not tell the two apart
 * would send the caller back to the wrong CA.
 *
 * It exists at all because the alternative is silence. A list that does not
 * cover a certificate does not list it either, so treating scope as a detail
 * turns "I am not about this certificate" into "this certificate is not
 * revoked" — the one misreading of a CRL that a compromised sub-CA survives.
 */
export function revocationOutOfScopeReason(path: string, why: string): PkiReason {
    return _reason('PKI_REASON_REVOCATION_OUT_OF_SCOPE', 'RFC 5280 §5.2.5',
        `the revocation list does not cover this certificate: ${why}. It was issued by the right CA, so the absence of the serial from it proves nothing`,
        path);
}

/**
 * The list covers only some revocation reasons, so its silence rules out only
 * those.
 *
 * Its own code rather than a flavour of `UNKNOWN`, for a reason that only shows
 * up one layer above: **partial answers add up**. A CA that publishes a
 * keyCompromise list it can reissue in minutes and a second list for everything
 * else has, between the two, answered completely — RFC 5280 §6.3.3 calls that
 * accumulation `reasons_mask`, and no single list can see it. So each list says
 * what it ruled out, in a code the composition can recognise and combine, and
 * `verifyCertificateChain` drops these once the union is complete.
 *
 * A caller consulting one list with `checkRevocation` gets to see it too, which
 * is the honest answer to "is it revoked?" from a list that only knows about
 * two of the nine ways it could be.
 */
export function revocationPartialReason(path: string, covered: readonly string[]): PkiReason {
    return _reason('PKI_REASON_REVOCATION_PARTIAL', 'RFC 5280 §5.2.5',
        `the list declares onlySomeReasons (${covered.join(', ') || 'none'}), so the serial's absence from it rules out only those reasons; another list covering the rest would complete the answer`,
        path);
}

/**
 * Revocation could not be established.
 *
 * Distinct from "not revoked" on purpose. A missing or unverified list is an
 * absence of evidence, and a caller choosing to proceed anyway — soft-fail —
 * should be choosing it, rather than having it chosen for them by a validator
 * that reported silence as a clean bill of health.
 */
export function revocationUnknownReason(path: string, why: string): PkiReason {
    return _reason('PKI_REASON_REVOCATION_UNKNOWN', 'RFC 5280 §6.3',
        `revocation status could not be established: ${why}. This is not "not revoked" — it is an absence of evidence, and proceeding on it is a decision to make deliberately`,
        path);
}

/**
 * The revocation answer is about a different certificate, or does not echo the
 * nonce that was sent.
 *
 * Its own code rather than a flavour of `UNKNOWN`, because the two call for
 * different actions. `UNKNOWN` means "ask again"; a mismatch means **this
 * answer is not yours** — a responder that got confused, a cache serving
 * somebody else's response, or an attacker substituting one. Retrying a
 * mismatch against the same responder is the wrong move, and a caller that
 * could not tell the two apart would do it.
 */
export function revocationMismatchReason(path: string, what: string): PkiReason {
    return _reason('PKI_REASON_REVOCATION_MISMATCH', 'RFC 6960 §3.2',
        `the revocation answer does not belong to this question: ${what}. Retrying will not help — this response was not produced for this certificate`,
        path);
}

/**
 * No certificate policy survives the path, and an explicit policy was
 * required — the only condition under which policy processing rejects a path.
 *
 * A tree that came out empty while nobody asked for an explicit policy is
 * **not** a failure: it means the question was never asked, and §6.1.5 (a)
 * leaves such a path valid.
 */
export function noValidPolicyReason(path: string): PkiReason {
    return _reason('PKI_REASON_NO_VALID_POLICY', 'RFC 5280 §6.1.5 (g)',
        'no certificate policy survives the whole path, and an explicit policy was required by a CA in it or by the caller',
        path);
}

/** A `policyMappings` extension maps to or from `anyPolicy`, which RFC 5280 forbids. */
export function policyMappingInvalidReason(path: string, issuerDomainPolicy: string, subjectDomainPolicy: string): PkiReason {
    return _reason('PKI_REASON_POLICY_MAPPING_INVALID', 'RFC 5280 §6.1.4 (a)',
        `the policy mapping ${issuerDomainPolicy} → ${subjectDomainPolicy} names anyPolicy, which may be neither an issuerDomainPolicy nor a subjectDomainPolicy; the mapping was ignored rather than honoured`,
        path);
}

/**
 * No name in the certificate matches the host or address the caller asked
 * about (RFC 6125).
 *
 * The message names **both** what was asked for and what the certificate
 * actually names, because the two together are what tells a reader whether
 * they have the wrong certificate, the wrong host, or a misissued SAN — and a
 * bare "name mismatch" tells them none of it.
 */
export function nameMismatchReason(path: string, wanted: string, found: string): PkiReason {
    return _reason('PKI_REASON_NAME_MISMATCH', 'RFC 6125 §6',
        `the certificate does not name ${wanted}: ${found}. A chain that verifies still says nothing about which host the certificate is for`,
        path);
}

/**
 * A certificate on the path does not permit the purpose the caller needs
 * (RFC 5280 §4.2.1.12).
 *
 * `permitted` is `null` when the certificate carries no `extKeyUsage` at all
 * and the caller asked for the purpose to be explicit: *"absent"* and *"present
 * and naming something else"* are different facts about a certificate, and a
 * reader deciding whether to ask the CA for a reissue needs to know which.
 */
export function purposeNotPermittedReason(
    path: string,
    purpose: string,
    permitted: readonly string[] | null,
    rule?: 'critical' | 'exclusive',
): PkiReason {
    const listed = (permitted ?? []).join(', ') || 'none';
    // RFC 3161 §2.3 is the one profile that asks more of extKeyUsage than that
    // it name the purpose: a TSA's must be critical and name timestamping
    // alone. It is the same fact — this certificate may not be used for this —
    // so it is the same code, with the sentence that says which rule it broke.
    if (rule === 'critical') {
        return _reason('PKI_REASON_PURPOSE_NOT_PERMITTED', 'RFC 3161 §2.3',
            `the certificate names ${purpose}, but its extKeyUsage is not critical, and a timestamp authority's must be — a non-critical purpose is one any relying party may ignore`,
            path);
    }
    if (rule === 'exclusive') {
        return _reason('PKI_REASON_PURPOSE_NOT_PERMITTED', 'RFC 3161 §2.3',
            `the certificate names ${purpose} among other purposes (${listed}), and a timestamp authority's certificate must name it alone`,
            path);
    }
    return _reason('PKI_REASON_PURPOSE_NOT_PERMITTED', 'RFC 5280 §4.2.1.12',
        permitted === null
            ? `the certificate carries no extKeyUsage, so it names no purpose, and ${purpose} was required to be named explicitly`
            : `the purpose ${purpose} is not among the ones this certificate permits (${listed}); a certificate carrying extKeyUsage must only be used for a purpose it names`,
        path);
}

// ── Signed messages (RFC 5652) ────────────────────────────────────────

/**
 * The SignedData has no signer.
 *
 * RFC 5652 §5.1 allows it — it is how `.p7b` certificate bundles are shipped —
 * and parsing one is ordinary. Verifying one proves nothing, and it has its
 * own code because the failure it guards against is silent: `[].every(valid)`
 * is `true`, so a verifier that looped over the signers would call a bundle of
 * certificates a valid signature.
 */
export function cmsNoSignersReason(path: string): PkiReason {
    return _reason('PKI_REASON_CMS_NO_SIGNERS', 'RFC 5652 §5.1',
        'the SignedData has no signer, so it signs nothing; a certificate bundle is read this way, and verifying one proves nothing about any content',
        path);
}

/** No available certificate matches the signer's identifier. */
export function cmsSignerNotFoundReason(path: string, identifier: string): PkiReason {
    return _reason('PKI_REASON_CMS_SIGNER_NOT_FOUND', 'RFC 5652 §5.3',
        `no certificate in the message or among those supplied matches the signer identifier (${identifier}); supply the signer's certificate, since without it there is no key to check the signature with`,
        path);
}

/**
 * The content is detached and was not supplied.
 *
 * Absent content is never empty content. A verifier that hashed zero bytes in
 * its place would check the signature against something the signer never
 * signed — and, worse, would pass a signature made over the empty string.
 */
export function cmsContentMissingReason(path: string): PkiReason {
    return _reason('PKI_REASON_CMS_CONTENT_MISSING', 'RFC 5652 §5.2',
        'the content is detached and was not supplied; pass the signed content, or its digest when the signer used signed attributes — absent content is not empty content',
        path);
}

/**
 * The content does not hash to what the signer committed to.
 *
 * This is the integrity failure itself: the signature may well verify, over
 * signed attributes that faithfully record the digest of **some other**
 * content. RFC 5652 §5.6 forbids trusting the signer's digest for that reason
 * — the recipient computes its own and compares.
 */
export function cmsDigestMismatchReason(path: string): PkiReason {
    return _reason('PKI_REASON_CMS_DIGEST_MISMATCH', 'RFC 5652 §11.2',
        'the content does not hash to the digest the signer committed to in its messageDigest attribute; the content was altered, or this is not the content that was signed',
        path);
}

/** A signed attribute the syntax requires is missing, repeated, multi-valued, misplaced or wrong. */
export function cmsAttributeInvalidReason(path: string, why: string): PkiReason {
    return _reason('PKI_REASON_CMS_ATTRIBUTE_INVALID', 'RFC 5652 §11',
        `${why}; the signed attributes are what bind a signature to a content and a content type, and one that breaks these rules binds nothing reliably`,
        path);
}

/**
 * The signer's algorithms disagree, or one is refused.
 *
 * A SignerInfo names its digest up to three times — `digestAlgorithm`, the
 * digest built into `signatureAlgorithm`, and the `CMSAlgorithmProtection`
 * attribute — and only the last is signed. Letting them disagree is how an
 * algorithm-substitution attack works (RFC 6211 §1): the verifier is steered
 * into checking the signature under a weaker algorithm than the signer chose.
 */
export function cmsAlgorithmMismatchReason(path: string, why: string): PkiReason {
    return _reason('PKI_REASON_CMS_ALGORITHM_MISMATCH', 'RFC 6211 §3',
        `${why}; a signer's algorithms must name one digest and one signature scheme, and disagreement between them is how an algorithm-substitution attack steers a verifier`,
        path);
}

/**
 * The signing-certificate attribute names another certificate.
 *
 * `ESSCertID` and `ESSCertIDv2` exist because a key can have more than one
 * certificate: a rollover, a cross-signature, a misissued second one. Without
 * the binding, a signature can be presented under whichever of them suits the
 * presenter; with it, only the one the signer committed to counts.
 */
export function cmsSigningCertificateMismatchReason(path: string, why: string): PkiReason {
    return _reason('PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH', 'RFC 5035 §3',
        `${why}; the signer committed to one specific certificate, and a signature presented under any other certificate for the same key is being re-attributed`,
        path);
}

// ── Timestamps (RFC 3161) ─────────────────────────────────────────────

/** The TSA declined; the response carries no token. */
export function tspNotGrantedReason(path: string, status: string, statusStrings: readonly string[], failInfo: readonly string[]): PkiReason {
    const said = statusStrings.length === 0 ? '' : ` It said: "${statusStrings.join(' / ')}".`;
    const why = failInfo.length === 0 ? '' : ` Failure: ${failInfo.join(', ')}.`;
    return _reason('PKI_REASON_TSP_NOT_GRANTED', 'RFC 3161 §2.4.2',
        `the timestamp authority answered ${status} and issued no token.${said}${why}`,
        path);
}

/** The token breaks a rule RFC 3161 sets for tokens. */
export function tspTokenInvalidReason(path: string, why: string): PkiReason {
    return _reason('PKI_REASON_TSP_TOKEN_INVALID', 'RFC 3161 §2.4.2',
        `${why}; a timestamp token is a narrower thing than a SignedData, and one that breaks its rules is not evidence of a time`,
        path);
}

/**
 * The token stamps another hash.
 *
 * A token proves that **a hash** existed at a time. Whether it is the hash of
 * your data is the one thing it cannot tell you on its own, which is why every
 * timestamp check starts from the caller's imprint and never from the token's.
 */
export function tspImprintMismatchReason(path: string): PkiReason {
    return _reason('PKI_REASON_TSP_IMPRINT_MISMATCH', 'RFC 3161 §2.4.2',
        'the token stamps a different hash from the one expected; it may be a perfectly good timestamp, of something else',
        path);
}

/**
 * A key or a bag of certificates is encrypted with a scheme pkinative refuses.
 *
 * The policy of `PKI_KEY_ENCRYPTION_UNSUPPORTED`, reported instead of thrown:
 * the rest of the container may still be read. `byRuntime` is the other
 * cause, and a different remedy: a PBES2 scheme pkinative opens, whose cipher
 * or PRF this host's Web Crypto does not implement — AES-192 on several
 * browsers.
 */
export function pkcs12EncryptionUnsupportedReason(path: string, scheme: string, byRuntime = false): PkiReason {
    return _reason('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED', 'RFC 8018 §6.2', byRuntime
        ? `encrypted with ${scheme}, which pkinative opens and this runtime's Web Crypto does not implement; try another runtime before concluding the file is at fault`
        : `encrypted with ${scheme}, which pkinative does not open: only PBES2 with PBKDF2 and AES-CBC is, because the PKCS#12 schemes derive their key with RFC 7292 Appendix B`,
        path);
}

/**
 * The container's integrity could not be checked.
 *
 * Returned whenever the MAC is not RFC 9579 PBMAC1 — which is most files
 * written before OpenSSL 3.4 — and when there is no MAC at all, unless the
 * caller said with `allowUnverifiedIntegrity` that they accept that.
 */
export function pkcs12IntegrityUnverifiedReason(path: string, why: 'pkcs12-kdf' | 'absent' | 'public-key' | 'pbmac1-unsupported'): PkiReason {
    const detail = why === 'absent'
        ? 'the container carries no MAC, so nothing vouches that its contents are what was written'
        : why === 'public-key'
            ? 'the container uses public-key integrity mode, which pkinative does not verify'
            : why === 'pbmac1-unsupported'
                ? 'its RFC 9579 PBMAC1 MAC uses a key derivation or an HMAC that Web Crypto does not run, so it cannot be checked here'
                : 'its MAC is keyed with the RFC 7292 Appendix B KDF, which pkinative does not implement; only an RFC 9579 PBMAC1 MAC can be checked';
    return _reason('PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED', 'RFC 9579 §3', detail, path);
}

/** The RFC 9579 MAC does not match. */
export function pkcs12MacMismatchReason(path: string): PkiReason {
    return _reason('PKI_REASON_PKCS12_MAC_MISMATCH', 'RFC 9579 §3',
        'the MAC does not match: the password is wrong, or the container was altered after it was written',
        path);
}

/** A key or a bag of certificates would not decrypt. */
export function pkcs12DecryptionFailedReason(path: string): PkiReason {
    return _reason('PKI_REASON_PKCS12_DECRYPTION_FAILED', 'RFC 8018 §6.2',
        'it would not decrypt under the password: the password is wrong, or the data was altered — AES-CBC cannot tell the two apart',
        path);
}

/**
 * A key shares its `localKeyId` with no certificate.
 *
 * An encrypted key is unwrapped straight into a `CryptoKey`, so its algorithm
 * must be known before it is decrypted; pkinative takes it from the certificate
 * the key belongs to, and here there is none.
 */
export function pkcs12KeyUnmatchedReason(path: string): PkiReason {
    return _reason('PKI_REASON_PKCS12_KEY_UNMATCHED', 'RFC 7292 §4.2',
        'no certificate in the container shares this key\'s localKeyId, so its algorithm is unknown until it is decrypted, and pkinative never decrypts a key into the clear',
        path);
}

/** A key of a kind this runtime or pkinative cannot import. */
export function pkcs12KeyUnsupportedReason(path: string, detail: string): PkiReason {
    return _reason('PKI_REASON_PKCS12_KEY_UNSUPPORTED', 'W3C WebCryptoAPI', detail, path);
}

/**
 * An RSA key whose scheme nobody named.
 *
 * A certificate with an `rsaEncryption` key does not say whether the key signs
 * with PKCS#1 v1.5 or PSS, nor with which hash, and a Web Crypto key is bound
 * to one scheme and one hash when it is unwrapped. pkinative does not guess:
 * the caller says, in `rsaAlgorithm`, and the key is opened on the next call.
 */
export function pkcs12RsaSchemeUnspecifiedReason(path: string): PkiReason {
    return _reason('PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED', 'RFC 8017 §8',
        'the key is RSA, and its certificate does not say whether it signs with PKCS#1 v1.5 or PSS, nor with which hash; name it in options.rsaAlgorithm — { name: \'RSASSA-PKCS1-v1_5\', hash: \'SHA-256\' } for nearly every certificate in use',
        path);
}

/**
 * The token does not answer the request that was sent.
 *
 * Its own code rather than a flavour of `IMPRINT_MISMATCH`, for the reason
 * `REVOCATION_MISMATCH` is its own: a nonce that does not come back is a
 * replayed or substituted response, and retrying the same TSA is the wrong
 * reaction to that.
 */
export function tspRequestMismatchReason(path: string, what: string): PkiReason {
    return _reason('PKI_REASON_TSP_REQUEST_MISMATCH', 'RFC 3161 §2.4.2',
        `the token does not answer the request that was sent: ${what}. A response that fails to echo its request may be replayed or substituted`,
        path);
}

/** No supplied candidate has a subject equal to this certificate's issuer. */
export function issuerNotFoundReason(path: string, issuer: string): PkiReason {
    return _reason('PKI_REASON_ISSUER_NOT_FOUND', 'RFC 5280 §6.1',
        `no supplied certificate has the subject ${issuer}, so this certificate has no issuer to check it against`,
        path);
}

/** The issuer's key does not verify this signature. A verdict, not an incident. */
export function signatureInvalidReason(path: string): PkiReason {
    return _reason('PKI_REASON_SIGNATURE_INVALID', 'RFC 5280 §6.1.3 (a)(1)',
        'the issuer\'s public key does not verify this certificate\'s signature',
        path);
}

/**
 * The signature could not be checked at all.
 *
 * Never a verdict about the certificate: a runtime without Web Crypto, or
 * one that refuses Ed448, says nothing about whether the signature is good.
 * Reporting it as `PKI_REASON_SIGNATURE_INVALID` would turn "ask me
 * elsewhere" into "this certificate is bad", which is the single most
 * expensive confusion in this whole vocabulary.
 */
export function signatureNotCheckedReason(path: string, errorCode: string, detail: string): PkiReason {
    return _reason('PKI_REASON_SIGNATURE_NOT_CHECKED', 'RFC 5280 §6.1.3 (a)(1)',
        `the signature could not be checked here (${errorCode}): ${detail.replace(/^pkinative: /, '')} — this says nothing about whether the signature is valid`,
        path, { errorCode });
}

/** The chain does not end at a trust anchor the caller supplied. */
export function noTrustAnchorReason(path: string): PkiReason {
    return _reason('PKI_REASON_NO_TRUST_ANCHOR', 'RFC 5280 §6.1.1 (d)',
        'the chain does not end at any of the trust anchors supplied; a signature that verifies is not a certificate that is trusted',
        path);
}

/** An issuing certificate is not allowed to issue. */
export function notACaReason(path: string, why: 'basicConstraints' | 'keyUsage' | 'version'): PkiReason {
    return _reason('PKI_REASON_NOT_A_CA', 'RFC 5280 §6.1.4 (k)',
        why === 'basicConstraints'
            ? 'a certificate in the chain issued another without asserting cA in basicConstraints'
            : why === 'keyUsage'
                ? 'a certificate in the chain issued another without asserting keyCertSign in keyUsage'
                : 'a version 1 or 2 certificate in the chain issued another; only a version 3 intermediate can assert cA',
        path);
}

/** A `pathLenConstraint`, or the caller's own bound, is exceeded. */
export function pathTooLongReason(path: string, allowed: number): PkiReason {
    return _reason('PKI_REASON_PATH_TOO_LONG', 'RFC 5280 §6.1.4 (l)',
        `the chain is longer than the ${String(allowed)} intermediate certificate(s) a pathLenConstraint in it allows`,
        path);
}

/** The same certificate appears twice. */
export function pathLoopsReason(path: string): PkiReason {
    return _reason('PKI_REASON_PATH_LOOPS', 'RFC 5280 §6.1',
        'the same certificate appears twice in the chain; a path that revisits a certificate is not a path',
        path);
}

/**
 * A named limit stopped the search.
 *
 * Reported rather than thrown, because reaching a bound while judging a
 * chain is an answer about that chain — "I will not spend more than this on
 * you" — and a caller who raised the bound deliberately gets to see which
 * one they would have to raise again.
 */
export function limitExceededReason(path: string, limit: string, configured: number): PkiReason {
    return _reason('PKI_REASON_LIMIT_EXCEEDED', 'CWE-400',
        `validation stopped at the ${limit} limit of ${String(configured)}; raise it only for input you trust`,
        path, { limit });
}
