# Use cases

> **The jobs pkinative does today, with the code that does them and the guarantee behind each.** Four need no signature at all; the rest check and write signatures, validate chains, ask about revocation, sign, verify and timestamp CMS messages, and open the PKCS#8 keys and PKCS#12 files that sign them.

A reading library is not half a PKI library. Most of what breaks in production PKI breaks before anyone reaches a signature: a certificate expired and nobody was watching, a parser accepted bytes it should have refused, a pinned key was pinned to the wrong thing. Those are the first four cases below.

<svg viewBox="0 0 960 200" role="img" aria-labelledby="decision-title decision-desc" class="guide-figure">
  <title id="decision-title">The decision path: bytes enter, and one of three things leaves</title>
  <desc id="decision-desc">Untrusted bytes reach decodeAsn1, which either throws a PkiEncodingError with a stable code or produces a value tree. The tree reaches parseCertificate, which either throws a PkiCertificateError or produces a certificate together with any diagnostics. Every refusal carries a code; nothing is ever half-accepted.</desc>
  <defs>
    <marker id="uc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0 0L10 5L0 10z" fill="var(--c-text-muted)"/>
    </marker>
  </defs>
  <g font-family="ui-monospace, SFMono-Regular, Consolas, monospace" font-size="13" text-anchor="middle">
    <rect x="8" y="72" width="126" height="46" rx="8" fill="var(--c-surface)" stroke="var(--c-border)"/>
    <text x="71" y="91" fill="var(--c-text)" font-family="inherit">untrusted</text>
    <text x="71" y="107" fill="var(--c-text-dim)" font-family="inherit">bytes</text>

    <rect x="192" y="72" width="150" height="46" rx="8" fill="var(--c-bg-card)" stroke="var(--c-primary)" stroke-width="1.5"/>
    <text x="267" y="99" fill="var(--c-primary)">decodeAsn1</text>

    <rect x="400" y="72" width="150" height="46" rx="8" fill="var(--c-bg-card)" stroke="var(--c-primary)" stroke-width="1.5"/>
    <text x="475" y="99" fill="var(--c-primary)">parseCertificate</text>

    <rect x="616" y="62" width="176" height="30" rx="8" fill="var(--c-bg-card)" stroke="var(--c-success)" stroke-width="1.5"/>
    <text x="704" y="82" fill="var(--c-text)">Certificate</text>
    <rect x="616" y="100" width="176" height="30" rx="8" fill="var(--c-surface)" stroke="var(--c-border)"/>
    <text x="704" y="120" fill="var(--c-text-dim)">+ diagnostics</text>

    <rect x="236" y="8" width="380" height="30" rx="8" fill="var(--c-surface)" stroke="var(--c-border)" stroke-dasharray="4 3"/>
    <text x="426" y="28" fill="var(--c-text-muted)">throw PkiEncodingError · PkiLimitError</text>
    <rect x="236" y="158" width="380" height="30" rx="8" fill="var(--c-surface)" stroke="var(--c-border)" stroke-dasharray="4 3"/>
    <text x="426" y="178" fill="var(--c-text-muted)">throw PkiCertificateError</text>
  </g>
  <g fill="none" stroke="var(--c-text-muted)" marker-end="url(#uc-arrow)">
    <path d="M134 95H186"/>
    <path d="M342 95H394"/>
    <path d="M550 87H610"/>
    <path d="M550 103V115H610"/>
    <path d="M267 72V38" stroke-dasharray="4 3"/>
    <path d="M475 118V152" stroke-dasharray="4 3"/>
  </g>
</svg>

Three exits, never a fourth. The decoder is iterative, so depth is a limit and not a stack overflow; every refusal carries a `code` you branch on and a message that names the remedy. What a refusal never is, is silence.

## Inventory a certificate estate

The job: read every certificate an organisation has on disk, and report what expires when. It needs no network, no signature and no trust store — only correct parsing of every field, including the ones that are usually skipped.

```ts
import { decodePem, formatDistinguishedName, getExtension, parseCertificate } from 'pkinative';

const DAY = 86_400_000;

export function expiring(bundle: string, within: number): string[] {
    const soon: string[] = [];
    for (const block of decodePem(bundle, { label: 'CERTIFICATE' })) {
        const cert = parseCertificate(block.bytes, { onDiagnostic: () => undefined });
        const days = Math.floor((cert.validity.notAfter.epochMilliseconds - Date.now()) / DAY);
        if (days > within) continue;
        const names = getExtension(cert, 'subjectAltName')?.names ?? [];
        soon.push(`${String(days)}d  ${formatDistinguishedName(cert.subject)}  ${names.length} SAN`);
    }
    return soon;
}
```

What makes this pkinative's job rather than `openssl x509`'s: a bundle is one string, a malformed block in the middle is a typed refusal rather than a partially-written report, and the result is data — not text you then have to parse back. `decodePem` with a `label` also refuses a private key hidden in the bundle, which is how a key ends up in a log.

The distinguished name is rendered by [RFC 4514](https://datatracker.ietf.org/doc/html/rfc4514), the one rendering two tools can compare. Times are `epochMilliseconds`, so there is no locale and no time zone to disagree about.

## Ingest hostile bytes

The job: accept certificates from somewhere you do not control — an upload form, a queue, a peer — and never crash, never hang, never read past the buffer.

```ts
import { DEFAULT_PKI_LIMITS, parseCertificate, PkiError, PkiLimitError } from 'pkinative';

export function ingest(der: Uint8Array): { ok: true; subject: string } | { ok: false; code: string } {
    try {
        // Every limit not named here keeps its DEFAULT_PKI_LIMITS value.
        const cert = parseCertificate(der, { limits: { maxInputBytes: 64 * 1024, maxExtensions: 32 } });
        return { ok: true, subject: cert.subject.der.length.toString() };
    } catch (error) {
        if (error instanceof PkiLimitError) return { ok: false, code: `${error.code}:${error.limit}` };
        if (error instanceof PkiError) return { ok: false, code: error.code };
        throw error;
    }
}
```

Every loop over input bytes consults a named, CWE-tagged bound from [`src/core/pki-limits.ts`](../../src/core/pki-limits.ts), and the caller can tighten any of them for its own context. `DEFAULT_PKI_LIMITS` is what you get when you name nothing.

Branch on `error.code`, never on the message: the codes are a registry ([docs/data/errors.json](../data/errors.json)), each one recording when it is raised, its remedy, the clause it comes from and its CWE. Messages are prose and may be reworded; codes are the contract. The [errors guide](errors.md) is the full list.

`PkiLimitError` additionally carries `limit`, `configured` and `observed`, so a rejection tells an operator which bound to raise and by how much — rather than leaving them to guess.

## Pin a public key, not a certificate

The job: remember that this peer is this peer, across a certificate renewal. Pinning the whole certificate breaks every ninety days; pinning the subject public key does not, because a renewal normally keeps the key.

```ts
import { computeFingerprint, formatFingerprint, parseCertificate } from 'pkinative';

/** The SHA-256 of the SubjectPublicKeyInfo — what HPKP and Certificate Transparency pin. */
export function keyPin(der: Uint8Array): string {
    const cert = parseCertificate(der, { onDiagnostic: () => undefined });
    return formatFingerprint(computeFingerprint(cert.subjectPublicKeyInfo.der, 'SHA-256'), { separator: '', letterCase: 'lower' });
}
```

The detail that decides whether a pin is right: **what exactly you hash.** Hashing the certificate pins the certificate. Hashing the public key *bits* pins something two different algorithms could collide on. The thing to hash is the full `SubjectPublicKeyInfo` — algorithm identifier and key together — and pkinative hands it to you as `der`, a zero-copy view of the original input rather than a re-encoding, so the bytes you hash are the bytes that arrived.

<svg viewBox="0 0 960 250" role="img" aria-labelledby="anatomy-title anatomy-desc" class="guide-figure">
  <title id="anatomy-title">What a parsed certificate gives you, and which slice each use case hashes</title>
  <desc id="anatomy-desc">A Certificate value exposes tbsDer and signatureValue at the top level. Inside tbsCertificate sit the serial number, issuer, validity, subject, subjectPublicKeyInfo and extensions. Key pinning hashes subjectPublicKeyInfo.der; a fingerprint hashes the whole certificate DER; verifyCertificateSignature checks signatureValue over tbsDer with the issuer key.</desc>
  <g font-family="ui-monospace, SFMono-Regular, Consolas, monospace" font-size="12.5">
    <rect x="8" y="8" width="944" height="234" rx="10" fill="none" stroke="var(--c-border)"/>
    <text x="24" y="32" fill="var(--c-text-dim)" font-size="12">Certificate</text>

    <rect x="24" y="44" width="620" height="146" rx="8" fill="var(--c-surface)" stroke="var(--c-border)"/>
    <text x="40" y="65" fill="var(--c-text-dim)" font-size="12">tbsCertificate — the signed bytes, exposed whole as tbsDer</text>

    <rect x="40" y="78" width="132" height="34" rx="6" fill="var(--c-bg-card)" stroke="var(--c-border)"/>
    <text x="106" y="99" fill="var(--c-text)" text-anchor="middle">serialNumber</text>
    <rect x="184" y="78" width="132" height="34" rx="6" fill="var(--c-bg-card)" stroke="var(--c-border)"/>
    <text x="250" y="99" fill="var(--c-text)" text-anchor="middle">issuer</text>
    <rect x="328" y="78" width="132" height="34" rx="6" fill="var(--c-bg-card)" stroke="var(--c-border)"/>
    <text x="394" y="99" fill="var(--c-text)" text-anchor="middle">validity</text>
    <rect x="472" y="78" width="132" height="34" rx="6" fill="var(--c-bg-card)" stroke="var(--c-border)"/>
    <text x="538" y="99" fill="var(--c-text)" text-anchor="middle">subject</text>

    <rect x="40" y="124" width="264" height="50" rx="6" fill="var(--c-bg-card)" stroke="var(--c-primary)" stroke-width="1.5"/>
    <text x="172" y="145" fill="var(--c-primary)" text-anchor="middle">subjectPublicKeyInfo</text>
    <text x="172" y="163" fill="var(--c-text-dim)" text-anchor="middle" font-size="11.5">.der — what a key pin hashes</text>

    <rect x="316" y="124" width="288" height="50" rx="6" fill="var(--c-bg-card)" stroke="var(--c-border)"/>
    <text x="460" y="145" fill="var(--c-text)" text-anchor="middle">extensions</text>
    <text x="460" y="163" fill="var(--c-text-dim)" text-anchor="middle" font-size="11.5">eighteen decoded kinds, or raw</text>

    <rect x="664" y="44" width="272" height="60" rx="8" fill="var(--c-surface)" stroke="var(--c-border)"/>
    <text x="800" y="70" fill="var(--c-text)" text-anchor="middle">signatureAlgorithm</text>
    <text x="800" y="90" fill="var(--c-text)" text-anchor="middle">signatureValue</text>

    <rect x="664" y="116" width="272" height="58" rx="8" fill="none" stroke="var(--c-text-muted)" stroke-dasharray="4 3"/>
    <text x="800" y="140" fill="var(--c-text-muted)" text-anchor="middle" font-size="11.5">tbsDer + signatureValue</text>
    <text x="800" y="158" fill="var(--c-text-muted)" text-anchor="middle" font-size="11.5">verifyCertificateSignature checks</text>

    <line x1="24" y1="206" x2="936" y2="206" stroke="var(--c-border)"/>
    <text x="24" y="228" fill="var(--c-text-dim)" font-size="11.5">Every slice is a zero-copy view of the input: the bytes you hash are the bytes that arrived.</text>
  </g>
</svg>

## Gate a DER round trip

The job: prove that a tool in your pipeline did not quietly rewrite a certificate. Re-encoding a decoded value and comparing it to the input is a total check — every octet, including the ones nothing in your code reads.

```ts
import { decodeAsn1, encodeAsn1Node } from 'pkinative';

/** True when `der` is canonical DER that survives a decode and re-encode unchanged. */
export function roundTrips(der: Uint8Array): boolean {
    const again = encodeAsn1Node(decodeAsn1(der));
    return again.length === der.length && again.every((b, i) => b === der[i]);
}
```

This is the check conformance level L2 runs over all 30 361 unique x509-limbo certificates on every release, so it is not a suggestion — it is a property the library is held to. A certificate that fails it was not canonical DER to begin with, which is itself the finding.

Strict DER is the default, and that is what makes the check meaningful: a non-minimal length, a constructed string, an indefinite length or a `BOOLEAN` that is not `0x00` or `0xFF` is refused rather than normalised. BER is available with `{ encodingRules: 'ber' }` when you must read what another tool wrote, and the differences it tolerated are reported as diagnostics rather than hidden.

## Check one link of a chain

The job: confirm that the key in one certificate really signed another. It is one link, and the honest name for it is a link — not a chain.

```ts
import { canVerify, parseCertificate, PkiCryptoError, verifyCertificateSignature } from 'pkinative';

export async function signedBy(leafDer: Uint8Array, issuerDer: Uint8Array): Promise<'yes' | 'no' | string> {
    if (!canVerify()) return 'PKI_CRYPTO_UNAVAILABLE';
    const quiet = { onDiagnostic: () => undefined };
    try {
        return await verifyCertificateSignature(parseCertificate(leafDer, quiet), parseCertificate(issuerDer, quiet)) ? 'yes' : 'no';
    } catch (error) {
        // Not a verdict: pkinative could not decide. Retrying elsewhere may
        // give a different answer, and treating it as a rejection would
        // blame the certificate for the runtime's limits.
        if (error instanceof PkiCryptoError) return error.code;
        throw error;
    }
}
```

**Three answers, and the third is the one people get wrong.** `true` and `false` are verdicts; a `PkiCryptoError` is not. A signature whose bytes are malformed, whose issuer key is of the wrong family, or whose two `signatureAlgorithm` fields disagree is `false` — fail closed, so a caller who forgets the `catch` gets "not verified" instead of an exception that some layer above may swallow into a success path.

Verification runs in [Web Crypto](https://www.w3.org/TR/WebCryptoAPI/), never in TypeScript: the key is imported from the SubjectPublicKeyInfo with `extractable: false` and the single usage `verify`, and pkinative never sees its bits. That is the whole of [`src/crypto/webcrypto.ts`](../../src/crypto/webcrypto.ts), sixty lines, and it is the only file in the library that may name a key operation at all.

## Issue a certificate, without ever holding the key

The job: mint a certificate or a PKCS#10 request from data you have, signed by a key your application already manages. A key that arrives as a PEM file or a `.p12` becomes a `SigningKey` through `importPrivateKey`, `decryptPrivateKey` or `openPkcs12` — see [Private keys and PKCS#12](#private-keys-and-pkcs12).

```ts
import { createCertificate, encodeBasicConstraints, encodeKeyUsage, type CertificateDescription, type SigningKey } from 'pkinative';

export async function issue(spki: Uint8Array, signer: SigningKey): Promise<Uint8Array> {
    // 128 random bits, forced into 0x40–0x7f at the top: positive, and never
    // a redundant leading octet DER would refuse. A counter is not a serial.
    const serial = crypto.getRandomValues(new Uint8Array(16));
    serial[0] = (serial[0]! & 0x7f) | 0x40;

    const description: CertificateDescription = {
        serialNumber: serial,
        subject: [[{ type: '2.5.4.3', value: 'host.example' }]],
        notBefore: Date.now(),
        notAfter: Date.now() + 90 * 86_400_000,
        subjectPublicKey: spki,          // SubjectPublicKeyInfo DER, not a CryptoKey
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        ],
    };
    return createCertificate(description, signer);
}
```

**`subjectPublicKey` is DER, and that is the point.** pkinative cannot take your `CryptoKey` and pull the public half out of it, because `exportKey` is refused inside `src/` in every version — the same rule that refuses `generateKey`. So the one line that extracts it is *yours*, in your code, where you can see it:

```ts
const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
```

An API that took a `CryptoKey` would be one line shorter and would make the library's central security claim unverifiable. This is the trade, stated rather than hidden.

The description types are ordinary data, so a certificate can be built in one place and signed in another: [`CertificateDescription`](../assets/api.json), [`CertificationRequestDescription`](../assets/api.json), [`NameDescription`](../assets/api.json), [`NameAttribute`](../assets/api.json), [`ExtensionDescription`](../assets/api.json) and [`PkiBuildOptions`](../assets/api.json) — the last carrying the same `limits` every other entry point takes, because an extension list assembled from attacker-supplied data is still a loop over untrusted input.

**Pass the issuer's own bytes, not its name.** `issuerDer: root.subject.der` copies the issuing certificate's encoding octet for octet. Re-describing that name and letting it round-trip through the string-type chooser will not reproduce a TeletexString, and a chain whose two names differ by one octet is a chain nothing will build. The full worked example, root and leaf and request, is [`recipes/create-certificate.ts`](../../recipes/create-certificate.ts).

## Validate a chain, and get told everything that is wrong with it

The job: decide whether a chain of certificates leads to something you trust.

```ts
import { validateCertificatePath, verifyCertificateSignature } from 'pkinative';

// Check every link first — in parallel, which is what you want anyway.
const signatures = await Promise.all(chain.slice(0, -1).map(async (subject, i) => ({
    certificate: subject,
    verdict: await verifyCertificateSignature(subject, chain[i + 1]!) ? 'valid' as const : 'invalid' as const,
})));

const report = validateCertificatePath({ path: chain, trustAnchors: roots, at: Date.now(), signatures });
if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
```

### When you have a bag rather than a chain

A TLS handshake hands over an unordered `certificate_list`, and **cross-signing means one subject name can have several plausible issuers** — Let's Encrypt's own hierarchy is the everyday case. `buildCertificatePath` searches instead of walking:

```ts
import { buildCertificatePath } from 'pkinative';

const report = buildCertificatePath({
    leaf, candidates: whateverTheServerSent, trustAnchors: yourRoots, at: Date.now(), signatures,
});
console.log(report.valid, report.explored);
```

Its input is a [`BuildCertificatePathInput`](../assets/api.json) and its answer a [`BuildCertificatePathReport`](../assets/api.json) — §6's report plus `explored`, the number of candidates tried. **`maxPathsExplored` (default 1 000) is the bound that matters here, not `maxChainLength`**: path building is exponential in the candidate set and only linear in the chain length, so a bag of thirty certificates that all name each other as issuer is a few kilobytes of input and an unbounded amount of work. A number near the bound in `explored` is a bag designed to be expensive, not a hierarchy.

Signature verdicts still arrive precomputed, which is the awkward part of building rather than validating: verify every plausible pair up front, in parallel, and pass them all. A pair with no verdict is `PKI_REASON_SIGNATURE_NOT_CHECKED` and the path is not taken — it fails closed. When no path is accepted you get the reasons from the attempt that got **furthest**, because "no path found" without saying why is a report nobody can act on.

Choosing which anchors to trust is yours, and so is fetching anything not already in the bag: a path builder that reached the network would be one an attacker can point at a host of their choosing.

**It takes signature verdicts, not keys**, and three things follow. `validateCertificatePath` is **synchronous** — putting `subtle.verify` inside would make the whole state machine asynchronous, unfuzzable without a host, and would mix an I/O-shaped failure with a logical one. It is **pure** — it reads data and returns a verdict, reaching nothing. And the signatures get checked in parallel, before the walk.

**It never throws for a validation issue.** An empty chain, no trust anchor, no signature verdicts: each is an answer, in the report. Only misusing the API — an unknown key in `limits` — throws. That is the [third vocabulary](errors.md#three-vocabularies-three-questions) doing its job: primitives return and throw, compositions report.

**It reports every reason, not the first.** A certificate can be expired *and* issued by something that is not a CA, and a caller fixing one per round trip is a caller the report failed.

Two behaviours worth knowing before you wire it up:

- **The trust anchor does not have to be in the chain.** RFC 5280 §6.1.1 takes it as a separate input, so a chain that stops at the intermediate is anchored when that intermediate names a root you supplied. Most servers send it exactly that way.
- **A certificate with no signature verdict is `PKI_REASON_SIGNATURE_NOT_CHECKED`, never assumed valid.** A validator that read silence as success would pass whenever the caller forgot to verify anything. And `NOT_CHECKED` is not `INVALID`: a runtime without Ed448 says nothing about whether a signature is good.

The input is a [`ValidateCertificatePathInput`](../assets/api.json) and the answer a [`ValidateCertificatePathReport`](../assets/api.json); `maxChainLength` (default 10) bounds the walk and `maxPolicyNodes` (default 4 096) bounds the policy tree, which is the part of §6 that actually explodes combinatorially; `PKI_REASON_LIMIT_EXCEEDED` names whichever one stopped the search. `recipes/validate-path.ts` runs all of this on the real Let's Encrypt hierarchy.

**Certificate policies are off by default, and that is the right default.** `requireExplicitPolicy` is what turns policy processing into a verdict: without it, a path that establishes no policy is still valid, because §6.1.5 (a) says the question was never asked. Turning it on by default would reject most of the public web. When you do need it, `initialPolicySet` is your `user-initial-policy-set`, and `PKI_REASON_NO_VALID_POLICY` is the answer when nothing survives.

**What it refuses rather than ignores.** RFC 5280 §6.1.3 (f) requires a verifier to refuse a critical extension it does not process, and `PROCESSED_CRITICAL_EXTENSIONS` is the exact boundary of what a chain may rely on: `basicConstraints`, `keyUsage`, `subjectAltName`, `nameConstraints`, `certificatePolicies`, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy` and `extKeyUsage`. Anything else marked critical comes back `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION` — including `cRLDistributionPoints`, until revocation lands. That is the correct answer rather than a placeholder: a validator that ignored a constraint it had not implemented would answer "valid" for a chain the issuing CA forbade, which is the shape of a CVE rather than a missing feature.

## Just tell me whether to accept this certificate

The job: you have a certificate a server presented, a trust store, and a host name. You want one answer.

```ts
import { verifyCertificateChain, KEY_PURPOSES } from 'pkinative';

const report = await verifyCertificateChain({
    leaf,
    candidates: whateverTheServerSent,
    trustAnchors: yourRoots,
    serverName: { kind: 'dns', value: 'bank.example' },
    purposes: [KEY_PURPOSES.serverAuth],
});
if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
```

Every layer below this one answers exactly one question and is deliberately blind to the others — §6 has no notion of the host you connected to, `checkServerName` knows nothing about trust, revocation takes a signature verdict it did not compute. That separation is what keeps each of them synchronous, pure, fuzzable and small, and it leaves somebody with the job of putting them in the right order. **If that somebody is every caller, every caller gets it slightly wrong.** So it is here, once: the signatures verified in parallel *before* anything is decided, the path built with the purpose already in hand, then the host name, then revocation. `VerifyCertificateChainInput` is the whole surface and `VerifyCertificateChainReport` adds `signatureVerifications` — the number of signatures computed, worth logging, because a number far above the path length is what a bag full of plausible issuers looks like.

Three defaults worth knowing. **`at` is now**, so omitting it asks about today. **Revocation is soft-fail**: with no list or response supplied nothing is claimed, and `requireRevocation: true` turns silence into `PKI_REASON_REVOCATION_UNKNOWN` — the right setting wherever you can actually obtain them, and off by default because a library that refuses every chain for which the caller happened not to download one is a library callers route around. **SHA-1 signatures are not evidence** and come back `PKI_REASON_SIGNATURE_NOT_CHECKED` unless `allowSha1` says otherwise. When the question is whether a certificate was good at some **past** instant — when a document was signed — do not move `at` to a time somebody merely claims: [a verified timestamp is what proves that instant](#prove-when-it-was-signed).

**Revocation takes `crls`, `ocspResponses`, or both** — DER as you downloaded it or as a TLS server stapled it, and pkinative fetches neither. A CRL is used when it names the CA that issued the certificate, **and** when that CA asserts `cRLSign`: a CA constrained to signing certificates may not revoke them (RFC 5280 §4.2.1.3). An OCSP response is matched on **all three** `CertID` fields — an answer about somebody else's serial is `PKI_REASON_REVOCATION_MISMATCH`, not a status — and its signer is authorised the way RFC 6960 §4.2.2.2 sets out: either the issuing CA signed it, or the CA issued a certificate carrying `id-kp-OCSPSigning` and *that* certificate signed it. The certificates a response **attaches** are a convenience for reaching that delegate, never a claim of authority; each is checked to have been issued by this CA, to carry the purpose and to be in date before its signature counts for anything. `ocspNonce` and `requireOcspNonce` are there for replay protection, off by default because most public responders omit the echo so answers stay cacheable.

And this is the **one place in `src/` that turns a `PkiError` into a reason**. The rule the library runs on is *primitives return and throw, compositions report, exactly one layer converts* — so a malformed CRL is `PKI_REASON_INPUT_MALFORMED`, carrying in `errorCode` the code that would have been thrown. That is how a report promises never to throw for bad input without copying the encoding vocabulary into a second registry that would then have to be frozen too. What it does **not** do is fetch: not a CRL, not an OCSP response, not a missing intermediate. A verifier that reached the network would be one an attacker can point at a host of their choosing.

The sections below are the same questions asked one at a time, for callers who need only one of them — or who want to know what this call is doing on their behalf.

## Two questions a validated chain does not answer

The job: you validated the path and it came back clean. You are not done.

RFC 5280 §6 asks whether a chain of certificates is internally sound and reaches something you trust. It has **no notion of the host you connected to** and it **never reads `extKeyUsage`**. So a chain can be perfectly valid and still be a certificate for somebody else, or a certificate for something else — and both of those are how a valid certificate gets accepted where it should not be.

```ts
import { buildCertificatePath, checkServerName, checkExtendedKeyUsage, KEY_PURPOSES } from 'pkinative';

const report = buildCertificatePath({ leaf, candidates, trustAnchors, at: Date.now(), signatures });
const problems = [
    ...report.reasons,
    ...checkServerName(leaf, { kind: 'dns', value: 'bank.example' }),
    ...checkExtendedKeyUsage(report.path, KEY_PURPOSES.serverAuth),
];
if (problems.length > 0) for (const reason of problems) console.log(reason.code, reason.path, reason.message);
```

**`checkServerName` is RFC 6125, written the strict way**, because every relaxation has been somebody's bypass. `subjectAltName` wins absolutely: if the certificate carries any `dNSName` or `iPAddress`, the `commonName` is never consulted, and `allowCommonNameFallback` is **off by default** — CA/Browser Forum BR 7.1.4.2.2 has forbidden CN-only certificates since 2017. Turned on, it also needs `path`, the validated path: RFC 5280 §6 constrains the subjectAltName and the subject, never a CN read as a host, so the fallback holds that CN to the `dNSName` name constraints of the CAs on the path — `PKI_REASON_NAME_NOT_PERMITTED` or `PKI_REASON_NAME_EXCLUDED`, as OpenSSL refuses it — and without `path` it refuses. A wildcard is one whole leftmost label and nothing else, it needs at least three labels, and `*.example.com` does not match `example.com`. An address is compared **as octets, never as text** (`ServerIdentity` takes `Uint8Array` for that reason), and the two forms never cross: `1.2.3.4` written as a `dNSName` is a whole class of bypass. `allowWildcards: false` is the right setting for an internal PKI that issues none. The same matcher is exported as `matchDnsName(presented, reference, options?)`, for a name you hold outside a certificate; its [`MatchDnsNameOptions`](../assets/api.json) take the same `allowWildcards`, on by default. No public suffix list is embedded — that is data which changes weekly, and a parser carrying a stale copy is worse than one that says it does not know.

**When you build rather than validate, put the purpose *into* the search.** `buildCertificatePath` takes `purposes`, and passing it is not an optimisation — a builder that picks a path without knowing what the path is for will confidently return one that `checkExtendedKeyUsage` then condemns **while an acceptable path existed**. A real bag of cross-signed intermediates, some restricted to `emailProtection` and some not, is exactly that shape. Whatever can make a path unacceptable belongs inside the search, for the same reason name constraints are inside §6 rather than after it — and `validateCertificatePath` is untouched by this, because §6 has no notion of purpose and searching is not §6.

```ts
const report = buildCertificatePath({
    leaf, candidates, trustAnchors, at: Date.now(), signatures,
    purposes: [KEY_PURPOSES.serverAuth],
});
```

**`checkExtendedKeyUsage` is RFC 5280 §4.2.1.12**, and it takes the purpose as an argument because which purpose you need is a fact about your protocol, not about the chain. One rule in it is **not** in the RFC: a CA's own `extKeyUsage` restricts what it may issue for. Every Web PKI validator enforces it and the CA/Browser Forum relies on it to constrain sub-CAs — without it, a sub-CA restricted to `emailProtection` issues a `serverAuth` certificate and the chain validates, which is the whole point of restricting it. So `restrictIssuers` is **on** by default, and `restrictIssuers: false` is the literal-RFC reading for an internal PKI that puts a purpose on a CA as documentation. An **absent** extension means unrestricted, which is why almost no public root ever appears in a refusal; `requireExplicitPurpose: true` is the stricter reading and applies to the end entity alone. `recipes/check-server-name.ts` and `recipes/check-purpose.ts` run both on real certificates.

## Ask a revocation list about one certificate

The job: a CA published a CRL, and you want to know whether this certificate is on it.

```ts
import { findRevocation, parseCertificateList } from 'pkinative';

const crl = parseCertificateList(der);
console.log(crl.issuer, crl.thisUpdate, crl.nextUpdate, crl.entryCount);

const entry = findRevocation(der, certificate.serialNumber.bytes);
if (entry !== undefined) console.log('revoked', entry.reason, new Date(entry.revocationDate.epochMilliseconds));
```

**There is no array of entries, on purpose.** A CRL entry costs three ASN.1 nodes, so decoding the list into a tree hits `maxNodes` (200 000) at roughly 65 000 entries — while `maxInputBytes` would allow millions, and real CRLs sit in between. So the envelope is decoded and the list is **walked**, one TLV header at a time, in constant memory, bounded by `maxRevokedCertificates` (default 1 000 000). Exposing an array would either cap the library below real-world sizes or allocate hundreds of megabytes to answer one yes-or-no. `entryCount` is there when you genuinely want the size, and it is counted by walking.

**Serials are compared by their content octets, never by `value`.** Two serials that differ only in a leading zero octet are two different serials to a CA, and comparing the `bigint` would make them one — a revocation silently missed. Pass `certificate.serialNumber.bytes`.

`findRevocation` walks from the start each time, so checking many certificates against one CRL is O(n·m). The alternative is a map keyed by serial, and that is your decision: you know how many serials you have and how much memory you will spend on them. What this library must not do is build that map behind your back for a single lookup.

`crl.crlNumber` and `crl.isDelta` are read from `cRLNumber` and `deltaCRLIndicator`; a **delta CRL is not a full one**, and treating it as complete would report every certificate absent from it as unrevoked. `crl.issuingDistributionPoint` is an [`IssuingDistributionPoint`](../assets/api.json) — the §5.2.5 scope, what the list says it is about — and [the section below](#what-a-list-is-about-rfc-5280-525) is what acts on it.

The envelope is a [`CertificateList`](../assets/api.json), an entry is a [`RevokedCertificate`](../assets/api.json) carrying its `reason` as a [`CrlReason`](../assets/api.json) and its `invalidityDate`, and `maxRevokedCertificates` is the bound on the walk.

### The decision, and the four answers it keeps apart

`findRevocation` says whether a serial is on a list. It does not say whether that list was entitled to answer, or whether it is current. `checkRevocation` does:

```ts
import { checkRevocation, parseCertificateList, verifyCrlSignature } from 'pkinative';

const crl = parseCertificateList(crlDer);
const signatureVerified = await verifyCrlSignature(crl, caCertificate);
const reasons = checkRevocation({ certificate, crl, crlDer, at: Date.now(), signatureVerified });
```

It takes a `signatureVerified` boolean rather than a key, which is what keeps it **synchronous and free of Web Crypto** — the same separation §6 makes. Its input is a [`CheckRevocationInput`](../assets/api.json), and it returns `PkiReason`s:

| Answer | Meaning |
|---|---|
| `[]` | Not revoked, by a list entitled to say so and current enough to believe |
| `PKI_REASON_REVOKED` | Listed by a list entitled to say so — this certificate's issuer's, covering it, its signature verified — and the message carries the date, because a signature made before it may still be good |
| `PKI_REASON_REVOCATION_STALE` | No `nextUpdate`, or it has passed beyond your `staleTolerance` |
| `PKI_REASON_REVOCATION_WRONG_ISSUER` | The list names another CA, compared by encoded name |
| `PKI_REASON_REVOCATION_OUT_OF_SCOPE` | The right CA's **wrong list** — its `issuingDistributionPoint` excludes this certificate |
| `PKI_REASON_REVOCATION_PARTIAL` | The list declares `onlySomeReasons`, so its silence rules out only those |
| `PKI_REASON_REVOCATION_UNKNOWN` | No evidence either way |

**`UNKNOWN` is not `[]`, and that distinction is the point.** A missing or unsigned list is an absence of evidence. Reporting it as "not revoked" would make the soft-fail decision on your behalf, invisibly. If you want soft-fail, you write it — `staleTolerance` is the same idea for a lapsed list: a number you chose, not a default that chose for you.

A list with **no `nextUpdate` at all is stale**, not current. RFC 5280 §5.1.2.5 makes the field optional and tells CAs to include it; nothing asserts such a list is still good.

**`REVOKED` is evidence, never a rumour.** RFC 5280 §6.3.3 consults a list only once its issuer and scope are this certificate's and its signature is valid, and serial numbers are unique per issuer, so a listing on another CA's list, an out-of-scope list or a list with a critical extension nothing here processes is not reported as a revocation: the reason that disqualifies the list already fails the answer. A list whose only fault is an unverified signature is still this CA's list about this certificate, so what it names is carried as a claim in a `PKI_REASON_REVOCATION_UNKNOWN`, dated. A stale list that may speak still proves a revocation — time does not withdraw one — and says it is stale besides. `checkOcspStatus` follows RFC 6960 §3.2 the same way: a `revoked` answer is `REVOKED` only when the signature verified and the signer is authorised.

### What a list is *about* (RFC 5280 §5.2.5)

A CRL is evidence of **absence**: your serial is not on it. That is worth exactly what the list's declared scope says it is worth, which is why `OUT_OF_SCOPE` is its own answer and not a flavour of `WRONG_ISSUER`. A CA that publishes one list for its end-entity certificates and another for its sub-CAs marks both with `issuingDistributionPoint`; read the first about a sub-CA and you get a clean bill of health for a CA that may well have been revoked on the second. RFC 5280 requires the extension to be critical for that reason alone.

`checkRevocation` therefore decides, before anything else, whether the list may answer at all: the kind of certificate it covers, the distribution point it was published at against the one your certificate names in `cRLDistributionPoints` — **including a point named relative to the CRL issuer**, composed rather than refused — and, when the certificate delegates to a `cRLIssuer`, whether the list itself asserts `indirectCRL`. Without that last agreement any CA named in any `cRLIssuer` field could answer for certificates it never issued.

A list carrying a **critical extension pkinative cannot process** is refused by §6.3.3, in the same words §6.1.3 (f) uses for a certificate — you get `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`.

### Delta CRLs (RFC 5280 §5.2.4)

A delta lists what *changed* since a complete list. Read alone it reports every certificate absent from it — nearly all of them — as unrevoked, so passing one as `crl` is refused. Pass it as `delta` instead, beside the base it applies over:

```ts
const reasons = checkRevocation({
    certificate, crl: base, crlDer: baseDer, at: Date.now(), signatureVerified,
    delta: { crl: newer, crlDer: newerDer, signatureVerified: deltaVerified },
});
```

**The delta answers first, and the base only where the delta is silent.** That order is the rule, which is why the pair goes into one call rather than being merged afterwards — and it is the only place the `removeFromCRL` entry reason can mean what it means, since it appears on a delta to withdraw a revocation the base still records.

The two are paired only when the base's `cRLNumber` is **at least** the delta's `baseCrlNumber` — otherwise everything revoked in between is invisible to both — and **below** the delta's own, otherwise the "delta" is the older document. Both must state a `cRLNumber`, both must name the same issuer, and both must cover the certificate. A delta whose signature nobody vouched for is not applied at all: one `removeFromCRL` entry on a forged delta would withdraw any revocation on the base, which is strictly easier than forging the base itself.

`verifyCertificateChain` does the pairing for you — hand it every list you hold, in any order.

### Who may sign a list

`signatureVerified` asks whether **a key entitled to sign it** did, and entitlement is more than a name. `verifyCertificateChain` requires `cRLSign` in the signer's `keyUsage` (§4.2.1.3); it honours the `authorityKeyIdentifier` a list names, which is how a CA holding several keys under one name says which of them revokes; and for a key the CA *delegated* the job to, it requires that certificate to be in date and **not itself revoked**. That last rule is what makes withdrawing a compromised CRL-signing key mean anything — without it, whoever holds that key goes on publishing "nothing is revoked" until the certificate expires.

`PKI_REASON_REVOCATION_PARTIAL` is the one answer that **adds up**. A CA may publish a keyCompromise list it can reissue in minutes and a second list for everything else; between them they have answered completely. No single list can see that, so `checkRevocation` reports what each one ruled out and `verifyCertificateChain` — which holds them all — does the addition (§6.3.3's `reasons_mask`) and drops the reason once the union is complete.

On an **indirect** list, pass `issuerDer` — the one field of [`FindRevocationOptions`](../assets/api.json) beyond the ordinary parse options — to `findRevocation`. A serial is not an identity there: the list holds entries for several CAs, each named by the running `certificateIssuer` state of §5.3.3, and two CAs issue the same serial all the time. `checkRevocation` passes it for you.

## Ask a responder instead of downloading a list

The job: OCSP. One question, one answer, no megabyte of CRL.

```ts
import { createOcspRequest, parseOcspResponse, verifyOcspSignature } from 'pkinative';

const body = createOcspRequest(certificate, issuer, { nonce: crypto.getRandomValues(new Uint8Array(16)) });
const bytes = new Uint8Array(await (await fetch(url, {
    method: 'POST', headers: { 'content-type': 'application/ocsp-request' }, body: body.slice(),
})).arrayBuffer());

const response = parseOcspResponse(bytes);
if (response.status !== 'successful') return `the responder declined: ${response.status}`;
const basic = response.basicResponse!;
if (!await verifyOcspSignature(basic, responderCertificate)) return 'not from that responder';

for (const single of basic.responses) console.log(single.status.kind);   // 'good' | 'revoked' | 'unknown'
```

**`body.slice()` is for the type checker, not the runtime.** Since TypeScript 5.7 a `Uint8Array` is generic over its buffer, and the DOM types that ship with TypeScript 5.9 accept only a `Uint8Array<ArrayBuffer>` as a `fetch` body or a `crypto.subtle` input. pkinative's outputs are typed plain `Uint8Array`, whose buffer could be a `SharedArrayBuffer` as far as the checker knows, so under `lib: ["DOM"]` passing one directly fails to compile, and `body.slice()` returns a copy typed on an `ArrayBuffer`. The timestamp loop below does the same before `crypto.subtle.digest`.

**Three states, never two.** RFC 6960 §2.2 gives `good`, `revoked` and `unknown`, and `unknown` is the responder saying it does not know about this certificate. Reducing that to a boolean turns *"I have never heard of this serial"* into a clean bill of health — the OCSP form of the same mistake `PKI_REASON_REVOCATION_UNKNOWN` names for CRLs. The six non-`successful` statuses are the responder declining to answer at all, and each is a reason to look elsewhere rather than a statement about any certificate. A `parseOcspResponse` result with a non-`successful` status carries **no** `basicResponse`, because the protocol carries no body there.

**`issuerKeyHash` is over the public key bits, not the SubjectPublicKeyInfo.** That is the single most common OCSP client bug: hashing the SPKI produces a request a responder answers `unknown` to, which a careless client then reports as not revoked. `encodeOcspCertId` is exported so you can recompute the same three values when matching a response back to your question.

`parseOcspResponse` returns an [`OcspResponse`](../assets/api.json) whose `basicResponse` is an [`OcspBasicResponse`](../assets/api.json). `CreateOcspRequestOptions` carries `hashAlgorithm` — an [`OcspHashAlgorithm`](../assets/api.json), SHA-1 by default, because RFC 6960 §4.3 makes it mandatory for responders and a SHA-256 `CertID` is answered `unknown` by many of them — and `nonce`, which binds the response to your request. **Supply your own random bytes**: pkinative generates none, and without a nonce a responder may serve a cached answer that an attacker can replay. `maxOcspSingleResponses` bounds how many `SingleResponse` entries are read.

### The decision, and the substitution it catches

`parseOcspResponse` reads. `checkOcspStatus` decides, and reports RFC 6960 §3.2's four client responsibilities:

```ts
import { checkOcspStatus, computeFingerprint } from 'pkinative';

const reasons = checkOcspStatus({
    response,
    expected: {
        issuerNameHash: computeFingerprint(issuer.subject.der, 'SHA-1'),
        issuerKeyHash: computeFingerprint(issuer.subjectPublicKeyInfo.publicKey.bytes, 'SHA-1'),
        serialNumber: certificate.serialNumber.bytes,
    },
    at: Date.now(),
    signatureVerified,        // you computed it
    responderAuthorized,      // your policy decided it
    nonce,
});
```

**`PKI_REASON_REVOCATION_MISMATCH` is its own code, not a flavour of `UNKNOWN`,** because the two call for different actions. `UNKNOWN` means ask again; a mismatch means *this answer is not yours* — a confused responder, a cache serving somebody else's response, or an attacker substituting one. Retrying a mismatch against the same responder is the wrong move, and a caller that could not tell them apart would do it. The answer is located by matching **all three** `CertID` fields, never by taking `responses[0]`: a response may carry several, and taking the first is how a client reads somebody else's status as its own.

A nonce that comes back **different** is always a mismatch. One that does not come back **at all** is reported only when `requireNonce` asks — the CA/Browser Forum discourages nonces so responses stay cacheable, and most public responders omit the echo, so which matters more is your choice rather than a default. Note that the nonce sits inside **two** OCTET STRINGs; comparing at the wrong layer is a check that passes on everything, and `OCSP_NONCE_OID` is exported so you can find the echo yourself.

**A missing `nextUpdate` is not stale here**, unlike a CRL. RFC 6960 §4.2.2.1 says its absence means newer information is always available — the opposite of the CRL case, where nothing promises a successor. `futureTolerance` (a minute by default) refuses a `thisUpdate` well ahead of now: clocks disagree by seconds, not hours.

**Which certificate may answer for a CA is not a question this library answers.** `basicResponse.certificates` are certificates the responder *attached*; trusting them because they arrived would let the responder nominate its own authority, which is exactly what RFC 6960 §4.2.2.2 exists to constrain. The request is unsigned, too — RFC 6960 §4.1.2 makes that optional, almost no responder requires it, and signing would mean this library holding a key.

## Sign a message, and verify one the whole way

The job: a PDF signature, an S/MIME message, a `.p7s` beside a release artefact. All three are an RFC 5652 CMS `SignedData`, and all three ask the same question — *is this what its signer signed, and do I trust the signer?*

```ts
import { createSignedData, verifySignedData } from 'pkinative';

const p7s = await createSignedData({ content: message, detached: true, certificate: signerCertificate }, signingKey);

const report = await verifySignedData({ signedData: p7s, content: message, trustAnchors: roots });
if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
```

**Writing.** `createSignedData` takes a [`CreateSignedDataInput`](../assets/api.json) and a `Signer`, and returns the DER `ContentInfo`. It writes one `SignerInfo`, **always with signed attributes** — every modern profile requires them, and they are what makes a signature over a digest possible at all: `contentType` and `messageDigest`, then `signingCertificateV2` (RFC 5035) and `CMSAlgorithmProtection` (RFC 6211) unless you turn them off, and `signingTime` only when you pass one, because the PAdES baseline forbids it and S/MIME expects it. The attribute set is built in DER order before it is signed and never re-sorted afterwards. `sid: 'subjectKeyIdentifier'` names the key instead of the certificate, `certificates` and `crls` embed the chain and its revocation evidence verbatim, and `signedAttributes`/`unsignedAttributes` take further `Attribute` encodings from `encodeAttribute`. Mind the readers downstream: `issuerAndSerialNumber`, the default, is the interoperable `sid` — libksba 1.6.7 (gpgsm 2.4.9) and pyca's `pkcs7.load_der_pkcs7_certificates` cannot parse a `subjectKeyIdentifier` signer, and gpgsm 2.4.9 refuses an Ed25519 `SignerInfo` — on OpenSSL's output as on pkinative's, as the interoperability matrix of the [conformance guide](conformance.md) records.

**Detached or attached.** With `content` alone the content travels inside the message; `detached: true` leaves it out, which is how a PDF signature and most S/MIME are made. `contentDigest` is the PDF case proper: you hash the `/ByteRange` with the signer's digest yourself and never hand over the document; it implies `detached`. The verifier mirrors this — pass `content` or `contentDigest` for a detached message, and nothing for an attached one. **Absent content is never treated as empty content**: a detached message verified without it is `PKI_REASON_CMS_CONTENT_MISSING`, and passing content for a message that carries its own throws `PKI_API_MISUSE`, because there would be two answers to which bytes were signed. A PDF `/Contents` is a zero-padded placeholder; `allowTrailingData: true` accepts that padding and nowhere else should it be on.

**`intact` is not `valid`.** Each signer's [`SignerReport`](../assets/api.json) carries both. `intact` is everything that needs no trust store: the attributes say what they must, the digest, signature and CMSAlgorithmProtection algorithms agree, the content hashes to the committed `messageDigest` — computed by pkinative, never taken from the signer — the signature verifies, and the key's certificate is the one the signer committed to. `valid` adds any timestamp and the signer's chain, judged by `verifyCertificateChain`. **`intact: true` with `valid: false` means *unaltered, but not by anybody you trust*.** That is why `trustAnchors` is required: an empty list is accepted and always yields `PKI_REASON_NO_TRUST_ANCHOR`, because a verifier that called a message valid without knowing whom its signer answers to would make "anyone with a key" the default signer.

The rest of [`VerifySignedDataInput`](../assets/api.json) is the chain's vocabulary: `at` (now by default), `purposes` (`KEY_PURPOSES.emailProtection` for S/MIME), `certificates` beyond those the message carries, `crls` and `ocspResponses` added to the evidence the message embeds, `requireRevocation`, `allowSha1`, `encodingRules: 'ber'` for a PKCS #7 producer that streams with indefinite lengths. A message is valid when it has at least one signer **and every signer is valid**; a `SignedData` with no signer — a `.p7b` certificate bundle — parses fine and verifies as `PKI_REASON_CMS_NO_SIGNERS`, because `[].every(valid)` is true and a bundle is not a signature. The [`VerifySignedDataReport`](../assets/api.json) also counts `signatureVerifications`, the signature verifications spent, chains and timestamps included.

**Two requirements RFC 5652 does not make, and profiles do.** `requireSigningCertificate` refuses a signer that does not name its certificate in a signing-certificate attribute, as CAdES and PAdES require: without it, anyone holding a second certificate for the same key — a rollover, a cross-signature — can present the signature under that one. `requireAlgorithmProtection` refuses a signer without `CMSAlgorithmProtection`, whose absence leaves `digestAlgorithm` and `signatureAlgorithm` outside the signature. Both are off by default, both come back as `PKI_REASON_CMS_ATTRIBUTE_INVALID` naming the attribute, and when the attributes *are* present they are always checked: a committed certificate that is not the one whose key verified is `PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH`, disagreeing algorithms are `PKI_REASON_CMS_ALGORITHM_MISMATCH`.

**Keys held elsewhere.** A `Signer` is a `SigningKey` — a `CryptoKey` pkinative hands to `crypto.subtle.sign` and nothing else — or an `ExternalSigner`, a function for a key in an HSM, a smart card, a cloud KMS or a remote service. `produceSignature` receives the exact bytes to sign, not a digest, and must return what `crypto.subtle.sign` would: **raw `r ‖ s` for ECDSA**, the plain octets otherwise. A DER ECDSA signature is refused with `PKI_API_MISUSE` rather than guessed at — guessing which form arrived is how a signature gets encoded twice. A key you were given as a file — PKCS#8 or a `.p12` — is turned into a non-extractable `SigningKey` as [Private keys and PKCS#12](#private-keys-and-pkcs12) describes.

**Reading without judging.** `parseSignedData` returns a [`SignedData`](../assets/api.json): `content` (`undefined` when detached), the `certificates`, `crls` and `ocspResponses` bags **as DER** — a bag is a claim by whoever assembled the message, and parsing all of it up front would refuse a whole message over one unrelated certificate — and each [`SignerInfo`](../assets/api.json). `signedAttributesDer` is **the exact bytes the signature covers**: the transmitted `[0]` with its tag replaced by the `SET OF` tag RFC 5652 §5.4 signs under; nothing downstream re-derives them. The conveniences — `contentType`, `messageDigest`, `signingTime`, `signingCertificate`, `algorithmProtection` — are set only when their attribute appears exactly once with one value, because "the first one" would hide a second `messageDigest`, which is the shape of an attack. `timeStampTokens` lists every RFC 3161 token among the unsigned attributes. [`ParseSignedDataOptions`](../assets/api.json) adds `allowTrailingData` to the ordinary parse options.

`verifySignerInfoSignature` is the primitive underneath, as `verifyOcspSignature` is under revocation: **did this certificate's key sign what this `SignerInfo` covers?** It returns a boolean and reads nothing else — no `messageDigest`, no `sid`, no chain — so it is `true` for a signer whose content has been swapped. Build a verifier with it; never report its `true` as the verdict on a message. [`VerifySignerInfoSignatureOptions`](../assets/api.json) carries `content`, needed only for a signer without signed attributes, and `allowSha1`.

`addUnsignedAttribute` adds one unsigned attribute to one signer **by surgery on the encoding**: every octet of the `SignerInfo` but its `unsignedAttrs` is copied as it is, so every signed octet — and every signature — survives. A parse-and-rebuild would re-sort a set some other signer never sorted.

**The three vocabularies, applied to CMS.** They answer different questions here as everywhere else:

| Vocabulary | Codes | Raised by | Means |
|---|---|---|---|
| Thrown `PkiCmsError` | `PKI_CMS_STRUCTURE_INVALID`, `PKI_CMS_CONTENT_TYPE_UNEXPECTED`, `PKI_CMS_VERSION_UNSUPPORTED`, `PKI_CMS_CONTENT_NOT_OCTET_STRING` | `parseSignedData`, the TSP readers, `addUnsignedAttribute` | The DER is well formed but is not the RFC 5652 or RFC 3161 structure it was read as; `path` and `offset` say where |
| Emitted diagnostics | `PKI_DIAG_CMS_VERSION_MISMATCH`, `PKI_DIAG_CMS_SET_NOT_SORTED`, `PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER`, `PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED` | `parseSignedData`, through `onDiagnostic` and `SignedData.diagnostics` | The structure deviates from the profile in a way no signature depends on |
| Returned reasons | `PKI_REASON_CMS_*`, `PKI_REASON_TSP_*`, plus every chain reason under `signerInfos[i].chain` | `verifySignedData`, `verifyTimeStampToken` | The message is readable, and the judgement is *no* |

`PkiCmsErrorCode` is the union a `PkiCmsError` narrows `code` to. `verifySignedData` **never throws for bad input** — bytes that are not a `SignedData` are `PKI_REASON_INPUT_MALFORMED`, carrying in `errorCode` the code that would have been thrown — and reads quietly, so the diagnostics are `parseSignedData`'s to show. It throws only for a call that is wrong: content given twice, an unknown `limits` key, a certificate `parseCertificate` did not make. `maxSignerInfos` and `maxCmsCertificatesAndCrls` bound what one message may cost, and `maxAttributes` each attribute list.

`recipes/sign-message.ts` runs all of this, from the detached signature to the three vocabularies; `recipes/external-signer.ts` signs a pre-computed PDF digest through an `ExternalSigner`.

## Prove when it was signed

The job: a signature has to outlive its certificate. A signing certificate lives a year or two; a contract, an invoice or a PDF must still verify after that. An RFC 3161 timestamp over the signature proves it existed **before** the certificate expired — CAdES-T, PAdES B-T.

```ts
import { addTimeStampToken, createTimeStampRequest, parseSignedData, parseTimeStampResponse, verifySignedData } from 'pkinative';

const signature = parseSignedData(p7s).signerInfos[0]!.signature;
const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', signature.slice()));
const nonce = new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0);
const body = createTimeStampRequest(hash, { nonce });
const response = parseTimeStampResponse(new Uint8Array(await (await fetch(tsaUrl, {
    method: 'POST', headers: { 'content-type': 'application/timestamp-query' }, body: body.slice(),
})).arrayBuffer()));
if (response.tokenDer === undefined) return `the TSA declined: ${response.status} ${response.failInfo.join(',')}`;

const stamped = addTimeStampToken(p7s, 0, response.tokenDer);
const report = await verifySignedData({ signedData: stamped, content: document, trustAnchors: roots, atTimeStamp: true });
```

**What is stamped is the hash of the signature value** (RFC 3161 Appendix A) — the `signature` octets of the `SignerInfo`, not the document and not the signed attributes. `createTimeStampRequest` takes that hash, never the data, and a [`CreateTimeStampRequestOptions`](../assets/api.json): `hashAlgorithm` (SHA-256 by default; SHA-384 and SHA-512 offered, SHA-1 not, because a collision would let one token cover two documents), `nonce`, `policy`, and `certReq` — **`true` by default**, which is not the grammar's default: with `certReq` false the TSA must leave its certificate out, and the verifier must then be given it through `certificates`. **Supply a nonce of at least 64 random bits**: without one, nothing says a response answers *this* request, and a replayed answer is indistinguishable from a fresh one. pkinative generates none.

**Reading the answer.** `parseTimeStampResponse` returns a [`TimeStampResponse`](../assets/api.json): `status`, the TSA's `statusStrings` and `failInfo` (`badAlg`, `unacceptedPolicy`, …), and — only when granted — `tokenDer`, the bytes to attach, and `token`, a [`TimeStampToken`](../assets/api.json). A token is a `SignedData` whose content is a [`TstInfo`](../assets/api.json), and the type keeps them apart on purpose: *who* signed is `token.signedData`, *what* was stamped and *when* is `token.tstInfo` — `messageImprint`, `genTime`, `accuracy`, the echoed `nonce`, `policy`, `serialNumber`, and `tsa`, a name that is a hint, never an identity. `parseTimeStampToken` reads a token already attached to a signature, and `parseTstInfo` reads the `TSTInfo` DER alone. Hand either reader a `SignedData` over anything but a `TSTInfo` and it throws `PKI_CMS_CONTENT_TYPE_UNEXPECTED`.

**Judging the token.** `verifyTimeStampToken` makes every check RFC 3161 §2.4.2 lists, in one call, and returns a [`VerifyTimeStampTokenReport`](../assets/api.json). Its [`VerifyTimeStampTokenInput`](../assets/api.json) **must say what was stamped** — `request`, `data` or `imprint` — or it throws `PKI_API_MISUSE`, because a check that never asked *of what* would confirm that some hash existed at some time, which is true of every token ever issued. The timestamp itself goes in as exactly one of `token` or `response`: the latter is the whole `TimeStampResp` the TSA sent over HTTP, and a response that granted nothing comes back as `PKI_REASON_TSP_NOT_GRANTED`, carrying the TSA's status, its text and its `failInfo`, rather than as a malformed input. **`request` is the strongest of the three**: the token must stamp the same imprint, echo the same nonce as the same integer and carry the policy asked for, and it is the only one that catches a replay (`PKI_REASON_TSP_REQUEST_MISMATCH`). A token over anything else is `PKI_REASON_TSP_IMPRINT_MISMATCH`; one with a second signer, or a `tsa` name its certificate does not hold, is `PKI_REASON_TSP_TOKEN_INVALID`. The signing-certificate attribute RFC 5816 makes mandatory is always required of a token, as `requireSigningCertificate` would require it of a message, and its absence is `PKI_REASON_CMS_ATTRIBUTE_INVALID`. The TSA's certificate must carry an `extKeyUsage` that is present, **critical**, and names `timeStamping` alone (§2.3); `allowNonCriticalTimeStampingEku` is the documented escape for deployed TSAs that did not mark it critical, off by default. `genTime` must fall inside that certificate's validity, and the certificate must chain to your `trustAnchors`. The report's `genTime`, `earliest` and `latest` — `genTime` minus and plus the declared accuracy — are filled in **only when the token is valid**.

A response that was not granted carries no token, so there is nothing to verify: branch on `status` before you reach for `tokenDer`.

**`at` or `atTimeStamp` — when is the signer judged?** Without a timestamp, `verifySignedData` judges each signer's chain at `at`, which is now by default: a signer whose certificate expired yesterday is `PKI_REASON_EXPIRED` today, however long ago it signed. `atTimeStamp: true` judges each signer's chain **at the time its own verified timestamp proves** — the earliest `latest` among its valid tokens, because the true time may be as late as `genTime` plus the accuracy, and a certificate that expired inside that window is not proved to have been valid. That is the long-term validation question: *was the certificate good when this was signed?* A signer with no valid timestamp is still judged at `at`, and the signer's own `signingTime` is **never** used: nothing vouches for it but the signer, which is why `SignerReport.signingTime` is reported as a claim.

**The timestamp authority is always judged at `at`, never at the `genTime` its token asserts.** A timestamp is proof of time only while its TSA is trusted. Judging the TSA's chain at the time its own token claims would let a TSA key compromised after its certificate expired **backdate** tokens that would then be believed — the attacker picks the `genTime`. So once the TSA's certificate has expired too, the stamped signature is `PKI_REASON_EXPIRED` under `signerInfos[0].unsignedAttrs.timeStampToken[0].token.tsaChain`, and it is also expired under `signerInfos[0].chain`, because the only proof of time no longer counts. TSA certificates are long-lived for this reason; carrying the proof beyond one needs an archive timestamp (PAdES B-LTA), which pkinative does not implement ([ADR 0009](../adr/0009-no-etsi-long-term-signature-formats.md)). Calling `verifyTimeStampToken` directly with `at` set to the token's `genTime` is possible, and is a deliberate decision to trust the time the token itself asserts.

A timestamp present on a signer **and invalid** makes the signer invalid, not merely unstamped: the message is claiming a time it cannot prove. `addTimeStampToken` attaches a token as `id-aa-signatureTimeStampToken` through `addUnsignedAttribute`, so every signed octet is unchanged; a `SignerInfo`'s `timeStampTokens` lists what is already there.

`recipes/timestamp.ts` runs the whole loop without a network — it plays the TSA with `createSignedData` over a `TSTInfo` built from the public encoders — including the replayed answer, the signer judged at the proved time, and the TSA judged after its own expiry.

## Private keys and PKCS#12

The job: somebody handed you the key to sign with — a `PRIVATE KEY` or `ENCRYPTED PRIVATE KEY` PEM file, or a `.p12`/`.pfx` and its password — and `createCertificate`, `createCertificationRequest` or `createSignedData` needs a `SigningKey`.

```ts
import { createSignedData, openPkcs12 } from 'pkinative';

// An RSA key needs its scheme named: the certificate does not say it, and pkinative does not guess.
const report = await openPkcs12(p12Bytes, { password, rsaAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } });
if (!report.valid) throw new Error(report.reasons.map((r) => `${r.code} at ${r.path}`).join('; '));
const [{ signingKey, certificate }] = report.keys;
const p7s = await createSignedData({ content: message, certificate: certificate! }, signingKey!);
```

**The key never becomes bytes pkinative holds.** Every call in this section returns a `SigningKey` whose `CryptoKey` is `extractable: false` with the single usage `sign`: it signs, and it cannot give its bits back to anyone. An unencrypted PKCS#8 is your own buffer and goes to the host exactly as it came. An encrypted one — a PKCS#8 under PBES2, or a PKCS#12 `pkcs8ShroudedKeyBag`, which is how OpenSSL and Windows store the key — is decrypted *by the host*, with `unwrapKey`, straight into that handle: the decrypted PKCS#8 is never a JavaScript value, so no code of pkinative's, and none of yours, can log it, copy it or leave it in a buffer. `exportKey` is refused inside `src/` in every version, so nothing here can turn the handle back into bytes either. The one case outside this is a writer that puts a plain `keyBag` inside an encrypted SafeContents: that SafeContents is opened with `decrypt`, and the key it holds is then as much in the clear as an unencrypted PKCS#8 you read from disk — `openPkcs12` wipes those bytes as soon as Web Crypto has imported them, a best effort, since the engine may already hold a copy.

**That is why the algorithm must be known before decrypting.** A key's type is inside the ciphertext, and the host has to be told what it is unwrapping *before* it unwraps it — pkinative never looks inside first. So:

- `decryptPrivateKey(der, { password, algorithm })` requires `algorithm` ([`DecryptPrivateKeyOptions`](../assets/api.json)). Name the wrong one and the host refuses to unwrap, which surfaces as `PKI_CRYPTO_DECRYPTION_FAILED` — AES-CBC carries no authentication tag, so a wrong password, altered bytes and a key that is not the algorithm named are one error, not three.
- `openPkcs12` takes the algorithm from **the certificate that shares the key's `localKeyId`**: ECDSA on the certificate's curve with that curve's customary digest (P-256 with SHA-256, P-384 with SHA-384, P-521 with SHA-512), Ed25519, Ed448. A certificate says "RSA" and not how the key will sign, and a Web Crypto key is bound to one scheme and one hash, so `rsaAlgorithm` decides, and there is no default: without it an RSA key stays shut with `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`, the rest of the file is still reported, and the next call names it — `{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }`, the scheme of nearly every RSA signing certificate in use, or `RSA-PSS`, over SHA-1, SHA-256, SHA-384 or SHA-512; anything else is `PKI_INVALID_OPTION` before the file is read. `importPrivateKey` refuses to guess an RSA scheme for the same reason, and a guess here would be worse: the key is non-extractable, so a wrong scheme could not be corrected by re-importing it. A key with no certificate sharing its `localKeyId` is not guessed at: it is `PKI_REASON_PKCS12_KEY_UNMATCHED`, and `decryptPrivateKey` with a named algorithm opens it.
- `importPrivateKey(der, options?)` reads an **unencrypted** key, so it can look at the algorithm OID first ([`ImportPrivateKeyOptions`](../assets/api.json)). An EC key decides for itself as above, and so does an Ed25519 or Ed448 key. An RSA key does not — PKCS#1 v1.5 or PSS, over any digest — and neither does an `id-RSASSA-PSS` key's digest, so both throw `PKI_API_MISUSE` until you name it: `{ algorithm: { name: 'RSA-PSS', hash: 'SHA-256' } }`. An algorithm you name must fit the key, family and curve, or it is `PKI_API_MISUSE` too.

**Describe before you decrypt.** `parsePrivateKeyInfo` returns a [`PrivateKeyInfo`](../assets/api.json) — `version`, the `algorithm`, `kind` (`rsa`, `rsa-pss`, `ec`, `ed25519`, `ed448` or `unknown`), `curve` (the same `EcCurve` a public key reports: `P-256`, `P-384`, `P-521` or `undefined`), the `attributes` and, for a version 1 key, `publicKey` — and **no field holding the private key**: the octets are checked for shape and never copied out, because a second convenient name for a secret is how it ends up in a log. (`der` is still your whole input, key included.) `parseEncryptedPrivateKeyInfo` returns an [`EncryptedPrivateKeyInfo`](../assets/api.json) whose `encryption.scheme` says in words what protects the key — `PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)` — and whose `encryption.pbes2` carries the salt, iteration count, PRF, AES size and IV, or is `undefined` for a scheme pkinative refuses. A refused scheme still parses, so a tool can say what a file is protected with, and why it will not open it, before anyone types a password.

**PBES2 only, by policy.** pkinative opens PBES2 with PBKDF2 (HMAC-SHA-1, -256, -384 or -512) and AES-128, -192 or -256 in CBC mode — what OpenSSL 1.1 and later write by default — and refuses every other scheme by name with `PKI_KEY_ENCRYPTION_UNSUPPORTED`: the RFC 7292 Appendix C schemes (`pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd40BitRC2-CBC` and the rest), PBES1, and PBES2 with another cipher. The PKCS#12 schemes derive their key with the RFC 7292 Appendix B KDF, iterated hashing with byte arithmetic over the password, and protect it with 3DES or 40-bit RC2; implementing them would put secret-dependent code in TypeScript, which is the one thing this library exists without. It is a refusal, not a backlog — the full table of OIDs is in [SECURITY.md](../../SECURITY.md). A legacy file converts once, with OpenSSL 3.4 or later, in two commands verified against OpenSSL 4.0.0:

```sh
openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem
openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12
```

The key in `bundle.pem` stays encrypted under the passphrase you give, PBES2 with AES-256-CBC is already the default, and `bundle.pem` is yours to delete afterwards. A key alone converts with `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256`.

**Why most MACs cannot be verified, and what `allowUnverifiedIntegrity` trades.** A PKCS#12 MAC is how a reader knows the file was not altered by someone without the password. Every MAC OpenSSL wrote before 3.4, and most it still writes, is keyed with the same Appendix B KDF — so pkinative can verify only an RFC 9579 PBMAC1 MAC, which is what `-pbmac1_pbkdf2` writes. `openPkcs12` **fails closed**: a file whose integrity cannot be checked — an Appendix B MAC, no MAC at all, a PBMAC1 the host cannot run, or public-key integrity mode — is still read and its contents reported, but `valid` is `false` with `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`. [`OpenPkcs12Options`](../assets/api.json)'s `allowUnverifiedIntegrity: true` accepts it, and it is a decision about the file's origin: without a MAC, any bag that is not encrypted — a certificate, a CRL, a plain key — can be replaced by anyone who can write the file, and the certificate you would then sign under is theirs. Pass it only for a file you trust by other means. The [`OpenPkcs12Report`](../assets/api.json)'s `integrity` says what was established either way: `verified`, `unverified`, or `mismatch` — a PBMAC1 that does not match, a wrong password most likely, after which nothing is decrypted and the only reason is `PKI_REASON_PKCS12_MAC_MISMATCH`.

**The password is UTF-8.** A string is encoded as UTF-8, which is what OpenSSL and RFC 9579 use under PBES2 and PBMAC1. A file written with another encoding opens with the exact octets as a `Uint8Array`, which is used as given and never modified — it is yours to wipe. A string with a lone surrogate has no UTF-8 form and is refused with `PKI_API_MISUSE` rather than silently replaced. An empty string is a password; `undefined` is not, and `openPkcs12` throws `PKI_INVALID_OPTION` for it.

**Windows writes BER.** A `.pfx` exported by Windows uses indefinite lengths and segmented OCTET STRINGs; pass `encodingRules: 'ber'` to `openPkcs12` or `parsePkcs12` for it. Without it, the strict DER reader refuses the file, and `openPkcs12` reports that as `PKI_REASON_INPUT_MALFORMED` carrying the encoding code.

**The report, and what it never does.** `openPkcs12` resolves with the MAC checked where it can be, every SafeContents opened, every certificate parsed (`certificates`, the keys' own and any chain), every CRL bag's DER (`crls`), and `keys` — one [`Pkcs12Key`](../assets/api.json) per private key, in encoded order, with its `path`, `localKeyId`, `friendlyName`, matching `certificate` and `signingKey`, which is `undefined` when that key could not be opened. **It never rejects for a problem with the file**: one malformed certificate or one key under a refused scheme is a reason, and the rest is still read. It throws only for a call that could never succeed — no Web Crypto (`PKI_CRYPTO_UNAVAILABLE`), a missing password or a bad option, an unknown `limits` key, an input that is not a `Uint8Array`. Guard with `canDecrypt()`, which says whether `globalThis.crypto.subtle` offers every operation PBES2 and RFC 9579 need — not which ciphers: several browsers that answer `true` lack AES-192, and a file using it comes back as `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`. It reads quietly: nothing is printed, and the container's diagnostics are on `report.pkcs12.diagnostics`.

**The primitives underneath.** `parsePkcs12` needs no password: it returns a [`Pkcs12`](../assets/api.json) whose `contents` are [`SafeContentsInfo`](../assets/api.json) entries — `encrypted`, the `encryption` scheme and ciphertext, or the `bags` already read when the SafeContents is plain — and whose `mac` says `kind: 'pbmac1'` or `kind: 'pkcs12-kdf'`, or is `undefined`. `verifyPkcs12Mac(pkcs12, password)` checks a PBMAC1 and returns `true` or `false`, the two failures being indistinguishable; it throws `PKI_KEY_MAC_UNSUPPORTED` for an Appendix B MAC and `PKI_API_MISUSE` for a file with none, so check `pkcs12.mac` first. `openSafeContents(contents, password)` returns the [`SafeBag`](../assets/api.json)s of one entry, decrypting it when it is PBES2-encrypted; each bag has its `kind`, `friendlyName`, `localKeyId`, and `certificateDer`, `crlDer`, `encryptedKey` or `privateKey` by kind, and a `path` such as `authSafe[1].bags[0]`. Nested `safeContentsBag`s are flattened, and every bag counts against `maxPkcs12Bags`. The layer never parses a certificate for you — `certificateDer` goes to `parseCertificate` — and `decryptPrivateKey(bag.encryptedKey.der, { password, algorithm })` opens a key. Public-key privacy mode (`envelopedData`) is reported as encrypted with no password scheme and refused by `openSafeContents`; public-key integrity mode is refused by `parsePkcs12` with `PKI_KEY_MAC_UNSUPPORTED`.

**The file declares its own cost.** The PBKDF2 iteration count is the file's to declare and the host's to run, inside Web Crypto where no JavaScript bound reaches, so `maxKdfIterations` (10 000 000, about ten seconds of SHA-256) is checked before the host is asked for anything: a file declaring 2³¹ iterations is `PKI_LIMIT_EXCEEDED` — thrown by the primitives, reported by `openPkcs12` as `PKI_REASON_INPUT_MALFORMED` carrying that code — and not a frozen process. A file may declare thousands of derivations, so `maxPkcs12KdfIterations` (also 10 000 000) bounds what one PKCS#12 costs in total — its PBMAC1 MAC, every encrypted SafeContents and every shrouded key — checked by `parsePkcs12` over what it can see, by `openSafeContents` before it derives and over the keys it reveals, and by `openPkcs12` before each derivation it runs. A count below the 1 000 RFC 8018 recommends still opens, with `PKI_DIAG_KEY_KDF_ITERATIONS_LOW`: the count is what a stolen copy costs to brute-force.

**The three vocabularies, applied to keys.**

| Vocabulary | Codes | Raised by | Means |
|---|---|---|---|
| Thrown `PkiKeyError` | `PKI_KEY_STRUCTURE_INVALID`, `PKI_KEY_VERSION_UNSUPPORTED`, `PKI_KEY_ENCRYPTION_UNSUPPORTED`, `PKI_KEY_MAC_UNSUPPORTED` | the parsers, `importPrivateKey`, `decryptPrivateKey`, `verifyPkcs12Mac`, `openSafeContents` | The structure is not RFC 5958 or RFC 7292, or it is protected by something pkinative refuses; `path` and `offset` say where, and the message names the conversion |
| Thrown `PkiCryptoError` | `PKI_CRYPTO_DECRYPTION_FAILED` | `decryptPrivateKey`, `openSafeContents` | The file was readable and the host could not decrypt it: the password, the data, or the algorithm named |
| Emitted diagnostic | `PKI_DIAG_KEY_KDF_ITERATIONS_LOW` | the parsers, through `onDiagnostic` and `diagnostics` | A PBKDF2 count below 1 000; the file still opens |
| Returned reasons | `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`, `PKI_REASON_PKCS12_MAC_MISMATCH`, `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`, `PKI_REASON_PKCS12_DECRYPTION_FAILED`, `PKI_REASON_PKCS12_KEY_UNMATCHED`, `PKI_REASON_PKCS12_KEY_UNSUPPORTED`, `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` | `openPkcs12` | The file is readable, and something in it could not be opened or trusted |

**A `PkiKeyError` never means a wrong password** — only the host can find that out, and it says so as a `PkiCryptoError`. `PkiKeyErrorCode` is the union a `PkiKeyError` narrows `code` to.

`recipes/private-key.ts` reads, imports and decrypts PKCS#8 keys written by `node:crypto`, names the RSA algorithm, and refuses a 3DES and an Appendix C key by name; `recipes/pkcs12.ts` writes a PBMAC1 `.p12`, opens it in one call and with the primitives, signs with the key, and reads the unverifiable, the wrong-password and the legacy cases apart.

## What none of these do

Each of the cases above is complete. What is **not** here is deliberate, and the [comparison guide](choose.md) says what to use instead:

| You need | pkinative | Instead |
|---|---|---|
| Open a legacy PKCS#12 or PKCS#8 — RFC 7292 Appendix C ciphers, PBES1, an Appendix B MAC checked | never, by design: the Appendix B KDF is iterated hashing with byte arithmetic over the password, secret-dependent code this library will not write | `openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12`, once |
| Decide that a key is too small or a curve unacceptable | never, by design | one comparison on the parsed `subjectPublicKeyInfo`; that floor moves by CA/Browser Forum ballot and does not belong frozen in a library |
| A public suffix list, so that `*.co.uk` is refused | never, by design | a maintained PSL package; a parsing library carrying a stale copy is worse than one that says it does not know |

**Three separate questions, and you need all three.** A fingerprint proves two byte strings are the same certificate. A verified signature proves one key signed one set of bytes. A validated path proves a chain reaches something you trust — and still says nothing about *which host* the certificate is for or *what* it may be used for, which is why `checkServerName` and `checkExtendedKeyUsage` are separate calls rather than options. pkinative does not collapse them, and that distinction is the whole of the [security model](security.md).

How well the path validator actually agrees with the world is measured rather than asserted: every case of the x509-limbo corpus is scored on each release, every disagreement carries a written reason in `scripts/data/limbo-score.json`, and a reviewed subset is pinned on its `PkiReasonCode` — because *rejected for the wrong reason* is a defect no pass/fail count can see.
