# Use cases

> **Eight jobs pkinative does today, with the code that does them and the guarantee behind each.** Four of them need no signature at all; the fifth checks one, the sixth writes one, the seventh validates a whole chain, and the eighth asks a revocation list about one certificate.

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
    <text x="704" y="82" fill="var(--c-success)">Certificate</text>
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
  <desc id="anatomy-desc">A Certificate value exposes tbsDer and signatureValue at the top level. Inside tbsCertificate sit the serial number, issuer, validity, subject, subjectPublicKeyInfo and extensions. Key pinning hashes subjectPublicKeyInfo.der; a fingerprint hashes the whole certificate DER; signature verification, arriving in 0.3, will read tbsDer and signatureValue.</desc>
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
    <text x="460" y="163" fill="var(--c-text-dim)" text-anchor="middle" font-size="11.5">twenty decoded kinds, or raw</text>

    <rect x="664" y="44" width="272" height="60" rx="8" fill="var(--c-surface)" stroke="var(--c-border)"/>
    <text x="800" y="70" fill="var(--c-text)" text-anchor="middle">signatureAlgorithm</text>
    <text x="800" y="90" fill="var(--c-text)" text-anchor="middle">signatureValue</text>

    <rect x="664" y="116" width="272" height="58" rx="8" fill="none" stroke="var(--c-text-muted)" stroke-dasharray="4 3"/>
    <text x="800" y="140" fill="var(--c-text-muted)" text-anchor="middle" font-size="11.5">tbsDer + signatureValue</text>
    <text x="800" y="158" fill="var(--c-text-muted)" text-anchor="middle" font-size="11.5">verified in 0.3, not today</text>

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

The job: mint a certificate or a PKCS#10 request from data you have, signed by a key your application already manages.

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

The description types are ordinary data, so a certificate can be built in one place and signed in another: [`CertificateDescription`](../assets/api.json), [`CertificationRequestDescription`](../assets/api.json), [`NameDescription`](../assets/api.json), [`NameAttribute`](../assets/api.json), [`ExtensionDescription`](../assets/api.json) and [`CreateOptions`](../assets/api.json) — the last carrying the same `limits` every other entry point takes, because an extension list assembled from attacker-supplied data is still a loop over untrusted input.

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

const report = validateCertificatePath({ certificates: chain, trustAnchors: roots, at: Date.now(), signatures });
if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
```

**It takes signature verdicts, not keys**, and three things follow. `validateCertificatePath` is **synchronous** — putting `subtle.verify` inside would make the whole state machine asynchronous, unfuzzable without a host, and would mix an I/O-shaped failure with a logical one. It is **pure** — it reads data and returns a verdict, reaching nothing. And the signatures get checked in parallel, before the walk.

**It never throws for a validation issue.** An empty chain, no trust anchor, no signature verdicts: each is an answer, in the report. Only misusing the API — an unknown key in `limits` — throws. That is the [third vocabulary](errors.md#three-vocabularies-three-questions) doing its job: primitives return and throw, compositions report.

**It reports every reason, not the first.** A certificate can be expired *and* issued by something that is not a CA, and a caller fixing one per round trip is a caller the report failed.

Two behaviours worth knowing before you wire it up:

- **The trust anchor does not have to be in the chain.** RFC 5280 §6.1.1 takes it as a separate input, so a chain that stops at the intermediate is anchored when that intermediate names a root you supplied. Most servers send it exactly that way.
- **A certificate with no signature verdict is `PKI_REASON_SIGNATURE_NOT_CHECKED`, never assumed valid.** A validator that read silence as success would pass whenever the caller forgot to verify anything. And `NOT_CHECKED` is not `INVALID`: a runtime without Ed448 says nothing about whether a signature is good.

The input is a [`PathValidationInput`](../assets/api.json) and the answer a [`PathValidationReport`](../assets/api.json); `maxChainLength` (default 10) bounds the walk and `maxPolicyNodes` (default 4 096) bounds the policy tree, which is the part of §6 that actually explodes combinatorially; `PKI_REASON_LIMIT_EXCEEDED` names whichever one stopped the search. `recipes/validate-path.ts` runs all of this on the real Let's Encrypt hierarchy.

**Certificate policies are off by default, and that is the right default.** `requireExplicitPolicy` is what turns policy processing into a verdict: without it, a path that establishes no policy is still valid, because §6.1.5 (a) says the question was never asked. Turning it on by default would reject most of the public web. When you do need it, `initialPolicySet` is your `user-initial-policy-set`, and `PKI_REASON_NO_VALID_POLICY` is the answer when nothing survives.

**What it refuses rather than ignores.** RFC 5280 §6.1.3 (f) requires a verifier to refuse a critical extension it does not process, and `PROCESSED_CRITICAL_EXTENSIONS` is the exact boundary of what a chain may rely on: `basicConstraints`, `keyUsage`, `subjectAltName`, `nameConstraints`, `certificatePolicies`, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy` and `extKeyUsage`. Anything else marked critical comes back `PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION` — including `cRLDistributionPoints`, until revocation lands. That is the correct answer rather than a placeholder: a validator that ignored a constraint it had not implemented would answer "valid" for a chain the issuing CA forbade, which is the shape of a CVE rather than a missing feature.

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

`crl.crlNumber` and `crl.isDelta` are read from `cRLNumber` and `deltaCRLIndicator`; a **delta CRL is not a full one**, and treating it as complete would report every certificate absent from it as unrevoked.

The envelope is a [`CertificateList`](../assets/api.json), an entry is a [`RevokedCertificate`](../assets/api.json) carrying its `reason` as a [`CrlReason`](../assets/api.json) and its `invalidityDate`, and `maxRevokedCertificates` is the bound on the walk.

### The decision, and the four answers it keeps apart

`findRevocation` says whether a serial is on a list. It does not say whether that list was entitled to answer, or whether it is current. `checkRevocation` does:

```ts
import { checkRevocation, parseCertificateList, verifyCrlSignature } from 'pkinative';

const crl = parseCertificateList(crlDer);
const signatureVerified = await verifyCrlSignature(crl, caCertificate);
const reasons = checkRevocation({ certificate, crl, crlDer, at: Date.now(), signatureVerified });
```

It takes a `signatureVerified` boolean rather than a key, which is what keeps it **synchronous and free of Web Crypto** — the same separation §6 makes. Its input is a [`RevocationCheckInput`](../assets/api.json), and it returns `PkiReason`s:

| Answer | Meaning |
|---|---|
| `[]` | Not revoked, by a list entitled to say so and current enough to believe |
| `PKI_REASON_REVOKED` | Listed — and the message carries the date, because a signature made before it may still be good |
| `PKI_REASON_REVOCATION_STALE` | No `nextUpdate`, or it has passed beyond your `staleTolerance` |
| `PKI_REASON_REVOCATION_WRONG_ISSUER` | The list names another CA, compared by encoded name |
| `PKI_REASON_REVOCATION_UNKNOWN` | No evidence either way |

**`UNKNOWN` is not `[]`, and that distinction is the point.** A missing or unsigned list is an absence of evidence. Reporting it as "not revoked" would make the soft-fail decision on your behalf, invisibly. If you want soft-fail, you write it — `staleTolerance` is the same idea for a lapsed list: a number you chose, not a default that chose for you.

A list with **no `nextUpdate` at all is stale**, not current. RFC 5280 §5.1.2.5 makes the field optional and tells CAs to include it; nothing asserts such a list is still good.

And a revocation found on a stale list from the wrong CA is **still reported**. Hiding it behind an earlier failure would be the one direction of error that matters.

## What none of these do yet

Each of the eight is complete. What is **not** here is deliberate, and the [comparison guide](choose.md) says what to use meanwhile:

| You need | pkinative | Until then |
|---|---|---|
| Name constraints and certificate policies in a chain | 0.5, and refused rather than ignored until then | pkijs; on Node.js, your TLS stack |
| Know whether a certificate is revoked | 0.5, CRL and OCSP | pkijs |

A fingerprint proves two byte strings are the same certificate. A verified signature proves one key signed one set of bytes. **Neither proves a certificate should be trusted** — that needs a trust anchor, a validity window, name constraints, policies and revocation, which is RFC 5280 §6 and arrives in 0.5. pkinative does not pretend otherwise, and that distinction is the whole of the [security model](security.md).
