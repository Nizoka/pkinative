# Migrating from node-forge or pkijs

> **What each node-forge or pkijs call becomes in pkinative, what changes shape on the way — a report with reason codes where there was a boolean or an exception — and what has no counterpart, by design.**

The node-forge and pkijs names below were read in the published packages, node-forge 1.4.3 and pkijs 4.0.1, on 2026-11-23; the pkinative code on this page runs on every test run.

## Three differences that are not renames

- **Bytes in, frozen values out.** pkinative takes a `Uint8Array` of DER and returns frozen plain objects that hold views of it. PEM is a step of its own, `decodePem`. node-forge works on binary strings and its own ASN.1 objects; pkijs takes a `BufferSource` and returns class instances built over asn1js.
- **A report, not a boolean.** `verifyCertificateChain`, `verifySignedData`, `verifyTimeStampToken`, `verifyCertificationRequest` and `openPkcs12` resolve with `{ valid, reasons }` — every reason at once, each a stable `PKI_REASON_…` code with the path of what it is about — and throw only for a call that is itself wrong. The [errors guide](errors.md) lists the codes.
- **No key is made or kept here.** A signature is one Web Crypto call with a key you hold, or with an `ExternalSigner` for a key in an HSM. Generating a key, exporting one and encrypting with one stay in your code, through Web Crypto or `node:crypto`: see [what has no counterpart](#what-has-no-counterpart-by-design).

## From node-forge

| You call (node-forge 1.4.3) | In pkinative | What changes |
|---|---|---|
| `forge.pki.certificateFromPem(pem)` | `decodePem(pemText, { label: 'CERTIFICATE' })`, then `parseCertificate(block.bytes)` | Every key type is read — node-forge's reader throws on a certificate whose key is not RSA — and every extension is typed |
| `forge.asn1.fromDer(bytes)`, then `forge.pki.certificateFromAsn1(obj)` | `parseCertificate(der)` | One call; `decodeAsn1(der)` when you want the tree itself |
| `forge.pki.createCaStore(certs)`, then `forge.pki.verifyCertificateChain(caStore, chain, options)` | `verifyCertificateChain({ leaf, candidates, trustAnchors })` | The path is built from candidates in any order; revocation, policies, purposes and the server name are options of the same call; the answer is a report |
| `forge.pki.certificationRequestFromPem(pem)`, then `csr.verify()` | `parseCertificationRequest(der)`, then `verifyCertificationRequest(request)` | A report; the extensions the request asks for are typed |
| `forge.pki.createCertificate()` … `cert.sign(key, md)` | `createCertificate(description, signer)` | The signer is a Web Crypto key with its algorithm. `cert.sign(key)` without a digest signs with SHA-1 |
| `forge.pki.createCertificationRequest()` … `csr.sign(key, md)` | `createCertificationRequest(description, signer)` | The same, and the same SHA-1 default on the node-forge side |
| `forge.pkcs7.messageFromPem(pem)`, `forge.pkcs7.messageFromAsn1(obj)` | `parseSignedData(der)` | SignedData only |
| `forge.pkcs7.createSignedData()` … `p7.sign()` | `createSignedData({ content, certificate, detached }, signer)` | One call, attached or detached |
| `message.verify()` on a SignedData, which throws `PKCS#7 signature verification not yet implemented.` | `verifySignedData({ signedData, content, trustAnchors })` | Implemented: every signer, its chain, its timestamp when there is one |
| `forge.pkcs12.pkcs12FromAsn1(obj, password)`, then `p12.getBags(filter)` | `openPkcs12(p12Bytes, { password })` | PBES2 files only; a key comes out as a non-extractable `CryptoKey`, never as numbers |
| `forge.pki.privateKeyFromPem(pem)`, `forge.pki.decryptRsaPrivateKey(pem, password)` | `decodePem`, then `importPrivateKey(der, options)` | A PKCS#8 key, RSA or not, becomes a non-extractable handle for Web Crypto; an `RSA PRIVATE KEY` block is PKCS#1, to convert once (`openssl pkcs8 -topk8 -in rsa.pem -out pkcs8.pem`) |

node-forge 1.4.3 has no module for CRLs, OCSP or RFC 3161 timestamps; in pkinative they are `parseCertificateList` and `checkRevocation`, `createOcspRequest`, `parseOcspResponse` and `checkOcspStatus`, `createTimeStampRequest` and `verifyTimeStampToken` — or the `crls` and `ocspResponses` of `verifyCertificateChain`, which composes them.

Reading a certificate, before and after:

```ts
import { decodePem, formatDistinguishedName, parseCertificate } from 'pkinative';

// const cert = forge.pki.certificateFromPem(pemText);
const [block] = decodePem(pemText, { label: 'CERTIFICATE' });
const cert = parseCertificate(block.bytes);

formatDistinguishedName(cert.subject);   // the subject, as text
cert.subjectPublicKeyInfo.kind;          // 'rsa', 'ec', 'ed25519', 'ml-dsa-65', …
```

A chain, before and after:

```ts
import { verifyCertificateChain } from 'pkinative';

// forge.pki.verifyCertificateChain(forge.pki.createCaStore(roots), chain)
const report = await verifyCertificateChain({ leaf, candidates, trustAnchors: roots });
if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
```

## From pkijs

| You call (pkijs 4.0.1) | In pkinative | What changes |
|---|---|---|
| `pkijs.Certificate.fromBER(raw)` | `parseCertificate(der)` | Strict DER: an encoding DER does not allow is refused with a typed error, not read |
| `certificate.verify(issuerCertificate)` | `verifyCertificateSignature(certificate, issuer)` | The same boolean — and, as there, a signature is not a chain |
| `new pkijs.CertificateChainValidationEngine({ certs, trustedCerts, crls, ocsps, checkDate })`, then `.verify()` | `verifyCertificateChain({ leaf, candidates, trustAnchors, crls, ocspResponses, at })` | `crls` and `ocspResponses` are DER bytes, `at` is milliseconds since the epoch; `{ result, resultCode, resultMessage }` becomes `{ valid, reasons }` |
| `pkijs.CertificationRequest.fromBER(raw)`, then `.verify()` | `parseCertificationRequest(der)`, then `verifyCertificationRequest(request)` | A report |
| `pkijs.ContentInfo.fromBER(raw)`, `new pkijs.SignedData({ schema: contentInfo.content })`, then `.verify({ signer, data, trustedCerts, checkChain })` | `verifySignedData({ signedData, content, trustAnchors })` | Every signer is judged in one call, with its chain; `report.signers` has each verdict |
| `signedData.sign(privateKey, signerIndex, hashAlgorithm, data)` | `createSignedData({ content, certificate, detached }, signer)` | One call returns the DER |
| `pkijs.CertificateRevocationList.fromBER(raw)`, `crl.verify({ issuerCertificate })`, `crl.isCertificateRevoked(certificate)` | `parseCertificateList(der)`, `verifyCrlSignature(crl, issuer)`, `checkRevocation({ certificate, crl, crlDer, at, signatureVerified })` | Scope, freshness and delta lists are decided too, as reasons |
| `ocspRequest.createForCertificate(certificate, { issuerCertificate, hashAlgorithm })` | `createOcspRequest(certificate, issuer)` | Returns the DER to send |
| `pkijs.OCSPResponse.fromBER(raw)`, then `.getCertificateStatus(certificate, issuerCertificate)` | `parseOcspResponse(der)`, then `checkOcspStatus({ response, expected, at, … })` | `{ isForCertificate, status }` becomes reasons: revoked, unknown, stale, not about this certificate |
| `pkijs.PFX.fromBER(raw)`, then `.parseInternalValues({ password, checkIntegrity })` | `openPkcs12(p12Bytes, { password })` | Integrity is checked unless you say otherwise; keys come out as non-extractable `CryptoKey`s |
| `pkijs.TimeStampResp.fromBER(raw)`, then `.verify({ data, trustedCerts })` | `verifyTimeStampToken({ response, data, trustAnchors })` | The TSA's chain and its `timeStamping` purpose are part of the verdict |
| `pkijs.AttributeCertificateV2.fromBER(raw)` | `parseAttributeCertificate(der)`, then `verifyAttributeCertificateSignature(ac, issuer)` | Attributes and extensions typed; the signature can be checked |
| `pkijs.setEngine(name, crypto)` | nothing | pkinative calls the host's Web Crypto; there is no engine to set |

pkijs 4.0.1 installs three dependencies and asks for asn1js as a peer; pkinative installs nothing else.

A CMS signature, before and after:

```ts
import { verifySignedData } from 'pkinative';

// const signedData = new pkijs.SignedData({ schema: pkijs.ContentInfo.fromBER(p7s).content });
// const ok = await signedData.verify({ signer: 0, data: signedContent, trustedCerts: roots, checkChain: true });
const report = await verifySignedData({ signedData: p7s, content: signedContent, trustAnchors: roots });
if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
```

A PKCS#12, before and after:

```ts
import { openPkcs12 } from 'pkinative';

// const pfx = pkijs.PFX.fromBER(p12Bytes); await pfx.parseInternalValues({ password, checkIntegrity: true });
// An rsaEncryption key needs its scheme named: the file does not say it, and pkinative does not guess.
const report = await openPkcs12(p12Bytes, { password, rsaAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } });
if (!report.valid) throw new Error(report.reasons.map((r) => `${r.code} at ${r.path}`).join('; '));
const [{ signingKey, certificate }] = report.keys;
console.log(certificate !== undefined, signingKey !== undefined);
```

## What has no counterpart, by design

Each of these is a recorded decision; [Choosing a library and a surface](choose.md) gives the record behind each one.

| You use | In pkinative | Instead |
|---|---|---|
| Key generation — `forge.pki.rsa.generateKeyPair(…)` | Refused in every version: no key is generated or exported here | `crypto.subtle.generateKey` in your own code, where it is visible |
| RSA, ciphers and TLS written in JavaScript — the rest of node-forge | None: pkinative holds no arithmetic on a secret | Web Crypto, `node:crypto`, `node:tls` |
| CMS EnvelopedData and EncryptedData | SignedData only | Keep the library you have for that part, or OpenSSL |
| A legacy PKCS#12 — RC2, 3DES, the RFC 7292 Appendix B MAC | Refused: PBES2 files only | Convert it once with OpenSSL: the two commands are in [the other guide](choose.md#what-it-does-not-do-by-design) |
| Writing a PKCS#12 or a PKCS#8 | Not written | Web Crypto or `node:crypto`, or OpenSSL |
| Fetching a CRL, an OCSP response or a timestamp | The engine does no I/O | Fetch the bytes yourself and pass them |

## Migrating in parts

Nothing requires one step. pkinative has no dependency and no global state, so it sits beside the library you have: move the reading of untrusted input first — the parser is where the advisories are — then the verdicts, and keep the other library for what the table above leaves to it. The boundary between the two is DER bytes: what one writes, the other reads.
