# pkinative — brief for AI coding agents

Paste this into a coding agent's context before it writes code that reads, builds or verifies certificates, paths, CMS messages or timestamps, or opens private keys and PKCS#12 files, with pkinative.

## Import

One entry point, no subpaths: import every name from `'pkinative'`. Every export, its module, signature and thrown error classes are in `docs/assets/api.json` — check a name there before using it; never invent one.

## Read a certificate

```ts
import { decodePem, getExtension, parseCertificate } from 'pkinative';

export function hostNames(pemText: string): string[] {
    const names: string[] = [];
    for (const { bytes } of decodePem(pemText, { label: 'CERTIFICATE' })) {
        const cert = parseCertificate(bytes);
        for (const name of getExtension(cert, 'subjectAltName')?.names ?? []) {
            if (name.kind === 'dNSName') names.push(name.value);
        }
    }
    return names;
}
```

- `parseCertificate` takes DER bytes (`Uint8Array`), never PEM text. There is no `parsePemCertificates`: compose `decodePem` and `parseCertificate`.
- Pass `label: 'CERTIFICATE'` so a private key in the same text is refused (`PKI_PEM_UNEXPECTED_LABEL`).
- Results are frozen and hold views of the input: do not mutate the input bytes afterwards.
- Times are `epochMilliseconds` numbers; serial numbers are `{ bytes, hex, value: bigint }`.
- Extensions: `getExtension(cert, kind)`. The kinds are exactly these 21, and no other value is valid: `authorityInfoAccess`, `authorityKeyIdentifier`, `basicConstraints`, `certificatePolicies`, `crlDistributionPoints`, `extendedKeyUsage`, `freshestCRL`, `inhibitAnyPolicy`, `issuerAltName`, `keyUsage`, `nameConstraints`, `ocspNoCheck`, `policyConstraints`, `policyMappings`, `signedCertificateTimestampList`, `subjectAltName`, `subjectDirectoryAttributes`, `subjectInfoAccess`, `subjectKeyIdentifier`, plus `raw` (kept encoded because the parse ran with `decodeExtensions: false`) and `unknown` (an OID pkinative does not decode) — both carry `oid`, `critical` and `valueDer`.
- Names: `formatDistinguishedName(cert.subject)` gives the RFC 4514 string.
- Every field of `Certificate`, of `subjectPublicKeyInfo` (by `kind`: `rsa`, `ec`, `ed25519`, `ml-dsa-65`, …) and of each extension is in `docs/assets/api.json` (`members`) and in the quick start guide, section "What a certificate holds".

## Catch

Every thrown failure is a `PkiError` or one of its six subclasses — `PkiEncodingError`, `PkiCertificateError`, `PkiLimitError`, `PkiCryptoError` (a verification or decryption that could not run — never one that failed), `PkiCmsError`, `PkiKeyError` — with a stable `code`. Branch on `error.code`, never on the message. Codes and remedies: `docs/data/errors.json`. The one-call verdicts (`verifyCertificateChain`, `verifySignedData`, `verifyTimeStampToken`, `openPkcs12`) do not throw for a problem with their input: they return reasons (`PKI_REASON_*`, `docs/data/reasons.json`).

## Diagnostics are not errors

Profile concerns (a long serial, an explicit DEFAULT, a non-critical name constraint) are diagnostics on `cert.diagnostics`, also passed to `onDiagnostic`. Use `strict: true` to refuse any certificate that has one. By default each code is logged with `console.warn`, once per code in each call; pass `onDiagnostic` to silence or redirect that.

## Signed messages and timestamps

- Verify a CMS `SignedData` (a `.p7s`, S/MIME, a PDF `/Contents`) with `verifySignedData({ signedData, content, trustAnchors })`; pass `contentDigest` instead of `content` for a PDF `/ByteRange` digest, and neither for attached content. It returns a report and never throws for bad input. `report.valid` means unaltered **and** trusted; `report.signers[i].intact` means unaltered only.
- Sign with `createSignedData(input, signer)`. The signer is a `SigningKey` (`{ key: CryptoKey, algorithm }`) or an `ExternalSigner`, whose `produceSignature` is given the exact bytes to sign and returns what `crypto.subtle.sign` would — raw `r ‖ s` for ECDSA, never DER.
- Timestamp a signature: hash the `SignerInfo`'s `signature` value (not the document), `createTimeStampRequest(hash, { nonce })` with a random nonce you generate, `parseTimeStampResponse`, then `addTimeStampToken(p7s, 0, response.tokenDer)`. Check a token alone with `verifyTimeStampToken({ token, request, trustAnchors })`.
- `atTimeStamp: true` judges each signer's chain at the time its verified timestamp proves; the TSA's own chain is still judged at `at`. Never use `signingTime` as proof of time: only the signer vouches for it.
- `parseSignedData` throws `PkiCmsError` (codes `PKI_CMS_*`, with `path`); the verifiers return `PKI_REASON_CMS_*` and `PKI_REASON_TSP_*` reasons instead.

## Private keys and PKCS#12

- Open a `.p12`/`.pfx` with `openPkcs12(bytes, { password })`; sign with `report.keys[i].signingKey`, a non-extractable `CryptoKey` whose algorithm comes from the certificate sharing the key's `localKeyId` (an RSA key needs `rsaAlgorithm` — there is no default, and without it the key stays shut with `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`). It returns a report and never throws for the file. `valid` is false with `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` for the common RFC 7292 Appendix B MAC, which pkinative never computes; pass `allowUnverifiedIntegrity: true` only for a file whose origin you trust.
- A PKCS#8 key: `importPrivateKey(der)` for `PRIVATE KEY` (an RSA key needs `{ algorithm }`), `decryptPrivateKey(der, { password, algorithm })` for `ENCRYPTED PRIVATE KEY` — `algorithm` is always required there, because the host unwraps the key without pkinative ever seeing its plaintext. `parsePrivateKeyInfo` and `parseEncryptedPrivateKeyInfo` describe a key file (type, curve, `encryption.scheme`) before any password.
- Only PBES2 with PBKDF2 and AES-CBC opens. Anything else throws `PkiKeyError` `PKI_KEY_ENCRYPTION_UNSUPPORTED` naming the scheme and the `openssl` conversion; do not write a 3DES, RC2 or Appendix B fallback. A wrong password is `PkiCryptoError` `PKI_CRYPTO_DECRYPTION_FAILED`, never a `PkiKeyError`. A string password is UTF-8; pass a `Uint8Array` for another encoding. Check `canDecrypt()` first.

## Do not

- Do not treat a verified signature as a trusted certificate. `verifyCertificateSignature` checks **one signature against one issuer**; a trust anchor, a validity window, name constraints, policies and revocation are RFC 5280 §6, and `verifyCertificateChain` is the call that judges them. Saying otherwise is an authentication bypass.
- Do not write RSA, ECDSA or other secret-dependent cryptography in TypeScript around it; use Web Crypto. pkinative generates and exports no key: `createCertificate` takes a SubjectPublicKeyInfo in DER and a private `CryptoKey` it only hands to `subtle.sign`, so the one `crypto.subtle.exportKey('spki', …)` call is yours to write.
- Do not raise a limit (`options.limits`) for untrusted input.
- Do not report `verifySignerInfoSignature`'s `true` as the verdict on a message: it checks one key against the signed attributes, and reads no content digest, no signer identifier and no chain. `verifySignedData` is the verdict.
- Do not install pkinative from a git URL (a git install carries no `dist/`): install it from npm, `npm install pkinative`; `npm audit signatures` verifies its registry signature and provenance.
