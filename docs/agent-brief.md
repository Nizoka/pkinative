# pkinative — brief for AI coding agents

Paste this into a coding agent's context before it writes code that reads certificates with pkinative 0.1.

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
- Extensions: `getExtension(cert, kind)`. The kinds are exactly these 20, and no other value is valid: `authorityInfoAccess`, `authorityKeyIdentifier`, `basicConstraints`, `certificatePolicies`, `crlDistributionPoints`, `extendedKeyUsage`, `freshestCRL`, `inhibitAnyPolicy`, `issuerAltName`, `keyUsage`, `nameConstraints`, `ocspNoCheck`, `policyConstraints`, `policyMappings`, `signedCertificateTimestampList`, `subjectAltName`, `subjectInfoAccess`, `subjectKeyIdentifier`, plus `raw` (kept encoded because the parse ran with `decodeExtensions: false`) and `unknown` (an OID pkinative does not decode) — both carry `oid`, `critical` and `valueDer`.
- Names: `formatDistinguishedName(cert.subject)` gives the RFC 4514 string.
- Every field of `Certificate`, of `subjectPublicKeyInfo` (by `kind`: `rsa`, `ec`, `ed25519`, `ml-dsa-65`, …) and of each extension is in `docs/assets/api.json` (`members`) and in the quick start guide, section "What a certificate holds".

## Catch

Every failure is a `PkiError` subclass (`PkiEncodingError`, `PkiCertificateError`, `PkiLimitError`) with a stable `code`. Branch on `error.code`, never on the message. Codes and remedies: `docs/data/errors.json`.

## Diagnostics are not errors

Profile concerns (a long serial, an explicit DEFAULT, a non-critical name constraint) are diagnostics on `cert.diagnostics`, also passed to `onDiagnostic`. Use `strict: true` to refuse any certificate that has one. By default each code is logged with `console.warn`, once per code in each call; pass `onDiagnostic` to silence or redirect that.

## Do not

- Do not claim pkinative verifies signatures or validates chains: 0.1 parses only (verification arrives in 0.3, path validation in 0.5).
- Do not write RSA, ECDSA or other secret-dependent cryptography in TypeScript around it; use Web Crypto.
- Do not raise a limit (`options.limits`) for untrusted input.
- Do not install pkinative from npm or from a git URL (a git install carries no `dist/`): 0.2 is the release tarball, `npm install https://github.com/Nizoka/pkinative/releases/download/v0.2.0/pkinative-0.2.0.tgz`.
