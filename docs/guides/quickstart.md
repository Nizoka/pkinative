# Quick start

> **Read a certificate in three calls, then learn the four things every pkinative call shares: strict DER, typed errors, diagnostics and limits.** Everything below runs on pkinative 0.1 as it is tested; every export named here is in `docs/assets/api.json`.

## Install

pkinative 0.1 is not on npm: install the tarball attached to the GitHub release, which a workflow builds, gates, installs as a test and attests:

```bash
npm install https://github.com/Nizoka/pkinative/releases/download/v0.1.0/pkinative-0.1.0.tgz
```

`gh attestation verify pkinative-0.1.0.tgz --repo Nizoka/pkinative` checks where the tarball was built. Node.js ≥ 22, browsers, Deno, Bun and Workers load the same build. There is no runtime dependency.

## Read a certificate

A certificate usually arrives as PEM text. `decodePem` returns its blocks, and the `label` option refuses any block that is not a certificate — a private key pasted into the same file is an error, not a certificate:

```ts
import { decodePem, formatDistinguishedName, getExtension, parseCertificate } from 'pkinative';

const [block] = decodePem(pemText, { label: 'CERTIFICATE' });
const cert = parseCertificate(block.bytes);

formatDistinguishedName(cert.subject);            // 'CN=letsencrypt.org'
cert.serialNumber.hex;                            // '0543933be386b3a2b3add534f2103bc8b65f'
new Date(cert.validity.notAfter.epochMilliseconds);
getExtension(cert, 'subjectAltName')?.names;      // [{ kind: 'dNSName', value: 'cp.letsencrypt.org', … }, …]
getExtension(cert, 'basicConstraints')?.cA;       // false
```

`parseCertificate` takes DER bytes. The result is frozen and holds zero-copy views of your input, so do not mutate the bytes while you use it (pass `bytes.slice()` to decouple). Times are `epochMilliseconds` numbers, exact from year 0000 to 9999.

## Every extension, typed

`cert.extensions` lists every extension in encoded order, each with `oid`, `critical` and `valueDer`, and a `kind` that says how it was decoded: `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `subjectAltName`, `issuerAltName`, `subjectKeyIdentifier`, `authorityKeyIdentifier`, `nameConstraints`, `certificatePolicies`, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy`, `authorityInfoAccess`, `subjectInfoAccess`, `crlDistributionPoints`, `freshestCRL`, `signedCertificateTimestampList`, `ocspNoCheck` — or `unknown` for an extension pkinative does not decode. `getExtension(cert, kind)` returns the one of that kind, typed.

An inspection tool that must show a certificate even when one extension is malformed parses with `decodeExtensions: false` — every extension stays `kind: 'raw'` — and decodes what it needs with `decodeExtensionValue(oid, valueDer)`.

## Diagnostics: what real issuers get wrong

A structural violation throws; a profile violation that real issuers commit is a diagnostic. Diagnostics are recorded on `cert.diagnostics`, each with a `code`, the RFC section it cites, a `path` and an `offset`:

```ts
const cert = parseCertificate(der, { onDiagnostic: (d) => log(d.code, d.path, d.standard) });
cert.diagnostics;   // the same list, in order
```

By default each code is also written to `console.warn`, once per code in each call; `onDiagnostic` replaces that, and `strict: true` turns the first diagnostic into a thrown `PkiError` with code `PKI_STRICT_DIAGNOSTIC` — the choice for a verifier that accepts only clean certificates.

## Errors: branch on the code

Every failure is a `PkiError` subclass with a stable `code`, a message that starts with `pkinative: ` and names the remedy, and — for certificates — the `path` and `offset` of the offending field:

```ts
import { parseCertificate, PkiCertificateError, PkiError, PkiLimitError } from 'pkinative';

try {
    parseCertificate(der);
} catch (error) {
    if (error instanceof PkiLimitError) console.error(error.limit, error.configured, error.observed);
    else if (error instanceof PkiCertificateError) console.error(error.code, error.path, error.offset);
    else if (error instanceof PkiError) console.error(error.code);
    else throw error;
}
```

Never branch on the message. The [error guide](errors.md) lists every code with its cause and remedy.

## Limits

Eleven named limits bound every loop over untrusted bytes. Tighten one for a context that expects small inputs, raise one only for input you trust:

```ts
parseCertificate(der, { limits: { maxExtensions: 32, maxGeneralNames: 100 } });
```

The [security guide](security.md) lists them with their defaults and CWE.

## Below the certificate: ASN.1 and OIDs

The layers the certificate parser stands on are public too. `decodeAsn1` decodes one DER value (BER with `encodingRules: 'ber'`) into frozen nodes that keep their exact bytes; typed readers turn a node into a value; the encoders emit DER only and refuse what DER cannot represent; `encodeAsn1Node` re-encodes a decoded tree to the exact input bytes:

```ts
import { decodeAsn1, encodeInteger, encodeObjectIdentifier, encodeSequence, getOidName, readInteger, readObjectIdentifier } from 'pkinative';

const der = encodeSequence([encodeObjectIdentifier('2.5.29.17'), encodeInteger(65537n)]);
const [oidNode, integerNode] = decodeAsn1(der).children;
readObjectIdentifier(oidNode);                 // '2.5.29.17'
getOidName('2.5.29.17');                       // 'subjectAltName'
readInteger(integerNode);                      // 65537n
```

The readers are `readBoolean`, `readInteger` (a bigint), `readSmallInteger` (a number), `readNull`, `readBitString`, `readOctetString`, `readObjectIdentifier`, `readString` (UTF8String, NumericString, PrintableString, TeletexString, IA5String, VisibleString, UniversalString, BMPString) and `readTime` (UTCTime and GeneralizedTime); ENUMERATED, REAL and RELATIVE-OID have none yet. For OIDs, `encodeOid` and `decodeOid` convert between dotted text and content octets, `isValidOid` checks a string, and `getOidName` names 300+ registered OIDs. `decodePem` takes an optional `label` that every block must carry, and `mode: 'lax'` accepts whitespace, long lines and RFC 1421 headers, each reported once per call as a diagnostic.

## Next

- [recipes/](../../recipes/) — six executable recipes: the quick start, a CA bundle, fingerprints, extensions on demand, ASN.1 and OIDs, hostile input.
- [Conformance](conformance.md) — how pkinative is held to x509-limbo, Wycheproof and OpenSSL.
- [Choosing a library](choose.md) — when pkinative is the right tool, and when it is not yet.
