# Quick start

> **Read a certificate in three calls, then learn the four things every pkinative call shares: strict DER, typed errors, diagnostics and limits.** Everything below runs on pkinative 0.3 as it is tested; every export named here is in `docs/assets/api.json`.

## Install

pkinative 0.3 is not on npm: install the tarball attached to the GitHub release, which a workflow builds, gates, installs as a test and attests:

```bash
npm install https://github.com/Nizoka/pkinative/releases/download/v0.7.0/pkinative-0.7.0.tgz
```

`gh attestation verify pkinative-0.7.0.tgz --repo Nizoka/pkinative` checks where the tarball was built. Node.js ≥ 22, browsers, Deno, Bun and Workers load the same build. There is no runtime dependency.

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

## What a certificate holds

Every field is listed with its type in `docs/assets/api.json` (the `members` of `Certificate` and of each extension interface); the ones you reach for first:

| Field | Holds |
|---|---|
| `der`, `tbsDer` | The whole certificate, and the `tbsCertificate` bytes its signature covers |
| `version` | `1`, `2` or `3` (the encoded INTEGER is 0, 1 or 2) |
| `serialNumber` | `{ bytes, hex, value }` — the content octets, their lowercase hex, and a `bigint` |
| `signatureAlgorithm`, `tbsSignatureAlgorithm` | `{ oid, parameters, der }`; RFC 5280 requires the two to be equal (a diagnostic says when they are not) |
| `signatureValue` | `{ bytes, unusedBits }` — the signature; `verifyCertificateSignature(cert, issuer)` checks it |
| `issuer`, `subject` | `{ rdns, der }`: each RDN a list of `{ type, value, valueDer }`, `value` a `{ stringType, value, raw }` string when the attribute is one |
| `validity` | `{ notBefore, notAfter }`, each `{ type, epochMilliseconds, text }` |
| `subjectPublicKeyInfo` | `{ kind, algorithm, publicKey, der, … }`, by `kind`: `rsa` and `rsa-pss` add `modulus`, `modulusBits`, `publicExponent`; `ec` adds `namedCurve`, `curve` (`P-256`, `P-384`, `P-521` or `undefined`), `pointFormat`, `point`; `ed25519`, `ed448`, `x25519`, `x448`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` add `key`; `unknown` adds nothing |
| `issuerUniqueId`, `subjectUniqueId` | `{ bytes, unusedBits }` or `undefined` |
| `extensions`, `diagnostics` | In encoded order, below |

The fields of the extensions `getExtension` returns:

| Kind | Fields |
|---|---|
| `basicConstraints` | `cA`, `pathLenConstraint` (`undefined` when absent) |
| `keyUsage` | `usages` (`digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`), `bits` |
| `extendedKeyUsage` | `purposes`: KeyPurposeId OIDs, e.g. `1.3.6.1.5.5.7.3.1` (serverAuth) |
| `subjectAltName`, `issuerAltName` | `names`: GeneralNames, by `kind` — `dNSName`, `rfc822Name`, `uniformResourceIdentifier` with `value`; `iPAddress` with `version`, `address`, `mask`, `bytes`; `directoryName` with `name`; `otherName` with `typeId`, `value`; `registeredID` with `oid`; `x400Address`, `ediPartyName` with `value` |
| `subjectKeyIdentifier` | `keyIdentifier` |
| `authorityKeyIdentifier` | `keyIdentifier`, `authorityCertIssuer`, `authorityCertSerialNumber` |
| `authorityInfoAccess`, `subjectInfoAccess` | `descriptions`: `{ accessMethod, accessLocation }` — `1.3.6.1.5.5.7.48.1` is OCSP, `1.3.6.1.5.5.7.48.2` CA issuers, the location a GeneralName (usually a `uniformResourceIdentifier`) |
| `crlDistributionPoints`, `freshestCRL` | `points`: `{ fullName, nameRelativeToCRLIssuer, reasons, cRLIssuer }` |
| `certificatePolicies` | `policies`: `{ policyIdentifier, qualifiers }`, a qualifier `cps` with `uri`, `userNotice` with `noticeRef` and `explicitText`, or `unknown` |
| `policyMappings` | `mappings`: `{ issuerDomainPolicy, subjectDomainPolicy }` |
| `policyConstraints` | `requireExplicitPolicy`, `inhibitPolicyMapping` |
| `inhibitAnyPolicy` | `skipCerts` |
| `nameConstraints` | `permittedSubtrees`, `excludedSubtrees`: `{ base, minimum, maximum }`, `base` a GeneralName (an `iPAddress` base carries its `mask`) |
| `signedCertificateTimestampList` | `list`: the RFC 6962 SCT list in its TLS encoding |
| `ocspNoCheck` | nothing beyond `oid`, `critical`, `valueDer` |

## Every extension, typed

`cert.extensions` lists every extension in encoded order, each with `oid`, `critical` and `valueDer`, and a `kind` that says how it was decoded: `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `subjectAltName`, `issuerAltName`, `subjectKeyIdentifier`, `authorityKeyIdentifier`, `nameConstraints`, `certificatePolicies`, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy`, `authorityInfoAccess`, `subjectInfoAccess`, `crlDistributionPoints`, `freshestCRL`, `signedCertificateTimestampList`, `ocspNoCheck` — or `unknown` for an extension pkinative does not decode. `getExtension(cert, kind)` returns the one of that kind, typed.

An inspection tool that must show a certificate even when one extension is malformed parses with `decodeExtensions: false` — every extension stays `kind: 'raw'` — and decodes what it needs with `decodeExtensionValue(oid, valueDer, { critical })`; `critical` (default `false`) is reported on the result and decides whether an unknown extension raises `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION`.

`computeFingerprint(der, algorithm)` takes `'SHA-1'`, `'SHA-256'`, `'SHA-384'` or `'SHA-512'` (anything else is `PKI_INVALID_OPTION`); `formatFingerprint(digest, { separator, letterCase })` writes `96:BC:EC:…` by default — `separator` defaults to `':'`, `letterCase` to `'upper'` (or `'lower'`), so `{ separator: '', letterCase: 'lower' }` gives the pinning form.

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

Nineteen named limits bound every loop over untrusted bytes. Tighten one for a context that expects small inputs, raise one only for input you trust:

```ts
parseCertificate(der, { limits: { maxExtensions: 32, maxGeneralNames: 100 } });
```

The [security guide](security.md) lists them with their defaults and CWE.

## Below the certificate: ASN.1 and OIDs

The layers the certificate parser stands on are public too. `decodeAsn1` decodes one DER value (BER with `encodingRules: 'ber'`) into frozen nodes that keep their exact bytes, and refuses anything after that value unless you pass `allowTrailingData: true`; typed readers turn a node into a value; the encoders emit DER only and refuse what DER cannot represent; `encodeAsn1Node` re-encodes a decoded tree to the exact input bytes:

```ts
import { decodeAsn1, encodeInteger, encodeObjectIdentifier, encodeSequence, getOidName, readInteger, readObjectIdentifier } from 'pkinative';

const der = encodeSequence([encodeObjectIdentifier('2.5.29.17'), encodeInteger(65537n)]);
const [oidNode, integerNode] = decodeAsn1(der).children;
readObjectIdentifier(oidNode);                 // '2.5.29.17'
getOidName('2.5.29.17');                       // 'subjectAltName'
readInteger(integerNode);                      // 65537n
```

A node is `{ tagClass, tagNumber, constructed, offset, headerLength, contentLength, indefinite, bytes, content, children }`: `tagClass` is `'universal'`, `'application'`, `'context'` or `'private'`, `bytes` the whole encoding and `content` the content octets, both views of the input. A reader accepts its universal tag or any implicit (non-universal) tag, which it reads as its own type; `readString` and `readTime` need the type of an implicit tag — `readString(node, { stringType: 'ia5' })`, `readTime(node, { timeType: 'GeneralizedTime' })` — and throw `PKI_API_MISUSE` without it.

The readers are `readBoolean`, `readInteger` (a bigint), `readSmallInteger` (a number), `readNull`, `readBitString`, `readOctetString`, `readObjectIdentifier`, `readString` (UTF8String, NumericString, PrintableString, TeletexString, IA5String, VisibleString, UniversalString, BMPString) and `readTime` (UTCTime and GeneralizedTime); ENUMERATED, REAL and RELATIVE-OID have none yet. For OIDs, `encodeOid` and `decodeOid` convert between dotted text and content octets, `isValidOid` checks a string, and `getOidName` names 300+ registered OIDs. `decodePem` returns blocks of `{ label, bytes, headers, offset }` — `headers` holds the RFC 1421 `[name, value]` pairs lax mode reads; it takes an optional `label` that every block must carry, and `mode: 'lax'` accepts whitespace around and inside the block, long lines and RFC 1421 headers, each reported once per call as a diagnostic. `OID_REGISTRY` entries are `{ oid, name, standard }`.

## Types you write

Most of what pkinative returns you never name: you reach it through a return value, and its fields are in `docs/assets/api.json`. These are the ones you may have to write down — in a signature, a variable annotation or an options object.

- **Certificate**: `DistinguishedName` (`subject`, `issuer`), `PkiTime` (both ends of `validity`), `Extension` (the union `certificate.extensions` holds) and `DecodedExtensionKind` (the argument `getExtension` takes).
- **ASN.1**: `Asn1Node` (what `decodeAsn1` returns and every reader takes), `TagClass` (`node.tagClass`, and the first argument of `encodeTlv`), `Asn1String` and `Asn1StringType` (what `readString` returns, and the eight types it can read), `BitString` (`readBitString`, `encodeBitString`, and `certificate.signatureValue`).
- **PEM**: `PemBlock` — what `decodePem` yields, and what `encodePem` reverses.
- **Fingerprints**: `FingerprintAlgorithm` — `'SHA-1'`, `'SHA-256'`, `'SHA-384'` or `'SHA-512'`.
- **Options**, one per function, each extending `PkiParseOptions` (which carries `limits`, `strict` and `onDiagnostic`): `ParseCertificateOptions`, `DecodeExtensionValueOptions`, `DecodeAsn1Options`, `DecodePemOptions`, `ReadStringOptions`, `ReadTimeOptions`, and `FormatFingerprintOptions`.

Error code unions are in the [errors guide](errors.md).

## Next

- [recipes/](../../recipes/) — 19 executable recipes: the quick start, the agent brief, a CA bundle, fingerprints, extensions on demand, ASN.1 and OIDs, the ASN.1 primitives, hostile input, signature verification, certificate and CSR creation, path validation, the one-call verification, server-name matching, extended key usage, revocation lists, OCSP, CMS signing and verification, an external signer, RFC 3161 timestamps.
- [Use cases](use-cases.md) — the jobs end to end, from a certificate inventory to a timestamped signature.
- [Conformance](conformance.md) — how pkinative is held to x509-limbo, Wycheproof and OpenSSL.
- [Choosing a library](choose.md) — when pkinative is the right tool, and when it is not yet.
