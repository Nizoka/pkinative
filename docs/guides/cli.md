# pkinative-cli — Command-line reference

> **pkinative-cli 1.0.0 puts the whole pkinative engine on the command line: 18 commands, offline, with a stable `--json` contract for scripts, CI and AI agents.** It pins pkinative ^1.0.0, its only runtime dependency.

[pkinative-cli](https://github.com/Nizoka/pkinative-cli) is a thin, strict front end over pkinative. Every PKI decision — parsing, path validation, revocation, signature verification, CMS, timestamps, key import — is the engine's; the CLI adds what a library deliberately does not do: it reads files and stdin, tells PEM from DER, bounds every read, turns options into flags, writes artefacts safely, renders reports, and maps every failure to one of 13 stable error classes while carrying the engine's `PKI_*` code verbatim. Its 18 commands reach every runtime export of pkinative 1.0.0 (117: 104 functions, the 7 classes of the `PkiError` family, 6 constants), and a test in the CLI repository proves it.

| Command | Subcommands | Engine API behind it |
|---|---|---|
| `pem` | `decode`, `encode` | `decodePem`, `encodePem` |
| `oid` | `name`, `encode`, `decode`, `validate`, `list` | `getOidName`; `encodeOid`, `encodeObjectIdentifier`, `encodeRelativeOid`; `decodeOid`, `readObjectIdentifier`, `readRelativeOid`; `isValidOid`; `OID_REGISTRY` |
| `fingerprint` | — | `computeFingerprint`, `computeFingerprintAsync` (`--webcrypto`), `formatFingerprint`, `computeKeyIdentifier` (`--key-id`), `shake256` (`--shake256`) |
| `asn1` | `decode`, `encode` | `decodeAsn1`, `decodeAsn1Sequence`, the eleven `read*` readers, `encodeAsn1Node`; the `encode*` builders (`encodeSequence`, `encodeInteger`, `encodeTime`, …) |
| `cert` | `inspect`, `create`, `encode`, `decode-extension`, `verify-signature`, `check-name`, `match-name`, `check-purpose` | `parseCertificate`, `getExtension`, `formatDistinguishedName`; `createCertificate`; the X.509 encoders (`encodeDistinguishedName`, `encodeSubjectAltName`, `encodeSignatureAlgorithm`, …); `decodeExtensionValue`; `verifyCertificateSignature`, `verifySelfSignature`; `checkServerName`; `matchDnsName`; `checkExtendedKeyUsage` |
| `csr` | `inspect`, `create`, `verify` | `parseCertificationRequest`, `createCertificationRequest`, `verifyCertificationRequest` |
| `chain` | `verify`, `build`, `validate` | `verifyCertificateChain`; `buildCertificatePath`; `validateCertificatePath`, with `verifyCertificateSignature` on each link |
| `crl` | `inspect`, `find`, `verify-signature`, `check` | `parseCertificateList`, `findRevocation`, `verifyCrlSignature`, `checkRevocation` |
| `ocsp` | `request`, `cert-id`, `inspect`, `verify-signature`, `check` | `createOcspRequest`, `encodeOcspCertId`, `parseOcspResponse`, `verifyOcspSignature`, `checkOcspStatus` |
| `cms` | `sign`, `verify`, `inspect`, `verify-signer`, `add-attribute`, `add-timestamp` | `createSignedData`, `verifySignedData`, `parseSignedData`, `verifySignerInfoSignature`, `addUnsignedAttribute`; `addTimeStampToken` after `verifyTimeStampToken` |
| `tsp` | `request`, `inspect`, `verify` | `createTimeStampRequest`; `parseTimeStampResponse`, `parseTimeStampToken`, `parseTstInfo`; `verifyTimeStampToken` |
| `key` | `inspect`, `check` | `parsePrivateKeyInfo`, `parseEncryptedPrivateKeyInfo`; `importPrivateKey`, `decryptPrivateKey` |
| `p12` | `inspect`, `verify-mac`, `bags`, `open` | `parsePkcs12`, `verifyPkcs12Mac`, `openSafeContents`, `openPkcs12` |
| `doctor` | — | `canVerify`, `canSign`, `canDecrypt`, plus the Node.js and engine version checks |
| `limits` | — | `DEFAULT_PKI_LIMITS` |
| `explain` | — | the error, reason and diagnostic registries of the pinned pkinative release |
| `schema` | — | — (the CLI's own JSON Schemas, draft 2020-12, and its capability manifest) |
| `completion` | — | — (generated from the same command registry as `--help`) |

That is 53 invocations: 47 subcommands and the 6 commands that take none. The CLI repository's knowledge base maps every engine export to the invocations that reach it.

## Installation

```bash
npm install --global pkinative-cli
pkinative doctor
```

The binary is `pkinative`. It runs on Node.js `^22.22.2 || ^24.14.1 || >=25.8.2` — the first releases that fix CVE-2026-21713, a variable-time PKCS#12 MAC comparison in Web Crypto — and `pkinative doctor` checks that floor. The package has exactly one runtime dependency, pkinative ^1.0.0, imported through one module and never inlined into the CLI's own CommonJS binary. It declares Node.js only; its CI also smoke-runs the built CLI under Deno and Bun, as information rather than a promise.

Every release is published from CI with npm provenance, a Sigstore build-provenance attestation and CycloneDX and SPDX SBOMs attached to the GitHub release. To check what you installed:

```bash
npm pack pkinative-cli@1.0.0
gh attestation verify pkinative-cli-1.0.0.tgz --repo Nizoka/pkinative-cli
```

## When to use the CLI

| Use the **CLI** when… | Use the **library** when… | Use the **MCP server** when… |
|---|---|---|
| You write shell scripts, Makefiles or CI jobs | You build a service in Node.js, Deno, Bun, a browser or a worker | A conversational assistant needs PKI tools |
| Certificates, CRLs and signatures live on disk or arrive through a pipe | The bytes live in memory and you call the engine directly | The bytes arrive as PEM or base64 in a tool call, or sit in a sandbox directory |
| You want exit codes, `--dry-run` and one JSON envelope per run | You want the full API, its types and an `ExternalSigner` | You want typed tools with schemas, prompts and resources |

The three surfaces share one engine, so a verdict is the same whichever one computes it; [Choosing your surface](choose.md#choosing-your-surface) holds the capability × surface table.

## Quick start

```bash
# What is this certificate?
pkinative cert inspect server.pem

# Is it valid for this host, now, with revocation?
pkinative chain verify server.pem --untrusted intermediate.pem --trust root.pem \
  --host www.example.com --crl ca.crl --require-revocation

# Issue a self-signed CA, then a leaf under it
pkinative cert create --spec ca.json --key ca.key -o ca.pem
pkinative cert create --spec leaf.json --key ca.key --issuer ca.pem --public-key leaf.csr -o leaf.pem

# Sign and verify a file
pkinative cms sign --content report.pdf --cert signer.pem --key signer.key --detached -o report.p7s
pkinative cms verify report.p7s --content report.pdf --trust root.pem

# Machine-readable everything
pkinative chain verify server.pem --trust root.pem --untrusted ca.pem --json --summary
```

Every subcommand has a runnable example in the CLI repository's `samples/` directory, as a `.sh` and a `.ps1` script, and those are the examples its CI runs and pins.

## The agent contract

The CLI is built to be driven by programs — CI steps, scripts, AI agents — without parsing prose. Everything in this section is stable across 1.x, and fields are only ever added.

- **stdout is the artefact or the report — nothing else, ever.** PEM, DER or hex artefacts, text or JSON reports, schemas and completion scripts go to stdout.
- **stderr is the channel.** Notes and diagnostics go there, and under `--json` (or `PKINATIVE_JSON=1`) exactly one JSON envelope, as the last line.
- **`--json` is agent mode.** Report commands print compact JSON on stdout (the engine's result in pkinative's wire form) and the envelope on stderr. `--format text|json` on a report command overrides the default; `--format json` without `--json` prints indented JSON.
- **A negative verdict prints its full report on stdout and exits 1 with an envelope** (`chain verify`, `cms verify`, `ocsp check`, …): read both.
- **`--help` is text for people** whatever `--json` says; `--version --json` prints one object on stdout, `{"name":"pkinative-cli","version":"1.0.0","pkinative":"1.0.0"}`. Neither writes an envelope.

| Exit | Meaning |
|---|---|
| `0` | Success; also a closed pipe (EPIPE), which ends the process quietly |
| `1` | Any failure but usage: parse, I/O, policy, a limit, a negative verdict (the report is printed first) |
| `2` | Usage error (`E_USAGE`) |
| `130` / `143` | Interrupted by SIGINT / SIGTERM; the file being written is removed, finished outputs stay |

A status envelope and two error envelopes, as an agent sees them (output of the 1.0.0 binary on the CLI's own test fixtures):

```json
{"ok":true,"command":"chain verify","valid":true,"pathLength":3,"signaturesChecked":true,"diagnostics":[]}
{"ok":false,"command":"cert inspect","error":{"code":"E_INPUT","message":"leaf.key.pem holds no CERTIFICATE or X509 CERTIFICATE or TRUSTED CERTIFICATE PEM block (labels present: PRIVATE KEY).","pkiCode":"PKI_PEM_UNEXPECTED_LABEL","remedy":"pkinative pem decode <file> (lists the labels present)"},"diagnostics":[]}
{"ok":false,"command":"cert inspect","error":{"code":"E_LIMIT","message":"certificate \"leaf.crt.pem\" exceeds --max-input-bytes (100 bytes; observed at least 1005). Raise the bound only for trusted input.","detail":{"limit":"maxInputBytes","flag":"--max-input-bytes","configured":100,"observed":1005},"remedy":"--max-input-bytes <size> (trusted input only)"},"diagnostics":[]}
```

| Envelope field | Present | Meaning |
|---|---|---|
| `ok`, `command` | always | The outcome, and the command with its subcommand (`"chain verify"`) |
| `error.code` | failures | One of the 13 `E_*` classes — branch on this |
| `error.message` | failures | For people: the CLI's context, then the engine's message |
| `error.pkiCode` | engine failures | pkinative's frozen `PKI_*` code, verbatim — the exact cause |
| `error.detail` | when known | `limit`, `flag`, `configured`, `observed`; `offset`, `path`, `algorithm` |
| `error.remedy` | when a flag or command lifts it | The CLI flag that changes the outcome, e.g. `--allow-sha1`, `--ber`, `--max-depth <value>` |
| `error.reasons` | negative verdicts | The engine's `PkiReason` list in the wire form |
| `diagnostics` | always | Every `PkiDiagnostic` the engine emitted: `{ code, severity, message, standard, path, offset? }` |
| `config` | a config file supplied defaults | The `.pkinativerc.json` that did |

Command-specific success fields — `valid`, `pathLength`, `signaturesChecked`, `output`, `bytes` (the DER length of an artefact), `encoding`, `nonce`, `count`, `dryRun`, … — are listed per invocation by `pkinative schema manifest`. Without `--json`, a failure prints `error E_<CLASS> (PKI_<CODE>): <message>` on stderr, then a `remedy: …` line when there is one.

**JSON reports use pkinative's wire form:** `bigint` becomes a decimal string, `Uint8Array` lowercase hex, `epochMilliseconds` stays a number, absent optional members are omitted and member names are unchanged. The CLI adds nothing to an engine result except where it is a CLI view: `key` and `p12` reports are allow-list views that never carry key bytes, and command-level wrappers (`{ blocks }`, `{ oids }`, `{ valid, reasons }`) are documented per command.

**Token economy.** `--summary` prints the command's minimal JSON shape (codes instead of full reasons, names instead of objects); `--fields a,b.c` keeps only these dot-paths, a segment on an array mapping over it; an unknown path is omitted, except under an array, where each element it matches nothing in becomes `null`; `--pretty` indents; `--quiet` silences text notes and diagnostics on stderr, while the envelope still carries the diagnostics.

**Inputs.** A PKI input is a path, `-` for stdin, or stdin when the path is absent — refused on an interactive terminal. It is PEM when its first non-blank bytes are `-----BEGIN `, DER otherwise. Where one object is expected, a PEM file with several matching blocks is refused (`E_INPUT`) rather than reduced to its first block; `pem decode --index` extracts one. The repeatable inputs (`--trust`, `--untrusted`, `--chain`, `--crl`, `--ocsp`) accept PEM bundles. Time is `--at <ISO 8601 | epoch ms | now>`, UTC unless zoned: pin it for reproducible verdicts.

**Parsing rules.** Global flags and subcommand flags may sit anywhere on the line; a boolean flag never consumes the next token; `--flag=value` is the explicit form; a lone `-` is a value (stdin or stdout); `--` ends the flags. Short aliases: `-i` (`--input`), `-o` (`--output`), `-f` (`--format`), `-q`, `-h`, `-V`. Each flag is given once unless the manifest marks it repeatable, and a subcommand takes at most the operands the manifest declares, so a verdict never depends on argument order.

### The `schema` subjects

`pkinative schema` (or `schema list`) lists the twelve subjects; every JSON Schema is draft 2020-12 with an `$id` versioned by the CLI release.

| Subject | Kind | Prints |
|---|---|---|
| `manifest` | document | Commands, flags, operands, exit codes, error classes, the wire form, each invocation's outputs and envelope status fields |
| `errors` | document | The `E_*` classes and the 57 `PKI_*` → `E_*` mappings with their remedies |
| `limits` | document | The 22 bounds: flag, kind, effective value |
| `status` | schema | The `--json` success envelope |
| `error` | schema | The `--json` failure envelope |
| `asn1-spec` | schema | The `asn1 encode` node spec |
| `cert-spec` | schema | The `cert create` spec |
| `csr-spec` | schema | The `csr create` spec |
| `config` | schema | The `.pkinativerc.json` file |
| `cert-encode-spec` | schema | The `cert encode` spec of each structure (`$defs/<structure>`) |
| `report` | schema | `report <command> [<subcommand>]`: the `--json` report on stdout, generated from the TypeScript types and held to every sample |
| `summary` | schema | `summary <command> [<subcommand>]`: its `--summary` shape |

```bash
pkinative schema manifest --pretty
pkinative schema report chain verify
pkinative schema summary cert inspect
```

### Refused combinations

Usage errors are `E_USAGE`, exit 2, and they are detected before anything is written — save the one only the input can reveal, `p12 open` on an RSA key without `--rsa-scheme` (below). Beyond an unknown flag, a malformed value or a missing required flag, the CLI refuses:

| Where | Refused |
|---|---|
| Every command | `--password`, `--pass`, `--passin` and `--key-password` (before anything else runs); `--password-stdin=<value>`; two password sources at once; the password from stdin when an input is read from stdin too; combined short flags (`-qf`) and `-o=value`; a single-value flag given twice, a switch given twice, a flag under both its names; more operands than the invocation takes; an operand beside the flag it stands for; a `--max-*` value that is zero, not an integer, or beyond `Number.MAX_SAFE_INTEGER` (there is no "unbounded"); an `--at` that is not ISO 8601, epoch milliseconds or `now`, or a date that does not exist; `--encoding pem` with no PEM label; raw DER to an interactive terminal; a `.pkinativerc.json` key outside the nine presentation keys; `--config` naming a file that does not exist |
| `pem` | `decode --output` without `--index`; `encode` without `--label` |
| `oid` | `name`, `encode` or `validate` without an OID; `encode` with more than one; `--relative` without `--tlv`; `decode` with both, or neither, a hex argument and `--input` |
| `fingerprint` | `--key-id` with `--shake256`; `--webcrypto` with `--key-id` or `--shake256` |
| `asn1` | `decode --sequence` with `--path`, `--read` or `--reencode`; `--read` with `--reencode`; a `--path` that is not dot-separated indices; `encode` without `--spec` |
| `cert` | `inspect --extension` with `--raw-extensions`, or naming a kind outside the 19; `create` or `encode <structure>` without `--spec`; `create` with no subject key (it is derived from `--key` only for a self-signed certificate from an unencrypted key); `encode` without one known structure; `encode signature-algorithm` with `--spec`; `decode-extension` without `--oid`, or with both or neither of `--value` and `--input`; `check-name` without exactly one of `--host` and `--ip`; `match-name` without two operands; `check-purpose` without `--purpose` |
| Signing (`cert create`, `cert encode signature-algorithm`, `csr create`, `cms sign`) | neither or both of `--key` and `--p12`; an RSA key without `--rsa-scheme`; `--rsa-scheme` or `--salt-length` on a non-RSA key; `--salt-length` with `pkcs1`; `pkcs1` for an id-RSASSA-PSS key; `--hash` on Ed25519 or Ed448; `--hash SHA-1` without `--allow-sha1`; an encrypted key or a PKCS#12 without a password; an encrypted key whose type nothing names (`--key-type`, the certificate or the public key) |
| `csr` | `create` without `--spec`, or with no public key (derived from `--key` only for an unencrypted key) |
| `chain` | `verify`, `build` or `validate` without `--trust`; `verify` with both `--host` and `--ip`; `validate` without a path |
| `crl` | `find` without exactly one of `--serial` and `--cert`; `verify-signature` without `--issuer`; `check` without `--cert` |
| `ocsp` | `request` or `cert-id` without `--issuer`; a nonce outside 1–32 octets (RFC 8954), also for `chain verify --ocsp-nonce`; `check` without `--cert` and `--issuer` |
| `cms` | `sign` without `--content` or `--content-digest`, with both, or with `--content-digest` but no `--detached`; `sign` without a signer certificate (`--cert`, or a `--p12` that holds it); `verify` without `--trust`; `verify-signer` without `--cert`; `add-attribute` without `--attribute`; `add-timestamp` without `--token` |
| `tsp` | `request` with both, or neither, of `--data` and `--digest`; `verify` with both, or neither, of `--token` and `--response`, without `--trust`, or without what was stamped (`--request`, `--data` or `--digest`) |
| `p12` | `verify-mac`, `bags` or `open` without a password; `open` on an RSA key without `--rsa-scheme` — only the file can reveal it, so the report (`PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`, the key not imported) is printed first, then `E_USAGE` exits 2 with the remedy `--rsa-scheme pkcs1\|pss`, and no `--certs-out` is written |
| `explain` | neither a code nor `--list` |
| `schema` | an unknown subject; an argument after a subject other than `report` and `summary`; `report` or `summary` without a known invocation |
| `completion` | no shell, or a shell other than `bash`, `zsh`, `fish`, `powershell` (`pwsh` is accepted for PowerShell) |

`--config` together with `--no-config` is not refused: `--no-config` wins and the named file is never read.

## Error classes, codes and remedies

Every failure is one of 13 classes. pkinative's 57 frozen error codes map to them by a fixed table — typed against the engine's code union, so an engine release that added a code would fail the CLI's type-check rather than leak as `E_RUNTIME` — and the engine's code always rides along, verbatim, in `error.pkiCode`.

| Class | Exit | `PKI_*` codes mapped to it | When |
|---|---|---|---|
| `E_USAGE` | 2 | `PKI_INVALID_OPTION`, `PKI_API_MISUSE`, `PKI_LIMIT_INVALID` | A missing, unknown or invalid flag, argument or option value |
| `E_INPUT` | 1 | `PKI_INVALID_INPUT`, `PKI_ASN1_VALUE_OUT_OF_RANGE`, `PKI_PEM_LABEL_INVALID`, `PKI_PEM_UNEXPECTED_LABEL`, `PKI_CMS_CONTENT_TYPE_UNEXPECTED` | A spec, label or value is unacceptable; a key does not belong to its certificate |
| `E_PARSE` | 1 | the other 35: every remaining `PKI_ASN1_*`, `PKI_OID_INVALID`, `PKI_PEM_NO_BLOCK`, `PKI_PEM_LABEL_MISMATCH`, `PKI_PEM_UNTERMINATED`, `PKI_PEM_BASE64_INVALID`, the ten `PKI_X509_*`, `PKI_CMS_STRUCTURE_INVALID`, `PKI_KEY_STRUCTURE_INVALID` | The bytes are not the DER, PEM or JSON they claim to be |
| `E_IO` | 1 | — | A filesystem failure, including a refused overwrite (`remedy: --overwrite`) |
| `E_SECURITY` | 1 | `PKI_CRYPTO_ALGORITHM_REFUSED`, `PKI_KEY_ENCRYPTION_UNSUPPORTED`, `PKI_KEY_MAC_UNSUPPORTED` | A policy refusal: SHA-1, a legacy PKCS#12 cipher or MAC, a PBES1 key |
| `E_LIMIT` | 1 | `PKI_LIMIT_EXCEEDED` | A bound was exceeded: one of the 22 pkinative limits, or `--max-content-size` |
| `E_UNSUPPORTED` | 1 | `PKI_PEM_HEADERS_FORBIDDEN`, `PKI_CRYPTO_ALGORITHM_UNSUPPORTED`, `PKI_CRYPTO_KEY_UNSUPPORTED`, `PKI_CMS_VERSION_UNSUPPORTED`, `PKI_CMS_CONTENT_NOT_OCTET_STRING`, `PKI_KEY_VERSION_UNSUPPORTED` | The algorithm, key or structure is not supported |
| `E_CRYPTO` | 1 | `PKI_CRYPTO_UNAVAILABLE` | Web Crypto could not run the operation |
| `E_PASSWORD` | 1 | `PKI_CRYPTO_DECRYPTION_FAILED` | A wrong password, or a MAC that does not match it |
| `E_NOT_FOUND` | 1 | — | A named item is absent: an extension, a PEM block, a signer, a code |
| `E_VERIFY_FAILED` | 1 | — | A signature, chain, request, timestamp or MAC verdict is negative; `error.reasons` says why |
| `E_CHECK_FAILED` | 1 | `PKI_STRICT_DIAGNOSTIC` | A check returned reasons (revocation, OCSP, name, purpose), or `--strict` escalated a warning |
| `E_RUNTIME` | 1 | `PKI_INTERNAL` | Anything else; the CLI's seeded fuzz suite holds that no input reaches it |

`E_IO`, `E_NOT_FOUND` and `E_VERIFY_FAILED` carry no engine code: they are the CLI's own (a filesystem error, a missing item, a negative verdict whose reasons are in `error.reasons`). `pkinative schema errors` prints the whole 57 → 13 table.

**Remedies.** The engine's messages name library options that do not exist on a command line, so the envelope adds `remedy` — the flag or command that lifts the refusal. A code absent from this table has no flag-level remedy: the input itself must change. A few call sites give a remedy of their own where the right advice depends on what was being read (`cert decode-extension`, a legacy-encrypted PKCS#8 `--key`), and a limit the CLI enforces before the engine runs names its own flag.

| `pkiCode` | `remedy` |
|---|---|
| `PKI_ASN1_LENGTH_NON_MINIMAL`, `PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN`, `PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN`, `PKI_ASN1_BOOLEAN_INVALID` | `--ber` (the producer wrote BER, not DER) |
| `PKI_ASN1_TRAILING_DATA` | Pass exactly one object; `asn1 decode --sequence` for concatenated objects; `--allow-trailing` (`asn1 decode`, `cms inspect`, `cms verify`) when the container defines what follows |
| `PKI_PEM_BASE64_INVALID` | `--pem-mode lax` (whitespace, line length, headers); a missing `=` padding must be restored first |
| `PKI_PEM_UNEXPECTED_LABEL` | `pkinative pem decode <file>` (lists the labels present) |
| `PKI_STRICT_DIAGNOSTIC` | Drop `--strict`, or fix the producer the diagnostic names |
| `PKI_CRYPTO_ALGORITHM_REFUSED` | `--allow-sha1` (only for legacy material you already trust) |
| `PKI_CRYPTO_DECRYPTION_FAILED` | `--password-file <file>` \| `--password-stdin` \| `PKINATIVE_PASSWORD` (check the password) |
| `PKI_X509_EXTENSION_MALFORMED` | `cert inspect --raw-extensions` (keeps every extension undecoded) |
| `PKI_KEY_ENCRYPTION_UNSUPPORTED` | From a PKCS#12: convert it once with OpenSSL 3.4 or later (`openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12`). From a PKCS#8 `--key`: re-encrypt it with PBES2 (`openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256`) |
| `PKI_KEY_MAC_UNSUPPORTED` | `--allow-unverified-integrity` (`p12 open`; only for a file whose origin you trust), or re-export it with `openssl pkcs12 -export -pbmac1_pbkdf2` |
| `PKI_API_MISUSE` | `pkinative <command> --help` (the options given are incomplete or inconsistent for this input) |
| `PKI_LIMIT_EXCEEDED` | `--max-<limit> <value>`, the flag `detail.flag` names (`pkinative limits` lists them); raise a bound for trusted input only |

**Diagnostics are not errors.** The engine's `PKI_DIAG_*` codes ride in the envelope's `diagnostics[]` and print as `warning PKI_DIAG_… at <path>: <message> (<standard>)` lines on stderr unless `--quiet`. `--strict` escalates the first warning to `E_CHECK_FAILED` (`pkiCode: PKI_STRICT_DIAGNOSTIC`) before any report or artefact is written — including a warning that a verify or check report collects, not only one raised while parsing.

**`pkinative explain <code>`** explains any code the CLI can print: the 13 `E_*` classes, and from the registries of the pinned pkinative release every `PKI_*` error (with its CLI class, exit code and the flag that lifts it), every `PKI_REASON_*` reason and every `PKI_DIAG_*` diagnostic. `pkinative explain --list [--kind error|reason|diagnostic|cli]` enumerates them. The [errors guide](errors.md) explains the engine's three vocabularies, and [Where the codes surface](errors.md#where-the-codes-surface) compares the library, CLI and MCP views of the same failure.

```bash
pkinative explain PKI_CRYPTO_ALGORITHM_REFUSED
pkinative explain E_VERIFY_FAILED --json
pkinative explain --list --kind reason
```

## Command reference

Eighteen commands in six groups: Encodings (`pem`, `oid`, `fingerprint`, `asn1`), Certificates (`cert`, `csr`), Paths & revocation (`chain`, `crl`, `ocsp`), Signatures & time-stamps (`cms`, `tsp`), Keys (`key`, `p12`) and Meta (`doctor`, `limits`, `explain`, `schema`, `completion`). Every invocation also accepts the [global options](#global-options); the tables below list each subcommand's own flags, and `pkinative <command> --help` prints the same reference. A flag marked *(repeatable)* may be given several times; `<file>` may be `-` for stdin.

### Encodings

#### `pkinative pem`

RFC 7468 textual encoding. `decode` lists every block (label, size, offset, headers), or writes one block's bytes with `--index`; `encode` wraps DER bytes in one block. The global `--pem-mode lax` tolerates whitespace, line length and RFC 1421 headers; a missing base64 padding is refused in both modes.

```bash
pkinative pem decode [<file>] [--index <n> [--encoding pem|der|hex] [-o <file>]]
pkinative pem encode [<file>] --label <LABEL> [-o <file>]
```

| `pem decode` | Description |
|---|---|
| `--input`, `-i <file>` | PEM text (default: the operand, or stdin) |
| `--label <LABEL>` | Refuse any block with another label |
| `--index <n>` | Extract block `n` (from 0); `E_NOT_FOUND` past the last block |
| `--encoding pem\|der\|hex` | Encoding of the extracted block (default `der`) |
| `--output`, `-o <file>` | Write the block to a file (default stdout); needs `--index` |
| `--format`, `-f text\|json` | Format of the listing |

| `pem encode` | Description |
|---|---|
| `--input`, `-i <file>` | DER bytes (default: the operand, or stdin); PEM input is refused (`E_INPUT`) |
| `--label <LABEL>` | The block label, e.g. `CERTIFICATE` (required) |
| `--output`, `-o <file>` | Write the PEM text to a file (default stdout) |

#### `pkinative oid`

Object identifiers: names, X.690 §8.19–8.20 encodings, validation and the registry pkinative knows.

```bash
pkinative oid name <oid>...
pkinative oid encode <oid> [--tlv] [--relative] [--encoding hex|der|pem]
pkinative oid decode <hex> [--tlv] [--relative]
pkinative oid decode --input <file> --tlv
pkinative oid validate <oid>...
pkinative oid list [--filter <text>]
```

| Subcommand | Flags |
|---|---|
| `name <oid>...` | `--format`, `-f text\|json`. Prints each OID's registered name, or that it is not registered |
| `encode <oid>` | `--tlv` (the whole TLV — tag 06, or 0D with `--relative` — instead of the content octets); `--relative` (RELATIVE-OID, needs `--tlv`); `--encoding pem\|der\|hex` (default `hex`); `--label <LABEL>` (with `--encoding pem`); `--output`, `-o <file>` |
| `decode <hex>` | `--input`, `-i <file>` (read the bytes from a file instead of the operand); `--tlv` (the bytes are a whole TLV); `--relative` (needs `--tlv`); `--format`, `-f` |
| `validate <oid>...` | `--format`, `-f`. Exit 1 (`E_CHECK_FAILED`) when one is invalid |
| `list` | `--filter <text>` (keep entries whose OID, name or standard contains it); `--format`, `-f` |

#### `pkinative fingerprint`

Digests of one PKI object (certificate, request, CRL, public key, …) given as one PEM block or DER object; no subcommand.

```bash
pkinative fingerprint [<file>] [--alg SHA-256] [--separator :] [--case upper]
pkinative fingerprint [<file>] --key-id [--alg SHA-1|SHA-256]
pkinative fingerprint [<file>] --shake256 <bytes>
```

| Flag | Description |
|---|---|
| `--input`, `-i <file>` | The object (default: the operand, or stdin) |
| `--alg SHA-1\|SHA-256\|SHA-384\|SHA-512` | Digest (default `SHA-256`; `SHA-1` for `--key-id`, as RFC 5280 §4.2.1.2 specifies) |
| `--separator <text>` | Between bytes (default `:`; `""` for none) |
| `--case upper\|lower` | Hex letter case (default `upper`) |
| `--webcrypto` | Digest with Web Crypto instead of the pure-TypeScript path (fingerprint mode only) |
| `--key-id` | The key identifier of the public key of a certificate, request or `PUBLIC KEY` |
| `--shake256 <bytes>` | SHAKE256 of the input, this many bytes (at most 1 MiB) |
| `--format`, `-f text\|json` | Report format |

#### `pkinative asn1`

X.690 DER, or BER with the global `--ber`. `decode` prints the node tree like `openssl asn1parse` (offset, depth, lengths, tag, value), reads one node with a typed reader, or re-encodes it; `encode` turns a JSON node spec into DER (`pkinative schema asn1-spec`).

```bash
pkinative asn1 decode [<file>] [--path i.j.k] [--read <type>] [--reencode]
pkinative asn1 decode [<file>] --sequence [--allow-trailing]
pkinative asn1 encode --spec <spec.json> [--encoding der|hex|pem]
```

| `asn1 decode` | Description |
|---|---|
| `--input`, `-i <file>` | The object, DER or one PEM block (default: the operand, or stdin) |
| `--path <i.j.k>` | Select a node by child indices from the root; `E_NOT_FOUND` past a node's children |
| `--read <type>` | Read the node: `boolean`, `integer`, `small-integer`, `enumerated`, `null`, `bit-string`, `octet-string`, `oid`, `relative-oid`, `string`, `time` |
| `--string-type <type>` | With `--read string` on an IMPLICIT-tagged node: `utf8`, `numeric`, `printable`, `teletex`, `ia5`, `visible`, `universal`, `bmp` |
| `--time-type UTCTime\|GeneralizedTime` | With `--read time` on an IMPLICIT-tagged node |
| `--reencode` | Re-encode the node (byte-identical for DER; the status says `identical`) |
| `--sequence` | Decode concatenated top-level objects |
| `--allow-trailing` | Ignore bytes after the first object |
| `--encoding pem\|der\|hex` | `--reencode` output encoding (default `der`) |
| `--label <LABEL>` | PEM label with `--encoding pem` |
| `--output`, `-o <file>` | `--reencode` output file (default stdout) |
| `--format`, `-f text\|json` | Report format |

| `asn1 encode` | Description |
|---|---|
| `--spec <file>` | JSON node spec (`-` = stdin; or the operand). Types: `boolean`, `integer`, `enumerated`, `null`, `bit-string`, `named-bits`, `octet-string`, `oid`, `relative-oid`, `string`, `time`, `sequence`, `set`, `set-of`, `explicit`, `implicit`, `tlv`, `der` |
| `--encoding pem\|der\|hex` | Output encoding (default `der`) |
| `--label <LABEL>` | PEM label with `--encoding pem` |
| `--output`, `-o <file>` | Output file (default stdout) |

### Certificates

#### `pkinative cert`

RFC 5280 certificates: read, issue, encode their building blocks, verify one signature, and check names and purposes.

```bash
pkinative cert inspect [<file>] [--extension <kind>] [--raw-extensions]
pkinative cert create --spec <spec.json> --key <key> [--issuer <ca.pem>] [--public-key <file>] [-o <file>]
pkinative cert encode <structure> --spec <spec.json>
pkinative cert encode signature-algorithm --key <key> [--rsa-scheme <scheme>]
pkinative cert decode-extension --oid <oid> --value <hex> [--critical]
pkinative cert verify-signature [<file>] [--issuer <file>]
pkinative cert check-name [<file>] --host <name> | --ip <address>
pkinative cert match-name <presented> <reference> [--no-wildcards]
pkinative cert check-purpose [<file>] --purpose <name|oid|any> [--chain <file>]...
```

| `cert inspect` | Description |
|---|---|
| `--input`, `-i <file>` | The certificate, PEM or DER (default: the operand) |
| `--extension <kind>` | Print one decoded extension (`E_NOT_FOUND` if absent). The 19 kinds: `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `subjectAltName`, `issuerAltName`, `subjectKeyIdentifier`, `authorityKeyIdentifier`, `nameConstraints`, `certificatePolicies`, `policyMappings`, `policyConstraints`, `inhibitAnyPolicy`, `authorityInfoAccess`, `subjectInfoAccess`, `crlDistributionPoints`, `freshestCRL`, `signedCertificateTimestampList`, `ocspNoCheck`, `subjectDirectoryAttributes` |
| `--raw-extensions` | Keep every extension undecoded |
| `--format`, `-f text\|json` | Report format |

| `cert create` | Description |
|---|---|
| `--spec <file>` | JSON spec (`-` = stdin): `subject`, `issuer`, `serialNumber`, `notBefore`, `notAfter` or `validityDays`, `extensions` (`pkinative schema cert-spec`). Defaults when omitted: a random 127-bit `serialNumber`, `notBefore` now, `validityDays` 365 |
| `--issuer <file>` | Issuer certificate; omitted = self-signed |
| `--public-key <file>` | Subject key: a certificate, request or `PUBLIC KEY` (default: derived from an unencrypted `--key` when self-signed) |
| signing flags | `--key`, `--p12`, `--key-type`, `--hash`, `--rsa-scheme`, `--salt-length`, `--password-file`, `--password-stdin` (below) |
| `--output`, `-o <file>` | Output file (default stdout) |
| `--encoding pem\|der\|hex` | Output encoding (default `pem`) |

The new certificate is verified against `--issuer` (or itself) before it is written: a key that does not belong to the issuer is refused (`E_INPUT`). The status envelope carries `serialNumber`, `selfSigned` and `signatureVerified`.

| `cert encode <structure>` | Description |
|---|---|
| `<structure>` | `name`, `name-attribute`, `validity`, `spki`, `algorithm-identifier`, `attribute`, `extension`, `extensions`, `basic-constraints`, `key-usage`, `extended-key-usage`, `subject-alt-name`, `subject-key-identifier`, `authority-key-identifier`, `signature-algorithm` (from the signing key) |
| `--spec <file>` | JSON value of the structure (`-` = stdin); the members of each spec: `pkinative schema cert-encode-spec` |
| signing flags | `signature-algorithm` only: the key decides the algorithm |
| `--output`, `-o <file>` | Output file (default stdout) |
| `--encoding pem\|der\|hex` | Output encoding (default `hex`) |
| `--label <LABEL>` | PEM label with `--encoding pem` |

| `cert decode-extension` | Description |
|---|---|
| `--oid <oid>` | The extension OID (required) |
| `--value <hex>` | The `extnValue` content |
| `--input`, `-i <file>` | … or read it from a file, DER |
| `--critical` | Decode as a critical extension |
| `--format`, `-f text\|json` | Report format |

| `cert verify-signature` | Description |
|---|---|
| `--input`, `-i <file>` | The certificate (default: the operand) |
| `--issuer <file>` | The issuer certificate (default: the self-signature) |
| `--allow-algorithm-mismatch` | Accept a `tbsCertificate` and outer signature algorithm that differ |
| `--format`, `-f text\|json` | Report format. Exit 1 (`E_VERIFY_FAILED`) when the signature does not verify |

| `cert check-name` | Description |
|---|---|
| `--input`, `-i <file>` | The certificate (default: the operand) |
| `--host <name>` | DNS reference identity |
| `--ip <address>` | IPv4 or IPv6 reference identity |
| `--chain <file>` *(repeatable)* | Issuers, for name constraints |
| `--allow-cn-fallback` | Accept a commonName when there is no SAN |
| `--no-wildcards` | Refuse wildcard names |
| `--format`, `-f text\|json` | Report format. Exit 1 (`E_CHECK_FAILED`) on a mismatch |

| `cert match-name <presented> <reference>` | Description |
|---|---|
| `--no-wildcards` | Refuse wildcard names |
| `--format`, `-f text\|json` | Report format. Exit 1 (`E_CHECK_FAILED`) on a mismatch |

| `cert check-purpose` | Description |
|---|---|
| `--input`, `-i <file>` | The certificate (default: the operand) |
| `--purpose <name\|oid\|any>` | `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`, `any`, or an OID |
| `--chain <file>` *(repeatable)* | The issuers, leaf-first order |
| `--no-restrict-issuers` | Do not require the purpose in issuer EKUs |
| `--require-explicit-purpose` | Refuse a certificate without an EKU |
| `--format`, `-f text\|json` | Report format. Exit 1 (`E_CHECK_FAILED`) when the purpose fails |

**Signing flags** (`cert create`, `cert encode signature-algorithm`, `csr create`, `cms sign`). The algorithm follows the key: ECDSA on the key's curve with the curve's hash, Ed25519 and Ed448 without a hash, RSA only with an explicit scheme.

| Flag | Description |
|---|---|
| `--key <file>` | PKCS#8 private key, plain or PBES2-encrypted |
| `--p12 <file>` | PKCS#12 file holding one key (PBES2 and PBMAC1) |
| `--key-type <type>` | Type of an encrypted key when no certificate or public key tells it: `ec-p256`, `ec-p384`, `ec-p521`, `ed25519`, `ed448`, `rsa`, `rsa-pss` |
| `--hash SHA-256\|SHA-384\|SHA-512` | Digest (default: the curve's, or `SHA-256`; `SHA-1` only with `--allow-sha1`) |
| `--rsa-scheme pkcs1\|pss` | Required for an RSA key: there is no default |
| `--salt-length <n>` | RSA-PSS salt length (default: the hash length) |
| `--password-file <file>` | Key or PKCS#12 password: the first line of the file |
| `--password-stdin` | … or the first line of stdin (or `PKINATIVE_PASSWORD`; never on the command line) |

#### `pkinative csr`

PKCS#10 certification requests (RFC 2986).

```bash
pkinative csr inspect [<file>] [--raw-extensions]
pkinative csr create --spec <spec.json> --key <key> [--public-key <file>]
pkinative csr verify [<file>]
```

| Subcommand | Flags |
|---|---|
| `inspect` | `--input`, `-i <file>` (the request, PEM or DER; default the operand); `--raw-extensions` (keep requested extensions undecoded); `--format`, `-f text\|json` |
| `create` | `--spec <file>` (`{ "subject": {...}, "extensions": {...} }`, `pkinative schema csr-spec`; `-` = stdin); `--public-key <file>` (the key to certify; default derived from an unencrypted `--key`); the signing flags; `--output`, `-o <file>`; `--encoding pem\|der\|hex` (default `pem`). The proof of possession is verified before the request is written |
| `verify` | `--input`, `-i <file>`; `--format`, `-f`. Exit 1 (`E_VERIFY_FAILED`) when the self-signature does not verify |

### Paths & revocation

#### `pkinative chain`

RFC 5280 §6 certification paths. `verify` is the one-call verdict: path building, every signature, RFC 5280 validation, the server name (RFC 6125), the purposes and, with CRLs or OCSP responses, revocation. `build` finds a path without checking signatures: its verdict is the path, so `valid` is false with `PKI_REASON_SIGNATURE_NOT_CHECKED`, the envelope says `signaturesChecked: false`, and it exits 0 whenever a path is found, 1 when none is. `validate` takes the path in order and verifies each link's signature first. A negative verdict prints the report, then exits 1 (`E_VERIFY_FAILED`). Offline: CRLs and OCSP responses are files you fetched.

```bash
pkinative chain verify [<leaf>] --trust <roots> [--untrusted <file>]... [--host <name> | --ip <address>]
                       [--purpose <p>]... [--crl <file>]... [--ocsp <file>]... [--require-revocation] [--at <instant>]
pkinative chain build [<leaf>] --trust <roots> [--untrusted <file>]...
pkinative chain validate --path <leaf> --path <ca>... --trust <roots>
```

| Flag | `verify` | `build` | `validate` | Description |
|---|---|---|---|---|
| `--input`, `-i <file>` | ✓ | ✓ | | The leaf (default: the operand) |
| `--path <file>` *(repeatable)* | | | ✓ | The path, leaf first (or operands) |
| `--trust <file>` *(repeatable)* | ✓ | ✓ | ✓ | Trust anchors, PEM bundle or DER (required) |
| `--untrusted <file>` *(repeatable)* | ✓ | ✓ | | Intermediate candidates |
| `--at <instant>` | ✓ | ✓ | ✓ | Validation time: ISO 8601 (UTC unless zoned), epoch milliseconds or `now` (default now) |
| `--purpose <name\|oid>` *(repeatable)* | ✓ | ✓ | ✓ | Required extended key usage: `serverAuth`, `clientAuth`, `codeSigning`, … |
| `--policy <oid>` *(repeatable)* | ✓ | ✓ | ✓ | Initial policy set |
| `--require-explicit-policy`, `--inhibit-policy-mapping`, `--inhibit-any-policy` | ✓ | ✓ | ✓ | RFC 5280 §6.1.1 policy inputs |
| `--host <name>` / `--ip <address>` | ✓ | | | The DNS name or IP address the leaf must hold |
| `--crl <file>` *(repeatable)* | ✓ | | | CRLs, PEM bundle or DER |
| `--ocsp <file>` *(repeatable)* | ✓ | | | OCSP responses, DER or PEM (a PEM bundle is accepted) |
| `--ocsp-nonce <hex>` | ✓ | | | The nonce the OCSP request carried (1–32 octets) |
| `--require-ocsp-nonce` | ✓ | | | Refuse an OCSP response without that nonce |
| `--require-revocation` | ✓ | | | Fail when a certificate's status is unknown |
| `--no-signatures` | | | ✓ | Skip the link signatures: a structural verdict, headed as such |
| `--format`, `-f text\|json` | ✓ | ✓ | ✓ | Report format |

The `chain` envelopes carry `valid`, `pathLength` and `signaturesChecked`; `verify --summary` prints `valid`, the reason codes, the path's subjects, `explored` and `signatureVerifications`.

#### `pkinative crl`

RFC 5280 §5 certificate revocation lists. `find` reports whether a serial is listed and exits 0 either way; `check` is the verdict — listed, stale, wrong scope or unverified is exit 1 (`E_CHECK_FAILED`). With `--issuer` the CRL signature is verified; without it, it counts as unchecked.

```bash
pkinative crl inspect [<crl>]
pkinative crl find [<crl>] --serial <hex> | --cert <file>
pkinative crl verify-signature [<crl>] --issuer <ca>
pkinative crl check [<crl>] --cert <file> [--issuer <ca>] [--delta <crl>] [--at <instant>] [--stale-tolerance <ms>]
```

| Subcommand | Flags |
|---|---|
| `inspect` | `--input`, `-i <file>` (the CRL, PEM or DER; default the operand); `--format`, `-f text\|json` |
| `find` | `--input`, `-i`; `--serial <hex>` (the serial number, hexadecimal) or `--cert <file>` (the certificate to look up); `--format`, `-f` |
| `verify-signature` | `--input`, `-i`; `--issuer <file>` (the CRL issuer, required); `--format`, `-f`. Exit 1 (`E_VERIFY_FAILED`) when it does not verify |
| `check` | `--input`, `-i`; `--cert <file>` (the certificate to check, required); `--issuer <file>`; `--delta <file>` (a delta CRL to apply on top; one without a deltaCRLIndicator is `E_INPUT`); `--at <instant>` (default now); `--stale-tolerance <ms>` (accept a CRL this long past nextUpdate); `--format`, `-f` |

#### `pkinative ocsp`

RFC 6960, offline: the CLI writes the request and judges the response; sending the request is yours (`curl --data-binary @req.der -H 'Content-Type: application/ocsp-request'`).

```bash
pkinative ocsp request --cert <file> --issuer <ca> [--hash SHA-1|SHA-256] [--nonce <hex>|random] [-o req.der]
pkinative ocsp cert-id --cert <file> --issuer <ca> [--hash SHA-1|SHA-256]
pkinative ocsp inspect [<response>]
pkinative ocsp verify-signature [<response>] [--responder <cert>]
pkinative ocsp check [<response>] --cert <file> --issuer <ca> [--responder <cert>] [--nonce <hex>] [--at <instant>]
```

| Subcommand | Flags |
|---|---|
| `request` | `--cert <file>` (or the operand); `--issuer <file>` (required); `--hash SHA-1\|SHA-256` (CertID hash, default `SHA-1`, as responders expect); `--nonce <hex>\|random` (an RFC 8954 nonce of 1 to 32 octets, printed in the status); `--output`, `-o <file>`; `--encoding pem\|der\|hex` (default `der`); `--label <LABEL>` |
| `cert-id` | `--cert <file>` (or the operand); `--issuer <file>`; `--hash SHA-1\|SHA-256`; `--output`, `-o`; `--encoding` (default `hex`); `--label` |
| `inspect` | `--input`, `-i <file>` (the response, DER or PEM; default the operand); `--format`, `-f text\|json` |
| `verify-signature` | `--input`, `-i`; `--responder <file>` (default: the certificates the response embeds); `--format`, `-f`. Exit 1 (`E_VERIFY_FAILED`) when no responder certificate verifies it |
| `check` | `--input`, `-i`; `--cert <file>`, `--issuer <file>` (both required); `--responder <file>` (default: the embedded certificates, then the issuer); `--responder-trusted` (trust the responder out of band; otherwise it must be the CA or a delegate the CA issued with OCSPSigning, RFC 6960 §4.2.2.2); `--hash SHA-1\|SHA-256` (default: the response's own); `--nonce <hex>`; `--require-nonce`; `--at <instant>`; `--stale-tolerance <ms>`; `--future-tolerance <ms>` (accept a thisUpdate this far ahead, default 60000); `--format`, `-f` |

`ocsp check` exits 1 (`E_CHECK_FAILED`) unless the answer is a clean, signed, authorised `good` for this certificate.

### Signatures & time-stamps

#### `pkinative cms`

CMS SignedData (RFC 5652, with RFC 5035 signing-certificate-v2 and RFC 6211 algorithm protection).

```bash
pkinative cms sign --content <file> --cert <cert> --key <key> [--detached] [--chain <file>]... [-o out.p7s]
pkinative cms verify [<p7s>] [--content <file>] --trust <roots>
pkinative cms inspect [<p7s>]
pkinative cms verify-signer [<p7s>] --cert <cert> [--signer-index <n>]
pkinative cms add-attribute [<p7s>] --attribute <der> [--signer-index <n>]
pkinative cms add-timestamp [<p7s>] --token <tst|tsr> [--signer-index <n>]
```

| `cms sign` | Description |
|---|---|
| `--content <file>` | The content to sign |
| `--content-digest <hex>` | Sign a precomputed digest instead (needs `--detached`) |
| `--cert <file>` | The signer certificate (or the one in `--p12`) |
| `--chain <file>` *(repeatable)* | Certificates to embed |
| `--crl <file>` *(repeatable)* | CRLs to embed |
| `--detached` | Leave the content out of the SignedData |
| `--content-type <oid>` | eContentType (default id-data) |
| `--sid issuer-serial\|ski` | Signer identifier form (default `issuer-serial`) |
| `--signing-time <instant\|now\|none>` | signingTime attribute (default now) |
| `--no-signing-certificate` | Omit ESS signing-certificate-v2 |
| `--no-algorithm-protection` | Omit CMS algorithm protection |
| `--signed-attribute <file>` *(repeatable)* | Extra signed attribute, DER |
| `--unsigned-attribute <file>` *(repeatable)* | Extra unsigned attribute, DER |
| signing flags | `--key`, `--p12`, `--key-type`, `--hash`, `--rsa-scheme`, `--salt-length`, `--password-file`, `--password-stdin` |
| `--output`, `-o <file>` | Output file (default stdout) |
| `--encoding pem\|der\|hex` | Output encoding (default `der`; PEM label `CMS`) |

The new signature is verified under `--cert` before it is written; a key that does not belong to the certificate is `E_INPUT`.

| `cms verify` | Description |
|---|---|
| `--input`, `-i <file>` | The SignedData, PEM or DER (default: the operand) |
| `--content <file>` / `--content-digest <hex>` | The content of a detached signature, or its digest |
| `--trust <file>` *(repeatable)* | Trust anchors (required) |
| `--untrusted <file>` *(repeatable)* | Extra certificates for the chains |
| `--purpose <name\|oid>` *(repeatable)* | Required extended key usage |
| `--crl <file>`, `--ocsp <file>` *(repeatable)*, `--require-revocation` | Revocation evidence |
| `--at <instant>` | Validation time (default now) |
| `--at-timestamp` | Validate at the signer's verified timestamp |
| `--require-signing-certificate`, `--require-algorithm-protection` | Demand those signed attributes |
| `--allow-trailing` | Accept bytes after the SignedData |
| `--format`, `-f text\|json` | Report format. Exit 1 (`E_VERIFY_FAILED`) unless every signer verifies |

| Subcommand | Flags |
|---|---|
| `inspect` | `--input`, `-i <file>`; `--allow-trailing`; `--format`, `-f text\|json` |
| `verify-signer` | `--input`, `-i`; `--cert <file>` (the signer certificate, required); `--signer-index <n>` (default 0); `--content <file>` (of a detached signature); `--format`, `-f`. A key check on one signer, not the verdict |
| `add-attribute` | `--input`, `-i`; `--signer-index <n>`; `--attribute <file>` (one Attribute, DER, required); `--output`, `-o`; `--encoding` (default `der`) |
| `add-timestamp` | `--input`, `-i`; `--signer-index <n>`; `--token <file>` (a TimeStampToken or TimeStampResp, required); `--output`, `-o`; `--encoding` (default `der`) |

A counter timestamp stamps the signer's **signature value**, not the content: take it from `cms inspect --fields signerInfos.signature`, hash it, and request the timestamp over that digest (`tsp request --digest`). `add-timestamp` refuses a token over anything else before writing a byte (`E_INPUT`, `PKI_REASON_TSP_IMPRINT_MISMATCH` in `error.reasons`, the recipe as `remedy`).

#### `pkinative tsp`

RFC 3161 timestamping, offline: the CLI writes the request and judges the answer; posting it to a TSA is yours (`curl --data-binary @req.tsq -H 'Content-Type: application/timestamp-query'`).

```bash
pkinative tsp request --data <file> | --digest <hex> [--hash SHA-256] [--nonce <n>|random] [--policy <oid>] [-o req.tsq]
pkinative tsp inspect [<file>] [--as response|token|tstinfo]
pkinative tsp verify --response <tsr> | --token <tst> --trust <roots> (--request <tsq> | --data <file> | --digest <hex>)
```

| Subcommand | Flags |
|---|---|
| `request` | `--data <file>` (hashed with `--hash`) or `--digest <hex>`; `--hash SHA-256\|SHA-384\|SHA-512` (imprint hash, default `SHA-256`); `--nonce <n>\|random` (decimal, `0x`-hex, or 63 random bits; printed in the status); `--policy <oid>`; `--no-cert-req` (do not ask the TSA to embed its certificate); `--output`, `-o <file>`; `--encoding pem\|der\|hex` (default `der`); `--label <LABEL>` |
| `inspect` | `--input`, `-i <file>` (default the operand); `--as response\|token\|tstinfo` (skip the detection); `--format`, `-f text\|json` |
| `verify` | `--response <file>` (or the operand) or `--token <file>`; `--request <file>` (nonce and imprint must match it), `--data <file>` or `--digest <hex>`; `--trust <file>` *(repeatable, required)*; `--untrusted <file>` *(repeatable)*; `--crl <file>`, `--ocsp <file>` *(repeatable)*, `--require-revocation`; `--at <instant>`; `--allow-noncritical-eku` (accept a TSA whose timeStamping EKU is not critical); `--format`, `-f`. Exit 1 (`E_VERIFY_FAILED`) unless the timestamp verifies |

### Keys

#### `pkinative key`

PKCS#8 private keys (RFC 5958, PBES2 per RFC 8018). `inspect` describes a key — algorithm, curve, attributes, or the PBES2 parameters of an encrypted key — without a password; `check` imports or decrypts it into a non-extractable Web Crypto key to prove it is usable. No report ever contains a key byte.

```bash
pkinative key inspect [<file>]
pkinative key check [<file>] [--key-type <type>] [--rsa-scheme pkcs1|pss]
```

| Subcommand | Flags |
|---|---|
| `inspect` | `--input`, `-i <file>` (the key, PEM or DER; default the operand); `--format`, `-f text\|json` |
| `check` | `--input`, `-i`; `--key-type <type>` (of an encrypted key: `ec-p256`, `ec-p384`, `ec-p521`, `ed25519`, `ed448`, `rsa`, `rsa-pss`); `--hash SHA-256\|SHA-384\|SHA-512` (the digest the key will sign with); `--rsa-scheme pkcs1\|pss` (required for an RSA key); `--salt-length <n>`; `--password-file <file>`; `--password-stdin`; `--format`, `-f` |

#### `pkinative p12`

PKCS#12 (RFC 7292) under PBES2 and PBMAC1 (RFC 9579) only. `inspect` needs no password; the others read it from `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD`. The legacy RC2 and 3DES ciphers are refused by doctrine (`E_SECURITY`, with the two-step OpenSSL conversion as `remedy`). A MAC keyed with the RFC 7292 Appendix B KDF is never checked: `verify-mac` refuses it (`E_SECURITY`, `PKI_KEY_MAC_UNSUPPORTED`), and `open` reports it as unverified integrity (`E_VERIFY_FAILED`) unless `--allow-unverified-integrity` is given. No report ever contains a key byte.

```bash
pkinative p12 inspect [<file>]
pkinative p12 verify-mac [<file>]
pkinative p12 bags [<file>]
pkinative p12 open [<file>] [--certs-out <bundle.pem>] [--rsa-scheme pkcs1|pss]
```

| Subcommand | Flags |
|---|---|
| `inspect` | `--input`, `-i <file>` (default the operand); `--format`, `-f text\|json` |
| `verify-mac` | `--input`, `-i`; `--password-file <file>`; `--password-stdin`; `--format`, `-f`. Exit 1: `E_PASSWORD` when the MAC does not match (a wrong password or an altered file), `E_VERIFY_FAILED` when the file carries no MAC |
| `bags` | `--input`, `-i`; `--password-file`; `--password-stdin`; `--format`, `-f`. Lists every bag, decrypting the encrypted contents |
| `open` | `--input`, `-i`; `--password-file`; `--password-stdin`; `--allow-unverified-integrity` (accept a file whose MAC cannot be checked); `--rsa-scheme pkcs1\|pss` (import an RSA key for this scheme); `--hash SHA-256\|SHA-384\|SHA-512` (the RSA key's digest, default `SHA-256`); `--certs-out <file>` (write the certificates and CRLs as PEM, only from a file that opened); `--format`, `-f`. Exit 0 only when everything opened; otherwise exit 1 — `E_PASSWORD` on a MAC mismatch, `E_VERIFY_FAILED` when the MAC cannot be checked, `E_SECURITY` for a legacy cipher — except an RSA key without `--rsa-scheme`: `E_USAGE`, exit 2 |

### Meta

| Command | Flags | Does |
|---|---|---|
| `pkinative doctor` | `--format`, `-f text\|json` | Offline preflight: the Node.js security floor, the installed pkinative against the range the CLI was built for, and whether Web Crypto can verify, sign and decrypt. Exit 1 (`E_CHECK_FAILED`) when a check fails |
| `pkinative limits` | `--format`, `-f text\|json` (and any `--max-*`) | The 22 pkinative bounds with the flag that raises each, its default, the effective value under the `--max-*` flags given and its CWE, plus the CLI's `--max-content-size`; `--format json` adds what each guards |
| `pkinative explain [<code>]` | `--list`; `--kind error\|reason\|diagnostic\|cli` (with `--list`); `--format`, `-f text\|json` | Explains a code; `E_NOT_FOUND` for an unknown one |
| `pkinative schema [<subject>]` | — (up to three operands) | The [schema subjects](#the-schema-subjects) |
| `pkinative completion <shell>` | — | A completion script for `bash`, `zsh`, `fish` or `powershell` |

## Global options

| Flag | Description |
|---|---|
| `--help`, `-h` | Global or per-command help, on stdout |
| `--version`, `-V` | The CLI version; with `--json`, `{ name, version, pkinative }` |
| `--json` | Agent mode: compact JSON report on stdout, one JSON envelope on stderr (also `PKINATIVE_JSON=1`) |
| `--pretty` | Indent JSON output |
| `--fields <a,b.c>` | Keep only these dot-paths of a JSON report |
| `--summary` | Print the command's minimal JSON shape |
| `--quiet`, `-q` | No notes or diagnostics on stderr; errors and envelopes still print (also `PKINATIVE_QUIET=1`) |
| `--no-color` | No ANSI colour; colour is also off under `NO_COLOR`, `TERM=dumb` or a pipe, and forced by `FORCE_COLOR` |
| `--dry-run` | Validate everything, write nothing (the status says `dryRun: true`) |
| `--strict` | Escalate the first engine warning to `E_CHECK_FAILED` |
| `--ber` | Accept BER as well as DER (common in CMS) |
| `--pem-mode strict\|lax` | PEM reading: RFC 7468 strict (default) or lax |
| `--allow-sha1` | Accept or produce SHA-1 signatures (legacy material you trust) |
| `--overwrite` | Replace an existing output file, atomically |
| `--config <file>` | Use this `.pkinativerc.json` (default: the nearest one upward) |
| `--no-config` | Ignore any `.pkinativerc.json` |
| `--max-content-size <size>` | The CLI's own bound on content read whole — content to sign, verify or timestamp, and JSON specs (default 1 GiB) |
| `--max-<limit> <n>` | The 22 pkinative limits (below) |

**The 22 `--max-*` flags** are the keys of pkinative's `DEFAULT_PKI_LIMITS` in kebab case: `--max-input-bytes` (64 MiB, read before a byte is buffered), `--max-depth`, `--max-nodes`, `--max-integer-bytes`, `--max-oid-bytes`, `--max-ber-segments`, `--max-pem-blocks`, `--max-extensions`, `--max-general-names`, `--max-name-attributes`, `--max-policies`, `--max-chain-length`, `--max-policy-nodes`, `--max-revoked-certificates`, `--max-ocsp-single-responses`, `--max-paths-explored`, `--max-signer-infos`, `--max-attributes`, `--max-cms-certificates-and-crls`, `--max-kdf-iterations`, `--max-pkcs12-bags`, `--max-pkcs12-kdf-iterations`. A byte bound accepts a binary suffix (`65536`, `64k`, `16MiB`, `1g`); a count bound takes digits only. Every value is a positive integer: pkinative refuses an unbounded limit, and so does the CLI. `pkinative limits` prints each bound with its default and CWE; the [security guide](security.md) explains what each one guards.

### Configuration file

`.pkinativerc.json` is found by walking upward from the working directory, the nearest file winning, unless `--config <file>` names one or `--no-config` disables the mechanism. **It is presentation only:** a file planted in a cloned repository must never change what a command reads, trusts, when it judges, or where it writes. So it may set nine keys and nothing else — `json`, `pretty`, `quiet`, `no-color`, `format`, `encoding`, `fields`, `summary`, `strict` (which only tightens) — and any other key, present or future, is `E_USAGE`: an input, a trust anchor, the validation time, a tolerance, a bound, an output path or a password source can be set on the command line only.

A top-level key applies to every command; a key naming a command (`"cert"`) or a subcommand (`"cert inspect"`) holds a section, and the most specific section wins. A key applies only where the invoked subcommand declares the flag, and an explicit flag always beats the file. Switches take `true` or `false`, the three value keys take a string; a wrong type, a section naming no subcommand, `__proto__`, `constructor`, `prototype`, invalid JSON, a non-object or a file above 1 MiB is `E_USAGE`. The file that supplied defaults is named in the envelope (`config`) and in a note on stderr.

```json
{
  "no-color": true,
  "cert inspect": { "format": "json", "fields": "subject,validity" },
  "cms sign": { "encoding": "pem" }
}
```

`pkinative schema config` prints the file's JSON Schema.

## Environment

| Variable | Effect |
|---|---|
| `PKINATIVE_JSON=1` | Same as `--json` |
| `PKINATIVE_QUIET=1` | Same as `--quiet` |
| `PKINATIVE_PASSWORD` | The third password source, beside `--password-file` and `--password-stdin`; giving two sources is `E_USAGE` |
| `PKINATIVE_DEBUG=1` | Adds the stack trace of a failure to stderr |
| `NO_COLOR` / `FORCE_COLOR` / `TERM=dumb` | Colour of the text report, which is otherwise on when stdout is a terminal (`--no-color` also turns it off) |

The recommended loop for an agent: run `pkinative doctor --json` once per environment; run the command with `--json` (and `--summary` when only the verdict matters); on exit 1 read `error.code`, then `error.pkiCode` and `error.reasons`, and apply `error.remedy` only when the input is trusted and the policy allows it; on exit 2 fix the invocation and never retry it unchanged.

## Security posture

- **Offline, always.** No module of the CLI opens a socket or makes a request; `node:net` is imported only to classify an IP address. It never fetches a CRL, an OCSP response, a timestamp, an intermediate or an AIA URL: revocation evidence and timestamps are files you supply, and `ocsp request` and `tsp request` write the requests you send yourself. There is no SSRF surface and no verdict that changes with the network.
- **No key generation, no key export.** Bring keys from your HSM, KMS or `openssl genpkey`; the CLI imports them into non-extractable Web Crypto keys. There is no PKCS#8 or PKCS#12 writer, and `key` and `p12` reports are allow-list views that never contain a key byte.
- **No secret on argv.** `--password`, `--pass`, `--passin` and `--key-password` are refused (exit 2) before any command runs, because argv is readable by other users and lands in shell history. The sources are `--password-file <file>` (first line), `--password-stdin` and `PKINATIVE_PASSWORD`; a password is never written to stdout, stderr or an envelope, and an argument mistakenly typed after `--password-stdin` is never echoed.
- **Doctrine kept, never relaxed by configuration.** No SHA-1 signature made or accepted without `--allow-sha1`; no RC2 or 3DES PKCS#12 (`E_SECURITY`, and no flag lifts it); an RFC 7292 Appendix B MAC is never checked, and `p12 open` accepts such a file only under `--allow-unverified-integrity`, a decision about its origin; no default RSA signature scheme (`--rsa-scheme` is required). A created certificate, request or SignedData is verified before it is written.
- **Every read is bounded.** PKI inputs by `--max-input-bytes` before the file is read, stdin as it streams; content and JSON specs by `--max-content-size`; the `asn1 encode` spec is depth-bounded by `maxDepth` (`--max-depth`). Unknown flags are refused, so a misspelt security flag is an error rather than a silent no-op.
- **Writes are exclusive or atomic.** Without `--overwrite`, an existing output path — a dangling symlink included — is refused (`E_IO`); with it, the bytes go to a temporary file in the same directory and a rename replaces the target, never following a link. A file being written when SIGINT or SIGTERM arrives is removed.

The CLI repository's `SECURITY.md` and threat model hold the full posture; the [security guide](security.md) covers the engine underneath.

## Shell completion

Completion scripts are generated from the command registry: commands and subcommands after global flags, flags, the values of enumerated flags under every spelling, paths after a file flag, and the shell names after `completion`.

```bash
pkinative completion bash > /etc/bash_completion.d/pkinative
pkinative completion zsh  > "${fpath[1]}/_pkinative"
pkinative completion fish > ~/.config/fish/completions/pkinative.fish
```

```powershell
pkinative completion powershell >> $PROFILE
```

## Conformance

The CLI computes no verdict of its own, so the engine's conformance — x509-limbo, NIST PKITS, the pinned RFC texts and the OpenSSL and Windows interop matrix — is the CLI's; the [conformance guide](conformance.md) carries the figures. What the CLI repository adds is proof that nothing is lost on the way through the process boundary:

- **Parity with the library.** Parity tests compare the CLI's JSON output with the library's own result for `cert inspect`, `csr inspect`, `crl inspect` and `find`, `ocsp inspect`, `cms inspect` and `verify`, `tsp inspect`, `chain verify`, `asn1 decode`, `pem decode`, `oid list` and `fingerprint`.
- **OpenSSL reads what the CLI writes.** An interop suite has OpenSSL accept the certificates and requests the CLI creates (ECDSA, RSA PKCS#1 v1.5, RSA-PSS, Ed25519), verify its CMS signatures and read its OCSP and timestamp requests; it is required in the publish gate.
- **Pinned samples.** 57 runnable samples, each as a `.sh` and a `.ps1` script, cover every invocation but `doctor`, and their output is pinned by hash.
- **No unmapped failure.** A seeded fuzz suite holds that no argv or input reaches `E_RUNTIME`, and coverage is 100 % on statements, branches, functions and lines.

## Not supported

| Not supported | Instead |
|---|---|
| Network access | None, in any mode: you fetch CRLs, OCSP responses, timestamps and intermediates |
| Key generation, key export | Bring keys from an HSM, a KMS or `openssl genpkey` |
| Writing a PKCS#8 or PKCS#12 | Use OpenSSL; the CLI opens and verifies them |
| Legacy PKCS#12 ciphers (RC2, 3DES) and PBES1 keys; checking an RFC 7292 Appendix B MAC | Refused by doctrine; the `remedy` gives the one-time OpenSSL conversion (a file with an Appendix B MAC opens, unverified, under `--allow-unverified-integrity`) |
| An RSA signature without a named scheme | `--rsa-scheme pkcs1\|pss` is required |
| SHA-1 signatures by default | `--allow-sha1`, for legacy material you already trust |
| A password on the command line | `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD` |
| An unbounded limit | Every `--max-*` value is a positive integer |
| Raising a bound or naming a trust anchor from a config file | Command line only |

The engine's own refusals — DSA verification, ETSI long-term signature formats, names compared by §7.1 preparation — are listed in [the choosing guide](choose.md#what-it-does-not-do-by-design).

## Versioning

pkinative-cli follows Semantic Versioning, and its agent contract is stable across 1.x: the commands and their flags, the exit codes, the 13 `E_*` classes and the `PKI_*` → `E_*` mapping, the envelope fields, the `schema` subjects and the configuration keys; fields are only ever added. pkinative-cli 1.0.0, released on 2026-10-08, pins pkinative ^1.0.0; security fixes land on the latest 1.x minor, for as long as the engine's 1.x line is supported.

## Further reading

- [CLI command builder](../playgrounds/cli.html) — assemble a command line, checked against the CLI's refusals, and copy it.
- [CLI use cases](use-cases-cli.md) — a CI chain gate, offline revocation, a signed and timestamped release, a PKCS#12 audit.
- [MCP guide](mcp.md) — the same engine for AI assistants.
- [Choosing a library and a surface](choose.md#choosing-your-surface) — library, CLI or MCP server, per capability.
- [Errors, diagnostics and reasons](errors.md) · [Security model](security.md) · [Conformance](conformance.md).
- The CLI's [README](https://github.com/Nizoka/pkinative-cli/blob/main/README.md), its [agent contract](https://github.com/Nizoka/pkinative-cli/blob/main/docs/AGENT_CONTRACT.md) and its [llms.txt](https://github.com/Nizoka/pkinative-cli/blob/main/llms.txt).
