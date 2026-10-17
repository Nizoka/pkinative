# pkinative-mcp — AI client integration

> **pkinative-mcp 1.0.0 gives AI assistants the pkinative engine as 34 typed tools, seven prompts and sandboxed file resources, over stdio or loopback Streamable HTTP, with no network access, ever.** It pins pkinative ^1.0.0.

[pkinative-mcp](https://github.com/Nizoka/pkinative-mcp) exposes the engine to any client that speaks the [Model Context Protocol](https://modelcontextprotocol.io) — Claude Desktop, Claude Code, Cursor, VS Code, Continue, Zed, Windsurf, Cline, Roo Code, the MCP Inspector, or any local client over stdio or loopback Streamable HTTP. With it installed an assistant can be asked *"Is this server certificate trustworthy for this host today, given the CRL I fetched?"* and answer by calling `verify_certificate_chain`, reasoning on a typed verdict instead of prose.

All PKI logic lives in pkinative: the server is a thin wrapper that adds the MCP SDK and zod — three runtime dependencies in total (pkinative ^1.0.0, `@modelcontextprotocol/server` ^2.0.0, zod ^4.2.0) — plus a sandbox, a response cache, token-frugal projections and a human-in-the-loop issue drafter. Its 34 tools reach every runtime export of pkinative 1.0.0, and the engine's error, reason and diagnostic codes pass through verbatim.

## Installation

```bash
# Run directly with npx — the recommended form for MCP clients
npx -y pkinative-mcp

# Or install globally
npm install -g pkinative-mcp
pkinative-mcp
```

The binary is `pkinative-mcp`; the package requires Node.js 22 or later, and the engine's own floor is `^22.22.2 || ^24.14.1 || >=25.8.2` — `describe_engine` reports `capabilities.nodeFloorSatisfied`. Its MCP registry name is `io.github.Nizoka/pkinative-mcp`, and its `server.json` declares the npm package with `runtimeHint: "npx"`, the arguments `-y pkinative-mcp`, the stdio transport and the nine environment variables below.

## Configuration by client

Every client runs the same `command` + `args` + `env` triple. `PKINATIVE_MCP_OUTPUT_DIR` is optional: without it every tool works on inline PEM or base64, and nothing touches the filesystem.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pkinative": {
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": {
        "PKINATIVE_MCP_OUTPUT_DIR": "/Users/you/Documents/mcp-pki"
      }
    }
  }
}
```

### Claude Code

`.mcp.json` at the root of the project:

```json
{
  "mcpServers": {
    "pkinative": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_OUTPUT_DIR": "/absolute/path/to/your/project/.mcp-pki" }
    }
  }
}
```

The value must be absolute: Claude Code does not expand `${CLAUDE_PROJECT_DIR}` here (it sets that variable only in the server's environment), and the server refuses a relative path.

### Cursor · Continue · Zed · Windsurf · Cline · Roo Code

Any client that supports stdio servers works with the same triple. For Cursor, `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "pkinative": {
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_OUTPUT_DIR": "/Users/you/Documents/mcp-pki" }
    }
  }
}
```

Windsurf, Cline and Roo Code use the same shape inside their own MCP configuration files.

### VS Code

`.vscode/mcp.json` — note the top-level key `servers`:

```json
{
  "servers": {
    "pkinative": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_OUTPUT_DIR": "${workspaceFolder}/.mcp-pki" }
    }
  }
}
```

### Streamable HTTP (local HTTP clients)

```bash
PKINATIVE_MCP_PORT=3000 PKINATIVE_MCP_HTTP_TOKEN="$(openssl rand -hex 24)" PKINATIVE_MCP_OUTPUT_DIR=/srv/pki npx -y pkinative-mcp
# stderr: [pkinative-mcp] ready (HTTP transport, MCP 2026-07-28 + legacy) on http://127.0.0.1:3000/mcp — bearer token required
# every request: POST /mcp with Authorization: Bearer <token>
```

The endpoint binds `127.0.0.1` only and accepts `POST /mcp`; `GET` and `DELETE` answer 405 (the server is stateless, with no SSE resumability), a foreign `Host` or `Origin` answers 403 (DNS-rebinding guard), and a body above 256 MiB answers 413. **Without `PKINATIVE_MCP_HTTP_TOKEN` the endpoint has no authentication**, and other local processes can reach it; with the token, a missing bearer answers 401 with `WWW-Authenticate: Bearer realm="pkinative-mcp"`, a wrong one adds `error="invalid_token"`.

A hosted client such as ChatGPT connects from its own infrastructure: this endpoint answers a non-loopback `Host` or `Origin` with 403, so it is not reachable from there as shipped.

## Environment variables

All nine are declared in `server.json` and read once at startup; an invalid value — a port outside 1–65535, a relative output directory, a malformed instant or ceiling, a weak token — refuses to start with one `[pkinative-mcp] fatal:` line on stderr, never a silent fallback. Only the *presence* of a secret is logged.

| Variable | Default | Meaning |
|---|---|---|
| `PKINATIVE_MCP_OUTPUT_DIR` | *(unset)* | Absolute path of the one sandbox: every `path` input is read from it, `outputMode: 'file'` artefacts are written under it (exclusive create, never overwritten), and `resources/*` list and serve it. The real path of every file read and of every parent written must stay inside — a planted symlink or junction is `SECURITY_VIOLATION`. Key-bearing files (`.key .p8 .p12 .pfx`) may be named by any `path` input — no tool returns their key bytes — but are never written, never listed and never served as resources. Unset: inline PEM and base64 only |
| `PKINATIVE_MCP_CACHE_DIR` | *(unset)* | Opt-in content-addressed response cache: SHA-256 keyed, 1 h TTL, 256 MiB LRU, plaintext at rest, namespaced by tool API, package and engine version. Never caches a `path` input, file output, a call carrying a `password` or a `signer`, a `'random'` serial or nonce, a `'now'` or unpinned instant, `describe_engine`, `draft_governance_issue`, nor any password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set. A hit carries `_meta.cached: true` |
| `PKINATIVE_MCP_PORT` | *(unset → stdio)* | Serve Streamable HTTP on `127.0.0.1:<port>/mcp` instead of stdio |
| `PKINATIVE_MCP_HTTP_TOKEN` | *(unset)* | *(secret)* Opt-in bearer token for HTTP: at least 16 characters, no whitespace (a weaker value refuses to start); compared in constant time, never logged |
| `PKINATIVE_MCP_PASSWORD` | *(unset)* | *(secret)* The operator-side password of the encrypted PKCS#8 key or PKCS#12 file the tools open, which keeps the secret out of the model transcript. It counts as the password of every password-accepting tool, so describing a file without a password needs it unset. Exclusive with the per-call `password` input (both at once is `VALIDATION_ERROR`) |
| `PKINATIVE_MCP_AT` | *(unset → wall clock)* | Pinned instant (ISO 8601 or epoch milliseconds) that every omitted `at`, `notBefore` and `signingTime` falls back to, for reproducible verdicts and artefacts. Unset, a clock-dependent result is never cached |
| `PKINATIVE_MCP_MAX_INPUT_BYTES` | `67108864` (64 MiB) | Operator ceiling for `limits.maxInputBytes` and the decoded size of one PKI object; integer ≥ 1024 |
| `PKINATIVE_MCP_MAX_KDF_ITERATIONS` | `10000000` | Operator ceiling for `limits.maxKdfIterations` and `limits.maxPkcs12KdfIterations`: the CPU bound of a hostile PBES2 key or PKCS#12 file; integer ≥ 1 |
| `PKINATIVE_MCP_MAX_PATHS_EXPLORED` | `1000` | Operator ceiling for `limits.maxPathsExplored`: the RFC 5280 §6 path-building work bound; integer ≥ 1 |

**The operator ceilings.** A call may raise any of the engine's 22 limits through its `limits` input, for trusted input only; four of them are capped by the three ceilings above (`PKINATIVE_MCP_MAX_KDF_ITERATIONS` bounds both KDF limits), and a value above a ceiling is refused with `LIMIT_CEILING_EXCEEDED`, `data.env` naming the variable an operator would raise. There is no "unbounded", and no ceiling a tool argument can move.

## Protocol and transport

- **MCP 2026-07-28** on the MCP TypeScript SDK v2 (`@modelcontextprotocol/server`): stateless serving through `server/discover`, the `_meta` `serverInfo` envelope and `resultType` on every result, `Mcp-Method` / `Mcp-Name` headers over HTTP, and cache hints — `tools/list` and `prompts/list` public for 24 h, `server/discover` public for 1 h, the resource methods private with `ttlMs: 0`.
- **Automatic legacy fallback** for clients that open with `initialize`: the five legacy revisions 2024-10-07, 2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25 are negotiated on both transports, and the `tools/call` payload is identical on every path.
- **stdio is the default transport**, with the frame cap raised to 256 MiB so a multi-MiB base64 CMS message or PKCS#12 fits in one call; stdout carries JSON-RPC frames only.
- **Schemas.** Every tool advertises an `inputSchema` and an `outputSchema`; every object input is closed (an unknown or misspelt key at any depth is `VALIDATION_ERROR` naming the path), and input schemas carry no `$schema` keyword and no `$ref`, because some hosts forward them to function-calling APIs. Every `structuredContent` validates against the tool's `outputSchema`, projections included. Every tool carries `_meta.apiVersion` (`1.0.0`) and up to two executable `_meta.examples`.
- **Instructions.** The `initialize` / `server/discover` response carries a server-instructions block — which tool answers which question, the security posture and the pitfalls — and the seven prompts repeat that material on demand.
- **Protocol errors** are JSON-RPC errors: an unknown tool is `-32602` with `[UNKNOWN_TOOL] Unknown tool: …`, an unknown resource URI `-32602` with `data.uri` (the server's `UNKNOWN_RESOURCE` code is not sent on the wire). `isError: true` is reserved for execution failures.

## Tool reference

Thirty-four tools in six groups, listed here in the order `tools/list` returns them. Every tool advertises `openWorldHint: false` and `destructiveHint: false`; the other annotations put each in one of three classes:

| Annotation class | `readOnlyHint` | `idempotentHint` | Tools |
|---|---|---|---|
| read-only | true | true | 23: `resolve_oid`, `compute_fingerprint`, `decode_asn1`, `inspect_certificate`, `decode_extension`, `check_certificate_name`, `check_certificate_purpose`, `inspect_csr`, `verify_certificate_chain`, `build_certificate_path`, `validate_certificate_path`, `inspect_crl`, `check_crl_revocation`, `inspect_ocsp_response`, `check_ocsp_status`, `verify_cms`, `inspect_cms`, `inspect_timestamp`, `verify_timestamp`, `inspect_private_key`, `inspect_pkcs12`, `describe_engine`, `explain_code` |
| writes a deterministic artefact | false | true | 6: `convert_pem`, `encode_asn1`, `encode_x509_structure`, `amend_cms`, `open_pkcs12`, `draft_governance_issue` |
| produces a non-idempotent artefact | false | false | 5: `create_certificate`, `create_csr`, `create_ocsp_request`, `sign_cms`, `create_timestamp_request` — a random serial or nonce, the wall clock, or randomised ECDSA |

A tool's **kind** says how its result is shaped: a *read* tool returns facts in `structuredContent`; a *verdict* tool returns `valid` and `reasons[]` and is never `isError` for a negative verdict; an *artefact* tool delivers its bytes once, as an embedded `resource` block inline or a `resource_link` in file mode, with `{ mode, encoding, sizeBytes, sha256, summary, diagnostics }` in `structuredContent`.

**Shared inputs.** The tool sections below name these fragments rather than repeating them:

| Fragment | Shape | Rules |
|---|---|---|
| PKI input | `{ pem }` \| `{ derBase64 }` \| `{ path }` | Exactly one. `pem` is RFC 7468 text; `derBase64` is the DER as base64, exactly once (no `data:` URI, not PEM); `path` is relative to the sandbox, with an allow-listed extension. The label is checked before any byte is parsed (`PKI_PEM_UNEXPECTED_LABEL`); a PEM text holding several blocks where one object is expected is refused |
| PKI bundle | 1–256 PKI inputs | `trustAnchors`, `candidates`, `crls`, `ocspResponses`, `chain`, `path`: every PEM block of every item is taken, in order |
| Content input | `{ text }` \| `{ base64 }` \| `{ path }` | The bytes to sign, verify or timestamp: UTF-8 text, base64 (≤ 128 MiB decoded) or a sandbox file (≤ 1 GiB); a sandbox file that is key-bearing by extension or holds key material is `SECURITY_VIOLATION` (inline `text` and `base64` are taken as given) |
| Parse options | `encodingRules`, `pemMode`, `strict`, `limits` | `'der'` (default) or `'ber'`; `'strict'` (default) or `'lax'` PEM; `strict: true` escalates the first engine warning to `PKI_STRICT_DIAGNOSTIC`; `limits` raises the engine's named bounds under the operator ceilings |
| Signer | `{ key }` \| `{ p12 }`, plus `password`, `keyType`, `hash`, `rsaScheme`, `saltLength` | A PKCS#8 key (plain or PBES2) or a PKCS#12 (PBES2 and PBMAC1), imported as a non-extractable Web Crypto key. The algorithm follows the key; RSA requires `rsaScheme` (`'pkcs1'` \| `'pss'`); an encrypted key needs a password and a `keyType` unless a certificate or public key input names it |
| Trust | `trustAnchors`, `candidates`, `crls`, `ocspResponses`, `at`, `requireRevocation`, `purposes`, `policy` | A verdict is relative to the anchors you name. `at` is a string: ISO 8601 (UTC unless zoned), epoch milliseconds as digits, or `'now'`; omitted, `PKINATIVE_MCP_AT`, else the wall clock |
| Projection | `verbosity`, `fields` | See [Token-frugal reads](#token-frugal-reads) |
| Output | `outputMode`, `outputPath`, `encoding` | `'base64'` (default, inline ≤ 50 MiB) or `'file'` (a relative `outputPath` in the sandbox, never overwritten, ≤ 1 GiB); `encoding` `'pem'`, `'der'` or `'hex'` (inline only, ≤ 64 KiB, in `structuredContent.hex`) |

Every engine tool's result also carries `diagnostics[]` (de-duplicated by code and path, at most 200) and `diagnosticCounts` (`describe_engine`, `explain_code` and `draft_governance_issue` carry none).

## Encodings

### `convert_pem`

**Purpose:** the RFC 7468 layer. `mode: 'decode'` lists every block of a PEM text (label, DER size, offset, SHA-256) and `extractIndex` delivers one as DER, PEM or hex; `mode: 'encode'` wraps exactly one DER value into one strict block under `label`. **Key inputs:** `mode`, `input` (PKI input), `label`, `extractIndex`, parse options, projection, output. **Output:** `blocks[]`, `count`, `extracted`, and the artefact when a block is extracted or DER is wrapped. **Annotation:** writes a deterministic artefact (kind: read). A private-key block is listed (label, size, offset, SHA-256), never extracted and never produced: `extractIndex` on it, or `encode` of DER that holds key material or under a key label, is `SECURITY_VIOLATION`; an index past the last block is `NOT_FOUND`.

### `resolve_oid`

**Purpose:** object identifiers in one call. **Key inputs:** `mode` (`name` \| `validate` \| `list` \| `encode` \| `decode`), `oids[]` (≤ 1000), `filter`, `offset` / `limit` (200 by default, 2000 at most), `form` (`content` \| `tlv`), `relative`, `hex` or `input` as the `decode` source. **Output:** per mode, `oids[]` with names or validity, `entries[]` with `total` / `hasMore`, or one `oid` and `name`; `encode` answers hex, never an artefact. **Annotation:** read-only. `validate` reports an invalid OID; `encode` and `decode` refuse one with `PKI_OID_INVALID`.

### `compute_fingerprint`

**Purpose:** the digest of one object. **Key inputs:** `input` (any label or DER; a bundle is refused), `mode` (`fingerprint` \| `key-id` \| `shake256`), `algorithm` (fingerprint: SHA-256 by default, or SHA-1, SHA-384, SHA-512; key-id: SHA-1 by default — RFC 5280 method 1 — or SHA-256; refused with `shake256`), `webcrypto`, `outputLength` (≤ 1 MiB, SHAKE256), `separator`, `letterCase`. **Output:** `hex`, `formatted`, `algorithm`, `sizeBytes`, `label`, and `from` (where a key identifier's public key came from). **Annotation:** read-only. No input byte is returned.

### `decode_asn1`

**Purpose:** the X.690 node tree of any DER (BER with `encodingRules: 'ber'`). **Key inputs:** `input` (never a private key or a PKCS#12), `sequence`, `nodePath` (`'0.2.1'`), `read` (`boolean`, `integer`, `small-integer`, `enumerated`, `null`, `bit-string`, `octet-string`, `oid`, `relative-oid`, `string`, `time`), `stringType`, `timeType`, `reencode`, `label`, `allowTrailingData`, `maxPreviewBytes` (default 32). **Output:** `nodes[]` (path, offset, lengths, tag, children, preview, OID and name), `nodeCount`, `truncated` (past 20 000 nodes), `value` (the typed read), `reencode.identical` and the re-encoded artefact. **Annotation:** read-only. A key or PKCS#12 is `SECURITY_VIOLATION`; a missing `nodePath` step is `NOT_FOUND`.

### `encode_asn1`

**Purpose:** a JSON node `spec` encoded to DER through the engine's own encoders — the inverse of `decode_asn1`. **Key inputs:** `spec` (`boolean`, `integer`, `enumerated`, `null`, `bit-string`, `named-bits`, `octet-string`, `oid`, `relative-oid`, `string`, `time`, `sequence`, `set`, `set-of`, `explicit`, `implicit`, `tlv`, `der`), `label`, parse options, output (DER by default). **Output:** the artefact and `summary` (root tag, node count). **Annotation:** writes a deterministic artefact. A malformed spec is `VALIDATION_ERROR` naming the JSON path; nesting past `limits.maxDepth` is `PKI_LIMIT_EXCEEDED`; a value that parses as a key or a PKCS#12 is `SECURITY_VIOLATION`.

## Certificates and requests

### `inspect_certificate`

**Purpose:** the RFC 5280 report of one certificate. **Key inputs:** `certificate`, `extension` (one of the 19 kinds), `rawExtensions`, `issuer` or `checkSelfSignature`, `requireAlgorithmMatch`, `fingerprints[]`, `allowSha1`. **Output:** `version`, `serialNumber`, `signatureAlgorithm`, `issuer` / `subject` with their RFC 4514 strings, `validity`, `subjectPublicKeyInfo`, `extensions[]`, `selfIssued`, `fingerprints`, and `signature` when one was checked. **Annotation:** read-only. One signature check against one key is not trust: `verify_certificate_chain` is. A missing `extension` is `NOT_FOUND`; a key given as a certificate is `PKI_PEM_UNEXPECTED_LABEL`; SHA-1 without `allowSha1` is `PKI_CRYPTO_ALGORITHM_REFUSED`.

### `create_certificate`

**Purpose:** issue an X.509 v3 certificate — a self-signed CA, or a leaf issued from a certificate, a CSR or a `PUBLIC KEY`. **Key inputs:** `spec` (`serialNumber` — an integer, a hex string or `'random'`, the default; `subject`; `issuer`; `notBefore`; `notAfter` or `validityDays`; `extensions`), `issuerCertificate` (omitted: self-signed), `subjectPublicKey`, `signer`, `allowSha1`, output (PEM by default). **Output:** the artefact and `summary` (`serialNumber`, `randomSerial`, subject, issuer, `selfSigned`, `signatureAlgorithm`, `notBefore` / `notAfter` with `notBeforeSource`, extension kinds, `signatureVerified`, `publicKeyFrom`). **Annotation:** produces a non-idempotent artefact. The certificate is verified against its issuer before the bytes return (`KEY_MISMATCH` otherwise); `RSA_SCHEME_REQUIRED`, `KEY_TYPE_REQUIRED`, `SECRET_REQUIRED`, `UNSUPPORTED_KEY` name what the signer lacks.

### `encode_x509_structure`

**Purpose:** one X.509 building block encoded deterministically from a closed `spec`; nothing here signs. **Key inputs:** `structure` (`name`, `name-attribute`, `validity`, `spki`, `algorithm-identifier`, `attribute`, `extension`, `extensions`, `basic-constraints`, `key-usage`, `extended-key-usage`, `subject-alt-name`, `subject-key-identifier`, `authority-key-identifier`, `signature-algorithm`), `spec`, `signer` (`signature-algorithm` only: only the key's algorithm is read), `label`, output (hex by default). **Output:** the artefact and `summary`. **Annotation:** writes a deterministic artefact. An unknown or missing spec member is `VALIDATION_ERROR` naming it, never dropped silently.

### `decode_extension`

**Purpose:** one `extnValue` content decoded by its OID exactly as `inspect_certificate` would. **Key inputs:** `oid`, `valueHex` or `value` (the DER inside the OCTET STRING), `critical`. **Output:** `kind`, `oid`, `name`, `critical`, `sizeBytes`, `decoded`, and the criticality check as a diagnostic. **Annotation:** read-only. A malformed value is `PKI_X509_EXTENSION_MALFORMED`, with `decode_asn1` as its remedy.

### `check_certificate_name`

**Purpose:** the RFC 6125 identity verdict. **Key inputs:** the certificate form — `certificate` with `host` or `ip`, `chain[]` (for the commonName fallback's name constraints), `allowCommonNameFallback` (default false), `allowWildcards` (default true) — or the match form, `presented` and `reference` with no certificate. **Output:** `form`, `valid`, `reasons[]`, `reference`, `subject` or `presented`, `match`. **Annotation:** read-only (kind: verdict). `PKI_REASON_NAME_MISMATCH` arrives in `reasons[]`, never as `isError`; both forms at once is `VALIDATION_ERROR`.

### `check_certificate_purpose`

**Purpose:** the RFC 5280 §4.2.1.12 purpose verdict along `[certificate, ...chain]`. **Key inputs:** `certificate`, `chain[]` (the leaf's issuer first), `purpose` (`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`, `any` or a dotted OID), `restrictIssuers` (default true), `requireExplicitPurpose` (default false). **Output:** `valid`, `reasons[]`, `purposeOid`, `purposeName`, `subject`, `pathLength`. **Annotation:** read-only (kind: verdict); `PKI_REASON_PURPOSE_NOT_PERMITTED` arrives in `reasons[]`.

### `inspect_csr`

**Purpose:** the RFC 2986 report of one PKCS#10 request. **Key inputs:** `request`, `rawExtensions`, `verify` (default true: the proof of possession, one Web Crypto verification), `allowSha1`. **Output:** `subject`, `subjectPublicKeyInfo`, `attributes[]`, `extensions[]`, `challengePassword` (present or not, never its text), `signatureAlgorithm`, `signature` (`valid`, `reasons[]`). **Annotation:** read-only.

### `create_csr`

**Purpose:** a PKCS#10 request from `spec`, signed by `signer`. **Key inputs:** `spec` (`subject`, the extensions to request: `subjectAltName`, `keyUsage`, `extendedKeyUsage`, `basicConstraints`, `subjectKeyIdentifier`, raw), `subjectPublicKey` (required for an encrypted PKCS#8 key), `signer`, `allowSha1`, output (PEM by default). **Output:** the artefact and `summary` (subject, `signatureAlgorithm`, the requested extension kinds, `signatureVerified`, `publicKeyFrom`). **Annotation:** produces a non-idempotent artefact. The proof of possession is verified before the bytes return; a key that does not match the public key named is `KEY_MISMATCH`.

## Paths, CRLs and OCSP

### `verify_certificate_chain`

**Purpose:** the one-call trust verdict — a path from `leaf` through `candidates` to one of your `trustAnchors`, every signature verified, RFC 5280 §6 validation at `at`, the server name (RFC 6125), the purposes, and revocation from the CRL and OCSP bytes you supply. **Key inputs:** `leaf`, `trustAnchors` (required), `candidates`, `crls`, `ocspResponses`, `at`, `requireRevocation` (demands evidence for the end-entity certificate), `purposes`, `policy`, `serverName` (`host` \| `ip`), `ocspNonce`, `requireOcspNonce`, `allowSha1`. **Output:** `valid`, `reasons[]`, `path[]` (leaf first), `pathLength`, `explored`, `signatureVerifications[]`, `evaluatedAt` with `evaluatedAtSource`, `revocationEvidence`. **Annotation:** read-only (kind: verdict). `PKI_REASON_NO_TRUST_ANCHOR`, `PKI_REASON_EXPIRED`, `PKI_REASON_NOT_YET_VALID`, `PKI_REASON_REVOKED`, `PKI_REASON_REVOCATION_UNKNOWN`, `PKI_REASON_NAME_MISMATCH` and the other reasons arrive in `reasons[]`, never as `isError`.

### `build_certificate_path`

**Purpose:** path discovery only — which intermediates lead from `leaf` to an anchor under the structural rules at `at`. **No signature is checked.** **Key inputs:** `leaf`, `trustAnchors`, `candidates`, `at`, `purposes`, `policy`. **Output:** `found`, `structuralReasons[]`, `path[]`, `pathLength`, `explored`, `valid` (always false), `reasons[]` (always holding `PKI_REASON_SIGNATURE_NOT_CHECKED`), `signaturesChecked: false`. **Annotation:** read-only (kind: verdict). With no path to an anchor, `structuralReasons[]` holds `PKI_REASON_NO_TRUST_ANCHOR`.

### `validate_certificate_path`

**Purpose:** RFC 5280 §6.1 validation of a path you ordered, leaf first, against your anchors at `at`; every link signature is verified first. No revocation here. **Key inputs:** `path[]`, `trustAnchors`, `at`, `checkSignatures` (default true; false gives the structural verdict), `policy`, `allowSha1`. **Output:** `valid`, `reasons[]`, `failingReasons[]`, `path[]`, `signaturesChecked`, `signatures[]` (one verdict per link), `evaluatedAt`. **Annotation:** read-only (kind: verdict).

### `inspect_crl`

**Purpose:** the RFC 5280 §5 report of one CRL. **Key inputs:** `crl`, `find` (`serialHex` \| `certificate`), `issuer` (one signature check), `allowSha1`. **Output:** `issuer`, `signatureAlgorithm`, `thisUpdate` / `nextUpdate`, `crlNumber`, `isDelta`, `baseCrlNumber`, `issuingDistributionPoint`, `entryCount` (walked, never all decoded), `extensions[]`, `entry` (revoked, revocation date, reason, invalidity date), `signature`. **Annotation:** read-only.

### `check_crl_revocation`

**Purpose:** one `certificate` against one base `crl` (and an optional `delta`) you fetched, at `at`: scope, freshness, the signature verified against `issuer`, the serial looked up. **Key inputs:** `certificate`, `crl`, `delta`, `issuer` (without it the list is not evidence: `PKI_REASON_REVOCATION_UNKNOWN`), `at`, `staleTolerance` (ms), `allowSha1`. **Output:** `valid`, `reasons[]`, `signatureVerified`, `deltaSignatureVerified`, `crlNumber`, `isDelta`, `deltaCrlNumber`, `evaluatedAt`. **Annotation:** read-only (kind: verdict). A `delta` whose signature does not verify is not applied; a `delta` without a deltaCRLIndicator is `VALIDATION_ERROR`.

### `create_ocsp_request`

**Purpose:** the DER OCSPRequest (RFC 6960) for `certificate` under `issuer`, which you POST to the responder yourself. **Key inputs:** `certificate`, `issuer`, `hashAlgorithm` (`SHA-1` by default \| `SHA-256`), `nonce` (`'random'` or 1–32 bytes of hex, RFC 8954), `certIdOnly`, `label`, output (DER by default). **Output:** the artefact and `summary` (`certIdHex`, `nonceHex`, `randomNonce`, serial, subject, issuer) — keep `nonceHex` to demand it back from `check_ocsp_status`. **Annotation:** produces a non-idempotent artefact.

### `inspect_ocsp_response`

**Purpose:** the RFC 6960 report of one response. **Key inputs:** `response`, `responder` (one signature check; omitted, the embedded certificates are tried). **Output:** `status`, `basicResponse` (responder id, producedAt, every SingleResponse with its CertID, status and updates, extensions, certificates), `noncePresent`, `signature` (valid, source). **Annotation:** read-only.

### `check_ocsp_status`

**Purpose:** one `response` for one `certificate`: the CertID recomputed from `issuer`, the signature verified, the signer authorised (the CA, or a delegate it issued with OCSPSigning, RFC 6960 §4.2.2.2), the status, freshness at `at` and the nonce. **Key inputs:** `response`, `certificate`, `issuer` (all three required), `responder`, `responderTrusted`, `hashAlgorithm`, `nonce` (hex), `requireNonce`, `at`, `staleTolerance`, `futureTolerance`, `allowSha1`. **Output:** `valid`, `reasons[]`, `status` (`good` \| `revoked` \| `unknown` \| null), `signatureVerified`, `responderAuthorized`, `responder`, `responderSource`, `hashAlgorithm`, `certIdHex`, `evaluatedAt`. **Annotation:** read-only (kind: verdict). A response whose status is not successful is a negative verdict with `status: null`.

## CMS and timestamps

### `sign_cms`

**Purpose:** an RFC 5652 SignedData over `content` (attached or detached) or a precomputed digest. The signed attributes contentType, messageDigest, signingTime, SigningCertificateV2 and CMSAlgorithmProtection are written by default. **Key inputs:** `content` (content input) or `contentDigest` (hex, `detached` only), `detached`, `contentType`, `certificate`, `chain[]`, `crls[]`, `sid` (`issuerAndSerialNumber` by default \| `subjectKeyIdentifier`), `signingTime` (an instant, `'now'` or `'none'`), `signingCertificateV2`, `algorithmProtection`, `signedAttributes[]` / `unsignedAttributes[]` (DER attributes as hex), `signer` (the only required input), `allowSha1`, output (DER by default). **Output:** the artefact and `summary` (`detached`, `contentType`, signer subject and serial, `sid`, digest and signature algorithms, `signingTime` with its source, certificates and CRLs embedded, attribute counts, `signatureVerified`). **Annotation:** produces a non-idempotent artefact. The new signature is verified against the signer certificate before the bytes return (`KEY_MISMATCH` otherwise).

### `verify_cms`

**Purpose:** the one-call verdict on a SignedData: for every signer the signed attributes, the content digest, the signature, the chain to your `trustAnchors` at `at`, every counter timestamp, and revocation from the bytes you supply and those the message carries. **Key inputs:** `signedData`, `trustAnchors` (required), `content` or `contentDigest` (detached signatures), `candidates`, `crls`, `ocspResponses`, `at`, `requireRevocation`, `purposes`, `atTimeStamp` (validate at the verified timestamp), `requireSigningCertificate`, `requireAlgorithmProtection`, `allowTrailingData`, `allowSha1`. **Output:** `valid`, `reasons[]`, `signers[]` (per signer `valid`, `intact`, `reasons[]`, chain, timestamps, revocation), `signerCount`, `signatureVerifications[]`, `evaluatedAt`, `atTimeStamp`. **Annotation:** read-only (kind: verdict). `valid` means unaltered and trusted; `signers[i].intact` means unaltered only.

### `inspect_cms`

**Purpose:** the RFC 5652 report. **Key inputs:** `signedData`, `allowTrailingData`, `signerCertificate` (one key check on the signer `signerIndex` names), `signerIndex`, `content`, `allowSha1`. **Output:** `version`, `contentType`, `contentLength` (null when detached), `digestAlgorithms[]`, `certificates[]`, `crlCount`, `ocspResponseCount`, `signerInfos[]` (identifier, algorithms, signing time as claimed, attributes, timestamp count, and the `signature` value a counter timestamp stamps, as hex), `signerSignature`. **Annotation:** read-only. `signerSignature` is a key check, not the verdict.

### `amend_cms`

**Purpose:** the one edit a signed message legitimately receives afterwards, every signed octet unchanged. **Key inputs:** `signedData`, `signerIndex`, `operation` (`add-unsigned-attribute` \| `add-timestamp`), `attribute` (a DER Attribute as hex), `token` (a TimeStampToken or a whole TimeStampResp), `allowSha1`, output (DER by default). **Output:** the artefact and `summary`. **Annotation:** writes a deterministic artefact. The token's imprint is checked against the signer's signature value before anything is written: a token over anything else is `VALIDATION_ERROR` with `data.detail` `PKI_REASON_TSP_IMPRINT_MISMATCH`, the remedy naming the `inspect_cms` → `create_timestamp_request` → `amend_cms` sequence.

### `create_timestamp_request`

**Purpose:** the RFC 3161 TimeStampReq you POST to a TSA yourself. **Key inputs:** `data` (content input) or `digestHex`, `hashAlgorithm` (`SHA-256` by default \| `SHA-384` \| `SHA-512`), `nonce` (`'random'`, decimal or `0x` hex), `policy`, `certReq` (default true), `label`, output (DER by default). **Output:** the artefact and `summary` (`imprintHex`, `hashAlgorithm`, `nonce`, `randomNonce`, `policy`, `certReq`). **Annotation:** produces a non-idempotent artefact. A digest whose length does not match the algorithm is `VALIDATION_ERROR`.

### `inspect_timestamp`

**Purpose:** a TimeStampResp, a TimeStampToken or a bare TSTInfo, auto-detected or named with `as`. **Key inputs:** `input`, `as` (`response` \| `token` \| `tstinfo`). **Output:** `as`, `status` (status strings, failInfo), `token` (signer count, certificates), `tstInfo` (policy, messageImprint, serialNumber, genTime, accuracy, ordering, nonce, the TSA name as stated, extensions). **Annotation:** read-only. Parsing proves nothing; `verify_timestamp` judges.

### `verify_timestamp`

**Purpose:** a `token` or `response` judged against what you say was stamped, the TSA signature, its chain to your anchors at `at` with a critical timeStamping EKU, and revocation from the bytes you supply. **Key inputs:** `token` or `response`, `request` (imprint, nonce and policy all checked), `data` or `digestHex` — at least one of `request`, `data`, `digestHex` — `trustAnchors` (required), `candidates`, `crls`, `ocspResponses`, `at`, `requireRevocation`, `allowNonCriticalTimeStampingEku`, `allowSha1`. **Output:** `valid`, `reasons[]`, `genTime`, `earliest` / `latest` (accuracy applied), `tsa`, `chain`, `signatureVerifications[]`, `evaluatedAt`. **Annotation:** read-only (kind: verdict). `PKI_REASON_TSP_IMPRINT_MISMATCH`, `PKI_REASON_TSP_NOT_GRANTED`, `PKI_REASON_TSP_REQUEST_MISMATCH` and `PKI_REASON_TSP_TOKEN_INVALID` arrive in `reasons[]`; nothing stamped given is `VALIDATION_ERROR`.

## Private keys and PKCS#12

### `inspect_private_key`

**Purpose:** describe a PKCS#8 key without its password — format, kind, curve, algorithm, attributes, the PBES2 parameters of an encrypted key or the legacy scheme pkinative refuses — and, with `tryImport: true`, import it as a non-extractable Web Crypto key and report the handle. **Key inputs:** `key`, `tryImport`, `password` (or `PKINATIVE_MCP_PASSWORD`), `keyType`, `hash`, `rsaScheme`, `saltLength`, `allowSha1`. **Output:** `format` (`pkcs8` \| `encrypted-pkcs8`), `kind`, `curve`, `algorithm`, `attributes`, `publicKey`, `encryption`, `encryptedBytes`, `imported` (handle type, algorithm, usages). **Annotation:** read-only. No result ever carries a key byte; a wrong password is `PKI_CRYPTO_DECRYPTION_FAILED`, a legacy cipher `PKI_KEY_ENCRYPTION_UNSUPPORTED` with the `openssl pkcs8` remedy.

### `inspect_pkcs12`

**Purpose:** describe a `.p12` or `.pfx` without its password: the MAC construction (PBMAC1, or the legacy RFC 7292 MAC), every SafeContents and its scheme, the bags of the plain ones. **Key inputs:** `pkcs12` (BER with `encodingRules: 'ber'` for a Windows-written PFX), `password` (optional). **Output:** `version`, `mac`, `contents[]`, `bagCount`, and with a password `macVerified` and `opened[]` (allow-list views of every bag). **Annotation:** read-only. A set `PKINATIVE_MCP_PASSWORD` counts as the password, so describing a file without one needs it unset.

### `open_pkcs12`

**Purpose:** open a PKCS#12 in one call: MAC verified, PBES2 SafeContents decrypted, every key unwrapped straight into a non-extractable Web Crypto key (described, never exported), certificates parsed, CRLs counted. **Key inputs:** `pkcs12`, `password` (or `PKINATIVE_MCP_PASSWORD`), `allowUnverifiedIntegrity`, `rsaScheme`, `hash`, `exportCertificates` (attach a PEM bundle of the certificates and CRLs — never a key), output (PEM only). **Output:** `valid`, `integrity` (`verified` \| `unverified` \| `mismatch`), `reasons[]`, `keys[]`, `certificates[]`, `keyCount` / `certificateCount` / `crlCount`, `exportSkipped`, the bundle artefact. **Annotation:** writes a deterministic artefact (kind: verdict). No password from either channel is `SECRET_REQUIRED`; `PKI_REASON_PKCS12_MAC_MISMATCH`, `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`, `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` and `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` arrive in `reasons[]`.

## Meta

### `describe_engine`

**Purpose:** the offline preflight. **Key inputs:** projection only. **Output:** `server` (name, version, tool API version, protocol, tool count), `engine` (name, version, Node.js floor), `capabilities` (`canVerify`, `canSign`, `canDecrypt`, `node`, `nodeFloorSatisfied`, platform), `randomness`, `defaultLimits` (the 22 engine limits), `ceilings`, `caps`, `sandbox` (enabled, cache enabled, pinned instant, the extension allow-lists), `network: 'none'`, `registries` (the engine's 57 error codes, 43 reasons and 97 diagnostics, the 21 wrapper codes, purposes, key-usage bits, the OID registry count), `refusals` (the doctrine) and `unexposed`. **Annotation:** read-only. Never cached.

### `explain_code`

**Purpose:** any code this server can emit, explained from the registries vendored at the pkinative v1.0.0 tag — class, standard, CWE, the version that brought it, the remedy and the MCP input that lifts it. **Key inputs:** `code`, or `list: true` with `kind` (`error` \| `reason` \| `diagnostic` \| `wrapper`); projection. **Output:** `code`, `kind`, `summary`, `standard`, `severity`, `errorClass`, `engineClass`, `cwe`, `since`, `remedy` — or `codes[]` and `count`. **Annotation:** read-only. An unknown code is `NOT_FOUND`.

### `draft_governance_issue`

**Purpose:** a local GitHub issue draft plus a compliance report, for `pkinative` (engine behaviour), `pkinative-cli` or `pkinative-mcp` (wrapper behaviour). The server never contacts GitHub — it has no network code path — and a human reviews and submits the draft under their own identity. **Key inputs:** `title`, `summary`, `issueType` (`bug` \| `feature` \| `security` \| `docs` \| `performance`), `targetRepo`, `reproduction` (`{ command, result }`), `expectedBehavior`, `actualBehavior`, `affectedPackages[]`, `duplicateSearchPerformed` (must be `true`), `outputMode` (`inline` \| `file`) with `outputPath` (a relative `.md` in the sandbox). **Output:** `draftMarkdown`, `warnings[]`, `compliance`. **Annotation:** writes a deterministic artefact. A draft that proposes a runtime dependency, embeds a private key or a password, has no reproduction, or was not preceded by a duplicate search is `GOVERNANCE_VIOLATION`.

## Prompts

Seven read-only prompts, without arguments: two carry the governance contract, five are ready-made PKI recipes that name the tools in order.

| Prompt | Title | What it walks through |
|---|---|---|
| `governance_contract` | AI-governance & HITL contract | The agent is a draftsman and the human the only gate: zero runtime dependencies, no autonomous GitHub writes, no network, no secret in a draft |
| `draft_issue_workflow` | Human-in-the-loop issue workflow | Drafting an issue with `draft_governance_issue` and handing it to a human for review and submission |
| `verify_before_trust` | Verify before you trust | `inspect_certificate` → `verify_certificate_chain` with a pinned instant → offline revocation evidence, and why a verified signature is not trust |
| `issue_certificate` | Issue a CA, a CSR and a leaf certificate | How `create_csr` and `create_certificate` chain together, what is derived, what is verified before the bytes return, and the key, scheme and instant rules |
| `sign_and_timestamp` | Sign content and add an RFC 3161 time-stamp | `sign_cms`, the counter timestamp over the signature value (`create_timestamp_request` → your TSA → `amend_cms`), and `verify_cms` as the one verdict |
| `offline_revocation` | Revocation without a network | Where to fetch CRL and OCSP evidence yourself, how `create_ocsp_request` builds the request, and how `check_crl_revocation`, `check_ocsp_status` and `verify_certificate_chain` judge the bytes you bring |
| `open_keys_safely` | Keys and PKCS#12 without leaking a byte | `inspect_private_key`, `inspect_pkcs12` and `open_pkcs12`: describe before opening, the PBES2 and PBMAC1 doctrine, the legacy-file remedy, the two password channels |

The [MCP use cases](use-cases-mcp.md) follow four of them call by call.

## Resources

With `PKINATIVE_MCP_OUTPUT_DIR` set, every regular file under the sandbox is a resource, addressed by the template `pkinative://output/{+path}` from `resources/templates/list`. `resources/list` enumerates at most 1000 files to a depth of 8, and `resources/read` serves one (PEM, Markdown, JSON and text as `text`, everything else as a base64 `blob`, at most 50 MiB). Key-bearing extensions are never listed and never served, and key material is refused by content too, whatever the file name — a PEM key after a prefix, a key among many blocks, a raw DER key behind junk, base64 key material inside a text file. An artefact written with `outputMode: 'file'` comes back as a `resource_link` to its `pkinative://output/<path>` URI, so a `create_csr` → `create_certificate` → `verify_certificate_chain` sequence never re-sends the bytes.

## Token-frugal reads

The read, verdict and engine tools, `explain_code` included, accept two optional inputs:

- **`verbosity: 'summary'`** keeps the tool's canonical scalar subset and drops the heavy arrays. `verify_certificate_chain` then answers `{ valid, reasonCodes, pathLength, evaluatedAt, revocationEvidence, diagnosticCount }`; `inspect_certificate` answers the serial, subject and issuer strings, validity, key kind and extension kinds.
- **`fields: ['a', 'b.c']`** projects the result to at most 16 dot-paths, applied after `verbosity`; an array segment maps over every element. A path that matched nothing is omitted and reported in `_meta.unmatchedFields`, with `_meta.availableFields`; a `__proto__`, `constructor` or `prototype` segment is `VALIDATION_ERROR`.

Because a result can be projected, these tools declare every property of their `outputSchema` optional, so a projected `structuredContent` still validates. Artefacts are never duplicated into `structuredContent`: they arrive once, as an embedded `resource` block (PEM as `text`, DER as a `blob` with its media type — `application/pkix-cert`, `application/pkcs10`, `application/pkcs7-signature`, `application/ocsp-request`, `application/timestamp-query`, …) or as a `resource_link`, and `structuredContent.sha256` is the SHA-256 of the DER — the reproducibility proof when serial, nonce and instants are pinned.

The smallest "can I trust this server certificate?" probe:

```json
{ "leaf": { "path": "leaf.crt.pem" }, "trustAnchors": [{ "path": "root.crt.pem" }], "at": "2027-01-01T00:00:00Z", "serverName": { "host": "example.test" }, "verbosity": "summary", "fields": ["valid", "reasonCodes"] }
```

## Error model

A refused call is a tool result with `isError: true`, `content[0].text` = `<tool> failed [CODE]: message` and `_meta.error = { code, message, data }`. The code is one of two kinds:

- **One of pkinative's 57 `PKI_*` error codes, passed through verbatim** as `_meta.error.code`, with `data.errorClass` (the coarse class: `usage`, `input`, `parse`, `security`, `limit`, `unsupported`, `crypto`, `password`, `check`, `internal`), `data.engineError` (the `PkiError` subclass), `path`, `offset`, `algorithm`, `limit`, `configured`, `observed` or `env` where the engine knows them, and `data.remedy` phrased as MCP inputs.
- **One of the server's 21 wrapper codes**, for the boundary the engine does not own — validation, sandbox, caps, secrets and output — each with its remedy:

| Wrapper code | Raised when |
|---|---|
| `VALIDATION_ERROR` | The input fails the schema: a wrong type, bound or enum, an unknown key at any depth, none or several of the exclusive members, SHA-1 without `allowSha1`, a password given twice |
| `INPUT_TOO_LARGE` | A decoded inline input, the sum of inline inputs, or a sandbox file exceeds its cap |
| `INPUT_NOT_FOUND` | A path input does not exist in the sandbox, or is not a regular file |
| `INVALID_PATH` | A path member is empty or not a string |
| `INVALID_EXTENSION` | A path input or `outputPath` does not end in an allowed extension |
| `SECURITY_VIOLATION` | File I/O without a sandbox; an absolute, drive, UNC or escaping path; a link whose real path leaves the sandbox; a key-bearing `outputPath`; an attempt to extract, dump or serve private-key material |
| `OUTPUT_TOO_LARGE` | An artefact above its inline, hex, file or resource cap |
| `OUTPUT_EXISTS` | The target file already exists — the server never overwrites |
| `MISSING_OUTPUT_PATH` | `outputMode: 'file'` without `outputPath` |
| `IO_ERROR` | A filesystem operation failed; the message carries the errno, never an absolute path |
| `LIMIT_CEILING_EXCEEDED` | A `limits.*` value above its operator ceiling (`data.env` names the variable) |
| `UNKNOWN_RESOURCE` | `resources/read` outside `pkinative://output/`, or of a missing file — surfaced as JSON-RPC `-32602` with `data: { uri }`; the code name itself is not sent |
| `GOVERNANCE_VIOLATION` | A `draft_governance_issue` draft breaks the AI-governance contract |
| `SECRET_REQUIRED` | An encrypted key, a PKCS#12 or a MAC check needs a password and none was given |
| `KEY_TYPE_REQUIRED` | An encrypted PKCS#8 key whose type nothing names (`signer.keyType`, a certificate or a public key) |
| `RSA_SCHEME_REQUIRED` | An RSA key without `rsaScheme`: there is no default RSA signature scheme |
| `KEY_MISMATCH` | The signing key does not belong to the certificate, issuer or public key it was paired with |
| `UNSUPPORTED_KEY` | A key algorithm Web Crypto cannot sign with on this host |
| `NOT_FOUND` | A named element is absent: an extension, a `nodePath` step, a `signerIndex`, an `extractIndex`, a code |
| `ENGINE_VERDICT` | A one-call engine operation (opening a PKCS#12 to sign) came back negative; `data.reasons` carries the `PKI_REASON_*` codes |
| `ENGINE_ERROR` | The engine threw something that is not a `PkiError`: a bug, to report with a reproduction |

Two real results, from the 1.0.0 server. The first `PKI_*` code is raised by the server's own label check before any byte reaches the engine, so its `data` carries no `engineError`:

```json
{"content":[{"type":"text","text":"inspect_certificate failed [PKI_PEM_UNEXPECTED_LABEL]: certificate (fixtures/leaf.key.pem) holds no CERTIFICATE or X509 CERTIFICATE or TRUSTED CERTIFICATE PEM block (labels present: PRIVATE KEY)."}],"isError":true,"_meta":{"error":{"code":"PKI_PEM_UNEXPECTED_LABEL","message":"certificate (fixtures/leaf.key.pem) holds no CERTIFICATE or X509 CERTIFICATE or TRUSTED CERTIFICATE PEM block (labels present: PRIVATE KEY).","data":{"errorClass":"input","path":"certificate","remedy":"convert_pem mode:'decode' (lists the labels present)"}}}}
{"content":[{"type":"text","text":"create_certificate failed [RSA_SCHEME_REQUIRED]: An RSA key needs signer.rsaScheme:'pkcs1'|'pss': pkinative has no default RSA signature scheme."}],"isError":true,"_meta":{"error":{"code":"RSA_SCHEME_REQUIRED","message":"An RSA key needs signer.rsaScheme:'pkcs1'|'pss': pkinative has no default RSA signature scheme.","data":{"path":"signer.rsaScheme","remedy":"rsaScheme:'pkcs1'|'pss'"}}}}
```

**A negative verdict is not an error.** A verdict tool that answers *no* returns `valid: false` and `reasons[]` — the engine's `PKI_REASON_*` codes, each with its message, standard and path — in `structuredContent`, with `isError` false. `isError` means the input itself was refused, or the call was wrong. `PKI_DIAG_*` diagnostics are not errors either: they ride in `diagnostics[]` unless `strict: true` escalates the first warning to `PKI_STRICT_DIAGNOSTIC`.

**`explain_code`** explains any of these codes — a `PKI_*` error, a `PKI_REASON_*` reason, a `PKI_DIAG_*` diagnostic or a wrapper code. The [errors guide](errors.md) documents the engine's three vocabularies, and [Where the codes surface](errors.md#where-the-codes-surface) compares the library, CLI and MCP views.

## Security model

- **No network, ever.** The server has no network code path: no CRL, OCSP, AIA or TSA fetch, no telemetry, no GitHub, no update check, no URL from any tool argument, no operator-configurable endpoint. `describe_engine` reports `network: 'none'` and every tool advertises `openWorldHint: false`. Revocation evidence and timestamp tokens are inputs you fetched; `create_ocsp_request` and `create_timestamp_request` produce the bytes you transport.
- **No key byte is ever returned.** Signing keys are imported into non-extractable Web Crypto handles; every key and PKCS#12 report is an allow-list view built field by field; key-bearing files are never written and never served as resources; `convert_pem` never extracts or wraps private-key material, and `decode_asn1` and `encode_asn1` refuse it. There is no key generation and no key export, and the test suite proves with needles computed from the fixtures that no key byte, scalar, JWK member or password reaches a result, stderr, a cache file or the stdio transcript.
- **Two password channels, never a third.** The per-call `password` input, or the operator's `PKINATIVE_MCP_PASSWORD` — one per call. A password is never echoed, logged, cached or served; a call carrying one is never cached.
- **One sandbox.** `PKINATIVE_MCP_OUTPUT_DIR` is the only filesystem boundary, for reads (every `path` input, `resources/read`) and writes (`outputPath`, governance drafts): relative paths only, no traversal, NUL bytes or unlisted extensions, the real path of every file read and of every parent written inside it, exclusive creates, and a partial file removed when a write fails. In `outputMode: 'file'` a result names the absolute path it wrote, in `structuredContent.filePath` and in its text; that is the one place a host path reaches the transcript. Unset, no tool touches the filesystem; the opt-in response cache under `PKINATIVE_MCP_CACHE_DIR` is the only other I/O the server performs.
- **Ceilings and caps.** The engine's 22 limits apply to every call and rise only by explicit input, never above the operator ceilings; every byte and count the wrapper bounds is a constant `describe_engine.caps` advertises — 256 MiB per stdio frame or HTTP body, 128 MiB of inline PKI input per call, 50 MiB per inline artefact, 1 GiB per file output, 64 KiB per hex artefact.
- **The engine's doctrine, surfaced.** SHA-1 only with `allowSha1: true`; RSA only with an explicit `rsaScheme`; PBES2 and PBMAC1 only, a legacy RC2 or 3DES PKCS#12 refused with the OpenSSL 3.4 conversion as remedy; DSA and ML-DSA parsed, never verified; no writer for PKCS#8, PKCS#12, CRLs, OCSP responses or timestamp responses. `describe_engine.refusals` lists each line with its remedy.

The server's own conformance gate has OpenSSL 3 read back every artefact it writes, in CI and before every publish; the [conformance guide](conformance.md) covers the engine underneath, and the [security guide](security.md) its threat model.

## Further reading

- [MCP tool explorer](../playgrounds/mcp.html) — the client configuration, and each tool's `tools/call` payload with the engine call behind it run in your tab.
- [MCP use cases](use-cases-mcp.md) — a failing TLS chain, a test certificate, offline revocation, keys opened safely.
- [CLI guide](cli.md) — the same engine on the command line.
- [Choosing a library and a surface](choose.md#choosing-your-surface) — library, CLI or MCP server, per capability.
- The server's [agent contract](https://github.com/Nizoka/pkinative-mcp/blob/main/docs/AGENT_CONTRACT.md), its [AI agent guide](https://github.com/Nizoka/pkinative-mcp/blob/main/docs/AI_GUIDE.md), its [llms.txt](https://github.com/Nizoka/pkinative-mcp/blob/main/llms.txt) and its [README](https://github.com/Nizoka/pkinative-mcp/blob/main/README.md).
