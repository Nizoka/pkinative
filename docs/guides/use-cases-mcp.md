# MCP use cases

> **Four conversations built from the pkinative-mcp examples and prompts: triaging a failing TLS chain, issuing a test certificate, checking revocation offline, and opening keys without leaking a byte.**

pkinative-mcp 1.0.0 ships an `examples/` directory of executable tool calls that its test suite runs against the server, and seven prompts, five of which are PKI recipes naming the tools in order. Each case below follows one prompt, with the calls taken from those examples. The examples address the test PKI as `fixtures/…` inside the sandbox (`PKINATIVE_MCP_OUTPUT_DIR`), where their runner copies it; `test-only-password` is that PKI's published password. Every payload is a `tools/call` request's `params`, every result was printed by the 1.0.0 server, and the tools and their inputs are documented in the [MCP guide](mcp.md).

## Case 1 — An agent triages a failing TLS chain

A user pastes a server certificate and says their TLS client rejects it. The `verify_before_trust` prompt gives the agent the order: describe the certificate, then ask for the verdict at a pinned instant, then bring revocation evidence — and branch on `reasons[].code`, never on message text.

**Describe first** (`examples/inspect-certificate-summary.json`):

```json
{ "name": "inspect_certificate", "arguments": { "certificate": { "path": "fixtures/leaf.crt.pem" }, "verbosity": "summary" } }
```

```json
{"serialNumberHex":"1001","subjectString":"CN=example.test,O=pkinative-cli test,C=FR","issuerString":"CN=Test Intermediate CA,O=pkinative-cli test,C=FR","notBefore":"2026-01-01T00:00:00.000Z","notAfter":"2046-01-01T00:00:00.000Z","publicKey":"ec","extensionKinds":["basicConstraints","keyUsage","extendedKeyUsage","subjectAltName","subjectKeyIdentifier","authorityKeyIdentifier","crlDistributionPoints","authorityInfoAccess"],"selfIssued":false,"diagnosticCount":0}
```

**Then the verdict** (`examples/verify-certificate-chain-server.json`) — the leaf, the intermediates the server sent as `candidates`, the roots the client trusts, the host and the purpose:

```json
{ "name": "verify_certificate_chain", "arguments": { "leaf": { "path": "fixtures/leaf.crt.pem" }, "candidates": [{ "path": "fixtures/inter.crt.pem" }], "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "at": "2027-01-01T00:00:00Z", "serverName": { "host": "a.wild.example.test" }, "purposes": ["serverAuth"], "verbosity": "summary" } }
```

```json
{"valid":true,"reasonCodes":[],"pathLength":3,"evaluatedAt":"2027-01-01T00:00:00.000Z","revocationEvidence":{"crls":0,"ocspResponses":0,"required":false},"diagnosticCount":0}
```

When the client rejects it, the same call answers why, and each reason code sends the agent to its next call. A negative verdict is `valid: false` in `structuredContent`, never `isError`:

| `reasonCodes` | What it means | Next call |
|---|---|---|
| `PKI_REASON_NO_TRUST_ANCHOR` | No path reaches the anchors: the server did not send its intermediate, or the client trusts another root. The same call without `candidates` answers `["PKI_REASON_SIGNATURE_NOT_CHECKED","PKI_REASON_NO_TRUST_ANCHOR"]` with `pathLength: 1` | `build_certificate_path`, to see how far the path gets (`examples/build-certificate-path-no-anchor.json`: `found: false`, `structuralReasons` `PKI_REASON_NO_TRUST_ANCHOR`) |
| `PKI_REASON_EXPIRED`, `PKI_REASON_NOT_YET_VALID` | A certificate of the path is outside its validity at `at` (`examples/verify-certificate-chain-expired.json`, with `at` 2050-01-01, answers one `PKI_REASON_EXPIRED` per certificate) | `inspect_certificate` on each, for `notBefore` and `notAfter` |
| `PKI_REASON_NAME_MISMATCH` | The chain is sound and the certificate is for another host | `check_certificate_name`, whose reason lists the names the certificate holds |
| `PKI_REASON_PURPOSE_NOT_PERMITTED` | The certificate, or a CA above it, does not allow `serverAuth` | `check_certificate_purpose` |
| `PKI_REASON_REVOCATION_UNKNOWN` | `requireRevocation` was asked and no evidence covers the leaf | Case 3 |

The name check (`examples/check-certificate-name-mismatch.json`):

```json
{ "name": "check_certificate_name", "arguments": { "certificate": { "path": "fixtures/leaf.crt.der" }, "host": "evil.test" } }
```

```json
{"form":"certificate","valid":false,"reasons":[{"code":"PKI_REASON_NAME_MISMATCH","message":"the certificate does not name the DNS name \"evil.test\": it names \"example.test\", \"*.wild.example.test\", 192.0.2.1. A chain that verifies still says nothing about which host the certificate is for","standard":"RFC 6125 §6","path":"certificate.subjectAltName"}],"reference":{"kind":"dns","value":"evil.test"},"subject":"CN=example.test,O=pkinative-cli test,C=FR","diagnostics":[],"diagnosticCounts":{}}
```

**Why pin `at`.** A verdict depends on the instant. A pinned `at` — or the operator's `PKINATIVE_MCP_AT` — makes it reproducible and cacheable; an omitted one is the wall clock, reported in `evaluatedAtSource`, and never cached. **Limits:** the server never fetches the intermediate a server forgot to send, nor the root: the agent asks the user for them, and the verdict is only ever relative to the anchors named in the call. A `signature.valid` from `inspect_certificate` is one signature against one key, not trust.

## Case 2 — Issuing a test certificate

A developer needs a CA and a TLS server certificate for an integration test, from keys they already have. The `issue_certificate` prompt chains three calls; the server generates no key and exports none, and each artefact is verified before its bytes are returned. The calls below are `examples/create-certificate-self-signed-ca.json`, `examples/create-csr-round-trip.json` and `examples/create-certificate-issue-leaf.json`, written into the sandbox with `outputMode: 'file'` and chained as the prompt describes — the leaf issued by the new CA — so no artefact travels back through the model's context.

**The CA**, self-signed because no `issuerCertificate` is given; serial and `notBefore` are pinned, so its bytes are reproducible:

```json
{ "name": "create_certificate", "arguments": { "spec": { "serialNumber": 1, "subject": { "C": "FR", "O": "Acme", "CN": "Acme Test CA" }, "notBefore": "2027-01-01T00:00:00Z", "validityDays": 3650, "extensions": { "basicConstraints": { "ca": true, "pathLen": 0 }, "keyUsage": ["keyCertSign", "cRLSign"] } }, "signer": { "key": { "path": "fixtures/ed25519.key.pem" } }, "outputMode": "file", "outputPath": "out/acme-ca.pem", "encoding": "pem" } }
```

The result carries a `resource_link` to `pkinative://output/out/acme-ca.pem` and, in `structuredContent`, the size, the SHA-256 of the DER and a summary:

```json
{"encoding":"pem","sizeBytes":350,"sha256":"694fa39766a751eaaf6be471061639f5b3bdce183549d0a15272fbca5e79e0b8","mode":"file","summary":{"serialNumber":"01","randomSerial":false,"subject":"CN=Acme Test CA,O=Acme,C=FR","issuer":"CN=Acme Test CA,O=Acme,C=FR","selfSigned":true,"signatureAlgorithm":{"oid":"1.3.101.112","name":"Ed25519","hasParameters":false},"notBefore":"2027-01-01T00:00:00.000Z","notAfter":"2036-12-29T00:00:00.000Z","notBeforeSource":"input","extensions":["basicConstraints","keyUsage","subjectKeyIdentifier"],"signatureVerified":true,"publicKeyFrom":"signer"},"diagnostics":[],"diagnosticCounts":{}}
```

**The request**, on the subject's side; the proof of possession is verified before the bytes return:

```json
{ "name": "create_csr", "arguments": { "spec": { "subject": { "C": "FR", "O": "Acme", "CN": "svc.example.test" }, "extensions": { "subjectAltName": { "dns": ["svc.example.test", "www.svc.example.test"] }, "keyUsage": ["digitalSignature"], "extendedKeyUsage": ["serverAuth"] } }, "signer": { "key": { "path": "fixtures/leaf.key.pem" } }, "outputMode": "file", "outputPath": "out/svc.csr.pem", "encoding": "pem" } }
```

**The leaf**, its public key taken from the request, signed by the CA's key; the `authorityKeyIdentifier` is added, and the certificate is verified against the issuer before it is written (`summary.signatureVerified: true`, `publicKeyFrom: "csr"`):

```json
{ "name": "create_certificate", "arguments": { "spec": { "serialNumber": "0x1a2b3c", "subject": { "C": "FR", "O": "Acme", "CN": "svc.example.test" }, "notBefore": "2027-01-01T00:00:00Z", "validityDays": 90, "extensions": { "subjectAltName": { "dns": ["svc.example.test", "www.svc.example.test"] }, "extendedKeyUsage": ["serverAuth"], "keyUsage": ["digitalSignature"] } }, "issuerCertificate": { "path": "out/acme-ca.pem" }, "subjectPublicKey": { "path": "out/svc.csr.pem" }, "signer": { "key": { "path": "fixtures/ed25519.key.pem" } }, "outputMode": "file", "outputPath": "out/svc.crt.pem", "encoding": "pem" } }
```

**Prove it**, as the prompt's last step asks — the leaf against the new CA, for its host and purpose:

```json
{ "name": "verify_certificate_chain", "arguments": { "leaf": { "path": "out/svc.crt.pem" }, "trustAnchors": [{ "path": "out/acme-ca.pem" }], "at": "2027-02-01T00:00:00Z", "serverName": { "host": "www.svc.example.test" }, "purposes": ["serverAuth"], "verbosity": "summary" } }
```

```json
{"valid":true,"reasonCodes":[],"pathLength":2,"evaluatedAt":"2027-02-01T00:00:00.000Z","revocationEvidence":{"crls":0,"ocspResponses":0,"required":false},"diagnosticCount":0}
```

**What is reproducible.** The CA and the leaf are signed with Ed25519 and have pinned serials and dates: run again, they hash the same. The request is signed with an ECDSA key, whose signatures are randomised, so its SHA-256 changes on every run — which is why `create_csr`, like `create_certificate` with its default `'random'` serial, is annotated as producing a non-idempotent artefact. **Refusals the agent meets:** an RSA signer without `rsaScheme` is `RSA_SCHEME_REQUIRED` (`data.remedy`: `rsaScheme:'pkcs1'|'pss'`); an encrypted key without a password is `SECRET_REQUIRED`, without a type `KEY_TYPE_REQUIRED`; a key that does not belong to the issuer is `KEY_MISMATCH`; an `outputPath` that already exists is `OUTPUT_EXISTS` — the server never overwrites. SHA-1 needs `allowSha1: true`.

## Case 3 — Offline revocation

An agent working on an air-gapped or egress-restricted host is asked whether a certificate has been revoked. The server has no network code path; the `offline_revocation` prompt tells the agent where the evidence comes from and which tool judges it.

**Where to fetch.** `inspect_certificate` lists the `crlDistributionPoints` and `authorityInfoAccess` extensions — the CRL and OCSP responder URLs. The user, or another tool with network access, fetches the CRL; for OCSP, the server builds the request to send (`examples/create-ocsp-request.json`):

```json
{ "name": "create_ocsp_request", "arguments": { "certificate": { "path": "fixtures/leaf.crt.pem" }, "issuer": { "path": "fixtures/inter.crt.pem" }, "hashAlgorithm": "SHA-256", "nonce": "random", "encoding": "hex" } }
```

The request's bytes land in `structuredContent.hex`, POSTed by the user as `application/ocsp-request`; the summary keeps what the answer must match:

```json
{"certIdHex":"3057300d0609608648016503040201050004206445323505d6fdd731e1330cfe6724f37cef7f6086d287b50353561b96e64e1904201c0b32ab5ee79c8e1de725b94e5ef34ce779d13fef4d97c290fe5931cc4c47c402021001","hashAlgorithm":"SHA-256","nonceHex":"1dc290a3e07935fff3bae7572d4101bb","randomNonce":true,"certIdOnly":false,"serialNumber":"1001","subject":"CN=example.test,O=pkinative-cli test,C=FR","issuer":"CN=Test Intermediate CA,O=pkinative-cli test,C=FR","sizeBytes":136}
```

**Judge the CRL** (`examples/check-crl-revocation.json`, second step) — scope, freshness, the signature against `issuer`, the serial:

```json
{ "name": "check_crl_revocation", "arguments": { "certificate": { "path": "fixtures/revoked.crt.pem" }, "crl": { "path": "fixtures/inter.crl.der" }, "issuer": { "path": "fixtures/inter.crt.pem" }, "at": "2027-01-01T00:00:00Z", "fields": ["valid", "reasons.code", "signatureVerified", "crlNumber"] } }
```

```json
{"valid":false,"reasons":[{"code":"PKI_REASON_REVOKED"}],"signatureVerified":true,"crlNumber":"1"}
```

**Judge the OCSP response** (`examples/check-ocsp-status.json`) — the CertID recomputed from `issuer`, the signature, the responder's authorisation, freshness, and the nonce the request carried:

```json
{ "name": "check_ocsp_status", "arguments": { "response": { "path": "fixtures/leaf.ocsp.der" }, "certificate": { "path": "fixtures/leaf.crt.pem" }, "issuer": { "path": "fixtures/inter.crt.pem" }, "nonce": "1538349c433373ed058c291909df5b3e", "requireNonce": true, "at": "2027-01-01T00:00:00Z", "verbosity": "summary" } }
```

```json
{"valid":true,"reasonCodes":[],"status":"good","signatureVerified":true,"responderAuthorized":true,"responder":"CN=Test OCSP Responder,O=pkinative-cli test,C=FR","evaluatedAt":"2027-01-01T00:00:00.000Z","diagnosticCount":0}
```

The responder here is a delegate the intermediate issued with the OCSPSigning purpose, embedded in the response; the server accepts the CA itself or such a delegate (RFC 6960 §4.2.2.2), and any other signer only with `responderTrusted: true`.

**Or in one call** (`examples/verify-certificate-chain-revoked.json`): the chain verdict with the evidence attached and `requireRevocation`, which demands evidence for the end-entity certificate:

```json
{ "name": "verify_certificate_chain", "arguments": { "leaf": { "path": "fixtures/revoked.crt.pem" }, "candidates": [{ "path": "fixtures/inter.crt.pem" }], "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "crls": [{ "path": "fixtures/inter.crl.pem" }], "ocspResponses": [{ "path": "fixtures/revoked.ocsp.der" }], "requireRevocation": true, "at": "2027-01-01T00:00:00Z", "fields": ["valid", "reasons.code", "revocationEvidence", "pathLength"] } }
```

```json
{"valid":false,"reasons":[{"code":"PKI_REASON_REVOKED"},{"code":"PKI_REASON_REVOKED"}],"revocationEvidence":{"crls":1,"ocspResponses":1,"required":true},"pathLength":3}
```

**Limits.** `PKI_REASON_REVOKED` is reported only from authenticated evidence; with none covering a certificate, the reason is `PKI_REASON_REVOCATION_UNKNOWN` — an absence of evidence, never "not revoked". `check_crl_revocation` without `issuer` does not accept the list as evidence, and a delta CRL whose signature does not verify is not applied.

## Case 4 — Opening keys safely

A user hands the agent a `.p12` and an encrypted key from an old export and asks what they hold. The `open_keys_safely` prompt says: describe before opening, open without exporting, and keep the password out of the transcript where possible.

**Describe without a password** (`examples/inspect-pkcs12-describe.json`, `examples/inspect-private-key-describe.json`). `PKINATIVE_MCP_PASSWORD` counts as the password of every password-accepting tool, so describing a file without one needs it unset:

```json
{ "name": "inspect_pkcs12", "arguments": { "pkcs12": { "path": "fixtures/leaf.p12" }, "verbosity": "summary" } }
```

```json
{"version":3,"macKind":"pbmac1","contentCount":2,"bagCount":1,"bagKinds":["pkcs8ShroudedKeyBag"],"diagnosticCount":0}
```

```json
{ "name": "inspect_private_key", "arguments": { "key": { "path": "fixtures/leaf.key.enc.pem" } } }
```

The key report names the scheme — `PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)`, 2048 PBKDF2 iterations, 144 encrypted bytes — and neither its kind nor its curve, which an encrypted PKCS#8 key reveals only once decrypted. A legacy file is recognised before anyone types a password (`examples/inspect-pkcs12-legacy.json`):

```json
{ "name": "inspect_pkcs12", "arguments": { "pkcs12": { "path": "fixtures/legacy.p12" }, "fields": ["mac.kind", "contents.path", "contents.encryption.scheme"] } }
```

```json
{"mac":{"kind":"pkcs12-kdf"},"contents":[{"path":"authSafe[0]","encryption":{"scheme":"pbeWithSHAAnd40BitRC2-CBC"}},{"path":"authSafe[1]"}]}
```

**Open** (`examples/inspect-private-key-import.json`, and `examples/open-pkcs12-file.json` inline): the key is decrypted straight into a non-extractable Web Crypto key, described and never exported:

```json
{ "name": "inspect_private_key", "arguments": { "key": { "path": "fixtures/leaf.key.enc.pem" }, "tryImport": true, "password": "test-only-password", "keyType": "ec-p256", "fields": ["imported", "encryption.scheme"] } }
```

```json
{"imported":{"ok":true,"encrypted":true,"algorithm":{"name":"ECDSA","hash":"SHA-256","namedCurve":"P-256"},"key":{"type":"private","algorithm":"ECDSA","extractable":false,"usages":["sign"]}},"encryption":{"scheme":"PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)"}}
```

```json
{ "name": "open_pkcs12", "arguments": { "pkcs12": { "path": "fixtures/leaf.p12" }, "password": "test-only-password", "exportCertificates": true, "verbosity": "summary" } }
```

```json
{"valid":true,"integrity":"verified","reasonCodes":[],"keyCount":1,"certificateCount":2,"crlCount":0,"diagnosticCount":0}
```

`exportCertificates: true` attaches a PEM bundle of the certificates and CRLs — never a key — as an embedded resource, or as a sandbox file with `outputMode: 'file'`.

**What goes wrong, and how it says so.** Opening is a verdict, so most failures are `valid: false` with a reason, not `isError`:

| Situation | Result |
|---|---|
| No password from either channel (`examples/open-pkcs12-no-password.json`) | `isError`, `SECRET_REQUIRED`, before anything is read |
| A wrong password on `open_pkcs12` | `valid: false`, `integrity: "mismatch"`, `PKI_REASON_PKCS12_MAC_MISMATCH` — nothing is decrypted |
| A wrong password on `inspect_pkcs12` or `inspect_private_key` | `isError`, `PKI_CRYPTO_DECRYPTION_FAILED` (`data.errorClass: "password"`) |
| The legacy file opened | `valid: false`, `integrity: "unverified"`, `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` and `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`; `explain_code` gives the OpenSSL 3.4 conversion |
| An RSA key without `rsaScheme` (`fixtures/rsa.p12`) | `valid: false`, `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`; with `rsaScheme: "pkcs1"` (`examples/open-pkcs12-rsa.json`) it opens |

**Passwords.** A `password` input lands in the host's transcript; `PKINATIVE_MCP_PASSWORD`, set in the server's environment by the operator, does not. Never both — that is `VALIDATION_ERROR`. A call carrying a password is never cached, and the value is never echoed, logged or served. **Limits:** key-bearing files (`.key .p8 .p12 .pfx`) in the sandbox are read by the key and signer tools only, never listed or served as resources, and nothing in the server writes one: a converted PKCS#12 comes from OpenSSL.

## See also

- [MCP guide](mcp.md) — every tool, prompt, variable and error code.
- [CLI use cases](use-cases-cli.md) — the same workflows from a shell or a CI job.
- [Use cases](use-cases.md) — the library in applications.
- [Errors, diagnostics and reasons](errors.md) — every `PKI_*` code these cases return.
- The server's [examples](https://github.com/Nizoka/pkinative-mcp/tree/main/examples), its [AI agent guide](https://github.com/Nizoka/pkinative-mcp/blob/main/docs/AI_GUIDE.md) and its [agent contract](https://github.com/Nizoka/pkinative-mcp/blob/main/docs/AGENT_CONTRACT.md).
