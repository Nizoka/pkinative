# CLI use cases

> **Four pipelines built from the pkinative-cli samples: a CI gate on a chain and its expiry, revocation checked offline, a signed and timestamped release, and a PKCS#12 audit.** Every command below is one a sample runs, or a flag the CLI guide documents.

pkinative-cli 1.0.0 ships 57 samples in its repository's `samples/` directory, at least one for every invocation but `doctor`, each as a `.sh` and a `.ps1` script that its CI runs and pins. A sample runs from the repository root against the test PKI in `tests/fixtures/pki` (`F` below), the inputs in `samples/inputs` (`S`) and an output directory (`O`), and calls `${PKINATIVE:-node dist/cli.cjs}` — with the CLI installed, `PKINATIVE=pkinative`. The cases below quote those command lines, then show the output the 1.0.0 binary prints for them; every flag is documented in the [CLI guide](cli.md).

```bash
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
```

## Case 1 — A CI gate on a certificate chain and its expiry

A deployment should not ship a certificate that does not chain to the roots it is meant to chain to, that names another host, or that expires before the next release. `chain verify` answers all three in one call, and its process contract — the verdict on stdout, one envelope on stderr, exit 0, 1 or 2 — is what a CI step branches on.

![Architecture: a CI job carries the leaf certificate, its intermediate and the trust anchors, and pins an instant 30 days ahead with --at. pkinative chain verify checks the path, signatures, host name, purpose and revocation at that instant, then writes the verdict on stdout and one JSON envelope on stderr. The step branches on the exit code: 0 ships, 1 is E_VERIFY_FAILED with reason codes such as PKI_REASON_EXPIRED or PKI_REASON_NAME_MISMATCH, 2 is E_USAGE and fails the build without a retry. Limits: the CLI never fetches an intermediate or a CRL, and chain build is a diagnostic, never a gate.](../assets/use-case-cli-ci-gate.svg)

The building blocks, from `samples/chain/`:

```bash
# samples/chain/chain-verify.sh — one-call verdict with revocation (expected exit 0)
pkinative chain verify "$F"/leaf.crt.pem --untrusted "$F"/inter.crt.pem --trust "$F"/root.crt.pem --host example.test --crl "$F"/inter.crl.pem --ocsp "$F"/leaf.ocsp.der --require-revocation --at 2027-01-01T00:00:00Z

# samples/chain/chain-verify-revoked.sh — a revoked leaf fails the verdict (expected exit 1)
pkinative chain verify "$F"/revoked.crt.pem --untrusted "$F"/inter.crt.pem --trust "$F"/root.crt.pem --crl "$F"/inter.crl.pem --at 2027-01-01T00:00:00Z -q

# samples/chain/chain-build.sh — find a path to a trust anchor, signatures not checked (expected exit 0)
pkinative chain build "$F"/leaf.crt.pem --untrusted "$F"/inter.crt.pem --trust "$F"/root.crt.pem --at 2027-01-01T00:00:00Z --json --summary
```

Add `--json --summary` and the first sample's verdict is two lines, stdout then stderr:

```json
{"valid":true,"reasons":[],"path":["CN=example.test,O=pkinative-cli test,C=FR","CN=Test Intermediate CA,O=pkinative-cli test,C=FR","CN=Test Root CA,O=pkinative-cli test,C=FR"],"explored":2,"signatureVerifications":2}
{"ok":true,"command":"chain verify","valid":true,"pathLength":3,"signaturesChecked":true,"diagnostics":[]}
```

**Expiry is a question of `--at`.** The verdict is computed at the instant `--at` names — ISO 8601, epoch milliseconds or `now` — so an expiry gate is the same command asked about the future. Moving the first sample's `--at` past the leaf's `notAfter` (2046-01-01) gives exit 1, `E_VERIFY_FAILED`, one `PKI_REASON_EXPIRED` per certificate of the path, and two `PKI_REASON_REVOCATION_UNKNOWN` on the OCSP response, whose delegated responder certificate has expired too:

```json
{"valid":false,"reasons":["PKI_REASON_EXPIRED","PKI_REASON_EXPIRED","PKI_REASON_EXPIRED","PKI_REASON_REVOCATION_UNKNOWN","PKI_REASON_REVOCATION_UNKNOWN"],"path":["CN=example.test,O=pkinative-cli test,C=FR","CN=Test Intermediate CA,O=pkinative-cli test,C=FR","CN=Test Root CA,O=pkinative-cli test,C=FR"],"explored":3,"signatureVerifications":2}
```

A CI step built on those pieces — verify the chain as it will stand 30 days from now, and fail with the reason codes when it does not (GNU `date` and `jq` assumed on the runner):

```bash
AT="$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)"
pkinative chain verify server.pem --untrusted intermediate.pem --trust root.pem \
  --host www.example.com --purpose serverAuth --at "$AT" \
  --json --summary > verdict.json 2> envelope.json
case $? in
  0) echo "chain valid on $AT" ;;
  1) echo "chain refused: $(jq -r '.reasons | join(", ")' verdict.json)"; jq -c .error envelope.json; exit 1 ;;
  2) echo "invocation error: $(jq -r .error.message envelope.json)"; exit 2 ;;
esac
```

A name mismatch is caught by the same call: on the sample chain, `--host other.test` exits 1 with `PKI_REASON_NAME_MISMATCH`, whose message lists the names the certificate does hold. Exit 2 is never a verdict — an unknown flag, a missing `--trust`, both `--host` and `--ip` — and a gate should fail the build on it rather than retry.

**Limits.** `chain verify` judges the files it is given: it never fetches an intermediate or a CRL, so a CI job must carry them (Case 2). `chain build` exits 0 whenever a path is found, because it checks no signature — its `valid` is always false with `PKI_REASON_SIGNATURE_NOT_CHECKED` and its envelope says `signaturesChecked: false` — so it is a diagnostic, never a gate.

## Case 2 — Offline and air-gapped revocation checking

Revocation is where a verifier is most tempted to reach the network, and where an air-gapped signing host cannot. The CLI never fetches anything: it writes the OCSP request you send, and judges the CRL and the OCSP response you carry back.

![Architecture: on the connected side, pkinative ocsp request writes an OCSP request with a random nonce, and your own HTTP client posts it and fetches the CRL from URLs the certificate names. The response, the CRL and the nonce cross the air gap. There, crl check, ocsp check with --require-nonce and chain verify with --require-revocation judge that evidence at a pinned --at instant: a good certificate exits 0, a revoked one exits 1 with PKI_REASON_REVOKED and its date. Limits: the CLI never fetches, an unknown status passes unless revocation is required, and a CRL past nextUpdate fails chain verify, which takes no tolerance, and passes crl check only within --stale-tolerance.](../assets/use-case-cli-offline-revocation.svg)

The building blocks, from `samples/ocsp/` and `samples/crl/`:

```bash
# samples/ocsp/ocsp-request.sh — build an OCSP request (expected exit 0)
pkinative ocsp request --cert "$F"/leaf.crt.pem --issuer "$F"/inter.crt.pem -o "$O"/ocsp-req.der

# samples/crl/crl-verify-signature.sh — verify a CRL signature (expected exit 0)
pkinative crl verify-signature "$F"/inter.crl.der --issuer "$F"/inter.crt.pem

# samples/crl/crl-find.sh — look a serial up in a CRL (expected exit 0)
pkinative crl find "$F"/inter.crl.der --serial 1002

# samples/crl/crl-check.sh — decide a status from a CRL (expected exit 0)
pkinative crl check "$F"/inter.crl.der --cert "$F"/leaf.crt.pem --issuer "$F"/inter.crt.pem --at 2027-01-01T00:00:00Z

# samples/ocsp/ocsp-verify-signature.sh — verify the responder signature (expected exit 0)
pkinative ocsp verify-signature "$F"/leaf.ocsp.der

# samples/ocsp/ocsp-check.sh — decide a status from an OCSP response (expected exit 1: revoked)
pkinative ocsp check "$F"/revoked.ocsp.der --cert "$F"/revoked.crt.pem --issuer "$F"/inter.crt.pem --at 2027-01-01T00:00:00Z -q
```

The workflow splits across the gap:

```bash
# Connected side: write the request with a random RFC 8954 nonce, send it, fetch the CRL.
pkinative ocsp request --cert leaf.pem --issuer ca.pem --nonce random -o req.der --json
#   stderr: {"ok":true,"command":"ocsp request","nonce":"<32 hex digits>","bytes":106,"encoding":"der","output":"req.der","diagnostics":[]}
curl --data-binary @req.der -H 'Content-Type: application/ocsp-request' -o resp.der "$OCSP_URL"
curl -o ca.crl "$CRL_URL"

# Air-gapped side: judge the evidence you carried, at a pinned instant.
pkinative crl check ca.crl --cert leaf.pem --issuer ca.pem --at "$AT" --json --summary
pkinative ocsp check resp.der --cert leaf.pem --issuer ca.pem --nonce "$NONCE" --require-nonce --at "$AT" --json --summary
pkinative chain verify leaf.pem --untrusted ca.pem --trust root.pem --crl ca.crl --ocsp resp.der \
  --ocsp-nonce "$NONCE" --require-ocsp-nonce --require-revocation --at "$AT" --json --summary
```

The URLs come from the certificate itself: `cert inspect --extension crlDistributionPoints` and `--extension authorityInfoAccess`. `ocsp check` recomputes the CertID with the responder's hash, finds the signer among `--responder`, the embedded certificates and the issuer, and accepts it only if it is the CA or a delegate the CA issued with the OCSPSigning purpose (RFC 6960 §4.2.2.2) — unless you say `--responder-trusted`. `crl check` without `--issuer` counts the list's signature as unchecked, and the verdict fails.

On the samples' revoked leaf, both checks are negative verdicts — exit 1, `E_CHECK_FAILED`, the reason with the revocation date:

```json
{"valid":false,"reasons":[{"code":"PKI_REASON_REVOKED","message":"the certificate was revoked on 2026-06-01T00:00:00.000Z (reason: keyCompromise); a signature made before that instant may still be good, which is why the date is here","standard":"RFC 5280 §5.1","path":"ocsp"}],"status":"revoked","signatureVerified":true,"responderAuthorized":true}
```

and on the good leaf, `ocsp check` answers `{"valid":true,"reasons":[],"status":"good","signatureVerified":true,"responderAuthorized":true}` with exit 0.

**Limits.** `--require-revocation` turns an unknown status into a failure; without it, a chain whose revocation evidence is missing can still verify, which is a soft-fail decision you make explicitly. A CRL past its `nextUpdate` is stale: `crl check` accepts one only within `--stale-tolerance <ms>`, and `chain verify`, which takes no tolerance, reports `PKI_REASON_REVOCATION_STALE`; an OCSP `thisUpdate` in the future is refused by `ocsp check` beyond `--future-tolerance` (60000 ms by default) — on an air-gapped host, pin `--at` rather than trust its clock.

## Case 3 — CMS signature and RFC 3161 timestamp in a release pipeline

A release artefact signed with a detached CMS signature can be verified long after the signing certificate expires — if a timestamp proves the signature existed while the certificate was valid.

![Architecture: cms sign signs release.tgz detached with the signer certificate, its chain and a key whose password comes from a file, and checks the new signature before writing release.p7s. cms inspect extracts the signature value, tsp request hashes it into stamp.tsq, and your own call to the TSA returns stamp.tsr. cms add-timestamp attaches the token only if it stamps that signature value, else exit 1, E_INPUT, PKI_REASON_TSP_IMPRINT_MISMATCH. cms verify --at-timestamp then judges the signer at the stamped instant. Limits: the CLI never posts to a TSA, and tsp verify needs what was stamped.](../assets/use-case-cli-release-signing.svg)

The building blocks, from `samples/cms/` and `samples/tsp/` (`cms-sign.sh` signs with the CA that `samples/cert/cert-create-ca.sh` writes into `$O`):

```bash
# samples/cert/cert-create-ca.sh — issue a self-signed Ed25519 CA (expected exit 0)
pkinative cert create --spec "$S"/ca.json --key "$F"/ed25519.key.pem -o "$O"/ca.pem

# samples/cms/cms-sign.sh — sign detached; Ed25519 is deterministic (expected exit 0)
pkinative cms sign --content "$F"/content.txt --cert "$O"/ca.pem --key "$F"/ed25519.key.pem --detached --signing-time 2027-01-01T00:00:00Z -o "$O"/content.p7s

# samples/cms/cms-verify.sh — verify an attached signature (expected exit 0)
pkinative cms verify "$F"/attached.p7s --trust "$F"/root.crt.pem --at 2027-01-01T00:00:00Z --json --summary

# samples/tsp/tsp-request.sh — build a timestamp request (expected exit 0)
pkinative tsp request --data "$F"/content.txt --nonce 42 -o "$O"/req.tsq

# samples/tsp/tsp-verify.sh — verify a timestamp against its request and data (expected exit 0)
pkinative tsp verify --response "$F"/content.tsr --request "$F"/content.tsq --data "$F"/content.txt --trust "$F"/root.crt.pem --at 2027-01-01T00:00:00Z -q

# samples/cms/cms-add-timestamp.sh — refuse a token that stamps the content, not the signature value (expected exit 1)
pkinative cms add-timestamp "$F"/attached.p7s --token "$F"/content.tsr -o "$O"/stamped.p7s
```

`cms sign` verifies the new signature under `--cert` before it writes a byte, and its envelope reports what it wrote: `{"ok":true,"command":"cms sign","detached":true,"bytes":980,"encoding":"der","output":"…/content.p7s","diagnostics":[]}`. The last sample is the one that matters for a pipeline: a counter timestamp stamps the **signer's signature value**, and a token over anything else — here, over the content — is refused before anything is written, with the recipe as `remedy`:

```json
{"ok":false,"command":"cms add-timestamp","error":{"code":"E_INPUT","message":"The token does not stamp signer 0's signature value: its imprint is over something else (PKI_REASON_TSP_IMPRINT_MISMATCH).","remedy":"request the token over the signature value: cms inspect --fields signerInfos.signature, hash it, tsp request --digest <hex> --hash <alg>","reasons":[{"code":"PKI_REASON_TSP_IMPRINT_MISMATCH","message":"the token stamps a different hash from the one expected; it may be a perfectly good timestamp, of something else","standard":"RFC 3161 §2.4.2","path":"token.tstInfo.messageImprint"}]},"diagnostics":[{"code":"PKI_DIAG_CMS_SET_NOT_SORTED","severity":"warning","message":"this SET OF is not in DER order; nothing signed depends on it, but a strict DER reader will refuse the message","standard":"ITU-T X.690 §11.6","path":"content.certificates","offset":235}]}
```

The pipeline that follows that remedy (`jq` and `xxd` assumed on the runner; the TSA call is yours):

```bash
# 1. Sign the release artefact, detached.
pkinative cms sign --content release.tgz --cert signer.pem --chain intermediate.pem \
  --key signer.key --password-file signer.pass --detached -o release.p7s

# 2. Timestamp the signature value, not the artefact.
pkinative cms inspect release.p7s --json --fields signerInfos.signature \
  | jq -r '.signerInfos[0].signature' | xxd -r -p > signature.bin
pkinative tsp request --data signature.bin --nonce random -o stamp.tsq
curl --data-binary @stamp.tsq -H 'Content-Type: application/timestamp-query' -o stamp.tsr https://tsa.example.test/

# 3. Attach the token — refused unless it stamps that signature value — and verify at the stamped time.
pkinative cms add-timestamp release.p7s --token stamp.tsr -o release-stamped.p7s
pkinative cms verify release-stamped.p7s --content release.tgz --trust root.pem --at-timestamp --json --summary
```

`cms inspect --fields signerInfos.signature` prints the signature value as hex — `{"signerInfos":[{"signature":"3046022100f22e…"}]}` on the samples' attached message — and `tsp request --data` hashes the bytes you give it (`--hash`, SHA-256 by default). `cms verify --at-timestamp` validates the signer at its verified timestamp instead of the wall clock. An ECDSA or RSA-PSS signature differs on each run; the signing sample uses Ed25519, which is deterministic, so its output can be pinned.

**Limits.** The CLI never posts to a TSA. `tsp verify` needs to be told what was stamped — `--request`, `--data` or `--digest` — and refuses (exit 2) when it is not, because a token verified without what it stamps proves nothing. A TSA certificate whose timeStamping EKU is not critical is accepted only under `--allow-noncritical-eku`.

## Case 4 — A PKCS#12 audit with `--password-file`

A `.p12` arriving from a partner or an old export should be described before anyone types its password, and opened without its key ever reaching a terminal or a log.

![Architecture: p12 inspect describes a partner's PKCS#12 file without a password. p12 verify-mac, p12 bags and p12 open then read the password from the first line of a protected file through --password-file; p12 open imports the keys non-extractable and exports the certificates with --certs-out. A password on argv is E_USAGE, exit 2; a wrong one E_PASSWORD, exit 1; a legacy RC2 or 3DES file E_SECURITY, exit 1, with PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED and PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED. Limits: no report holds a key byte; the CLI writes no PKCS#12 or PKCS#8.](../assets/use-case-cli-pkcs12-audit.svg)

The building blocks, from `samples/p12/` and `samples/key/`:

```bash
# samples/p12/p12-inspect.sh — describe a PKCS#12 file, no password (expected exit 0)
pkinative p12 inspect "$F"/leaf.p12

# samples/p12/p12-verify-mac.sh — verify the PBMAC1 integrity (expected exit 0)
PKINATIVE_PASSWORD=test-only-password pkinative p12 verify-mac "$F"/leaf.p12

# samples/p12/p12-bags.sh — list the bags, decrypted (expected exit 0)
PKINATIVE_PASSWORD=test-only-password pkinative p12 bags "$F"/leaf.p12

# samples/p12/p12-open.sh — open it and export its certificates (expected exit 0)
PKINATIVE_PASSWORD=test-only-password pkinative p12 open "$F"/leaf.p12 --certs-out "$O"/bundle.pem -q

# samples/key/key-inspect.sh — describe an encrypted key, no password needed (expected exit 0)
pkinative key inspect "$F"/leaf.key.enc.pem --json

# samples/key/key-check.sh — prove an encrypted key decrypts (expected exit 0)
PKINATIVE_PASSWORD=test-only-password pkinative key check "$F"/leaf.key.enc.pem --key-type ec-p256 --json
```

The samples pass the password through `PKINATIVE_PASSWORD`. An audit script on a shared host should prefer `--password-file`, which reads the first line of a file you protect, and never the command line — `--password` is refused before any command runs:

```bash
umask 077 && printf '%s\n' "$P12_PASSWORD" > p12.pass

pkinative p12 inspect partner.p12 --json --fields mac.kind,mac.iterations,contents.path,contents.encryption.scheme
pkinative p12 verify-mac partner.p12 --password-file p12.pass --json --summary
pkinative p12 bags partner.p12 --password-file p12.pass --json
pkinative p12 open partner.p12 --password-file p12.pass --certs-out partner-chain.pem --json --summary
```

On the samples' `leaf.p12`, `p12 inspect`, `p12 verify-mac` and `p12 open` say what protects the file, whether the password is right, and what it holds — its key imported as a non-extractable Web Crypto key, without a key byte anywhere:

```json
{"mac":{"kind":"pbmac1","iterations":2048},"contents":[{"path":"authSafe[0]","encryption":{"scheme":"PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)"}},{"path":"authSafe[1]"}]}
{"valid":true}
{"valid":true,"integrity":"verified","keys":[{"path":"authSafe[1].bags[0]","friendlyName":"test leaf","certificate":"CN=example.test,O=pkinative-cli test,C=FR","signingKey":{"algorithm":{"name":"ECDSA","namedCurve":"P-256","hash":"SHA-256"},"key":{"type":"private","algorithm":"ECDSA","extractable":false,"usages":["sign"]}}}],"certificates":[{"subject":"CN=example.test,O=pkinative-cli test,C=FR","serialNumber":"1001"},{"subject":"CN=Test Intermediate CA,O=pkinative-cli test,C=FR","serialNumber":"02"}],"crls":0,"reasons":[]}
```

The failures an audit meets are classes, each with its remedy (exit codes in brackets):

```json
{"ok":false,"command":"p12 verify-mac","error":{"code":"E_PASSWORD","message":"The PKCS#12 MAC does not match: the password is wrong, or the file was altered.","remedy":"--password-file <file> | --password-stdin | PKINATIVE_PASSWORD (check the password)"},"diagnostics":[]}
{"ok":false,"command":"p12 open","error":{"code":"E_USAGE","message":"--password is refused: a password on the command line is visible to every process on the machine.","remedy":"--password-file <file> | --password-stdin | PKINATIVE_PASSWORD"},"diagnostics":[]}
```

A wrong password is `E_PASSWORD` [1]; a password on argv is `E_USAGE` [2]. A legacy file — RC2 or 3DES, the RFC 7292 Appendix B MAC — is described by `p12 inspect` (`mac.kind` is `pkcs12-kdf`, the scheme is named) and refused by `p12 open` with `E_SECURITY` [1], the reasons `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` and `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`, and the one-time OpenSSL 3.4 conversion as `remedy`. A file whose MAC cannot be checked opens only under `--allow-unverified-integrity`, for a file whose origin you trust; an RSA key opens only with `--rsa-scheme pkcs1|pss`.

**Limits.** No `key` or `p12` report contains a key byte: they are allow-list views, and keys are imported non-extractable. The CLI writes no PKCS#12 or PKCS#8 — a converted file comes from OpenSSL — and `--certs-out` writes the certificates and CRLs only, and only from a file that opened.

## See also

- [CLI guide](cli.md) — every command, flag, exit code and error class.
- [MCP use cases](use-cases-mcp.md) — the same workflows driven by an AI assistant.
- [Use cases](use-cases.md) — the library in applications.
- [Errors, diagnostics and reasons](errors.md) — every `PKI_*` code these cases print.
- The CLI's [samples](https://github.com/Nizoka/pkinative-cli/tree/main/samples) and [agent contract](https://github.com/Nizoka/pkinative-cli/blob/main/docs/AGENT_CONTRACT.md).
