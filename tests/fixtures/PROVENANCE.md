# Fixture provenance

Every committed binary in `tests/fixtures/` has foreign provenance: it was produced by someone other than pkinative, so a parser bug cannot be baked into both the fixture and its reading. Hostile inputs are never committed — the tests build them with `tests/helpers/raw-der-builder.ts`. Never regenerate these files: re-downloading a newer certificate is a new fixture with a new row.

`tests/docs/fixture-budget.test.ts` checks that every file below exists with exactly this SHA-256, that no unlisted file is committed, and that the tree stays under its byte budget.

| File | What it is | Source | Retrieved | SHA-256 | Terms |
|---|---|---|---|---|---|
| `certs/isrg-root-x1.der` | ISRG Root X1, RSA 4096, self-signed | https://letsencrypt.org/certs/isrgrootx1.der | 2026-09-19 | `96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6` | Public CA certificate published by ISRG for distribution |
| `certs/isrg-root-x2.der` | ISRG Root X2, ECDSA P-384, self-signed | https://letsencrypt.org/certs/isrg-root-x2.der | 2026-09-19 | `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470` | Public CA certificate published by ISRG for distribution |
| `certs/lets-encrypt-e7.der` | Let's Encrypt E7, ECDSA P-384 intermediate under ISRG Root X2 | https://letsencrypt.org/certs/2024/e7.der | 2026-09-19 | `54715420224c5b65beed018dc3940d7338c577e322d5488f633d8c6a8fed61b2` | Public CA certificate published by ISRG for distribution |
| `certs/lets-encrypt-r12.der` | Let's Encrypt R12, RSA 2048 intermediate under ISRG Root X1 | https://letsencrypt.org/certs/2024/r12.der | 2026-09-19 | `131fce7784016899a5a00203a9efc80f18ebbd75580717edc1553580930836ec` | Public CA certificate published by ISRG for distribution |
| `certs/letsencrypt-org-leaf.der` | End-entity certificate of letsencrypt.org, ECDSA P-256, with SCTs, AIA, CRL distribution point and ten DNS names | TLS handshake with letsencrypt.org:443 (`openssl s_client -showcerts`) | 2026-09-19 | `1fc4f697eefa3022d872df232293bdda7624c93964d778a53026912d9d529a53` | Public certificate, logged in Certificate Transparency |
| `certs/rfc8410-x25519.der` | The X25519 certificate signed with Ed25519 of RFC 8410 §10.2, converted from its PEM text | https://www.rfc-editor.org/rfc/rfc8410.txt | 2026-09-19 | `180516f0a03e4893d234a28f3ad28921bc35d1b12bd35134847240dafb715a11` | IETF Trust Legal Provisions; code components under the Revised BSD License |

The RFC 8410 example encodes three DEFAULT values explicitly (cA FALSE, and critical FALSE on two extensions), which DER omits: pkinative reads it with three `PKI_DIAG_DEFAULT_ENCODED` diagnostics, as Go, OpenSSL and BoringSSL read it.
