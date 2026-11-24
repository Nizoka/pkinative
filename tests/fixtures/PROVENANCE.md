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
| `ml-dsa/rfc9881-ml-dsa-44.der` | The self-signed ML-DSA-44 example certificate of RFC 9881 Appendix C.3, converted from its PEM text | https://www.rfc-editor.org/rfc/rfc9881.txt | 2026-11-17 | `9762ddd44288af89bde9213f63212e273815ebbe37f2ce918c496365b1382165` | IETF Trust Legal Provisions; code components under the Revised BSD License |
| `ml-dsa/rfc9881-ml-dsa-65.der` | The self-signed ML-DSA-65 example certificate of RFC 9881 Appendix C.3, converted from its PEM text | https://www.rfc-editor.org/rfc/rfc9881.txt | 2026-11-17 | `7bf5da6c6ee25c59abb6b3561c27092872fec9052bcb98a5aa94dfa806057bd2` | IETF Trust Legal Provisions; code components under the Revised BSD License |
| `ml-dsa/rfc9881-ml-dsa-87.der` | The self-signed ML-DSA-87 example certificate of RFC 9881 Appendix C.3, converted from its PEM text | https://www.rfc-editor.org/rfc/rfc9881.txt | 2026-11-17 | `ee6db12f8b68b814a9ff912f6badb8299ea9baebf121fceffa60cf23d3b97e34` | IETF Trust Legal Provisions; code components under the Revised BSD License |
| `ml-dsa/root-ml-dsa-65.der` | Self-signed CA certificate, ML-DSA-65 key and signature | OpenSSL 3.5.5, commands below | 2026-11-17 | `65538f67c6ddd72553812ec6ee25da230131fb1d1bf0ecea16db114a4b706346` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/leaf-ml-dsa-44.der` | End-entity certificate, ML-DSA-44 key, signed by the root with ML-DSA-65 | OpenSSL 3.5.5, commands below | 2026-11-17 | `8d791490922f57e6578b7922f97183661b9d60e439215e64560a6b3a4ae1a293` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/csr-ml-dsa-44.der` | PKCS#10 certification request of the leaf, self-signed with ML-DSA-44 | OpenSSL 3.5.5, commands below | 2026-11-17 | `ce8cf9dbd2d4695ca283045db3ddae6710a728f32b9623a5dcabd038bc3bb690` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/crl-ml-dsa-65.der` | Empty CRL of the root, signed with ML-DSA-65 | OpenSSL 3.5.5, commands below | 2026-11-17 | `991c3c3dc4d81d66761b1ea38a81cf5c2309b66af2ea3037f18ed7c33691c466` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/ocsp-ml-dsa-65.der` | OCSP response for the leaf, status good, signed by the root with ML-DSA-65 | OpenSSL 3.5.5, commands below | 2026-11-17 | `cae1b7d3b39151c90b1cac3c6e542bce58171ac30541d3c8278fbea8717f1d70` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/cms-ml-dsa-44-sha512.der` | CMS SignedData by the leaf: ML-DSA-44 over signed attributes, SHA-512 digest, content and certificate attached | OpenSSL 3.5.5, commands below | 2026-11-17 | `d6a7c770ee4f73c3e52a72207d3ee6cb56d86e8191490cefcd9f7efb1782689a` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/cms-ml-dsa-44-shake256.der` | CMS SignedData by the leaf: ML-DSA-44 over signed attributes, SHAKE256 (512-bit) digest, content attached, no certificate | OpenSSL 3.5.5, commands below | 2026-11-17 | `bf5e649af7f585373f59f6397312e945ac9f365abb56a7f2bf938f7e4ab30e84` | Made for this repository with OpenSSL; MIT, as the repository |
| `ml-dsa/tst-ml-dsa-44.der` | RFC 3161 timestamp token: a CMS SignedData over a TSTInfo, signed with ML-DSA-44 by a timestamping certificate the root issued | OpenSSL 3.5.5, commands below | 2026-11-17 | `dd0f665fa5a35c0c09506ef98b17d3ff5da8242bccb5d5155918ffb9cc7460e8` | Made for this repository with OpenSSL; MIT, as the repository |

The RFC 8410 example encodes three DEFAULT values explicitly (cA FALSE, and critical FALSE on two extensions), which DER omits: pkinative reads it with three `PKI_DIAG_DEFAULT_ENCODED` diagnostics, as Go, OpenSSL and BoringSSL read it.

## The ML-DSA files (`ml-dsa/`)

pkinative signs nothing with ML-DSA ([ADR 0026](../../docs/adr/0026-ml-dsa-verified-where-the-host-verifies-it.md)), so every ML-DSA signature the suites verify was made elsewhere: three by the authors of RFC 9881, the rest by OpenSSL 3.5.5 (`OpenSSL 3.5.5 27 Jan 2026`) with the commands below, run once on 2026-11-17. The private keys were generated for these files, never committed and not kept: the files cannot be regenerated, only replaced by new ones with new rows. Each file was checked by OpenSSL itself before it was committed (`openssl verify`, `openssl crl -CAfile`, `openssl ocsp -respin`, `openssl cms -verify`).

```sh
# RFC 9881 Appendix C.3 — the three PEM blocks of the RFC text, in order (ML-DSA-44, -65, -87)
openssl x509 -in rfc9881-c3-N.pem -outform DER -out rfc9881-ml-dsa-NN.der

# The root and the leaf
openssl genpkey -algorithm ML-DSA-65 -out root.key
openssl genpkey -algorithm ML-DSA-44 -out leaf.key
openssl req -new -x509 -key root.key -subj "/CN=pkinative ML-DSA-65 test root" \
    -not_before 20260101000000Z -not_after 20460101000000Z \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -outform DER -out root-ml-dsa-65.der
openssl req -new -key leaf.key -subj "/CN=pkinative ML-DSA-44 test signer" \
    -addext "keyUsage=critical,digitalSignature" -outform DER -out csr-ml-dsa-44.der
# leaf.ext: basicConstraints=critical,CA:FALSE / keyUsage=critical,digitalSignature,nonRepudiation
#           subjectKeyIdentifier=hash / authorityKeyIdentifier=keyid
openssl x509 -req -inform DER -in csr-ml-dsa-44.der -CA root-ml-dsa-65.der -CAkey root.key \
    -set_serial 0x4D4C445341 -not_before 20260101000000Z -not_after 20460101000000Z \
    -extfile leaf.ext -outform DER -out leaf-ml-dsa-44.der

# The CRL (ca.cnf: database, crlnumber, default_md = default, authorityKeyIdentifier = keyid) and the OCSP response
openssl ca -config ca.cnf -gencrl -cert root.pem -keyfile root.key -crlexts crl_ext \
    -crl_lastupdate 20260601000000Z -crl_nextupdate 20360601000000Z -out crl.pem
openssl crl -in crl.pem -outform DER -out crl-ml-dsa-65.der
openssl ocsp -sha256 -issuer root.pem -cert leaf.pem -no_nonce -reqout ocsp-req.der
openssl ocsp -index index.txt -CA root.pem -rsigner root.pem -rkey root.key -reqin ocsp-req.der \
    -ndays 3650 -resp_no_certs -respout ocsp-ml-dsa-65.der

# The CMS messages: content.txt holds "pkinative ML-DSA CMS fixture" and a line feed.
# OpenSSL has no default digest for an ML-DSA signer: -md is required.
openssl cms -sign -binary -nodetach -md sha512 -in content.txt -signer leaf.pem -inkey leaf.key \
    -outform DER -out cms-ml-dsa-44-sha512.der
openssl cms -sign -binary -nodetach -nocerts -md shake256 -in content.txt -signer leaf.pem -inkey leaf.key \
    -outform DER -out cms-ml-dsa-44-shake256.der

# The timestamp token. `openssl ts` signs through PKCS#7, which refuses an ML-DSA key, so the token is
# what RFC 3161 §2.4.2 says it is: a CMS SignedData whose content is a TSTInfo. tsa.pem is a second
# ML-DSA-44 certificate under the root (extendedKeyUsage=critical,timeStamping); tstinfo.der is version 1,
# policy 1.3.6.1.4.1.99999.1, the SHA-512 imprint of content.txt, serial 1, genTime 20261117220000Z,
# written with `openssl asn1parse -genconf`.
openssl cms -sign -binary -nodetach -cades -nosmimecap -md sha512 -econtent_type 1.2.840.113549.1.9.16.1.4 \
    -in tstinfo.der -signer tsa.pem -inkey tsa.key -outform DER -out tst-ml-dsa-44.der
```
