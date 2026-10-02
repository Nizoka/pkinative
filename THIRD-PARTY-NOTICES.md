# Third-Party Notices

pkinative itself is licensed under the [MIT License](LICENSE) and has **zero runtime dependencies**: the published package contains only code written for this project.

This file lists third-party material the repository uses for testing and conformance, where it comes from, and its licence. None of it is included in the npm package.

## Conformance corpora (downloaded, never committed)

`npm run conformance:fetch` downloads these files into `test-output/corpora/` (git-ignored) at the pinned commit and refuses any file whose SHA-256 differs from `.github/checksums/<corpus>-<commit>.sha256`. The pins live in `scripts/lib/corpora.ts`; the `corpus-pin-parity` rule of `npm run verify:docs` holds this section to them.

| Corpus | Source | Pinned commit | Files | Licence |
|---|---|---|---|---|
| x509-limbo | https://github.com/C2SP/x509-limbo | `118721335e675edde10015df89b138cf292d7554` | `limbo.json` (schema version 1) | Apache-2.0 |
| Project Wycheproof | https://github.com/C2SP/wycheproof | `3fa63dd0344abb611f1fb1d77e119938603ea230` | `testvectors_v1/ecdsa_secp256r1_sha256_test.json`, `ecdsa_secp384r1_sha384_test.json`, `ecdsa_secp521r1_sha512_test.json` | Apache-2.0 |
| NIST Public Key Interoperability Test Suite (PKITS) | https://csrc.nist.gov/projects/pki-testing | `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665` (SHA-256 of `PKITS_data.zip`; NIST publishes no version) | `certs/` and `crls/`, 578 files extracted from the archive | US Government Work (17 U.S.C. §105), public domain |

x509-limbo is a project of the C2SP (Community Cryptography Specification Project), originally by Trail of Bits; Project Wycheproof was started by Google and is maintained under C2SP. PKITS is published by the US National Institute of Standards and Technology and is a work of the United States Government, which 17 U.S.C. §105 places in the public domain. All three are used unmodified, as test inputs only.

PKITS is distributed as a ZIP archive and nothing else, so it is pinned twice: by the SHA-256 of the archive, which fixes every byte in it, and by a per-file list in `.github/checksums/` that holds this project's own ZIP reader to the bytes reviewed. The archive also carries PKCS#12 bundles, S/MIME messages, cross-certificate pairs and an LDIF export; none is extracted.

## Standards text (downloaded, never committed)

| Document | Source | Pinned SHA-256 | Files | Licence |
|---|---|---|---|---|
| RFC 5280, Internet X.509 PKI Certificate and CRL Profile (plain text) | https://www.rfc-editor.org/rfc/rfc5280 | `a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d` (SHA-256 of `rfc5280.txt`; an RFC has no version but its number) | `rfc5280.txt`, from https://www.rfc-editor.org/rfc/rfc5280.txt | Copyright (C) The IETF Trust (2008), BCP 78 |
| RFC 5652, Cryptographic Message Syntax (CMS) (plain text) | https://www.rfc-editor.org/rfc/rfc5652 | `dbd209ae7844031f51722c4d9e2d1fa3fff3081319851d581f914f5f0147f918` (SHA-256 of `rfc5652.txt`) | `rfc5652.txt`, from https://www.rfc-editor.org/rfc/rfc5652.txt | Copyright (C) The IETF Trust (2009), BCP 78 |
| RFC 3161, Internet X.509 PKI Time-Stamp Protocol (TSP) (plain text) | https://www.rfc-editor.org/rfc/rfc3161 | `39fd17644ff2d654bc83814a78b1c5b5e7517f496741f34ead5064943eb98240` (SHA-256 of `rfc3161.txt`) | `rfc3161.txt`, from https://www.rfc-editor.org/rfc/rfc3161.txt | Copyright (C) The Internet Society (2001) |
| RFC 6960, X.509 Internet PKI Online Certificate Status Protocol - OCSP (plain text) | https://www.rfc-editor.org/rfc/rfc6960 | `7e63ffa1ea2ce2737d9aaf895a63776e9105ddbdfc97b8ae4029e3e825b4cdea` (SHA-256 of `rfc6960.txt`) | `rfc6960.txt`, from https://www.rfc-editor.org/rfc/rfc6960.txt | Copyright (C) The IETF Trust (2013), BCP 78 |
| RFC 7292, PKCS #12: Personal Information Exchange Syntax v1.1 (plain text) | https://www.rfc-editor.org/rfc/rfc7292 | `168ce6749ac36f9a03c105e29b968ebe6f0d77cefce0200857f1d82d7de6cbad` (SHA-256 of `rfc7292.txt`) | `rfc7292.txt`, from https://www.rfc-editor.org/rfc/rfc7292.txt | Copyright (C) The IETF Trust (2014), BCP 78 |
| RFC 7468, Textual Encodings of PKIX, PKCS, and CMS Structures (plain text) | https://www.rfc-editor.org/rfc/rfc7468 | `0b2c3c2087cc0b099789c90e61c0208e87b25793f0ce40090979e8c734b3d989` (SHA-256 of `rfc7468.txt`) | `rfc7468.txt`, from https://www.rfc-editor.org/rfc/rfc7468.txt | Copyright (C) The IETF Trust (2015), BCP 78 |

RFC 5280 is fetched and pinned like the corpora above, by `npm run conformance:fetch`, and read by conformance level L5 to check that every clause of `scripts/lib/clauses.ts` quotes it verbatim and that every requirement sentence of its §4.1 and §4.2 is accounted for. The document is not redistributed. Individual sentences of it are quoted, each with its section, in `scripts/lib/clauses.ts` and `scripts/data/rfc5280-requirements.json`, as the subject of that review; the RFC's copyright notice is *"Copyright (C) The IETF Trust (2008). This document is subject to the rights, licenses and restrictions contained in BCP 78, and except as set forth therein, the authors retain all their rights"*, and the IETF Trust Legal Provisions (https://trustee.ietf.org/license-info) govern its use. The ITU-T X.690 sentences quoted by three clauses are not pinned and not checked this way: they quote Recommendation ITU-T X.690 (02/2021), published by the ITU only as a PDF, were compared with its text by hand, and `tests/conformance/clauses.test.ts` holds them to that reading.

RFC 5652, RFC 3161, RFC 6960, RFC 7292 and RFC 7468 are fetched, pinned and read the same way, so that every requirement sentence of their inventoried sections is accounted for in `scripts/data/rfc<NNNN>-requirements.json`, where those sentences are quoted with their section as the subject of that review. None is redistributed. RFC 5652, 6960, 7292 and 7468 carry the IETF Trust notice of their year under BCP 78 and the IETF Trust Legal Provisions; RFC 3161 predates the Trust and carries *"Copyright (C) The Internet Society (2001). All Rights Reserved."*, whose full statement permits copies and derivative works that keep the notice.

## Committed test fixtures

`tests/fixtures/certs/` holds six public certificates of foreign provenance — the ISRG roots, two Let's Encrypt intermediates, one Let's Encrypt end-entity certificate and the RFC 8410 §10.2 example. [tests/fixtures/PROVENANCE.md](tests/fixtures/PROVENANCE.md) lists the source, retrieval date, SHA-256 and terms of each; `tests/docs/fixture-budget.test.ts` holds the files to those hashes. Certificates are public data published for distribution; none carries a private key.

## Cross-implementation validators (run, never vendored)

Conformance level L4 confronts pkinative's reading of a certificate with other implementations'. Each of them is a toolchain the runner already provides, or one the conformance workflow installs at a pinned version:

- **Microsoft CryptoAPI**, reached through .NET's `X509Certificate2` under Windows PowerShell, which ships with Windows.
- **Go crypto/x509**, through `scripts/validators/go-x509/main.go` (standard library only), with the Go toolchain `actions/setup-go` installs at a commit-pinned release on the Linux runner.
- **pyca/cryptography**, through `scripts/validators/python-cryptography.py`, installed on the Linux runner from `scripts/data/interop-python-requirements.txt`, pinned by version and by the SHA-256 of every file (`pip --require-hashes`).
- **OpenSSL**, through the `openssl` command line at level L3 — the OpenSSL build of the runner image, and separately the one inside Node.js.

None of these is vendored, cached or redistributed by this repository: the gate invokes them, and what it installs it pins, so nothing reaches the gate that a reviewer did not pin. That is also the rule for admitting a new one. They are used as independent readers, never as libraries, and no code of theirs enters `dist/`.

## Interoperability matrix tools (run, never vendored)

`npm run interop` (`scripts/run-interop.ts`) hands what pkinative writes to foreign tools and verifies what they write. Each is invoked as a separate program; none is vendored, redistributed or linked, and no code of theirs enters `dist/`. Where the conformance workflow installs one, it pins it.

| Tool id | What it is | Where it comes from |
|---|---|---|
| `openssl` | The OpenSSL command line | the runner image |
| `windows-cryptoapi` | Microsoft CryptoAPI through .NET Framework's `X509Certificate2` | Windows PowerShell, part of Windows |
| `dotnet` | .NET's `X509Certificate2`, `CertificateRequest`, `SignedCms` and `Rfc3161TimestampRequest` | PowerShell 7, part of the runner image |
| `gnutls-certtool` | GnuTLS `certtool` | the Ubuntu archive (`gnutls-bin`), installed by the workflow |
| `go-x509` | Go `crypto/x509` | `actions/setup-go`, pinned by commit |
| `python-cryptography` | pyca/cryptography | `scripts/data/interop-python-requirements.txt`, pinned by version and SHA-256 |
| `java-keytool` | The JDK's `CertificateFactory`, PKIX validator and `keytool` | the runner image, wherever it carries a JDK |
| `gpgsm` | GnuPG's `gpgsm` over libksba | the Ubuntu archive, installed by the workflow |
| `zlint` | zlint v3, the Web PKI certificate linter | `go install github.com/zmap/zlint/v3/cmd/zlint@v3.7.2`, verified by the Go checksum database |
| `pkilint` | DigiCert pkilint | `scripts/data/interop-python-requirements.txt`, pinned by version and SHA-256 |

## Not included

- No third-party code is bundled into `dist/`.
- No private key of any kind is committed to the repository.
