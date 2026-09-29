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

RFC 5280 is fetched and pinned like the corpora above, by `npm run conformance:fetch`, and read by conformance level L5 to check that every clause of `scripts/lib/clauses.ts` quotes it verbatim and that every requirement sentence of its §4.1 and §4.2 is accounted for. The document is not redistributed. Individual sentences of it are quoted, each with its section, in `scripts/lib/clauses.ts` and `scripts/data/rfc5280-requirements.json`, as the subject of that review; the RFC's copyright notice is *"Copyright (C) The IETF Trust (2008). This document is subject to the rights, licenses and restrictions contained in BCP 78, and except as set forth therein, the authors retain all their rights"*, and the IETF Trust Legal Provisions (https://trustee.ietf.org/license-info) govern its use. The ITU-T X.690 sentences quoted by three clauses are not pinned and not checked this way.

## Committed test fixtures

`tests/fixtures/certs/` holds six public certificates of foreign provenance — the ISRG roots, two Let's Encrypt intermediates, one Let's Encrypt end-entity certificate and the RFC 8410 §10.2 example. [tests/fixtures/PROVENANCE.md](tests/fixtures/PROVENANCE.md) lists the source, retrieval date, SHA-256 and terms of each; `tests/docs/fixture-budget.test.ts` holds the files to those hashes. Certificates are public data published for distribution; none carries a private key.

## Cross-implementation validators (already on the runner, never fetched)

Conformance level L4 confronts pkinative's reading of a certificate with other implementations'. Each of them is a toolchain the runner already provides:

- **Microsoft CryptoAPI**, reached through .NET's `X509Certificate2` under Windows PowerShell, which ships with Windows.
- **OpenSSL**, through the `openssl` command line at level L3 — the OpenSSL build of the runner image, and separately the one inside Node.js.

None of these is downloaded, vendored, cached or checksum-pinned by this repository, and none is redistributed: the gate invokes what the platform already has, so it adds no supply-chain surface of its own. That is also the rule for admitting a new one. They are used as independent readers, never as libraries, and no code of theirs enters `dist/`.

## Not included

- No third-party code is bundled into `dist/`.
- No private key of any kind is committed to the repository.
