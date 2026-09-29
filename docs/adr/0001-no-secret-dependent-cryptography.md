---
status: accepted
date: 2026-09-29
since: 0.1.0
---

# No secret-dependent cryptography in TypeScript; Web Crypto is the one door

## Context and Problem Statement

pkinative verifies signatures (0.3), creates certificates, requests and CMS messages signed by a caller's key (0.3, 0.7), and opens password-protected private keys (0.8). Each of those needs a cryptographic primitive, and some of them touch secret material.

pkinative grew out of the X.509 and CMS code of pdfnative, whose RSA and ECDSA are pure JavaScript over `BigInt` and are not constant-time ([README.md §Origin](../../README.md)). The question is where arithmetic on secrets happens, and how a test, rather than a sentence, can keep it out of `src/`.

## Decision Drivers

- Constant-time implementations exist in the host (Web Crypto); a TypeScript `BigInt` implementation is not constant-time.
- A guarantee is worth more when a test can check it: arithmetic cannot be recognised from a syntax tree, but *naming* a Web Crypto key operation can ([SECURITY.md §Cryptographic Implementation Scope](../../SECURITY.md)).
- The key should never belong to pkinative: a builder takes the public half as DER and the private key only as an opaque handle ([ROADMAP.md §0.3.x](../../ROADMAP.md)).
- Key material handed back as an `ArrayBuffer` cannot be zeroised; a non-extractable handle can be dropped.
- Everything pkinative asks of a host should be readable in a small, fixed set of files.

## Considered Options

1. Port pdfnative's TypeScript RSA and ECDSA.
2. A blanket ban on every Web Crypto key operation anywhere in `src/` — the rule pkinative started with, which refused eleven operations everywhere, type declarations included.
3. A per-operation, per-module policy: each operation lists the exact modules allowed to name it, and an empty list is a permanent refusal.

## Decision Outcome

Chosen option: 3, `KEY_OPERATION_POLICY` in [`scripts/lib/architecture.ts`](../../scripts/lib/architecture.ts). Option 1 is the non-constant-time code this library exists without. Option 2 made 0.3 impossible, because the boundary could not even declare the host types it calls ([CHANGELOG.md, 0.3.0](../../CHANGELOG.md)); deleting entries from the ban would have traded the guarantee for the feature.

| Operation | Allowed in | Since |
|---|---|---|
| `importKey`, `verify`, `sign` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.3.0 |
| `deriveKey`, `unwrapKey`, `decrypt` | `src/types/webcrypto.ts`, `src/crypto/webcrypto.ts` | 0.8.0 |
| `generateKey`, `exportKey`, `deriveBits`, `encrypt`, `wrapKey` | nowhere | never |

The five refusals are permanent, each for the reason `KEY_OPERATION_POLICY` records beside it: `generateKey` and `exportKey` because owning a key's lifetime is the caller's job; `deriveBits` because it returns key material nothing can zeroise, and `deriveKey` strictly dominates it; `encrypt` and `wrapKey` because pkinative reads containers and writes none ([ADR 0003](0003-no-pkcs8-or-pkcs12-writer.md)). The host object has one door too: only `src/crypto/webcrypto.ts` and `src/hash/fingerprint.ts` may reach `globalThis.crypto` (`WEBCRYPTO_HOST_MODULES`).

Hashing (SHA-1, SHA-256, SHA-384, SHA-512) stays in TypeScript, for synchronous fingerprints of **public** data only, and the DER ↔ P1363 converter stays in TypeScript because a signature holds no key and the conversion copies bytes.

### Consequences

- Good, because the promise is checkable: a file outside the allowed list that names an operation — in a call or in a type — fails the build.
- Good, because verification ships no parser: the verification probe of `scripts/verify-bundle.ts` weighs the built artefact and finds neither the certificate parser nor the decoder in it.
- Good, because an encrypted private key is opened with `unwrapKey` into a non-extractable `CryptoKey`, so its plaintext never exists in JavaScript ([release-notes/v0.8.0.md](../../release-notes/v0.8.0.md)).
- Bad, because the caller writes one line of their own to export a SubjectPublicKeyInfo, since `exportKey` is refused ([SECURITY.md](../../SECURITY.md)).
- Bad, because an algorithm the host lacks cannot be verified here at all ([ADR 0004](0004-dsa-and-ed448-cms-signers-not-verified.md)), and legacy password-based schemes cannot be opened ([ADR 0002](0002-pkcs12-pbes2-only.md)).
- Bad, because arithmetic itself is kept out by review, not by a test — SECURITY.md says so.

### Confirmation

- `tests/tools/architecture.test.ts` decides, from the syntax tree, that every key operation is named only by the modules `KEY_OPERATION_POLICY` allows, and that only `WEBCRYPTO_HOST_MODULES` reach the host object.
- The `key-operation-parity` rule of `npm run verify:docs` holds the SECURITY.md table to `KEY_OPERATION_POLICY`; widening the policy is a reviewed commit that changes both in the same diff.
- `npm run verify:bundle` (the gate step of the same name) keeps the verification probe free of the parser markers.
- `docs/assets/ecosystem.json` → `contracts.secret_dependent_primitives`: "never implemented; Web Crypto only".

## More Information

- [SECURITY.md §Cryptographic Implementation Scope](../../SECURITY.md) — the table and the reasoning behind each refusal.
- [CHANGELOG.md, 0.3.0](../../CHANGELOG.md) and [release-notes/v0.3.0.md](../../release-notes/v0.3.0.md) — `KEY_OPERATION_POLICY` replaces the blanket ban of eleven operations.
- [release-notes/v0.8.0.md](../../release-notes/v0.8.0.md) — the door opens `deriveKey`, `unwrapKey` and `decrypt`, in its own commit, to the two boundary files only.
- The principle has been part of the mission since the first tag; the per-module policy took effect at 0.3.0 and was widened once, at 0.8.0.
