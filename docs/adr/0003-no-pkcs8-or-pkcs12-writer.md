---
status: accepted
date: 2026-09-29
since: 0.8.0
---

# No PKCS#8 or PKCS#12 writer

## Context and Problem Statement

0.8 reads PKCS#8 and PKCS#12 ([ADR 0002](0002-pkcs12-pbes2-only.md)). A reader invites the symmetric request: export a key, or a key with its chain, to a password-protected file. Writing an encrypted PKCS#8 or a PKCS#12 means encrypting or wrapping private-key material, and having that material in hand in the first place.

## Decision Drivers

- [ADR 0001](0001-no-secret-dependent-cryptography.md): pkinative creates, exports, wraps and derives no raw key material, in any version.
- `encrypt` and `wrapKey` are refused by `KEY_OPERATION_POLICY` — "pkinative reads containers; it writes none" ([`scripts/lib/architecture.ts`](../../scripts/lib/architecture.ts)).
- `exportKey` is refused too, so a `CryptoKey` a caller holds could not be serialised into a container anyway.

## Considered Options

1. Write PKCS#8 and PKCS#12, opening `encrypt`, `wrapKey` and `exportKey` to the Web Crypto boundary.
2. Read only; leave writing key containers to the tools that generate the keys.

## Decision Outcome

Chosen option: 2. A writer would need the three operations the policy refuses permanently, and opening them would dissolve the guarantee that no key material passes through pkinative. The limitation is stated in every place a reader of 0.8 would look for it: "pkinative writes neither PKCS#8 nor PKCS#12, in any version: encrypting or wrapping a key is refused by `KEY_OPERATION_POLICY`" ([ROADMAP.md §0.8.x](../../ROADMAP.md), [release-notes/v0.8.0.md](../../release-notes/v0.8.0.md)).

### Consequences

- Good, because the reading half keeps its property: an encrypted key goes from ciphertext to a non-extractable `CryptoKey` and never exists in the clear here.
- Good, because the interop matrix for key containers is a one-way arrow with a clear burden of proof: a foreign tool writes, pkinative reads ([docs/guides/conformance.md](../guides/conformance.md)).
- Bad, because a caller who needs to produce a `.p12` or an encrypted key file does it with another tool, typically the one that generated the key.

### Confirmation

- `KEY_OPERATION_POLICY` lists `encrypt`, `wrapKey` and `exportKey` with no allowed module, and `tests/tools/architecture.test.ts` fails on any file of `src/` that names one.
- The `key-operation-parity` rule of `npm run verify:docs` holds the "nowhere / never" rows of SECURITY.md to that policy.

## More Information

- [SECURITY.md §Cryptographic Implementation Scope](../../SECURITY.md) — "Nowhere / never" is a promise, not a backlog.
- [docs/guides/conformance.md §Key containers](../guides/conformance.md) — why the interop arrow is turned back for key containers.
