---
description: "Untrusted-input hardening rules — bounds, strictness, error discipline and the cryptographic scope."
applyTo: "src/**"
---

# Security rules

Every certificate, PEM file and DER blob is attacker-controlled. Assume adversarial bytes at every field.

- **Every loop over input bytes** (TLV walk, base64 decode, string decode, extension list, name list) consults a
  named bound from `PkiLimits` (`src/core/pki-limits.ts`). Adding a loop means adding or citing a limit — with
  CWE tag, default, fuzzing test, and SECURITY.md row in the same PR.
- **Validate before allocating.** A declared length is checked against the remaining input and the limits before
  any buffer is created or any child is pushed.
- **The decoder is iterative.** Nesting is bounded by `maxDepth` and ends in `PkiLimitError`, never in a
  `RangeError` from the call stack.
- **Refuse ambiguity.** DER is the default; every X.690 §10–11 violation throws. Accepting two encodings of one
  value lets a signature cover bytes that two parsers read differently (CWE-436). BER is an explicit opt-in.
- **Structural failures throw; conformance concerns diagnose; never both.** A diagnostic never hides a structural
  failure, and a thrown error never carries a merely pedantic concern.
- **Every thrown value is a `PkiError` subclass** with a stable `code` and a message that starts with
  `pkinative: ` and names the remedy. A `TypeError` escaping from malformed input is a bug.
- **No object keys from input.** Decoded names and OIDs go into arrays or `Map`s, never into plain object keys
  (prototype pollution, CWE-1321).
- **No secret-dependent cryptography, ever.** `src/` holds no modular exponentiation, no elliptic-curve scalar
  multiplication and no signature algorithm. Hashing covers public data only. Signing and verification are each
  one call to Web Crypto with a key the **caller** owns.
- **Web Crypto has exactly one door**, `src/crypto/webcrypto.ts`: the only module that may name `importKey`,
  `verify`, `sign` and, since 0.8, `deriveKey`, `unwrapKey` and `decrypt`. `KEY_OPERATION_POLICY`
  (`scripts/lib/architecture.ts`) is the table, it is per module and not per layer, and
  `tests/tools/architecture.test.ts` enforces it from the syntax tree — a declaration in an interface counts. Adding a key operation anywhere means editing that table in its own reviewed commit.
- **`generateKey` and `exportKey` are refused in every version.** That is why `createCertificate` takes
  `subjectPublicKey` as SubjectPublicKeyInfo **DER** and not a `CryptoKey`: extracting the public half is one
  line in the caller's code, where it is visible, and an API that hid it would make this promise unverifiable.
  A private key reaches `src/` only as an opaque handle: one the caller passes to be handed straight to
  `subtle.sign`, or one the door itself creates non-extractable from a PKCS#8 — `unwrapKey` for an encrypted
  one, so its plaintext never exists in JavaScript. `deriveBits` stays refused because `deriveKey` returns a
  handle where it would return bytes, and **RFC 7292 Appendix B is never implemented**: it is iterated hashing
  with byte arithmetic over the password.
- **Verification fails closed; signing does not.** A host that throws during `verify` is a `false`, because "no"
  is a legitimate verdict. A signature that did not happen has no safe falsy value — an empty signature is a
  certificate that verifies nowhere and looks valid until someone checks — so `signData` throws.
- No `eval`/`Function`/`setTimeout(string)`. No sockets. No filesystem. No `process`. No dynamic `import()`.
- Fuzzing tests must assert: a clean typed error (a `PkiError` subclass), no hang, bounded memory — for every
  truncation point and corruption class.
