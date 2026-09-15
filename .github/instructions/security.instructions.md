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
  multiplication, no key generation, no signing. Hashing covers public data only. Verification (0.3) goes through
  Web Crypto.
- No `eval`/`Function`/`setTimeout(string)`. No sockets. No filesystem. No `process`. No dynamic `import()`.
- Fuzzing tests must assert: a clean typed error (a `PkiError` subclass), no hang, bounded memory — for every
  truncation point and corruption class.
