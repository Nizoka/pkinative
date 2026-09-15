# pkinative

**Read the certificates your software trusts — strictly, safely, on every runtime, without a single dependency.**

![Zero runtime dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![TypeScript strict mode](https://img.shields.io/badge/TypeScript-strict-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Zero runtime dependencies. 100% TypeScript. One API across Node.js ≥ 22, browsers, Deno, Bun and Workers. The third library of the *native* family, under the engineering doctrine of [pdfnative](https://github.com/Nizoka/pdfnative) and [zipnative](https://github.com/Nizoka/zipnative).

> **Status: in development toward 0.1.0 — not on npm.** The npm name is reserved by an empty 0.0.1; pre-1.0 versions are git tags, and the first npm publication is 1.0.0 ([ROADMAP.md](ROADMAP.md)).

## Why pkinative?

The JavaScript ecosystem parses certificates with node-forge, pkijs, asn1js and @peculiar/x509 — tens of millions of weekly downloads between them, pre-ES2015 code or dependency chains, and a history of ASN.1 parser advisories. pkinative starts from the other end:

- **Strict by default.** DER is decoded as X.690 §10–11 requires: two encodings of one value is an ambiguity an attacker can exploit, so it is refused, not guessed at.
- **Safe on hostile input.** Every loop runs under a named, CWE-tagged, caller-configurable limit; nesting is iterative; every failure is a typed error with a stable code.
- **Complete.** Every RFC 5280 extension decoded to its ASN.1 module, every GeneralName form, every DirectoryString type — not the four name attributes a signing tool happened to need.
- **No cryptography it should not own.** pkinative never implements signing, key generation or arithmetic on secret material; verification arrives through Web Crypto.
- **Held to external corpora.** A blocking conformance gate runs x509-limbo and Wycheproof, pinned by commit and checksum.
- **Agent-pilotable.** Machine-readable error codes, a diagnostics channel, `llms.txt`, and a human-in-the-loop AI governance policy.

## What pkinative will NOT do

No runtime dependency. No TypeScript implementation of signing, key generation or modular arithmetic on secrets. No certificate path validation before 0.5. No filesystem, network or process access inside the engine. No lenient decoder that silently accepts what the standard forbids.

## License

[MIT](LICENSE) © Nizoka — Plika
