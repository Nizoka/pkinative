---
status: accepted
date: 2026-09-29
since: 0.1.0
---

# No network I/O in the engine

## Context and Problem Statement

Several answers pkinative gives depend on bytes that live elsewhere: a CRL named by `cRLDistributionPoints`, an OCSP responder named by `authorityInfoAccess`, a missing intermediate an AIA `caIssuers` URI points at, a timestamp from a TSA. Many PKI stacks fetch them during validation. The question is whether pkinative's engine does.

## Decision Drivers

- A verifier that reached the network would be one an attacker can point at a host of their choosing: every such URI comes from a certificate or a message under the attacker's control ([release-notes/v0.5.0.md](../../release-notes/v0.5.0.md)).
- One API across Node, browsers, Deno, Bun and Workers: the engine has no `node:` import, no `process` and no filesystem (AGENTS.md §Mission and constraints).
- Validation stays synchronous and pure below `verify/`, and fuzzable without a host.

## Considered Options

1. Fetch inside the engine: CRLs, OCSP responses, AIA intermediates and timestamps, on demand during validation.
2. Fetch nothing: the caller passes every byte — DER as downloaded or as stapled — and pkinative decides.

## Decision Outcome

Chosen option: 2. Nothing in `src/` fetches — not a CRL, not an OCSP response, not a missing intermediate, not a timestamp. `verifyCertificateChain` takes `crls` and `ocspResponses`, `buildCertificatePath` searches the bag it is given, and a TSA request is built with `createTimeStampRequest` and sent by the caller ([docs/guides/use-cases.md](../guides/use-cases.md)).

### Consequences

- Good, because no certificate can make pkinative open a connection, and no validation outcome depends on the network being up.
- Good, because the same code runs unchanged on every host.
- Bad, because the caller owns fetching, caching and freshness, and a chain whose intermediate was not supplied fails to build.
- Bad, because the guides must show the fetch the library will not make; they do, as caller code.

### Confirmation

- `tests/tools/architecture.test.ts` refuses, from the syntax tree, `node:` imports, bare package specifiers, dynamic `import`, and the globals of `FORBIDDEN_GLOBALS` in [`scripts/lib/architecture.ts`](../../scripts/lib/architecture.ts) — `fetch`, `WebSocket`, `XMLHttpRequest`, `EventSource` and `process` among them.
- [SECURITY.md §Code Safety](../../SECURITY.md) — "No filesystem, network or process access in the engine".

## More Information

- [README.md §What pkinative will NOT do](../../README.md).
- [CHANGELOG.md, 0.5.0](../../CHANGELOG.md) — the verify layer "does not fetch", and why.
- [release-notes/v0.7.0.md §Known limitations](../../release-notes/v0.7.0.md) — "Nothing here fetches — not a CRL, not an OCSP response, not a timestamp."
