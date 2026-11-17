---
status: accepted
date: 2026-11-17
since: 1.1.0
---

# `strict` in the verify and check verbs: a composition reports the refused warning, a primitive throws it

## Context and Problem Statement

`strict: true` refuses the first `warning` diagnostic of a parse with `PKI_STRICT_DIAGNOSTIC` (`src/core/pki-diagnostics.ts`). Until 1.1.0 it stopped at the parsers. The verbs that parse on the caller's behalf — `verifyCertificateChain`, `verifyTimeStampToken`, `verifySignedData`, `checkRevocation`, `checkOcspStatus` — took `onDiagnostic` (four of them) and no `strict`; `verifySignedData` took neither and read its message with a silent sink. [ADR 0013](0013-renames-before-the-freeze.md) had removed `strict` from `CheckRevocationInput` on purpose, on the ground that nothing passed it, and the TSDoc of two inputs said "`strict` is not an input here". `openPkcs12` accepted both options in its type, through `PkiParseOptions`, and applied neither.

The consequence, reported in [issue #18](https://github.com/Nizoka/pkinative/issues/18): the same bytes are refused by `parseTimeStampToken(token, { strict: true })` and accepted by `verifyTimeStampToken({ token, strict: true })`, and a front end that promises "strict escalates the first engine warning" has to collect the diagnostics itself, decide which severity counts, and for `verifySignedData` parse the message a second time to reach a sink. Which warning counts is the engine's knowledge.

Adding `strict` to the verbs raises one question the parsers never had to answer: a parser refuses by throwing, and a report function promises to resolve ([ADR 0011](0011-reasons-returned-and-one-converting-layer.md)). What does a report do with a warning it was asked to refuse?

## Decision Drivers

- ADR 0011: a composition reports; `PKI_REASON_INPUT_MALFORMED` exists to wrap, in `errorCode`, the `PkiErrorCode` that would have been thrown, so that a report never needs a second vocabulary of failures. Only `src/verify/` turns a `PkiError` into a reason.
- `tests/fuzzing/reports.test.ts` holds every report function to "always resolves". An option that made one of them throw for the input's sake would put a `try` back around every call site that passes it.
- `verifyCertificationRequest` has taken `strict` since 1.0.0 and already answers this way: the refused warning is `PKI_REASON_INPUT_MALFORMED` carrying `PKI_STRICT_DIAGNOSTIC` (`src/verify/verify-csr.ts`).
- `checkRevocation` and `checkOcspStatus` live in `revocation/`, a layer that may not convert an error into a reason, and `checkRevocation` already throws for a malformed entry met during the walk. `findRevocation`, the walk itself, already takes `strict` and throws.
- [ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md): an added optional member is a compatible change; a changed heritage is not one `api-surface-frozen` can prove compatible. Under `strict: true`, 1.x keeps `PKI_STRICT_DIAGNOSTIC` as the code and lets a minor change which inputs are refused.
- A certificate that merely travels with the evidence — in a SignedData's bag, attached to an OCSP response — is a hint from whoever assembled the message. The parsers that read the carrying structure do not parse it, so they do not refuse it under `strict` either.

## Considered Options

1. Leave `strict` to the parsers, and document that a strict caller parses first and verifies second.
2. Add `strict` everywhere, and let every verb throw `PKI_STRICT_DIAGNOSTIC` as the parsers do.
3. Add `strict` everywhere: a composition in `verify/` reports the refusal as a reason, a primitive in `revocation/` throws it.
4. Option 3, with the input types extending `PkiParseOptions` instead of declaring the member.

## Decision Outcome

Chosen option: 3. Each of `VerifyCertificateChainInput`, `VerifyTimeStampTokenInput`, `VerifySignedDataInput`, `CheckRevocationInput` and `CheckOcspStatusInput` declares `strict?: boolean | undefined` inline, and `VerifySignedDataInput` declares `onDiagnostic` as well. The rule has two halves.

**In a composition (`src/verify/`)** a warning refused under `strict` is never an exception. It is `valid: false` with `PKI_REASON_INPUT_MALFORMED`, `errorCode: 'PKI_STRICT_DIAGNOSTIC'`, at the path of the member that carried it: `crls[i]` and `ocspResponses[i]` in `verifyCertificateChain` (the list or the response as parsed, an entry met by the walk, what `checkOcspStatus` raises about the response); `token` or `response`, and `token.certificates` for the `certReq` contract, in `verifyTimeStampToken`; `signedData` in `verifySignedData`, which forwards `strict` and its sink to the timestamp and chain verifications it nests, so their refusals arrive under `signerInfos[i].unsignedAttrs.timeStampToken[j]` and `signerInfos[i].chain` as their other reasons do, and their diagnostics reach the caller's handler with the same prefix on `path`. The reason's `message` is the thrown one, which names the diagnostic code.

**In a primitive (`checkRevocation`, `checkOcspStatus`)** it throws `PKI_STRICT_DIAGNOSTIC`, as `findRevocation` does. The primitive is the caller's own composition step: it has no report to put a reason in whose code would not be a second meaning for a revocation reason, and `checkRevocation` already throws for the bytes it walks. `verifyCertificateChain` catches both, at the places it already caught a malformed entry and a malformed response.

Three readings stay lenient under `strict`, because refusing there would change a verdict without saying why:

- **Certificates in a bag.** `_parseBag` (the certificates a SignedData or a token carries) and the certificates an OCSP response attaches are parsed without `strict`. A bag certificate that failed a strict parse would be counted "unreadable" and the signer reported not found; an attached delegate would be skipped and the response reported unauthorised — a refusal with the cause hidden. `parseSignedData` and `parseOcspResponse` under `strict` do not refuse them either, since they keep them as DER.
- **Certificates the caller passes parsed** (`leaf`, `candidates`, `trustAnchors`, `certificates`, `signer`): the caller parsed them, with the strictness the caller chose.
- **The `request` of `verifyTimeStampToken`**: the caller's own question, not evidence. It is read without `strict`; a malformed one still throws, as misuse.

A `strict` that is not a boolean is misuse and throws `PKI_INVALID_OPTION` before anything is read, in the compositions and in `checkRevocation`; an `info` is reported and never refused, as everywhere.

**`openPkcs12` is wired, not exempted.** `OpenPkcs12Options` has extended `PkiParseOptions` since 0.8.0, `docs/data/defaults.json` listed it in the `strict` row, and the function built its reading options without either member. From 1.1.0 it passes both to every reader it calls. Each of those calls already sat in a catch that reports, so the composition rule holds with no new code path: a refused warning is `PKI_REASON_INPUT_MALFORMED` with `PKI_STRICT_DIAGNOSTIC` at `pkcs12`, at the SafeContents, or at the bag. Unlike a CMS bag, the certificates of a PKCS#12 are what the call opens, each reported at its own path, so they are read under `strict`. Without a handler the call stays silent, as before.

Option 1 was rejected because it leaves the knowledge of what counts with every front end, and cannot reach what only the verify decides (`PKI_DIAG_TSP_CERTREQ_UNMET`, `PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH`). Option 2 was rejected because it breaks "a report always resolves" for exactly the callers who asked for more care. Option 4 was rejected because `classify` in `scripts/lib/api-surface.ts` reads a changed interface head as incompatible, and because `encodingRules` would then be promised on inputs whose lists, responses and tokens are read as DER and nothing else.

This record amends ADR 0013 on one point: `CheckRevocationInput` takes `strict` again. The ground given there — nothing passes it — no longer holds.

### Consequences

- Good, because one option means one thing from the parser to the report: the bytes a strict parse refuses, a strict verify refuses, with the same code.
- Good, because a front end reads `errorCode === 'PKI_STRICT_DIAGNOSTIC'` on a reason instead of re-deriving the engine's severity rule, and `verifySignedData` no longer needs a second parse to report.
- Good, because "always resolves" now holds for every composition under `strict: true` as well as under the default options; the fuzzing suite runs both.
- Bad, because the two halves are two behaviours for one option: `checkRevocation` and `checkOcspStatus` throw where `verifyCertificateChain` reports. The line is the one ADR 0011 already drew between a primitive and a composition.
- Bad, because `checkOcspStatus` can now throw for something other than its tolerances; a caller who passes `strict: true` to it accepts a `try`.
- Bad, because one refusal is not named where it happens: a warning met only while a delegated CRL signer or OCSP responder is itself being judged against the caller's lists makes that delegate not believed — fail closed, exactly as an entry that cannot be read there already does — and the report then says the list or response it signed is unverified, not why. The list that raised the warning is named whenever a certificate of the path is judged against it.
- Bad, because a caller who passed `strict: true` or `onDiagnostic` to `openPkcs12` on 1.0.x, where both were ignored, sees them take effect: a container with a warning is now reported `valid: false`. This is the meaning the option always had (ADR 0018, non-default options), and the release note says so under the decision surface.
- Neutral, because the default is unchanged everywhere: without `strict` no verdict moves, and without a handler the compositions stay silent.

### Confirmation

- `tests/verify/verify-chain.test.ts`, `verify-timestamp.test.ts`, `verify-signed-data.test.ts` and `verify-pkcs12.test.ts`: for each verb, the same bytes — the parser throws `PKI_STRICT_DIAGNOSTIC` under `strict`, the verify resolves `valid: false` with `PKI_REASON_INPUT_MALFORMED`, `errorCode: 'PKI_STRICT_DIAGNOSTIC'` and the member's path; a bag certificate and an attached delegate carrying a warning do not change the verdict under `strict`.
- `tests/revocation/crl-check.test.ts` and `ocsp-check.test.ts`: the primitives throw `PKI_STRICT_DIAGNOSTIC` for a `warning`, and report an `info`.
- `tests/fuzzing/reports.test.ts`: every report function resolves with a registered report under the default options and under `strict: true`.
- `docs/data/defaults.json`: the `strict` row names the five input types, the silent `onDiagnostic` row names `VerifySignedDataInput` and `OpenPkcs12Options`; `option-defaults-parity` holds each row to its source line.
- `.github/instructions/decision.instructions.md` states the rule for agents; `claude-rules-sync` holds its compiled copy.

## More Information

- [ADR 0011](0011-reasons-returned-and-one-converting-layer.md) — reasons are returned, and one layer converts.
- [ADR 0013](0013-renames-before-the-freeze.md) — where `strict` left `CheckRevocationInput`; amended by this record.
- [ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md) — an added optional member is compatible; what `strict: true` promises.
- [docs/guides/errors.md](../guides/errors.md) — `PKI_STRICT_DIAGNOSTIC`, and where a refused warning surfaces.
- [Issue #18](https://github.com/Nizoka/pkinative/issues/18) — the request.
