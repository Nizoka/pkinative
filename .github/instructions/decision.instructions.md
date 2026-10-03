---
description: "Use when working on path building and validation, CRL and OCSP revocation, or the one-call verify reports. Covers verdicts versus errors, fail-closed rules, the verdict table of the 1.x promise and the conformance corpora."
applyTo: "src/path/**,src/revocation/**,src/verify/**"
---
# Decision-layer rules (path, revocation, verify)

## Verdicts, not exceptions
- A report function (`verifyCertificateChain`, `checkRevocation`, `checkOcspStatus`, `verifySignedData`, `verifyTimeStampToken`, `openPkcs12`, …) **always resolves** with a report; `tests/fuzzing/reports.test.ts` holds that for every one of them. Only `verify/` turns a `PkiError` into a reason, through `_reasonOf`-style helpers that keep the error's `code` in the report.
- Reasons are `PKI_REASON_<SUBJECT>_<CONDITION>` in `docs/data/reasons.json`, part of `api.frozen.json`: a reason is never renamed; a new one carries `since` newer than the snapshot's `asOf` — reuse an existing reason before proposing one.
- A conformance concern inside a decision (responderID ≠ signer, a delegate checked at `producedAt`, a certReq unmet) is a **diagnostic** through the context's emitter, never a verdict change, unless an RFC makes it a MUST that decides validity.

## Fail closed
- A host that throws during `verify` is `false`; "no" is a legitimate verdict. Missing evidence is a reason (`…_UNAVAILABLE`, `…_UNCHECKED`), never `good`.
- Every candidate (certificate, CRL, OCSP response, signer) is bounded by a named limit before it is examined (`maxPathsExplored`, `maxRevokedCertificates`, `maxOcspSingleResponses`, `maxPolicyNodes`); limits trip as `PKI_LIMIT_EXCEEDED` with the limit's name, turned into a reason by `verify/`.
- A trust anchor is matched by **name and key**; a CRL or OCSP signer off the path is validated under the same anchors as the path; the user's policy set is intersected in the anchor's domain. Each of these was a bypass found by the 1.0 review — the locking tests are in `tests/verify/` and must stay.
- `Date.now()` is a default only; every report takes `at` and records the instant it used.

## The verdict table (ADR 0018)
- A verdict that changes in a minor (an acceptance where a reason stood, or the reverse) is listed in the release note's verdict table with the old and new reason and the RFC sentence that decides it. Run the corpora before and after: `npm run build` then `npx tsx scripts/validate-certs.ts --level 8 --require-all`; refusals (`docs/data/refusals.frozen.json`) must not move; L6 (x509-limbo), L7 (PKITS) and L8 scores move only in the direction the release note states.
- Signature verdicts come **precomputed** into `path/` (`SignatureResult[]`); `path/` and `cms/` never import `crypto/`. Laziness lives in `verify/`, where the Web Crypto door is reachable.

## Tests
- Each decision rule has a synthetic chain built with `tests/helpers/` (certificate templates + raw DER builder), not a committed fixture; the test asserts the reason code and the step that produced it.
- Revocation: CRL scope (IDP, `onlySomeReasons`, delta, indirect), OCSP (CertID, nonce, delegate, `thisUpdate`/`nextUpdate`) — one `it` per RFC sentence, named with its section.
