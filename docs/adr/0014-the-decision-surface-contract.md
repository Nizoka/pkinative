---
status: accepted
date: 2026-09-29
since: 1.0.0
---

# The decision surface: a frozen refusal keeps its code, a new refusal is a recorded fix, and DER re-encodes byte for byte

## Context and Problem Statement

ROADMAP §1.0.0 promises three things, each held by a rule: the export surface, the error vocabulary, and the *decision surface*, which certificate pkinative refuses, with which code, plus the identity that decoding DER and encoding the result gives back the same bytes — `encodeAsn1Node(decodeAsn1(der))` equal to `der` ([ROADMAP.md §1.0.0](../../ROADMAP.md)). The first two already have a snapshot and a rule: `docs/assets/api.frozen.json` and `api-surface-frozen` ([ADR 0013](0013-renames-before-the-freeze.md)), `docs/data/errors.frozen.json` and `error-codes-frozen` ([ADR 0012](0012-frozen-error-vocabulary.md)). The third is behaviour, not a name, and pkinative decides at three levels:

- **Parsing.** `parseCertificate` returns a certificate or throws a `PkiError` with a code. The conformance gate measures it at L1 over the 30 361 unique x509-limbo certificates: 565 are refused, each only where every limbo case using it expects failure, and each is held, code included, to the reviewed baseline `scripts/data/limbo-refusals.json` ([scripts/validate-certs.ts](../../scripts/validate-certs.ts)).
- **Encoding.** At L2 every one of those certificates — the refused ones included — is decoded with `decodeAsn1` and re-encoded with `encodeAsn1Node`, and must come back byte for byte.
- **Path validation, revocation and CMS.** `validateCertificatePath`, `verifyCertificateChain` and `verifySignedData` return a verdict and `PkiReasonCode`s. L6, L7 and L8 score them against x509-limbo and NIST PKITS, each disagreement recorded with a reason in `scripts/data/limbo-score.json`, `pkits-score.json` and `pkits-smime-score.json` ([ADR 0008](0008-section-6-judged-by-scored-corpora.md)).

The hard part is the word *frozen*. 0.9.0 closed two defects in which pkinative **accepted** a path RFC 5280 rejects — an `rfc822Name` constraint that did not reach a subject `emailAddress`, and an excluded `directoryName` compared by bytes only ([ADR 0005](0005-names-compared-by-encoded-bytes.md), [release-notes/v0.9.0.md](../../release-notes/v0.9.0.md)). A decision surface frozen as "no verdict ever changes in 1.x" would have made both fixes semver-major, which is a promise to stay vulnerable until 2.0. The question is what exactly is promised, at which level, in which direction, and what holds it.

## Decision Drivers

- Callers branch on `PkiError.code` and on whether a parser throws at all: a code that moves breaks them as surely as a renamed export ([ADR 0012](0012-frozen-error-vocabulary.md)).
- A security fix must be possible in a minor release. Every acceptance defect found so far was fixed by making pkinative refuse more, never less.
- The two directions are not symmetric. A new refusal costs availability; a lifted refusal can let through what a caller relied on being stopped.
- A promise is worth what checks it. Offline, a rule can compare two committed files; online, the conformance gate can compare the engine with the corpus. A sentence nothing checks is not a contract.
- The corpora move. A re-pin changes scores ([ADR 0008](0008-section-6-judged-by-scored-corpora.md)), and an upstream regeneration can replace certificates wholesale; the promise must say what becomes of a refused certificate the corpus no longer holds.
- Diagnostics are advice, and their severity and wording may change in a minor ([ADR 0012](0012-frozen-error-vocabulary.md)).

## Considered Options

1. **Freeze every verdict.** Parse refusals, the re-encoding identity, and every path, revocation and CMS verdict with its reasons: any change is semver-major.
2. **Promise nothing beyond the error vocabulary.** The decision surface is behaviour, and behaviour changes in minors; the release note says what moved.
3. **Freeze the parse-level refusals asymmetrically, and the re-encoding identity absolutely; record path verdicts without freezing them.** A frozen refusal never changes code and is never lifted in 1.x; a new refusal is a recorded fix; path verdicts may change in a minor, never silently.

## Decision Outcome

Chosen option: 3. Option 1 forbids the fixes 0.9 needed, at the level where they happened. Option 2 leaves a caller who files certificates by refusal code with nothing to rely on, and gives up the one level where the corpus can hold every answer to a code.

### What 1.x promises

The promise is made for the default options — DER, `strict: false`, `DEFAULT_PKI_LIMITS` — because those are what the gate runs.

| Change within 1.x | Semver | Held by |
|---|---|---|
| A refusal of `docs/data/refusals.frozen.json` is raised with another code | **major** — never in 1.x | `refusal-baseline-frozen`, conformance L1 |
| A refusal of the snapshot is lifted: the certificate now parses | **major** — never in 1.x | `refusal-baseline-frozen`, conformance L1 |
| A corpus certificate that parsed becomes refused | **minor**, only as a recorded security or conformance fix, listed by SHA-256 under `### Decision surface` in the release note that ships it | conformance L1 (only certificates whose every case expects failure), `refusal-baseline-frozen` (the release ratchet and the note) |
| `encodeAsn1Node(decodeAsn1(der))` differs from `der` for a corpus certificate | **never** — a defect, fixed in a patch | conformance L2 |
| A path, revocation or CMS verdict, or the reasons it returns, changes | **minor**, recorded: the reviewed baseline moves in the same diff, and the release note says so | conformance L6, L7, L8 |
| A `PkiReasonCode` is removed or renamed | **major** | `api-surface-frozen` ([ADR 0012](0012-frozen-error-vocabulary.md)) |

**Why a code change is major.** A refusal is the pair (certificate, code); callers branch on the second. A new check ordered before an existing one can pre-empt that code, so a fix must be placed where it does not — and if it cannot be, it waits for 2.0.

**Why lifting a refusal is major, although it is the permissive direction.** Every row of the baseline is used only by x509-limbo cases that expect failure — L1 fails otherwise — so lifting one cannot correct a verdict the corpus calls wrong: it only removes a refusal, or moves it later. A certificate refused wrongly by the standard's own reading stays refused until 2.0; that is the cost of a caller being able to rely on the refusal, and it errs closed.

**Why a new refusal is minor.** It is how security fixes land. Under L1 it can only touch a certificate every limbo case of which expects failure; a refusal outside that set fails the gate before it can ship. It is never silent: the release that ships it records it in the snapshot with its `since`, and the rule refuses the snapshot until that release's note lists it. A new refusal of a certificate outside the corpus is described under the same heading, but no rule can see it — the release audit reads for it.

**The re-encoding identity** holds for every certificate of the pinned corpora, the 565 refused at L1 included, in every 1.x release. It is stated for DER input: a value decoded from the BER indefinite-length form has no DER re-encoding, and `encodeAsn1Node` refuses it by design with `PKI_API_MISUSE`.

**Path verdicts are recorded, not frozen.** Both fixes of 0.9 were path verdicts, and §6 is judged by scored corpora whose scores move at every re-pin ([ADR 0008](0008-section-6-judged-by-scored-corpora.md)); the set of reasons also grows ([ADR 0012](0012-frozen-error-vocabulary.md)). What is promised is that no verdict moves unseen: a changed verdict is a `NEW-DISAGREEMENT` or an `UNEXPECTED-AGREEMENT`, a changed reason on a pinned case fails "rejected for a different reason", and each fails the gate until the reviewed baseline moves in the same diff, with a sentence for every new deviation.

### What is not promised

- **Diagnostics**: codes are additions-only ([ADR 0012](0012-frozen-error-vocabulary.md)), but a diagnostic's severity and wording may change in a minor. So under `strict: true`, which turns diagnostics into `PKI_STRICT_DIAGNOSTIC`, a certificate may become refused in a minor.
- **Error message wording.** The code and the class are the contract; the sentence after `pkinative: ` is for a human.
- **Limit default values.** A default may be **lowered** in a minor when an attack makes it dangerous — a new refusal like any other, recorded the same way. A caller who needs more raises it for trusted input; the library does not promise to. The limit *names* are frozen ([ADR 0012](0012-frozen-error-vocabulary.md)), and a raised default may never lift a frozen refusal: the two denial-of-service certificates refused by `maxNameAttributes` pin that one.
- **Conformance scores**, bundle sizes and performance. They are measurements, and they move when a corpus is re-pinned or a budget is reviewed.

### When the corpus is re-pinned

The snapshot keys every refusal by the SHA-256 of the certificate, and names the x509-limbo commit it was last verified at. `npx tsx scripts/build-refusals-frozen.ts --repin` moves it to a new pin. A refusal whose certificate the new corpus still holds is carried over, code and all. One whose certificate the new corpus dropped is **retired**: moved to the snapshot's `retired` list with the commit it was last verified at and an accepted ADR that records the re-pin (`--repin --adr docs/adr/NNNN-….md`; the generator refuses a retirement without one). A retired refusal is still promised; the gate verifies it only while a corpus holds its certificate. A certificate the new corpus refuses for the first time is new to the corpus, not new behaviour, and joins the snapshot without a `since`. A re-pin commit carries no engine change, so that the two cannot be confused.

### Phases, and the 1.x support policy

Like the other two snapshots, the refusal snapshot has a phase. In the **rehearsal** (0.9.x, `frozenAt` 0.9.0) no refusal may be added, lifted or recoded: 1.0.0 is the freeze itself and adds no engine behaviour. The 1.0.0 release commit rebases it to **stable** (`--major 1.0.0`, which `scripts/release-prepare.ts` runs and which is refused unless the rehearsal held), and every later 1.x release ratchets it (`--ratchet`), which records the new refusals the release ships and refuses to record a lifted or recoded one.

From 1.0.0 the **latest minor only** is supported: a security fix ships as a patch or minor of the newest 1.x line, and is not backported to older minors. This contract is what makes that bearable — moving from 1.y to the newest 1.z changes no export incompatibly, no error code, and no frozen refusal. Two facts decide it. There is one maintainer, and a backport line doubles every release, audit and gate run. And `.github/rulesets/main.json` protects only `~DEFAULT_BRANCH`: a maintenance branch would release without the required pull request and the seven required checks, which is a weaker release than the one it patches. Until the 1.0.0 bump, SECURITY.md §Supported Versions keeps the pre-1.0 table.

### Consequences

- Good, because a caller can rely on the code a certificate is refused with, and on a refused certificate staying refused, for the whole major line.
- Good, because a security fix that refuses more remains a minor release, as both fixes of 0.9 would have been.
- Good, because the whole promise is checked twice: offline by a rule that compares two committed files, online by the gate that compares the engine with the corpus.
- Good, because the machine-readable form — `docs/assets/ecosystem.json` → `contracts.compatibility` — names the snapshot, the rule and the record of each leg, and a rule holds the three to each other.
- Bad, because a refusal found wrong in 1.x stays until 2.0, and a fix that would change the code of an existing refusal waits for 2.0 too.
- Bad, because only the corpus is under the rule: a new refusal of a certificate outside x509-limbo is listed by hand, and the release audit is what checks it.
- Bad, because a caller who pins a path verdict, rather than a parse refusal, has to read the release notes: those verdicts may change in a minor.
- Bad, because an upstream regeneration of x509-limbo can retire a frozen refusal from verification. It stays promised, but nothing re-runs it until a corpus holds that certificate again.

### Confirmation

- `refusal-baseline-frozen` (`npm run verify:docs`) holds `scripts/data/limbo-refusals.json` to `docs/data/refusals.frozen.json`: in every phase a frozen refusal that is missing or carries another code fails, every code must be registered in `docs/data/errors.json`, and the snapshot's commit must be the baseline's; in the rehearsal a new refusal fails too; in the stable phase every refusal added by a release must be listed under `### Decision surface` in that release's note. The phase must agree with `package.json`.
- `scripts/validate-certs.ts` L1 reads the snapshot directly: every frozen or retired refusal whose certificate the corpus holds must be refused with its frozen code, whatever the baseline says — so regenerating the baseline cannot drop one silently. L2 holds the re-encoding identity.
- `scripts/build-refusals-frozen.ts` writes the snapshot only in the ways this record allows, and `scripts/release-prepare.ts` runs it at every release from 1.0.0; `tests/tools/refusals-frozen.test.ts` proves each refusal.
- `contracts-shape` holds `contracts.compatibility` in `docs/assets/ecosystem.json` to the three snapshots, to the rules that hold them, to the records, and to SECURITY.md §Compatibility promise, both ways.

## More Information

- [SECURITY.md §Compatibility promise](../../SECURITY.md) — the promise as a user reads it.
- `docs/data/refusals.frozen.json` — the snapshot and its `$comment`; `scripts/build-refusals-frozen.ts` — the only way it is written.
- [docs/guides/conformance.md §The levels](../guides/conformance.md#the-levels) — L1, L2 and L6 to L8.
- [ADR 0012](0012-frozen-error-vocabulary.md) and [ADR 0013](0013-renames-before-the-freeze.md) — the other two legs.
