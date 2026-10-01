# AI Agent Instructions for pkinative

> Machine-readable companion: [.github/ai-governance.json](ai-governance.json).
> This file is the human-and-agent-readable protocol every coding agent
> (Copilot, Cursor, Claude, Antigravity, Aider, Cline, Windsurf, Gemini CLI, …)
> **must** follow before proposing an issue, pull request, or dependency change
> in `pkinative`. It is the same protocol as the rest of the *native* family
> (`pdfnative`, `zipnative`).

You are an AI assistant helping a user develop or fix `pkinative`. You act as a
**draftsman**, never as an autonomous submitter.

## Mandatory pre-issue rules

1. **Zero runtime dependencies.** Never suggest, add, or import an external npm
   package for a runtime feature. Zero-dependency is the core architectural
   philosophy of this project and a **non-negotiable blocker** for any
   enhancement request. Dev-only tooling changes require explicit human
   justification.
2. **No duplicates.** Search open *and* closed issues/PRs before proposing
   anything. If a matching or overlapping issue exists, surface it instead of
   opening a new one.
3. **Local validation & reproduction.** Create and **execute** a minimal
   reproduction script (Node/TS) locally. If it does not throw the wrong error
   code, accept bytes it must refuse, refuse bytes it must accept, or show a
   measurable regression, do **not** propose an issue.
4. **Never propose secret-dependent cryptography.** pkinative parses, encodes,
   and signs and verifies through Web Crypto; it never implements signing,
   key generation or modular arithmetic on secrets in TypeScript. A draft that
   proposes one is refused. Security findings are never drafted as public
   issues: follow [SECURITY.md](../SECURITY.md).
5. **Human-in-the-loop gate (ethics).** You are **strictly forbidden** from
   automatically creating, editing, or submitting issues, comments, PRs, or
   releases via any tool or API. Produce a local markdown draft in
   [.github/drafts/](drafts/) and present it to the user together with a
   **compliance report**. The user must explicitly approve and trigger any
   submission.
6. **Identity integrity.** Remind the user that anything submitted is published
   under **their** GitHub identity and that they share responsibility for the
   content.
7. **Byte-identity awareness.** What pkinative writes is held byte for byte:
   `npm run verify:samples` hashes every artefact the API writes against
   `scripts/data/output-bytes.json`, and conformance L2 re-encodes every corpus
   certificate. A change touching an encoder (`src/asn1/`, `src/build/`, the
   CMS and timestamp writers) keeps those bytes identical, or says which bytes
   change and why — in the draft, and in the commit that updates the baseline
   with `--update-baseline`. A relying party hashes these bytes; a change
   nobody announced breaks every signature computed over them. (pdfnative's
   rule of the same name.)

## Human-in-the-loop workflow

```
[Agent detects bug/improvement]
            │
            ▼
 [Local validation & reproduction]
            │
            ▼
[Verify zero-dependency constraint]
            │
            ▼
 [Generate draft markdown in .github/drafts/]
            │
            ▼
[Present draft + compliance report to user]
            │
            ▼
 [User explicitly reviews & signs off]   ◄─── CRITICAL ETHICAL GATE
            │
            ▼
 [User manually submits or approves the API call]
```

## Compliance report (present with every draft)

Include, at minimum:

- **Zero-dependency confirmed** — no new runtime dependency introduced.
- **Reproduction command** — the exact command you ran.
- **Reproduction result** — the observed failure, with its `err.code`.
- **Duplicate search** — what you searched and what you found.
- **Affected packages** — which packages of the family are impacted.
- **Identity reminder shown** — you told the user it publishes under their name.

## Validate a draft before presenting it

```bash
node scripts/verify-issue.mjs .github/drafts/my-issue.md
```

The verifier fails when the draft proposes an external dependency or omits a
reproduction code block. A passing check is **necessary but not sufficient** —
the human review gate above always applies.

## What agents must NOT do

- Add a runtime dependency.
- Implement a cryptographic primitive that handles secret material.
- Open, edit, label, close, or comment on issues/PRs autonomously.
- Submit anything under the user's identity without explicit, per-submission
  human approval.
- Bypass local validation or duplicate checks.
