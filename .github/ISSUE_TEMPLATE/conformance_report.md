---
name: Conformance report
about: A certificate or DER encoding that pkinative accepts but must refuse, or refuses but must accept
title: '[conformance] '
labels: conformance
assignees: ''
---

<!-- If accepting the input could let an attacker bypass a security decision,
     do NOT file it here: follow SECURITY.md. -->

## Direction

- [ ] pkinative **accepts** an input the standard forbids
- [ ] pkinative **refuses** an input the standard allows
- [ ] pkinative decodes a field **differently** from another implementation

## The clause

The standard and the section that decides the case (e.g. `ITU-T X.690 §10.1`,
`RFC 5280 §4.1.2.5`, `RFC 7468 §3`):

## Evidence

- pkinative code + output (`err.code` or the decoded field):
- The other implementation, with its **exact version** (e.g. `OpenSSL 3.4.0`, `Go 1.24 crypto/x509`):
- The input, as PEM or base64 DER (public material only):

## Producer

If the certificate came from a real-world issuer or tool, name it — the
conformance corpus grows from these reports.
