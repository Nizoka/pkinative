---
name: Bug Report
about: Report a bug in pkinative
title: ''
labels: bug
assignees: ''
---

<!-- Security problems (a bypass, a crash on hostile input, a resource exhaustion)
     are NOT reported here: follow SECURITY.md. -->

## Description

<!-- A clear description of the bug. -->

## Steps to Reproduce

1. 
2. 
3. 

## Expected Behavior

<!-- What should happen? -->

## Actual Behavior

<!-- What happens instead? Include `err.code` and the message when an error is thrown. -->

## Environment

- **pkinative version:** 
- **Runtime:** <!-- Node.js 22, Chrome 128, Deno 2.x, Bun 1.x, Cloudflare Workers, etc. -->
- **OS:** 

## Minimal Reproduction

```typescript
// Smallest code snippet that demonstrates the issue.
// Attach public certificates only (PEM or base64 DER) — never a private key.
```

## Additional Context

<!-- `openssl x509 -noout -text` output, the producer of the certificate, etc. -->
