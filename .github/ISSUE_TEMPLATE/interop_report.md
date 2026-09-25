---
name: Interoperability report
about: A certificate or request pkinative WROTE that another tool will not read, or reads differently
title: '[interop] '
labels: interop
assignees: ''
---

<!-- This template is for the WRITE direction: bytes pkinative produced that
     something else cannot consume. If the problem is a certificate pkinative
     cannot READ, use the Conformance report instead — the two have different
     burdens of proof, and the difference matters. When another tool refuses
     what pkinative wrote, the bytes are ours and the defect is presumed ours
     until shown otherwise. -->

## The tool that disagrees

| | |
|---|---|
| Tool and version | <!-- `openssl version`, `keytool -help`, `python -c "import cryptography; print(cryptography.__version__)"` … --> |
| Operating system | |
| How it was invoked | <!-- the exact command, so anyone can repeat it --> |

## What pkinative wrote

The code that produced it, short enough to run as-is:

```ts
import { createCertificate } from 'pkinative';
// …
```

pkinative version, and how it was installed (the release tarball, a git
checkout, a local build):

## What happened

- [ ] The tool **refused** the artefact outright
- [ ] The tool accepted it and read a field **differently** from pkinative
- [ ] The tool accepted it and another tool refused it

The tool's own output, verbatim:

```
```

## What the standard says

The clause that decides it (`RFC 5280 §4.2.1.6`, `ITU-T X.690 §11.6`, …), and
the sentence itself. A disagreement between two implementations is not
settled by either of them:

## Does pkinative read it back?

Parsing what pkinative wrote is the first thing to try, because a builder
whose own reader complains has written something someone else's reader will
refuse too:

```ts
const cert = parseCertificate(der, { onDiagnostic: (d) => console.log(d.code, d.path, d.standard) });
```

- [ ] pkinative reads it back with **no diagnostic**
- [ ] pkinative reads it back and reports: <!-- the codes -->
- [ ] pkinative refuses its own output <!-- always a bug, say so plainly -->

## The artefact

Attach the DER (or paste the PEM). **Do not attach anything containing a
private key**, even a test one: re-create the case with a key generated for
the report.
