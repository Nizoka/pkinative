# Support

Thanks for using **pkinative**! Here is where to get help depending on what you need.

## :books: Documentation

- **Quick start & API overview:** [README.md](./README.md)
- **In-depth guides:** [`docs/guides/`](./docs/guides/) (quick start, use cases, security model, conformance, error codes, choosing a library)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)
- **Roadmap:** [ROADMAP.md](./ROADMAP.md)

## :question: Questions, bugs & feature requests

- **GitHub Issues** — [github.com/Nizoka/pkinative/issues](https://github.com/Nizoka/pkinative/issues) — the one public channel.
  Use it for how-to questions too: most of them are a documentation gap, and an issue is where that gets fixed.
  Before opening an issue, please:
  1. Search existing issues — it may already be reported or resolved.
  2. Reproduce on the latest release on npm.
  3. Include a **minimal reproduction** (code + inputs) and the **exact error code** (`err.code`) or the expected vs actual output.
  4. Attach the certificate or DER blob when relevant — **never a private key**. Public certificates only; redact anything confidential.

Templates are provided for bug reports, feature requests and conformance reports.

## :lock: Security vulnerabilities

**Do not open public issues for security problems.**

See [SECURITY.md](./SECURITY.md) for the private disclosure procedure (GitHub Security Advisories).
We acknowledge reports within 48 hours and target a fix within 7 days for Critical severity and within 14 days for High severity.

## :handshake: Contributing

Interested in contributing? Start with [CONTRIBUTING.md](./CONTRIBUTING.md) and our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## :warning: What is *not* supported

- **Private email support** — we do not offer one-on-one support; please use the public issue tracker above so the whole community benefits.
- **Commercial SLAs** — pkinative is MIT-licensed open source with no warranty. Consider sponsoring or contributing patches if you rely on it heavily.
- **Legacy Node versions** — only Node.js **22 LTS** and **24** are tested in CI (with Deno, Bun and headless Chromium smoke tests). Node.js below 22 is outside `engines` and is not supported.

## :sparkles: Sponsor

If pkinative saves you time or money, consider starring the repo or
[sponsoring via GitHub Sponsors](https://github.com/sponsors/Nizoka). Every bit helps
keep development sustainable.
