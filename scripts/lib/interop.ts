/**
 * pkinative — the interoperability matrix's declared tools
 * ========================================================
 * The tools the write direction is *meant* to confront, including the ones
 * not written yet. It lives here, apart from `scripts/run-interop.ts`, so a
 * verify-docs rule can read it without running the matrix.
 *
 * A gap that is written down is a gap someone can close. A matrix that
 * silently contains whatever happened to be installed on one laptop is a
 * matrix that looks complete and is not — which is why `interop-matrix-declared`
 * holds ROADMAP.md to this list in both directions.
 *
 * @module scripts/lib/interop
 */

export interface PendingTool {
    readonly id: string;
    /** `'all'`, or a `process.platform` value where the tool exists. */
    readonly platform: string;
    /** Why it is not implemented, in enough detail to act on. */
    readonly why: string;
}

/**
 * Declared and not yet implemented.
 *
 * `--require-all` turns each of these into a failure, which is why the
 * conformance workflow does not pass it yet: it goes on in the commit that
 * lands the last entry, and the list is empty from then on.
 */
export const PENDING_TOOLS: readonly PendingTool[] = Object.freeze([
    {
        id: 'windows-certutil',
        platform: 'win32',
        why: 'certutil -dump reads the artefacts correctly, but its output is TRANSLATED: on a French Windows it prints "Numéro de série", and a runner parsing "Serial Number" reported a perfectly good certificate as refused. Reaching CryptoAPI through the .NET API gives locale-independent values, which windows-cryptoapi already does; a second front end onto the same engine is worth adding only with a stable machine-readable output',
    },
    {
        id: 'gnutls-certtool',
        platform: 'linux',
        why: 'GnuTLS is the second-most-deployed TLS stack and shares no code with OpenSSL; not installed on the development machine, so it would ship unrun',
    },
    {
        id: 'java-keytool',
        platform: 'all',
        why: 'the JDK reads certificates through a lineage no C implementation here shares, and is what every Java service will use to read what pkinative writes; no JDK on the development machine',
    },
    {
        id: 'macos-security',
        platform: 'darwin',
        why: 'the macOS Security framework is the only way to check what Apple platforms accept; needs a macOS runner, which conformance-macos provides and the development machine does not',
    },
    {
        id: 'python-cryptography',
        platform: 'all',
        why: 'the most widely used PKI library in the Python ecosystem, and the one most downstream tools embed; needs a Python with `cryptography` installed',
    },
]);

/** The tools the matrix runs today. Kept here so the rule can compare both halves. */
export const IMPLEMENTED_TOOLS: readonly string[] = Object.freeze(['openssl', 'windows-cryptoapi']);
