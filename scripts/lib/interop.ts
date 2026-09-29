/**
 * pkinative — the interoperability matrix's declared tools
 * ========================================================
 * The tools the matrix is *meant* to confront, including the ones not
 * written yet, and the key containers the implemented ones write for
 * pkinative to read. It lives here, apart from `scripts/run-interop.ts`, so a
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

// ── The read direction: key containers ──────────────────────────────

/**
 * One kind of key container a foreign tool writes and pkinative must read.
 *
 * pkinative never writes a PKCS#8 or a PKCS#12 — it may not encrypt or wrap a
 * key, by policy — so for key containers the arrow points the other way: the
 * foreign tool writes, pkinative reads, and what is compared is what the tool
 * says it wrote, what pkinative says it read, and whether the key it hands
 * back signs data the certificate's public key verifies.
 */
export interface KeyContainerCase {
    /** `<tool>:<case>`, the spelling the conformance guide uses. */
    readonly id: string;
    /** The implemented tool that writes it. */
    readonly tool: string;
    /** The command or API call that writes it. */
    readonly writes: string;
    /** What pkinative must make of it. */
    readonly expect: string;
}

/**
 * Every key-container case the matrix runs. `run-interop` refuses to evaluate
 * a case that is not listed here, and `interop-matrix-declared` holds the list
 * to the conformance guide in both directions.
 */
export const KEY_CONTAINER_CASES: readonly KeyContainerCase[] = Object.freeze([
    { id: 'openssl:pkcs12-pbmac1', tool: 'openssl', writes: 'openssl pkcs12 -export -pbmac1_pbkdf2 (EC P-256, RSA 2048, Ed25519)', expect: 'valid, integrity verified, the key signs, the certificate byte-identical' },
    { id: 'openssl:pkcs12-default', tool: 'openssl', writes: 'openssl pkcs12 -export (EC P-256, RSA 2048, Ed25519)', expect: 'what the tool says it wrote decides: under PBES2, integrity unverified and valid with allowUnverifiedIntegrity; under the legacy schemes, as openssl:pkcs12-legacy' },
    { id: 'openssl:pkcs12-legacy', tool: 'openssl', writes: 'openssl pkcs12 -export -legacy, with the legacy provider', expect: 'reported, never thrown: PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED naming each refused scheme' },
    { id: 'openssl:pkcs12-wrong-password', tool: 'openssl', writes: 'openssl pkcs12 -export -pbmac1_pbkdf2, read with another password', expect: 'PKI_REASON_PKCS12_MAC_MISMATCH, nothing decrypted' },
    { id: 'openssl:pkcs12-converted', tool: 'openssl', writes: 'the conversion SECURITY.md documents: pkcs12 -in legacy.p12 -legacy -out bundle.pem, then pkcs12 -export -in bundle.pem -pbmac1_pbkdf2', expect: 'valid, integrity verified, the key signs' },
    { id: 'openssl:pkcs8-pbes2', tool: 'openssl', writes: 'openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 (EC P-256, RSA 2048, Ed25519)', expect: 'decryptPrivateKey returns a key that signs' },
    { id: 'openssl:pkcs8-pbes1', tool: 'openssl', writes: 'openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES', expect: 'decryptPrivateKey throws PKI_KEY_ENCRYPTION_UNSUPPORTED naming the scheme' },
    { id: 'windows-cryptoapi:pfx-export', tool: 'windows-cryptoapi', writes: 'X509Certificate2.Export(X509ContentType.Pkcs12, password) from Windows PowerShell, .NET Framework over CryptoAPI (EC P-256, RSA 2048)', expect: 'reported, never thrown: the 3DES contents and key named, integrity unverified' },
    { id: 'windows-cryptoapi:pfx-pbes2', tool: 'windows-cryptoapi', writes: 'X509Certificate2.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password) from PowerShell 7 on .NET 9 or later (EC P-256, RSA 2048)', expect: 'integrity unverified (Appendix B MAC); valid with allowUnverifiedIntegrity, the key signs' },
]);
