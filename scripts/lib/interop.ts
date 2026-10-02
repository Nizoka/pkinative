/**
 * pkinative — the interoperability matrix's declared tools
 * ========================================================
 * The tools the matrix is *meant* to confront, including the ones not
 * written yet; which of them each platform must have; what each one is known
 * not to be able to read, and why; and the cases where a foreign tool writes
 * and pkinative reads. It lives here, apart from `scripts/run-interop.ts`, so
 * a verify-docs rule can read it without running the matrix.
 *
 * A gap that is written down is a gap someone can close. A matrix that
 * silently contains whatever happened to be installed on one laptop is a
 * matrix that looks complete and is not — which is why `interop-matrix-declared`
 * holds ROADMAP.md, the conformance guide and the workflow to these lists.
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
 * Declared and not yet implemented. A pending tool is reported on every run
 * and never fails one: what fails is a tool of `REQUIRED_TOOLS` that is
 * absent, under `--require-all`.
 */
export const PENDING_TOOLS: readonly PendingTool[] = Object.freeze([
    {
        id: 'windows-certutil',
        platform: 'win32',
        why: 'certutil -dump reads the artefacts correctly, but its output is TRANSLATED: on a French Windows it prints "Numéro de série", and a runner parsing "Serial Number" reported a perfectly good certificate as refused. Reaching CryptoAPI through the .NET API gives locale-independent values, which windows-cryptoapi already does; a second front end onto the same engine is worth adding only with a stable machine-readable output',
    },
    {
        id: 'macos-security',
        platform: 'darwin',
        why: 'the macOS Security framework is the only way to check what Apple platforms accept; it needs a program written against SecCertificate/SecTrust and proved on a macOS machine, and the development machine is not one — conformance-macos would run it, unproved, which is how a matrix starts lying',
    },
    {
        // `dotnet` is implemented and proved on Windows only (TOOL_PLATFORMS);
        // these two entries are the rest of its platforms, declared so the gap
        // is held by interop-matrix-declared instead of a code comment.
        id: 'dotnet-linux',
        platform: 'linux',
        why: '.NET runs on Linux, but scripts/validators/dotnet.ps1 has been run and proved on Windows only, where X509Chain and SignedCms sit on CryptoAPI; on Linux the same API sits on OpenSSL, so it would be a second front end onto a lineage the matrix already runs, and it is not run unproved',
    },
    {
        id: 'dotnet-macos',
        platform: 'darwin',
        why: '.NET on macOS reaches the Apple Security framework, which would be a lineage the matrix does not have yet, but scripts/validators/dotnet.ps1 has never been run on a macOS machine and the development machine is not one — it is not run unproved, the same reason macos-security waits',
    },
]);

/** The tools the matrix runs today. Kept here so the rule can compare both halves. */
export const IMPLEMENTED_TOOLS: readonly string[] = Object.freeze([
    'openssl',
    'windows-cryptoapi',
    'gnutls-certtool',
    'java-keytool',
    'python-cryptography',
    'go-x509',
    'dotnet',
    'gpgsm',
    'zlint',
    'pkilint',
]);

/**
 * What each platform of the conformance workflow must have. Under
 * `--require-all` — which the workflow and the release gate pass — a tool of
 * this list that is absent fails the run instead of being skipped. Every
 * other implemented tool runs wherever it is found (a Windows workstation
 * reaches the Linux ones through WSL) and is held to the same agreement when
 * it does.
 *
 * Linux carries the most because the workflow installs it: GnuTLS and gpgsm
 * from the distribution, Go from a pinned setup-go, zlint at a pinned module
 * version, pyca/cryptography and pkilint from a hash-pinned requirements file;
 * the JDK behind `java-keytool` is the one the ubuntu image carries. Every
 * tool the Linux runner has is required there, so none of them can disappear
 * into a skip. Windows needs nothing installed. macOS has only its system
 * `openssl`, which is not the reference build and is held to reading, not to
 * agreement on refusals.
 */
export const REQUIRED_TOOLS: Readonly<Record<'linux' | 'win32' | 'darwin', readonly string[]>> = Object.freeze({
    linux: ['openssl', 'gnutls-certtool', 'gpgsm', 'java-keytool', 'python-cryptography', 'go-x509', 'zlint', 'pkilint'],
    win32: ['openssl', 'windows-cryptoapi', 'dotnet'],
    darwin: ['openssl'],
});

/**
 * Where each implemented tool may run: the platforms its driver has been run
 * and proved on. A tool is never run, unproved, where nobody has seen it
 * answer — that is how a matrix starts lying — and the report says so
 * instead. win32 includes the tools a Windows workstation reaches through WSL
 * (scripts/lib/interop-host.ts); the GitHub Windows runner has no
 * distribution, so there they are simply absent.
 */
export const TOOL_PLATFORMS: Readonly<Record<string, readonly string[]>> = Object.freeze({
    openssl: ['linux', 'win32', 'darwin'],
    'windows-cryptoapi': ['win32'],
    dotnet: ['win32'],
    'gnutls-certtool': ['linux', 'win32'],
    'java-keytool': ['linux', 'win32'],
    'python-cryptography': ['linux', 'win32'],
    'go-x509': ['linux', 'win32'],
    gpgsm: ['linux', 'win32'],
    zlint: ['linux', 'win32'],
    pkilint: ['linux', 'win32'],
});

// ── What a foreign tool is known not to read ─────────────────────────

/**
 * A reviewed limitation of a foreign tool: a check it cannot pass for a
 * reason that is the tool's, not pkinative's. Each one was proved the same
 * way — the same check fails identically on a control built by OpenSSL from
 * the same keys — and the proof is written beside it.
 *
 * `match` lists `<check>@<artefact id>` patterns (`*` matches anything;
 * a lint is `lint:<lint id>@<artefact id>`). `always` limitations are
 * evaluated anyway, and one that starts to pass fails the run as stale: a
 * limitation nobody needs any more hides the next real failure. A
 * `self-declared` one applies only when the tool itself answers `unsupported`
 * for the reason given (a JDK reporting it has no EdDSA).
 */
export interface ToolLimitation {
    readonly tool: string;
    readonly match: readonly string[];
    readonly when: 'always' | 'self-declared';
    readonly reason: string;
    readonly proof: string;
}

export const TOOL_LIMITATIONS: readonly ToolLimitation[] = Object.freeze([
    {
        tool: 'dotnet',
        // The frozen samples (`sample/…`) are Ed25519 too.
        match: ['chain.verify@ed25519/*', 'csr.verify@ed25519/*', 'csr.pem@ed25519/*', 'cms.verify@ed25519/*', 'chain.verify@sample/*', 'csr.verify@sample/*', 'csr.pem@sample/*'],
        when: 'always',
        reason: '.NET has no Ed25519: X509Chain reports "an unknown chain building error", CertificateRequest "1.3.101.112 is not a known key algorithm" and SignedCms "Unknown algorithm" — reading the certificate works, verifying anything it signs does not',
        proof: 'an Ed25519 certificate made by OpenSSL 4.0 fails X509Chain.Build the same way on .NET 10.0.12 (pre-publication audit of 1.0.0, auditor W)',
    },
    {
        tool: 'java-keytool',
        match: ['*@ed25519/*', '*@sample/*'],
        when: 'self-declared',
        reason: 'a JDK before 15 has no EdDSA (JEP 339); the reader reports it after failing to get a KeyFactory for Ed25519, and every JDK on the GitHub runners is 17 or later',
        proof: 'KeyFactory.getInstance("Ed25519") throws NoSuchAlgorithmException on JDK 13.0.1',
    },
    {
        tool: 'python-cryptography',
        match: ['cms.certificates@*/cms-ski'],
        when: 'always',
        reason: 'pyca/cryptography reads PKCS #7 version 1 SignedData only; a SignerInfo identified by subject key identifier makes the structure CMS version 3 (RFC 5652 §5.1), which its loader refuses with "Unable to parse PKCS7 data"',
        proof: 'openssl cms -sign -keyid output fails pkcs7.load_der_pkcs7_certificates identically with cryptography 50.0.1 (auditor W)',
    },
    {
        tool: 'gpgsm',
        match: ['cms.verify@*/cms-ski'],
        when: 'always',
        reason: 'libksba 1.6 cannot parse a SignerInfo whose sid is the [0] subjectKeyIdentifier choice: "ksba: ber-decoder: TLV length too large"',
        proof: 'openssl cms -sign -keyid output fails gpgsm --verify identically with gpgsm 2.4.8 / libksba 1.6.7 (auditor W)',
    },
    {
        tool: 'gpgsm',
        match: ['cms.verify@ed25519/*'],
        when: 'always',
        reason: 'gpgsm 2.4 verifies an Ed25519 CMS signature as if it were DSA over a digest and fails with "DSA requires the hash length to be a multiple of 8 bits"',
        proof: 'an Ed25519 SignedData made by openssl cms -sign fails gpgsm --verify identically (auditor W)',
    },
    {
        tool: 'pkilint',
        match: ['lint:pkix.signature_verification_failed@pss-*/leaf-*'],
        when: 'always',
        reason: 'pkilint\'s SubjectSignatureVerificationValidator cannot verify an RSASSA-PSS signature over the tbsCertificate — it reports pkix.signature_verification_failed for every RSASSA-PSS chain, whoever wrote it, while OpenSSL, GnuTLS, Go, pyca, .NET and the JDK all verify the same chain',
        proof: 'an RSASSA-PSS leaf issued by OpenSSL from the same keys fails lint_pkix_signer_signee_cert_chain identically with pkilint 0.13.3 (auditor W)',
    },
    {
        tool: 'zlint',
        match: ['lint:e_subject_dn_not_printable_characters@*/leaf-rich'],
        when: 'always',
        reason: 'zlint\'s e_subject_dn_not_printable_characters scans the raw octets of every subject attribute for control characters, and a BMPString is UTF-16: every character below U+0100 has a 0x00 octet. The lint fires on any BMPString, ASCII included, which RFC 5280 Appendix A allows in DirectoryString',
        proof: 'otherwise identical certificates whose O is the ASCII BMPString "Plain Org", the BMPString "Société Ωmega" and the UTF8String "Société Ωmega": the first two fail the lint, the third passes it, with zlint v3.7.2 (auditor W)',
    },
]);

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

// ── The read direction: signed structures ────────────────────────────

/**
 * A signed structure a foreign tool writes and pkinative verifies — CMS,
 * RFC 3161 tokens, OCSP responses, CRLs — with the verdict it must reach.
 * The same discipline as the key containers: every case is declared here,
 * described in the conformance guide, and the runner refuses one that is not.
 */
export interface ReadCase {
    /** `<tool>:<case>`. */
    readonly id: string;
    readonly tool: string;
    readonly writes: string;
    /** What pkinative must decide. */
    readonly expect: string;
}

export const READ_CASES: readonly ReadCase[] = Object.freeze([
    { id: 'openssl:cms-rsa', tool: 'openssl', writes: 'openssl cms -sign -nodetach, RSA 2048 PKCS #1 v1.5', expect: 'verifySignedData valid' },
    { id: 'openssl:cms-rsa-pss', tool: 'openssl', writes: 'openssl cms -sign -keyopt rsa_padding_mode:pss, detached', expect: 'verifySignedData valid' },
    { id: 'openssl:cms-ecdsa', tool: 'openssl', writes: 'openssl cms -sign -nodetach -md sha384, ECDSA P-384', expect: 'verifySignedData valid' },
    { id: 'openssl:cms-ed25519', tool: 'openssl', writes: 'openssl cms -sign -md sha512, Ed25519, detached', expect: 'verifySignedData valid' },
    { id: 'openssl:cms-ber-stream', tool: 'openssl', writes: 'openssl cms -sign -stream -nodetach: indefinite-length BER', expect: 'refused under the default DER rules with a message naming encodingRules: \'ber\'; valid under them' },
    { id: 'openssl:cms-tampered', tool: 'openssl', writes: 'openssl cms -sign -nodetach, one content octet changed afterwards', expect: 'not valid: PKI_REASON_CMS_DIGEST_MISMATCH' },
    { id: 'openssl:tsp-reply', tool: 'openssl', writes: 'openssl ts -reply to an openssl ts -query -cert, RSA TSA with a critical timeStamping EKU', expect: 'verifyTimeStampToken valid against the request and the data; PKI_REASON_TSP_IMPRINT_MISMATCH against other data' },
    { id: 'openssl:ocsp-good', tool: 'openssl', writes: 'openssl ocsp -index, signed by a delegated responder (id-kp-OCSPSigning, ocspNoCheck)', expect: 'verifyCertificateChain valid with requireRevocation' },
    { id: 'openssl:ocsp-revoked', tool: 'openssl', writes: 'openssl ocsp -index after openssl ca -revoke -crl_reason keyCompromise', expect: 'verifyCertificateChain: PKI_REASON_REVOKED' },
    { id: 'openssl:crl-base', tool: 'openssl', writes: 'openssl ca -gencrl after one revocation (keyCompromise)', expect: 'the revoked certificate PKI_REASON_REVOKED, the other valid with requireRevocation' },
    { id: 'openssl:crl-delta', tool: 'openssl', writes: 'openssl crl -gendelta -sha256 between that CRL and the next, after a second revocation', expect: 'with the base CRL, the certificate revoked after it is PKI_REASON_REVOKED' },
    { id: 'gnutls-certtool:crl', tool: 'gnutls-certtool', writes: 'certtool --generate-crl over a CA and a certificate it issued', expect: 'the listed certificate PKI_REASON_REVOKED, the other valid with requireRevocation' },
    { id: 'gpgsm:cms-detached', tool: 'gpgsm', writes: 'gpgsm --detach-sign with a key imported from PKCS #12', expect: 'verifySignedData valid' },
    { id: 'gpgsm:cms-attached', tool: 'gpgsm', writes: 'gpgsm --sign: indefinite-length BER', expect: 'verifySignedData valid with encodingRules: \'ber\'' },
    { id: 'dotnet:cms-rsa', tool: 'dotnet', writes: 'SignedCms.ComputeSignature, RSA PKCS #1 v1.5, detached, IssuerAndSerialNumber', expect: 'verifySignedData valid' },
    { id: 'dotnet:cms-rsa-ski', tool: 'dotnet', writes: 'SignedCms.ComputeSignature, RSA, attached, SubjectKeyIdentifier, SHA-512', expect: 'verifySignedData valid' },
    { id: 'dotnet:cms-rsa-pss', tool: 'dotnet', writes: 'SignedCms.ComputeSignature with RSASignaturePadding.Pss', expect: 'verifySignedData valid' },
    { id: 'dotnet:cms-ecdsa', tool: 'dotnet', writes: 'SignedCms.ComputeSignature, ECDSA P-256', expect: 'verifySignedData valid' },
]);
