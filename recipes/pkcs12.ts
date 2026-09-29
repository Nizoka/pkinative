/**
 * Recipe: open a PKCS#12 file (`.p12`, `.pfx`) — in one call, then with the
 * primitives underneath — and read the files pkinative describes but will
 * not open.
 *
 * `openPkcs12` is the call most code wants: a password in, the signing key
 * and its certificate out, and a report that says what could not be opened
 * instead of an exception about the first thing. Three rules shape it.
 * **A key never exists in plaintext here**: Web Crypto unwraps it straight
 * into a non-extractable `CryptoKey`. **Its algorithm comes from its
 * certificate**, because the host must be told what a key is before it
 * decrypts it. **Integrity fails closed**: most files carry a MAC keyed with
 * RFC 7292 Appendix B, which pkinative never computes, and such a file is
 * read but not `valid` unless you say `allowUnverifiedIntegrity`.
 *
 * The file is written here, by a small local writer, the way OpenSSL 3.4+
 * writes one with `-pbmac1_pbkdf2`: the certificates in a PBES2-encrypted
 * SafeContents, the key in a PBES2-shrouded bag, an RFC 9579 PBMAC1 MAC over
 * the lot. Every cipher and MAC in the writer is the host's Web Crypto in
 * the caller's code; pkinative only reads.
 */
import {
    canDecrypt,
    canSign,
    createCertificate,
    createSignedData,
    decryptPrivateKey,
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeBasicConstraints,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeKeyUsage,
    encodeNull,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeSet,
    encodeString,
    formatDistinguishedName,
    openSafeContents,
    parseCertificate,
    parsePkcs12,
    parseSignedData,
    PkiKeyError,
    openPkcs12,
    verifyPkcs12Mac,
    verifySignerInfoSignature,
    type Pkcs12,
    type PkiDiagnostic,
    type PkiKeyErrorCode,
    type OpenPkcs12Options,
    type OpenPkcs12Report,
    type SafeBag,
    type SafeContentsInfo,
    type SigningKey,
} from 'pkinative';

const PASSWORD = 'correct horse battery staple';
const NOW = Date.UTC(2026, 0, 15);
const DAY = 86_400_000;

const OID = {
    data: '1.2.840.113549.1.7.1',
    encryptedData: '1.2.840.113549.1.7.6',
    pbes2: '1.2.840.113549.1.5.13',
    pbkdf2: '1.2.840.113549.1.5.12',
    pbmac1: '1.2.840.113549.1.5.14',
    hmacWithSHA256: '1.2.840.113549.2.9',
    aes256Cbc: '2.16.840.1.101.3.4.1.42',
    sha256: '2.16.840.1.101.3.4.2.1',
    shroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
    certBag: '1.2.840.113549.1.12.10.1.3',
    x509Certificate: '1.2.840.113549.1.9.22.1',
    friendlyName: '1.2.840.113549.1.9.20',
    localKeyId: '1.2.840.113549.1.9.21',
    // Two RFC 7292 Appendix C schemes — what OpenSSL wrote by default before 3.0.
    pbeWithSHAAnd3KeyTripleDES: '1.2.840.113549.1.12.1.3',
    pbeWithSHAAnd40BitRC2: '1.2.840.113549.1.12.1.6',
};

/** What the host says of a key: pkinative types the handle opaquely, and the runtime's CryptoKey answers. */
const handle = (signer: SigningKey): string => {
    const key = signer.key as unknown as { readonly extractable: boolean; readonly usages: readonly string[] };
    return `extractable=${String(key.extractable)} usages=${key.usages.join(',')}`;
};
const codes = (report: OpenPkcs12Report): string => report.reasons.map((reason) => `${reason.code}@${reason.path}`).join(' ') || 'none';

// ── A small PKCS#12 writer (RFC 7292, RFC 8018, RFC 9579) ──

const seq = (...children: Uint8Array[]): Uint8Array => encodeSequence(children);
const oid = encodeObjectIdentifier;
const contentInfo = (type: string, content: Uint8Array): Uint8Array => seq(oid(type), encodeExplicit(0, content));
const random = (length: number): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
const passwordKey = () =>
    crypto.subtle.importKey('raw', new TextEncoder().encode(PASSWORD), 'PBKDF2', false, ['deriveKey']);

/** PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC: the AlgorithmIdentifier and the ciphertext. */
async function pbes2(plaintext: Uint8Array, iterations: number): Promise<{ algorithm: Uint8Array; ciphertext: Uint8Array }> {
    const salt = random(16);
    const iv = random(16);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, await passwordKey(),
        { name: 'AES-CBC', length: 256 }, false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, plaintext));
    const algorithm = encodeAlgorithmIdentifier(OID.pbes2, seq(
        encodeAlgorithmIdentifier(OID.pbkdf2, seq(encodeOctetString(salt), encodeInteger(iterations), encodeAlgorithmIdentifier(OID.hmacWithSHA256, encodeNull()))),
        encodeAlgorithmIdentifier(OID.aes256Cbc, encodeOctetString(iv)),
    ));
    return { algorithm, ciphertext };
}

/** An RFC 7292 Appendix C AlgorithmIdentifier — salt and iterations — over random bytes nothing here could encrypt. */
const legacyScheme = (schemeOid: string): { algorithm: Uint8Array; ciphertext: Uint8Array } =>
    ({ algorithm: encodeAlgorithmIdentifier(schemeOid, seq(encodeOctetString(random(8)), encodeInteger(2048))), ciphertext: random(64) });

/** RFC 9579 PBMAC1: HMAC-SHA-256 over the AuthenticatedSafe, keyed with PBKDF2. */
async function pbmac1(authSafe: Uint8Array, iterations: number): Promise<Uint8Array> {
    const salt = random(16);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, await passwordKey(),
        { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, authSafe));
    const algorithm = encodeAlgorithmIdentifier(OID.pbmac1, seq(
        encodeAlgorithmIdentifier(OID.pbkdf2, seq(encodeOctetString(salt), encodeInteger(iterations), encodeInteger(32), encodeAlgorithmIdentifier(OID.hmacWithSHA256, encodeNull()))),
        encodeAlgorithmIdentifier(OID.hmacWithSHA256, encodeNull()),
    ));
    // Under PBMAC1, RFC 9579 has the verifier ignore macSalt and iterations.
    return seq(seq(algorithm, encodeOctetString(mac)), encodeOctetString(new TextEncoder().encode('NOT USED')), encodeInteger(iterations));
}

/** A MacData shaped like the RFC 7292 Appendix B MAC OpenSSL writes by default. pkinative never computes one, so it cannot tell these random octets from a genuine MAC. */
const appendixBMac = (): Uint8Array =>
    seq(seq(encodeAlgorithmIdentifier(OID.sha256, encodeNull()), encodeOctetString(random(32))), encodeOctetString(random(8)), encodeInteger(2048));

interface Material { readonly pkcs8: Uint8Array; readonly certificate: Uint8Array }

/**
 * A PFX: the certificate in an encrypted SafeContents, the key in a shrouded
 * bag, the two tied by `localKeyId`. `scheme` chooses how both are encrypted;
 * `mac` how the whole is authenticated.
 */
async function writePfx(material: Material, options: { scheme: 'pbes2' | 'legacy'; mac: 'pbmac1' | 'appendix-b'; iterations?: number }): Promise<Uint8Array> {
    const iterations = options.iterations ?? 2048;
    // bagAttributes is a SET OF, written here in the order DER sorts it: the shorter encoding first.
    const attributes = encodeSet([
        encodeAttribute(OID.localKeyId, [encodeOctetString(Uint8Array.of(1))]),
        encodeAttribute(OID.friendlyName, [encodeString('bmp', 'signing key')]),
    ]);
    const certBag = seq(oid(OID.certBag), encodeExplicit(0, seq(oid(OID.x509Certificate), encodeExplicit(0, encodeOctetString(material.certificate)))), attributes);
    const certs = options.scheme === 'pbes2' ? await pbes2(seq(certBag), iterations) : legacyScheme(OID.pbeWithSHAAnd40BitRC2);
    const key = options.scheme === 'pbes2' ? await pbes2(material.pkcs8, iterations) : legacyScheme(OID.pbeWithSHAAnd3KeyTripleDES);
    const keyBag = seq(oid(OID.shroudedKeyBag), encodeExplicit(0, seq(key.algorithm, encodeOctetString(key.ciphertext))), attributes);

    const authSafe = seq(
        contentInfo(OID.encryptedData, seq(encodeInteger(0), seq(oid(OID.data), certs.algorithm, encodeImplicit(0, encodeOctetString(certs.ciphertext))))),
        contentInfo(OID.data, encodeOctetString(seq(keyBag))),
    );
    const mac = options.mac === 'pbmac1' ? await pbmac1(authSafe, iterations) : appendixBMac();
    return seq(encodeInteger(3), contentInfo(OID.data, encodeOctetString(authSafe)), mac);
}

/** The caller's key and a self-signed certificate for it — generated and exported by the caller, never by pkinative. */
async function material(): Promise<Material> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const signer: SigningKey = { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } };
    const certificate = await createCertificate({
        serialNumber: 1n,
        subject: [[{ type: '2.5.4.3', value: 'Example Signer' }]],
        notBefore: NOW,
        notAfter: NOW + 365 * DAY,
        subjectPublicKey: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature', 'nonRepudiation']) },
        ],
    }, signer);
    return { pkcs8: new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)), certificate };
}

export default async function run(): Promise<Record<string, string>> {
    // Without Web Crypto nothing in a PKCS#12 can be opened; openPkcs12 would throw PKI_CRYPTO_UNAVAILABLE.
    if (!canDecrypt() || !canSign()) return { available: 'no' };
    const keys = await material();
    const modern = await writePfx(keys, { scheme: 'pbes2', mac: 'pbmac1' });

    // ── One call ──
    const options: OpenPkcs12Options = { password: PASSWORD };
    const report = await openPkcs12(modern, options);
    const [entry] = report.keys;

    // The key is ready to sign, and cannot give its bits back to anyone.
    const message = new TextEncoder().encode('Pay 100 EUR to account 42.');
    const p7s = await createSignedData({ content: message, certificate: entry!.certificate! }, entry!.signingKey!);
    const signerInfo = parseSignedData(p7s).signerInfos[0]!;

    // A wrong password fails the MAC, and nothing is decrypted after it.
    const wrong = await openPkcs12(modern, { password: 'Correct horse battery staple' });

    // ── A MAC nobody here can check ──
    // The shape of most .p12 files in circulation. The contents are read and
    // reported; `valid` stays false until you waive the check, knowingly.
    const unverifiable = await writePfx(keys, { scheme: 'pbes2', mac: 'appendix-b' });
    const closed = await openPkcs12(unverifiable, { password: PASSWORD });
    const waived = await openPkcs12(unverifiable, { password: PASSWORD, allowUnverifiedIntegrity: true });
    // With no MAC to fail first, a wrong password surfaces where it bites:
    // the encrypted certificates will not decrypt, and the key, whose
    // certificate was among them, has no algorithm to be unwrapped as.
    const guessed = await openPkcs12(unverifiable, { password: 'Correct horse battery staple', allowUnverifiedIntegrity: true });

    // ── The primitives underneath ──
    // parsePkcs12 needs no password: it says what is encrypted, with what,
    // and how the file is authenticated, before anyone types one.
    const p12: Pkcs12 = parsePkcs12(modern);
    const layout = p12.contents.map((c: SafeContentsInfo) => `${c.path}:${c.encrypted ? c.encryption!.scheme : `plain(${String(c.bags.length)})`}`).join(' ');
    const intact = p12.mac?.kind === 'pbmac1' && await verifyPkcs12Mac(p12, PASSWORD);
    const bags: SafeBag[] = [];
    for (const contents of p12.contents) bags.push(...await openSafeContents(contents, PASSWORD));
    const certBag = bags.find((bag) => bag.certificateDer !== undefined)!;
    const keyBag = bags.find((bag) => bag.encryptedKey !== undefined)!;
    // The primitive decrypts a key with the algorithm you name: here, the
    // one its certificate — found through the shared localKeyId — carries.
    const primitiveKey = await decryptPrivateKey(keyBag.encryptedKey!.der, {
        password: PASSWORD,
        algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
    });

    // A PBKDF2 count below RFC 8018's 1 000 still opens, with a diagnostic.
    const seen: PkiDiagnostic[] = [];
    parsePkcs12(await writePfx(keys, { scheme: 'pbes2', mac: 'pbmac1', iterations: 100 }), { onDiagnostic: (d) => { seen.push(d); } });

    // ── A legacy file: described, refused by name, never guessed at ──
    const legacy = await writePfx(keys, { scheme: 'legacy', mac: 'appendix-b' });
    const described = parsePkcs12(legacy);
    const legacyKey = described.contents[1]!.bags[0]!.encryptedKey!;
    let refused: PkiKeyErrorCode | undefined;
    let refusedMessage = '';
    try {
        await openSafeContents(described.contents[0]!, PASSWORD);
    } catch (error) {
        if (!(error instanceof PkiKeyError)) throw error;
        refused = error.code;
        refusedMessage = error.message;
    }
    let macRefused: PkiKeyErrorCode | undefined;
    try {
        await verifyPkcs12Mac(described, PASSWORD);
    } catch (error) {
        if (!(error instanceof PkiKeyError)) throw error;
        macRefused = error.code;
    }
    const legacyReport = await openPkcs12(legacy, { password: PASSWORD, allowUnverifiedIntegrity: true });

    return {
        available: 'yes',
        valid: `valid=${String(report.valid)} integrity=${report.integrity} keys=${String(report.keys.length)} certificates=${String(report.certificates.length)}`,
        key: `${entry!.path} ${entry!.friendlyName ?? ''} ${entry!.signingKey!.algorithm.name} ${handle(entry!.signingKey!)}`,
        signs: String(await verifySignerInfoSignature(signerInfo, entry!.certificate!)),
        wrongPassword: `integrity=${wrong.integrity} keys=${String(wrong.keys.length)} ${codes(wrong)}`,
        unverified: `valid=${String(closed.valid)} integrity=${closed.integrity} keys=${String(closed.keys.filter((k) => k.signingKey).length)} ${codes(closed)}`,
        waived: `valid=${String(waived.valid)} integrity=${waived.integrity}`,
        waivedWrongPassword: codes(guessed),
        layout,
        mac: `${p12.mac?.kind ?? 'none'} intact=${String(intact)} diagnostics=${String(p12.diagnostics.length)}`,
        bags: bags.map((bag) => `${bag.kind}@${bag.path}`).join(' '),
        certificate: `${formatDistinguishedName(parseCertificate(certBag.certificateDer!).subject)} sameLocalKeyId=${String(certBag.localKeyId?.join() === keyBag.localKeyId?.join())}`,
        primitive: `${primitiveKey.algorithm.name} ${handle(primitiveKey)}`,
        lowIterations: `${seen[0]?.code ?? 'none'} at ${seen.map((d) => d.path?.split('.')[0]).join(',')}`,
        legacyScheme: `${described.contents[0]!.encryption!.scheme} / ${legacyKey.encryption.scheme} pbes2=${String(legacyKey.encryption.pbes2 !== undefined)} mac=${described.mac?.kind ?? 'none'}`,
        refused: String(refused),
        refusedNames: String(refusedMessage.includes('pbeWithSHAAnd40BitRC2-CBC')),
        macRefused: String(macRefused),
        legacyReport: `valid=${String(legacyReport.valid)} ${codes(legacyReport)}`,
    };
}
