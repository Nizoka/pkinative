/**
 * Recipe: read a PKCS#8 private key — plain or password-protected — and sign
 * with it, without its bits ever passing through pkinative.
 *
 * `parsePrivateKeyInfo` and `parseEncryptedPrivateKeyInfo` describe a key
 * file before anything is imported or any password typed: its type and
 * curve, or the scheme it is encrypted with. `importPrivateKey` and
 * `decryptPrivateKey` turn it into a `SigningKey` — a `CryptoKey` with
 * `extractable: false` and the single usage `sign` — ready for
 * `createCertificate`, `createCertificationRequest` or `createSignedData`.
 *
 * Two rules to know before the code. **An encrypted key is unwrapped by the
 * host straight into a handle**, so its plaintext never exists in JavaScript,
 * and that is why `decryptPrivateKey` requires `algorithm`: the host must be
 * told what the key is before it decrypts it. **Only PBES2 with PBKDF2 and
 * AES-CBC is opened** — what OpenSSL 1.1 and later write by default; any
 * other scheme is named and refused with the conversion to run.
 *
 * The key files are written here by `node:crypto`, standing in for
 * `openssl genpkey` and `openssl pkcs8 -topk8`.
 */
import { generateKeyPairSync } from 'node:crypto';
import {
    canDecrypt,
    canSign,
    createCertificate,
    decodePem,
    decryptPrivateKey,
    encodeAlgorithmIdentifier,
    encodeInteger,
    encodeOctetString,
    encodePem,
    encodeSequence,
    importPrivateKey,
    parseCertificate,
    parseEncryptedPrivateKeyInfo,
    parsePrivateKeyInfo,
    PkiCryptoError,
    PkiError,
    PkiKeyError,
    verifySelfSignature,
    type DecryptPrivateKeyOptions,
    type EncryptedPrivateKeyInfo,
    type ImportPrivateKeyOptions,
    type PrivateKeyInfo,
    type SigningKey,
} from 'pkinative';

const PASSPHRASE = 'correct horse battery staple';
const NOW = Date.UTC(2026, 0, 15);

/** What the host says of a key: pkinative types the handle opaquely, and the runtime's CryptoKey answers. */
const handle = (signer: SigningKey): string => {
    const key = signer.key as unknown as { readonly extractable: boolean; readonly usages: readonly string[] };
    return `extractable=${String(key.extractable)} usages=${key.usages.join(',')}`;
};

/** The code a call fails with, or `ok`. */
async function failure(call: () => Promise<unknown>): Promise<string> {
    try {
        await call();
        return 'ok';
    } catch (error) {
        if (!(error instanceof PkiError)) throw error;
        return `${error.constructor.name}:${error.code}`;
    }
}

export default async function run(): Promise<Record<string, string>> {
    if (!canSign() || !canDecrypt()) return { available: 'no' };

    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spki = new Uint8Array(ec.publicKey.export({ type: 'spki', format: 'der' }));

    // ── A plain key: described, then imported ──
    // A `PRIVATE KEY` PEM block is a PKCS#8 PrivateKeyInfo in DER.
    const pemText = encodePem('PRIVATE KEY', new Uint8Array(ec.privateKey.export({ type: 'pkcs8', format: 'der' })));
    const [block] = decodePem(pemText, { label: 'PRIVATE KEY' });
    const info: PrivateKeyInfo = parsePrivateKeyInfo(block!.bytes);
    // An EC key names its curve, so the algorithm is inferred: ECDSA on
    // P-256 with SHA-256, the digest that curve is customarily paired with.
    const imported: SigningKey = await importPrivateKey(block!.bytes);

    // ── An RSA key does not say how it signs ──
    // PKCS#1 v1.5 or PSS, over any digest: a guess would be a signature a
    // relying party refuses, so the caller names it.
    const rsa = new Uint8Array(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'der' }));
    const rsaUnnamed = await failure(() => importPrivateKey(rsa));
    const rsaOptions: ImportPrivateKeyOptions = { algorithm: { name: 'RSA-PSS', hash: 'SHA-256' } };
    const rsaKey = await importPrivateKey(rsa, rsaOptions);
    // A named algorithm must fit the key: its family, and for ECDSA its curve.
    const misnamed = await failure(() => importPrivateKey(block!.bytes, { algorithm: { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' } }));

    // ── An encrypted key: its scheme is readable before any password ──
    // `openssl pkcs8 -topk8 -v2 aes-256-cbc` writes this.
    const encrypted = new Uint8Array(ec.privateKey.export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: PASSPHRASE }));
    const described: EncryptedPrivateKeyInfo = parseEncryptedPrivateKeyInfo(encrypted);
    const options: DecryptPrivateKeyOptions = {
        password: PASSPHRASE,
        algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
    };
    const decrypted = await decryptPrivateKey(encrypted, options);

    // AES-CBC carries no authentication tag: a wrong password, altered bytes
    // and a key that is not the algorithm named are one error, not three.
    const wrongPassword = await failure(() => decryptPrivateKey(encrypted, { ...options, password: 'Correct horse battery staple' }));
    const wrongAlgorithm = await failure(() => decryptPrivateKey(encrypted, { ...options, algorithm: { name: 'Ed25519' } }));

    // ── The decrypted key signs ──
    const certificate = parseCertificate(await createCertificate({
        serialNumber: 1n,
        subject: [[{ type: '2.5.4.3', value: 'Example Signer' }]],
        notBefore: NOW,
        notAfter: NOW + 365 * 86_400_000,
        subjectPublicKey: spki,
    }, decrypted));

    // ── A scheme pkinative will not open: named, never guessed at ──
    // PBES2 with 3DES instead of AES (what `-v2 des3` writes) parses, says
    // what it is, and is refused only when asked to decrypt.
    const des3 = new Uint8Array(ec.privateKey.export({ type: 'pkcs8', format: 'der', cipher: 'des-ede3-cbc', passphrase: PASSPHRASE }));
    const des3Scheme = parseEncryptedPrivateKeyInfo(des3).encryption;
    // An RFC 7292 Appendix C scheme, as a PKCS#12 shrouds its keys before OpenSSL 3.0 — built by hand, with random bytes for ciphertext.
    const legacy = encodeSequence([
        encodeAlgorithmIdentifier('1.2.840.113549.1.12.1.3', encodeSequence([encodeOctetString(new Uint8Array(8)), encodeInteger(2048)])),
        encodeOctetString(crypto.getRandomValues(new Uint8Array(48))),
    ]);
    let refusal = '';
    try {
        await decryptPrivateKey(legacy, options);
    } catch (error) {
        if (!(error instanceof PkiKeyError)) throw error;
        // The message names the scheme and the OpenSSL command that converts the file.
        refusal = `${error.code} path=${error.path ?? ''} names=${String(error.message.includes('pbeWithSHAAnd3-KeyTripleDES-CBC'))} convert=${String(error.message.includes('openssl pkcs8 -topk8 -v2 aes-256-cbc'))}`;
    }

    // A wrong password is a PkiCryptoError, never a PkiKeyError: the file was
    // readable, the decryption did not succeed.
    let cryptoError = '';
    try {
        await decryptPrivateKey(encrypted, { ...options, password: '' });
    } catch (error) {
        if (error instanceof PkiCryptoError) cryptoError = `${error.code} algorithm=${error.algorithm ?? ''}`;
    }

    return {
        available: 'yes',
        info: `v${String(info.version)} ${info.kind} ${String(info.curve)} attributes=${String(info.attributes.length)} publicKey=${String(info.publicKey !== undefined)}`,
        imported: `${imported.algorithm.name} ${'hash' in imported.algorithm ? imported.algorithm.hash : ''} ${handle(imported)}`,
        rsaUnnamed,
        rsa: `${rsaKey.algorithm.name} ${'hash' in rsaKey.algorithm ? rsaKey.algorithm.hash : ''}`,
        misnamed,
        scheme: described.encryption.scheme,
        pbes2: `iterations=${String(described.encryption.pbes2?.iterations)} prf=${String(described.encryption.pbes2?.prf)} keyBits=${String(described.encryption.pbes2?.keyBits)}`,
        decrypted: `${decrypted.algorithm.name} ${handle(decrypted)}`,
        wrongPassword,
        wrongAlgorithm,
        signed: `${String(await verifySelfSignature(certificate))}`,
        des3: `${des3Scheme.scheme} pbes2=${String(des3Scheme.pbes2 !== undefined)} ${await failure(() => decryptPrivateKey(des3, options))}`,
        refusal,
        cryptoError,
    };
}
