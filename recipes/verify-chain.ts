/**
 * Recipe: the one call — chain, host, purpose and revocation, together.
 *
 * Every other recipe here asks one question. This one asks all of them, because
 * that is what a relying party actually needs and because composing them
 * correctly is not obvious: the signatures have to be verified **before**
 * anything is decided and in parallel, the purpose has to go **into** the path
 * search rather than after it, and the host name is a question RFC 5280 §6
 * never asks at all.
 *
 * If you are reaching for `validateCertificatePath` and wondering what else you
 * need, the answer is this function.
 */
import {
    KEY_PURPOSES,
    parseCertificate,
    verifyCertificateChain,
    type Certificate,
    type VerifyChainReport,
} from 'pkinative';
import { fixture } from './_fixtures.js';

const quiet = { onDiagnostic: (): undefined => undefined };
const load = (name: string): Certificate => parseCertificate(fixture(name), quiet);

const root = load('isrg-root-x1');
const intermediate = load('lets-encrypt-r12');
/** Inside R12's window (2024-03-13 … 2027-03-12) and the root's. */
const at = Date.UTC(2026, 9, 1);

/** `ok` when nothing is wrong, the reason codes otherwise. */
const summarise = (report: VerifyChainReport): string =>
    report.reasons.map((reason) => reason.code).join(',') || `ok, ${String(report.path.length)} certificates`;

export default async function run(): Promise<Record<string, string>> {
    // R12 really was signed by ISRG Root X1, by a key nobody here holds — so
    // this is a signature verified rather than asserted.
    const real = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [root], at });

    // The same chain against nothing trusted. A verdict, not an exception:
    // "I do not trust this" is an answer a caller has to be able to read.
    const untrusted = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [], at });

    // …and after it expires. Note that `at` defaults to now, so a caller who
    // omits it is asking about today, which is almost always what they mean.
    const late = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [root], at: Date.UTC(2040, 0, 1) });

    // The host name is the question §6 never asks. R12 is a CA and names no
    // host, so asking about one is a mismatch — and the chain itself is fine,
    // which is exactly the shape that gets a valid certificate accepted for
    // somebody else when nobody asks.
    const wrongHost = await verifyCertificateChain({
        leaf: intermediate, trustAnchors: [root], at,
        serverName: { kind: 'dns', value: 'bank.example' },
    });

    // The purpose is the other question §6 never asks. R12 permits serverAuth
    // and clientAuth; it was never issued for signing code.
    const forServers = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [root], at, purposes: [KEY_PURPOSES.serverAuth] });
    const forCode = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [root], at, purposes: [KEY_PURPOSES.codeSigning] });

    // Revocation is soft-fail by default: with no list supplied, nothing is
    // claimed. `requireRevocation: true` turns silence into an answer, which is
    // the right setting wherever you can actually obtain the lists — and
    // "unknown" is never "not revoked", because an absence of evidence is not
    // evidence of absence.
    const noList = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [root], at });
    const listRequired = await verifyCertificateChain({ leaf: intermediate, trustAnchors: [root], at, requireRevocation: true });

    // Bad bytes are reported, never thrown. PKI_REASON_INPUT_MALFORMED carries
    // in `errorCode` the PkiErrorCode that *would* have been thrown, which is
    // how a report promises never to throw for bad input without copying the
    // whole encoding vocabulary into a second registry.
    const badCrl = await verifyCertificateChain({
        leaf: intermediate, trustAnchors: [root], at,
        crls: [Uint8Array.of(0x30, 0x80, 0x00)],
    });
    const malformed = badCrl.reasons.find((reason) => reason.code === 'PKI_REASON_INPUT_MALFORMED');

    // An OCSP response is matched on ALL THREE CertID fields and its signer is
    // authorised the RFC 6960 §4.2.2.2 way: the issuing CA signed it, or the CA
    // issued a certificate carrying id-kp-OCSPSigning and that certificate did.
    // The certificates a response ATTACHES are a convenience for reaching that
    // delegate, never a claim of authority — a client that trusted the attached
    // bag would let the responder nominate itself. These bytes are not a
    // response at all, which is reported rather than thrown.
    const badOcsp = await verifyCertificateChain({
        leaf: intermediate, trustAnchors: [root], at,
        ocsp: [Uint8Array.of(0x30, 0x80, 0x00)],
    });

    return {
        real: summarise(real),
        // How many signatures the call had to compute. A number far above the
        // path length is what a bag full of plausible issuers looks like, which
        // is what a caller passing a whole trust store will see.
        verified: String(real.verified),
        untrusted: summarise(untrusted),
        expired: summarise(late),
        wrongHost: summarise(wrongHost),
        forServers: summarise(forServers),
        forCode: summarise(forCode),
        noList: summarise(noList),
        listRequired: summarise(listRequired),
        badCrlReported: `${malformed?.code ?? 'none'} errorCode=${malformed?.errorCode ?? 'none'}`,
        badOcspReported: badOcsp.reasons.map((reason) => reason.code).join(','),
        neverThrows: 'true',
    };
}
