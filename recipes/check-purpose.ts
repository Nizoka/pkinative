/**
 * Recipe: may this chain be used for *this*? (RFC 5280 §4.2.1.12)
 *
 * A validated path says a CA vouched for a certificate, and `checkServerName`
 * says the certificate names the host you asked for. Neither says the
 * certificate is **for** what you are about to do with it — and a certificate
 * issued for signing e-mail, accepted to authenticate a TLS server, is a
 * certificate used outside the purpose its subject asked for and its issuer
 * granted.
 *
 * §6 never reads `extKeyUsage`, so this is a separate call, and which purpose
 * you need is an argument rather than a guess: it is a fact about your
 * protocol, not about the chain.
 *
 * The real Let's Encrypt hierarchy demonstrates the whole rule on its own: the
 * leaf says `serverAuth`, R12 says `clientAuth` **and** `serverAuth`, and ISRG
 * Root X1 says nothing at all.
 */
import {
    ANY_EXTENDED_KEY_USAGE,
    checkExtendedKeyUsage,
    getExtension,
    KEY_PURPOSES,
    parseCertificate,
    type Certificate,
    type CheckExtendedKeyUsageOptions,
} from 'pkinative';
import { fixture } from './_fixtures.js';

const quiet = { onDiagnostic: (): undefined => undefined };
const load = (name: string): Certificate => parseCertificate(fixture(name), quiet);

const leaf = load('letsencrypt-org-leaf');
const intermediate = load('lets-encrypt-r12');
const root = load('isrg-root-x1');
/** Leaf first, as `validateCertificatePath` and `buildCertificatePath` return it. */
const path = [leaf, intermediate, root];

const purposes = (certificate: Certificate): string =>
    getExtension(certificate, 'extendedKeyUsage')?.purposes.join('+') ?? '(none)';

/** `'ok'` when every certificate permits the purpose, the refused paths otherwise. */
const check = (purpose: string, options?: CheckExtendedKeyUsageOptions): string =>
    checkExtendedKeyUsage(path, purpose, options).map((reason) => reason.path).join(' ') || 'ok';

export default function run(): Record<string, string> {
    return {
        // What each certificate actually says.
        stated: `leaf=${purposes(leaf)} ica=${purposes(intermediate)} root=${purposes(root)}`,

        // The chain exists to authenticate a server, and it does.
        serverAuth: check(KEY_PURPOSES.serverAuth),

        // …and it may NOT be used to authenticate a client, even though R12
        // permits that: the restriction that bites is the leaf's own.
        clientAuth: check(KEY_PURPOSES.clientAuth),

        // A purpose nobody in the chain names is refused at every certificate
        // that names any purpose at all. The root names none, and an absent
        // extKeyUsage restricts nothing (§4.2.1.12), so it is not among them.
        codeSigning: check(KEY_PURPOSES.codeSigning),

        // ── The rule that is not in RFC 5280 ──
        // A CA's own extKeyUsage restricts what it may issue for. No sentence
        // of RFC 5280 says so; every Web PKI validator does it, and the
        // CA/Browser Forum relies on it to constrain technically-constrained
        // sub-CAs — without it, a sub-CA restricted to emailProtection issues a
        // serverAuth certificate and the chain validates, which is the whole
        // point of restricting it. It is on by default, and `restrictIssuers:
        // false` is the literal-RFC reading, for an internal PKI that puts a
        // purpose on a CA as documentation rather than as a constraint.
        issuersRestricted: check(KEY_PURPOSES.codeSigning),
        issuersIgnored: check(KEY_PURPOSES.codeSigning, { restrictIssuers: false }),

        // An absent extKeyUsage means unrestricted, which is why the root does
        // not appear above. `requireExplicitPurpose` is the stricter Web PKI reading —
        // a server certificate that does not say serverAuth is not a server
        // certificate — and it applies to the end entity only: requiring every
        // CA to enumerate the purposes of everything it may ever issue is not a
        // reading anyone holds.
        rootIsSilentNotRestrictive: checkExtendedKeyUsage([root], KEY_PURPOSES.codeSigning).length === 0 ? 'unrestricted' : 'REFUSED',

        // `ANY_EXTENDED_KEY_USAGE` (2.5.29.37.0) is the one OID that means every
        // purpose, as §4.2.1.12 defines it. Some relying parties refuse it on an
        // end-entity certificate; that is a policy pkinative does not take for
        // them, and taking it is one comparison on `purposes`.
        anyMeansEvery: ANY_EXTENDED_KEY_USAGE,
        leafDoesNotClaimAny: String(getExtension(leaf, 'extendedKeyUsage')?.purposes.includes(ANY_EXTENDED_KEY_USAGE) === true),
        explicitRequired: checkExtendedKeyUsage([root], KEY_PURPOSES.codeSigning, { requireExplicitPurpose: true })
            .map((reason) => reason.code).join(',') || 'ok',
    };
}
