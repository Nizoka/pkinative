/**
 * pkinative — RFC 5280 §4.2.1.12 extended key usage, along a path
 * ===============================================================
 * May this chain be used for *this*?
 *
 * A validated path says a CA vouched for a certificate and `checkServerName`
 * says the certificate names the host you asked for. Neither says the
 * certificate is *for* the thing you are about to do with it — and a
 * certificate issued for signing e-mail, accepted to authenticate a TLS server,
 * is a certificate used outside the purpose its subject asked for and its
 * issuer granted.
 *
 * ## Why this is not part of §6
 *
 * §6 never reads `extKeyUsage`. RFC 5280 §4.2.1.12 says the extension
 * *"indicates one or more purposes for which the certified public key may be
 * used"* and leaves the consequence to the application: *"If the extension is
 * present, then the certificate MUST only be used for one of the purposes
 * indicated"*. Which purpose you need is a fact about your protocol, not about
 * the chain, so it arrives as an argument rather than being guessed — exactly
 * as the host name does.
 *
 * ## The one rule RFC 5280 does not state, and why it is on by default
 *
 * **A CA's own `extKeyUsage` restricts what it may issue for.** No sentence of
 * RFC 5280 says so; every browser and every Web PKI validator enforces it, and
 * the CA/Browser Forum relies on it to constrain technically-constrained
 * sub-CAs. Without it, a sub-CA restricted to `emailProtection` issues a
 * certificate asserting `serverAuth` and the chain validates — which is the
 * whole point of restricting it. So `restrictIssuers` defaults to **on**, and
 * turning it off is the literal-RFC reading, offered because an internal PKI
 * may deliberately put a purpose on a CA as documentation rather than as a
 * constraint.
 *
 * `anyExtendedKeyUsage` (`2.5.29.37.0`) permits every purpose, as §4.2.1.12
 * defines it. Some relying parties refuse it on an end-entity certificate; that
 * is a policy this module does not take, and a caller who wants it writes one
 * comparison on `purposes`.
 *
 * @module path/path-purpose
 */

import { purposeNotPermittedReason } from '../core/pki-reasons.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate } from '../types/x509-types.js';
import { getExtension } from '../x509/x509-extensions.js';

/** `2.5.29.37.0`, anyExtendedKeyUsage — every purpose (RFC 5280 §4.2.1.12). */
export const ANY_EXTENDED_KEY_USAGE = '2.5.29.37.0';

/**
 * The five purposes RFC 5280 §4.2.1.12 names, by the names it gives them.
 *
 * A convenience, not a limit: `checkExtendedKeyUsage` takes any OID, because
 * the purpose registry is open and a caller with a private one should not have
 * to wait for this table.
 */
export const KEY_PURPOSES: Readonly<Record<'serverAuth' | 'clientAuth' | 'codeSigning' | 'emailProtection' | 'timeStamping' | 'ocspSigning', string>> =
    /*#__PURE__*/ Object.freeze({
        serverAuth: '1.3.6.1.5.5.7.3.1',
        clientAuth: '1.3.6.1.5.5.7.3.2',
        codeSigning: '1.3.6.1.5.5.7.3.3',
        emailProtection: '1.3.6.1.5.5.7.3.4',
        timeStamping: '1.3.6.1.5.5.7.3.8',
        ocspSigning: '1.3.6.1.5.5.7.3.9',
    });

/** Options of {@link checkExtendedKeyUsage}. */
export interface CheckExtendedKeyUsageOptions {
    /**
     * Apply a CA's own `extKeyUsage` to what it issued. **On by default.**
     *
     * No sentence of RFC 5280 requires this; every Web PKI validator does it,
     * and the CA/Browser Forum relies on it to constrain sub-CAs. Off is the
     * literal-RFC reading, for an internal PKI that puts a purpose on a CA as
     * documentation rather than as a constraint.
     */
    readonly restrictIssuers?: boolean | undefined;
    /**
     * Require the end-entity certificate to carry `extKeyUsage` and name the
     * purpose explicitly. **Off by default**, because §4.2.1.12 makes the
     * extension optional and its absence means *unrestricted* — a certificate
     * with no `extKeyUsage` is usable for anything its `keyUsage` allows.
     *
     * On is the stricter Web PKI reading, where a server certificate that does
     * not say `serverAuth` is not a server certificate.
     */
    readonly requireExplicitPurpose?: boolean | undefined;
}

/**
 * Check that every certificate in a path permits a purpose.
 *
 * ```ts
 * import { checkExtendedKeyUsage, KEY_PURPOSES } from 'pkinative';
 *
 * const reasons = checkExtendedKeyUsage(report.path, KEY_PURPOSES.serverAuth);
 * if (reasons.length > 0) return 'this chain is not for authenticating a server';
 * ```
 *
 * This is **not** part of RFC 5280 §6 and `validateCertificatePath` does not do
 * it: §6 never reads `extKeyUsage`, and which purpose you need is a fact about
 * your protocol. Pass the `path` of a validation or build report, leaf first —
 * validating a chain and then asking what it is for are two questions, and a
 * caller answering only the first has a chain that is sound for something else.
 *
 * @param path    The validated path, **leaf first**, as a report returns it.
 * @param purpose The KeyPurposeId OID needed, e.g. `KEY_PURPOSES.serverAuth`.
 * @param options See {@link CheckExtendedKeyUsageOptions}.
 * @returns One `PKI_REASON_PURPOSE_NOT_PERMITTED` per certificate that forbids
 *   the purpose; empty when every certificate permits it.
 * @throws Never — a purpose a chain does not permit is an answer.
 */
export function checkExtendedKeyUsage(
    path: readonly Certificate[],
    purpose: string,
    options?: CheckExtendedKeyUsageOptions,
): readonly PkiReason[] {
    const out: PkiReason[] = [];
    const restrictIssuers = options?.restrictIssuers !== false;
    for (const [index, certificate] of path.entries()) {
        // Index 0 is the end entity; everything above it issued what is below.
        // With `restrictIssuers` off, only the end entity is judged.
        if (index > 0 && !restrictIssuers) break;
        const extension = getExtension(certificate, 'extendedKeyUsage');
        if (extension === undefined) {
            // Absent means unrestricted (§4.2.1.12), and it is only ever
            // reported for the end entity: requiring every CA above it to
            // enumerate the purposes of everything it may ever issue is not a
            // reading anyone holds.
            if (index === 0 && options?.requireExplicitPurpose === true) {
                out.push(purposeNotPermittedReason(`path[${String(index)}]`, purpose, null));
            }
            continue;
        }
        if (extension.purposes.includes(purpose) || extension.purposes.includes(ANY_EXTENDED_KEY_USAGE)) continue;
        out.push(purposeNotPermittedReason(`path[${String(index)}].extKeyUsage`, purpose, extension.purposes));
    }
    return out;
}
