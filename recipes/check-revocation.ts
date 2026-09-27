/**
 * Recipe: read a CRL and ask it about one certificate.
 *
 * The shape to notice is what is **not** here: there is no array of revoked
 * entries. A CRL entry costs three ASN.1 nodes, so decoding the list into a
 * tree hits `maxNodes` at roughly 65 000 entries, while real CRLs run to
 * millions. The envelope is decoded and the list is *walked*, one TLV header at
 * a time, in constant memory. `findRevocation` is the question; `entryCount` is
 * the size, counted by walking.
 *
 * The CRL is built here rather than downloaded, because a recipe that needs the
 * network is a recipe that fails on a plane. It is assembled from raw DER, the
 * way a CA would emit it, so nothing in this file depends on pkinative being
 * able to write a CRL — which it cannot yet.
 */
import {
    encodeEnumerated,
    encodeExtension,
    encodeExtensions,
    encodeSequence,
    encodeTime,
    encodeTlv,
    findRevocation,
    parseCertificateList,
    type CertificateList,
    type CrlReason,
    type RevokedCertificate,
} from 'pkinative';

const DAY = 86_400_000;
const THIS_UPDATE = Date.UTC(2026, 0, 1);

/** `AlgorithmIdentifier { sha256WithRSAEncryption, NULL }`, by hand. */
const algorithm = encodeSequence([
    encodeTlv('universal', 6, false, Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b)),
    encodeTlv('universal', 5, false, new Uint8Array(0)),
]);

/** `Name` with one `CN` attribute. */
const issuerName = encodeSequence([
    encodeTlv('universal', 17, true, encodeSequence([
        encodeTlv('universal', 6, false, Uint8Array.of(0x55, 0x04, 0x03)),
        encodeTlv('universal', 12, false, new TextEncoder().encode('pkinative example CA')),
    ])),
]);

const serial = (...bytes: readonly number[]): Uint8Array => encodeTlv('universal', 2, false, Uint8Array.from(bytes));

/** One `revokedCertificates` entry, optionally carrying a `cRLReason`. */
function entry(bytes: readonly number[], revokedAt: number, reason?: number): Uint8Array {
    const extensions = reason === undefined
        ? []
        // cRLReason is 2.5.29.21, and its value is an ENUMERATED — an INTEGER
        // there is a common encoder bug, and the reason encodeEnumerated exists.
        : [encodeExtensions([{ oid: '2.5.29.21', value: encodeEnumerated(reason) }])];
    return encodeSequence([serial(...bytes), encodeTime(revokedAt, 'UTCTime'), ...extensions]);
}

/** A complete `CertificateList`, signature bytes included but not computed. */
function buildCrl(entries: readonly Uint8Array[], crlNumber: number): Uint8Array {
    const tbs = encodeSequence([
        encodeTlv('universal', 2, false, Uint8Array.of(0x01)),   // v2
        algorithm,
        issuerName,
        encodeTime(THIS_UPDATE, 'UTCTime'),
        encodeTime(THIS_UPDATE + 30 * DAY, 'UTCTime'),
        encodeSequence(entries),
        // crlExtensions [0] EXPLICIT, carrying cRLNumber (2.5.29.20).
        encodeTlv('context', 0, true, encodeExtensions([
            { oid: '2.5.29.20', value: encodeTlv('universal', 2, false, Uint8Array.of(crlNumber)) },
        ])),
    ]);
    // The signature is not computed: this recipe is about reading a list, and
    // `parseCertificateList` never verifies one — that is the caller's step,
    // the same separation §6 makes for certificates.
    return encodeSequence([tbs, algorithm, encodeTlv('universal', 3, false, Uint8Array.of(0x00, 0xde, 0xad))]);
}

const describe = (crl: CertificateList): string =>
    `v${String(crl.version)} entries=${String(crl.entryCount)} crlNumber=${String(crl.crlNumber)} delta=${String(crl.isDelta)} diag=${String(crl.diagnostics.length)}`;

const describeEntry = (found: RevokedCertificate | undefined): string =>
    found === undefined
        ? 'not listed'
        : `${found.serialNumber.hex} on ${new Date(found.revocationDate.epochMilliseconds).toISOString().slice(0, 10)} reason=${String(found.reason)}`;

export default function run(): Record<string, string> {
    const der = buildCrl([
        entry([0x01], THIS_UPDATE - DAY),
        entry([0x02], THIS_UPDATE - 2 * DAY, 1),          // keyCompromise
        entry([0x00, 0xff], THIS_UPDATE - 3 * DAY, 5),    // cessationOfOperation
    ], 7);

    const crl = parseCertificateList(der, { onDiagnostic: () => undefined });

    // Serials are compared by their CONTENT OCTETS, never by the bigint: two
    // serials that differ only in a leading zero octet are two serials to a CA,
    // and comparing the value would make them one — a revocation missed.
    const leadingZero = findRevocation(der, Uint8Array.of(0x00, 0xff));
    const withoutIt = findRevocation(der, Uint8Array.of(0xff));

    // A single extension that names a reason nobody assigned. RFC 5280 §5.3.1
    // skips 7, so the entry is found and its reason stays undefined rather than
    // being invented.
    const unassigned = parseCertificateList(buildCrl([entry([0x09], THIS_UPDATE, 7)], 8));
    const oddEntry = findRevocation(buildCrl([entry([0x09], THIS_UPDATE, 7)], 8), Uint8Array.of(0x09));

    const reasons: CrlReason[] = ['keyCompromise', 'cessationOfOperation'];

    return {
        envelope: describe(crl),
        issuer: crl.issuer.rdns.length === 1 ? 'one RDN' : 'unexpected',
        noReason: describeEntry(findRevocation(der, Uint8Array.of(0x01))),
        withReason: describeEntry(findRevocation(der, Uint8Array.of(0x02))),
        leadingZeroMatters: `${describeEntry(leadingZero)} | ${describeEntry(withoutIt)}`,
        notListed: describeEntry(findRevocation(der, Uint8Array.of(0x42))),
        unassignedReason: `${String(unassigned.entryCount)} entry, reason=${String(oddEntry?.reason)}`,
        reasonsSeen: reasons.join(','),
        // One extension is enough to show the shape a caller reaches for when
        // building a structure pkinative does not model.
        oneExtension: [...encodeExtension({ oid: '2.5.29.21', value: encodeEnumerated(1) })].map((b) => b.toString(16).padStart(2, '0')).join(''),
    };
}
