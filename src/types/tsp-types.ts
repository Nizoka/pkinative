/**
 * pkinative — RFC 3161 timestamp types
 * ====================================
 * What a timestamp authority is asked, what it answers, and what its token
 * asserts.
 *
 * The shape worth reading before the fields is `TimeStampToken`. A token is a
 * CMS `SignedData` whose content is a `TSTInfo` — so everything about *who*
 * signed it is the SignedData's, and everything about *what* was stamped is the
 * TSTInfo's. Keeping the two apart is what makes the checks RFC 3161 §2.4.2
 * lists land in the right place: the imprint and the nonce are facts about the
 * TSTInfo, the TSA's authority is a fact about the signer's certificate.
 *
 * A token says that **a hash existed** at a time. It says nothing about the
 * document the hash was computed from, which is why every check here starts
 * from the caller's own imprint rather than from anything the token carries.
 *
 * @module types/tsp-types
 */

import type { PkiTime } from './asn1-types.js';
import type { SignedData } from './cms-types.js';
import type { PkiDiagnostic } from './pki-types.js';
import type { AlgorithmIdentifier, Extension, GeneralName, SerialNumber } from './x509-types.js';

/** `MessageImprint` (RFC 3161 §2.4.1): the hash of the stamped data, and how it was computed. */
export interface MessageImprint {
    /** The digest algorithm. */
    readonly hashAlgorithm: AlgorithmIdentifier;
    /** The digest. Its length must match the algorithm's, which the parser checks. */
    readonly hashedMessage: Uint8Array;
}

/**
 * `Accuracy` (RFC 3161 §2.4.2): how far the stated time may be from the real
 * one. All three fields absent means the TSA declared no accuracy — which is
 * not the same as an exact time, and a caller comparing two timestamps must
 * treat it as unknown.
 */
export interface TimeStampAccuracy {
    /** Whole seconds; `0` when absent. */
    readonly seconds: number;
    /** Milliseconds, 1 to 999; `0` when absent. */
    readonly millis: number;
    /** Microseconds, 1 to 999; `0` when absent. */
    readonly micros: number;
}

/** `TSTInfo` (RFC 3161 §2.4.2): what the authority asserts. */
export interface TstInfo {
    /** Always `1`; any other version is refused. */
    readonly version: 1;
    /** The TSA policy under which the token was issued. */
    readonly policy: string;
    /** The hash that was stamped. It must equal the request's, and the caller's. */
    readonly messageImprint: MessageImprint;
    /** Unique per token issued by this TSA. Compare by `bytes` or `hex`. */
    readonly serialNumber: SerialNumber;
    /** The time the TSA asserts, in epoch milliseconds, with the fraction the TSA encoded. */
    readonly genTime: PkiTime;
    /** How far `genTime` may be from the real time; `undefined` when the TSA declared none. */
    readonly accuracy: TimeStampAccuracy | undefined;
    /** Whether tokens from this TSA may be ordered by `genTime` alone, whatever their accuracy. */
    readonly ordering: boolean;
    /** The request's nonce, echoed; `undefined` when the request carried none. */
    readonly nonce: bigint | undefined;
    /** The TSA's name as it chose to state it; `undefined` when absent. It is a hint, never an identity. */
    readonly tsa: GeneralName | undefined;
    /** `extensions`, decoded; empty when there are none. */
    readonly extensions: readonly Extension[];
    /** The whole `TSTInfo`, exactly as encoded — the `eContent` the token's signer signed. */
    readonly der: Uint8Array;
}

/** A timestamp token: a SignedData over a TSTInfo (RFC 3161 §2.4.2). */
export interface TimeStampToken {
    /** The CMS envelope — who signed, with what, and what certificates came with it. */
    readonly signedData: SignedData;
    /** What was stamped, and when. */
    readonly tstInfo: TstInfo;
}

/**
 * `PKIStatus` (RFC 3161 §2.4.2). Only `granted` and `grantedWithMods` carry a
 * token; every other status is the TSA declining, and a response in that state
 * has nothing to verify.
 */
export type TimeStampStatus = 'granted' | 'grantedWithMods' | 'rejection' | 'waiting' | 'revocationWarning' | 'revocationNotification';

/** The `PKIFailureInfo` bits RFC 3161 §2.4.2 names, in bit order. */
export type TimeStampFailure =
    | 'badAlg'
    | 'badRequest'
    | 'badDataFormat'
    | 'timeNotAvailable'
    | 'unacceptedPolicy'
    | 'unacceptedExtension'
    | 'addInfoNotAvailable'
    | 'systemFailure';

/** A parsed `TimeStampResp` (RFC 3161 §2.4.2). */
export interface TimeStampResponse {
    /** The whole response, as a zero-copy view of the input. */
    readonly der: Uint8Array;
    /** Whether the TSA granted the request. */
    readonly status: TimeStampStatus;
    /** `statusString`, the TSA's free text, in encoded order; empty when absent. */
    readonly statusStrings: readonly string[];
    /** `failInfo`, the reasons a request was declined; empty when absent. */
    readonly failInfo: readonly TimeStampFailure[];
    /** The token as DER — the bytes to embed as `id-aa-signatureTimeStampToken`; `undefined` unless granted. */
    readonly tokenDer: Uint8Array | undefined;
    /** The token, parsed; `undefined` unless granted. */
    readonly token: TimeStampToken | undefined;
    /** Profile concerns found while reading, in encoded order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}
