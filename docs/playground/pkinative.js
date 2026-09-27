// src/types/pki-errors.ts
var PkiError = class extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PkiError";
    this.code = code;
  }
};
var PkiEncodingError = class extends PkiError {
  constructor(code, message, offset) {
    super(code, message);
    this.name = "PkiEncodingError";
    this.offset = offset;
  }
};
var PkiCertificateError = class extends PkiError {
  constructor(code, message, path, offset) {
    super(code, message);
    this.name = "PkiCertificateError";
    this.path = path;
    this.offset = offset;
  }
};
var PkiLimitError = class extends PkiError {
  constructor(code, message, limit, configured, observed) {
    super(code, message);
    this.name = "PkiLimitError";
    this.limit = limit;
    this.configured = configured;
    this.observed = observed;
  }
};
var PkiCryptoError = class extends PkiError {
  constructor(code, message, algorithm) {
    super(code, message);
    this.name = "PkiCryptoError";
    this.algorithm = algorithm;
  }
};

// src/core/pki-limits.ts
var DEFAULT_PKI_LIMITS = /* @__PURE__ */ Object.freeze({
  maxInputBytes: 64 * 1024 * 1024,
  maxDepth: 64,
  maxNodes: 2e5,
  maxIntegerBytes: 8192,
  maxOidBytes: 256,
  maxBerSegments: 1e4,
  maxPemBlocks: 1e4,
  maxExtensions: 256,
  maxGeneralNames: 1e4,
  maxNameAttributes: 1024,
  maxPolicies: 1024,
  maxChainLength: 10,
  maxPolicyNodes: 4096,
  maxRevokedCertificates: 1e6,
  maxOcspResponses: 256,
  maxPathsExplored: 1e3
});
function resolveLimits(overrides) {
  if (overrides === void 0) return DEFAULT_PKI_LIMITS;
  if (typeof overrides !== "object" || overrides === null || Array.isArray(overrides)) {
    throw new PkiLimitError(
      "PKI_LIMIT_INVALID",
      "pkinative: options.limits must be an object of named limits \u2014 see DEFAULT_PKI_LIMITS for the keys",
      "limits",
      NaN,
      NaN
    );
  }
  const merged = { ...DEFAULT_PKI_LIMITS };
  const entries = overrides;
  for (const key of Object.keys(entries)) {
    const value = entries[key];
    if (value === void 0) continue;
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_PKI_LIMITS, key)) {
      throw new PkiLimitError(
        "PKI_LIMIT_INVALID",
        `pkinative: unknown limit '${key}' \u2014 valid keys are ${Object.keys(DEFAULT_PKI_LIMITS).join(", ")}`,
        key,
        NaN,
        NaN
      );
    }
    if (typeof value !== "number" || !(value > 0) || value !== Infinity && !Number.isInteger(value)) {
      throw new PkiLimitError(
        "PKI_LIMIT_INVALID",
        `pkinative: limit '${key}' must be a positive integer or Infinity, got ${String(value)}`,
        key,
        NaN,
        NaN
      );
    }
    merged[key] = value;
  }
  return Object.freeze(merged);
}
function enforceLimit(limits, limit, observed, context) {
  const configured = limits[limit];
  if (observed > configured) {
    throw new PkiLimitError(
      "PKI_LIMIT_EXCEEDED",
      `pkinative: ${context} (${observed}) exceeds limits.${limit} (${configured}) \u2014 raise limits.${limit} explicitly if this input is trusted`,
      limit,
      configured,
      observed
    );
  }
}

// src/asn1/asn1-cursor.ts
var CLASSES = ["universal", "application", "context", "private"];
function readTlvHeader(data, offset, path) {
  const first = data[offset];
  if (first === void 0) {
    throw new PkiEncodingError("PKI_ASN1_TRUNCATED", `pkinative: ${path} expects a value at offset ${String(offset)} and the input ends there \u2014 the structure is truncated`, offset);
  }
  const tagClass = CLASSES[first >> 6 & 3];
  const constructed = (first & 32) !== 0;
  let tagNumber = first & 31;
  let at = offset + 1;
  if (tagNumber === 31) {
    tagNumber = 0;
    let octets = 0;
    for (; ; ) {
      const byte = data[at];
      if (byte === void 0) {
        throw new PkiEncodingError("PKI_ASN1_TRUNCATED", `pkinative: ${path} has a high tag number that runs past the input`, offset);
      }
      if (octets === 0 && byte === 128) {
        throw new PkiEncodingError("PKI_ASN1_TAG_INVALID", `pkinative: ${path} has a high tag number whose first octet is 0x80, which is not the shortest form (X.690 \xA78.1.2.4.2)`, offset);
      }
      octets += 1;
      if (octets > 4) {
        throw new PkiEncodingError("PKI_ASN1_TAG_INVALID", `pkinative: ${path} has a tag number wider than four octets \u2014 no PKI structure uses one, and accepting it invites an integer overflow`, offset);
      }
      tagNumber = tagNumber << 7 | byte & 127;
      at += 1;
      if ((byte & 128) === 0) break;
    }
  }
  const lengthByte = data[at];
  if (lengthByte === void 0) {
    throw new PkiEncodingError("PKI_ASN1_TRUNCATED", `pkinative: ${path} has no length octet \u2014 the structure is truncated`, offset);
  }
  at += 1;
  let length;
  if (lengthByte < 128) {
    length = lengthByte;
  } else if (lengthByte === 128) {
    throw new PkiEncodingError("PKI_ASN1_LENGTH_INVALID", `pkinative: ${path} uses an indefinite length, which DER forbids (X.690 \xA710.1) and this cursor never accepts`, offset);
  } else {
    const octets = lengthByte & 127;
    if (octets > 6) {
      throw new PkiEncodingError("PKI_ASN1_LENGTH_INVALID", `pkinative: ${path} declares a length in ${String(octets)} octets; nothing this library reads is that large, and a wider length is an overflow waiting to happen`, offset);
    }
    length = 0;
    for (let i = 0; i < octets; i += 1) {
      const byte = data[at + i];
      if (byte === void 0) {
        throw new PkiEncodingError("PKI_ASN1_TRUNCATED", `pkinative: ${path} has a length that runs past the input`, offset);
      }
      if (i === 0 && byte === 0) {
        throw new PkiEncodingError("PKI_ASN1_LENGTH_INVALID", `pkinative: ${path} has a long-form length with a leading zero octet, which is not the shortest form (X.690 \xA710.1)`, offset);
      }
      length = length * 256 + byte;
    }
    if (length < 128) {
      throw new PkiEncodingError("PKI_ASN1_LENGTH_INVALID", `pkinative: ${path} encodes the length ${String(length)} in long form, and DER requires the short form below 128 (X.690 \xA710.1)`, offset);
    }
    at += octets;
  }
  const end = at + length;
  if (end > data.length) {
    throw new PkiEncodingError("PKI_ASN1_TRUNCATED", `pkinative: ${path} declares ${String(length)} content octets and only ${String(data.length - at)} remain \u2014 the structure is truncated`, offset);
  }
  return { tagClass, tagNumber, constructed, offset, contentStart: at, length, end };
}
function* walkChildren(data, parent, path) {
  let at = parent.contentStart;
  let index = 0;
  while (at < parent.end) {
    const child = readTlvHeader(data, at, `${path}[${String(index)}]`);
    if (child.end > parent.end) {
      throw new PkiEncodingError("PKI_ASN1_TRUNCATED", `pkinative: ${path}[${String(index)}] runs past the end of its parent \u2014 the two lengths disagree, and a value that overruns its container is how one parser reads what another does not`, child.offset);
    }
    yield child;
    at = child.end;
    index += 1;
  }
}

// src/core/bytes.ts
function assertBytes(input, what) {
  if (ArrayBuffer.isView(input) && Object.prototype.toString.call(input) === "[object Uint8Array]") {
    return input;
  }
  throw new PkiError(
    "PKI_INVALID_INPUT",
    `pkinative: ${what} must be a Uint8Array, got ${input === null ? "null" : typeof input} \u2014 decode PEM text with decodePem() first`
  );
}
function byteView(data) {
  return new DataView(data.buffer, data.byteOffset, data.byteLength);
}
function compareOctets(a, b) {
  const av = byteView(a);
  const bv = byteView(b);
  const min = Math.min(a.length, b.length);
  for (let i = 0; i < min; i++) {
    const diff = av.getUint8(i) - bv.getUint8(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}
var HEX_DIGITS = "0123456789abcdef";
function toHex(bytes, separator = "") {
  const parts = [];
  for (const b of bytes) parts.push(HEX_DIGITS.charAt(b >> 4) + HEX_DIGITS.charAt(b & 15));
  return parts.join(separator);
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
function concatBytes(parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// src/core/pki-diagnostics.ts
function _warn(message) {
  const sink = globalThis.console;
  if (sink !== void 0 && typeof sink.warn === "function") sink.warn(message);
}
function createDiagnosticEmitter(strict, handler) {
  const recorded = [];
  const warned = /* @__PURE__ */ new Set();
  return {
    diagnostics: recorded,
    emit(diagnostic) {
      if (strict === true) {
        throw new PkiError(
          "PKI_STRICT_DIAGNOSTIC",
          `pkinative: [${diagnostic.code}] ${diagnostic.message} \u2014 refused because strict: true; omit it to accept the input with this diagnostic`
        );
      }
      recorded.push(diagnostic);
      if (handler !== void 0) {
        handler(diagnostic);
        return;
      }
      if (!warned.has(diagnostic.code)) {
        warned.add(diagnostic.code);
        _warn(`pkinative: [${diagnostic.code}] ${diagnostic.message}`);
      }
    }
  };
}
function _diagnostic(code, severity, standard, message, path, offset) {
  return Object.freeze({ code, severity, message, standard, path, offset });
}
function serialTooLongDiagnostic(octets, offset) {
  return _diagnostic(
    "PKI_DIAG_SERIAL_TOO_LONG",
    "warning",
    "RFC 5280 \xA74.1.2.2",
    `the serial number is ${octets} octets long; RFC 5280 allows at most 20, and some verifiers refuse longer serials`,
    "tbsCertificate.serialNumber",
    offset
  );
}
function serialNotPositiveDiagnostic(offset) {
  return _diagnostic(
    "PKI_DIAG_SERIAL_NOT_POSITIVE",
    "warning",
    "RFC 5280 \xA74.1.2.2",
    "the serial number is zero or negative; RFC 5280 requires a positive integer (the value is still returned as decoded)",
    "tbsCertificate.serialNumber",
    offset
  );
}
function signatureAlgorithmMismatchDiagnostic(outer, inner) {
  return _diagnostic(
    "PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH",
    "warning",
    "RFC 5280 \xA74.1.1.2",
    `signatureAlgorithm (${outer}) differs from tbsCertificate.signature (${inner}); a verifier must refuse this certificate`,
    "signatureAlgorithm",
    void 0
  );
}
function rsaParametersNotNullDiagnostic(path, offset) {
  return _diagnostic(
    "PKI_DIAG_RSA_PARAMETERS_NOT_NULL",
    "warning",
    "RFC 3279 \xA72.2.1",
    "an RSA PKCS#1 v1.5 algorithm identifier has absent or non-NULL parameters; RFC 3279 requires NULL",
    path,
    offset
  );
}
function extensionsRequireV3Diagnostic(version) {
  return _diagnostic(
    "PKI_DIAG_EXTENSIONS_REQUIRE_V3",
    "warning",
    "RFC 5280 \xA74.1.2.1",
    `the certificate carries extensions but declares version ${version}; extensions require version 3`,
    "tbsCertificate.version",
    void 0
  );
}
function uniqueIdRequiresV2Diagnostic(version) {
  return _diagnostic(
    "PKI_DIAG_UNIQUE_ID_REQUIRES_V2",
    "warning",
    "RFC 5280 \xA74.1.2.8",
    `the certificate carries a unique identifier but declares version ${version}; unique identifiers require version 2 or 3`,
    "tbsCertificate.version",
    void 0
  );
}
function generalizedTimeBefore2050Diagnostic(path, text, offset) {
  return _diagnostic(
    "PKI_DIAG_GENERALIZED_TIME_BEFORE_2050",
    "warning",
    "RFC 5280 \xA74.1.2.5",
    `"${text}" is a GeneralizedTime before 2050; RFC 5280 requires UTCTime for dates through 2049`,
    path,
    offset
  );
}
function generalizedTimeFractionDiagnostic(path, text, offset) {
  return _diagnostic(
    "PKI_DIAG_GENERALIZED_TIME_FRACTION",
    "warning",
    "RFC 5280 \xA74.1.2.5.2",
    `"${text}" carries fractional seconds, which RFC 5280 forbids in certificates`,
    path,
    offset
  );
}
function validityInvertedDiagnostic(notBefore, notAfter) {
  return _diagnostic(
    "PKI_DIAG_VALIDITY_INVERTED",
    "warning",
    "RFC 5280 \xA74.1.2.5",
    `notBefore (${notBefore}) is later than notAfter (${notAfter}); the certificate is valid at no instant`,
    "tbsCertificate.validity",
    void 0
  );
}
function emptyIssuerDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_EMPTY_ISSUER",
    "warning",
    "RFC 5280 \xA74.1.2.4",
    "the issuer name is empty; RFC 5280 requires a non-empty issuer distinguished name",
    "tbsCertificate.issuer",
    void 0
  );
}
function emptySubjectSanNotCriticalDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL",
    "warning",
    "RFC 5280 \xA74.2.1.6",
    "the subject is empty but the subjectAltName extension is absent or not critical; the identity lives only in an extension a verifier may ignore",
    "tbsCertificate.subject",
    void 0
  );
}
function sanEmptyDiagnostic(path) {
  return _diagnostic(
    "PKI_DIAG_SAN_EMPTY",
    "warning",
    "RFC 5280 \xA74.2.1.6",
    "an alternative-name extension contains no name; RFC 5280 requires at least one GeneralName",
    path,
    void 0
  );
}
function rdnSetNotSortedDiagnostic(path, offset) {
  return _diagnostic(
    "PKI_DIAG_RDN_SET_NOT_SORTED",
    "warning",
    "ITU-T X.690 \xA711.6",
    "a multi-valued relative distinguished name is not in DER SET OF order; name comparison by bytes will differ from other implementations",
    path,
    offset
  );
}
function printableStringCharsetDiagnostic(path, character, offset) {
  return _diagnostic(
    "PKI_DIAG_PRINTABLE_STRING_CHARSET",
    "warning",
    "ITU-T X.680 \xA741.4",
    `a PrintableString contains "${character}", which is outside the PrintableString alphabet; the value was decoded as ASCII`,
    path,
    offset
  );
}
function teletexAsLatin1Diagnostic(path, offset) {
  return _diagnostic(
    "PKI_DIAG_TELETEX_AS_LATIN1",
    "info",
    "RFC 5280 \xA74.1.2.4",
    "a TeletexString was decoded as ISO 8859-1, the interpretation of real-world issuers; the original bytes are in the raw field",
    path,
    offset
  );
}
function unknownCriticalExtensionDiagnostic(oid, path) {
  return _diagnostic(
    "PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION",
    "warning",
    "RFC 5280 \xA74.2",
    `the critical extension ${oid} is not recognised; a verifier must refuse a certificate with an unrecognised critical extension`,
    path,
    void 0
  );
}
function pathLenWithoutCaDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_PATHLEN_WITHOUT_CA",
    "warning",
    "RFC 5280 \xA74.2.1.9",
    "basicConstraints sets pathLenConstraint while cA is false; the constraint is meaningless and RFC 5280 forbids it",
    "tbsCertificate.extensions.basicConstraints",
    void 0
  );
}
function keyUsageEmptyDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_KEY_USAGE_EMPTY",
    "warning",
    "RFC 5280 \xA74.2.1.3",
    "keyUsage asserts no usage bit; RFC 5280 requires at least one bit set",
    "tbsCertificate.extensions.keyUsage",
    void 0
  );
}
function namedBitsTrailingZeroDiagnostic(path, offset) {
  return _diagnostic(
    "PKI_DIAG_NAMED_BITS_TRAILING_ZERO",
    "warning",
    "ITU-T X.690 \xA711.2.2",
    "a named bit list keeps trailing zero bits that DER requires to be removed",
    path,
    offset
  );
}
function nameConstraintsNotCriticalDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL",
    "warning",
    "RFC 5280 \xA74.2.1.10",
    "nameConstraints is not marked critical; RFC 5280 requires conforming CAs to mark it critical",
    "tbsCertificate.extensions.nameConstraints",
    void 0
  );
}
function akiIssuerSerialUnpairedDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED",
    "warning",
    "RFC 5280 \xA74.2.1.1",
    "authorityKeyIdentifier carries only one of authorityCertIssuer and authorityCertSerialNumber; they must appear together",
    "tbsCertificate.extensions.authorityKeyIdentifier",
    void 0
  );
}
function policyDuplicateDiagnostic(oid) {
  return _diagnostic(
    "PKI_DIAG_POLICY_DUPLICATE",
    "warning",
    "RFC 5280 \xA74.2.1.4",
    `certificatePolicies lists the policy ${oid} more than once; a policy OID must not appear twice`,
    "tbsCertificate.extensions.certificatePolicies",
    void 0
  );
}
function policyConstraintsEmptyDiagnostic() {
  return _diagnostic(
    "PKI_DIAG_POLICY_CONSTRAINTS_EMPTY",
    "warning",
    "RFC 5280 \xA74.2.1.11",
    "policyConstraints sets neither requireExplicitPolicy nor inhibitPolicyMapping; RFC 5280 forbids an empty sequence",
    "tbsCertificate.extensions.policyConstraints",
    void 0
  );
}
function defaultEncodedDiagnostic(path, value, offset) {
  return _diagnostic(
    "PKI_DIAG_DEFAULT_ENCODED",
    "warning",
    "ITU-T X.690 \xA711.5",
    `the field encodes its DEFAULT value ${value}, which DER omits; the value reads the same either way, but a strict DER verifier may refuse the certificate`,
    path,
    offset
  );
}
function berConstructAcceptedDiagnostic(construct, offset) {
  return _diagnostic(
    "PKI_DIAG_BER_CONSTRUCT_ACCEPTED",
    "info",
    "ITU-T X.690 \xA710",
    `accepted a BER-only construct (${construct}) because encodingRules is 'ber'; a DER decoder refuses this input`,
    "",
    offset
  );
}
function pemLaxAcceptedDiagnostic(deviation, offset) {
  return _diagnostic(
    "PKI_DIAG_PEM_LAX_ACCEPTED",
    "info",
    "RFC 7468 \xA73",
    `accepted a lax PEM deviation (${deviation}) because mode is 'lax'; strict parsing refuses this text`,
    "",
    offset
  );
}

// src/asn1/asn1-context.ts
function createAsn1Context(options) {
  if (options !== void 0 && (typeof options !== "object" || options === null)) {
    throw new PkiError("PKI_INVALID_OPTION", "pkinative: options must be an object \u2014 pass { encodingRules, limits, strict, onDiagnostic } or omit it");
  }
  const rules = options?.encodingRules ?? "der";
  if (rules !== "der" && rules !== "ber") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: encodingRules must be 'der' or 'ber', got ${String(rules)}`);
  }
  if (options?.strict !== void 0 && typeof options.strict !== "boolean") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: strict must be a boolean, got ${typeof options.strict}`);
  }
  if (options?.onDiagnostic !== void 0 && typeof options.onDiagnostic !== "function") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: onDiagnostic must be a function, got ${typeof options.onDiagnostic}`);
  }
  return {
    rules,
    limits: resolveLimits(options?.limits),
    emitter: createDiagnosticEmitter(options?.strict, options?.onDiagnostic),
    berReported: /* @__PURE__ */ new Set(),
    nodes: 0
  };
}
function noteBer(ctx, construct, offset) {
  if (ctx.berReported.has(construct)) return;
  ctx.berReported.add(construct);
  ctx.emitter.emit(berConstructAcceptedDiagnostic(construct, offset));
}

// src/asn1/asn1-tags.ts
var TAG_BOOLEAN = 1;
var TAG_INTEGER = 2;
var TAG_BIT_STRING = 3;
var TAG_OCTET_STRING = 4;
var TAG_NULL = 5;
var TAG_OID = 6;
var TAG_ENUMERATED = 10;
var TAG_UTF8_STRING = 12;
var TAG_SEQUENCE = 16;
var TAG_SET = 17;
var TAG_NUMERIC_STRING = 18;
var TAG_PRINTABLE_STRING = 19;
var TAG_TELETEX_STRING = 20;
var TAG_IA5_STRING = 22;
var TAG_UTC_TIME = 23;
var TAG_GENERALIZED_TIME = 24;
var TAG_VISIBLE_STRING = 26;
var TAG_UNIVERSAL_STRING = 28;
var TAG_BMP_STRING = 30;
var TAG_CLASSES = ["universal", "application", "context", "private"];
function tagClassOf(identifier) {
  const bits = identifier & 192;
  if (bits === 0) return "universal";
  if (bits === 64) return "application";
  if (bits === 128) return "context";
  return "private";
}
var STRING_TAGS = {
  utf8: TAG_UTF8_STRING,
  numeric: TAG_NUMERIC_STRING,
  printable: TAG_PRINTABLE_STRING,
  teletex: TAG_TELETEX_STRING,
  ia5: TAG_IA5_STRING,
  visible: TAG_VISIBLE_STRING,
  universal: TAG_UNIVERSAL_STRING,
  bmp: TAG_BMP_STRING
};
var NAMES = {
  0: "end-of-contents",
  1: "BOOLEAN",
  2: "INTEGER",
  3: "BIT STRING",
  4: "OCTET STRING",
  5: "NULL",
  6: "OBJECT IDENTIFIER",
  7: "ObjectDescriptor",
  8: "EXTERNAL",
  9: "REAL",
  10: "ENUMERATED",
  11: "EMBEDDED PDV",
  12: "UTF8String",
  13: "RELATIVE-OID",
  14: "TIME",
  16: "SEQUENCE",
  17: "SET",
  18: "NumericString",
  19: "PrintableString",
  20: "TeletexString",
  21: "VideotexString",
  22: "IA5String",
  23: "UTCTime",
  24: "GeneralizedTime",
  25: "GraphicString",
  26: "VisibleString",
  27: "GeneralString",
  28: "UniversalString",
  29: "CHARACTER STRING",
  30: "BMPString"
};
function isPrimitiveOnly(tagNumber) {
  return tagNumber === 1 || tagNumber === 2 || tagNumber === 5 || tagNumber === 6 || tagNumber === 9 || tagNumber === 10 || tagNumber === 13 || tagNumber === 14;
}
function isConstructedOnly(tagNumber) {
  return tagNumber === 8 || tagNumber === 11 || tagNumber === 16 || tagNumber === 17 || tagNumber === 29;
}
function isStringTag(tagNumber) {
  return tagNumber === 3 || tagNumber === 4 || tagNumber === 7 || tagNumber === 12 || tagNumber >= 18 && tagNumber <= 28 || tagNumber === 30;
}
function stringTypeOfTag(tagNumber) {
  for (const type of Object.keys(STRING_TAGS)) {
    if (STRING_TAGS[type] === tagNumber) return type;
  }
  return void 0;
}
function tagLabel(tagClass, tagNumber) {
  if (tagClass === "universal") return NAMES[tagNumber] ?? `[UNIVERSAL ${tagNumber}]`;
  if (tagClass === "context") return `[${tagNumber}]`;
  return `[${tagClass.toUpperCase()} ${tagNumber}]`;
}

// src/asn1/asn1-decode.ts
function where(endIsInput) {
  return endIsInput ? "input" : "enclosing value";
}
function readHeader(view, offset, end, endIsInput, ctx) {
  if (offset >= end) {
    throw new PkiEncodingError(
      "PKI_ASN1_TRUNCATED",
      `pkinative: expected an identifier octet at offset ${offset}, but the ${where(endIsInput)} ends there \u2014 the input is incomplete`,
      offset
    );
  }
  const first = view.getUint8(offset);
  const tagClass = tagClassOf(first);
  const constructed = (first & 32) !== 0;
  let tagNumber = first & 31;
  let at = offset + 1;
  if (tagNumber === 31) {
    tagNumber = 0;
    for (let index = 0; ; index++) {
      if (at >= end) {
        throw new PkiEncodingError(
          "PKI_ASN1_TRUNCATED",
          `pkinative: the high-tag-number identifier at offset ${offset} runs past the end of the ${where(endIsInput)} \u2014 the input is incomplete`,
          offset
        );
      }
      const octet = view.getUint8(at);
      if (index === 0 && octet === 128) {
        throw new PkiEncodingError(
          "PKI_ASN1_TAG_INVALID",
          `pkinative: the high-tag-number identifier at offset ${offset} starts with 0x80, a non-minimal form X.690 \xA78.1.2.4.2 forbids`,
          offset
        );
      }
      tagNumber = tagNumber * 128 + (octet & 127);
      if (tagNumber > 2147483647) {
        throw new PkiEncodingError(
          "PKI_ASN1_TAG_INVALID",
          `pkinative: the tag number at offset ${offset} exceeds 2^31 \u2212 1 \u2014 the input is corrupt or crafted`,
          offset
        );
      }
      at++;
      if ((octet & 128) === 0) break;
    }
    if (tagNumber < 31) {
      throw new PkiEncodingError(
        "PKI_ASN1_TAG_INVALID",
        `pkinative: tag number ${tagNumber} at offset ${offset} uses the high-tag-number form, which X.690 \xA78.1.2.2 reserves for numbers of 31 and above`,
        offset
      );
    }
  }
  if (at >= end) {
    throw new PkiEncodingError(
      "PKI_ASN1_TRUNCATED",
      `pkinative: expected a length octet at offset ${at}, but the ${where(endIsInput)} ends there \u2014 the input is incomplete`,
      offset
    );
  }
  const lengthOctet = view.getUint8(at);
  at++;
  if (lengthOctet < 128) {
    return { tagClass, tagNumber, constructed, headerLength: at - offset, length: lengthOctet };
  }
  const label = tagLabel(tagClass, tagNumber);
  if (lengthOctet === 128) {
    if (!constructed) {
      throw new PkiEncodingError(
        "PKI_ASN1_CONSTRUCTED_FORM_INVALID",
        `pkinative: the primitive ${label} at offset ${offset} uses the indefinite length form, which X.690 \xA78.1.3.2 allows only for constructed values`,
        offset
      );
    }
    if (ctx.rules === "der") {
      throw new PkiEncodingError(
        "PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN",
        `pkinative: the ${label} at offset ${offset} uses the indefinite length form, which DER forbids \u2014 decode with encodingRules: 'ber' if the input is BER`,
        offset
      );
    }
    noteBer(ctx, "indefinite length", offset);
    return { tagClass, tagNumber, constructed, headerLength: at - offset, length: null };
  }
  if (lengthOctet === 255) {
    throw new PkiEncodingError(
      "PKI_ASN1_LENGTH_INVALID",
      `pkinative: the length octet 0xFF at offset ${at - 1} is reserved by X.690 \xA78.1.3.5 \u2014 the input is corrupt or not ASN.1`,
      offset
    );
  }
  const count = lengthOctet & 127;
  const lengthStart = at;
  let length = 0;
  for (let i = 0; i < count; i++) {
    if (at >= end) {
      throw new PkiEncodingError(
        "PKI_ASN1_TRUNCATED",
        `pkinative: the ${count}-octet length of the ${label} at offset ${offset} runs past the end of the ${where(endIsInput)} \u2014 the input is incomplete`,
        offset
      );
    }
    length = length * 256 + view.getUint8(at);
    at++;
  }
  const minimal = count === 1 ? length >= 128 : view.getUint8(lengthStart) !== 0;
  if (!minimal) {
    if (ctx.rules === "der") {
      throw new PkiEncodingError(
        "PKI_ASN1_LENGTH_NON_MINIMAL",
        `pkinative: the length of the ${label} at offset ${offset} is not in its shortest form, which DER requires (X.690 \xA710.1) \u2014 decode with encodingRules: 'ber' if the producer emits BER`,
        offset
      );
    }
    noteBer(ctx, "non-minimal length", offset);
  }
  return { tagClass, tagNumber, constructed, headerLength: at - offset, length };
}
function makeNode(data, tagClass, tagNumber, constructed, offset, headerLength, contentStart, contentEnd, end, indefinite, children) {
  return Object.freeze({
    tagClass,
    tagNumber,
    constructed,
    offset,
    headerLength,
    contentLength: contentEnd - contentStart,
    indefinite,
    bytes: data.subarray(offset, end),
    content: data.subarray(contentStart, contentEnd),
    children: Object.freeze(children)
  });
}
function decodeValueAt(data, start, ctx) {
  return decodeValueIn(byteView(data), data, start, ctx);
}
function decodeValueIn(view, data, start, ctx) {
  const frames = [];
  let pos = start;
  for (; ; ) {
    const top = frames[frames.length - 1];
    if (top !== void 0) {
      let closed = null;
      if (top.contentEnd !== null && pos === top.contentEnd) {
        closed = makeNode(data, top.tagClass, top.tagNumber, true, top.offset, top.headerLength, top.contentStart, pos, pos, false, top.children);
      } else if (top.contentEnd === null && pos + 1 < data.length && data[pos] === 0 && data[pos + 1] === 0) {
        closed = makeNode(data, top.tagClass, top.tagNumber, true, top.offset, top.headerLength, top.contentStart, pos, pos + 2, true, top.children);
        pos += 2;
      } else if (top.contentEnd === null && pos >= data.length) {
        throw new PkiEncodingError(
          "PKI_ASN1_TRUNCATED",
          `pkinative: the indefinite-length ${tagLabel(top.tagClass, top.tagNumber)} at offset ${top.offset} has no end-of-contents marker \u2014 the input is incomplete`,
          top.offset
        );
      }
      if (closed !== null) {
        frames.pop();
        const parent2 = frames[frames.length - 1];
        if (parent2 === void 0) return closed;
        parent2.children.push(closed);
        continue;
      }
    }
    const end = top?.contentEnd ?? data.length;
    const endIsInput = top === void 0 || top.contentEnd === null;
    const header = readHeader(view, pos, end, endIsInput, ctx);
    const label = tagLabel(header.tagClass, header.tagNumber);
    if (header.tagClass === "universal" && header.tagNumber === 0) {
      throw new PkiEncodingError(
        "PKI_ASN1_EOC_UNEXPECTED",
        `pkinative: an end-of-contents marker at offset ${pos} ${top?.contentEnd === null ? "is not the two octets 0x00 0x00" : "appears outside an indefinite-length value"} (X.690 \xA78.1.5) \u2014 the input is corrupt`,
        pos
      );
    }
    ctx.nodes++;
    enforceLimit(ctx.limits, "maxNodes", ctx.nodes, "the number of ASN.1 values");
    if (header.tagClass === "universal") {
      if (header.constructed && isPrimitiveOnly(header.tagNumber)) {
        throw new PkiEncodingError(
          "PKI_ASN1_CONSTRUCTED_FORM_INVALID",
          `pkinative: the ${label} at offset ${pos} is constructed, but X.690 encodes it in primitive form only \u2014 the input is corrupt`,
          pos
        );
      }
      if (!header.constructed && isConstructedOnly(header.tagNumber)) {
        throw new PkiEncodingError(
          "PKI_ASN1_CONSTRUCTED_FORM_INVALID",
          `pkinative: the ${label} at offset ${pos} is primitive, but X.690 encodes it in constructed form only \u2014 the input is corrupt`,
          pos
        );
      }
      if (header.constructed && isStringTag(header.tagNumber)) {
        if (ctx.rules === "der") {
          throw new PkiEncodingError(
            "PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN",
            `pkinative: the ${label} at offset ${pos} is in constructed form, which DER forbids (X.690 \xA710.2) \u2014 decode with encodingRules: 'ber' if the input is BER`,
            pos
          );
        }
        noteBer(ctx, "constructed string", pos);
      }
    }
    const contentStart = pos + header.headerLength;
    if (header.length === null) {
      enforceLimit(ctx.limits, "maxDepth", frames.length + 1, "the nesting depth");
      frames.push({ tagClass: header.tagClass, tagNumber: header.tagNumber, offset: pos, headerLength: header.headerLength, contentStart, contentEnd: null, children: [] });
      pos = contentStart;
      continue;
    }
    const contentEnd = contentStart + header.length;
    if (contentEnd > end) {
      if (endIsInput) {
        throw new PkiEncodingError(
          "PKI_ASN1_TRUNCATED",
          `pkinative: the ${label} at offset ${pos} declares ${header.length} content octets but only ${end - contentStart} remain in the input \u2014 the input is incomplete`,
          pos
        );
      }
      throw new PkiEncodingError(
        "PKI_ASN1_LENGTH_OVERFLOW",
        `pkinative: the ${label} at offset ${pos} declares ${header.length} content octets, which overruns its enclosing value by ${contentEnd - end} \u2014 the input is corrupt or crafted`,
        pos
      );
    }
    if (header.constructed) {
      enforceLimit(ctx.limits, "maxDepth", frames.length + 1, "the nesting depth");
      frames.push({ tagClass: header.tagClass, tagNumber: header.tagNumber, offset: pos, headerLength: header.headerLength, contentStart, contentEnd, children: [] });
      pos = contentStart;
      continue;
    }
    const node = makeNode(data, header.tagClass, header.tagNumber, false, pos, header.headerLength, contentStart, contentEnd, contentEnd, false, []);
    pos = contentEnd;
    const parent = frames[frames.length - 1];
    if (parent === void 0) return node;
    parent.children.push(node);
  }
}
function decodeWithContext(data, ctx, allowTrailingData) {
  enforceLimit(ctx.limits, "maxInputBytes", data.length, "the input size");
  const node = decodeValueAt(data, 0, ctx);
  const end = node.bytes.length;
  if (end !== data.length && !allowTrailingData) {
    throw new PkiEncodingError(
      "PKI_ASN1_TRAILING_DATA",
      `pkinative: ${data.length - end} byte(s) follow the outermost value at offset ${end} \u2014 pass exactly one DER object, split concatenated objects with decodeAsn1Sequence, or set allowTrailingData`,
      end
    );
  }
  return node;
}
function decodeAsn1(data, options) {
  const bytes = assertBytes(data, "decodeAsn1 input");
  const ctx = createAsn1Context(options);
  const allow = options?.allowTrailingData;
  if (allow !== void 0 && typeof allow !== "boolean") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: allowTrailingData must be a boolean, got ${typeof allow}`);
  }
  return decodeWithContext(bytes, ctx, allow === true);
}
function decodeAsn1Sequence(data, options) {
  const bytes = assertBytes(data, "decodeAsn1Sequence input");
  const ctx = createAsn1Context(options);
  enforceLimit(ctx.limits, "maxInputBytes", bytes.length, "the input size");
  const out = [];
  const view = byteView(bytes);
  let pos = 0;
  while (pos < bytes.length) {
    const node = decodeValueIn(view, bytes, pos, ctx);
    out.push(node);
    pos = node.offset + node.bytes.length;
  }
  return Object.freeze(out);
}

// src/core/text.ts
var CHUNK = 4096;
function _fromCodeUnits(units) {
  let out = "";
  for (let i = 0; i < units.length; i += CHUNK) {
    out += String.fromCharCode(...units.slice(i, i + CHUNK));
  }
  return out;
}
function _pushCodePoint(units, cp) {
  if (cp > 65535) {
    const v = cp - 65536;
    units.push(55296 + (v >> 10), 56320 + (v & 1023));
  } else {
    units.push(cp);
  }
}
function decodeUtf8(bytes) {
  const units = [];
  const view = byteView(bytes);
  let i = 0;
  while (i < bytes.length) {
    const b0 = view.getUint8(i);
    if (b0 < 128) {
      units.push(b0);
      i += 1;
      continue;
    }
    let need;
    let cp;
    let lower = 128;
    let upper = 191;
    if (b0 >= 194 && b0 <= 223) {
      need = 1;
      cp = b0 & 31;
    } else if (b0 >= 224 && b0 <= 239) {
      need = 2;
      cp = b0 & 15;
      if (b0 === 224) lower = 160;
      if (b0 === 237) upper = 159;
    } else if (b0 >= 240 && b0 <= 244) {
      need = 3;
      cp = b0 & 7;
      if (b0 === 240) lower = 144;
      if (b0 === 244) upper = 143;
    } else {
      return null;
    }
    for (let k = 1; k <= need; k++) {
      if (i + k >= bytes.length) return null;
      const b = view.getUint8(i + k);
      const lo = k === 1 ? lower : 128;
      const hi = k === 1 ? upper : 191;
      if (b < lo || b > hi) return null;
      cp = cp << 6 | b & 63;
    }
    _pushCodePoint(units, cp);
    i += need + 1;
  }
  return _fromCodeUnits(units);
}
function decodeUcs2Be(bytes) {
  if (bytes.length % 2 !== 0) return null;
  const units = [];
  const view = byteView(bytes);
  for (let i = 0; i < bytes.length; i += 2) {
    const unit = view.getUint16(i);
    if (unit >= 55296 && unit <= 57343) return null;
    units.push(unit);
  }
  return _fromCodeUnits(units);
}
function decodeUcs4Be(bytes) {
  if (bytes.length % 4 !== 0) return null;
  const units = [];
  const view = byteView(bytes);
  for (let i = 0; i < bytes.length; i += 4) {
    const cp = view.getUint32(i);
    if (cp > 1114111 || cp >= 55296 && cp <= 57343) return null;
    _pushCodePoint(units, cp);
  }
  return _fromCodeUnits(units);
}
function decodeLatin1(bytes) {
  return _fromCodeUnits(Array.from(bytes));
}
function decodeAsciiSubset(bytes, allowed) {
  const units = [];
  for (const b of bytes) {
    if (!allowed(b)) return null;
    units.push(b);
  }
  return _fromCodeUnits(units);
}
function firstOctetOutside(bytes, allowed) {
  for (const octet of bytes) {
    if (!allowed(octet)) return octet;
  }
  return -1;
}
function isPrintableOctet(b) {
  return b >= 65 && b <= 90 || b >= 97 && b <= 122 || b >= 48 && b <= 57 || b === 32 || b === 39 || b === 40 || b === 41 || b === 43 || b === 44 || b === 45 || b === 46 || b === 47 || b === 58 || b === 61 || b === 63;
}
function isIa5Octet(b) {
  return b < 128;
}
function isVisibleOctet(b) {
  return b >= 32 && b <= 126;
}
function isNumericOctet(b) {
  return b >= 48 && b <= 57 || b === 32;
}
function encodeUtf8(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    let cp = text.charCodeAt(i);
    if (cp >= 55296 && cp <= 56319) {
      const low = text.charCodeAt(i + 1);
      if (!(low >= 56320 && low <= 57343)) return null;
      cp = 65536 + (cp - 55296 << 10) + (low - 56320);
      i++;
    } else if (cp >= 56320 && cp <= 57343) {
      return null;
    }
    if (cp < 128) out.push(cp);
    else if (cp < 2048) out.push(192 | cp >> 6, 128 | cp & 63);
    else if (cp < 65536) out.push(224 | cp >> 12, 128 | cp >> 6 & 63, 128 | cp & 63);
    else out.push(240 | cp >> 18, 128 | cp >> 12 & 63, 128 | cp >> 6 & 63, 128 | cp & 63);
  }
  return Uint8Array.from(out);
}

// src/asn1/asn1-read.ts
function assertNode(node, reader) {
  const candidate = node;
  if (typeof node !== "object" || candidate === null || !(candidate.content instanceof Uint8Array) || !Array.isArray(candidate.children) || typeof candidate.tagNumber !== "number") {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: ${reader} expects a node returned by decodeAsn1, got ${node === null ? "null" : typeof node}`);
  }
  return node;
}
function expectUniversal(node, tagNumber) {
  if (node.tagClass === "universal" && node.tagNumber !== tagNumber) {
    throw new PkiEncodingError(
      "PKI_ASN1_UNEXPECTED_TAG",
      `pkinative: expected ${tagLabel("universal", tagNumber)} at offset ${node.offset}, found ${tagLabel(node.tagClass, node.tagNumber)} \u2014 check that the input is the structure this reader expects`,
      node.offset
    );
  }
}
function expectPrimitive(node, what) {
  if (node.constructed) {
    throw new PkiEncodingError(
      "PKI_ASN1_CONSTRUCTED_FORM_INVALID",
      `pkinative: the ${what} at offset ${node.offset} is constructed, but X.690 encodes it in primitive form only`,
      node.offset
    );
  }
}
function stringContent(node, ctx, segmentTag, what) {
  if (!node.constructed) return node.content;
  if (ctx.rules === "der") {
    throw new PkiEncodingError(
      "PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN",
      `pkinative: the ${what} at offset ${node.offset} is in constructed form, which DER forbids (X.690 \xA710.2) \u2014 decode with encodingRules: 'ber' if the input is BER`,
      node.offset
    );
  }
  noteBer(ctx, "constructed string", node.offset);
  const segments = [];
  const stack = [...node.children].reverse();
  while (stack.length > 0) {
    const segment = stack.pop();
    if (segment.tagClass !== "universal" || segment.tagNumber !== segmentTag) {
      throw new PkiEncodingError(
        "PKI_ASN1_UNEXPECTED_TAG",
        `pkinative: a segment of the constructed ${what} at offset ${node.offset} is ${tagLabel(segment.tagClass, segment.tagNumber)}, not ${tagLabel("universal", segmentTag)} (X.690 \xA78.7.3)`,
        segment.offset
      );
    }
    if (segment.constructed) {
      for (let i = segment.children.length - 1; i >= 0; i--) stack.push(segment.children[i]);
      continue;
    }
    segments.push(segment.content);
    enforceLimit(ctx.limits, "maxBerSegments", segments.length, `the segments of the constructed ${what}`);
  }
  return concatBytes(segments);
}
function _readBoolean(node, ctx) {
  expectUniversal(node, TAG_BOOLEAN);
  expectPrimitive(node, "BOOLEAN");
  if (node.contentLength !== 1) {
    throw new PkiEncodingError(
      "PKI_ASN1_BOOLEAN_INVALID",
      `pkinative: the BOOLEAN at offset ${node.offset} has ${node.contentLength} content octets; X.690 \xA78.2.1 requires exactly one`,
      node.offset
    );
  }
  const value = byteView(node.content).getUint8(0);
  if (value !== 0 && value !== 255) {
    if (ctx.rules === "der") {
      throw new PkiEncodingError(
        "PKI_ASN1_BOOLEAN_INVALID",
        `pkinative: the BOOLEAN at offset ${node.offset} encodes TRUE as 0x${value.toString(16).padStart(2, "0")}; DER requires 0xFF (X.690 \xA711.1)`,
        node.offset
      );
    }
    noteBer(ctx, "non-canonical BOOLEAN", node.offset);
  }
  return value !== 0;
}
function readBoolean(node, options) {
  return _readBoolean(assertNode(node, "readBoolean"), createAsn1Context(options));
}
function _readInteger(node, ctx) {
  expectUniversal(node, TAG_INTEGER);
  expectPrimitive(node, "INTEGER");
  const content = node.content;
  if (content.length === 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_INTEGER_INVALID",
      `pkinative: the INTEGER at offset ${node.offset} has no content octet (X.690 \xA78.3.1)`,
      node.offset
    );
  }
  enforceLimit(ctx.limits, "maxIntegerBytes", content.length, "the INTEGER content length");
  const view = byteView(content);
  const first = view.getUint8(0);
  if (content.length > 1) {
    const second = view.getUint8(1);
    if (first === 0 && (second & 128) === 0 || first === 255 && (second & 128) !== 0) {
      throw new PkiEncodingError(
        "PKI_ASN1_INTEGER_INVALID",
        `pkinative: the INTEGER at offset ${node.offset} is not in minimal two's complement form (X.690 \xA78.3.2) \u2014 the encoder is broken`,
        node.offset
      );
    }
  }
  let hex3 = "";
  for (const octet of content) hex3 += octet.toString(16).padStart(2, "0");
  let value = BigInt(`0x${hex3}`);
  if ((first & 128) !== 0) value -= 1n << BigInt(content.length * 8);
  return value;
}
function readInteger(node, options) {
  return _readInteger(assertNode(node, "readInteger"), createAsn1Context(options));
}
function _readSmallInteger(node, ctx) {
  const value = _readInteger(node, ctx);
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < -BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new PkiEncodingError(
      "PKI_ASN1_INTEGER_UNREPRESENTABLE",
      `pkinative: the INTEGER at offset ${node.offset} is outside \xB1(2^53 \u2212 1) \u2014 read it with readInteger to get a bigint`,
      node.offset
    );
  }
  return Number(value);
}
function readSmallInteger(node) {
  return _readSmallInteger(assertNode(node, "readSmallInteger"), createAsn1Context(void 0));
}
function readNull(node) {
  const checked = assertNode(node, "readNull");
  expectUniversal(checked, TAG_NULL);
  expectPrimitive(checked, "NULL");
  if (checked.contentLength !== 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_NULL_INVALID",
      `pkinative: the NULL at offset ${checked.offset} has ${checked.contentLength} content octets; X.690 \xA78.8.2 requires none`,
      checked.offset
    );
  }
  return null;
}
function bitStringFromContent(content, offset, ctx) {
  if (content.length === 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_BIT_STRING_INVALID",
      `pkinative: the BIT STRING at offset ${offset} has no initial octet; X.690 \xA78.6.2.2 requires the unused-bits count`,
      offset
    );
  }
  const view = byteView(content);
  const unusedBits = view.getUint8(0);
  if (unusedBits > 7) {
    throw new PkiEncodingError(
      "PKI_ASN1_BIT_STRING_INVALID",
      `pkinative: the BIT STRING at offset ${offset} declares ${unusedBits} unused bits; X.690 \xA78.6.2.2 allows 0 to 7`,
      offset
    );
  }
  if (content.length === 1 && unusedBits !== 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_BIT_STRING_INVALID",
      `pkinative: the empty BIT STRING at offset ${offset} declares ${unusedBits} unused bits; X.690 \xA78.6.2.3 requires 0`,
      offset
    );
  }
  if (unusedBits !== 0 && (view.getUint8(content.length - 1) & (1 << unusedBits) - 1) !== 0) {
    if (ctx.rules === "der") {
      throw new PkiEncodingError(
        "PKI_ASN1_BIT_STRING_INVALID",
        `pkinative: the BIT STRING at offset ${offset} has non-zero unused bits; DER requires them to be zero (X.690 \xA711.2.1)`,
        offset
      );
    }
    noteBer(ctx, "non-zero BIT STRING padding", offset);
  }
  return Object.freeze({ bytes: content.subarray(1), unusedBits });
}
function _readBitString(node, ctx) {
  expectUniversal(node, TAG_BIT_STRING);
  if (!node.constructed) return bitStringFromContent(node.content, node.offset, ctx);
  if (ctx.rules === "der") {
    throw new PkiEncodingError(
      "PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN",
      `pkinative: the BIT STRING at offset ${node.offset} is in constructed form, which DER forbids (X.690 \xA710.2) \u2014 decode with encodingRules: 'ber' if the input is BER`,
      node.offset
    );
  }
  noteBer(ctx, "constructed string", node.offset);
  const parts = [];
  let unusedBits = 0;
  const stack = [...node.children].reverse();
  while (stack.length > 0) {
    const segment = stack.pop();
    if (segment.tagClass !== "universal" || segment.tagNumber !== TAG_BIT_STRING) {
      throw new PkiEncodingError(
        "PKI_ASN1_UNEXPECTED_TAG",
        `pkinative: a segment of the constructed BIT STRING at offset ${node.offset} is ${tagLabel(segment.tagClass, segment.tagNumber)}, not BIT STRING (X.690 \xA78.6.4)`,
        segment.offset
      );
    }
    if (segment.constructed) {
      for (let i = segment.children.length - 1; i >= 0; i--) stack.push(segment.children[i]);
      continue;
    }
    if (unusedBits !== 0) {
      throw new PkiEncodingError(
        "PKI_ASN1_BIT_STRING_INVALID",
        `pkinative: a segment before the last one of the BIT STRING at offset ${node.offset} declares unused bits; X.690 \xA78.6.4 allows them only in the last segment`,
        segment.offset
      );
    }
    const piece = bitStringFromContent(segment.content, segment.offset, ctx);
    parts.push(piece.bytes);
    unusedBits = piece.unusedBits;
    enforceLimit(ctx.limits, "maxBerSegments", parts.length, "the segments of the constructed BIT STRING");
  }
  return Object.freeze({ bytes: concatBytes(parts), unusedBits });
}
function readBitString(node, options) {
  return _readBitString(assertNode(node, "readBitString"), createAsn1Context(options));
}
function _readOctetString(node, ctx) {
  expectUniversal(node, TAG_OCTET_STRING);
  return stringContent(node, ctx, TAG_OCTET_STRING, "OCTET STRING");
}
function readOctetString(node, options) {
  return _readOctetString(assertNode(node, "readOctetString"), createAsn1Context(options));
}
function invalidString(node, type, why) {
  return new PkiEncodingError(
    "PKI_ASN1_STRING_INVALID",
    `pkinative: the ${tagLabel("universal", STRING_TAGS[type])} at offset ${node.offset} ${why} \u2014 the issuer encoded it wrongly`,
    node.offset
  );
}
function _readString(node, ctx, implicitType, path) {
  let type;
  if (node.tagClass === "universal") {
    type = stringTypeOfTag(node.tagNumber);
    if (type === void 0) {
      throw new PkiEncodingError(
        "PKI_ASN1_UNEXPECTED_TAG",
        `pkinative: expected a character string at offset ${node.offset}, found ${tagLabel(node.tagClass, node.tagNumber)}`,
        node.offset
      );
    }
  } else {
    type = implicitType;
    if (type === void 0) {
      throw new PkiError(
        "PKI_API_MISUSE",
        `pkinative: the value at offset ${node.offset} carries the implicit tag ${tagLabel(node.tagClass, node.tagNumber)}; pass stringType to say which string type it is`
      );
    }
  }
  const raw = stringContent(node, ctx, TAG_OCTET_STRING, tagLabel("universal", STRING_TAGS[type]));
  let value;
  switch (type) {
    case "utf8":
      value = decodeUtf8(raw);
      if (value === null) throw invalidString(node, type, "is not well-formed UTF-8 (RFC 3629)");
      break;
    case "bmp":
      value = decodeUcs2Be(raw);
      if (value === null) throw invalidString(node, type, "has an odd length or a surrogate code unit, which UCS-2 does not allow");
      break;
    case "universal":
      value = decodeUcs4Be(raw);
      if (value === null) throw invalidString(node, type, "has a length that is not a multiple of four or a value outside the Unicode scalar range");
      break;
    case "teletex":
      value = decodeLatin1(raw);
      ctx.emitter.emit(teletexAsLatin1Diagnostic(path, node.offset));
      break;
    case "printable": {
      value = decodeAsciiSubset(raw, isIa5Octet);
      if (value === null) throw invalidString(node, type, "contains an octet above 0x7F");
      const outside = firstOctetOutside(raw, isPrintableOctet);
      if (outside >= 0) ctx.emitter.emit(printableStringCharsetDiagnostic(path, String.fromCharCode(outside), node.offset));
      break;
    }
    case "ia5":
      value = decodeAsciiSubset(raw, isIa5Octet);
      if (value === null) throw invalidString(node, type, "contains an octet above 0x7F");
      break;
    case "visible":
      value = decodeAsciiSubset(raw, isVisibleOctet);
      if (value === null) throw invalidString(node, type, "contains an octet outside printing ASCII");
      break;
    case "numeric":
      value = decodeAsciiSubset(raw, isNumericOctet);
      if (value === null) throw invalidString(node, type, "contains an octet other than a digit or a space");
      break;
  }
  return Object.freeze({ stringType: type, value, raw });
}
function readString(node, options) {
  const checked = assertNode(node, "readString");
  const ctx = createAsn1Context(options);
  const implicitType = options?.stringType;
  if (implicitType !== void 0 && !(implicitType in STRING_TAGS)) {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: stringType must be one of ${Object.keys(STRING_TAGS).join(", ")}, got ${String(implicitType)}`);
  }
  return _readString(checked, ctx, implicitType, "");
}

// src/asn1/asn1-time.ts
var MAX_TIME_OCTETS = 64;
var UTC_TIME = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:Z|[+-]\d{4})$/;
var GENERALIZED_TIME = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:([.,])(\d+))?(?:Z|[+-]\d{4})$/;
function zoneOf(text) {
  return text.endsWith("Z") ? "Z" : text.slice(-5);
}
function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
function daysInMonth(year, month) {
  return month === 2 ? isLeapYear(year) ? 29 : 28 : month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}
function invalidTime(node, type, text, why) {
  return new PkiEncodingError(
    "PKI_ASN1_TIME_INVALID",
    `pkinative: the ${type} "${text}" at offset ${node.offset} ${why} \u2014 RFC 5280 and X.690 leave no lenient interpretation`,
    node.offset
  );
}
function toEpoch(node, type, text, f) {
  if (f.month < 1 || f.month > 12) throw invalidTime(node, type, text, `names month ${f.month}`);
  if (f.day < 1 || f.day > daysInMonth(f.year, f.month)) throw invalidTime(node, type, text, `names day ${f.day} of a month that has ${daysInMonth(f.year, f.month)}`);
  if (f.hour > 23) throw invalidTime(node, type, text, `names hour ${f.hour}`);
  if (f.minute > 59) throw invalidTime(node, type, text, `names minute ${f.minute}`);
  if (f.second > 59) throw invalidTime(node, type, text, `names second ${f.second}`);
  let offsetMinutes = 0;
  if (f.zone !== "Z") {
    const hours = Number(f.zone.slice(1, 3));
    const minutes = Number(f.zone.slice(3, 5));
    if (hours > 23 || minutes > 59) throw invalidTime(node, type, text, `has the impossible offset ${f.zone}`);
    offsetMinutes = (f.zone[0] === "-" ? -1 : 1) * (hours * 60 + minutes);
  }
  const date = /* @__PURE__ */ new Date(0);
  date.setUTCFullYear(f.year, f.month - 1, f.day);
  date.setUTCHours(f.hour, f.minute, f.second, f.millisecond);
  return date.getTime() - offsetMinutes * 6e4;
}
function _readTime(node, ctx, implicitType) {
  let type;
  if (node.tagClass === "universal") {
    if (node.tagNumber === TAG_UTC_TIME) type = "UTCTime";
    else if (node.tagNumber === TAG_GENERALIZED_TIME) type = "GeneralizedTime";
    else {
      throw new PkiEncodingError(
        "PKI_ASN1_UNEXPECTED_TAG",
        `pkinative: expected UTCTime or GeneralizedTime at offset ${node.offset}, found ${tagLabel(node.tagClass, node.tagNumber)}`,
        node.offset
      );
    }
  } else if (implicitType === void 0) {
    throw new PkiError(
      "PKI_API_MISUSE",
      `pkinative: the value at offset ${node.offset} carries the implicit tag ${tagLabel(node.tagClass, node.tagNumber)}; pass timeType to say which time type it is`
    );
  } else {
    type = implicitType;
  }
  const raw = stringContent(node, ctx, TAG_OCTET_STRING, type);
  if (raw.length > MAX_TIME_OCTETS) {
    throw invalidTime(
      node,
      type,
      `${raw.length} octets`,
      `is longer than the ${MAX_TIME_OCTETS} octets any well-formed ${type} needs`
    );
  }
  const text = String.fromCharCode(...raw);
  if (type === "UTCTime") {
    const m2 = UTC_TIME.exec(text);
    if (m2 === null) throw invalidTime(node, type, text, "is not YYMMDDHHMM[SS](Z|\xB1hhmm)");
    const [, yy, mo2, dd2, hh2, mi2, ss2] = m2;
    const zone2 = zoneOf(text);
    if (ss2 === void 0 || zone2 !== "Z") {
      if (ctx.rules === "der") throw invalidTime(node, type, text, "omits the seconds or the Z; DER requires YYMMDDHHMMSSZ (X.690 \xA711.8)");
      noteBer(ctx, "UTCTime without seconds or with an offset", node.offset);
    }
    const twoDigit = Number(yy);
    const epochMilliseconds2 = toEpoch(node, type, text, {
      year: twoDigit >= 50 ? 1900 + twoDigit : 2e3 + twoDigit,
      month: Number(mo2),
      day: Number(dd2),
      hour: Number(hh2),
      minute: Number(mi2),
      second: Number(ss2 ?? "0"),
      millisecond: 0,
      zone: zone2
    });
    return Object.freeze({ type, epochMilliseconds: epochMilliseconds2, text });
  }
  const m = GENERALIZED_TIME.exec(text);
  if (m === null) throw invalidTime(node, type, text, "is not YYYYMMDDHHMM[SS[.f]](Z|\xB1hhmm)");
  const [, yyyy, mo, dd, hh, mi, ss, separator, fraction] = m;
  const zone = zoneOf(text);
  if (fraction !== void 0 && ss === void 0) throw invalidTime(node, type, text, "has a fraction without seconds");
  const nonCanonical = ss === void 0 || zone !== "Z" || separator === "," || fraction !== void 0 && fraction.endsWith("0");
  if (nonCanonical) {
    if (ctx.rules === "der") {
      throw invalidTime(node, type, text, "is not in the DER form YYYYMMDDHHMMSS[.f]Z with no trailing zero in the fraction (X.690 \xA711.7)");
    }
    noteBer(ctx, "non-canonical GeneralizedTime", node.offset);
  }
  const epochMilliseconds = toEpoch(node, type, text, {
    year: Number(yyyy),
    month: Number(mo),
    day: Number(dd),
    hour: Number(hh),
    minute: Number(mi),
    second: Number(ss ?? "0"),
    millisecond: fraction === void 0 ? 0 : Number(`${fraction}000`.slice(0, 3)),
    zone
  });
  return Object.freeze({ type, epochMilliseconds, text });
}
function readTime(node, options) {
  const checked = assertNode(node, "readTime");
  const ctx = createAsn1Context(options);
  const implicitType = options?.timeType;
  if (implicitType !== void 0 && implicitType !== "UTCTime" && implicitType !== "GeneralizedTime") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: timeType must be 'UTCTime' or 'GeneralizedTime', got ${String(implicitType)}`);
  }
  return _readTime(checked, ctx, implicitType);
}

// src/asn1/asn1-oid.ts
var EXACT_LIMIT = 70368744177663;
function _decodeOid(content, offset, ctx) {
  if (content.length === 0) {
    throw new PkiEncodingError(
      "PKI_OID_INVALID",
      `pkinative: the OBJECT IDENTIFIER at offset ${offset} has no content octet (X.690 \xA78.19.2)`,
      offset
    );
  }
  enforceLimit(ctx.limits, "maxOidBytes", content.length, "the OBJECT IDENTIFIER content length");
  const arcs = [];
  let value = 0;
  let big = null;
  let inArc = false;
  for (const octet of content) {
    if (!inArc && octet === 128) {
      throw new PkiEncodingError(
        "PKI_OID_INVALID",
        `pkinative: a subidentifier of the OBJECT IDENTIFIER at offset ${offset} starts with 0x80, a non-minimal form X.690 \xA78.19.2 forbids`,
        offset
      );
    }
    inArc = true;
    if (big === null && value > EXACT_LIMIT) big = BigInt(value);
    if (big === null) value = value * 128 + (octet & 127);
    else big = big * 128n + BigInt(octet & 127);
    if ((octet & 128) !== 0) continue;
    if (arcs.length === 0) {
      if (big === null) {
        if (value < 40) arcs.push("0", String(value));
        else if (value < 80) arcs.push("1", String(value - 40));
        else arcs.push("2", String(value - 80));
      } else {
        arcs.push("2", String(big - 80n));
      }
    } else {
      arcs.push(big === null ? String(value) : String(big));
    }
    value = 0;
    big = null;
    inArc = false;
  }
  if (inArc) {
    throw new PkiEncodingError(
      "PKI_OID_INVALID",
      `pkinative: the OBJECT IDENTIFIER at offset ${offset} ends inside a subidentifier \u2014 the input is truncated or corrupt`,
      offset
    );
  }
  return arcs.join(".");
}
function decodeOid(content, options) {
  return _decodeOid(assertBytes(content, "decodeOid content"), 0, createAsn1Context(options));
}
function _readObjectIdentifier(node, ctx) {
  expectUniversal(node, TAG_OID);
  if (node.constructed) {
    throw new PkiEncodingError(
      "PKI_ASN1_CONSTRUCTED_FORM_INVALID",
      `pkinative: the OBJECT IDENTIFIER at offset ${node.offset} is constructed, but X.690 encodes it in primitive form only`,
      node.offset
    );
  }
  return _decodeOid(node.content, node.offset, ctx);
}
function readObjectIdentifier(node, options) {
  return _readObjectIdentifier(assertNode(node, "readObjectIdentifier"), createAsn1Context(options));
}
var DOTTED = /^(?:[01]\.(?:[0-9]|[123][0-9])|2\.(?:0|[1-9][0-9]*))(?:\.(?:0|[1-9][0-9]*))*$/;
function isValidOid(oid) {
  return typeof oid === "string" && DOTTED.test(oid);
}
function encodeOid(oid) {
  if (typeof oid !== "string") {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: encodeOid expects a dotted-decimal string, got ${typeof oid}`);
  }
  if (!isValidOid(oid)) {
    throw new PkiEncodingError(
      "PKI_OID_INVALID",
      `pkinative: "${oid.length > 64 ? `${oid.slice(0, 61)}\u2026` : oid}" is not a dotted-decimal OID \u2014 use two or more decimal arcs without leading zeros, a first arc of 0, 1 or 2, and a second arc of at most 39 under 0 and 1`
    );
  }
  const subidentifiers = [];
  let head = null;
  for (const arc of oid.split(".")) {
    const value = BigInt(arc);
    if (head === null) head = value * 40n;
    else if (subidentifiers.length === 0) subidentifiers.push(head + value);
    else subidentifiers.push(value);
  }
  const out = [];
  for (const sub of subidentifiers) {
    const digits = [];
    let rest = sub;
    do {
      digits.unshift(Number(rest & 0x7fn));
      rest >>= 7n;
    } while (rest > 0n);
    let remaining = digits.length;
    for (const digit of digits) {
      remaining--;
      out.push(digit | (remaining > 0 ? 128 : 0));
    }
  }
  return Uint8Array.from(out);
}

// src/x509/x509-fields.ts
var REMEDIES = /* @__PURE__ */ Object.freeze({
  PKI_X509_STRUCTURE_INVALID: "check that the input is a certificate, not a CSR, a CRL or a key",
  PKI_X509_VERSION_INVALID: "the input is not a certificate version RFC 5280 defines",
  PKI_X509_NAME_INVALID: "the issuer encoded the name wrongly",
  PKI_X509_VALIDITY_INVALID: "the issuer encoded the validity period wrongly",
  PKI_X509_SPKI_INVALID: "the issuer encoded the public key wrongly",
  PKI_X509_UNIQUE_ID_INVALID: "the issuer encoded the certificate wrongly",
  PKI_X509_EXTENSIONS_EMPTY: "the issuer encoded the certificate wrongly",
  PKI_X509_EXTENSION_DUPLICATE: "which instance a verifier reads is undefined, so the certificate is refused",
  PKI_X509_EXTENSION_MALFORMED: "parse with decodeExtensions: false to keep every extension raw",
  PKI_X509_GENERAL_NAME_INVALID: "the issuer encoded the name wrongly"
});
function certificateError(code, path, offset, why) {
  return new PkiCertificateError(code, `pkinative: ${path} at offset ${offset} ${why} \u2014 ${REMEDIES[code]}`, path, offset);
}
function expectUniversalField(node, tagNumber, path, code, parentOffset) {
  const expected = tagLabel("universal", tagNumber);
  if (node === void 0) throw certificateError(code, path, parentOffset, `is missing; expected ${expected}`);
  if (node.tagClass !== "universal" || node.tagNumber !== tagNumber) {
    throw certificateError(code, path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; expected ${expected}`);
  }
  return node;
}

// src/x509/x509-algorithm.ts
var PKCS1_V15 = /* @__PURE__ */ new Set([
  "1.2.840.113549.1.1.1",
  "1.2.840.113549.1.1.2",
  "1.2.840.113549.1.1.3",
  "1.2.840.113549.1.1.4",
  "1.2.840.113549.1.1.5",
  "1.2.840.113549.1.1.11",
  "1.2.840.113549.1.1.12",
  "1.2.840.113549.1.1.13",
  "1.2.840.113549.1.1.14",
  "1.2.840.113549.1.1.15",
  "1.2.840.113549.1.1.16"
]);
function _readAlgorithmIdentifier(node, ctx, path, code, parentOffset) {
  const seq = expectUniversalField(node, TAG_SEQUENCE, path, code, parentOffset);
  if (seq.children.length > 2) {
    throw certificateError(code, path, seq.offset, `holds ${seq.children.length} values; an AlgorithmIdentifier is an OID and optional parameters`);
  }
  const oid = _readObjectIdentifier(expectUniversalField(seq.children[0], TAG_OID, `${path}.algorithm`, code, seq.offset), ctx);
  const parameters = seq.children[1];
  const isNull = parameters !== void 0 && parameters.tagClass === "universal" && parameters.tagNumber === TAG_NULL && parameters.contentLength === 0;
  if (PKCS1_V15.has(oid) && !isNull) ctx.emitter.emit(rsaParametersNotNullDiagnostic(`${path}.parameters`, seq.offset));
  const algorithm = { oid, parameters, der: seq.bytes };
  return Object.freeze(algorithm);
}

// src/x509/x509-ext-shared.ts
var MALFORMED = "PKI_X509_EXTENSION_MALFORMED";
function baseOf(input) {
  return { oid: input.oid, critical: input.critical, valueDer: input.valueDer };
}
function malformed(path, offset, why) {
  return certificateError(MALFORMED, path, offset, why);
}
function expectSequence(node, path, parentOffset) {
  return expectUniversalField(node, TAG_SEQUENCE, path, MALFORMED, parentOffset);
}
function expectNonEmpty(seq, path, what) {
  if (seq.children.length === 0) throw malformed(path, seq.offset, `holds no ${what}; the extension requires at least one`);
}
function contextFields(children, maxTag, path) {
  const fields = new Array(maxTag + 1).fill(void 0);
  let last = -1;
  for (const child of children) {
    if (child.tagClass !== "context" || child.tagNumber > maxTag || child.tagNumber <= last) {
      throw malformed(path, child.offset, `holds ${tagLabel(child.tagClass, child.tagNumber)} where only [0] to [${maxTag}], once each and in order, may appear`);
    }
    fields[child.tagNumber] = child;
    last = child.tagNumber;
  }
  return fields;
}
function readCount(node, ctx, path) {
  const value = _readInteger(node, ctx);
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw malformed(path, node.offset, `is ${String(value)}; expected an integer from 0 to 2^53 \u2212 1`);
  }
  return Number(value);
}
function bitAt(view, index) {
  return view.getUint8(index >> 3) >> 7 - (index & 7) & 1;
}
function readNamedBits(bits, names, ctx, path, offset) {
  const total = bits.bytes.length * 8 - bits.unusedBits;
  const view = byteView(bits.bytes);
  const set = [];
  for (let i = 0; i < total; i++) {
    if (bitAt(view, i) === 0) continue;
    const name = names[i];
    if (name === void 0) throw malformed(path, offset, `sets bit ${i}, beyond the ${names.length} named bits`);
    set.push(name);
  }
  if (total > 0 && bitAt(view, total - 1) === 0) ctx.emitter.emit(namedBitsTrailingZeroDiagnostic(path, offset));
  return set;
}

// src/x509/x509-name.ts
var CODE = "PKI_X509_NAME_INVALID";
function inDerSetOrder(elements) {
  for (let k = 1; k < elements.length; k++) {
    if (compareOctets(elements[k - 1].bytes, elements[k].bytes) > 0) return false;
  }
  return true;
}
function readRdn(set, ctx, rdnPath, budget) {
  if (!set.constructed || set.children.length === 0) {
    throw certificateError(CODE, rdnPath, set.offset, "is an empty relative distinguished name; RFC 5280 requires at least one attribute");
  }
  const atvs = [];
  for (let j = 0; j < set.children.length; j++) {
    budget.count++;
    enforceLimit(ctx.limits, "maxNameAttributes", budget.count, `the attributes of ${budget.scope}`);
    const atvPath = `${rdnPath}[${j}]`;
    const atv = expectUniversalField(set.children[j], TAG_SEQUENCE, atvPath, CODE, set.offset);
    if (atv.children.length !== 2) {
      throw certificateError(CODE, atvPath, atv.offset, `holds ${atv.children.length} values; an AttributeTypeAndValue is a type OID and one value`);
    }
    const type = _readObjectIdentifier(expectUniversalField(atv.children[0], TAG_OID, `${atvPath}.type`, CODE, atv.offset), ctx);
    const valueNode = atv.children[1];
    const value = valueNode.tagClass === "universal" && stringTypeOfTag(valueNode.tagNumber) !== void 0 ? _readString(valueNode, ctx, void 0, `${atvPath}.value`) : void 0;
    const attribute = { type, value, valueDer: valueNode.bytes };
    atvs.push(Object.freeze(attribute));
  }
  if (!inDerSetOrder(set.children)) ctx.emitter.emit(rdnSetNotSortedDiagnostic(rdnPath, set.offset));
  return Object.freeze(atvs);
}
function _readName(node, ctx, path, parentOffset) {
  const seq = expectUniversalField(node, TAG_SEQUENCE, path, CODE, parentOffset);
  const rdns = [];
  const budget = { count: 0, scope: path };
  for (let i = 0; i < seq.children.length; i++) {
    const rdnPath = `${path}.rdns[${i}]`;
    rdns.push(readRdn(expectUniversalField(seq.children[i], TAG_SET, rdnPath, CODE, seq.offset), ctx, rdnPath, budget));
  }
  const name = { rdns: Object.freeze(rdns), der: seq.bytes };
  return Object.freeze(name);
}
function _readRelativeDistinguishedName(node, ctx, path) {
  return readRdn(node, ctx, path, { count: 0, scope: path });
}

// src/x509/x509-general-name.ts
var CODE2 = "PKI_X509_GENERAL_NAME_INVALID";
function formatIpv4(bytes) {
  return bytes.join(".");
}
function formatIpv6(bytes) {
  const groups = [];
  const view = byteView(bytes);
  for (let i = 0; i < 16; i += 2) groups.push(view.getUint16(i));
  let bestStart = 0;
  let bestLength = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex3 = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex3.join(":");
  return `${hex3.slice(0, bestStart).join(":")}::${hex3.slice(bestStart + bestLength).join(":")}`;
}
function readIpAddress(node, ctx, path, inNameConstraints) {
  const bytes = stringContent(node, ctx, TAG_OCTET_STRING, "OCTET STRING");
  const half = inNameConstraints ? bytes.length / 2 : bytes.length;
  if (half !== 4 && half !== 16 || inNameConstraints && bytes.length % 2 !== 0) {
    throw certificateError(CODE2, path, node.offset, inNameConstraints ? `is an iPAddress of ${bytes.length} octets; in name constraints it is 8 (IPv4 and mask) or 32 (IPv6 and mask)` : `is an iPAddress of ${bytes.length} octets; it is 4 (IPv4) or 16 (IPv6)`);
  }
  const format = half === 4 ? formatIpv4 : formatIpv6;
  const name = {
    kind: "iPAddress",
    version: half === 4 ? 4 : 6,
    address: format(bytes.subarray(0, half)),
    mask: inNameConstraints ? format(bytes.subarray(half)) : void 0,
    bytes,
    der: node.bytes
  };
  return Object.freeze(name);
}
function _readGeneralName(node, ctx, path, inNameConstraints) {
  if (node.tagClass !== "context") {
    throw certificateError(CODE2, path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; a GeneralName carries a context-specific tag [0] to [8]`);
  }
  const der = node.bytes;
  switch (node.tagNumber) {
    case 0: {
      if (!node.constructed || node.children.length !== 2) {
        throw certificateError(CODE2, path, node.offset, "is not an otherName: a type-id OID followed by a value under an explicit [0] tag");
      }
      const typeNode = node.children[0];
      const wrapper = node.children[1];
      if (typeNode.tagClass !== "universal" || typeNode.tagNumber !== TAG_OID) {
        throw certificateError(CODE2, `${path}.typeId`, typeNode.offset, `is ${tagLabel(typeNode.tagClass, typeNode.tagNumber)}; expected OBJECT IDENTIFIER`);
      }
      if (wrapper.tagClass !== "context" || wrapper.tagNumber !== 0 || !wrapper.constructed || wrapper.children.length !== 1) {
        throw certificateError(CODE2, `${path}.value`, wrapper.offset, "is not one value under an explicit [0] tag");
      }
      const name = { kind: "otherName", typeId: _readObjectIdentifier(typeNode, ctx), value: wrapper.children[0], der };
      return Object.freeze(name);
    }
    case 1:
    case 2:
    case 6: {
      const value = decodeAsciiSubset(stringContent(node, ctx, TAG_OCTET_STRING, "IA5String"), isIa5Octet);
      if (value === null) {
        throw certificateError(CODE2, path, node.offset, "contains an octet above 0x7F; IA5String names are ASCII, and internationalized names are not decoded before 0.5");
      }
      const kind = node.tagNumber === 1 ? "rfc822Name" : node.tagNumber === 2 ? "dNSName" : "uniformResourceIdentifier";
      const name = { kind, value, der };
      return Object.freeze(name);
    }
    case 3:
    case 5: {
      const kind = node.tagNumber === 3 ? "x400Address" : "ediPartyName";
      if (!node.constructed) throw certificateError(CODE2, path, node.offset, `is primitive; ${kind} is a constructed type`);
      const name = { kind, value: node, der };
      return Object.freeze(name);
    }
    case 4: {
      if (!node.constructed || node.children.length !== 1) {
        throw certificateError(CODE2, path, node.offset, "is not a directoryName: one Name under an explicit [4] tag");
      }
      const name = { kind: "directoryName", name: _readName(node.children[0], ctx, `${path}.directoryName`, node.offset), der };
      return Object.freeze(name);
    }
    case 7:
      return readIpAddress(node, ctx, path, inNameConstraints);
    case 8: {
      if (node.constructed) throw certificateError(CODE2, path, node.offset, "is constructed; a registeredID is a primitive OBJECT IDENTIFIER");
      const name = { kind: "registeredID", oid: _readObjectIdentifier(node, ctx), der };
      return Object.freeze(name);
    }
    default:
      throw certificateError(CODE2, path, node.offset, `carries the tag [${node.tagNumber}]; GeneralName defines [0] to [8]`);
  }
}
function _readGeneralNames(node, ctx, path, inNameConstraints) {
  return _readGeneralNameList(expectUniversalField(node, TAG_SEQUENCE, path, CODE2, node.offset), ctx, path, inNameConstraints);
}
function _readGeneralNameList(container, ctx, path, inNameConstraints) {
  if (!container.constructed) {
    throw certificateError(CODE2, path, container.offset, "is primitive; GeneralNames is a constructed SEQUENCE OF GeneralName");
  }
  enforceLimit(ctx.limits, "maxGeneralNames", container.children.length, `the names of ${path}`);
  const names = [];
  for (let i = 0; i < container.children.length; i++) {
    names.push(_readGeneralName(container.children[i], ctx, `${path}[${i}]`, inNameConstraints));
  }
  return Object.freeze(names);
}

// src/x509/x509-ext-constraints.ts
var KEY_USAGES = [
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly"
];
function defaultEncoded(ctx, path, offset, value) {
  ctx.emitter.emit(defaultEncodedDiagnostic(path, value, offset));
}
function decodeBasicConstraints(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  let index = 0;
  let cA = false;
  const first = seq.children[0];
  if (first !== void 0 && first.tagClass === "universal" && first.tagNumber === TAG_BOOLEAN) {
    cA = _readBoolean(first, ctx);
    if (!cA) defaultEncoded(ctx, `${path}.cA`, first.offset, "FALSE");
    index = 1;
  }
  let pathLenConstraint;
  const second = seq.children[index];
  if (second !== void 0) {
    const lengthPath = `${path}.pathLenConstraint`;
    pathLenConstraint = readCount(expectUniversalField(second, TAG_INTEGER, lengthPath, MALFORMED, seq.offset), ctx, lengthPath);
    index++;
  }
  if (index !== seq.children.length) {
    throw malformed(path, seq.offset, `holds ${seq.children.length} values; BasicConstraints is an optional cA flag and an optional pathLenConstraint`);
  }
  if (pathLenConstraint !== void 0 && !cA) ctx.emitter.emit(pathLenWithoutCaDiagnostic());
  const extension = { ...baseOf(input), kind: "basicConstraints", cA, pathLenConstraint };
  return Object.freeze(extension);
}
function decodeKeyUsage(input) {
  const { node, ctx, path } = input;
  const bitsNode = expectUniversalField(node, TAG_BIT_STRING, path, MALFORMED, node.offset);
  const bits = _readBitString(bitsNode, ctx);
  const usages = readNamedBits(bits, KEY_USAGES, ctx, path, bitsNode.offset);
  if (usages.length === 0) ctx.emitter.emit(keyUsageEmptyDiagnostic());
  const extension = { ...baseOf(input), kind: "keyUsage", usages: Object.freeze(usages), bits };
  return Object.freeze(extension);
}
function decodeExtendedKeyUsage(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  expectNonEmpty(seq, path, "KeyPurposeId");
  const purposes = seq.children.map((child, i) => _readObjectIdentifier(expectUniversalField(child, TAG_OID, `${path}[${i}]`, MALFORMED, seq.offset), ctx));
  const extension = { ...baseOf(input), kind: "extendedKeyUsage", purposes: Object.freeze(purposes) };
  return Object.freeze(extension);
}
function readSubtree(node, ctx, path) {
  const seq = expectSequence(node, path, node.offset);
  const baseNode = seq.children[0];
  if (baseNode === void 0) throw malformed(path, seq.offset, "holds no base; a GeneralSubtree is a GeneralName and optional bounds");
  const base = _readGeneralName(baseNode, ctx, `${path}.base`, true);
  const [minimumNode, maximumNode] = contextFields(seq.children.slice(1), 1, path);
  let minimum = 0;
  if (minimumNode !== void 0) {
    minimum = readCount(minimumNode, ctx, `${path}.minimum`);
    if (minimum === 0) defaultEncoded(ctx, `${path}.minimum`, minimumNode.offset, "0");
  }
  const maximum = maximumNode === void 0 ? void 0 : readCount(maximumNode, ctx, `${path}.maximum`);
  const subtree = { base, minimum, maximum };
  return Object.freeze(subtree);
}
function readSubtrees(node, ctx, path) {
  if (node === void 0) return void 0;
  if (!node.constructed || node.children.length === 0) {
    throw malformed(path, node.offset, "is not a non-empty SEQUENCE OF GeneralSubtree under its implicit tag");
  }
  enforceLimit(ctx.limits, "maxGeneralNames", node.children.length, `the subtrees of ${path}`);
  return Object.freeze(node.children.map((child, i) => readSubtree(child, ctx, `${path}[${i}]`)));
}
function decodeNameConstraints(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  const [permitted, excluded] = contextFields(seq.children, 1, path);
  const extension = {
    ...baseOf(input),
    kind: "nameConstraints",
    permittedSubtrees: readSubtrees(permitted, ctx, `${path}.permittedSubtrees`),
    excludedSubtrees: readSubtrees(excluded, ctx, `${path}.excludedSubtrees`)
  };
  if (!input.critical) ctx.emitter.emit(nameConstraintsNotCriticalDiagnostic());
  return Object.freeze(extension);
}
function decodePolicyConstraints(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  const [requireNode, inhibitNode] = contextFields(seq.children, 1, path);
  const extension = {
    ...baseOf(input),
    kind: "policyConstraints",
    requireExplicitPolicy: requireNode === void 0 ? void 0 : readCount(requireNode, ctx, `${path}.requireExplicitPolicy`),
    inhibitPolicyMapping: inhibitNode === void 0 ? void 0 : readCount(inhibitNode, ctx, `${path}.inhibitPolicyMapping`)
  };
  if (requireNode === void 0 && inhibitNode === void 0) ctx.emitter.emit(policyConstraintsEmptyDiagnostic());
  return Object.freeze(extension);
}
function decodeInhibitAnyPolicy(input) {
  const { node, ctx, path } = input;
  const skipCerts = readCount(expectUniversalField(node, TAG_INTEGER, path, MALFORMED, node.offset), ctx, path);
  const extension = { ...baseOf(input), kind: "inhibitAnyPolicy", skipCerts };
  return Object.freeze(extension);
}

// src/x509/x509-ext-distribution.ts
var REASONS = [
  "unused",
  "keyCompromise",
  "cACompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "privilegeWithdrawn",
  "aACompromise"
];
function readDistributionPoint(node, ctx, path) {
  const seq = expectSequence(node, path, node.offset);
  const [nameNode, reasonsNode, issuerNode] = contextFields(seq.children, 2, path);
  let fullName;
  let nameRelativeToCRLIssuer;
  if (nameNode !== void 0) {
    const namePath = `${path}.distributionPoint`;
    const choice = nameNode.constructed && nameNode.children.length === 1 ? nameNode.children[0] : void 0;
    if (choice?.tagClass === "context" && choice.tagNumber === 0) {
      fullName = _readGeneralNameList(choice, ctx, `${namePath}.fullName`, false);
    } else if (choice?.tagClass === "context" && choice.tagNumber === 1) {
      nameRelativeToCRLIssuer = _readRelativeDistinguishedName(choice, ctx, `${namePath}.nameRelativeToCRLIssuer`);
    } else {
      throw malformed(namePath, nameNode.offset, "is not one DistributionPointName \u2014 fullName [0] or nameRelativeToCRLIssuer [1] \u2014 under an explicit [0] tag");
    }
  }
  let reasons;
  if (reasonsNode !== void 0) {
    reasons = Object.freeze(readNamedBits(_readBitString(reasonsNode, ctx), REASONS, ctx, `${path}.reasons`, reasonsNode.offset));
  }
  const point = {
    fullName,
    nameRelativeToCRLIssuer,
    reasons,
    cRLIssuer: issuerNode === void 0 ? void 0 : _readGeneralNameList(issuerNode, ctx, `${path}.cRLIssuer`, false)
  };
  return Object.freeze(point);
}
function readDistributionPoints(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  expectNonEmpty(seq, path, "DistributionPoint");
  enforceLimit(ctx.limits, "maxGeneralNames", seq.children.length, `the distribution points of ${path}`);
  return Object.freeze(seq.children.map((child, i) => readDistributionPoint(child, ctx, `${path}[${i}]`)));
}
function decodeCrlDistributionPoints(input) {
  const extension = { ...baseOf(input), kind: "crlDistributionPoints", points: readDistributionPoints(input) };
  return Object.freeze(extension);
}
function decodeFreshestCrl(input) {
  const extension = { ...baseOf(input), kind: "freshestCRL", points: readDistributionPoints(input) };
  return Object.freeze(extension);
}
function readAccessDescriptions(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  expectNonEmpty(seq, path, "AccessDescription");
  enforceLimit(ctx.limits, "maxGeneralNames", seq.children.length, `the access descriptions of ${path}`);
  return Object.freeze(seq.children.map((child, i) => {
    const descriptionPath = `${path}[${i}]`;
    const pair = expectSequence(child, descriptionPath, seq.offset);
    if (pair.children.length !== 2) {
      throw malformed(descriptionPath, pair.offset, `holds ${pair.children.length} values; an AccessDescription is an accessMethod and an accessLocation`);
    }
    const methodNode = expectUniversalField(pair.children[0], TAG_OID, `${descriptionPath}.accessMethod`, MALFORMED, pair.offset);
    return Object.freeze({
      accessMethod: _readObjectIdentifier(methodNode, ctx),
      accessLocation: _readGeneralName(pair.children[1], ctx, `${descriptionPath}.accessLocation`, false)
    });
  }));
}
function decodeAuthorityInfoAccess(input) {
  const extension = { ...baseOf(input), kind: "authorityInfoAccess", descriptions: readAccessDescriptions(input) };
  return Object.freeze(extension);
}
function decodeSubjectInfoAccess(input) {
  const extension = { ...baseOf(input), kind: "subjectInfoAccess", descriptions: readAccessDescriptions(input) };
  return Object.freeze(extension);
}

// src/x509/x509-ext-identifiers.ts
function decodeSubjectKeyIdentifier(input) {
  const { node, ctx, path } = input;
  const keyIdentifier = _readOctetString(expectUniversalField(node, TAG_OCTET_STRING, path, MALFORMED, node.offset), ctx);
  const extension = { ...baseOf(input), kind: "subjectKeyIdentifier", keyIdentifier };
  return Object.freeze(extension);
}
function decodeAuthorityKeyIdentifier(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  const [keyNode, issuerNode, serialNode] = contextFields(seq.children, 2, path);
  let authorityCertSerialNumber;
  if (serialNode !== void 0) {
    const serial = { bytes: serialNode.content, hex: toHex(serialNode.content), value: _readInteger(serialNode, ctx) };
    authorityCertSerialNumber = Object.freeze(serial);
  }
  const extension = {
    ...baseOf(input),
    kind: "authorityKeyIdentifier",
    keyIdentifier: keyNode === void 0 ? void 0 : _readOctetString(keyNode, ctx),
    authorityCertIssuer: issuerNode === void 0 ? void 0 : _readGeneralNameList(issuerNode, ctx, `${path}.authorityCertIssuer`, false),
    authorityCertSerialNumber
  };
  if (issuerNode === void 0 !== (serialNode === void 0)) ctx.emitter.emit(akiIssuerSerialUnpairedDiagnostic());
  return Object.freeze(extension);
}
function decodeSubjectAltName(input) {
  const names = _readGeneralNames(input.node, input.ctx, input.path, false);
  if (names.length === 0) input.ctx.emitter.emit(sanEmptyDiagnostic(input.path));
  const extension = { ...baseOf(input), kind: "subjectAltName", names };
  return Object.freeze(extension);
}
function decodeIssuerAltName(input) {
  const names = _readGeneralNames(input.node, input.ctx, input.path, false);
  if (names.length === 0) input.ctx.emitter.emit(sanEmptyDiagnostic(input.path));
  const extension = { ...baseOf(input), kind: "issuerAltName", names };
  return Object.freeze(extension);
}
function decodeSignedCertificateTimestampList(input) {
  const { node, ctx, path } = input;
  const list = _readOctetString(expectUniversalField(node, TAG_OCTET_STRING, path, MALFORMED, node.offset), ctx);
  const extension = { ...baseOf(input), kind: "signedCertificateTimestampList", list };
  return Object.freeze(extension);
}
function decodeOcspNoCheck(input) {
  const { node, path } = input;
  const value = expectUniversalField(node, TAG_NULL, path, MALFORMED, node.offset);
  if (value.contentLength !== 0) throw malformed(path, value.offset, `is a NULL with ${value.contentLength} content octets; X.690 \xA78.8.2 allows none`);
  const extension = { ...baseOf(input), kind: "ocspNoCheck" };
  return Object.freeze(extension);
}

// src/x509/x509-ext-policies.ts
var OID_CPS = "1.3.6.1.5.5.7.2.1";
var OID_USER_NOTICE = "1.3.6.1.5.5.7.2.2";
var DISPLAY_TEXT = /* @__PURE__ */ new Set(["ia5", "visible", "bmp", "utf8"]);
function readOid(node, ctx, path, parentOffset) {
  return _readObjectIdentifier(expectUniversalField(node, TAG_OID, path, MALFORMED, parentOffset), ctx);
}
function readText(node, ctx, path, allowed, what) {
  if (node.tagClass !== "universal" || stringTypeOfTag(node.tagNumber) === void 0) {
    throw malformed(path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; expected ${what}`);
  }
  const text = _readString(node, ctx, void 0, path);
  if (!allowed.has(text.stringType)) throw malformed(path, node.offset, `is a ${text.stringType} string; expected ${what}`);
  return text;
}
var displayText = (node, ctx, path) => readText(node, ctx, path, DISPLAY_TEXT, "DisplayText: an IA5String, VisibleString, BMPString or UTF8String");
function readNoticeReference(node, ctx, path) {
  const seq = expectSequence(node, path, node.offset);
  if (seq.children.length !== 2) throw malformed(path, seq.offset, `holds ${seq.children.length} values; a NoticeReference is an organization and its notice numbers`);
  const organization = displayText(seq.children[0], ctx, `${path}.organization`);
  const numbers = expectSequence(seq.children[1], `${path}.noticeNumbers`, seq.offset);
  enforceLimit(ctx.limits, "maxPolicies", numbers.children.length, `the notice numbers of ${path}`);
  const noticeNumbers = numbers.children.map((child, i) => _readInteger(expectUniversalField(child, TAG_INTEGER, `${path}.noticeNumbers[${i}]`, MALFORMED, numbers.offset), ctx));
  const reference = { organization, noticeNumbers: Object.freeze(noticeNumbers) };
  return Object.freeze(reference);
}
function readUserNotice(oid, node, ctx, path) {
  const seq = expectSequence(node, path, node.offset);
  let index = 0;
  let noticeRef;
  const first = seq.children[0];
  if (first !== void 0 && first.tagClass === "universal" && first.tagNumber === TAG_SEQUENCE) {
    noticeRef = readNoticeReference(first, ctx, `${path}.noticeRef`);
    index = 1;
  }
  let explicitText;
  const text = seq.children[index];
  if (text !== void 0) {
    explicitText = displayText(text, ctx, `${path}.explicitText`);
    index++;
  }
  if (index !== seq.children.length) throw malformed(path, seq.offset, `holds ${seq.children.length} values; a UserNotice is an optional noticeRef and an optional explicitText`);
  const qualifier = { kind: "userNotice", oid, noticeRef, explicitText };
  return Object.freeze(qualifier);
}
function readQualifier(node, ctx, path) {
  const seq = expectSequence(node, path, node.offset);
  if (seq.children.length !== 2) throw malformed(path, seq.offset, `holds ${seq.children.length} values; a PolicyQualifierInfo is a qualifier OID and its qualifier`);
  const oid = readOid(seq.children[0], ctx, `${path}.policyQualifierId`, seq.offset);
  const value = seq.children[1];
  if (oid === OID_CPS) {
    const uri = readText(value, ctx, `${path}.qualifier`, /* @__PURE__ */ new Set(["ia5"]), "a CPSuri IA5String").value;
    const qualifier2 = { kind: "cps", oid, uri };
    return Object.freeze(qualifier2);
  }
  if (oid === OID_USER_NOTICE) return readUserNotice(oid, value, ctx, `${path}.qualifier`);
  const qualifier = { kind: "unknown", oid, qualifier: value };
  return Object.freeze(qualifier);
}
function readPolicy(node, ctx, path) {
  const seq = expectSequence(node, path, node.offset);
  if (seq.children.length < 1 || seq.children.length > 2) {
    throw malformed(path, seq.offset, `holds ${seq.children.length} values; a PolicyInformation is a policy OID and optional qualifiers`);
  }
  const policyIdentifier = readOid(seq.children[0], ctx, `${path}.policyIdentifier`, seq.offset);
  let qualifiers = [];
  const qualifiersNode = seq.children[1];
  if (qualifiersNode !== void 0) {
    const qualifiersPath = `${path}.policyQualifiers`;
    const list = expectSequence(qualifiersNode, qualifiersPath, seq.offset);
    expectNonEmpty(list, qualifiersPath, "PolicyQualifierInfo");
    enforceLimit(ctx.limits, "maxPolicies", list.children.length, `the qualifiers of ${path}`);
    qualifiers = list.children.map((child, i) => readQualifier(child, ctx, `${qualifiersPath}[${i}]`));
  }
  const policy = { policyIdentifier, qualifiers: Object.freeze(qualifiers) };
  return Object.freeze(policy);
}
function decodeCertificatePolicies(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  expectNonEmpty(seq, path, "PolicyInformation");
  enforceLimit(ctx.limits, "maxPolicies", seq.children.length, `the policies of ${path}`);
  const policies = seq.children.map((child, i) => readPolicy(child, ctx, `${path}[${i}]`));
  const seen = /* @__PURE__ */ new Set();
  for (const policy of policies) {
    if (seen.has(policy.policyIdentifier)) ctx.emitter.emit(policyDuplicateDiagnostic(policy.policyIdentifier));
    seen.add(policy.policyIdentifier);
  }
  const extension = { ...baseOf(input), kind: "certificatePolicies", policies: Object.freeze(policies) };
  return Object.freeze(extension);
}
function decodePolicyMappings(input) {
  const { node, ctx, path } = input;
  const seq = expectSequence(node, path, node.offset);
  expectNonEmpty(seq, path, "policy mapping");
  enforceLimit(ctx.limits, "maxPolicies", seq.children.length, `the mappings of ${path}`);
  const mappings = seq.children.map((child, i) => {
    const mappingPath = `${path}[${i}]`;
    const pair = expectSequence(child, mappingPath, seq.offset);
    if (pair.children.length !== 2) throw malformed(mappingPath, pair.offset, `holds ${pair.children.length} values; a mapping is an issuerDomainPolicy and a subjectDomainPolicy`);
    return Object.freeze({
      issuerDomainPolicy: readOid(pair.children[0], ctx, `${mappingPath}.issuerDomainPolicy`, pair.offset),
      subjectDomainPolicy: readOid(pair.children[1], ctx, `${mappingPath}.subjectDomainPolicy`, pair.offset)
    });
  });
  const extension = { ...baseOf(input), kind: "policyMappings", mappings: Object.freeze(mappings) };
  return Object.freeze(extension);
}

// src/x509/x509-extensions.ts
var DECODERS = /* @__PURE__ */ new Map([
  ["2.5.29.14", decodeSubjectKeyIdentifier],
  ["2.5.29.15", decodeKeyUsage],
  ["2.5.29.17", decodeSubjectAltName],
  ["2.5.29.18", decodeIssuerAltName],
  ["2.5.29.19", decodeBasicConstraints],
  ["2.5.29.30", decodeNameConstraints],
  ["2.5.29.31", decodeCrlDistributionPoints],
  ["2.5.29.32", decodeCertificatePolicies],
  ["2.5.29.33", decodePolicyMappings],
  ["2.5.29.35", decodeAuthorityKeyIdentifier],
  ["2.5.29.36", decodePolicyConstraints],
  ["2.5.29.37", decodeExtendedKeyUsage],
  ["2.5.29.46", decodeFreshestCrl],
  ["2.5.29.54", decodeInhibitAnyPolicy],
  ["1.3.6.1.5.5.7.1.1", decodeAuthorityInfoAccess],
  ["1.3.6.1.5.5.7.1.11", decodeSubjectInfoAccess],
  ["1.3.6.1.4.1.11129.2.4.2", decodeSignedCertificateTimestampList],
  ["1.3.6.1.5.5.7.48.1.5", decodeOcspNoCheck]
]);
function _decodeExtension(data, start, oid, critical, valueDer, ctx, path) {
  const decoder = DECODERS.get(oid);
  if (decoder === void 0) {
    if (critical) ctx.emitter.emit(unknownCriticalExtensionDiagnostic(oid, path));
    const extension = { kind: "unknown", oid, critical, valueDer };
    return Object.freeze(extension);
  }
  try {
    const node = decodeValueAt(data, start, ctx);
    const end = node.offset + node.bytes.length;
    if (end !== data.length) throw malformed(path, end, `has ${data.length - end} octet(s) after the extension value inside extnValue`);
    return decoder({ node, ctx, path, oid, critical, valueDer });
  } catch (error) {
    if (error instanceof PkiEncodingError) {
      throw malformed(path, error.offset ?? start, `does not match its ASN.1 definition (${error.code})`);
    }
    throw error;
  }
}
function decodeExtensionValue(oid, valueDer, options) {
  if (typeof oid !== "string") throw new PkiError("PKI_INVALID_INPUT", `pkinative: decodeExtensionValue expects the extension OID as a dotted string, got ${typeof oid}`);
  if (!isValidOid(oid)) throw new PkiEncodingError("PKI_OID_INVALID", `pkinative: "${oid.slice(0, 64)}" is not a dotted-decimal OID X.660 allows \u2014 pass the extnID, e.g. 2.5.29.17`);
  const bytes = assertBytes(valueDer, "decodeExtensionValue value");
  const critical = options?.critical ?? false;
  if (typeof critical !== "boolean") throw new PkiError("PKI_INVALID_OPTION", `pkinative: critical must be a boolean, got ${typeof critical}`);
  return _decodeExtension(bytes, 0, oid, critical, bytes, createAsn1Context(options), "extnValue");
}
function getExtension(certificate, kind) {
  if (typeof certificate !== "object" || certificate === null || !Array.isArray(certificate.extensions)) {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: getExtension expects a certificate returned by parseCertificate, got ${certificate === null ? "null" : typeof certificate}`);
  }
  for (const extension of certificate.extensions) {
    if (extension.kind === kind) return extension;
  }
  return void 0;
}

// src/revocation/crl-parse.ts
var STRUCTURE = "PKI_X509_STRUCTURE_INVALID";
var REASONS2 = Object.freeze({
  0: "unspecified",
  1: "keyCompromise",
  2: "cACompromise",
  3: "affiliationChanged",
  4: "superseded",
  5: "cessationOfOperation",
  6: "certificateHold",
  8: "removeFromCRL",
  9: "privilegeWithdrawn",
  10: "aACompromise"
});
var OID_CRL_NUMBER = "2.5.29.20";
var OID_DELTA_CRL_INDICATOR = "2.5.29.27";
var OID_CRL_REASON = "2.5.29.21";
var OID_INVALIDITY_DATE = "2.5.29.24";
function crlError(path, offset, why) {
  return new PkiCertificateError(STRUCTURE, `pkinative: ${path} ${why} \u2014 the input is not an RFC 5280 CertificateList`, path, offset);
}
function decodeAt(der, header, ctx) {
  return decodeValueAt(der, header.offset, ctx);
}
var isTime = (header) => header.tagClass === "universal" && (header.tagNumber === 23 || header.tagNumber === 24);
function locate(der, outer) {
  const parts = [...walkChildren(der, outer, "CertificateList")];
  const tbs = parts[0];
  if (parts.length !== 3 || tbs === void 0) {
    throw crlError("CertificateList", outer.offset, `holds ${String(parts.length)} values where RFC 5280 \xA75.1 defines exactly three`);
  }
  const fields = [...walkChildren(der, tbs, "tbsCertList")];
  let at = 0;
  const take = (what) => {
    const field = fields[at];
    if (field === void 0) throw crlError(`tbsCertList.${what}`, tbs.offset, "is missing");
    at += 1;
    return field;
  };
  const first = fields[0];
  let version = 1;
  if (first !== void 0 && first.tagClass === "universal" && first.tagNumber === 2) {
    const encoded = der[first.contentStart];
    if (first.length !== 1 || encoded !== 0 && encoded !== 1) {
      throw crlError("tbsCertList.version", first.offset, "is not v1 (0) or v2 (1)");
    }
    version = encoded === 1 ? 2 : 1;
    at += 1;
  }
  const signatureIndex = at;
  take("signature");
  take("issuer");
  const thisUpdateAt = take("thisUpdate");
  if (!isTime(thisUpdateAt)) throw crlError("tbsCertList.thisUpdate", thisUpdateAt.offset, "is not a UTCTime or a GeneralizedTime");
  let nextUpdateAt;
  const maybeNext = fields[at];
  if (maybeNext !== void 0 && isTime(maybeNext)) {
    nextUpdateAt = maybeNext;
    at += 1;
  }
  let revoked;
  const maybeRevoked = fields[at];
  if (maybeRevoked !== void 0 && maybeRevoked.tagClass === "universal" && maybeRevoked.tagNumber === 16) {
    revoked = maybeRevoked;
    at += 1;
  }
  let extensionsField;
  const maybeExtensions = fields[at];
  if (maybeExtensions !== void 0 && maybeExtensions.tagClass === "context" && maybeExtensions.tagNumber === 0) {
    extensionsField = maybeExtensions;
    at += 1;
  }
  if (at !== fields.length) {
    throw crlError("tbsCertList", tbs.offset, `has ${String(fields.length - at)} field(s) after crlExtensions, where RFC 5280 \xA75.1 defines none`);
  }
  return { tbs, fields, revoked, extensionsField, version, signatureIndex, thisUpdateAt, nextUpdateAt };
}
function countEntries(der, revoked, ctx) {
  if (revoked === void 0) return 0;
  let count = 0;
  for (const entry of walkChildren(der, revoked, "tbsCertList.revokedCertificates")) {
    if (!entry.constructed || entry.tagClass !== "universal" || entry.tagNumber !== 16) {
      throw crlError(`tbsCertList.revokedCertificates[${String(count)}]`, entry.offset, "is not a SEQUENCE");
    }
    count += 1;
    enforceLimit(ctx.limits, "maxRevokedCertificates", count, `tbsCertList.revokedCertificates[${String(count)}]`);
  }
  return count;
}
function parseCertificateList(der, options) {
  const ctx = createAsn1Context(options);
  const outer = readTlvHeader(der, 0, "CertificateList");
  if (!outer.constructed || outer.tagClass !== "universal" || outer.tagNumber !== 16) {
    throw crlError("CertificateList", 0, "is not a SEQUENCE");
  }
  const env = locate(der, outer);
  const fields = env.fields;
  const tbsSignatureAlgorithm = _readAlgorithmIdentifier(decodeAt(der, fields[env.signatureIndex], ctx), ctx, "tbsCertList.signature", STRUCTURE, env.tbs.offset);
  const issuer = _readName(decodeAt(der, fields[env.signatureIndex + 1], ctx), ctx, "tbsCertList.issuer", env.tbs.offset);
  const thisUpdate = _readTime(decodeAt(der, env.thisUpdateAt, ctx), ctx, void 0);
  const nextUpdate = env.nextUpdateAt === void 0 ? void 0 : _readTime(decodeAt(der, env.nextUpdateAt, ctx), ctx, void 0);
  const parts = [...walkChildren(der, outer, "CertificateList")];
  const signatureAlgorithm = _readAlgorithmIdentifier(decodeAt(der, parts[1], ctx), ctx, "signatureAlgorithm", STRUCTURE, outer.offset);
  const signatureNode = decodeAt(der, parts[2], ctx);
  if (signatureNode.tagClass !== "universal" || signatureNode.tagNumber !== 3) {
    throw crlError("signatureValue", parts[2].offset, "is not a BIT STRING");
  }
  const unusedBits = signatureNode.content[0] ?? 0;
  const signatureValue = { bytes: signatureNode.content.subarray(1), unusedBits };
  const extensions = readExtensions(der, env.extensionsField, ctx, "tbsCertList.crlExtensions");
  let crlNumber;
  let isDelta = false;
  for (const extension of extensions) {
    if (extension.oid === OID_CRL_NUMBER) crlNumber = readIntegerValue(extension, ctx);
    if (extension.oid === OID_DELTA_CRL_INDICATOR) isDelta = true;
  }
  return Object.freeze({
    der: der.subarray(outer.offset, outer.end),
    tbsDer: der.subarray(env.tbs.offset, env.tbs.end),
    version: env.version,
    signatureAlgorithm,
    tbsSignatureAlgorithm,
    signatureValue: Object.freeze(signatureValue),
    issuer,
    thisUpdate,
    nextUpdate,
    extensions,
    crlNumber,
    isDelta,
    entryCount: countEntries(der, env.revoked, ctx),
    diagnostics: ctx.emitter.diagnostics
  });
}
function readExtensions(der, field, ctx, path) {
  if (field === void 0) return [];
  const wrapper = field.tagClass === "context" ? [...walkChildren(der, field, path)][0] : field;
  if (wrapper === void 0) return [];
  const out = [];
  let index = 0;
  for (const entry of walkChildren(der, wrapper, path)) {
    const where2 = `${path}[${String(index)}]`;
    enforceLimit(ctx.limits, "maxExtensions", index + 1, where2);
    const node = decodeAt(der, entry, ctx);
    const oidNode = node.children[0];
    const criticalNode = node.children.length === 3 ? node.children[1] : void 0;
    const valueNode = node.children[node.children.length - 1];
    if (oidNode === void 0 || valueNode === void 0 || node.children.length < 2) {
      throw crlError(where2, entry.offset, "is not an Extension");
    }
    out.push(_decodeExtension(
      der,
      entry.offset,
      readObjectIdentifier(oidNode),
      criticalNode !== void 0 && criticalNode.content[0] !== 0,
      valueNode.content,
      ctx,
      where2
    ));
    index += 1;
  }
  return Object.freeze(out);
}
function readIntegerValue(extension, ctx) {
  try {
    return readInteger(decodeValueAt(extension.valueDer, 0, ctx));
  } catch {
    return void 0;
  }
}
function findRevocation(der, serial, options) {
  const ctx = createAsn1Context(options);
  const outer = readTlvHeader(der, 0, "CertificateList");
  const env = locate(der, outer);
  if (env.revoked === void 0) return void 0;
  let index = 0;
  for (const entry of walkChildren(der, env.revoked, "tbsCertList.revokedCertificates")) {
    enforceLimit(ctx.limits, "maxRevokedCertificates", index + 1, `tbsCertList.revokedCertificates[${String(index)}]`);
    const path = `tbsCertList.revokedCertificates[${String(index)}]`;
    const parts = [...walkChildren(der, entry, path)];
    const serialField = parts[0];
    const dateField = parts[1];
    if (serialField === void 0 || dateField === void 0) {
      throw crlError(path, entry.offset, "holds fewer than the two fields RFC 5280 \xA75.1.2.6 requires");
    }
    index += 1;
    const content = der.subarray(serialField.contentStart, serialField.end);
    if (!sameBytes(content, serial)) continue;
    const revocationDate = _readTime(decodeAt(der, dateField, ctx), ctx, void 0);
    const extensions = readExtensions(der, parts[2], ctx, `${path}.crlEntryExtensions`);
    return Object.freeze({
      serialNumber: Object.freeze({ bytes: content, hex: toHex(content), value: readInteger(decodeAt(der, serialField, ctx)) }),
      revocationDate,
      extensions,
      reason: readReason(extensions, ctx),
      invalidityDate: readInvalidityDate(extensions, ctx)
    });
  }
  return void 0;
}
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
function readReason(extensions, ctx) {
  const extension = extensions.find((e) => e.oid === OID_CRL_REASON);
  if (extension === void 0) return void 0;
  try {
    const node = decodeValueAt(extension.valueDer, 0, ctx);
    if (node.tagClass !== "universal" || node.tagNumber !== 10 && node.tagNumber !== 2) return void 0;
    if (node.content.length !== 1) return void 0;
    return REASONS2[node.content[0]];
  } catch {
    return void 0;
  }
}
function readInvalidityDate(extensions, ctx) {
  const extension = extensions.find((e) => e.oid === OID_INVALIDITY_DATE);
  if (extension === void 0) return void 0;
  try {
    const time = _readTime(decodeValueAt(extension.valueDer, 0, ctx), ctx, void 0);
    return time.epochMilliseconds;
  } catch {
    return void 0;
  }
}

// src/core/pki-reasons.ts
function _reason(code, standard, message, path, extra) {
  return Object.freeze({ code, message, standard, path, errorCode: extra?.errorCode, limit: extra?.limit });
}
function notYetValidReason(path, notBefore, at) {
  return _reason(
    "PKI_REASON_NOT_YET_VALID",
    "RFC 5280 \xA76.1.3 (a)(2)",
    `the certificate is not valid until ${new Date(notBefore).toISOString()}, and validation was asked for ${new Date(at).toISOString()}`,
    path
  );
}
function expiredReason(path, notAfter, at) {
  return _reason(
    "PKI_REASON_EXPIRED",
    "RFC 5280 \xA76.1.3 (a)(2)",
    `the certificate expired on ${new Date(notAfter).toISOString()}, and validation was asked for ${new Date(at).toISOString()}`,
    path
  );
}
function unrecognisedCriticalExtensionReason(path, oid) {
  return _reason(
    "PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION",
    "RFC 5280 \xA76.1.3 (f)",
    `the certificate carries the critical extension ${oid}, which this implementation does not recognise; a verifier must refuse rather than ignore it`,
    path
  );
}
function nameNotPermittedReason(path, form, text) {
  return _reason(
    "PKI_REASON_NAME_NOT_PERMITTED",
    "RFC 5280 \xA76.1.3 (b)",
    `the ${form} "${text}" falls outside the permitted subtrees a CA above this certificate set; a sub-CA cannot issue for names its issuer withheld`,
    path
  );
}
function nameExcludedReason(path, form, text) {
  return _reason(
    "PKI_REASON_NAME_EXCLUDED",
    "RFC 5280 \xA76.1.3 (c)",
    `the ${form} "${text}" falls inside an excluded subtree; an exclusion anywhere on the path wins over every permission`,
    path
  );
}
function revokedReason(path, at, reason) {
  const why = reason === void 0 ? "no reason given" : `reason: ${reason}`;
  return _reason(
    "PKI_REASON_REVOKED",
    "RFC 5280 \xA75.1",
    `the certificate was revoked on ${new Date(at).toISOString()} (${why}); a signature made before that instant may still be good, which is why the date is here`,
    path
  );
}
function revocationStaleReason(path, nextUpdate, at) {
  const when = nextUpdate === void 0 ? "the list declares no nextUpdate, so nothing says it is still current" : `the list expected a successor by ${new Date(nextUpdate).toISOString()}`;
  return _reason(
    "PKI_REASON_REVOCATION_STALE",
    "RFC 5280 \xA75.1.2.5",
    `${when}, and the question was asked for ${new Date(at).toISOString()}`,
    path
  );
}
function revocationWrongIssuerReason(path) {
  return _reason(
    "PKI_REASON_REVOCATION_WRONG_ISSUER",
    "RFC 5280 \xA76.3.3",
    "the revocation list names a different issuer from the certificate, compared by encoded name; a list from another CA says nothing about this certificate",
    path
  );
}
function revocationUnknownReason(path, why) {
  return _reason(
    "PKI_REASON_REVOCATION_UNKNOWN",
    "RFC 5280 \xA76.3",
    `revocation status could not be established: ${why}. This is not "not revoked" \u2014 it is an absence of evidence, and proceeding on it is a decision to make deliberately`,
    path
  );
}
function revocationMismatchReason(path, what) {
  return _reason(
    "PKI_REASON_REVOCATION_MISMATCH",
    "RFC 6960 \xA73.2",
    `the revocation answer does not belong to this question: ${what}. Retrying will not help \u2014 this response was not produced for this certificate`,
    path
  );
}
function noValidPolicyReason(path) {
  return _reason(
    "PKI_REASON_NO_VALID_POLICY",
    "RFC 5280 \xA76.1.5 (g)",
    "no certificate policy survives the whole path, and an explicit policy was required by a CA in it or by the caller",
    path
  );
}
function policyMappingInvalidReason(path, issuerDomainPolicy, subjectDomainPolicy) {
  return _reason(
    "PKI_REASON_POLICY_MAPPING_INVALID",
    "RFC 5280 \xA76.1.4 (a)",
    `the policy mapping ${issuerDomainPolicy} \u2192 ${subjectDomainPolicy} names anyPolicy, which may be neither an issuerDomainPolicy nor a subjectDomainPolicy; the mapping was ignored rather than honoured`,
    path
  );
}
function nameMismatchReason(path, wanted, found) {
  return _reason(
    "PKI_REASON_NAME_MISMATCH",
    "RFC 6125 \xA76",
    `the certificate does not name ${wanted}: ${found}. A chain that verifies still says nothing about which host the certificate is for`,
    path
  );
}
function issuerNotFoundReason(path, issuer) {
  return _reason(
    "PKI_REASON_ISSUER_NOT_FOUND",
    "RFC 5280 \xA76.1",
    `no supplied certificate has the subject ${issuer}, so this certificate has no issuer to check it against`,
    path
  );
}
function signatureInvalidReason(path) {
  return _reason(
    "PKI_REASON_SIGNATURE_INVALID",
    "RFC 5280 \xA76.1.3 (a)(1)",
    "the issuer's public key does not verify this certificate's signature",
    path
  );
}
function signatureNotCheckedReason(path, errorCode, detail) {
  return _reason(
    "PKI_REASON_SIGNATURE_NOT_CHECKED",
    "RFC 5280 \xA76.1.3 (a)(1)",
    `the signature could not be checked here (${errorCode}): ${detail.replace(/^pkinative: /, "")} \u2014 this says nothing about whether the signature is valid`,
    path,
    { errorCode }
  );
}
function noTrustAnchorReason(path) {
  return _reason(
    "PKI_REASON_NO_TRUST_ANCHOR",
    "RFC 5280 \xA76.1.1 (d)",
    "the chain does not end at any of the trust anchors supplied; a signature that verifies is not a certificate that is trusted",
    path
  );
}
function notACaReason(path, why) {
  return _reason(
    "PKI_REASON_NOT_A_CA",
    "RFC 5280 \xA76.1.4 (k)",
    why === "basicConstraints" ? "a certificate in the chain issued another without asserting cA in basicConstraints" : "a certificate in the chain issued another without asserting keyCertSign in keyUsage",
    path
  );
}
function pathTooLongReason(path, allowed) {
  return _reason(
    "PKI_REASON_PATH_TOO_LONG",
    "RFC 5280 \xA76.1.4 (l)",
    `the chain is longer than the ${String(allowed)} intermediate certificate(s) a pathLenConstraint in it allows`,
    path
  );
}
function pathLoopsReason(path) {
  return _reason(
    "PKI_REASON_PATH_LOOPS",
    "RFC 5280 \xA76.1",
    "the same certificate appears twice in the chain; a path that revisits a certificate is not a path",
    path
  );
}
function limitExceededReason(path, limit, configured) {
  return _reason(
    "PKI_REASON_LIMIT_EXCEEDED",
    "CWE-400",
    `validation stopped at the ${limit} limit of ${String(configured)}; raise it only for input you trust`,
    path,
    { limit }
  );
}

// src/revocation/crl-check.ts
function checkRevocation(input) {
  const out = [];
  const path = "crl";
  if (!bytesEqual(input.crl.issuer.der, input.certificate.issuer.der)) {
    out.push(revocationWrongIssuerReason(path));
  }
  if (input.signatureVerified !== true) {
    out.push(revocationUnknownReason(path, input.signatureVerified === false ? "the list's signature did not verify against the key it was checked with" : "the list's signature was never checked, and an unsigned list is something anyone can publish"));
  }
  const tolerance = input.staleTolerance ?? 0;
  const nextUpdate = input.crl.nextUpdate?.epochMilliseconds;
  if (nextUpdate === void 0 || input.at > nextUpdate + tolerance) {
    out.push(revocationStaleReason(path, nextUpdate, input.at));
  }
  const entry = findRevocation(input.crlDer, input.certificate.serialNumber.bytes, input.options);
  if (entry !== void 0) {
    out.push(revokedReason(path, entry.revocationDate.epochMilliseconds, entry.reason));
  }
  return out;
}

// src/asn1/asn1-encode.ts
function encodeLength(length) {
  if (length < 128) return [length];
  const octets = [];
  let rest = length;
  while (rest > 0) {
    octets.unshift(rest % 256);
    rest = Math.floor(rest / 256);
  }
  return [128 | octets.length, ...octets];
}
function encodeTlv(tagClass, tagNumber, constructed, content) {
  const bytes = assertBytes(content, "encodeTlv content");
  const classIndex = TAG_CLASSES.indexOf(tagClass);
  if (classIndex < 0) {
    throw new PkiEncodingError("PKI_ASN1_VALUE_OUT_OF_RANGE", `pkinative: tagClass must be one of ${TAG_CLASSES.join(", ")}, got ${String(tagClass)}`);
  }
  if (!Number.isInteger(tagNumber) || tagNumber < 0 || tagNumber > 2147483647 || tagClass === "universal" && tagNumber === 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_VALUE_OUT_OF_RANGE",
      `pkinative: tag number ${String(tagNumber)} is outside 0 to 2^31 \u2212 1, or is the reserved universal tag 0 \u2014 pass a valid tag number`
    );
  }
  const leading = classIndex << 6 | (constructed ? 32 : 0);
  const identifier = [];
  if (tagNumber < 31) {
    identifier.push(leading | tagNumber);
  } else {
    const digits = [];
    let rest = tagNumber;
    do {
      digits.unshift(rest % 128);
      rest = Math.floor(rest / 128);
    } while (rest > 0);
    identifier.push(leading | 31);
    let remaining = digits.length;
    for (const digit of digits) {
      remaining--;
      identifier.push(digit | (remaining > 0 ? 128 : 0));
    }
  }
  const header = [...identifier, ...encodeLength(bytes.length)];
  const out = new Uint8Array(header.length + bytes.length);
  out.set(header, 0);
  out.set(bytes, header.length);
  return out;
}
function childrenContent(children, what) {
  if (!Array.isArray(children)) {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: ${what} expects an array of encodings, got ${typeof children}`);
  }
  return concatBytes(children.map((c) => assertBytes(c, `${what} child`)));
}
function encodeSequence(children) {
  return encodeTlv("universal", TAG_SEQUENCE, true, childrenContent(children, "encodeSequence"));
}
function encodeSet(children) {
  return encodeTlv("universal", TAG_SET, true, childrenContent(children, "encodeSet"));
}
function encodeSetOf(children) {
  childrenContent(children, "encodeSetOf");
  return encodeTlv("universal", TAG_SET, true, concatBytes([...children].sort(compareOctets)));
}
function hexToBytes(hex3) {
  const out = new Uint8Array(hex3.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex3.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function encodeInteger(value) {
  let v;
  if (typeof value === "bigint") {
    v = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value)) {
    v = BigInt(value);
  } else {
    throw new PkiEncodingError("PKI_ASN1_VALUE_OUT_OF_RANGE", `pkinative: encodeInteger expects a bigint or a safe integer, got ${String(value)}`);
  }
  let hex3;
  if (v >= 0n) {
    hex3 = v.toString(16);
    if (hex3.length % 2 === 1) hex3 = `0${hex3}`;
    if (parseInt(hex3.slice(0, 2), 16) >= 128) hex3 = `00${hex3}`;
  } else {
    let octets = 1;
    while (v < -(1n << BigInt(octets * 8 - 1))) octets++;
    hex3 = ((1n << BigInt(octets * 8)) + v).toString(16).padStart(octets * 2, "0");
  }
  return encodeTlv("universal", TAG_INTEGER, false, hexToBytes(hex3));
}
function encodeBoolean(value) {
  return encodeTlv("universal", TAG_BOOLEAN, false, Uint8Array.of(value ? 255 : 0));
}
function encodeNull() {
  return encodeTlv("universal", TAG_NULL, false, new Uint8Array(0));
}
function encodeBitString(bytes, unusedBits = 0) {
  const data = assertBytes(bytes, "encodeBitString bytes");
  if (!Number.isInteger(unusedBits) || unusedBits < 0 || unusedBits > 7 || data.length === 0 && unusedBits !== 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_VALUE_OUT_OF_RANGE",
      `pkinative: unusedBits must be 0 to 7, and 0 for an empty BIT STRING, got ${String(unusedBits)}`
    );
  }
  if (unusedBits > 0 && (byteView(data).getUint8(data.length - 1) & (1 << unusedBits) - 1) !== 0) {
    throw new PkiEncodingError(
      "PKI_ASN1_VALUE_OUT_OF_RANGE",
      `pkinative: the ${unusedBits} unused bits of the last octet must be zero in DER (X.690 \xA711.2.1) \u2014 clear them before encoding`
    );
  }
  const content = new Uint8Array(data.length + 1);
  content[0] = unusedBits;
  content.set(data, 1);
  return encodeTlv("universal", TAG_BIT_STRING, false, content);
}
function encodeOctetString(bytes) {
  return encodeTlv("universal", TAG_OCTET_STRING, false, assertBytes(bytes, "encodeOctetString bytes"));
}
function encodeEnumerated(value) {
  return encodeTlv("universal", TAG_ENUMERATED, false, encodeInteger(value).subarray(2));
}
function encodeExplicit(tagNumber, inner, options) {
  return encodeTlv(options?.tagClass ?? "context", tagNumber, true, assertBytes(inner, "encodeExplicit inner"));
}
function encodeImplicit(tagNumber, encoded, options) {
  const bytes = assertBytes(encoded, "encodeImplicit encoded");
  if (bytes.length < 2) {
    throw new PkiError("PKI_API_MISUSE", "pkinative: encodeImplicit needs a complete encoding to re-tag, and got fewer than two octets \u2014 pass the output of another encoder");
  }
  const view = byteView(bytes);
  const identifier = view.getUint8(0);
  if (view.getUint8(1) === 128) {
    throw new PkiError("PKI_API_MISUSE", "pkinative: encodeImplicit cannot re-tag an indefinite-length value \u2014 DER has no indefinite form, so encode the inner value definitely first");
  }
  const retagged = encodeTlv(options?.tagClass ?? "context", tagNumber, (identifier & 32) !== 0, new Uint8Array(0));
  const header = retagged.length - 1;
  const out = new Uint8Array(header + bytes.length - 1);
  out.set(retagged.subarray(0, header));
  out.set(bytes.subarray(1), header);
  return out;
}
function encodeNamedBits(bits) {
  let highest = -1;
  const positions = [];
  for (const bit of bits) {
    if (!Number.isInteger(bit) || bit < 0 || bit > 65535) {
      throw new PkiEncodingError("PKI_ASN1_VALUE_OUT_OF_RANGE", `pkinative: a named bit position must be an integer from 0 to 65535, got ${String(bit)}`);
    }
    positions.push(bit);
    if (bit > highest) highest = bit;
  }
  if (highest < 0) return encodeBitString(new Uint8Array(0), 0);
  const octets = new Uint8Array((highest >> 3) + 1);
  const view = byteView(octets);
  for (const bit of positions) view.setUint8(bit >> 3, view.getUint8(bit >> 3) | 128 >> (bit & 7));
  return encodeBitString(octets, 7 - (highest & 7));
}
function encodeObjectIdentifier(oid) {
  return encodeTlv("universal", TAG_OID, false, encodeOid(oid));
}
function outOfRange(type, index) {
  return new PkiEncodingError(
    "PKI_ASN1_VALUE_OUT_OF_RANGE",
    `pkinative: the character at index ${index} cannot be encoded as ${tagLabel("universal", STRING_TAGS[type])} \u2014 choose a string type whose character set contains it`
  );
}
function encodeString(type, value) {
  if (typeof value !== "string") {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: encodeString expects a string value, got ${typeof value}`);
  }
  let content;
  switch (type) {
    case "utf8": {
      const encoded = encodeUtf8(value);
      if (encoded === null) throw outOfRange(type, [...value].findIndex((c) => c.length === 1 && c.charCodeAt(0) >= 55296 && c.charCodeAt(0) <= 57343));
      content = encoded;
      break;
    }
    case "printable":
    case "ia5":
    case "visible":
    case "numeric": {
      const allowed = type === "printable" ? isPrintableOctet : type === "ia5" ? isIa5Octet : type === "visible" ? isVisibleOctet : isNumericOctet;
      content = new Uint8Array(value.length);
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code > 127 || !allowed(code)) throw outOfRange(type, i);
        content[i] = code;
      }
      break;
    }
    case "teletex":
      content = new Uint8Array(value.length);
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code > 255) throw outOfRange(type, i);
        content[i] = code;
      }
      break;
    case "bmp":
      content = new Uint8Array(value.length * 2);
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 55296 && code <= 57343) throw outOfRange(type, i);
        content[i * 2] = code >> 8;
        content[i * 2 + 1] = code & 255;
      }
      break;
    case "universal": {
      const points = [];
      let index = 0;
      for (const ch of value) {
        const lead = ch.charCodeAt(0);
        const code = ch.length === 2 ? 65536 + (lead - 55296 << 10) + (ch.charCodeAt(1) - 56320) : lead;
        if (code >= 55296 && code <= 57343) throw outOfRange(type, index);
        points.push(code >>> 24, code >> 16 & 255, code >> 8 & 255, code & 255);
        index += ch.length;
      }
      content = Uint8Array.from(points);
      break;
    }
    default:
      throw new PkiError("PKI_INVALID_OPTION", `pkinative: string type must be one of ${Object.keys(STRING_TAGS).join(", ")}, got ${String(type)}`);
  }
  return encodeTlv("universal", STRING_TAGS[type], false, content);
}
function pad(value, width) {
  return String(value).padStart(width, "0");
}
function encodeTime(epochMilliseconds, type = "rfc5280") {
  if (type !== "UTCTime" && type !== "GeneralizedTime" && type !== "rfc5280") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: time type must be 'UTCTime', 'GeneralizedTime' or 'rfc5280', got ${String(type)}`);
  }
  const date = new Date(typeof epochMilliseconds === "number" ? epochMilliseconds : NaN);
  const year = date.getUTCFullYear();
  if (Number.isNaN(date.getTime()) || year < 0 || year > 9999) {
    throw new PkiEncodingError("PKI_ASN1_VALUE_OUT_OF_RANGE", `pkinative: ${String(epochMilliseconds)} is not an instant in the years 0000 to 9999`);
  }
  const millisecond = date.getUTCMilliseconds();
  const resolved = type === "rfc5280" ? year >= 1950 && year <= 2049 ? "UTCTime" : "GeneralizedTime" : type;
  if (millisecond !== 0 && type !== "GeneralizedTime") {
    throw new PkiEncodingError(
      "PKI_ASN1_VALUE_OUT_OF_RANGE",
      `pkinative: ${date.toISOString()} has a fraction of a second, which ${type === "rfc5280" ? "RFC 5280 forbids in certificates" : "UTCTime cannot hold"} \u2014 round to whole seconds`
    );
  }
  const clock = `${pad(date.getUTCMonth() + 1, 2)}${pad(date.getUTCDate(), 2)}${pad(date.getUTCHours(), 2)}${pad(date.getUTCMinutes(), 2)}${pad(date.getUTCSeconds(), 2)}`;
  let text;
  if (resolved === "UTCTime") {
    if (year < 1950 || year > 2049) {
      throw new PkiEncodingError("PKI_ASN1_VALUE_OUT_OF_RANGE", `pkinative: UTCTime covers 1950 to 2049 only; ${year} needs GeneralizedTime`);
    }
    text = `${pad(year % 100, 2)}${clock}Z`;
  } else {
    const fraction = millisecond === 0 ? "" : `.${pad(millisecond, 3).replace(/0+$/, "")}`;
    text = `${pad(year, 4)}${clock}${fraction}Z`;
  }
  const content = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) content[i] = text.charCodeAt(i);
  return encodeTlv("universal", resolved === "UTCTime" ? TAG_UTC_TIME : TAG_GENERALIZED_TIME, false, content);
}
function encodeAsn1Node(node) {
  const root = assertNode(node, "encodeAsn1Node");
  const stack = [{ node: root, next: 0, parts: [] }];
  let result = new Uint8Array(0);
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    const current = top.node;
    if (current.indefinite) {
      throw new PkiError(
        "PKI_API_MISUSE",
        `pkinative: the value at offset ${current.offset} was decoded from the BER indefinite length form, which has no DER re-encoding \u2014 decode the original as DER, or keep its bytes`
      );
    }
    let encoded;
    if (!current.constructed) {
      encoded = encodeTlv(current.tagClass, current.tagNumber, false, current.content);
    } else {
      if (current.tagClass === "universal" && isStringTag(current.tagNumber)) {
        throw new PkiError(
          "PKI_API_MISUSE",
          `pkinative: the ${tagLabel(current.tagClass, current.tagNumber)} at offset ${current.offset} is a constructed string, which has no DER form \u2014 read it with the string reader and encode the result`
        );
      }
      if (top.next < current.children.length) {
        stack.push({ node: current.children[top.next], next: 0, parts: [] });
        top.next++;
        continue;
      }
      encoded = encodeTlv(current.tagClass, current.tagNumber, true, concatBytes(top.parts));
    }
    stack.pop();
    const parent = stack[stack.length - 1];
    if (parent === void 0) result = encoded;
    else parent.parts.push(encoded);
  }
  return result;
}

// src/build/build-structures.ts
var PARAMETERS_NULL = /* @__PURE__ */ new Set([
  "1.2.840.113549.1.1.1",
  "1.2.840.113549.1.1.5",
  "1.2.840.113549.1.1.11",
  "1.2.840.113549.1.1.12",
  "1.2.840.113549.1.1.13"
]);
function encodeAlgorithmIdentifier(oid, parameters) {
  const fields = [encodeObjectIdentifier(oid)];
  if (parameters !== void 0) fields.push(assertBytes(parameters, "encodeAlgorithmIdentifier parameters"));
  else if (PARAMETERS_NULL.has(oid)) fields.push(encodeNull());
  return encodeSequence(fields);
}
function encodeNameAttribute(attribute) {
  const { type, value, stringType } = attribute;
  const encoded = value instanceof Uint8Array ? value : typeof value === "string" ? encodeString(stringType ?? "utf8", value) : null;
  if (encoded === null) {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: the value of name attribute ${type} must be a string or a Uint8Array of its DER, got ${typeof value}`);
  }
  return encodeSequence([encodeObjectIdentifier(type), encoded]);
}
function encodeDistinguishedName(name, options) {
  if (!Array.isArray(name)) {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: a name is an array of relative distinguished names, got ${typeof name}`);
  }
  const limits = options?.limits === void 0 ? DEFAULT_PKI_LIMITS : resolveLimits(options.limits);
  let attributes = 0;
  const rdns = [];
  for (const rdn of name) {
    if (!Array.isArray(rdn) || rdn.length === 0) {
      throw new PkiError("PKI_INVALID_INPUT", "pkinative: every relative distinguished name is a non-empty array of attributes");
    }
    attributes += rdn.length;
    enforceLimit(limits, "maxNameAttributes", attributes, "the name being built");
    rdns.push(encodeSetOf(rdn.map(encodeNameAttribute)));
  }
  return encodeSequence(rdns);
}
function encodeValidity(notBefore, notAfter) {
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
    throw new PkiError("PKI_API_MISUSE", "pkinative: notBefore and notAfter are epoch milliseconds, and both must be finite numbers");
  }
  if (notAfter < notBefore) {
    throw new PkiError(
      "PKI_API_MISUSE",
      `pkinative: notAfter (${new Date(notAfter).toISOString()}) precedes notBefore (${new Date(notBefore).toISOString()}) \u2014 a certificate valid for a negative interval is valid nowhere`
    );
  }
  return encodeSequence([encodeTime(notBefore), encodeTime(notAfter)]);
}
function encodeExtension(extension) {
  const fields = [encodeObjectIdentifier(extension.oid)];
  if (extension.critical === true) fields.push(encodeBoolean(true));
  fields.push(encodeOctetString(assertBytes(extension.value, `extension ${extension.oid} value`)));
  return encodeSequence(fields);
}
function encodeExtensions(extensions, options) {
  const limits = options?.limits === void 0 ? DEFAULT_PKI_LIMITS : resolveLimits(options.limits);
  enforceLimit(limits, "maxExtensions", extensions.length, "the extensions being built");
  const seen = /* @__PURE__ */ new Set();
  for (const extension of extensions) {
    if (seen.has(extension.oid)) {
      throw new PkiError("PKI_API_MISUSE", `pkinative: extension ${extension.oid} appears twice; RFC 5280 \xA74.2 allows one instance, and which one a verifier reads is undefined`);
    }
    seen.add(extension.oid);
  }
  return encodeSequence(extensions.map(encodeExtension));
}
function encodeAttribute(oid, values) {
  return encodeSequence([encodeObjectIdentifier(oid), encodeSetOf(values)]);
}
function encodeSubjectPublicKeyInfo(algorithmOid, publicKey, parameters) {
  return encodeSequence([
    encodeAlgorithmIdentifier(algorithmOid, parameters),
    // A public key is a whole number of octets: no unused bits, ever.
    encodeBitString(assertBytes(publicKey, "encodeSubjectPublicKeyInfo publicKey"), 0)
  ]);
}
function encodeBasicConstraints(options) {
  const fields = [];
  if (options.cA) fields.push(encodeBoolean(true));
  if (options.pathLenConstraint !== void 0) {
    if (!Number.isInteger(options.pathLenConstraint) || options.pathLenConstraint < 0) {
      throw new PkiError("PKI_API_MISUSE", `pkinative: pathLenConstraint must be a non-negative integer, got ${String(options.pathLenConstraint)}`);
    }
    if (!options.cA) {
      throw new PkiError("PKI_API_MISUSE", "pkinative: pathLenConstraint is meaningful only when cA is true (RFC 5280 \xA74.2.1.9) \u2014 an end-entity certificate constrains no path");
    }
    fields.push(encodeInteger(options.pathLenConstraint));
  }
  return encodeSequence(fields);
}
var KEY_USAGE_BITS = /* @__PURE__ */ new Map([
  ["digitalSignature", 0],
  ["nonRepudiation", 1],
  ["keyEncipherment", 2],
  ["dataEncipherment", 3],
  ["keyAgreement", 4],
  ["keyCertSign", 5],
  ["cRLSign", 6],
  ["encipherOnly", 7],
  ["decipherOnly", 8]
]);
function encodeKeyUsage(usages) {
  const bits = [];
  for (const usage of usages) {
    const bit = KEY_USAGE_BITS.get(usage);
    if (bit === void 0) {
      throw new PkiError("PKI_INVALID_OPTION", `pkinative: ${usage} is not a KeyUsage of RFC 5280 \xA74.2.1.3 \u2014 one of ${[...KEY_USAGE_BITS.keys()].join(", ")}`);
    }
    bits.push(bit);
  }
  return encodeNamedBits(bits);
}
function encodeExtendedKeyUsage(purposes) {
  if (purposes.length === 0) {
    throw new PkiError("PKI_API_MISUSE", "pkinative: an extendedKeyUsage with no purpose permits nothing and is refused by RFC 5280 \xA74.2.1.12");
  }
  return encodeSequence(purposes.map(encodeObjectIdentifier));
}
function encodeSubjectKeyIdentifier(keyIdentifier) {
  return encodeOctetString(assertBytes(keyIdentifier, "subjectKeyIdentifier"));
}
function encodeAuthorityKeyIdentifier(keyIdentifier) {
  return encodeSequence([encodeImplicit(0, encodeOctetString(assertBytes(keyIdentifier, "authorityKeyIdentifier")))]);
}
function encodeSubjectAltName(names) {
  if (names.length === 0) {
    throw new PkiError("PKI_API_MISUSE", "pkinative: a subjectAltName with no name is refused by RFC 5280 \xA74.2.1.6 \u2014 omit the extension instead");
  }
  const tags = { rfc822Name: 1, dNSName: 2, uniformResourceIdentifier: 6 };
  return encodeSequence(names.map((name) => {
    if (name.kind === "directoryNameDer") return encodeExplicit(4, assertBytes(name.value, "directoryName"));
    if (name.kind === "iPAddress") {
      const address = assertBytes(name.value, "iPAddress");
      if (address.length !== 4 && address.length !== 16) {
        throw new PkiError("PKI_INVALID_OPTION", `pkinative: an iPAddress in a subjectAltName is 4 octets (IPv4) or 16 (IPv6), not ${String(address.length)} \u2014 the 8- and 32-octet forms carry a mask and belong to nameConstraints (RFC 5280 \xA74.2.1.6)`);
      }
      return encodeImplicit(7, encodeOctetString(address));
    }
    if (name.kind === "registeredID") return encodeImplicit(8, encodeObjectIdentifier(name.value));
    const tag = tags[name.kind];
    if (tag === void 0) {
      throw new PkiError("PKI_INVALID_OPTION", `pkinative: ${String(name.kind)} is not a GeneralName form this encoder writes \u2014 pass a directoryNameDer, or build the GeneralName with encodeImplicit`);
    }
    return encodeImplicit(tag, encodeString("ia5", name.value));
  }));
}

// src/hash/hash-shared.ts
var HIGH_WORD_UNIT = 536870912;
function writeBitLength(target, end, byteLength) {
  const view = new DataView(target.buffer, target.byteOffset, target.byteLength);
  view.setUint32(end - 8, Math.floor(byteLength / HIGH_WORD_UNIT), false);
  view.setUint32(end - 4, byteLength % HIGH_WORD_UNIT * 8, false);
}
function padMessage(input, blockSize, lengthOctets) {
  const total = Math.ceil((input.length + 1 + lengthOctets) / blockSize) * blockSize;
  const padded = new Uint8Array(total);
  padded.set(input);
  padded[input.length] = 128;
  writeBitLength(padded, total, input.length);
  return padded;
}

// src/hash/sha1.ts
function rotl(x, n) {
  return (x << n | x >>> 32 - n) >>> 0;
}
function sha1(input) {
  const padded = padMessage(input, 64, 8);
  const view = new DataView(padded.buffer);
  const w = new Uint32Array(80);
  let h0 = 1732584193;
  let h1 = 4023233417;
  let h2 = 2562383102;
  let h3 = 271733878;
  let h4 = 3285377520;
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let j = 0; j < 16; j++) w[j] = view.getUint32(offset + j * 4, false);
    for (let j = 16; j < 80; j++) {
      w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
    }
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let j = 0; j < 80; j++) {
      let f;
      let k;
      if (j < 20) {
        f = b & c | ~b & d;
        k = 1518500249;
      } else if (j < 40) {
        f = b ^ c ^ d;
        k = 1859775393;
      } else if (j < 60) {
        f = b & c | b & d | c & d;
        k = 2400959708;
      } else {
        f = b ^ c ^ d;
        k = 3395469782;
      }
      const temp = rotl(a, 5) + f + e + k + w[j] >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }
    h0 = h0 + a >>> 0;
    h1 = h1 + b >>> 0;
    h2 = h2 + c >>> 0;
    h3 = h3 + d >>> 0;
    h4 = h4 + e >>> 0;
  }
  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((word, i) => outView.setUint32(i * 4, word, false));
  return out;
}

// src/hash/sha256.ts
var K = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
function rotr(x, n) {
  return x >>> n | x << 32 - n;
}
function sha256(input) {
  const padded = padMessage(input, 64, 8);
  const view = new DataView(padded.buffer);
  const w = new Uint32Array(64);
  let h0 = 1779033703;
  let h1 = 3144134277;
  let h2 = 1013904242;
  let h3 = 2773480762;
  let h4 = 1359893119;
  let h5 = 2600822924;
  let h6 = 528734635;
  let h7 = 1541459225;
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let j = 0; j < 16; j++) w[j] = view.getUint32(offset + j * 4, false);
    for (let j = 16; j < 64; j++) {
      const x = w[j - 15];
      const y = w[j - 2];
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ x >>> 3;
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ y >>> 10;
      w[j] = w[j - 16] + s0 + w[j - 7] + s1 >>> 0;
    }
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;
    for (let j = 0; j < 64; j++) {
      const temp1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + (e & f ^ ~e & g) + K[j] + w[j] >>> 0;
      const temp2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + (a & b ^ a & c ^ b & c) >>> 0;
      h = g;
      g = f;
      f = e;
      e = d + temp1 >>> 0;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2 >>> 0;
    }
    h0 = h0 + a >>> 0;
    h1 = h1 + b >>> 0;
    h2 = h2 + c >>> 0;
    h3 = h3 + d >>> 0;
    h4 = h4 + e >>> 0;
    h5 = h5 + f >>> 0;
    h6 = h6 + g >>> 0;
    h7 = h7 + h >>> 0;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((word, i) => outView.setUint32(i * 4, word, false));
  return out;
}

// src/revocation/ocsp-request.ts
var HASH_OID = Object.freeze({
  "SHA-1": "1.3.14.3.2.26",
  "SHA-256": "2.16.840.1.101.3.4.2.1"
});
function encodeCertId(certificate, issuer, algorithm = "SHA-1") {
  assertParsed(certificate, "certificate");
  assertParsed(issuer, "issuer");
  const digest = algorithm === "SHA-1" ? sha1 : sha256;
  const nameHash = digest(issuer.subject.der);
  const keyHash = digest(issuer.subjectPublicKeyInfo.publicKey.bytes);
  return encodeSequence([
    encodeAlgorithmIdentifier(HASH_OID[algorithm], NULL_PARAMETERS),
    encodeOctetString(nameHash),
    encodeOctetString(keyHash),
    encodeTlv("universal", 2, false, certificate.serialNumber.bytes)
  ]);
}
var NULL_PARAMETERS = /* @__PURE__ */ encodeTlv("universal", 5, false, new Uint8Array(0));
function createOcspRequest(certificate, issuer, options) {
  const certId = encodeCertId(certificate, issuer, options?.hashAlgorithm ?? "SHA-1");
  const requestList = encodeSequence([encodeSequence([certId])]);
  const fields = [requestList];
  const nonce = options?.nonce;
  if (nonce !== void 0) {
    if (!(nonce instanceof Uint8Array)) {
      throw new PkiError("PKI_INVALID_INPUT", "pkinative: the OCSP nonce must be a Uint8Array of random bytes \u2014 pkinative generates none, so this is yours to produce with crypto.getRandomValues");
    }
    fields.push(encodeTlv("context", 2, true, encodeSequence([
      encodeSequence([
        encodeTlv("universal", 6, false, Uint8Array.of(43, 6, 1, 5, 5, 7, 48, 1, 2)),
        encodeOctetString(encodeOctetString(nonce))
      ])
    ])));
  }
  return encodeSequence([encodeSequence(fields)]);
}
function assertParsed(value, what) {
  if (typeof value !== "object" || value === null || !(value.der instanceof Uint8Array)) {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: ${what} must be a Certificate from parseCertificate(), not raw bytes`);
  }
}

// src/revocation/ocsp-response.ts
var STRUCTURE2 = "PKI_X509_STRUCTURE_INVALID";
var OID_BASIC_RESPONSE = "1.3.6.1.5.5.7.48.1.1";
var STATUSES = Object.freeze({
  0: "successful",
  1: "malformedRequest",
  2: "internalError",
  3: "tryLater",
  5: "sigRequired",
  6: "unauthorized"
});
var REASONS3 = Object.freeze({
  0: "unspecified",
  1: "keyCompromise",
  2: "cACompromise",
  3: "affiliationChanged",
  4: "superseded",
  5: "cessationOfOperation",
  6: "certificateHold",
  8: "removeFromCRL",
  9: "privilegeWithdrawn",
  10: "aACompromise"
});
function ocspError(path, offset, why) {
  return new PkiCertificateError(STRUCTURE2, `pkinative: ${path} ${why} \u2014 the input is not an RFC 6960 OCSPResponse`, path, offset);
}
var decodeAt2 = (der, header, ctx) => decodeValueAt(der, header.offset, ctx);
function parseOcspResponse(der, options) {
  const ctx = createAsn1Context(options);
  const outer = readTlvHeader(der, 0, "OCSPResponse");
  if (!outer.constructed || outer.tagClass !== "universal" || outer.tagNumber !== 16) {
    throw ocspError("OCSPResponse", 0, "is not a SEQUENCE");
  }
  const parts = [...walkChildren(der, outer, "OCSPResponse")];
  const statusField = parts[0];
  if (statusField === void 0 || statusField.tagClass !== "universal" || statusField.tagNumber !== 10) {
    throw ocspError("OCSPResponse.responseStatus", outer.offset, "is not an ENUMERATED");
  }
  if (statusField.length !== 1) {
    throw ocspError("OCSPResponse.responseStatus", statusField.offset, "is wider than one octet; RFC 6960 defines seven values");
  }
  const code = der[statusField.contentStart];
  const status = STATUSES[code];
  if (status === void 0) {
    throw ocspError("OCSPResponse.responseStatus", statusField.offset, `is ${String(code)}, which RFC 6960 \xA74.2.1 does not define (4 is unassigned)`);
  }
  const bytesField = parts[1];
  let basicResponse;
  if (bytesField !== void 0) {
    if (bytesField.tagClass !== "context" || bytesField.tagNumber !== 0) {
      throw ocspError("OCSPResponse.responseBytes", bytesField.offset, "is not [0] EXPLICIT");
    }
    basicResponse = readResponseBytes(der, bytesField, ctx);
  }
  if (status === "successful" && basicResponse === void 0) {
    throw ocspError("OCSPResponse", outer.offset, "says successful and carries no responseBytes; RFC 6960 \xA74.2.1 requires one");
  }
  if (status !== "successful" && basicResponse !== void 0) {
    throw ocspError("OCSPResponse", outer.offset, `says ${status} and still carries responseBytes; only a successful response has a body`);
  }
  return Object.freeze({
    der: der.subarray(outer.offset, outer.end),
    status,
    basicResponse,
    diagnostics: ctx.emitter.diagnostics
  });
}
function readResponseBytes(der, field, ctx) {
  const wrapper = [...walkChildren(der, field, "OCSPResponse.responseBytes")][0];
  if (wrapper === void 0) throw ocspError("OCSPResponse.responseBytes", field.offset, "is empty");
  const inner = [...walkChildren(der, wrapper, "ResponseBytes")];
  const typeField = inner[0];
  const valueField = inner[1];
  if (typeField === void 0 || valueField === void 0) {
    throw ocspError("ResponseBytes", wrapper.offset, "does not hold a responseType and a response");
  }
  const responseType = readObjectIdentifier(decodeAt2(der, typeField, ctx));
  if (responseType !== OID_BASIC_RESPONSE) {
    throw ocspError("ResponseBytes.responseType", typeField.offset, `is ${responseType}; only id-pkix-ocsp-basic (${OID_BASIC_RESPONSE}) is defined by RFC 6960`);
  }
  const body = der.subarray(valueField.contentStart, valueField.end);
  return readBasicResponse(body, ctx);
}
function readBasicResponse(der, ctx) {
  const outer = readTlvHeader(der, 0, "BasicOCSPResponse");
  const parts = [...walkChildren(der, outer, "BasicOCSPResponse")];
  const tbs = parts[0];
  const algorithmField = parts[1];
  const signatureField = parts[2];
  if (tbs === void 0 || algorithmField === void 0 || signatureField === void 0) {
    throw ocspError("BasicOCSPResponse", outer.offset, "holds fewer than the three required fields");
  }
  const signatureNode = decodeAt2(der, signatureField, ctx);
  if (signatureNode.tagClass !== "universal" || signatureNode.tagNumber !== 3) {
    throw ocspError("BasicOCSPResponse.signature", signatureField.offset, "is not a BIT STRING");
  }
  const certificates = [];
  const certsField = parts[3];
  if (certsField !== void 0) {
    const seq = [...walkChildren(der, certsField, "BasicOCSPResponse.certs")][0];
    for (const certificate of seq === void 0 ? [] : [...walkChildren(der, seq, "BasicOCSPResponse.certs")]) {
      enforceLimit(ctx.limits, "maxChainLength", certificates.length + 1, "BasicOCSPResponse.certs");
      certificates.push(der.subarray(certificate.offset, certificate.end));
    }
  }
  const data = readResponseData(der, tbs, ctx);
  return Object.freeze({
    tbsDer: der.subarray(tbs.offset, tbs.end),
    responderId: data.responderId,
    producedAt: data.producedAt,
    responses: data.responses,
    signatureAlgorithm: _readAlgorithmIdentifier(decodeAt2(der, algorithmField, ctx), ctx, "BasicOCSPResponse.signatureAlgorithm", STRUCTURE2, outer.offset),
    signatureValue: Object.freeze({ bytes: signatureNode.content.subarray(1), unusedBits: signatureNode.content[0] ?? 0 }),
    certificates: Object.freeze(certificates),
    extensions: data.extensions
  });
}
function readResponseData(der, tbs, ctx) {
  const fields = [...walkChildren(der, tbs, "ResponseData")];
  let at = 0;
  if (fields[0]?.tagClass === "context" && fields[0].tagNumber === 0) at += 1;
  const idField = fields[at];
  if (idField === void 0 || idField.tagClass !== "context" || idField.tagNumber !== 1 && idField.tagNumber !== 2) {
    throw ocspError("ResponseData.responderID", tbs.offset, "is neither byName [1] nor byKey [2]");
  }
  at += 1;
  const responderId = readResponderId(der, idField, ctx);
  const producedAtField = fields[at];
  if (producedAtField === void 0) throw ocspError("ResponseData.producedAt", tbs.offset, "is missing");
  at += 1;
  const producedAt = _readTime(decodeAt2(der, producedAtField, ctx), ctx, void 0);
  const responsesField = fields[at];
  if (responsesField === void 0 || responsesField.tagClass !== "universal" || responsesField.tagNumber !== 16) {
    throw ocspError("ResponseData.responses", tbs.offset, "is not a SEQUENCE");
  }
  at += 1;
  const responses = [];
  let index = 0;
  for (const single of walkChildren(der, responsesField, "ResponseData.responses")) {
    enforceLimit(ctx.limits, "maxOcspResponses", index + 1, `ResponseData.responses[${String(index)}]`);
    responses.push(readSingleResponse(der, single, ctx, `ResponseData.responses[${String(index)}]`));
    index += 1;
  }
  const extensionsField = fields[at];
  const extensions = extensionsField === void 0 ? [] : readExtensions2(der, extensionsField, ctx, "ResponseData.responseExtensions");
  return { responderId, producedAt, responses: Object.freeze(responses), extensions };
}
function readResponderId(der, field, ctx) {
  const inner = [...walkChildren(der, field, "ResponseData.responderID")][0];
  if (inner === void 0) throw ocspError("ResponseData.responderID", field.offset, "is empty");
  if (field.tagNumber === 1) return { kind: "byName", nameDer: der.subarray(inner.offset, inner.end) };
  const node = decodeAt2(der, inner, ctx);
  if (node.tagClass !== "universal" || node.tagNumber !== 4) {
    throw ocspError("ResponseData.responderID", inner.offset, "byKey is not an OCTET STRING");
  }
  return { kind: "byKey", keyHash: node.content };
}
function readSingleResponse(der, single, ctx, path) {
  const fields = [...walkChildren(der, single, path)];
  const idField = fields[0];
  const statusField = fields[1];
  const thisUpdateField = fields[2];
  if (idField === void 0 || statusField === void 0 || thisUpdateField === void 0) {
    throw ocspError(path, single.offset, "holds fewer than the three required fields");
  }
  let at = 3;
  let nextUpdate;
  if (fields[at]?.tagClass === "context" && fields[at]?.tagNumber === 0) {
    const inner = [...walkChildren(der, fields[at], `${path}.nextUpdate`)][0];
    if (inner !== void 0) nextUpdate = _readTime(decodeAt2(der, inner, ctx), ctx, void 0);
    at += 1;
  }
  const extensionsField = fields[at];
  return Object.freeze({
    certId: readCertId(der, idField, ctx, `${path}.certID`),
    status: readCertStatus(der, statusField, ctx, `${path}.certStatus`),
    thisUpdate: _readTime(decodeAt2(der, thisUpdateField, ctx), ctx, void 0),
    nextUpdate,
    extensions: extensionsField === void 0 ? [] : readExtensions2(der, extensionsField, ctx, `${path}.singleExtensions`)
  });
}
function readCertId(der, field, ctx, path) {
  const parts = [...walkChildren(der, field, path)];
  const [algorithmField, nameHashField, keyHashField, serialField] = parts;
  if (parts.length !== 4 || algorithmField === void 0 || nameHashField === void 0 || keyHashField === void 0 || serialField === void 0) {
    throw ocspError(path, field.offset, `holds ${String(parts.length)} values where a CertID has four`);
  }
  const serialContent = der.subarray(serialField.contentStart, serialField.end);
  return Object.freeze({
    hashAlgorithm: _readAlgorithmIdentifier(decodeAt2(der, algorithmField, ctx), ctx, `${path}.hashAlgorithm`, STRUCTURE2, field.offset),
    issuerNameHash: decodeAt2(der, nameHashField, ctx).content,
    issuerKeyHash: decodeAt2(der, keyHashField, ctx).content,
    serialNumber: Object.freeze({
      bytes: serialContent,
      hex: toHex(serialContent),
      value: readInteger(decodeAt2(der, serialField, ctx))
    })
  });
}
function readCertStatus(der, field, ctx, path) {
  if (field.tagClass !== "context") throw ocspError(path, field.offset, "is not a context-tagged CHOICE");
  if (field.tagNumber === 0) return { kind: "good" };
  if (field.tagNumber === 2) return { kind: "unknown" };
  if (field.tagNumber !== 1) throw ocspError(path, field.offset, `is [${String(field.tagNumber)}]; RFC 6960 defines [0] good, [1] revoked and [2] unknown`);
  const parts = [...walkChildren(der, field, path)];
  const timeField = parts[0];
  if (timeField === void 0) throw ocspError(path, field.offset, "is revoked and carries no revocationTime");
  let reason;
  const reasonField = parts[1];
  if (reasonField !== void 0 && reasonField.tagClass === "context" && reasonField.tagNumber === 0) {
    const inner = [...walkChildren(der, reasonField, `${path}.revocationReason`)][0];
    if (inner !== void 0 && inner.length === 1) reason = REASONS3[der[inner.contentStart]];
  }
  return { kind: "revoked", revocationTime: _readTime(decodeAt2(der, timeField, ctx), ctx, void 0), reason };
}
function readExtensions2(der, field, ctx, path) {
  if (field.tagClass !== "context") throw ocspError(path, field.offset, "is not a context-tagged Extensions field");
  const wrapper = [...walkChildren(der, field, path)][0];
  if (wrapper === void 0) return [];
  const out = [];
  let index = 0;
  for (const entry of walkChildren(der, wrapper, path)) {
    const where2 = `${path}[${String(index)}]`;
    enforceLimit(ctx.limits, "maxExtensions", index + 1, where2);
    const node = decodeAt2(der, entry, ctx);
    const oidNode = node.children[0];
    const valueNode = node.children[node.children.length - 1];
    if (oidNode === void 0 || valueNode === void 0 || node.children.length < 2) {
      throw ocspError(where2, entry.offset, "is not an Extension");
    }
    const criticalNode = node.children.length === 3 ? node.children[1] : void 0;
    out.push(_decodeExtension(
      der,
      entry.offset,
      readObjectIdentifier(oidNode),
      criticalNode !== void 0 && criticalNode.content[0] !== 0,
      valueNode.content,
      ctx,
      where2
    ));
    index += 1;
  }
  return Object.freeze(out);
}

// src/revocation/ocsp-check.ts
var OCSP_NONCE_OID = "1.3.6.1.5.5.7.48.1.2";
var MINUTE = 6e4;
function checkOcspStatus(input) {
  const out = [];
  const path = "ocsp";
  if (input.response.status !== "successful") {
    out.push(revocationUnknownReason(path, `the responder declined with ${input.response.status}, which says nothing about this certificate`));
    return out;
  }
  const basic = input.response.basicResponse;
  if (basic === void 0) {
    out.push(revocationUnknownReason(path, "the response carries no body"));
    return out;
  }
  if (input.signatureVerified !== true) {
    out.push(revocationUnknownReason(path, input.signatureVerified === false ? "the responder's signature did not verify against the key it was checked with" : "the responder's signature was never checked, and an unsigned response is something anyone can produce"));
  }
  if (input.responderAuthorised !== true) {
    out.push(revocationUnknownReason(path, input.responderAuthorised === false ? "the signer is not authorised to answer for this CA (RFC 6960 \xA74.2.2.2)" : "nothing says the signer is authorised to answer for this CA, and a responder nobody authorised is a responder anyone can be"));
  }
  out.push(...checkNonce(basic, input, path));
  const answer = basic.responses.find((single) => matches(single, input.expected));
  if (answer === void 0) {
    out.push(revocationMismatchReason(path, describeMismatch(basic, input)));
    return out;
  }
  out.push(...checkFreshness(answer, input, path));
  if (answer.status.kind === "revoked") {
    out.push(revokedReason(path, answer.status.revocationTime.epochMilliseconds, answer.status.reason));
  } else if (answer.status.kind === "unknown") {
    out.push(revocationUnknownReason(path, "the responder answered unknown, meaning it has no record of this certificate \u2014 often a sign the serial does not belong to that CA"));
  }
  return out;
}
function matches(single, expected) {
  return bytesEqual(single.certId.issuerNameHash, expected.issuerNameHash) && bytesEqual(single.certId.issuerKeyHash, expected.issuerKeyHash) && bytesEqual(single.certId.serialNumber.bytes, expected.serialNumber);
}
function describeMismatch(basic, input) {
  if (basic.responses.length === 0) return "the response carries no answers at all";
  const first = basic.responses[0];
  if (!bytesEqual(first.certId.serialNumber.bytes, input.expected.serialNumber)) {
    return `it answers about serial ${first.certId.serialNumber.hex}, and the question was about ${hex(input.expected.serialNumber)}`;
  }
  if (!bytesEqual(first.certId.issuerNameHash, input.expected.issuerNameHash)) {
    return "the serial matches but the issuer name hash does not, so the answer is about a certificate from another CA";
  }
  return "the serial matches but the issuer key hash does not, so the answer is about a certificate under another key";
}
function hex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}
function checkNonce(basic, input, path) {
  const sent = input.nonce;
  if (sent === void 0) return [];
  const echoed = basic.extensions.find((extension) => extension.oid === OCSP_NONCE_OID);
  if (echoed === void 0) {
    return input.requireNonce === true ? [revocationMismatchReason(path, "no nonce came back, and requireNonce was asked for \u2014 without an echo this response may be a replay")] : [];
  }
  const inner = unwrapOctetString(echoed.valueDer);
  if (inner === null || !bytesEqual(inner, sent)) {
    return [revocationMismatchReason(path, "the nonce that came back is not the one that was sent")];
  }
  return [];
}
function unwrapOctetString(bytes) {
  if (bytes.length < 2 || bytes[0] !== 4) return null;
  const length = bytes[1];
  if (length > 127 || 2 + length > bytes.length) return null;
  return bytes.subarray(2, 2 + length);
}
function checkFreshness(answer, input, path) {
  const out = [];
  const future = input.futureTolerance ?? MINUTE;
  if (answer.thisUpdate.epochMilliseconds > input.at + future) {
    out.push(revocationStaleReason(path, void 0, input.at));
  }
  const nextUpdate = answer.nextUpdate?.epochMilliseconds;
  if (nextUpdate !== void 0 && input.at > nextUpdate + (input.staleTolerance ?? 0)) {
    out.push(revocationStaleReason(path, nextUpdate, input.at));
  }
  return out;
}

// src/path/path-name-constraints.ts
var FORMS = ["dNSName", "rfc822Name", "uniformResourceIdentifier", "iPAddress", "directoryName"];
function initialNameConstraints() {
  const permitted = {};
  const excluded = {};
  for (const form of FORMS) {
    permitted[form] = null;
    excluded[form] = [];
  }
  return { permitted, excluded, unprocessed: /* @__PURE__ */ new Set() };
}
function formOf(base) {
  return FORMS.includes(base.kind) ? base.kind : null;
}
var fold = (text) => text.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
function dnsMatches(constraint, name) {
  const c = fold(constraint);
  const n = fold(name);
  if (c === "") return true;
  if (c.startsWith(".")) return n.endsWith(c);
  return n === c || n.endsWith(`.${c}`);
}
function emailMatches(constraint, name) {
  const c = fold(constraint);
  const n = fold(name);
  if (c === "") return true;
  const at = n.lastIndexOf("@");
  if (c.includes("@")) return n === c;
  const host = at >= 0 ? n.slice(at + 1) : n;
  if (c.startsWith(".")) return host.endsWith(c);
  return host === c;
}
function uriMatches(constraint, uri) {
  const host = uriHost(uri);
  if (host === null) return false;
  const c = fold(constraint);
  const h = fold(host);
  if (c === "") return true;
  if (c.startsWith(".")) return h.endsWith(c);
  return h === c;
}
function uriHost(uri) {
  const schemeEnd = uri.indexOf("://");
  if (schemeEnd < 0) return null;
  let authority = uri.slice(schemeEnd + 3);
  for (const stop of ["/", "?", "#"]) {
    const at2 = authority.indexOf(stop);
    if (at2 >= 0) authority = authority.slice(0, at2);
  }
  const at = authority.lastIndexOf("@");
  if (at >= 0) authority = authority.slice(at + 1);
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0) return null;
    authority = authority.slice(0, close + 1);
  } else {
    const colon = authority.indexOf(":");
    if (colon >= 0) authority = authority.slice(0, colon);
  }
  return authority === "" ? null : authority;
}
function ipMatches(constraintBytes, nameBytes) {
  const width = nameBytes.length;
  if (constraintBytes.length !== width * 2) return false;
  for (let i = 0; i < width; i += 1) {
    const mask = constraintBytes[width + i];
    if ((nameBytes[i] & mask) !== (constraintBytes[i] & mask)) return false;
  }
  return true;
}
function directoryMatches(constraint, name) {
  if (constraint.rdns.length > name.rdns.length) return false;
  return constraint.rdns.every((rdn, i) => _sameRdn(rdn, name.rdns[i]));
}
function _sameRdn(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    const y = b[i];
    return x.type === y.type && x.valueDer.length === y.valueDer.length && x.valueDer.every((byte, k) => byte === y.valueDer[k]);
  });
}
function wellFormedName(name) {
  switch (name.kind) {
    case "dNSName":
      return _wellFormedHost(name.value);
    case "rfc822Name": {
      const at = name.value.indexOf("@");
      return at > 0 && name.value.indexOf("@", at + 1) < 0 && _wellFormedHost(name.value.slice(at + 1));
    }
    case "uniformResourceIdentifier": {
      const host = uriHost(name.value);
      return host !== null && (host.startsWith("[") || _wellFormedHost(host));
    }
    case "iPAddress":
      return name.bytes.length === 4 || name.bytes.length === 16;
    default:
      return true;
  }
}
function _wellFormedHost(host) {
  if (host === "" || host.endsWith(".")) return false;
  return host.split(".").every((label) => label !== "");
}
function _starredSet(value) {
  if (!value.includes("*")) return null;
  const labels = fold(value).split(".");
  let last = -1;
  for (const [index, label] of labels.entries()) if (label.includes("*")) last = index;
  const parent = labels.slice(last + 1).join(".");
  return _wellFormedHost(parent) ? { parent, labels: last + 1 } : null;
}
function subtreeCoversWildcard(base, parent) {
  const b = fold(base);
  if (b === "") return true;
  if (b.startsWith(".")) return parent === b.slice(1) || parent.endsWith(b);
  return dnsMatches(b, parent);
}
function wildcardMeetsSubtree(base, parent, labels = 1) {
  if (subtreeCoversWildcard(base, parent)) return true;
  const b = fold(base);
  if (b.startsWith(".") || !b.endsWith(`.${parent}`)) return false;
  return b.slice(0, b.length - parent.length - 1).split(".").length === labels;
}
function subtreeCovers(subtree, name) {
  const base = subtree.base;
  if (base.kind !== name.kind) return false;
  if (subtree.minimum !== 0 || subtree.maximum !== void 0) return false;
  switch (base.kind) {
    case "dNSName":
      return name.kind === "dNSName" && dnsMatches(base.value, name.value);
    case "rfc822Name":
      return name.kind === "rfc822Name" && emailMatches(base.value, name.value);
    case "uniformResourceIdentifier":
      return name.kind === "uniformResourceIdentifier" && uriMatches(base.value, name.value);
    case "iPAddress":
      return name.kind === "iPAddress" && ipMatches(base.bytes, name.bytes);
    case "directoryName":
      return name.kind === "directoryName" && directoryMatches(base.name, name.name);
    default:
      return false;
  }
}
function accumulateNameConstraints(state, permitted, excluded) {
  if (permitted !== void 0) {
    const byForm = /* @__PURE__ */ new Map();
    for (const subtree of permitted) {
      const form = formOf(subtree.base);
      if (form === null) {
        state.unprocessed.add(subtree.base.kind);
        continue;
      }
      byForm.set(form, [...byForm.get(form) ?? [], subtree]);
    }
    for (const [form, subtrees] of byForm) {
      const existing = state.permitted[form];
      if (existing === null) {
        state.permitted[form] = subtrees;
        continue;
      }
      state.permitted[form] = subtrees.filter((subtree) => existing.some((outer) => subtreeCovers(outer, subtree.base)));
    }
  }
  for (const subtree of excluded ?? []) {
    const form = formOf(subtree.base);
    if (form === null) {
      state.unprocessed.add(subtree.base.kind);
      continue;
    }
    state.excluded[form] = [...state.excluded[form], subtree];
  }
}
function checkName(state, name) {
  const form = formOf(name);
  if (form === null) {
    return state.unprocessed.has(name.kind) ? { form: "directoryName", text: `${name.kind} \u2014 a constrained name form this validator does not process`, why: "not-permitted" } : null;
  }
  const text = nameText(name);
  const constrained = state.permitted[form] !== null || state.excluded[form].length > 0;
  const set = name.kind === "dNSName" ? _starredSet(name.value) : null;
  if (set !== null) {
    const usable = (subtree) => subtree.base.kind === "dNSName" && subtree.minimum === 0 && subtree.maximum === void 0;
    for (const subtree of state.excluded[form]) {
      if (usable(subtree) && wildcardMeetsSubtree(subtree.base.value, set.parent, set.labels)) {
        return { form, text, why: "excluded" };
      }
    }
    const permitted2 = state.permitted[form];
    if (permitted2 === null) return null;
    const whole = permitted2.some((subtree) => usable(subtree) && subtreeCoversWildcard(subtree.base.value, set.parent));
    return whole ? null : { form, text, why: "not-permitted" };
  }
  if (constrained && !wellFormedName(name)) return { form, text, why: "not-permitted" };
  for (const subtree of state.excluded[form]) {
    if (subtreeCovers(subtree, name)) return { form, text, why: "excluded" };
  }
  const permitted = state.permitted[form];
  if (permitted === null) return null;
  if (permitted.some((subtree) => subtreeCovers(subtree, name))) return null;
  return { form, text, why: "not-permitted" };
}
function nameText(name) {
  switch (name.kind) {
    case "dNSName":
    case "rfc822Name":
    case "uniformResourceIdentifier":
      return name.value;
    case "iPAddress":
      return name.address;
    case "directoryName":
      return `directoryName with ${String(name.name.rdns.length)} RDN(s)`;
    default:
      return name.kind;
  }
}

// src/path/path-policies.ts
var ANY_POLICY = "2.5.29.32.0";
function initialPolicyState(n, requireExplicit, inhibitMapping, inhibitAny) {
  const root = {
    validPolicy: ANY_POLICY,
    qualifiers: [],
    expectedPolicySet: [ANY_POLICY],
    children: [],
    alive: true
  };
  return {
    levels: [[root]],
    explicitPolicy: requireExplicit ? 0 : n + 1,
    policyMapping: inhibitMapping ? 0 : n + 1,
    inhibitAnyPolicy: inhibitAny ? 0 : n + 1,
    nodeCount: 1
  };
}
var live = (level) => level.filter((node) => node.alive);
function deepest(state) {
  return state.levels === null ? null : state.levels[state.levels.length - 1];
}
function prunePolicyTree(state) {
  const levels = state.levels;
  if (levels === null) return;
  for (let depth = levels.length - 2; depth >= 0; depth -= 1) {
    const level = levels[depth];
    const below = levels[depth + 1];
    for (const node of level) {
      if (!node.alive) continue;
      node.children = node.children.filter((index) => below[index]?.alive === true);
      if (node.children.length === 0) node.alive = false;
    }
  }
  if (live(levels[0]).length === 0) state.levels = null;
}
function growPolicyTree(state, policies, maxNodes) {
  const levels = state.levels;
  const parents = deepest(state);
  if (levels === null || parents === null) return "ok";
  const next = [];
  const push = (node, parentIndex) => {
    if (state.nodeCount >= maxNodes) return false;
    parents[parentIndex]?.children.push(next.length);
    next.push(node);
    state.nodeCount += 1;
    return true;
  };
  const asserted = policies.filter((policy) => policy.policyIdentifier !== ANY_POLICY);
  for (const policy of asserted) {
    const id = policy.policyIdentifier;
    let matched = false;
    for (const [index, parent] of parents.entries()) {
      if (!parent.alive || !parent.expectedPolicySet.includes(id)) continue;
      if (!push({ validPolicy: id, qualifiers: policy.qualifiers, expectedPolicySet: [id], children: [], alive: true }, index)) return "limit";
      matched = true;
    }
    if (matched) continue;
    for (const [index, parent] of parents.entries()) {
      if (!parent.alive || !parent.expectedPolicySet.includes(ANY_POLICY)) continue;
      if (!push({ validPolicy: id, qualifiers: policy.qualifiers, expectedPolicySet: [id], children: [], alive: true }, index)) return "limit";
    }
  }
  const any = policies.find((policy) => policy.policyIdentifier === ANY_POLICY);
  if (any !== void 0 && state.inhibitAnyPolicy > 0) {
    for (const [index, parent] of parents.entries()) {
      if (!parent.alive) continue;
      for (const expected of parent.expectedPolicySet) {
        if (next.some((node, i) => node.validPolicy === expected && parent.children.includes(i))) continue;
        if (!push({ validPolicy: expected, qualifiers: any.qualifiers, expectedPolicySet: [expected], children: [], alive: true }, index)) return "limit";
      }
    }
  }
  levels.push(next);
  prunePolicyTree(state);
  return "ok";
}
function killPolicyTree(state) {
  state.levels = null;
}
function applyPolicyMappings(state, mappings) {
  const level = deepest(state);
  if (level === null) return;
  const usable = mappings.filter((m) => m.issuerDomainPolicy !== ANY_POLICY && m.subjectDomainPolicy !== ANY_POLICY);
  const byIssuer = /* @__PURE__ */ new Map();
  for (const mapping of usable) {
    byIssuer.set(mapping.issuerDomainPolicy, [...byIssuer.get(mapping.issuerDomainPolicy) ?? [], mapping.subjectDomainPolicy]);
  }
  for (const node of level) {
    if (!node.alive) continue;
    const mapped = byIssuer.get(node.validPolicy);
    if (mapped === void 0) continue;
    if (state.policyMapping > 0) node.expectedPolicySet = mapped;
    else node.alive = false;
  }
  if (state.policyMapping === 0) prunePolicyTree(state);
}
function advancePolicyCounters(state, selfIssued, requireExplicit, inhibitMapping, inhibitAny) {
  if (!selfIssued) {
    if (state.explicitPolicy > 0) state.explicitPolicy -= 1;
    if (state.policyMapping > 0) state.policyMapping -= 1;
    if (state.inhibitAnyPolicy > 0) state.inhibitAnyPolicy -= 1;
  }
  if (requireExplicit !== void 0 && requireExplicit < state.explicitPolicy) state.explicitPolicy = requireExplicit;
  if (inhibitMapping !== void 0 && inhibitMapping < state.policyMapping) state.policyMapping = inhibitMapping;
  if (inhibitAny !== void 0 && inhibitAny < state.inhibitAnyPolicy) state.inhibitAnyPolicy = inhibitAny;
}
function wrapUpPolicies(state, initialPolicySet) {
  const anyRequested = initialPolicySet.length === 0 || initialPolicySet.includes(ANY_POLICY);
  const surviving = /* @__PURE__ */ new Set();
  const level = deepest(state);
  for (const node of level ?? []) {
    if (node.alive) surviving.add(node.validPolicy);
  }
  const intersected = anyRequested ? [...surviving] : [...surviving].filter((policy) => initialPolicySet.includes(policy));
  const treeSurvives = state.levels !== null && intersected.length > 0;
  return state.explicitPolicy > 0 || treeSurvives ? intersected : null;
}

// src/x509/x509-name-format.ts
var SHORT_NAMES = /* @__PURE__ */ new Map([
  ["2.5.4.3", "CN"],
  ["2.5.4.7", "L"],
  ["2.5.4.8", "ST"],
  ["2.5.4.10", "O"],
  ["2.5.4.11", "OU"],
  ["2.5.4.6", "C"],
  ["2.5.4.9", "STREET"],
  ["0.9.2342.19200300.100.1.25", "DC"],
  ["0.9.2342.19200300.100.1.1", "UID"]
]);
var SPECIAL = '"+,;<>\\';
var BIDI_CONTROLS = /* @__PURE__ */ new Set([1564, 8206, 8207, 8234, 8235, 8236, 8237, 8238, 8294, 8295, 8296, 8297]);
var hex2 = (octet) => `\\${octet.toString(16).padStart(2, "0")}`;
function hexpairs(code) {
  if (code < 128) return hex2(code);
  if (code < 2048) return hex2(192 | code >> 6) + hex2(128 | code & 63);
  return hex2(224 | code >> 12) + hex2(128 | code >> 6 & 63) + hex2(128 | code & 63);
}
function escapeValue(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i);
    const code = text.charCodeAt(i);
    if (code < 32 || code >= 127 && code <= 159 || BIDI_CONTROLS.has(code)) out += hexpairs(code);
    else if (SPECIAL.includes(ch)) out += `\\${ch}`;
    else if (i === 0 && (ch === " " || ch === "#") || i === text.length - 1 && ch === " ") out += `\\${ch}`;
    else out += ch;
  }
  return out;
}
function formatAttribute(attribute) {
  const short = SHORT_NAMES.get(attribute.type);
  if (short === void 0 || attribute.value === void 0) return `${short ?? attribute.type}=#${toHex(attribute.valueDer)}`;
  return `${short}=${escapeValue(attribute.value.value)}`;
}
function formatDistinguishedName(name) {
  if (typeof name !== "object" || name === null || !Array.isArray(name.rdns)) {
    throw new PkiError(
      "PKI_INVALID_INPUT",
      `pkinative: formatDistinguishedName expects the subject or issuer of a parsed certificate, got ${name === null ? "null" : typeof name}`
    );
  }
  const parts = [];
  for (const rdn of name.rdns) {
    if (!Array.isArray(rdn)) {
      throw new PkiError(
        "PKI_INVALID_INPUT",
        "pkinative: formatDistinguishedName expects the subject or issuer of a parsed certificate, whose rdns are arrays of attributes"
      );
    }
    parts.push(rdn.map(formatAttribute).join("+"));
  }
  parts.reverse();
  return parts.join(",");
}

// src/path/path-validate.ts
var PROCESSED_CRITICAL_EXTENSIONS = /* @__PURE__ */ new Set([
  "2.5.29.19",
  // basicConstraints — §6.1.4 (k), (l)
  "2.5.29.15",
  // keyUsage — §6.1.4 (n)
  "2.5.29.17",
  // subjectAltName — §6.1.3 (b), (c), against the name constraints
  "2.5.29.30",
  // nameConstraints — §6.1.4 (g)
  "2.5.29.32",
  // certificatePolicies — §6.1.3 (d)
  "2.5.29.33",
  // policyMappings — §6.1.4 (a), (b)
  "2.5.29.36",
  // policyConstraints — §6.1.4 (i)
  "2.5.29.54",
  // inhibitAnyPolicy — §6.1.4 (j)
  "2.5.29.37"
  // extKeyUsage: not a §6 input; carried so a leaf that marks it critical still validates
]);
var _hex = (bytes) => {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
};
function checkValidity(certificate, at, path) {
  const { notBefore, notAfter } = certificate.validity;
  if (at < notBefore.epochMilliseconds) return notYetValidReason(`${path}.validity`, notBefore.epochMilliseconds, at);
  if (at > notAfter.epochMilliseconds) return expiredReason(`${path}.validity`, notAfter.epochMilliseconds, at);
  return null;
}
function checkCriticalExtensions(certificate, path) {
  const out = [];
  for (const extension of certificate.extensions) {
    if (extension.critical && !PROCESSED_CRITICAL_EXTENSIONS.has(extension.oid)) {
      out.push(unrecognisedCriticalExtensionReason(`${path}.extensions`, extension.oid));
    }
  }
  return out;
}
function checkSignature(certificate, context, path, issuer) {
  const subject = _hex(certificate.der);
  const result = (issuer === void 0 ? void 0 : context.signatures.get(`${subject}|${_hex(issuer.der)}`)) ?? context.signatures.get(subject);
  if (result === void 0) {
    return signatureNotCheckedReason(path, "PKI_CRYPTO_UNAVAILABLE", "no signature verdict was supplied for this certificate");
  }
  if (result === "ambiguous") {
    return signatureNotCheckedReason(
      path,
      "PKI_API_MISUSE",
      "two verdicts disagree about this certificate and neither names its issuer \u2014 pass `issuer` in each SignatureResult when several candidates share a subject name"
    );
  }
  if (result.verdict === "valid") return null;
  if (result.verdict === "invalid") return signatureInvalidReason(path);
  return signatureNotCheckedReason(path, result.errorCode ?? "PKI_CRYPTO_KEY_UNSUPPORTED", result.detail ?? "the signature could not be checked");
}
function checkIssuingCapability(issuer, state, path) {
  const out = [];
  const basicConstraints = getExtension(issuer, "basicConstraints");
  const keyUsage = getExtension(issuer, "keyUsage");
  if (basicConstraints?.cA !== true) out.push(notACaReason(path, "basicConstraints"));
  if (keyUsage !== void 0 && !keyUsage.usages.includes("keyCertSign")) out.push(notACaReason(path, "keyUsage"));
  const selfIssued = _hex(issuer.subject.der) === _hex(issuer.issuer.der);
  if (!selfIssued) {
    if (state.maxPathLength <= 0) out.push(pathTooLongReason(path, 0));
    state.maxPathLength -= 1;
  }
  const constraint = basicConstraints?.pathLenConstraint;
  if (constraint !== void 0 && constraint < state.maxPathLength) state.maxPathLength = constraint;
  return out;
}
function checkNamesAgainstConstraints(certificate, names, path) {
  const out = [];
  if (certificate.subject.rdns.length > 0) {
    const asDirectory = { kind: "directoryName", name: certificate.subject, der: certificate.subject.der };
    const verdict = checkName(names, asDirectory);
    if (verdict !== null) {
      out.push(verdict.why === "excluded" ? nameExcludedReason(`${path}.subject`, "subject", formatDistinguishedName(certificate.subject)) : nameNotPermittedReason(`${path}.subject`, "subject", formatDistinguishedName(certificate.subject)));
    }
  }
  for (const entry of getExtension(certificate, "subjectAltName")?.names ?? []) {
    const verdict = checkName(names, entry);
    if (verdict === null) continue;
    out.push(verdict.why === "excluded" ? nameExcludedReason(`${path}.subjectAltName`, verdict.form, verdict.text) : nameNotPermittedReason(`${path}.subjectAltName`, verdict.form, verdict.text));
  }
  return out;
}
function advancePolicies(certificate, policies, maxNodes, path) {
  const out = [];
  const asserted = getExtension(certificate, "certificatePolicies");
  if (asserted === void 0) {
    killPolicyTree(policies);
  } else if (growPolicyTree(policies, asserted.policies, maxNodes) === "limit") {
    out.push(limitExceededReason(`${path}.certificatePolicies`, "maxPolicyNodes", maxNodes));
  }
  const mappings = getExtension(certificate, "policyMappings");
  if (mappings !== void 0) {
    for (const mapping of mappings.mappings) {
      if (mapping.issuerDomainPolicy === ANY_POLICY || mapping.subjectDomainPolicy === ANY_POLICY) {
        out.push(policyMappingInvalidReason(`${path}.policyMappings`, mapping.issuerDomainPolicy, mapping.subjectDomainPolicy));
      }
    }
    applyPolicyMappings(policies, mappings.mappings);
  }
  const constraints = getExtension(certificate, "policyConstraints");
  const inhibitAny = getExtension(certificate, "inhibitAnyPolicy");
  const selfIssued = _hex(certificate.subject.der) === _hex(certificate.issuer.der);
  advancePolicyCounters(policies, selfIssued, constraints?.requireExplicitPolicy, constraints?.inhibitPolicyMapping, inhibitAny?.skipCerts);
  return out;
}
function validateCertificatePath(input) {
  const limits = resolveLimits(input.limits);
  const signatures = /* @__PURE__ */ new Map();
  for (const result of input.signatures ?? []) {
    const subject = _hex(result.certificate.der);
    const entry = { verdict: result.verdict, errorCode: result.errorCode, detail: result.detail };
    if (result.issuer !== void 0) {
      signatures.set(`${subject}|${_hex(result.issuer.der)}`, entry);
      continue;
    }
    const existing = signatures.get(subject);
    if (existing !== void 0 && (existing === "ambiguous" || existing.verdict !== result.verdict)) {
      signatures.set(subject, "ambiguous");
      continue;
    }
    signatures.set(subject, entry);
  }
  const context = {
    at: input.at,
    signatures,
    trustAnchorSubjects: new Set(input.trustAnchors.map((c) => _hex(c.subject.der))),
    maxPathLength: limits.maxChainLength,
    maxCertificates: limits.maxChainLength
  };
  const state = {
    maxPathLength: context.maxPathLength,
    expectedIssuer: null,
    seen: /* @__PURE__ */ new Set(),
    reasons: []
  };
  const walked = [];
  let anchored = false;
  for (const [index, certificate] of input.certificates.entries()) {
    const path = `path[${String(index)}]`;
    if (index >= context.maxCertificates) {
      state.reasons.push(limitExceededReason(path, "maxChainLength", context.maxCertificates));
      break;
    }
    const fingerprint2 = _hex(certificate.der);
    if (state.seen.has(fingerprint2)) {
      state.reasons.push(pathLoopsReason(path));
      break;
    }
    state.seen.add(fingerprint2);
    walked.push(certificate);
    if (state.expectedIssuer !== null && _hex(certificate.subject.der) !== _hex(state.expectedIssuer.der)) {
      state.reasons.push(issuerNotFoundReason(path, formatDistinguishedName(state.expectedIssuer)));
      break;
    }
    const validity = checkValidity(certificate, context.at, path);
    if (validity !== null) state.reasons.push(validity);
    state.reasons.push(...checkCriticalExtensions(certificate, path));
    if (context.trustAnchorSubjects.has(_hex(certificate.subject.der))) {
      anchored = true;
      break;
    }
    const wanted = _hex(certificate.issuer.der);
    const issuer = input.certificates[index + 1] ?? input.trustAnchors.find((candidate) => _hex(candidate.subject.der) === wanted);
    const signature = checkSignature(certificate, context, path, issuer);
    if (signature !== null) state.reasons.push(signature);
    state.expectedIssuer = certificate.issuer;
  }
  if (!anchored && state.expectedIssuer !== null) {
    const wanted = _hex(state.expectedIssuer.der);
    const anchor = input.trustAnchors.find((candidate) => _hex(candidate.subject.der) === wanted);
    if (anchor !== void 0) {
      anchored = true;
      const path = `path[${String(walked.length)}]`;
      const validity = checkValidity(anchor, context.at, path);
      if (validity !== null) state.reasons.push(validity);
      state.reasons.push(...checkCriticalExtensions(anchor, path));
      walked.push(anchor);
    }
  }
  if (!anchored) state.reasons.push(noTrustAnchorReason(`path[${String(Math.max(walked.length - 1, 0))}]`));
  const names = initialNameConstraints();
  const policies = initialPolicyState(
    walked.length,
    input.requireExplicitPolicy === true,
    input.inhibitPolicyMapping === true,
    input.inhibitAnyPolicy === true
  );
  for (let index = walked.length - 1; index >= 1; index -= 1) {
    const issuer = walked[index];
    const below = walked[index - 1];
    const belowPath = `path[${String(index - 1)}]`;
    state.reasons.push(...checkIssuingCapability(issuer, state, `path[${String(index)}]`));
    const constraints = getExtension(issuer, "nameConstraints");
    if (constraints !== void 0) accumulateNameConstraints(names, constraints.permittedSubtrees, constraints.excludedSubtrees);
    const selfIssued = _hex(below.subject.der) === _hex(below.issuer.der);
    if (!selfIssued || index - 1 === 0) state.reasons.push(...checkNamesAgainstConstraints(below, names, belowPath));
    state.reasons.push(...advancePolicies(below, policies, limits.maxPolicyNodes, belowPath));
  }
  if (wrapUpPolicies(policies, input.initialPolicySet ?? []) === null) {
    state.reasons.push(noValidPolicyReason("path"));
  }
  return { valid: state.reasons.length === 0, reasons: state.reasons, path: walked };
}

// src/path/path-build.ts
var fingerprint = (certificate) => {
  let out = "";
  for (const b of certificate.der) out += b.toString(16).padStart(2, "0");
  return out;
};
function buildCertificatePath(input) {
  const limits = resolveLimits(input.limits);
  const anchors = new Set(input.trustAnchors.map((c) => fingerprint(c)));
  const anchorSubjects = new Set(input.trustAnchors.map((c) => hexOf(c.subject.der)));
  const bySubject = /* @__PURE__ */ new Map();
  for (const candidate of input.candidates) {
    const key = hexOf(candidate.subject.der);
    bySubject.set(key, [...bySubject.get(key) ?? [], candidate]);
  }
  for (const anchor of input.trustAnchors) {
    const key = hexOf(anchor.subject.der);
    const existing = bySubject.get(key) ?? [];
    if (!existing.some((c) => bytesEqual(c.der, anchor.der))) bySubject.set(key, [...existing, anchor]);
  }
  const first = validateCertificatePath({ ...input, certificates: [input.leaf] });
  let explored = 1;
  if (first.valid) return { ...first, explored };
  let best = first;
  let bestDepth = 0;
  let limitHit = false;
  const extend = (chain, seen) => {
    if (chain.length >= limits.maxChainLength) return null;
    const last = chain[chain.length - 1];
    if (anchors.has(fingerprint(last)) || anchorSubjects.has(hexOf(last.subject.der))) return null;
    for (const issuer of bySubject.get(hexOf(last.issuer.der)) ?? []) {
      const key = fingerprint(issuer);
      if (seen.has(key)) continue;
      if (explored >= limits.maxPathsExplored) {
        limitHit = true;
        return null;
      }
      explored += 1;
      const next = [...chain, issuer];
      const report = validateCertificatePath({ ...input, certificates: next });
      if (report.valid) return { ...report, explored };
      if (next.length - 1 > bestDepth) {
        best = report;
        bestDepth = next.length - 1;
      }
      const found2 = extend(next, /* @__PURE__ */ new Set([...seen, key]));
      if (found2 !== null) return found2;
      if (limitHit) return null;
    }
    return null;
  };
  const found = extend([input.leaf], /* @__PURE__ */ new Set([fingerprint(input.leaf)]));
  if (found !== null) return found;
  const reasons = [...best.reasons];
  if (limitHit) reasons.push(limitExceededReason("path", "maxPathsExplored", limits.maxPathsExplored));
  return { valid: false, reasons, path: best.path, explored };
}
function hexOf(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// src/path/path-server-name.ts
var OID_COMMON_NAME = "2.5.4.3";
function checkServerName(certificate, identity, options) {
  const san = getExtension(certificate, "subjectAltName");
  const names = san?.names ?? [];
  const sanIsAuthoritative = names.some((name) => name.kind === "dNSName" || name.kind === "iPAddress");
  const wildcards = options?.allowWildcards !== false;
  if (sanIsAuthoritative) {
    for (const name of names) {
      if (matches2(name, identity, wildcards)) return [];
    }
    return [nameMismatchReason("certificate.subjectAltName", identityText(identity), listed(names))];
  }
  if (options?.allowCommonNameFallback !== true) {
    return [nameMismatchReason(
      "certificate.subjectAltName",
      identityText(identity),
      names.length === 0 ? "the certificate carries no subjectAltName at all, and the deprecated commonName fallback was not asked for" : "the subjectAltName carries no dNSName and no iPAddress, and the deprecated commonName fallback was not asked for"
    )];
  }
  for (const common of commonNames(certificate)) {
    if (identity.kind === "dns" && dnsMatches2(common, identity.value, wildcards)) return [];
  }
  return [nameMismatchReason("certificate.subject", identityText(identity), `commonName ${commonNames(certificate).map((c) => JSON.stringify(c)).join(", ") || "(none)"}`)];
}
function matches2(name, identity, wildcards) {
  if (identity.kind === "dns") {
    return name.kind === "dNSName" && dnsMatches2(name.value, identity.value, wildcards);
  }
  return name.kind === "iPAddress" && sameBytes2(name.bytes, identity.value);
}
function fold2(text) {
  return text.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}
function dnsMatches2(presented, reference, wildcards = true) {
  if (presented === "" || presented.includes("\0") || reference === "" || reference.includes("\0")) return false;
  const host = fold2(stripTrailingDot(reference));
  const pattern = fold2(stripTrailingDot(presented));
  if (!pattern.includes("*")) return pattern === host;
  if (!wildcards) return false;
  const labels = pattern.split(".");
  const first = labels[0];
  if (first !== "*") return false;
  if (labels.slice(1).some((label) => label.includes("*"))) return false;
  if (labels.length < 3) return false;
  if (labels.slice(1).some((label) => label === "")) return false;
  const suffix = labels.slice(1).join(".");
  const hostLabels = host.split(".");
  if (hostLabels.length !== labels.length) return false;
  if (hostLabels[0] === "") return false;
  return hostLabels.slice(1).join(".") === suffix;
}
function stripTrailingDot(name) {
  return name.endsWith(".") ? name.slice(0, -1) : name;
}
function sameBytes2(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
function commonNames(certificate) {
  const out = [];
  for (const rdn of certificate.subject.rdns) {
    for (const attribute of rdn) {
      if (attribute.type === OID_COMMON_NAME && attribute.value !== void 0) out.push(attribute.value.value);
    }
  }
  return out;
}
function identityText(identity) {
  if (identity.kind === "dns") return `the DNS name "${identity.value}"`;
  const bytes = identity.value;
  const text = bytes.length === 4 ? Array.from(bytes, (b) => String(b)).join(".") : Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `the address ${text}`;
}
function listed(names) {
  const hosts = [];
  for (const name of names) {
    if (name.kind === "dNSName") hosts.push(JSON.stringify(name.value));
    else if (name.kind === "iPAddress") hosts.push(name.address);
  }
  const more = hosts.length > 8 ? `, and ${String(hosts.length - 8)} more` : "";
  return `it names ${hosts.slice(0, 8).join(", ")}${more}`;
}

// src/oid/oid-registry.ts
var GROUPS = [
  // ── Name attributes ──
  ["ITU-T X.520", [
    ["2.5.4.0", "objectClass"],
    ["2.5.4.3", "commonName"],
    ["2.5.4.4", "surname"],
    ["2.5.4.5", "serialNumber"],
    ["2.5.4.6", "countryName"],
    ["2.5.4.7", "localityName"],
    ["2.5.4.8", "stateOrProvinceName"],
    ["2.5.4.9", "streetAddress"],
    ["2.5.4.10", "organizationName"],
    ["2.5.4.11", "organizationalUnitName"],
    ["2.5.4.12", "title"],
    ["2.5.4.13", "description"],
    ["2.5.4.15", "businessCategory"],
    ["2.5.4.16", "postalAddress"],
    ["2.5.4.17", "postalCode"],
    ["2.5.4.18", "postOfficeBox"],
    ["2.5.4.19", "physicalDeliveryOfficeName"],
    ["2.5.4.20", "telephoneNumber"],
    ["2.5.4.36", "userCertificate"],
    ["2.5.4.37", "cACertificate"],
    ["2.5.4.38", "authorityRevocationList"],
    ["2.5.4.39", "certificateRevocationList"],
    ["2.5.4.40", "crossCertificatePair"],
    ["2.5.4.41", "name"],
    ["2.5.4.42", "givenName"],
    ["2.5.4.43", "initials"],
    ["2.5.4.44", "generationQualifier"],
    ["2.5.4.45", "x500UniqueIdentifier"],
    ["2.5.4.46", "dnQualifier"],
    ["2.5.4.51", "houseIdentifier"],
    ["2.5.4.53", "deltaRevocationList"],
    ["2.5.4.65", "pseudonym"],
    ["2.5.4.72", "role"],
    ["2.5.4.97", "organizationIdentifier"]
  ]],
  ["RFC 4519", [
    ["0.9.2342.19200300.100.1.1", "uid"],
    ["0.9.2342.19200300.100.1.25", "domainComponent"]
  ]],
  ["RFC 4524", [
    ["0.9.2342.19200300.100.1.3", "mail"]
  ]],
  ["CA/Browser Forum EV Guidelines", [
    ["1.3.6.1.4.1.311.60.2.1.1", "jurisdictionLocalityName"],
    ["1.3.6.1.4.1.311.60.2.1.2", "jurisdictionStateOrProvinceName"],
    ["1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountryName"]
  ]],
  ["RFC 2985", [
    ["1.2.840.113549.1.9.1", "emailAddress"],
    ["1.2.840.113549.1.9.2", "unstructuredName"],
    ["1.2.840.113549.1.9.3", "contentType"],
    ["1.2.840.113549.1.9.4", "messageDigest"],
    ["1.2.840.113549.1.9.5", "signingTime"],
    ["1.2.840.113549.1.9.6", "counterSignature"],
    ["1.2.840.113549.1.9.7", "challengePassword"],
    ["1.2.840.113549.1.9.8", "unstructuredAddress"],
    ["1.2.840.113549.1.9.14", "extensionRequest"],
    ["1.2.840.113549.1.9.20", "friendlyName"],
    ["1.2.840.113549.1.9.21", "localKeyId"],
    ["1.2.840.113549.1.9.22.1", "x509Certificate"],
    ["1.2.840.113549.1.9.22.2", "sdsiCertificate"],
    ["1.2.840.113549.1.9.23.1", "x509Crl"]
  ]],
  ["RFC 8551", [
    ["1.2.840.113549.1.9.15", "smimeCapabilities"]
  ]],
  // ── Certificate and CRL extensions ──
  ["RFC 5280", [
    ["2.5.29.9", "subjectDirectoryAttributes"],
    ["2.5.29.14", "subjectKeyIdentifier"],
    ["2.5.29.15", "keyUsage"],
    ["2.5.29.16", "privateKeyUsagePeriod"],
    ["2.5.29.17", "subjectAltName"],
    ["2.5.29.18", "issuerAltName"],
    ["2.5.29.19", "basicConstraints"],
    ["2.5.29.20", "cRLNumber"],
    ["2.5.29.21", "cRLReasons"],
    ["2.5.29.23", "holdInstructionCode"],
    ["2.5.29.24", "invalidityDate"],
    ["2.5.29.27", "deltaCRLIndicator"],
    ["2.5.29.28", "issuingDistributionPoint"],
    ["2.5.29.29", "certificateIssuer"],
    ["2.5.29.30", "nameConstraints"],
    ["2.5.29.31", "cRLDistributionPoints"],
    ["2.5.29.32", "certificatePolicies"],
    ["2.5.29.32.0", "anyPolicy"],
    ["2.5.29.33", "policyMappings"],
    ["2.5.29.35", "authorityKeyIdentifier"],
    ["2.5.29.36", "policyConstraints"],
    ["2.5.29.37", "extKeyUsage"],
    ["2.5.29.37.0", "anyExtendedKeyUsage"],
    ["2.5.29.46", "freshestCRL"],
    ["2.5.29.54", "inhibitAnyPolicy"],
    ["1.3.6.1.5.5.7.1.1", "authorityInfoAccess"],
    ["1.3.6.1.5.5.7.1.11", "subjectInfoAccess"],
    ["1.3.6.1.5.5.7.2.1", "cps"],
    ["1.3.6.1.5.5.7.2.2", "unotice"],
    ["1.3.6.1.5.5.7.3.1", "serverAuth"],
    ["1.3.6.1.5.5.7.3.2", "clientAuth"],
    ["1.3.6.1.5.5.7.3.3", "codeSigning"],
    ["1.3.6.1.5.5.7.3.4", "emailProtection"],
    ["1.3.6.1.5.5.7.3.8", "timeStamping"],
    ["1.3.6.1.5.5.7.3.9", "OCSPSigning"],
    ["1.3.6.1.5.5.7.48.1", "ocsp"],
    ["1.3.6.1.5.5.7.48.2", "caIssuers"],
    ["1.3.6.1.5.5.7.48.3", "id-ad-timeStamping"],
    ["1.3.6.1.5.5.7.48.5", "caRepository"],
    ["1.2.840.10040.2.1", "holdInstructionNone"],
    ["1.2.840.10040.2.2", "holdInstructionCallIssuer"],
    ["1.2.840.10040.2.3", "holdInstructionReject"]
  ]],
  ["RFC 3739", [
    ["1.3.6.1.5.5.7.1.2", "biometricInfo"],
    ["1.3.6.1.5.5.7.1.3", "qcStatements"],
    ["1.3.6.1.5.5.7.11.2", "qcsPkixQCSyntax-v2"],
    ["1.3.6.1.5.5.7.9.1", "dateOfBirth"],
    ["1.3.6.1.5.5.7.9.2", "placeOfBirth"],
    ["1.3.6.1.5.5.7.9.3", "gender"],
    ["1.3.6.1.5.5.7.9.4", "countryOfCitizenship"],
    ["1.3.6.1.5.5.7.9.5", "countryOfResidence"]
  ]],
  ["RFC 3709", [["1.3.6.1.5.5.7.1.12", "logotype"]]],
  ["RFC 3779", [
    ["1.3.6.1.5.5.7.1.7", "ipAddrBlocks"],
    ["1.3.6.1.5.5.7.1.8", "autonomousSysIds"]
  ]],
  ["RFC 6487", [
    ["1.3.6.1.5.5.7.48.10", "rpkiManifest"],
    ["1.3.6.1.5.5.7.48.11", "signedObject"]
  ]],
  ["RFC 8182", [["1.3.6.1.5.5.7.48.13", "rpkiNotify"]]],
  ["RFC 7633", [["1.3.6.1.5.5.7.1.24", "tlsFeature"]]],
  ["RFC 9608", [["2.5.29.56", "noRevAvail"]]],
  ["RFC 6962", [
    ["1.3.6.1.4.1.11129.2.4.2", "signedCertificateTimestampList"],
    ["1.3.6.1.4.1.11129.2.4.3", "ctPrecertificatePoison"],
    ["1.3.6.1.4.1.11129.2.4.4", "ctPrecertificateSigning"],
    ["1.3.6.1.4.1.11129.2.4.5", "ocspSignedCertificateTimestampList"]
  ]],
  ["RFC 6960", [
    ["1.3.6.1.5.5.7.48.1.1", "ocspBasic"],
    ["1.3.6.1.5.5.7.48.1.2", "ocspNonce"],
    ["1.3.6.1.5.5.7.48.1.3", "ocspCrlId"],
    ["1.3.6.1.5.5.7.48.1.4", "ocspResponse"],
    ["1.3.6.1.5.5.7.48.1.5", "ocspNoCheck"],
    ["1.3.6.1.5.5.7.48.1.6", "ocspArchiveCutoff"],
    ["1.3.6.1.5.5.7.48.1.7", "ocspServiceLocator"]
  ]],
  // ── Extended key usages and other names ──
  ["RFC 4334", [
    ["1.3.6.1.5.5.7.3.13", "eapOverPPP"],
    ["1.3.6.1.5.5.7.3.14", "eapOverLAN"]
  ]],
  ["RFC 4945", [["1.3.6.1.5.5.7.3.17", "ipsecIKE"]]],
  ["RFC 5924", [["1.3.6.1.5.5.7.3.20", "sipDomain"]]],
  ["RFC 6187", [
    ["1.3.6.1.5.5.7.3.21", "secureShellClient"],
    ["1.3.6.1.5.5.7.3.22", "secureShellServer"]
  ]],
  ["RFC 6402", [
    ["1.3.6.1.5.5.7.3.27", "cmcCA"],
    ["1.3.6.1.5.5.7.3.28", "cmcRA"],
    ["1.3.6.1.5.5.7.3.29", "cmcArchive"]
  ]],
  ["RFC 8209", [["1.3.6.1.5.5.7.3.30", "bgpsecRouter"]]],
  ["RFC 9336", [["1.3.6.1.5.5.7.3.36", "documentSigning"]]],
  ["RFC 4043", [["1.3.6.1.5.5.7.8.3", "permanentIdentifier"]]],
  ["RFC 4108", [["1.3.6.1.5.5.7.8.4", "hardwareModuleName"]]],
  ["RFC 6120", [["1.3.6.1.5.5.7.8.5", "xmppAddr"]]],
  ["RFC 4985", [["1.3.6.1.5.5.7.8.7", "srvName"]]],
  ["RFC 9598", [["1.3.6.1.5.5.7.8.9", "smtpUTF8Mailbox"]]],
  ["RFC 4556", [
    ["1.3.6.1.5.2.2", "pkinitSan"],
    ["1.3.6.1.5.2.3.4", "pkinitKPClientAuth"],
    ["1.3.6.1.5.2.3.5", "pkinitKPKdc"]
  ]],
  ["Microsoft", [
    ["1.3.6.1.4.1.311.10.3.4", "msEncryptedFileSystem"],
    ["1.3.6.1.4.1.311.10.3.12", "msDocumentSigning"],
    ["1.3.6.1.4.1.311.20.2", "msCertificateTemplateName"],
    ["1.3.6.1.4.1.311.20.2.2", "msSmartcardLogon"],
    ["1.3.6.1.4.1.311.20.2.3", "msUserPrincipalName"],
    ["1.3.6.1.4.1.311.21.1", "msCAVersion"],
    ["1.3.6.1.4.1.311.21.2", "msPreviousCertHash"],
    ["1.3.6.1.4.1.311.21.7", "msCertificateTemplate"],
    ["1.3.6.1.4.1.311.21.10", "msApplicationCertPolicies"]
  ]],
  ["Netscape", [
    ["2.16.840.1.113730.1.1", "netscapeCertType"],
    ["2.16.840.1.113730.1.13", "netscapeComment"]
  ]],
  ["Adobe (ISO 32000)", [
    ["1.2.840.113583.1.1.8", "adbeRevocationInfoArchival"],
    ["1.2.840.113583.1.1.9.1", "adbeTimestamp"]
  ]],
  // ── Certificate policies and qualified certificates ──
  ["CA/Browser Forum Baseline Requirements", [
    ["2.23.140.1.1", "extendedValidation"],
    ["2.23.140.1.2.1", "domainValidated"],
    ["2.23.140.1.2.2", "organizationValidated"],
    ["2.23.140.1.2.3", "individualValidated"],
    ["2.23.140.1.3", "extendedValidationCodeSigning"],
    ["2.23.140.1.4.1", "codeSigningRequirements"]
  ]],
  ["ETSI EN 319 411-1", [
    ["0.4.0.2042.1.1", "etsiNcp"],
    ["0.4.0.2042.1.2", "etsiNcpPlus"],
    ["0.4.0.2042.1.3", "etsiLcp"],
    ["0.4.0.2042.1.4", "etsiEvcp"],
    ["0.4.0.2042.1.6", "etsiDvcp"],
    ["0.4.0.2042.1.7", "etsiOvcp"]
  ]],
  ["ETSI EN 319 411-2", [
    ["0.4.0.194112.1.0", "etsiQcpNatural"],
    ["0.4.0.194112.1.1", "etsiQcpLegal"],
    ["0.4.0.194112.1.2", "etsiQcpNaturalQscd"],
    ["0.4.0.194112.1.3", "etsiQcpLegalQscd"],
    ["0.4.0.194112.1.4", "etsiQcpWeb"]
  ]],
  ["ETSI EN 319 412-1", [
    ["0.4.0.194121.1.1", "etsiSemanticsIdNatural"],
    ["0.4.0.194121.1.2", "etsiSemanticsIdLegal"]
  ]],
  ["ETSI EN 319 412-5", [
    ["0.4.0.1862.1.1", "qcCompliance"],
    ["0.4.0.1862.1.2", "qcLimitValue"],
    ["0.4.0.1862.1.3", "qcRetentionPeriod"],
    ["0.4.0.1862.1.4", "qcSSCD"],
    ["0.4.0.1862.1.5", "qcPDS"],
    ["0.4.0.1862.1.6", "qcType"],
    ["0.4.0.1862.1.6.1", "qcTypeESign"],
    ["0.4.0.1862.1.6.2", "qcTypeESeal"],
    ["0.4.0.1862.1.6.3", "qcTypeWeb"],
    ["0.4.0.1862.1.7", "qcCClegislation"]
  ]],
  ["ETSI TS 119 495", [["0.4.0.19495.2", "qcsPsd2"]]],
  // ── CMS, timestamps and signed attributes ──
  ["RFC 5652", [
    ["1.2.840.113549.1.7.1", "data"],
    ["1.2.840.113549.1.7.2", "signedData"],
    ["1.2.840.113549.1.7.3", "envelopedData"],
    ["1.2.840.113549.1.7.5", "digestedData"],
    ["1.2.840.113549.1.7.6", "encryptedData"],
    ["1.2.840.113549.1.9.16.1.2", "authData"]
  ]],
  ["RFC 3274", [["1.2.840.113549.1.9.16.1.9", "compressedData"]]],
  ["RFC 5083", [["1.2.840.113549.1.9.16.1.23", "authEnvelopedData"]]],
  ["RFC 3161", [
    ["1.2.840.113549.1.9.16.1.4", "tstInfo"],
    ["1.2.840.113549.1.9.16.2.14", "timeStampToken"]
  ]],
  ["RFC 6211", [["1.2.840.113549.1.9.52", "cmsAlgorithmProtection"]]],
  ["RFC 2634", [["1.2.840.113549.1.9.16.2.12", "signingCertificate"]]],
  ["RFC 5035", [["1.2.840.113549.1.9.16.2.47", "signingCertificateV2"]]],
  ["RFC 5126", [
    ["1.2.840.113549.1.9.16.2.15", "sigPolicyId"],
    ["1.2.840.113549.1.9.16.2.16", "commitmentType"],
    ["1.2.840.113549.1.9.16.2.17", "signerLocation"],
    ["1.2.840.113549.1.9.16.2.18", "signerAttr"],
    ["1.2.840.113549.1.9.16.2.19", "otherSigCert"],
    ["1.2.840.113549.1.9.16.2.20", "contentTimestamp"],
    ["1.2.840.113549.1.9.16.2.21", "certificateRefs"],
    ["1.2.840.113549.1.9.16.2.22", "revocationRefs"],
    ["1.2.840.113549.1.9.16.2.23", "certValues"],
    ["1.2.840.113549.1.9.16.2.24", "revocationValues"],
    ["1.2.840.113549.1.9.16.2.25", "escTimeStamp"],
    ["1.2.840.113549.1.9.16.2.26", "certCRLTimestamp"],
    ["1.2.840.113549.1.9.16.2.27", "archiveTimeStamp"],
    ["1.2.840.113549.1.9.16.6.1", "proofOfOrigin"],
    ["1.2.840.113549.1.9.16.6.2", "proofOfReceipt"],
    ["1.2.840.113549.1.9.16.6.3", "proofOfDelivery"],
    ["1.2.840.113549.1.9.16.6.4", "proofOfSender"],
    ["1.2.840.113549.1.9.16.6.5", "proofOfApproval"],
    ["1.2.840.113549.1.9.16.6.6", "proofOfCreation"]
  ]],
  // ── PKCS #12 and password-based encryption ──
  ["RFC 7292", [
    ["1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC"],
    ["1.2.840.113549.1.12.1.6", "pbeWithSHAAnd40BitRC2-CBC"],
    ["1.2.840.113549.1.12.10.1.1", "keyBag"],
    ["1.2.840.113549.1.12.10.1.2", "pkcs8ShroudedKeyBag"],
    ["1.2.840.113549.1.12.10.1.3", "certBag"],
    ["1.2.840.113549.1.12.10.1.4", "crlBag"],
    ["1.2.840.113549.1.12.10.1.5", "secretBag"],
    ["1.2.840.113549.1.12.10.1.6", "safeContentsBag"]
  ]],
  ["RFC 8018", [
    ["1.2.840.113549.1.5.12", "pbkdf2"],
    ["1.2.840.113549.1.5.13", "pbes2"],
    ["1.2.840.113549.2.7", "hmacWithSHA1"],
    ["1.2.840.113549.2.8", "hmacWithSHA224"],
    ["1.2.840.113549.2.9", "hmacWithSHA256"],
    ["1.2.840.113549.2.10", "hmacWithSHA384"],
    ["1.2.840.113549.2.11", "hmacWithSHA512"],
    ["1.2.840.113549.3.2", "rc2CBC"],
    ["1.2.840.113549.3.7", "des-EDE3-CBC"]
  ]],
  // ── Public-key and signature algorithms ──
  ["RFC 8017", [
    ["1.2.840.113549.1.1.1", "rsaEncryption"],
    ["1.2.840.113549.1.1.2", "md2WithRSAEncryption"],
    ["1.2.840.113549.1.1.3", "md4WithRSAEncryption"],
    ["1.2.840.113549.1.1.4", "md5WithRSAEncryption"],
    ["1.2.840.113549.1.1.5", "sha1WithRSAEncryption"],
    ["1.2.840.113549.1.1.7", "RSAES-OAEP"],
    ["1.2.840.113549.1.1.8", "mgf1"],
    ["1.2.840.113549.1.1.9", "pSpecified"],
    ["1.2.840.113549.1.1.10", "RSASSA-PSS"],
    ["1.2.840.113549.1.1.11", "sha256WithRSAEncryption"],
    ["1.2.840.113549.1.1.12", "sha384WithRSAEncryption"],
    ["1.2.840.113549.1.1.13", "sha512WithRSAEncryption"],
    ["1.2.840.113549.1.1.14", "sha224WithRSAEncryption"],
    ["1.2.840.113549.1.1.15", "sha512-224WithRSAEncryption"],
    ["1.2.840.113549.1.1.16", "sha512-256WithRSAEncryption"]
  ]],
  ["OIW", [["1.3.14.3.2.29", "sha1WithRSASignature"]]],
  ["RFC 3279", [
    ["1.2.840.113549.2.2", "md2"],
    ["1.2.840.113549.2.5", "md5"],
    ["1.3.14.3.2.26", "sha1"],
    ["1.2.840.10040.4.1", "dsa"],
    ["1.2.840.10040.4.3", "dsa-with-sha1"],
    ["1.2.840.10045.4.1", "ecdsa-with-SHA1"],
    ["1.2.840.10046.2.1", "dhpublicnumber"]
  ]],
  ["RFC 5758", [
    ["1.2.840.10045.4.3.1", "ecdsa-with-SHA224"],
    ["1.2.840.10045.4.3.2", "ecdsa-with-SHA256"],
    ["1.2.840.10045.4.3.3", "ecdsa-with-SHA384"],
    ["1.2.840.10045.4.3.4", "ecdsa-with-SHA512"],
    ["2.16.840.1.101.3.4.3.1", "dsa-with-sha224"],
    ["2.16.840.1.101.3.4.3.2", "dsa-with-sha256"]
  ]],
  ["RFC 5480", [
    ["1.2.840.10045.2.1", "ecPublicKey"],
    ["1.3.132.1.12", "ecDH"],
    ["1.3.132.1.13", "ecMQV"],
    ["1.2.840.10045.3.1.1", "secp192r1"],
    ["1.3.132.0.33", "secp224r1"],
    ["1.2.840.10045.3.1.7", "secp256r1"],
    ["1.3.132.0.34", "secp384r1"],
    ["1.3.132.0.35", "secp521r1"]
  ]],
  ["SEC 2", [["1.3.132.0.10", "secp256k1"]]],
  ["RFC 5639", [
    ["1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"],
    ["1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"],
    ["1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"]
  ]],
  ["RFC 8410", [
    ["1.3.101.110", "X25519"],
    ["1.3.101.111", "X448"],
    ["1.3.101.112", "Ed25519"],
    ["1.3.101.113", "Ed448"]
  ]],
  ["NIST CSOR", [
    ["2.16.840.1.101.3.4.3.9", "ecdsa-with-SHA3-224"],
    ["2.16.840.1.101.3.4.3.10", "ecdsa-with-SHA3-256"],
    ["2.16.840.1.101.3.4.3.11", "ecdsa-with-SHA3-384"],
    ["2.16.840.1.101.3.4.3.12", "ecdsa-with-SHA3-512"],
    ["2.16.840.1.101.3.4.3.13", "sha3-224WithRSAEncryption"],
    ["2.16.840.1.101.3.4.3.14", "sha3-256WithRSAEncryption"],
    ["2.16.840.1.101.3.4.3.15", "sha3-384WithRSAEncryption"],
    ["2.16.840.1.101.3.4.3.16", "sha3-512WithRSAEncryption"]
  ]],
  ["FIPS 204", [
    ["2.16.840.1.101.3.4.3.17", "ml-dsa-44"],
    ["2.16.840.1.101.3.4.3.18", "ml-dsa-65"],
    ["2.16.840.1.101.3.4.3.19", "ml-dsa-87"]
  ]],
  ["FIPS 205", [
    ["2.16.840.1.101.3.4.3.20", "slh-dsa-sha2-128s"],
    ["2.16.840.1.101.3.4.3.21", "slh-dsa-sha2-128f"],
    ["2.16.840.1.101.3.4.3.22", "slh-dsa-sha2-192s"],
    ["2.16.840.1.101.3.4.3.23", "slh-dsa-sha2-192f"],
    ["2.16.840.1.101.3.4.3.24", "slh-dsa-sha2-256s"],
    ["2.16.840.1.101.3.4.3.25", "slh-dsa-sha2-256f"],
    ["2.16.840.1.101.3.4.3.26", "slh-dsa-shake-128s"],
    ["2.16.840.1.101.3.4.3.27", "slh-dsa-shake-128f"],
    ["2.16.840.1.101.3.4.3.28", "slh-dsa-shake-192s"],
    ["2.16.840.1.101.3.4.3.29", "slh-dsa-shake-192f"],
    ["2.16.840.1.101.3.4.3.30", "slh-dsa-shake-256s"],
    ["2.16.840.1.101.3.4.3.31", "slh-dsa-shake-256f"]
  ]],
  ["FIPS 203", [
    ["2.16.840.1.101.3.4.4.1", "ml-kem-512"],
    ["2.16.840.1.101.3.4.4.2", "ml-kem-768"],
    ["2.16.840.1.101.3.4.4.3", "ml-kem-1024"]
  ]],
  // ── Digests and symmetric algorithms ──
  ["FIPS 180-4", [
    ["2.16.840.1.101.3.4.2.1", "sha256"],
    ["2.16.840.1.101.3.4.2.2", "sha384"],
    ["2.16.840.1.101.3.4.2.3", "sha512"],
    ["2.16.840.1.101.3.4.2.4", "sha224"],
    ["2.16.840.1.101.3.4.2.5", "sha512-224"],
    ["2.16.840.1.101.3.4.2.6", "sha512-256"]
  ]],
  ["FIPS 202", [
    ["2.16.840.1.101.3.4.2.7", "sha3-224"],
    ["2.16.840.1.101.3.4.2.8", "sha3-256"],
    ["2.16.840.1.101.3.4.2.9", "sha3-384"],
    ["2.16.840.1.101.3.4.2.10", "sha3-512"],
    ["2.16.840.1.101.3.4.2.11", "shake128"],
    ["2.16.840.1.101.3.4.2.12", "shake256"],
    ["2.16.840.1.101.3.4.2.13", "hmacWithSHA3-224"],
    ["2.16.840.1.101.3.4.2.14", "hmacWithSHA3-256"],
    ["2.16.840.1.101.3.4.2.15", "hmacWithSHA3-384"],
    ["2.16.840.1.101.3.4.2.16", "hmacWithSHA3-512"]
  ]],
  ["RFC 3565", [
    ["2.16.840.1.101.3.4.1.2", "aes128-CBC"],
    ["2.16.840.1.101.3.4.1.22", "aes192-CBC"],
    ["2.16.840.1.101.3.4.1.42", "aes256-CBC"]
  ]],
  ["RFC 3394", [
    ["2.16.840.1.101.3.4.1.5", "aes128-wrap"],
    ["2.16.840.1.101.3.4.1.25", "aes192-wrap"],
    ["2.16.840.1.101.3.4.1.45", "aes256-wrap"]
  ]],
  ["RFC 5649", [
    ["2.16.840.1.101.3.4.1.8", "aes128-wrap-pad"],
    ["2.16.840.1.101.3.4.1.28", "aes192-wrap-pad"],
    ["2.16.840.1.101.3.4.1.48", "aes256-wrap-pad"]
  ]],
  ["RFC 5084", [
    ["2.16.840.1.101.3.4.1.6", "aes128-GCM"],
    ["2.16.840.1.101.3.4.1.26", "aes192-GCM"],
    ["2.16.840.1.101.3.4.1.46", "aes256-GCM"]
  ]],
  ["RFC 8103", [["1.2.840.113549.1.9.16.3.18", "aeadChaCha20Poly1305"]]]
];
function buildRegistry(groups) {
  const entries = [];
  for (const [standard, pairs] of groups) {
    for (const [oid, name] of pairs) entries.push(Object.freeze({ oid, name, standard }));
  }
  return Object.freeze(entries);
}
var OID_REGISTRY = /* @__PURE__ */ buildRegistry(GROUPS);

// src/oid/oid-names.ts
function indexByOid(entries) {
  const map = /* @__PURE__ */ new Map();
  for (const entry of entries) map.set(entry.oid, entry.name);
  return map;
}
var NAME_BY_OID = /* @__PURE__ */ indexByOid(OID_REGISTRY);
function getOidName(oid) {
  return typeof oid === "string" ? NAME_BY_OID.get(oid) : void 0;
}

// src/core/base64.ts
var ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function _reverseTable() {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i;
  return table;
}
var REVERSE = /* @__PURE__ */ _reverseTable();
function _sextet(text, index) {
  const c = text.charCodeAt(index);
  return c < 128 ? REVERSE[c] ?? -1 : -1;
}
function decodeBase64(text) {
  if (text.length % 4 !== 0) return null;
  if (text.length === 0) return new Uint8Array(0);
  let padding = 0;
  if (text.charCodeAt(text.length - 1) === 61) padding = text.charCodeAt(text.length - 2) === 61 ? 2 : 1;
  const out = new Uint8Array(text.length / 4 * 3 - padding);
  let at = 0;
  for (let i = 0; i < text.length; i += 4) {
    const last = i + 4 === text.length;
    const a = _sextet(text, i);
    const b = _sextet(text, i + 1);
    const c = last && padding === 2 ? 0 : _sextet(text, i + 2);
    const d = last && padding >= 1 ? 0 : _sextet(text, i + 3);
    if (a < 0 || b < 0 || c < 0 || d < 0) return null;
    if (last && padding === 2 && (b & 15) !== 0) return null;
    if (last && padding === 1 && (c & 3) !== 0) return null;
    const triple = a << 18 | b << 12 | c << 6 | d;
    out[at++] = triple >> 16 & 255;
    if (!(last && padding === 2)) out[at++] = triple >> 8 & 255;
    if (!(last && padding >= 1)) out[at++] = triple & 255;
  }
  return out;
}
function encodeBase64(bytes) {
  const parts = [];
  const view = byteView(bytes);
  for (let i = 0; i < bytes.length; i += 3) {
    const remaining = bytes.length - i;
    const b0 = view.getUint8(i);
    const b1 = remaining > 1 ? view.getUint8(i + 1) : 0;
    const b2 = remaining > 2 ? view.getUint8(i + 2) : 0;
    const triple = b0 << 16 | b1 << 8 | b2;
    parts.push(
      ALPHABET.charAt(triple >> 18 & 63),
      ALPHABET.charAt(triple >> 12 & 63),
      remaining > 1 ? ALPHABET.charAt(triple >> 6 & 63) : "=",
      remaining > 2 ? ALPHABET.charAt(triple & 63) : "="
    );
  }
  return parts.join("");
}

// src/pem/pem.ts
var LABEL = /^(?:[\x21-\x2c\x2e-\x7e](?:[- ]?[\x21-\x2c\x2e-\x7e])*)?$/;
var BEGIN = /^-----BEGIN .*-----$/;
var END = /^-----END .*-----$/;
var BEGIN_PREFIX = "-----BEGIN ".length;
var END_PREFIX = "-----END ".length;
var BOUNDARY_SUFFIX = "-----".length;
var BASE64_LINE = /^[A-Za-z0-9+/=]+$/;
var HEADER = /^[\x21-\x39\x3b-\x7e]+:[ \t]*.*$/;
var LAX_WHITESPACE = /[ \t\v\f\r\n]/g;
var TRAILING_WHITESPACE = /[ \t\v\f]+$/;
var LEADING_WHITESPACE = /^[ \t\v\f]+/;
function splitLines(text) {
  const lines = [];
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 10 && c !== 13) continue;
    lines.push({ text: text.slice(start, i), start });
    if (c === 13 && text.charCodeAt(i + 1) === 10) i++;
    start = i + 1;
  }
  if (start < text.length) lines.push({ text: text.slice(start), start });
  return lines;
}
function isValidLabel(label) {
  return LABEL.test(label);
}
function deviate(state, what, offset) {
  if (state.reported.has(what)) return;
  state.reported.add(what);
  state.emitter.emit(pemLaxAcceptedDiagnostic(what, offset));
}
function decodePem(text, options) {
  if (typeof text !== "string") {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: decodePem expects PEM text as a string, got ${text === null ? "null" : typeof text} \u2014 for DER bytes, call the DER function directly`);
  }
  if (options !== void 0 && (typeof options !== "object" || options === null)) {
    throw new PkiError("PKI_INVALID_OPTION", "pkinative: options must be an object \u2014 pass { mode, label, limits, strict, onDiagnostic } or omit it");
  }
  const mode = options?.mode ?? "strict";
  if (mode !== "strict" && mode !== "lax") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: mode must be 'strict' or 'lax', got ${String(mode)}`);
  }
  const wanted = options?.label;
  if (wanted !== void 0 && (typeof wanted !== "string" || !isValidLabel(wanted))) {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: label must be an RFC 7468 label such as 'CERTIFICATE', got ${JSON.stringify(wanted)}`);
  }
  if (options?.strict !== void 0 && typeof options.strict !== "boolean") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: strict must be a boolean, got ${typeof options.strict}`);
  }
  if (options?.onDiagnostic !== void 0 && typeof options.onDiagnostic !== "function") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: onDiagnostic must be a function, got ${typeof options.onDiagnostic}`);
  }
  const limits = resolveLimits(options?.limits);
  enforceLimit(limits, "maxInputBytes", text.length, "the PEM text length");
  const state = { emitter: createDiagnosticEmitter(options?.strict, options?.onDiagnostic), reported: /* @__PURE__ */ new Set() };
  const lax = mode === "lax";
  const boundary = (line) => {
    if (!lax) return line.text;
    const trimmed = line.text.replace(LEADING_WHITESPACE, "").replace(TRAILING_WHITESPACE, "");
    if (trimmed !== line.text && (BEGIN.test(trimmed) || END.test(trimmed))) deviate(state, "whitespace around a boundary line", line.start);
    return trimmed;
  };
  const lines = splitLines(text);
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const beginLine = lines[i];
    const begin = BEGIN.exec(boundary(beginLine));
    if (begin === null) continue;
    const label = begin[0].slice(BEGIN_PREFIX, -BOUNDARY_SUFFIX);
    if (!isValidLabel(label)) {
      throw new PkiEncodingError(
        "PKI_PEM_LABEL_INVALID",
        `pkinative: the BEGIN label ${JSON.stringify(label)} at offset ${beginLine.start} is outside the RFC 7468 label grammar \u2014 printable ASCII joined by single spaces or hyphens`,
        beginLine.start
      );
    }
    enforceLimit(limits, "maxPemBlocks", blocks.length + 1, "the number of PEM blocks");
    const body = [];
    let endLine;
    let endLabel = "";
    const bodyStart = i + 1;
    for (i++; i < lines.length; i++) {
      const line = lines[i];
      const shown = boundary(line);
      const end = END.exec(shown);
      if (end !== null) {
        endLine = line;
        endLabel = end[0].slice(END_PREFIX, -BOUNDARY_SUFFIX);
        break;
      }
      if (BEGIN.test(shown)) break;
      body.push(line);
    }
    if (endLine === void 0) {
      if (!lax && lines.slice(bodyStart).some((l) => l.text !== l.text.trim() && END.test(l.text.trim()))) {
        throw new PkiEncodingError(
          "PKI_PEM_UNTERMINATED",
          `pkinative: the "${label}" block at offset ${beginLine.start} has an END line with whitespace around it, which strict RFC 7468 parsing does not accept as a boundary \u2014 decode with mode: 'lax' to accept it`,
          beginLine.start
        );
      }
      throw new PkiEncodingError(
        "PKI_PEM_UNTERMINATED",
        `pkinative: the "${label}" block at offset ${beginLine.start} has no matching END line \u2014 the text is truncated or spliced`,
        beginLine.start
      );
    }
    if (endLabel !== label) {
      throw new PkiEncodingError(
        "PKI_PEM_LABEL_MISMATCH",
        `pkinative: the block that begins as "${label}" at offset ${beginLine.start} ends as "${endLabel}" at offset ${endLine.start} \u2014 the text was spliced or corrupted`,
        endLine.start
      );
    }
    if (wanted !== void 0 && label !== wanted) {
      throw new PkiEncodingError(
        "PKI_PEM_UNEXPECTED_LABEL",
        `pkinative: the block at offset ${beginLine.start} is "${label}", not "${wanted}" \u2014 pass the right block, or omit the label option`,
        beginLine.start
      );
    }
    const headers = [];
    let first = 0;
    if (body.length > 0 && HEADER.test(body[0].text.replace(LEADING_WHITESPACE, ""))) {
      if (!lax) {
        throw new PkiEncodingError(
          "PKI_PEM_HEADERS_FORBIDDEN",
          `pkinative: the "${label}" block at offset ${beginLine.start} carries RFC 1421 headers, which strict RFC 7468 parsing refuses \u2014 decode with mode: 'lax' to read legacy PEM`,
          body[0].start
        );
      }
      deviate(state, "RFC 1421 headers", body[0].start);
      for (; first < body.length; first++) {
        const raw = body[first].text;
        if (raw.trim() === "") break;
        const header = HEADER.exec(raw.replace(LEADING_WHITESPACE, ""));
        const previous = headers[headers.length - 1];
        if (header !== null && !LEADING_WHITESPACE.test(raw)) {
          const colon = header[0].indexOf(":");
          headers.push([header[0].slice(0, colon), header[0].slice(colon + 1).trim()]);
        } else if (previous !== void 0 && LEADING_WHITESPACE.test(raw)) headers[headers.length - 1] = [previous[0], `${previous[1]} ${raw.trim()}`];
        else break;
      }
      if (first >= body.length || body[first].text.trim() !== "") {
        throw new PkiEncodingError(
          "PKI_PEM_BASE64_INVALID",
          `pkinative: the headers of the "${label}" block at offset ${beginLine.start} are not followed by a blank line (RFC 1421 \xA74.4)`,
          beginLine.start
        );
      }
      first++;
    }
    let base64 = "";
    const content = body.slice(first);
    if (lax) {
      base64 = content.map((l) => l.text).join("\n");
      const stripped = base64.replace(LAX_WHITESPACE, "");
      const lengths = content.map((l) => l.text.length).filter((n) => n > 0);
      if (stripped !== base64.replace(/\n/g, "")) deviate(state, "whitespace inside the base64 text", beginLine.start);
      else if (lengths.slice(0, -1).some((n) => n !== 64) || (lengths[lengths.length - 1] ?? 0) > 64 || content.some((l) => l.text.length === 0)) {
        deviate(state, "base64 lines that are not 64 characters long", beginLine.start);
      }
      base64 = stripped;
    } else {
      for (let k = 0; k < content.length; k++) {
        const line = content[k];
        const last = k === content.length - 1;
        if (!BASE64_LINE.test(line.text) || line.text.length > 64 || !last && line.text.length !== 64) {
          throw new PkiEncodingError(
            "PKI_PEM_BASE64_INVALID",
            `pkinative: line ${k + 1} of the "${label}" block at offset ${line.start} is not a strict base64 line (64 characters from the base64 alphabet, the last one shorter) \u2014 decode with mode: 'lax' to tolerate whitespace and line lengths`,
            line.start
          );
        }
        base64 += line.text;
      }
    }
    const bytes = decodeBase64(base64);
    if (bytes === null) {
      throw new PkiEncodingError(
        "PKI_PEM_BASE64_INVALID",
        `pkinative: the body of the "${label}" block at offset ${beginLine.start} is not canonical base64 (alphabet, padding and zero padding bits, RFC 4648 \xA73.5)`,
        beginLine.start
      );
    }
    blocks.push(Object.freeze({ label, bytes, headers: Object.freeze(headers), offset: beginLine.start }));
  }
  if (blocks.length === 0) {
    if (!lax && lines.some((l) => BEGIN.test(l.text.trim()))) {
      throw new PkiEncodingError(
        "PKI_PEM_NO_BLOCK",
        "pkinative: the text has a -----BEGIN line with whitespace around it, which strict RFC 7468 parsing does not accept as a boundary \u2014 decode with mode: 'lax' to accept it",
        0
      );
    }
    throw new PkiEncodingError(
      "PKI_PEM_NO_BLOCK",
      "pkinative: the text contains no -----BEGIN line \u2014 pass the PEM text itself, or call the DER function directly for binary input",
      0
    );
  }
  return Object.freeze(blocks);
}
function encodePem(label, bytes) {
  if (typeof label !== "string" || !isValidLabel(label)) {
    throw new PkiEncodingError(
      "PKI_PEM_LABEL_INVALID",
      `pkinative: ${JSON.stringify(label)} is not an RFC 7468 label \u2014 use printable ASCII joined by single spaces or hyphens, such as 'CERTIFICATE'`
    );
  }
  const base64 = encodeBase64(assertBytes(bytes, "encodePem bytes"));
  const lines = [];
  for (let i = 0; i < base64.length; i += 64) lines.push(base64.slice(i, i + 64));
  return `-----BEGIN ${label}-----
${lines.map((l) => `${l}
`).join("")}-----END ${label}-----
`;
}

// src/hash/sha512.ts
var K_HI = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298,
  3391569614,
  3515267271,
  3940187606,
  4118630271,
  116418474,
  174292421,
  289380356,
  460393269,
  685471733,
  852142971,
  1017036298,
  1126000580,
  1288033470,
  1501505948,
  1607167915,
  1816402316
]);
var K_LO = /* @__PURE__ */ new Uint32Array([
  3609767458,
  602891725,
  3964484399,
  2173295548,
  4081628472,
  3053834265,
  2937671579,
  3664609560,
  2734883394,
  1164996542,
  1323610764,
  3590304994,
  4068182383,
  991336113,
  633803317,
  3479774868,
  2666613458,
  944711139,
  2341262773,
  2007800933,
  1495990901,
  1856431235,
  3175218132,
  2198950837,
  3999719339,
  766784016,
  2566594879,
  3203337956,
  1034457026,
  2466948901,
  3758326383,
  168717936,
  1188179964,
  1546045734,
  1522805485,
  2643833823,
  2343527390,
  1014477480,
  1206759142,
  344077627,
  1290863460,
  3158454273,
  3505952657,
  106217008,
  3606008344,
  1432725776,
  1467031594,
  851169720,
  3100823752,
  1363258195,
  3750685593,
  3785050280,
  3318307427,
  3812723403,
  2003034995,
  3602036899,
  1575990012,
  1125592928,
  2716904306,
  442776044,
  593698344,
  3733110249,
  2999351573,
  3815920427,
  3928383900,
  566280711,
  3454069534,
  4000239992,
  1914138554,
  2731055270,
  3203993006,
  320620315,
  587496836,
  1086792851,
  365543100,
  2618297676,
  3409855158,
  4234509866,
  987167468,
  1246189591
]);
var IV_512 = [
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
];
var IV_384 = [
  3418070365,
  3238371032,
  1654270250,
  914150663,
  2438529370,
  812702999,
  355462360,
  4144912697,
  1731405415,
  4290775857,
  2394180231,
  1750603025,
  3675008525,
  1694076839,
  1203062813,
  3204075428
];
function add(out, ah, al, bh, bl) {
  const low = al + bl >>> 0;
  out[0] = ah + bh + (low < al ? 1 : 0) >>> 0;
  out[1] = low;
}
function core(input, iv, outputLength) {
  const padded = padMessage(input, 128, 16);
  const view = new DataView(padded.buffer);
  const state = Uint32Array.from(iv);
  const wh = new Uint32Array(80);
  const wl = new Uint32Array(80);
  const t = new Uint32Array(2);
  const fold3 = (i, high, low) => {
    add(t, state[i], state[i + 1], high, low);
    state[i] = t[0];
    state[i + 1] = t[1];
  };
  for (let offset = 0; offset < padded.length; offset += 128) {
    for (let j = 0; j < 16; j++) {
      wh[j] = view.getUint32(offset + j * 8, false);
      wl[j] = view.getUint32(offset + j * 8 + 4, false);
    }
    for (let j = 16; j < 80; j++) {
      const xh = wh[j - 15];
      const xl = wl[j - 15];
      const s0h = (xh >>> 1 | xl << 31) ^ (xh >>> 8 | xl << 24) ^ xh >>> 7;
      const s0l = (xl >>> 1 | xh << 31) ^ (xl >>> 8 | xh << 24) ^ (xl >>> 7 | xh << 25);
      const yh = wh[j - 2];
      const yl = wl[j - 2];
      const s1h = (yh >>> 19 | yl << 13) ^ (yl >>> 29 | yh << 3) ^ yh >>> 6;
      const s1l = (yl >>> 19 | yh << 13) ^ (yh >>> 29 | yl << 3) ^ (yl >>> 6 | yh << 26);
      add(t, wh[j - 16], wl[j - 16], s0h >>> 0, s0l >>> 0);
      add(t, t[0], t[1], wh[j - 7], wl[j - 7]);
      add(t, t[0], t[1], s1h >>> 0, s1l >>> 0);
      wh[j] = t[0];
      wl[j] = t[1];
    }
    let aH = state[0], aL = state[1];
    let bH = state[2], bL = state[3];
    let cH = state[4], cL = state[5];
    let dH = state[6], dL = state[7];
    let eH = state[8], eL = state[9];
    let fH = state[10], fL = state[11];
    let gH = state[12], gL = state[13];
    let hH = state[14], hL = state[15];
    for (let j = 0; j < 80; j++) {
      const sigma1H = (eH >>> 14 | eL << 18) ^ (eH >>> 18 | eL << 14) ^ (eL >>> 9 | eH << 23);
      const sigma1L = (eL >>> 14 | eH << 18) ^ (eL >>> 18 | eH << 14) ^ (eH >>> 9 | eL << 23);
      const choiceH = eH & fH ^ ~eH & gH;
      const choiceL = eL & fL ^ ~eL & gL;
      add(t, hH, hL, sigma1H >>> 0, sigma1L >>> 0);
      add(t, t[0], t[1], choiceH >>> 0, choiceL >>> 0);
      add(t, t[0], t[1], K_HI[j], K_LO[j]);
      add(t, t[0], t[1], wh[j], wl[j]);
      const temp1H = t[0];
      const temp1L = t[1];
      const sigma0H = (aH >>> 28 | aL << 4) ^ (aL >>> 2 | aH << 30) ^ (aL >>> 7 | aH << 25);
      const sigma0L = (aL >>> 28 | aH << 4) ^ (aH >>> 2 | aL << 30) ^ (aH >>> 7 | aL << 25);
      const majorityH = aH & bH ^ aH & cH ^ bH & cH;
      const majorityL = aL & bL ^ aL & cL ^ bL & cL;
      add(t, sigma0H >>> 0, sigma0L >>> 0, majorityH >>> 0, majorityL >>> 0);
      const temp2H = t[0];
      const temp2L = t[1];
      hH = gH;
      hL = gL;
      gH = fH;
      gL = fL;
      fH = eH;
      fL = eL;
      add(t, dH, dL, temp1H, temp1L);
      eH = t[0];
      eL = t[1];
      dH = cH;
      dL = cL;
      cH = bH;
      cL = bL;
      bH = aH;
      bL = aL;
      add(t, temp1H, temp1L, temp2H, temp2L);
      aH = t[0];
      aL = t[1];
    }
    fold3(0, aH, aL);
    fold3(2, bH, bL);
    fold3(4, cH, cL);
    fold3(6, dH, dL);
    fold3(8, eH, eL);
    fold3(10, fH, fL);
    fold3(12, gH, gL);
    fold3(14, hH, hL);
  }
  const out = new Uint8Array(64);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) outView.setUint32(i * 4, state[i], false);
  return outputLength === 64 ? out : out.slice(0, 48);
}
function sha512(input) {
  return core(input, IV_512, 64);
}
function sha384(input) {
  return core(input, IV_384, 48);
}

// src/hash/fingerprint.ts
var ALGORITHMS = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
function digestFunction(algorithm) {
  switch (algorithm) {
    case "SHA-1":
      return sha1;
    case "SHA-256":
      return sha256;
    case "SHA-384":
      return sha384;
    case "SHA-512":
      return sha512;
    default:
      throw new PkiError("PKI_INVALID_OPTION", `pkinative: the fingerprint algorithm must be one of ${ALGORITHMS.join(", ")}, got ${String(algorithm)}`);
  }
}
function computeFingerprint(der, algorithm) {
  const hash = digestFunction(algorithm);
  return hash(assertBytes(der, "computeFingerprint input"));
}
async function computeFingerprintAsync(der, algorithm) {
  const hash = digestFunction(algorithm);
  const bytes = assertBytes(der, "computeFingerprintAsync input");
  const subtle = globalThis.crypto?.subtle;
  if (subtle !== void 0 && typeof subtle.digest === "function") {
    try {
      return new Uint8Array(await subtle.digest(algorithm, bytes));
    } catch {
    }
  }
  return hash(bytes);
}
function formatFingerprint(digest, options) {
  const bytes = assertBytes(digest, "formatFingerprint digest");
  const separator = options?.separator ?? ":";
  const letterCase = options?.letterCase ?? "upper";
  if (typeof separator !== "string") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: separator must be a string, got ${typeof separator}`);
  }
  if (letterCase !== "upper" && letterCase !== "lower") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: letterCase must be 'upper' or 'lower', got ${String(letterCase)}`);
  }
  const hex3 = toHex(bytes, separator);
  return letterCase === "upper" ? hex3.toUpperCase() : hex3;
}

// src/x509/x509-spki.ts
var CODE3 = "PKI_X509_SPKI_INVALID";
var OID_RSA = "1.2.840.113549.1.1.1";
var OID_RSA_PSS = "1.2.840.113549.1.1.10";
var OID_EC = "1.2.840.10045.2.1";
var CURVES = /* @__PURE__ */ new Map([
  ["1.2.840.10045.3.1.7", { curve: "P-256", size: 32 }],
  ["1.3.132.0.34", { curve: "P-384", size: 48 }],
  ["1.3.132.0.35", { curve: "P-521", size: 66 }]
]);
var OCTET_KEYS = /* @__PURE__ */ new Map([
  ["1.3.101.110", { kind: "x25519", length: 32 }],
  ["1.3.101.111", { kind: "x448", length: 56 }],
  ["1.3.101.112", { kind: "ed25519", length: 32 }],
  ["1.3.101.113", { kind: "ed448", length: 57 }],
  ["2.16.840.1.101.3.4.3.17", { kind: "ml-dsa-44", length: 1312 }],
  ["2.16.840.1.101.3.4.3.18", { kind: "ml-dsa-65", length: 1952 }],
  ["2.16.840.1.101.3.4.3.19", { kind: "ml-dsa-87", length: 2592 }]
]);
function requireWholeOctets(parts, what) {
  if (parts.publicKey.unusedBits !== 0) {
    throw certificateError(CODE3, parts.keyPath, parts.keyOffset, `has ${parts.publicKey.unusedBits} unused bits; ${what} key is a whole number of octets`);
  }
}
function readRsa(parts, kind, ctx) {
  requireWholeOctets(parts, "an RSA");
  try {
    const key = decodeWithContext(parts.publicKey.bytes, ctx, false);
    const modulusNode = key.children[0];
    const exponentNode = key.children[1];
    if (key.tagClass !== "universal" || key.tagNumber !== TAG_SEQUENCE || key.children.length !== 2 || modulusNode?.tagClass !== "universal" || modulusNode.tagNumber !== TAG_INTEGER || exponentNode?.tagClass !== "universal" || exponentNode.tagNumber !== TAG_INTEGER) {
      throw certificateError(CODE3, parts.keyPath, parts.keyOffset, "is not an RSAPublicKey: a SEQUENCE of the modulus and the public exponent, two INTEGERs");
    }
    const modulus = _readInteger(modulusNode, ctx);
    const publicExponent = _readInteger(exponentNode, ctx);
    if (modulus <= 0n || publicExponent <= 0n) {
      throw certificateError(CODE3, parts.keyPath, parts.keyOffset, "has a modulus or public exponent that is not positive");
    }
    const content = modulusNode.content;
    const info = {
      kind,
      algorithm: parts.algorithm,
      publicKey: parts.publicKey,
      der: parts.der,
      modulus: content[0] === 0 ? content.subarray(1) : content,
      modulusBits: modulus.toString(2).length,
      publicExponent
    };
    return Object.freeze(info);
  } catch (error) {
    if (error instanceof PkiEncodingError) {
      throw certificateError(CODE3, parts.keyPath, parts.keyOffset, `is not a DER RSAPublicKey (${error.code})`);
    }
    throw error;
  }
}
function readEc(parts, ctx) {
  const parameters = parts.algorithm.parameters;
  if (parameters === void 0) {
    throw certificateError(CODE3, `${parts.keyPath.replace(/subjectPublicKey$/, "algorithm")}.parameters`, parts.keyOffset, "are absent; an EC key names its curve (RFC 5480 \xA72.1.1)");
  }
  const namedCurve = parameters.tagClass === "universal" && parameters.tagNumber === TAG_OID ? _readObjectIdentifier(parameters, ctx) : void 0;
  const spec = namedCurve === void 0 ? void 0 : CURVES.get(namedCurve);
  requireWholeOctets(parts, "an EC");
  const point = parts.publicKey.bytes;
  const first = point[0];
  let pointFormat;
  if (first === 4) {
    pointFormat = "uncompressed";
    const valid = spec === void 0 ? point.length >= 3 && point.length % 2 === 1 : point.length === 1 + 2 * spec.size;
    if (!valid) throw certificateError(CODE3, parts.keyPath, parts.keyOffset, `is an uncompressed point of ${point.length} octets, which ${spec?.curve ?? "no curve"} allows`);
  } else if (first === 2 || first === 3) {
    pointFormat = "compressed";
    const valid = spec === void 0 ? point.length >= 2 : point.length === 1 + spec.size;
    if (!valid) throw certificateError(CODE3, parts.keyPath, parts.keyOffset, `is a compressed point of ${point.length} octets, which ${spec?.curve ?? "no curve"} allows`);
  } else {
    throw certificateError(CODE3, parts.keyPath, parts.keyOffset, "does not start with 0x04 (uncompressed) or 0x02/0x03 (compressed); RFC 5480 \xA72.2 allows no other point form");
  }
  const info = {
    kind: "ec",
    algorithm: parts.algorithm,
    publicKey: parts.publicKey,
    der: parts.der,
    namedCurve,
    curve: spec?.curve,
    pointFormat,
    point
  };
  return Object.freeze(info);
}
function readOctetKey(parts, spec) {
  if (parts.algorithm.parameters !== void 0) {
    throw certificateError(CODE3, parts.keyPath, parts.keyOffset, `belongs to ${spec.kind}, whose AlgorithmIdentifier must omit the parameters (RFC 8410 \xA73)`);
  }
  requireWholeOctets(parts, `an ${spec.kind}`);
  if (parts.publicKey.bytes.length !== spec.length) {
    throw certificateError(CODE3, parts.keyPath, parts.keyOffset, `is ${parts.publicKey.bytes.length} octets; an ${spec.kind} key is ${spec.length}`);
  }
  const info = { kind: spec.kind, algorithm: parts.algorithm, publicKey: parts.publicKey, der: parts.der, key: parts.publicKey.bytes };
  return Object.freeze(info);
}
function _readSubjectPublicKeyInfo(node, ctx, path, parentOffset) {
  const seq = expectUniversalField(node, TAG_SEQUENCE, path, CODE3, parentOffset);
  if (seq.children.length > 2) {
    throw certificateError(CODE3, path, seq.offset, `holds ${seq.children.length} values; SubjectPublicKeyInfo is an AlgorithmIdentifier and a BIT STRING`);
  }
  const algorithm = _readAlgorithmIdentifier(seq.children[0], ctx, `${path}.algorithm`, CODE3, seq.offset);
  const keyPath = `${path}.subjectPublicKey`;
  const keyNode = expectUniversalField(seq.children[1], TAG_BIT_STRING, keyPath, CODE3, seq.offset);
  const parts = { algorithm, publicKey: _readBitString(keyNode, ctx), der: seq.bytes, keyPath, keyOffset: keyNode.offset };
  if (algorithm.oid === OID_RSA) return readRsa(parts, "rsa", ctx);
  if (algorithm.oid === OID_RSA_PSS) return readRsa(parts, "rsa-pss", ctx);
  if (algorithm.oid === OID_EC) return readEc(parts, ctx);
  const octetKey = OCTET_KEYS.get(algorithm.oid);
  if (octetKey !== void 0) return readOctetKey(parts, octetKey);
  const info = { kind: "unknown", algorithm, publicKey: parts.publicKey, der: seq.bytes };
  return Object.freeze(info);
}

// src/x509/x509-certificate.ts
var STRUCTURE3 = "PKI_X509_STRUCTURE_INVALID";
var OID_SUBJECT_ALT_NAME = "2.5.29.17";
var NO_EXTENSIONS = /* @__PURE__ */ Object.freeze([]);
function readVersion(field, ctx) {
  const path = "tbsCertificate.version";
  if (!field.constructed || field.children.length !== 1) {
    throw certificateError(STRUCTURE3, path, field.offset, "is not one INTEGER under the explicit [0] tag");
  }
  const node = expectUniversalField(field.children[0], TAG_INTEGER, path, STRUCTURE3, field.offset);
  const value = _readInteger(node, ctx);
  if (value !== 0n && value !== 1n && value !== 2n) {
    throw certificateError("PKI_X509_VERSION_INVALID", path, node.offset, `is ${String(value)}; RFC 5280 defines v1 (0), v2 (1) and v3 (2)`);
  }
  if (value === 0n) ctx.emitter.emit(defaultEncodedDiagnostic(path, "v1", field.offset));
  return Number(value) + 1;
}
function readValidityTime(node, ctx, path) {
  if (node.tagClass !== "universal" || node.tagNumber !== TAG_UTC_TIME && node.tagNumber !== TAG_GENERALIZED_TIME) {
    throw certificateError("PKI_X509_VALIDITY_INVALID", path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; a certificate time is a UTCTime or a GeneralizedTime`);
  }
  const time = _readTime(node, ctx, void 0);
  if (time.type === "GeneralizedTime") {
    if (Number(time.text.slice(0, 4)) < 2050) ctx.emitter.emit(generalizedTimeBefore2050Diagnostic(path, time.text, node.offset));
    if (/[.,]/.test(time.text)) ctx.emitter.emit(generalizedTimeFractionDiagnostic(path, time.text, node.offset));
  }
  return time;
}
function readValidity(node, ctx, parentOffset) {
  const path = "tbsCertificate.validity";
  const seq = expectUniversalField(node, TAG_SEQUENCE, path, "PKI_X509_VALIDITY_INVALID", parentOffset);
  if (seq.children.length !== 2) {
    throw certificateError("PKI_X509_VALIDITY_INVALID", path, seq.offset, `holds ${seq.children.length} values; Validity is notBefore and notAfter`);
  }
  const notBefore = readValidityTime(seq.children[0], ctx, `${path}.notBefore`);
  const notAfter = readValidityTime(seq.children[1], ctx, `${path}.notAfter`);
  if (notBefore.epochMilliseconds > notAfter.epochMilliseconds) ctx.emitter.emit(validityInvertedDiagnostic(notBefore.text, notAfter.text));
  const validity = { notBefore, notAfter };
  return Object.freeze(validity);
}
function readExtensions3(field, ctx, input, decode) {
  const path = "tbsCertificate.extensions";
  if (!field.constructed || field.children.length !== 1) {
    throw certificateError(STRUCTURE3, path, field.offset, "is not one SEQUENCE under the explicit [3] tag");
  }
  const seq = expectUniversalField(field.children[0], TAG_SEQUENCE, path, STRUCTURE3, field.offset);
  if (seq.children.length === 0) {
    throw certificateError("PKI_X509_EXTENSIONS_EMPTY", path, seq.offset, "is present but holds no extension; RFC 5280 requires at least one");
  }
  enforceLimit(ctx.limits, "maxExtensions", seq.children.length, "the extensions of the certificate");
  const seen = /* @__PURE__ */ new Set();
  const extensions = [];
  for (let i = 0; i < seq.children.length; i++) {
    const extPath = `${path}[${i}]`;
    const ext = expectUniversalField(seq.children[i], TAG_SEQUENCE, extPath, STRUCTURE3, seq.offset);
    if (ext.children.length < 2 || ext.children.length > 3) {
      throw certificateError(STRUCTURE3, extPath, ext.offset, `holds ${ext.children.length} values; an Extension is extnID, an optional critical flag and extnValue`);
    }
    const oid = _readObjectIdentifier(expectUniversalField(ext.children[0], TAG_OID, `${extPath}.extnID`, STRUCTURE3, ext.offset), ctx);
    let critical = false;
    if (ext.children.length === 3) {
      const flag = expectUniversalField(ext.children[1], TAG_BOOLEAN, `${extPath}.critical`, STRUCTURE3, ext.offset);
      critical = _readBoolean(flag, ctx);
      if (!critical) ctx.emitter.emit(defaultEncodedDiagnostic(`${extPath}.critical`, "FALSE", flag.offset));
    }
    const valueNode = expectUniversalField(ext.children[ext.children.length - 1], TAG_OCTET_STRING, `${extPath}.extnValue`, STRUCTURE3, ext.offset);
    const valueDer = _readOctetString(valueNode, ctx);
    if (seen.has(oid)) {
      throw certificateError("PKI_X509_EXTENSION_DUPLICATE", extPath, ext.offset, `repeats the extension ${oid}; RFC 5280 \xA74.2 allows each extension once`);
    }
    seen.add(oid);
    if (!decode) {
      const extension = { kind: "raw", oid, critical, valueDer };
      extensions.push(Object.freeze(extension));
    } else if (valueNode.constructed) {
      extensions.push(_decodeExtension(valueDer, 0, oid, critical, valueDer, ctx, extPath));
    } else {
      const start = valueNode.offset + valueNode.headerLength;
      extensions.push(_decodeExtension(input.subarray(0, start + valueNode.contentLength), start, oid, critical, valueDer, ctx, extPath));
    }
  }
  return Object.freeze(extensions);
}
function parseCertificate(der, options) {
  const bytes = assertBytes(der, "parseCertificate input");
  const ctx = createAsn1Context(options);
  const decode = options?.decodeExtensions ?? true;
  if (typeof decode !== "boolean") {
    throw new PkiError("PKI_INVALID_OPTION", `pkinative: decodeExtensions must be a boolean, got ${typeof decode}`);
  }
  const cert = expectUniversalField(decodeWithContext(bytes, ctx, false), TAG_SEQUENCE, "certificate", STRUCTURE3, 0);
  if (cert.children.length !== 3) {
    throw certificateError(STRUCTURE3, "certificate", cert.offset, `holds ${cert.children.length} values; a Certificate is tbsCertificate, signatureAlgorithm and signatureValue`);
  }
  const tbs = expectUniversalField(cert.children[0], TAG_SEQUENCE, "tbsCertificate", STRUCTURE3, cert.offset);
  const fields = tbs.children;
  let index = 0;
  let version = 1;
  const first = fields[0];
  if (first !== void 0 && first.tagClass === "context" && first.tagNumber === 0) {
    version = readVersion(first, ctx);
    index = 1;
  }
  const serialNode = expectUniversalField(fields[index++], TAG_INTEGER, "tbsCertificate.serialNumber", STRUCTURE3, tbs.offset);
  const serialValue = _readInteger(serialNode, ctx);
  if (serialNode.contentLength > 20) ctx.emitter.emit(serialTooLongDiagnostic(serialNode.contentLength, serialNode.offset));
  if (serialValue <= 0n) ctx.emitter.emit(serialNotPositiveDiagnostic(serialNode.offset));
  const tbsSignatureAlgorithm = _readAlgorithmIdentifier(fields[index++], ctx, "tbsCertificate.signature", STRUCTURE3, tbs.offset);
  const issuer = _readName(fields[index++], ctx, "tbsCertificate.issuer", tbs.offset);
  if (issuer.rdns.length === 0) ctx.emitter.emit(emptyIssuerDiagnostic());
  const validity = readValidity(fields[index++], ctx, tbs.offset);
  const subject = _readName(fields[index++], ctx, "tbsCertificate.subject", tbs.offset);
  const subjectPublicKeyInfo = _readSubjectPublicKeyInfo(fields[index++], ctx, "tbsCertificate.subjectPublicKeyInfo", tbs.offset);
  let issuerUniqueId;
  let subjectUniqueId;
  let extensions = NO_EXTENSIONS;
  let extensionsPresent = false;
  let rank = 0;
  for (; index < fields.length; index++) {
    const field = fields[index];
    const tag = field.tagClass === "context" ? field.tagNumber : -1;
    if (tag !== 1 && tag !== 2 && tag !== 3) {
      throw certificateError(
        STRUCTURE3,
        `tbsCertificate[${index}]`,
        field.offset,
        `is ${tagLabel(field.tagClass, field.tagNumber)}, where only issuerUniqueID [1], subjectUniqueID [2] or extensions [3] may follow the public key`
      );
    }
    const path = tag === 1 ? "tbsCertificate.issuerUniqueID" : tag === 2 ? "tbsCertificate.subjectUniqueID" : "tbsCertificate.extensions";
    if (tag <= rank) {
      throw certificateError(
        tag === 3 ? STRUCTURE3 : "PKI_X509_UNIQUE_ID_INVALID",
        path,
        field.offset,
        "appears twice or out of order; TBSCertificate orders issuerUniqueID, subjectUniqueID, then extensions"
      );
    }
    rank = tag;
    if (tag === 3) {
      extensions = readExtensions3(field, ctx, bytes, decode);
      extensionsPresent = true;
      continue;
    }
    if (field.constructed && ctx.rules === "der") {
      throw certificateError("PKI_X509_UNIQUE_ID_INVALID", path, field.offset, "is constructed; a unique identifier is a primitive BIT STRING under its implicit tag");
    }
    const id = _readBitString(field, ctx);
    if (tag === 1) issuerUniqueId = id;
    else subjectUniqueId = id;
  }
  if ((issuerUniqueId !== void 0 || subjectUniqueId !== void 0) && version === 1) ctx.emitter.emit(uniqueIdRequiresV2Diagnostic(version));
  if (extensionsPresent && version !== 3) ctx.emitter.emit(extensionsRequireV3Diagnostic(version));
  if (subject.rdns.length === 0 && extensions.find((e) => e.oid === OID_SUBJECT_ALT_NAME)?.critical !== true) {
    ctx.emitter.emit(emptySubjectSanNotCriticalDiagnostic());
  }
  const signatureAlgorithm = _readAlgorithmIdentifier(cert.children[1], ctx, "signatureAlgorithm", STRUCTURE3, cert.offset);
  if (!bytesEqual(signatureAlgorithm.der, tbsSignatureAlgorithm.der)) {
    ctx.emitter.emit(signatureAlgorithmMismatchDiagnostic(signatureAlgorithm.oid, tbsSignatureAlgorithm.oid));
  }
  const signatureValue = _readBitString(expectUniversalField(cert.children[2], TAG_BIT_STRING, "signatureValue", STRUCTURE3, cert.offset), ctx);
  const serialNumber = { bytes: serialNode.content, hex: toHex(serialNode.content), value: serialValue };
  const certificate = {
    der: cert.bytes,
    tbsDer: tbs.bytes,
    version,
    serialNumber: Object.freeze(serialNumber),
    signatureAlgorithm,
    tbsSignatureAlgorithm,
    signatureValue,
    issuer,
    validity,
    subject,
    subjectPublicKeyInfo,
    issuerUniqueId,
    subjectUniqueId,
    extensions,
    diagnostics: Object.freeze([...ctx.emitter.diagnostics])
  };
  return Object.freeze(certificate);
}

// src/crypto/crypto-algorithms.ts
var HASH_BY_OID = /* @__PURE__ */ new Map([
  ["1.3.14.3.2.26", "SHA-1"],
  ["2.16.840.1.101.3.4.2.1", "SHA-256"],
  ["2.16.840.1.101.3.4.2.2", "SHA-384"],
  ["2.16.840.1.101.3.4.2.3", "SHA-512"]
]);
var DEFAULT_PSS_SALT_LENGTH = 20;
var SIGNATURE_BY_OID = /* @__PURE__ */ new Map([
  ["1.2.840.113549.1.1.5", { family: "rsa-pkcs1", hash: "SHA-1" }],
  ["1.2.840.113549.1.1.11", { family: "rsa-pkcs1", hash: "SHA-256" }],
  ["1.2.840.113549.1.1.12", { family: "rsa-pkcs1", hash: "SHA-384" }],
  ["1.2.840.113549.1.1.13", { family: "rsa-pkcs1", hash: "SHA-512" }],
  ["1.2.840.113549.1.1.10", { family: "rsa-pss" }],
  ["1.2.840.10045.4.1", { family: "ecdsa", hash: "SHA-1" }],
  ["1.2.840.10045.4.3.2", { family: "ecdsa", hash: "SHA-256" }],
  ["1.2.840.10045.4.3.3", { family: "ecdsa", hash: "SHA-384" }],
  ["1.2.840.10045.4.3.4", { family: "ecdsa", hash: "SHA-512" }],
  ["1.3.101.112", { family: "ed25519" }],
  ["1.3.101.113", { family: "ed448" }]
]);
function unsupported(message, oid) {
  return new PkiCryptoError("PKI_CRYPTO_ALGORITHM_UNSUPPORTED", `pkinative: ${message} \u2014 verify it with a library that implements it, or ask for it in an issue naming the certificate that needs it`, oid);
}
function readPssParams(parameters, oid) {
  let hash = "SHA-1";
  let saltLength;
  let mgfHash = "SHA-1";
  if (parameters !== void 0) {
    if (parameters.tagClass !== "universal" || parameters.tagNumber !== TAG_SEQUENCE) {
      throw unsupported("the RSASSA-PSS parameters are not a SEQUENCE", oid);
    }
    for (const field of parameters.children) {
      if (field.tagClass !== "context") continue;
      const inner = field.children[0];
      if (inner === void 0) continue;
      if (field.tagNumber === 0) hash = hashNameOf(inner, oid);
      else if (field.tagNumber === 1) mgfHash = mgf1HashOf(inner, oid);
      else if (field.tagNumber === 2) saltLength = readSmallInteger(inner);
      else if (field.tagNumber === 3 && readSmallInteger(inner) !== 1) {
        throw unsupported("the RSASSA-PSS trailerField is not 1, the only value RFC 4055 defines", oid);
      }
    }
  }
  if (mgfHash !== hash) {
    throw unsupported(`the RSASSA-PSS mask generation uses ${mgfHash} while the signature uses ${hash}, and Web Crypto only offers MGF1 over the signature hash`, oid);
  }
  if (saltLength === void 0) saltLength = DEFAULT_PSS_SALT_LENGTH;
  if (saltLength < 0) throw unsupported("the RSASSA-PSS salt length is negative", oid);
  return { hash, saltLength };
}
function hashNameOf(algorithm, oid) {
  const first = algorithm.tagClass === "universal" && algorithm.tagNumber === TAG_SEQUENCE ? algorithm.children[0] : void 0;
  if (first === void 0 || first.tagClass !== "universal" || first.tagNumber !== TAG_OID) {
    throw unsupported("an RSASSA-PSS hash parameter is not an AlgorithmIdentifier", oid);
  }
  const hashOid = readObjectIdentifier(first);
  const name = HASH_BY_OID.get(hashOid);
  if (name === void 0) throw unsupported(`the RSASSA-PSS digest ${hashOid} is not one Web Crypto implements`, oid);
  return name;
}
function mgf1HashOf(algorithm, oid) {
  const first = algorithm.tagClass === "universal" && algorithm.tagNumber === TAG_SEQUENCE ? algorithm.children[0] : void 0;
  if (first === void 0 || first.tagClass !== "universal" || first.tagNumber !== TAG_OID) {
    throw unsupported("the RSASSA-PSS maskGenAlgorithm is not an AlgorithmIdentifier", oid);
  }
  if (readObjectIdentifier(first) !== "1.2.840.113549.1.1.8") {
    throw unsupported("the RSASSA-PSS mask generation function is not MGF1, the only one Web Crypto implements", oid);
  }
  const inner = algorithm.children[1];
  return inner === void 0 ? "SHA-1" : hashNameOf(inner, oid);
}
var isRsaKey = (key) => key.kind === "rsa" || key.kind === "rsa-pss";
function resolveAlgorithm(algorithm, key) {
  const shape = SIGNATURE_BY_OID.get(algorithm.oid);
  if (shape === void 0) throw unsupported(`the signature algorithm ${algorithm.oid} is not one pkinative verifies`, algorithm.oid);
  if (shape.family === "rsa-pss") {
    if (!isRsaKey(key)) return null;
    const { hash, saltLength } = readPssParams(algorithm.parameters, algorithm.oid);
    const verifyParams = { name: "RSA-PSS", saltLength };
    return { family: shape.family, importParams: { name: "RSA-PSS", hash: { name: hash } }, verifyParams, curve: void 0, hash };
  }
  if (shape.family === "rsa-pkcs1") {
    if (!isRsaKey(key)) return null;
    const verifyParams = { name: "RSASSA-PKCS1-v1_5" };
    return { family: shape.family, importParams: { name: "RSASSA-PKCS1-v1_5", hash: { name: shape.hash } }, verifyParams, curve: void 0, hash: shape.hash };
  }
  if (shape.family === "ecdsa") {
    if (key.kind !== "ec") return null;
    const curve = key.curve;
    if (curve !== "P-256" && curve !== "P-384" && curve !== "P-521") {
      throw new PkiCryptoError(
        "PKI_CRYPTO_KEY_UNSUPPORTED",
        `pkinative: the issuer's EC key is on ${curve ?? "a curve pkinative does not name"}, and Web Crypto verifies ECDSA only on P-256, P-384 and P-521`,
        algorithm.oid
      );
    }
    const verifyParams = { name: "ECDSA", hash: { name: shape.hash } };
    return { family: shape.family, importParams: { name: "ECDSA", namedCurve: curve }, verifyParams, curve, hash: shape.hash };
  }
  if (key.kind !== shape.family) return null;
  const name = shape.family === "ed25519" ? "Ed25519" : "Ed448";
  return { family: shape.family, importParams: { name }, verifyParams: { name }, curve: void 0, hash: void 0 };
}
function coordinateBytes(curve) {
  return curve === "P-256" ? 32 : curve === "P-384" ? 48 : 66;
}
var OID_BY_SIGNATURE = /* @__PURE__ */ new Map([
  ["RSASSA-PKCS1-v1_5/SHA-1", "1.2.840.113549.1.1.5"],
  ["RSASSA-PKCS1-v1_5/SHA-256", "1.2.840.113549.1.1.11"],
  ["RSASSA-PKCS1-v1_5/SHA-384", "1.2.840.113549.1.1.12"],
  ["RSASSA-PKCS1-v1_5/SHA-512", "1.2.840.113549.1.1.13"],
  ["ECDSA/SHA-1", "1.2.840.10045.4.1"],
  ["ECDSA/SHA-256", "1.2.840.10045.4.3.2"],
  ["ECDSA/SHA-384", "1.2.840.10045.4.3.3"],
  ["ECDSA/SHA-512", "1.2.840.10045.4.3.4"]
]);
var EDWARDS_OID = /* @__PURE__ */ Object.freeze({
  Ed25519: "1.3.101.112",
  Ed448: "1.3.101.113"
});
var OID_BY_HASH = /* @__PURE__ */ new Map([
  ["SHA-1", "1.3.14.3.2.26"],
  ["SHA-256", "2.16.840.1.101.3.4.2.1"],
  ["SHA-384", "2.16.840.1.101.3.4.2.2"],
  ["SHA-512", "2.16.840.1.101.3.4.2.3"]
]);
var HASH_BYTES = /* @__PURE__ */ new Map([
  ["SHA-1", 20],
  ["SHA-256", 32],
  ["SHA-384", 48],
  ["SHA-512", 64]
]);
function resolveSigner(algorithm) {
  if (algorithm.name === "Ed25519" || algorithm.name === "Ed448") {
    return { oid: EDWARDS_OID[algorithm.name], signParams: { name: algorithm.name }, curve: void 0, pss: void 0 };
  }
  if (algorithm.name === "RSA-PSS") {
    const hashOid = OID_BY_HASH.get(algorithm.hash);
    const size = HASH_BYTES.get(algorithm.hash);
    if (hashOid === void 0 || size === void 0) throw unsupported(`RSASSA-PSS with ${algorithm.hash} is not a digest pkinative writes`, "1.2.840.113549.1.1.10");
    const saltLength = algorithm.saltLength ?? size;
    if (!Number.isInteger(saltLength) || saltLength < 0) {
      throw unsupported(`the RSASSA-PSS salt length must be a non-negative integer, got ${String(algorithm.saltLength)}`, "1.2.840.113549.1.1.10");
    }
    return {
      oid: "1.2.840.113549.1.1.10",
      signParams: { name: "RSA-PSS", saltLength },
      curve: void 0,
      pss: { hashOid, saltLength }
    };
  }
  const oid = OID_BY_SIGNATURE.get(`${algorithm.name}/${algorithm.hash}`);
  if (oid === void 0) throw unsupported(`${algorithm.name} with ${algorithm.hash} has no RFC 5280 signature OID`, "");
  if (algorithm.name === "ECDSA") {
    return { oid, signParams: { name: "ECDSA", hash: { name: algorithm.hash } }, curve: algorithm.namedCurve, pss: void 0 };
  }
  return { oid, signParams: { name: "RSASSA-PKCS1-v1_5" }, curve: void 0, pss: void 0 };
}

// src/crypto/crypto-signature.ts
var SEQUENCE_OCTET = 48;
var INTEGER_OCTET = 2;
function ecdsaDerToRaw(der, size) {
  if (der.length < 8) return null;
  const view = new DataView(der.buffer, der.byteOffset, der.byteLength);
  if (view.getUint8(0) !== SEQUENCE_OCTET) return null;
  let at = 2;
  let content = view.getUint8(1);
  if (content === 129) {
    content = view.getUint8(2);
    at = 3;
    if (content < 128) return null;
  } else if (content > 127) {
    return null;
  }
  if (at + content !== der.length) return null;
  const r = readInteger2(der, view, at, size);
  if (r === null) return null;
  const s = readInteger2(der, view, r.next, size);
  if (s === null || s.next !== der.length) return null;
  const raw = new Uint8Array(size * 2);
  raw.set(r.value, size - r.value.length);
  raw.set(s.value, size * 2 - s.value.length);
  return raw;
}
function ecdsaRawToDer(raw, size) {
  if (raw.length !== size * 2) {
    throw new PkiError(
      "PKI_API_MISUSE",
      `pkinative: an ECDSA signature on this curve is ${String(size * 2)} bytes and this one is ${String(raw.length)} \u2014 the curve and the signing key disagree`
    );
  }
  const body = concat(derInteger(raw.subarray(0, size)), derInteger(raw.subarray(size)));
  const header = body.length < 128 ? [SEQUENCE_OCTET, body.length] : [SEQUENCE_OCTET, 129, body.length];
  return concat(Uint8Array.from(header), body);
}
function derInteger(value) {
  const view = byteView(value);
  let at = 0;
  while (at < value.length - 1 && view.getUint8(at) === 0) at++;
  const trimmed = value.subarray(at);
  const pad2 = (view.getUint8(at) & 128) !== 0 ? 1 : 0;
  const out = new Uint8Array(2 + pad2 + trimmed.length);
  out[0] = INTEGER_OCTET;
  out[1] = pad2 + trimmed.length;
  out.set(trimmed, 2 + pad2);
  return out;
}
function concat(...parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
function readInteger2(der, view, at, size) {
  if (at + 2 > der.length || view.getUint8(at) !== INTEGER_OCTET) return null;
  const length = view.getUint8(at + 1);
  if (length === 0 || length > 127) return null;
  const start = at + 2;
  const end = start + length;
  if (end > der.length) return null;
  const first = view.getUint8(start);
  if ((first & 128) !== 0) return null;
  const padded = first === 0 && length > 1;
  if (padded && (view.getUint8(start + 1) & 128) === 0) return null;
  const value = der.subarray(padded ? start + 1 : start, end);
  if (value.length > size) return null;
  return { value, next: end };
}

// src/crypto/webcrypto.ts
function publicKeySubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === void 0 || typeof subtle.importKey !== "function" || typeof subtle.verify !== "function") return null;
  return subtle;
}
function signingSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === void 0 || typeof subtle.sign !== "function") return null;
  return subtle;
}
function canVerify() {
  return publicKeySubtle() !== null;
}
function requireSubtle(oid) {
  const subtle = publicKeySubtle();
  if (subtle === null) {
    throw new PkiCryptoError(
      "PKI_CRYPTO_UNAVAILABLE",
      "pkinative: this runtime exposes no crypto.subtle with importKey and verify, so no signature can be checked \u2014 call canVerify() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)",
      oid
    );
  }
  return subtle;
}
async function importPublicKey(spkiDer, params, oid) {
  const subtle = requireSubtle(oid);
  try {
    return await subtle.importKey("spki", spkiDer, params, false, ["verify"]);
  } catch (cause) {
    throw new PkiCryptoError(
      "PKI_CRYPTO_KEY_UNSUPPORTED",
      `pkinative: this runtime refused to import the issuer's ${params.name} public key (${String(cause)}) \u2014 the algorithm may not be implemented here, or the key may be malformed; try another runtime before concluding the certificate is at fault`,
      oid
    );
  }
}
async function verifySignature(key, params, signature, data) {
  const subtle = requireSubtle(params.name);
  try {
    return await subtle.verify(params, key, signature, data);
  } catch {
    return false;
  }
}
function canSign() {
  return signingSubtle() !== null;
}
async function signData(key, params, data) {
  const subtle = signingSubtle();
  if (subtle === null) {
    throw new PkiCryptoError(
      "PKI_CRYPTO_UNAVAILABLE",
      "pkinative: this runtime exposes no crypto.subtle.sign, so nothing can be signed \u2014 call canSign() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)",
      params.name
    );
  }
  try {
    return new Uint8Array(await subtle.sign(params, key, data));
  } catch (cause) {
    throw new PkiCryptoError(
      "PKI_CRYPTO_KEY_UNSUPPORTED",
      `pkinative: this runtime refused to sign with the key given for ${params.name} (${String(cause)}) \u2014 check that the key is private, carries the "sign" usage, and matches the algorithm named`,
      params.name
    );
  }
}

// src/crypto/x509-verify.ts
async function verifyCertificateSignature(certificate, issuer, options) {
  const subject = assertCertificate(certificate, "certificate");
  const signer = assertCertificate(issuer, "issuer");
  return verifySignedStructure(subject, signer, resolveOptions(options));
}
function resolveOptions(options) {
  return { requireAlgorithmMatch: options?.requireAlgorithmMatch !== false, allowSha1: options?.allowSha1 === true };
}
async function verifySignedStructure(signed, signer, options) {
  const inner = signed.tbsSignatureAlgorithm;
  if (options.requireAlgorithmMatch && inner !== void 0 && !bytesEqual(signed.signatureAlgorithm.der, inner.der)) {
    return false;
  }
  if (signed.signatureValue.unusedBits !== 0) return false;
  const resolved = resolveAlgorithm(signed.signatureAlgorithm, signer.subjectPublicKeyInfo);
  if (resolved === null) return false;
  if (resolved.hash === "SHA-1" && !options.allowSha1) {
    throw new PkiCryptoError(
      "PKI_CRYPTO_ALGORITHM_REFUSED",
      "pkinative: this signature is over SHA-1, whose collisions have been practical since 2017, so verifying it would assert something it cannot show \u2014 get the certificate reissued under SHA-256, or pass { allowSha1: true } to examine a historical artefact rather than rely on it",
      signed.signatureAlgorithm.oid
    );
  }
  let signature = signed.signatureValue.bytes;
  if (resolved.curve !== void 0) {
    const raw = ecdsaDerToRaw(signature, coordinateBytes(resolved.curve));
    if (raw === null) return false;
    signature = raw;
  }
  const key = await importPublicKey(signer.subjectPublicKeyInfo.der, resolved.importParams, signed.signatureAlgorithm.oid);
  return verifySignature(key, resolved.verifyParams, signature, signed.tbsDer);
}
async function verifyCrlSignature(crl, issuer, options) {
  if (typeof crl !== "object" || crl === null || !(crl.tbsDer instanceof Uint8Array)) {
    throw new PkiError("PKI_INVALID_INPUT", "pkinative: crl must be a CertificateList from parseCertificateList(), not raw bytes");
  }
  const signer = assertCertificate(issuer, "issuer");
  return verifySignedStructure(crl, signer, resolveOptions(options));
}
async function verifyOcspSignature(basicResponse, responder) {
  if (typeof basicResponse !== "object" || basicResponse === null || !(basicResponse.tbsDer instanceof Uint8Array)) {
    throw new PkiError("PKI_INVALID_INPUT", "pkinative: basicResponse must come from parseOcspResponse(), not raw bytes \u2014 and a response whose status is not successful has none");
  }
  const signer = assertCertificate(responder, "responder");
  return verifySignedStructure(basicResponse, signer, { requireAlgorithmMatch: false, allowSha1: false });
}
async function verifySelfSignature(certificate, options) {
  const self = assertCertificate(certificate, "certificate");
  if (!bytesEqual(self.subject.der, self.issuer.der)) return false;
  return verifyCertificateSignature(self, self, options);
}
function assertCertificate(value, what) {
  const candidate = value;
  if (typeof value !== "object" || candidate === null || !(candidate.tbsDer instanceof Uint8Array) || typeof candidate.signatureAlgorithm !== "object" || candidate.signatureAlgorithm === null || typeof candidate.subjectPublicKeyInfo !== "object" || candidate.subjectPublicKeyInfo === null) {
    throw new PkiError("PKI_INVALID_INPUT", `pkinative: ${what} must be a certificate from parseCertificate \u2014 pass the parsed value, not its DER`);
  }
  return value;
}

// src/build/build-certificate.ts
function signatureAlgorithmDer(signer) {
  const resolved = resolveSigner(signer.algorithm);
  if (resolved.pss === void 0) return encodeAlgorithmIdentifier(resolved.oid);
  const hash = encodeAlgorithmIdentifier(resolved.pss.hashOid);
  return encodeAlgorithmIdentifier(resolved.oid, encodeSequence([
    encodeExplicit(0, hash),
    encodeExplicit(1, encodeAlgorithmIdentifier("1.2.840.113549.1.1.8", hash)),
    encodeExplicit(2, encodeInteger(resolved.pss.saltLength))
  ]));
}
function encodeSerial(serial) {
  if (typeof serial === "bigint") {
    if (serial < 0n) {
      throw new PkiError("PKI_API_MISUSE", "pkinative: a certificate serial number must be positive (RFC 5280 \xA74.1.2.2) \u2014 a negative serial is refused by most relying parties");
    }
    return encodeInteger(serial);
  }
  const bytes = assertBytes(serial, "serialNumber");
  const first = bytes[0];
  if (first === void 0) {
    throw new PkiError("PKI_API_MISUSE", "pkinative: a certificate serial number cannot be empty \u2014 an INTEGER has at least one content octet (X.690 \xA78.3.1); pass a bigint, or the octets of an existing serial");
  }
  const second = bytes[1];
  if (second !== void 0 && (first === 0 && second < 128 || first === 255 && second >= 128)) {
    throw new PkiError("PKI_API_MISUSE", `pkinative: the serial number's leading 0x${first.toString(16).padStart(2, "0")} octet is redundant, and DER requires the shortest form (X.690 \xA78.3.2) \u2014 drop it, or pass a bigint and let pkinative encode it`);
  }
  return encodeTlv("universal", 2, false, bytes);
}
async function signAndWrap(tbs, signer) {
  const resolved = resolveSigner(signer.algorithm);
  const raw = await signData(signer.key, resolved.signParams, tbs);
  const signature = resolved.curve === void 0 ? raw : ecdsaRawToDer(raw, coordinateBytes(resolved.curve));
  return encodeSequence([tbs, signatureAlgorithmDer(signer), encodeBitString(signature, 0)]);
}
async function createCertificate(description, signer, options) {
  const limits = options?.limits === void 0 ? void 0 : { limits: options.limits };
  const subject = description.subjectDer !== void 0 ? assertBytes(description.subjectDer, "subjectDer") : encodeDistinguishedName(description.subject, limits);
  const issuer = description.issuerDer !== void 0 ? assertBytes(description.issuerDer, "issuerDer") : description.issuer !== void 0 ? encodeDistinguishedName(description.issuer, limits) : subject;
  const extensions = description.extensions ?? [];
  const fields = [
    // v3 whenever there are extensions, v1 otherwise. RFC 5280 §4.1.2.1
    // makes the version DEFAULT v1, so a v1 certificate omits the field
    // entirely — writing [0] EXPLICIT INTEGER 0 is a DER violation.
    ...extensions.length > 0 ? [encodeExplicit(0, encodeInteger(2))] : [],
    encodeSerial(description.serialNumber),
    // tbsCertificate.signature is the field the signature covers; the
    // outer one is not. They must be equal, and they are, because both
    // come from the same call.
    signatureAlgorithmDer(signer),
    issuer,
    encodeValidity(description.notBefore, description.notAfter),
    subject,
    assertBytes(description.subjectPublicKey, "subjectPublicKey")
  ];
  if (extensions.length > 0) fields.push(encodeExplicit(3, encodeExtensions(extensions, limits)));
  return signAndWrap(encodeSequence(fields), signer);
}

// src/build/build-csr.ts
var EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
async function createCertificationRequest(description, signer, options) {
  const limits = options?.limits === void 0 ? void 0 : { limits: options.limits };
  const subject = description.subjectDer !== void 0 ? assertBytes(description.subjectDer, "subjectDer") : encodeDistinguishedName(description.subject, limits);
  const extensions = description.extensions ?? [];
  const attributes = extensions.length === 0 ? [] : [encodeAttribute(EXTENSION_REQUEST, [encodeExtensions(extensions, limits)])];
  const info = encodeSequence([
    // version is 0 for a PKCS#10 v1 request, and unlike the certificate's
    // it is not DEFAULT: it is written even when it is zero.
    encodeInteger(0),
    subject,
    assertBytes(description.subjectPublicKey, "subjectPublicKey"),
    // `attributes [0] IMPLICIT SET OF Attribute` — RFC 2986's module is
    // IMPLICIT TAGS, so [0] *replaces* the SET's tag rather than wrapping
    // it: the content is the sorted attribute encodings directly, and the
    // constructed bit comes from the SET the tag replaced. The field is
    // present even when empty, because an empty SET is not an absent one.
    encodeImplicit(0, encodeSetOf(attributes))
  ]);
  return signAndWrap(info, signer);
}

export { DEFAULT_PKI_LIMITS, KEY_USAGE_BITS, OCSP_NONCE_OID, OID_REGISTRY, PkiCertificateError, PkiCryptoError, PkiEncodingError, PkiError, PkiLimitError, buildCertificatePath, canSign, canVerify, checkOcspStatus, checkRevocation, checkServerName, computeFingerprint, computeFingerprintAsync, createCertificate, createCertificationRequest, createOcspRequest, decodeAsn1, decodeAsn1Sequence, decodeExtensionValue, decodeOid, decodePem, dnsMatches2 as dnsMatches, encodeAlgorithmIdentifier, encodeAsn1Node, encodeAttribute, encodeAuthorityKeyIdentifier, encodeBasicConstraints, encodeBitString, encodeBoolean, encodeCertId, encodeDistinguishedName, encodeEnumerated, encodeExplicit, encodeExtendedKeyUsage, encodeExtension, encodeExtensions, encodeImplicit, encodeInteger, encodeKeyUsage, encodeNameAttribute, encodeNamedBits, encodeNull, encodeObjectIdentifier, encodeOctetString, encodeOid, encodePem, encodeSequence, encodeSet, encodeSetOf, encodeString, encodeSubjectAltName, encodeSubjectKeyIdentifier, encodeSubjectPublicKeyInfo, encodeTime, encodeTlv, encodeValidity, findRevocation, formatDistinguishedName, formatFingerprint, getExtension, getOidName, isValidOid, parseCertificate, parseCertificateList, parseOcspResponse, readBitString, readBoolean, readInteger, readNull, readObjectIdentifier, readOctetString, readSmallInteger, readString, readTime, signatureAlgorithmDer, validateCertificatePath, verifyCertificateSignature, verifyCrlSignature, verifyOcspSignature, verifySelfSignature };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map