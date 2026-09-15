/**
 * pkinative — OID name registry
 * =============================
 * The object identifiers a PKI tool meets in certificates, CRLs, OCSP and CMS,
 * each with a display name and the standard that defines it. Pure data: only
 * `getOidName` and a direct `OID_REGISTRY` import pull it into a bundle, and
 * the certificate parser never imports this layer (AGENTS.md §Architecture).
 *
 * A name is the ASN.1 value identifier of the defining standard, with the
 * `id-` family prefix dropped where the rest stays unambiguous
 * (`id-ce-keyUsage` → `keyUsage`). Names and OIDs are both unique, which
 * tests/oid/oid-registry.test.ts holds.
 *
 * The registry is a frozen array, never an object keyed by OID: a lookup key
 * is caller input, and input never becomes an object key (CWE-1321).
 *
 * @module oid/oid-registry
 */

/** One registered object identifier. */
export interface OidRegistryEntry {
    /** Dotted-decimal form, e.g. `2.5.29.17`. */
    readonly oid: string;
    /** Display name, e.g. `subjectAltName`. */
    readonly name: string;
    /** The defining standard, e.g. `RFC 5280`. */
    readonly standard: string;
}

type OidGroup = readonly [standard: string, entries: ReadonlyArray<readonly [oid: string, name: string]>];

// ── Data ─────────────────────────────────────────────────────────────

const GROUPS: readonly OidGroup[] = [
    // ── Name attributes ──
    ['ITU-T X.520', [
        ['2.5.4.0', 'objectClass'],
        ['2.5.4.3', 'commonName'],
        ['2.5.4.4', 'surname'],
        ['2.5.4.5', 'serialNumber'],
        ['2.5.4.6', 'countryName'],
        ['2.5.4.7', 'localityName'],
        ['2.5.4.8', 'stateOrProvinceName'],
        ['2.5.4.9', 'streetAddress'],
        ['2.5.4.10', 'organizationName'],
        ['2.5.4.11', 'organizationalUnitName'],
        ['2.5.4.12', 'title'],
        ['2.5.4.13', 'description'],
        ['2.5.4.15', 'businessCategory'],
        ['2.5.4.16', 'postalAddress'],
        ['2.5.4.17', 'postalCode'],
        ['2.5.4.18', 'postOfficeBox'],
        ['2.5.4.19', 'physicalDeliveryOfficeName'],
        ['2.5.4.20', 'telephoneNumber'],
        ['2.5.4.36', 'userCertificate'],
        ['2.5.4.37', 'cACertificate'],
        ['2.5.4.38', 'authorityRevocationList'],
        ['2.5.4.39', 'certificateRevocationList'],
        ['2.5.4.40', 'crossCertificatePair'],
        ['2.5.4.41', 'name'],
        ['2.5.4.42', 'givenName'],
        ['2.5.4.43', 'initials'],
        ['2.5.4.44', 'generationQualifier'],
        ['2.5.4.45', 'x500UniqueIdentifier'],
        ['2.5.4.46', 'dnQualifier'],
        ['2.5.4.51', 'houseIdentifier'],
        ['2.5.4.53', 'deltaRevocationList'],
        ['2.5.4.65', 'pseudonym'],
        ['2.5.4.72', 'role'],
        ['2.5.4.97', 'organizationIdentifier'],
    ]],
    ['RFC 4519', [
        ['0.9.2342.19200300.100.1.1', 'uid'],
        ['0.9.2342.19200300.100.1.25', 'domainComponent'],
    ]],
    ['RFC 4524', [
        ['0.9.2342.19200300.100.1.3', 'mail'],
    ]],
    ['CA/Browser Forum EV Guidelines', [
        ['1.3.6.1.4.1.311.60.2.1.1', 'jurisdictionLocalityName'],
        ['1.3.6.1.4.1.311.60.2.1.2', 'jurisdictionStateOrProvinceName'],
        ['1.3.6.1.4.1.311.60.2.1.3', 'jurisdictionCountryName'],
    ]],
    ['RFC 2985', [
        ['1.2.840.113549.1.9.1', 'emailAddress'],
        ['1.2.840.113549.1.9.2', 'unstructuredName'],
        ['1.2.840.113549.1.9.3', 'contentType'],
        ['1.2.840.113549.1.9.4', 'messageDigest'],
        ['1.2.840.113549.1.9.5', 'signingTime'],
        ['1.2.840.113549.1.9.6', 'counterSignature'],
        ['1.2.840.113549.1.9.7', 'challengePassword'],
        ['1.2.840.113549.1.9.8', 'unstructuredAddress'],
        ['1.2.840.113549.1.9.14', 'extensionRequest'],
        ['1.2.840.113549.1.9.20', 'friendlyName'],
        ['1.2.840.113549.1.9.21', 'localKeyId'],
        ['1.2.840.113549.1.9.22.1', 'x509Certificate'],
        ['1.2.840.113549.1.9.22.2', 'sdsiCertificate'],
        ['1.2.840.113549.1.9.23.1', 'x509Crl'],
    ]],
    ['RFC 8551', [
        ['1.2.840.113549.1.9.15', 'smimeCapabilities'],
    ]],

    // ── Certificate and CRL extensions ──
    ['RFC 5280', [
        ['2.5.29.9', 'subjectDirectoryAttributes'],
        ['2.5.29.14', 'subjectKeyIdentifier'],
        ['2.5.29.15', 'keyUsage'],
        ['2.5.29.16', 'privateKeyUsagePeriod'],
        ['2.5.29.17', 'subjectAltName'],
        ['2.5.29.18', 'issuerAltName'],
        ['2.5.29.19', 'basicConstraints'],
        ['2.5.29.20', 'cRLNumber'],
        ['2.5.29.21', 'cRLReasons'],
        ['2.5.29.23', 'holdInstructionCode'],
        ['2.5.29.24', 'invalidityDate'],
        ['2.5.29.27', 'deltaCRLIndicator'],
        ['2.5.29.28', 'issuingDistributionPoint'],
        ['2.5.29.29', 'certificateIssuer'],
        ['2.5.29.30', 'nameConstraints'],
        ['2.5.29.31', 'cRLDistributionPoints'],
        ['2.5.29.32', 'certificatePolicies'],
        ['2.5.29.32.0', 'anyPolicy'],
        ['2.5.29.33', 'policyMappings'],
        ['2.5.29.35', 'authorityKeyIdentifier'],
        ['2.5.29.36', 'policyConstraints'],
        ['2.5.29.37', 'extKeyUsage'],
        ['2.5.29.37.0', 'anyExtendedKeyUsage'],
        ['2.5.29.46', 'freshestCRL'],
        ['2.5.29.54', 'inhibitAnyPolicy'],
        ['1.3.6.1.5.5.7.1.1', 'authorityInfoAccess'],
        ['1.3.6.1.5.5.7.1.11', 'subjectInfoAccess'],
        ['1.3.6.1.5.5.7.2.1', 'cps'],
        ['1.3.6.1.5.5.7.2.2', 'unotice'],
        ['1.3.6.1.5.5.7.3.1', 'serverAuth'],
        ['1.3.6.1.5.5.7.3.2', 'clientAuth'],
        ['1.3.6.1.5.5.7.3.3', 'codeSigning'],
        ['1.3.6.1.5.5.7.3.4', 'emailProtection'],
        ['1.3.6.1.5.5.7.3.8', 'timeStamping'],
        ['1.3.6.1.5.5.7.3.9', 'OCSPSigning'],
        ['1.3.6.1.5.5.7.48.1', 'ocsp'],
        ['1.3.6.1.5.5.7.48.2', 'caIssuers'],
        ['1.3.6.1.5.5.7.48.3', 'id-ad-timeStamping'],
        ['1.3.6.1.5.5.7.48.5', 'caRepository'],
        ['1.2.840.10040.2.1', 'holdInstructionNone'],
        ['1.2.840.10040.2.2', 'holdInstructionCallIssuer'],
        ['1.2.840.10040.2.3', 'holdInstructionReject'],
    ]],
    ['RFC 3739', [
        ['1.3.6.1.5.5.7.1.2', 'biometricInfo'],
        ['1.3.6.1.5.5.7.1.3', 'qcStatements'],
        ['1.3.6.1.5.5.7.11.2', 'qcsPkixQCSyntax-v2'],
        ['1.3.6.1.5.5.7.9.1', 'dateOfBirth'],
        ['1.3.6.1.5.5.7.9.2', 'placeOfBirth'],
        ['1.3.6.1.5.5.7.9.3', 'gender'],
        ['1.3.6.1.5.5.7.9.4', 'countryOfCitizenship'],
        ['1.3.6.1.5.5.7.9.5', 'countryOfResidence'],
    ]],
    ['RFC 3709', [['1.3.6.1.5.5.7.1.12', 'logotype']]],
    ['RFC 3779', [
        ['1.3.6.1.5.5.7.1.7', 'ipAddrBlocks'],
        ['1.3.6.1.5.5.7.1.8', 'autonomousSysIds'],
    ]],
    ['RFC 6487', [
        ['1.3.6.1.5.5.7.48.10', 'rpkiManifest'],
        ['1.3.6.1.5.5.7.48.11', 'signedObject'],
    ]],
    ['RFC 8182', [['1.3.6.1.5.5.7.48.13', 'rpkiNotify']]],
    ['RFC 7633', [['1.3.6.1.5.5.7.1.24', 'tlsFeature']]],
    ['RFC 9608', [['2.5.29.56', 'noRevAvail']]],
    ['RFC 6962', [
        ['1.3.6.1.4.1.11129.2.4.2', 'signedCertificateTimestampList'],
        ['1.3.6.1.4.1.11129.2.4.3', 'ctPrecertificatePoison'],
        ['1.3.6.1.4.1.11129.2.4.4', 'ctPrecertificateSigning'],
        ['1.3.6.1.4.1.11129.2.4.5', 'ocspSignedCertificateTimestampList'],
    ]],
    ['RFC 6960', [
        ['1.3.6.1.5.5.7.48.1.1', 'ocspBasic'],
        ['1.3.6.1.5.5.7.48.1.2', 'ocspNonce'],
        ['1.3.6.1.5.5.7.48.1.3', 'ocspCrlId'],
        ['1.3.6.1.5.5.7.48.1.4', 'ocspResponse'],
        ['1.3.6.1.5.5.7.48.1.5', 'ocspNoCheck'],
        ['1.3.6.1.5.5.7.48.1.6', 'ocspArchiveCutoff'],
        ['1.3.6.1.5.5.7.48.1.7', 'ocspServiceLocator'],
    ]],

    // ── Extended key usages and other names ──
    ['RFC 4334', [
        ['1.3.6.1.5.5.7.3.13', 'eapOverPPP'],
        ['1.3.6.1.5.5.7.3.14', 'eapOverLAN'],
    ]],
    ['RFC 4945', [['1.3.6.1.5.5.7.3.17', 'ipsecIKE']]],
    ['RFC 5924', [['1.3.6.1.5.5.7.3.20', 'sipDomain']]],
    ['RFC 6187', [
        ['1.3.6.1.5.5.7.3.21', 'secureShellClient'],
        ['1.3.6.1.5.5.7.3.22', 'secureShellServer'],
    ]],
    ['RFC 6402', [
        ['1.3.6.1.5.5.7.3.27', 'cmcCA'],
        ['1.3.6.1.5.5.7.3.28', 'cmcRA'],
        ['1.3.6.1.5.5.7.3.29', 'cmcArchive'],
    ]],
    ['RFC 8209', [['1.3.6.1.5.5.7.3.30', 'bgpsecRouter']]],
    ['RFC 9336', [['1.3.6.1.5.5.7.3.36', 'documentSigning']]],
    ['RFC 4043', [['1.3.6.1.5.5.7.8.3', 'permanentIdentifier']]],
    ['RFC 4108', [['1.3.6.1.5.5.7.8.4', 'hardwareModuleName']]],
    ['RFC 6120', [['1.3.6.1.5.5.7.8.5', 'xmppAddr']]],
    ['RFC 4985', [['1.3.6.1.5.5.7.8.7', 'srvName']]],
    ['RFC 9598', [['1.3.6.1.5.5.7.8.9', 'smtpUTF8Mailbox']]],
    ['RFC 4556', [
        ['1.3.6.1.5.2.2', 'pkinitSan'],
        ['1.3.6.1.5.2.3.4', 'pkinitKPClientAuth'],
        ['1.3.6.1.5.2.3.5', 'pkinitKPKdc'],
    ]],
    ['Microsoft', [
        ['1.3.6.1.4.1.311.10.3.4', 'msEncryptedFileSystem'],
        ['1.3.6.1.4.1.311.10.3.12', 'msDocumentSigning'],
        ['1.3.6.1.4.1.311.20.2', 'msCertificateTemplateName'],
        ['1.3.6.1.4.1.311.20.2.2', 'msSmartcardLogon'],
        ['1.3.6.1.4.1.311.20.2.3', 'msUserPrincipalName'],
        ['1.3.6.1.4.1.311.21.1', 'msCAVersion'],
        ['1.3.6.1.4.1.311.21.2', 'msPreviousCertHash'],
        ['1.3.6.1.4.1.311.21.7', 'msCertificateTemplate'],
        ['1.3.6.1.4.1.311.21.10', 'msApplicationCertPolicies'],
    ]],
    ['Netscape', [
        ['2.16.840.1.113730.1.1', 'netscapeCertType'],
        ['2.16.840.1.113730.1.13', 'netscapeComment'],
    ]],
    ['Adobe (ISO 32000)', [
        ['1.2.840.113583.1.1.8', 'adbeRevocationInfoArchival'],
        ['1.2.840.113583.1.1.9.1', 'adbeTimestamp'],
    ]],

    // ── Certificate policies and qualified certificates ──
    ['CA/Browser Forum Baseline Requirements', [
        ['2.23.140.1.1', 'extendedValidation'],
        ['2.23.140.1.2.1', 'domainValidated'],
        ['2.23.140.1.2.2', 'organizationValidated'],
        ['2.23.140.1.2.3', 'individualValidated'],
        ['2.23.140.1.3', 'extendedValidationCodeSigning'],
        ['2.23.140.1.4.1', 'codeSigningRequirements'],
    ]],
    ['ETSI EN 319 411-1', [
        ['0.4.0.2042.1.1', 'etsiNcp'],
        ['0.4.0.2042.1.2', 'etsiNcpPlus'],
        ['0.4.0.2042.1.3', 'etsiLcp'],
        ['0.4.0.2042.1.4', 'etsiEvcp'],
        ['0.4.0.2042.1.6', 'etsiDvcp'],
        ['0.4.0.2042.1.7', 'etsiOvcp'],
    ]],
    ['ETSI EN 319 411-2', [
        ['0.4.0.194112.1.0', 'etsiQcpNatural'],
        ['0.4.0.194112.1.1', 'etsiQcpLegal'],
        ['0.4.0.194112.1.2', 'etsiQcpNaturalQscd'],
        ['0.4.0.194112.1.3', 'etsiQcpLegalQscd'],
        ['0.4.0.194112.1.4', 'etsiQcpWeb'],
    ]],
    ['ETSI EN 319 412-1', [
        ['0.4.0.194121.1.1', 'etsiSemanticsIdNatural'],
        ['0.4.0.194121.1.2', 'etsiSemanticsIdLegal'],
    ]],
    ['ETSI EN 319 412-5', [
        ['0.4.0.1862.1.1', 'qcCompliance'],
        ['0.4.0.1862.1.2', 'qcLimitValue'],
        ['0.4.0.1862.1.3', 'qcRetentionPeriod'],
        ['0.4.0.1862.1.4', 'qcSSCD'],
        ['0.4.0.1862.1.5', 'qcPDS'],
        ['0.4.0.1862.1.6', 'qcType'],
        ['0.4.0.1862.1.6.1', 'qcTypeESign'],
        ['0.4.0.1862.1.6.2', 'qcTypeESeal'],
        ['0.4.0.1862.1.6.3', 'qcTypeWeb'],
        ['0.4.0.1862.1.7', 'qcCClegislation'],
    ]],
    ['ETSI TS 119 495', [['0.4.0.19495.2', 'qcsPsd2']]],

    // ── CMS, timestamps and signed attributes ──
    ['RFC 5652', [
        ['1.2.840.113549.1.7.1', 'data'],
        ['1.2.840.113549.1.7.2', 'signedData'],
        ['1.2.840.113549.1.7.3', 'envelopedData'],
        ['1.2.840.113549.1.7.5', 'digestedData'],
        ['1.2.840.113549.1.7.6', 'encryptedData'],
        ['1.2.840.113549.1.9.16.1.2', 'authData'],
    ]],
    ['RFC 3274', [['1.2.840.113549.1.9.16.1.9', 'compressedData']]],
    ['RFC 5083', [['1.2.840.113549.1.9.16.1.23', 'authEnvelopedData']]],
    ['RFC 3161', [
        ['1.2.840.113549.1.9.16.1.4', 'tstInfo'],
        ['1.2.840.113549.1.9.16.2.14', 'timeStampToken'],
    ]],
    ['RFC 6211', [['1.2.840.113549.1.9.52', 'cmsAlgorithmProtection']]],
    ['RFC 2634', [['1.2.840.113549.1.9.16.2.12', 'signingCertificate']]],
    ['RFC 5035', [['1.2.840.113549.1.9.16.2.47', 'signingCertificateV2']]],
    ['RFC 5126', [
        ['1.2.840.113549.1.9.16.2.15', 'sigPolicyId'],
        ['1.2.840.113549.1.9.16.2.16', 'commitmentType'],
        ['1.2.840.113549.1.9.16.2.17', 'signerLocation'],
        ['1.2.840.113549.1.9.16.2.18', 'signerAttr'],
        ['1.2.840.113549.1.9.16.2.19', 'otherSigCert'],
        ['1.2.840.113549.1.9.16.2.20', 'contentTimestamp'],
        ['1.2.840.113549.1.9.16.2.21', 'certificateRefs'],
        ['1.2.840.113549.1.9.16.2.22', 'revocationRefs'],
        ['1.2.840.113549.1.9.16.2.23', 'certValues'],
        ['1.2.840.113549.1.9.16.2.24', 'revocationValues'],
        ['1.2.840.113549.1.9.16.2.25', 'escTimeStamp'],
        ['1.2.840.113549.1.9.16.2.26', 'certCRLTimestamp'],
        ['1.2.840.113549.1.9.16.2.27', 'archiveTimeStamp'],
        ['1.2.840.113549.1.9.16.6.1', 'proofOfOrigin'],
        ['1.2.840.113549.1.9.16.6.2', 'proofOfReceipt'],
        ['1.2.840.113549.1.9.16.6.3', 'proofOfDelivery'],
        ['1.2.840.113549.1.9.16.6.4', 'proofOfSender'],
        ['1.2.840.113549.1.9.16.6.5', 'proofOfApproval'],
        ['1.2.840.113549.1.9.16.6.6', 'proofOfCreation'],
    ]],

    // ── PKCS #12 and password-based encryption ──
    ['RFC 7292', [
        ['1.2.840.113549.1.12.1.3', 'pbeWithSHAAnd3-KeyTripleDES-CBC'],
        ['1.2.840.113549.1.12.1.6', 'pbeWithSHAAnd40BitRC2-CBC'],
        ['1.2.840.113549.1.12.10.1.1', 'keyBag'],
        ['1.2.840.113549.1.12.10.1.2', 'pkcs8ShroudedKeyBag'],
        ['1.2.840.113549.1.12.10.1.3', 'certBag'],
        ['1.2.840.113549.1.12.10.1.4', 'crlBag'],
        ['1.2.840.113549.1.12.10.1.5', 'secretBag'],
        ['1.2.840.113549.1.12.10.1.6', 'safeContentsBag'],
    ]],
    ['RFC 8018', [
        ['1.2.840.113549.1.5.12', 'pbkdf2'],
        ['1.2.840.113549.1.5.13', 'pbes2'],
        ['1.2.840.113549.2.7', 'hmacWithSHA1'],
        ['1.2.840.113549.2.8', 'hmacWithSHA224'],
        ['1.2.840.113549.2.9', 'hmacWithSHA256'],
        ['1.2.840.113549.2.10', 'hmacWithSHA384'],
        ['1.2.840.113549.2.11', 'hmacWithSHA512'],
        ['1.2.840.113549.3.2', 'rc2CBC'],
        ['1.2.840.113549.3.7', 'des-EDE3-CBC'],
    ]],

    // ── Public-key and signature algorithms ──
    ['RFC 8017', [
        ['1.2.840.113549.1.1.1', 'rsaEncryption'],
        ['1.2.840.113549.1.1.2', 'md2WithRSAEncryption'],
        ['1.2.840.113549.1.1.3', 'md4WithRSAEncryption'],
        ['1.2.840.113549.1.1.4', 'md5WithRSAEncryption'],
        ['1.2.840.113549.1.1.5', 'sha1WithRSAEncryption'],
        ['1.2.840.113549.1.1.7', 'RSAES-OAEP'],
        ['1.2.840.113549.1.1.8', 'mgf1'],
        ['1.2.840.113549.1.1.9', 'pSpecified'],
        ['1.2.840.113549.1.1.10', 'RSASSA-PSS'],
        ['1.2.840.113549.1.1.11', 'sha256WithRSAEncryption'],
        ['1.2.840.113549.1.1.12', 'sha384WithRSAEncryption'],
        ['1.2.840.113549.1.1.13', 'sha512WithRSAEncryption'],
        ['1.2.840.113549.1.1.14', 'sha224WithRSAEncryption'],
        ['1.2.840.113549.1.1.15', 'sha512-224WithRSAEncryption'],
        ['1.2.840.113549.1.1.16', 'sha512-256WithRSAEncryption'],
    ]],
    ['OIW', [['1.3.14.3.2.29', 'sha1WithRSASignature']]],
    ['RFC 3279', [
        ['1.2.840.113549.2.2', 'md2'],
        ['1.2.840.113549.2.5', 'md5'],
        ['1.3.14.3.2.26', 'sha1'],
        ['1.2.840.10040.4.1', 'dsa'],
        ['1.2.840.10040.4.3', 'dsa-with-sha1'],
        ['1.2.840.10045.4.1', 'ecdsa-with-SHA1'],
        ['1.2.840.10046.2.1', 'dhpublicnumber'],
    ]],
    ['RFC 5758', [
        ['1.2.840.10045.4.3.1', 'ecdsa-with-SHA224'],
        ['1.2.840.10045.4.3.2', 'ecdsa-with-SHA256'],
        ['1.2.840.10045.4.3.3', 'ecdsa-with-SHA384'],
        ['1.2.840.10045.4.3.4', 'ecdsa-with-SHA512'],
        ['2.16.840.1.101.3.4.3.1', 'dsa-with-sha224'],
        ['2.16.840.1.101.3.4.3.2', 'dsa-with-sha256'],
    ]],
    ['RFC 5480', [
        ['1.2.840.10045.2.1', 'ecPublicKey'],
        ['1.3.132.1.12', 'ecDH'],
        ['1.3.132.1.13', 'ecMQV'],
        ['1.2.840.10045.3.1.1', 'secp192r1'],
        ['1.3.132.0.33', 'secp224r1'],
        ['1.2.840.10045.3.1.7', 'secp256r1'],
        ['1.3.132.0.34', 'secp384r1'],
        ['1.3.132.0.35', 'secp521r1'],
    ]],
    ['SEC 2', [['1.3.132.0.10', 'secp256k1']]],
    ['RFC 5639', [
        ['1.3.36.3.3.2.8.1.1.7', 'brainpoolP256r1'],
        ['1.3.36.3.3.2.8.1.1.11', 'brainpoolP384r1'],
        ['1.3.36.3.3.2.8.1.1.13', 'brainpoolP512r1'],
    ]],
    ['RFC 8410', [
        ['1.3.101.110', 'X25519'],
        ['1.3.101.111', 'X448'],
        ['1.3.101.112', 'Ed25519'],
        ['1.3.101.113', 'Ed448'],
    ]],
    ['NIST CSOR', [
        ['2.16.840.1.101.3.4.3.9', 'ecdsa-with-SHA3-224'],
        ['2.16.840.1.101.3.4.3.10', 'ecdsa-with-SHA3-256'],
        ['2.16.840.1.101.3.4.3.11', 'ecdsa-with-SHA3-384'],
        ['2.16.840.1.101.3.4.3.12', 'ecdsa-with-SHA3-512'],
        ['2.16.840.1.101.3.4.3.13', 'sha3-224WithRSAEncryption'],
        ['2.16.840.1.101.3.4.3.14', 'sha3-256WithRSAEncryption'],
        ['2.16.840.1.101.3.4.3.15', 'sha3-384WithRSAEncryption'],
        ['2.16.840.1.101.3.4.3.16', 'sha3-512WithRSAEncryption'],
    ]],
    ['FIPS 204', [
        ['2.16.840.1.101.3.4.3.17', 'ml-dsa-44'],
        ['2.16.840.1.101.3.4.3.18', 'ml-dsa-65'],
        ['2.16.840.1.101.3.4.3.19', 'ml-dsa-87'],
    ]],
    ['FIPS 205', [
        ['2.16.840.1.101.3.4.3.20', 'slh-dsa-sha2-128s'],
        ['2.16.840.1.101.3.4.3.21', 'slh-dsa-sha2-128f'],
        ['2.16.840.1.101.3.4.3.22', 'slh-dsa-sha2-192s'],
        ['2.16.840.1.101.3.4.3.23', 'slh-dsa-sha2-192f'],
        ['2.16.840.1.101.3.4.3.24', 'slh-dsa-sha2-256s'],
        ['2.16.840.1.101.3.4.3.25', 'slh-dsa-sha2-256f'],
        ['2.16.840.1.101.3.4.3.26', 'slh-dsa-shake-128s'],
        ['2.16.840.1.101.3.4.3.27', 'slh-dsa-shake-128f'],
        ['2.16.840.1.101.3.4.3.28', 'slh-dsa-shake-192s'],
        ['2.16.840.1.101.3.4.3.29', 'slh-dsa-shake-192f'],
        ['2.16.840.1.101.3.4.3.30', 'slh-dsa-shake-256s'],
        ['2.16.840.1.101.3.4.3.31', 'slh-dsa-shake-256f'],
    ]],
    ['FIPS 203', [
        ['2.16.840.1.101.3.4.4.1', 'ml-kem-512'],
        ['2.16.840.1.101.3.4.4.2', 'ml-kem-768'],
        ['2.16.840.1.101.3.4.4.3', 'ml-kem-1024'],
    ]],

    // ── Digests and symmetric algorithms ──
    ['FIPS 180-4', [
        ['2.16.840.1.101.3.4.2.1', 'sha256'],
        ['2.16.840.1.101.3.4.2.2', 'sha384'],
        ['2.16.840.1.101.3.4.2.3', 'sha512'],
        ['2.16.840.1.101.3.4.2.4', 'sha224'],
        ['2.16.840.1.101.3.4.2.5', 'sha512-224'],
        ['2.16.840.1.101.3.4.2.6', 'sha512-256'],
    ]],
    ['FIPS 202', [
        ['2.16.840.1.101.3.4.2.7', 'sha3-224'],
        ['2.16.840.1.101.3.4.2.8', 'sha3-256'],
        ['2.16.840.1.101.3.4.2.9', 'sha3-384'],
        ['2.16.840.1.101.3.4.2.10', 'sha3-512'],
        ['2.16.840.1.101.3.4.2.11', 'shake128'],
        ['2.16.840.1.101.3.4.2.12', 'shake256'],
        ['2.16.840.1.101.3.4.2.13', 'hmacWithSHA3-224'],
        ['2.16.840.1.101.3.4.2.14', 'hmacWithSHA3-256'],
        ['2.16.840.1.101.3.4.2.15', 'hmacWithSHA3-384'],
        ['2.16.840.1.101.3.4.2.16', 'hmacWithSHA3-512'],
    ]],
    ['RFC 3565', [
        ['2.16.840.1.101.3.4.1.2', 'aes128-CBC'],
        ['2.16.840.1.101.3.4.1.22', 'aes192-CBC'],
        ['2.16.840.1.101.3.4.1.42', 'aes256-CBC'],
    ]],
    ['RFC 3394', [
        ['2.16.840.1.101.3.4.1.5', 'aes128-wrap'],
        ['2.16.840.1.101.3.4.1.25', 'aes192-wrap'],
        ['2.16.840.1.101.3.4.1.45', 'aes256-wrap'],
    ]],
    ['RFC 5649', [
        ['2.16.840.1.101.3.4.1.8', 'aes128-wrap-pad'],
        ['2.16.840.1.101.3.4.1.28', 'aes192-wrap-pad'],
        ['2.16.840.1.101.3.4.1.48', 'aes256-wrap-pad'],
    ]],
    ['RFC 5084', [
        ['2.16.840.1.101.3.4.1.6', 'aes128-GCM'],
        ['2.16.840.1.101.3.4.1.26', 'aes192-GCM'],
        ['2.16.840.1.101.3.4.1.46', 'aes256-GCM'],
    ]],
    ['RFC 8103', [['1.2.840.113549.1.9.16.3.18', 'aeadChaCha20Poly1305']]],
];

// ── Registry ─────────────────────────────────────────────────────────

function buildRegistry(groups: readonly OidGroup[]): readonly OidRegistryEntry[] {
    const entries: OidRegistryEntry[] = [];
    for (const [standard, pairs] of groups) {
        for (const [oid, name] of pairs) entries.push(Object.freeze({ oid, name, standard }));
    }
    return Object.freeze(entries);
}

/**
 * Every registered object identifier, grouped by area and frozen. Use
 * `getOidName` for a lookup; iterate this array to list or search the names.
 */
export const OID_REGISTRY: readonly OidRegistryEntry[] = /*#__PURE__*/ buildRegistry(GROUPS);
