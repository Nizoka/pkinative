import { describe, it, expect } from 'vitest';
import { PkiCertificateError, PkiEncodingError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';

describe('PkiError', () => {
    it('should carry the code, the name and the message, and be an Error', () => {
        const err = new PkiError('PKI_INTERNAL', 'pkinative: broken invariant — report it');
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe('PkiError');
        expect(err.code).toBe('PKI_INTERNAL');
        expect(err.message).toBe('pkinative: broken invariant — report it');
    });
});

describe('PkiEncodingError', () => {
    it('should extend PkiError and carry the offset when known', () => {
        const err = new PkiEncodingError('PKI_ASN1_TRUNCATED', 'pkinative: truncated', 17);
        expect(err).toBeInstanceOf(PkiError);
        expect(err.name).toBe('PkiEncodingError');
        expect(err.code).toBe('PKI_ASN1_TRUNCATED');
        expect(err.offset).toBe(17);
    });

    it('should leave the offset undefined when it is not given', () => {
        expect(new PkiEncodingError('PKI_PEM_NO_BLOCK', 'pkinative: no block').offset).toBeUndefined();
    });
});

describe('PkiCertificateError', () => {
    it('should carry the structural path and the offset', () => {
        const err = new PkiCertificateError('PKI_X509_EXTENSION_DUPLICATE', 'pkinative: duplicate', 'tbsCertificate.extensions[2]', 412);
        expect(err).toBeInstanceOf(PkiError);
        expect(err.name).toBe('PkiCertificateError');
        expect(err.path).toBe('tbsCertificate.extensions[2]');
        expect(err.offset).toBe(412);
        expect(new PkiCertificateError('PKI_X509_STRUCTURE_INVALID', 'pkinative: x').path).toBeUndefined();
    });
});

describe('PkiLimitError', () => {
    it('should name the limit with its configured and observed values', () => {
        const err = new PkiLimitError('PKI_LIMIT_EXCEEDED', 'pkinative: too deep', 'maxDepth', 64, 65);
        expect(err).toBeInstanceOf(PkiError);
        expect(err.name).toBe('PkiLimitError');
        expect(err).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxDepth', configured: 64, observed: 65 });
    });
});
