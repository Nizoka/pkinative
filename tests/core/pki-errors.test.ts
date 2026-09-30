import { describe, it, expect, vi } from 'vitest';
import { PkiCertificateError, PkiCmsError, PkiCryptoError, PkiEncodingError, PkiError, PkiKeyError, PkiLimitError } from '../../src/types/pki-errors.js';

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

describe('instanceof across copies of pkinative', () => {
    // A second, independent instance of the module: what an application gets
    // when one dependency imports the ES module build and another requires
    // the CommonJS one. Its classes are distinct objects from ours.
    const other = async (): Promise<typeof import('../../src/types/pki-errors.js')> => {
        vi.resetModules();
        return import('../../src/types/pki-errors.js');
    };

    it('should load a copy whose classes really are different', async () => {
        const copy = await other();
        expect(copy.PkiError).not.toBe(PkiError);
        expect(Function.prototype[Symbol.hasInstance].call(PkiError, new copy.PkiError('PKI_INTERNAL', 'pkinative: x'))).toBe(false);
    });

    it('should recognise an error of the other copy, in both directions, keeping subclass precision', async () => {
        const copy = await other();
        const foreign = new copy.PkiEncodingError('PKI_ASN1_TRUNCATED', 'pkinative: truncated', 3);
        expect(foreign instanceof PkiError).toBe(true);
        expect(foreign instanceof PkiEncodingError).toBe(true);
        expect(foreign instanceof PkiCertificateError).toBe(false);
        expect(foreign instanceof PkiLimitError).toBe(false);
        const ours = new PkiCertificateError('PKI_X509_NAME_INVALID', 'pkinative: name');
        expect(ours instanceof copy.PkiError).toBe(true);
        expect(ours instanceof copy.PkiCertificateError).toBe(true);
        expect(ours instanceof copy.PkiEncodingError).toBe(false);
        expect(new copy.PkiError('PKI_INTERNAL', 'pkinative: x') instanceof PkiEncodingError).toBe(false);
    });

    it.each([
        'PkiError', 'PkiEncodingError', 'PkiCertificateError', 'PkiLimitError', 'PkiCryptoError', 'PkiCmsError', 'PkiKeyError',
    ] as const)('should brand a %s with its family, under the shared Symbol.for key', async (family) => {
        const copy = await other();
        const Klass = copy[family] as unknown as new (...args: unknown[]) => Error;
        const error = new Klass('PKI_INTERNAL', 'pkinative: x', 'limit', 1, 2);
        expect((error as unknown as Record<symbol, unknown>)[Symbol.for('pkinative.PkiError')]).toBe(family);
        const Ours = { PkiError, PkiEncodingError, PkiCertificateError, PkiLimitError, PkiCryptoError, PkiCmsError, PkiKeyError }[family];
        expect(error instanceof Ours).toBe(true);
        expect(error instanceof PkiError).toBe(true);
        // Not enumerable, so JSON.stringify and spreading an error do not show it.
        expect(Object.getOwnPropertyDescriptor(error, Symbol.for('pkinative.PkiError'))?.enumerable).toBe(false);
    });

    it('should not let a brand turn a non-error, or a caller\'s subclass, into a match', async () => {
        const mark = Symbol.for('pkinative.PkiError');
        expect({ [mark]: 'PkiError' } instanceof PkiError).toBe(false);
        expect((null as unknown as object) instanceof PkiError).toBe(false);
        expect(('PkiError' as unknown as object) instanceof PkiError).toBe(false);
        const forged = Object.assign(new Error('x'), { [mark]: 42 });
        expect(forged instanceof PkiError).toBe(false);
        // A caller's own subclass keeps the ordinary prototype test: another
        // copy's PkiEncodingError is not an instance of it.
        class Wrapped extends PkiEncodingError {}
        const copy = await other();
        expect(new copy.PkiEncodingError('PKI_ASN1_TRUNCATED', 'pkinative: t') instanceof Wrapped).toBe(false);
        expect(new Wrapped('PKI_ASN1_TRUNCATED', 'pkinative: t') instanceof Wrapped).toBe(true);
    });

    it('should recognise an error thrown in another realm', async () => {
        const { runInNewContext } = await import('node:vm');
        // Symbol.for is shared by every realm of the agent; an Error made in
        // another realm fails the local `instanceof Error`, and still matches.
        const alien = runInNewContext(`Object.defineProperty(new Error('pkinative: x'), Symbol.for('pkinative.PkiError'), { value: 'PkiCmsError' })`) as unknown;
        expect(alien instanceof Error).toBe(false);
        expect(alien instanceof PkiError).toBe(true);
        expect(alien instanceof PkiCmsError).toBe(true);
        expect(alien instanceof PkiKeyError).toBe(false);
    });
});
