import { describe, it, expect } from 'vitest';
import { ISO_3166_1_ALPHA2, isCountryCode } from '../../src/x509/iso3166.js';

describe('ISO 3166-1 alpha-2', () => {
    it('should hold the 249 officially assigned codes, each two capital letters, sorted and unique', () => {
        const codes = [...ISO_3166_1_ALPHA2];
        expect(codes).toHaveLength(249);
        expect(codes.every((code) => /^[A-Z]{2}$/.test(code))).toBe(true);
        expect([...codes].sort()).toEqual(codes);
    });

    it.each(['AD', 'FR', 'GB', 'US', 'TW', 'EH', 'SS', 'ZW'])('should know %s', (code) => {
        expect(ISO_3166_1_ALPHA2.has(code)).toBe(true);
        expect(isCountryCode(code)).toBe(true);
    });

    it.each(['AA', 'QM', 'QZ', 'XA', 'XK', 'XZ', 'ZZ'])('should admit the user-assigned code %s (ISO 3166-1 §8.1.3) without listing it', (code) => {
        expect(ISO_3166_1_ALPHA2.has(code)).toBe(false);
        expect(isCountryCode(code)).toBe(true);
    });

    it.each([
        ['UK', 'exceptionally reserved: the assigned code is GB'],
        ['EU', 'exceptionally reserved'],
        ['AN', 'transitionally reserved: the Netherlands Antilles were dissolved'],
        ['CS', 'transitionally reserved'],
        ['QL', 'just below the user-assigned range QM–QZ'],
        ['ZY', 'just below ZZ'],
        ['AB', 'just above AA'],
        ['fr', 'lower case'],
        ['F', 'one letter'],
        ['FRA', 'alpha-3'],
        ['', 'empty'],
        ['Fr', 'mixed case'],
    ])('should refuse %s (%s)', (code) => {
        expect(isCountryCode(code)).toBe(false);
    });
});
