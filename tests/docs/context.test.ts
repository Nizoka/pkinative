import { describe, it, expect } from 'vitest';
import { escapeRegExp } from '../../scripts/verify-docs/context.js';

/**
 * pkinative — verify-docs context helpers
 * ============================================================
 * `escapeRegExp` replaced three hand-written escapes in the site rules: one
 * escaped the dot only, one replaced a character by itself. A rule that
 * builds a pattern from a version or a heading must match that text and
 * nothing else.
 */
describe('escapeRegExp', () => {
    it('should make a version with build metadata match itself only', () => {
        const pattern = new RegExp(`^v${escapeRegExp('1.1.0+build.7')}$`);
        expect(pattern.test('v1.1.0+build.7')).toBe(true);
        // Unescaped, `.` matches any character and `+` repeats the one before it.
        expect(pattern.test('v1x1x00build.7')).toBe(false);
        expect(pattern.test('v1.1.00build.7')).toBe(false);
    });

    it('should escape every metacharacter, the backslash and the bracket included', () => {
        const text = 'a.b*c+d?e^f$g{h}i(j)k|l[m]n\\o';
        expect(escapeRegExp(text)).toBe('a\\.b\\*c\\+d\\?e\\^f\\$g\\{h\\}i\\(j\\)k\\|l\\[m\\]n\\\\o');
        expect(new RegExp(`^${escapeRegExp(text)}$`).test(text)).toBe(true);
    });

    it('should leave a heading with a dash and spaces as it is', () => {
        expect(escapeRegExp('Human-in-the-loop — steps for the maintainer')).toBe('Human-in-the-loop — steps for the maintainer');
    });
});
