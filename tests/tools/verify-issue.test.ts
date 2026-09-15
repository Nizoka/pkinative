import { describe, it, expect } from 'vitest';
import { validateIssueMarkdown } from '../../scripts/verify-issue.mjs';

// AI governance: the draft-issue verifier enforces the zero-dependency policy
// and a mandatory reproduction code block, and warns on missing fields.

const GOOD = `# Bug: a UTCTime with seconds 60 is accepted

## Environment
- pkinative 0.1.0, Node 22, Windows

## Expected behavior
PKI_ASN1_TIME_INVALID is thrown.

## Minimal reproduction
\`\`\`ts
console.log("repro");
\`\`\`
`;

describe('validateIssueMarkdown', () => {
    it('should pass a well-formed draft', () => {
        const r = validateIssueMarkdown(GOOD);
        expect(r.ok).toBe(true);
        expect(r.errors).toEqual([]);
    });

    it('should reject an npm install dependency request', () => {
        const r = validateIssueMarkdown('# X\nRun npm install node-forge\n```ts\nx\n```');
        expect(r.ok).toBe(false);
        expect(r.errors.some((e) => /dependency/i.test(e))).toBe(true);
    });

    it('should reject yarn/pnpm/bun add', () => {
        for (const cmd of ['yarn add foo', 'pnpm add foo', 'bun add foo']) {
            const r = validateIssueMarkdown(`# X\n${cmd}\n\`\`\`ts\nx\n\`\`\``);
            expect(r.ok, cmd).toBe(false);
        }
    });

    it('should reject a draft that adds a dependencies block', () => {
        const r = validateIssueMarkdown('# X\n```json\n"dependencies": { "asn1js": "^3.0.0" }\n```');
        expect(r.ok).toBe(false);
    });

    it('should reject a draft without a reproduction code block', () => {
        const r = validateIssueMarkdown('# X\n## Environment\nNode 22\n## Expected behavior\nok');
        expect(r.ok).toBe(false);
        expect(r.errors.some((e) => /reproduction code block/i.test(e))).toBe(true);
    });

    it('should not flag the mere word "dependencies" in prose', () => {
        const r = validateIssueMarkdown('# X\nThis is about the zero-dependencies policy.\n```ts\nx\n```');
        expect(r.ok).toBe(true);
    });

    it('should warn (not error) on missing recommended fields', () => {
        const r = validateIssueMarkdown('# X\n```ts\nx\n```');
        expect(r.ok).toBe(true);
        expect(r.warnings.length).toBeGreaterThan(0);
    });
});
