import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Artefact } from '../../scripts/lib/interop-artefacts.ts';
import { toWslPath } from '../../scripts/lib/interop-host.ts';
import { canonical, compareFacts, glob, judge, type LintWaiver } from '../../scripts/lib/interop-judge.ts';
import { pemBlocks } from '../../scripts/lib/interop-reads.ts';
import {
    certtoolSanDns,
    gpgsmVerified,
    intHex,
    normaliseSeverity,
    opensslReference,
    parseOcspReqText,
    parseRfc4514,
    parseTsQueryText,
    writeTools,
    zlintFindings,
    zlintSources,
    type CheckResult,
} from '../../scripts/lib/interop-tools.ts';
import {
    IMPLEMENTED_TOOLS,
    KEY_CONTAINER_CASES,
    PENDING_TOOLS,
    READ_CASES,
    REQUIRED_TOOLS,
    TOOL_LIMITATIONS,
    TOOL_PLATFORMS,
    type ToolLimitation,
} from '../../scripts/lib/interop.ts';

// The interoperability matrix decides in scripts/lib/interop-judge.ts and
// reads foreign output in scripts/lib/interop-tools.ts. Both run only where
// the tools are installed, so every rule of the decision and every parser is
// proved here, on recorded output, in the fast gate: a matrix whose refusal
// rule never fired, or whose parser silently read nothing, would report
// agreement it never established.

const artefact = (over: Partial<Artefact> = {}): Artefact => ({
    id: 'p256/leaf-br', profile: 'p256', kind: 'cert', der: 'x.der', pem: 'x.pem', shape: 'br', issuer: 'p256/ca',
    expect: { serial: '1a2b', commonName: 'www.example.com', dnsNames: 'www.example.com' }, ...over,
});
const ok = (over: Partial<CheckResult> = {}): CheckResult => ({ artefact: 'p256/leaf-br', check: 'cert.read', ok: true, facts: { serial: '1a2b' }, ...over });
const SET = [artefact()];

describe('the decision (interop-judge)', () => {
    it('should agree when every fact matches, counting the fields it compared', () => {
        const verdict = judge('tool', [ok({ facts: { serial: '1A2B', commonName: 'www.example.com' } })], SET, true, [], []);
        expect(verdict.failures).toEqual([]);
        expect(verdict.compared).toBe(2);
    });

    it('should compare integers by value, not by spelling', () => {
        expect(canonical('serial', '00ff', 'cert')).toBe('ff');
        expect(canonical('nonce', '00ff', 'tsq')).toBe('ff');
        // An OCSP nonce is octets: a leading zero is part of it.
        expect(canonical('nonce', '00ff', 'ocsp-request')).toBe('00ff');
        expect(compareFacts({ serial: '0a' }, { serial: 'A' }, 'cert').differences).toEqual([]);
    });

    it('should fail on a fact that disagrees', () => {
        const verdict = judge('tool', [ok({ facts: { commonName: 'other' } })], SET, true, [], []);
        expect(verdict.failures.join('\n')).toContain('commonName "other", pkinative wrote "www.example.com"');
    });

    it('should fail on a refusal of pkinative\'s bytes by a reference build', () => {
        const verdict = judge('tool', [ok({ ok: false, error: 'bad' })], SET, true, [], []);
        expect(verdict.failures.join('\n')).toContain('REFUSED cert.read@p256/leaf-br');
    });

    it('should report a refusal by a non-reference build as not applicable, and still need agreement elsewhere', () => {
        const verdict = judge('tool', [ok({ ok: false, error: 'bad' }), ok()], SET, false, [], []);
        expect(verdict.failures).toEqual([]);
        expect(verdict.notApplicable.join('\n')).toContain('not the reference build');
    });

    it('should never blame the artefact for an answer the runner could not read', () => {
        const verdict = judge('tool', [ok({ ok: false, unreadable: true, error: 'garbled' }), ok()], SET, true, [], []);
        expect(verdict.failures.join('\n')).toContain('a defect in this runner, not in the artefact');
    });

    it('should fail as vacuous when nothing was agreed', () => {
        expect(judge('tool', [], SET, true, [], []).failures.join('\n')).toContain('agreed on nothing');
    });

    const always: ToolLimitation = { tool: 'tool', match: ['chain.verify@p256/*'], when: 'always', reason: 'r', proof: 'p' };
    const declared: ToolLimitation = { tool: 'tool', match: ['*@p256/*'], when: 'self-declared', reason: 'r', proof: 'p' };

    it('should accept a reviewed limitation as not applicable', () => {
        const verdict = judge('tool', [ok({ check: 'chain.verify', ok: false, error: 'no' }), ok()], SET, true, [always], []);
        expect(verdict.failures).toEqual([]);
        expect(verdict.notApplicable.join('\n')).toContain('a reviewed limitation of tool');
    });

    it('should fail a limitation whose check now passes, as stale', () => {
        const verdict = judge('tool', [ok({ check: 'chain.verify', facts: undefined })], SET, true, [always], []);
        expect(verdict.failures.join('\n')).toContain('the limitation is stale');
    });

    it('should fail a limitation that matches nothing, as stale or misspelt', () => {
        const verdict = judge('tool', [ok()], SET, true, [always], []);
        expect(verdict.failures.join('\n')).toContain('matched no check of this run');
    });

    it('should honour a self-declared limitation only when the tool declares it', () => {
        const declaredIt = judge('tool', [ok({ ok: false, error: 'x', unsupported: 'no EdDSA' }), ok()], SET, true, [declared], []);
        expect(declaredIt.failures).toEqual([]);
        const didNot = judge('tool', [ok({ ok: false, error: 'x' }), ok()], SET, true, [declared], []);
        expect(didNot.failures.join('\n')).toContain('REFUSED');
    });

    it('should refuse an unsupported answer no limitation reviews', () => {
        const verdict = judge('tool', [ok({ ok: false, unsupported: 'cannot' }), ok()], SET, true, [], []);
        expect(verdict.failures.join('\n')).toContain('TOOL_LIMITATIONS reviews no such limitation');
    });

    const lint = (severity: 'error' | 'warning' | 'info', name = 'w_some_lint'): CheckResult => ({ artefact: 'p256/leaf-br', check: 'lint.cert', ok: true, findings: [{ lint: name, severity }] });
    const waiver: LintWaiver = { tool: 'tool', lint: 'w_some_lint', artefacts: ['*/leaf-br'], reason: 'r' };

    it('should never waive a lint error', () => {
        const verdict = judge('tool', [lint('error')], SET, true, [], [{ ...waiver }]);
        expect(verdict.failures.join('\n')).toContain('a lint error is never waived');
    });

    it('should accept a lint error only as a proved limitation of the linter', () => {
        const limitation: ToolLimitation = { tool: 'tool', match: ['lint:w_some_lint@*/leaf-br'], when: 'always', reason: 'r', proof: 'p' };
        expect(judge('tool', [lint('error')], SET, true, [limitation], []).failures).toEqual([]);
    });

    it('should require a review for every lint warning, and accept a reviewed one', () => {
        expect(judge('tool', [lint('warning')], SET, true, [], []).failures.join('\n')).toContain('does not review it');
        expect(judge('tool', [lint('warning')], SET, true, [], [waiver]).failures).toEqual([]);
    });

    it('should fail a waiver that matched nothing, as stale', () => {
        expect(judge('tool', [lint('info')], SET, true, [], [waiver]).failures.join('\n')).toContain('it is stale; delete it');
    });

    it('should match patterns with * and nothing else', () => {
        expect(glob('pss-*/leaf-*', 'pss-sha256/leaf-br')).toBe(true);
        expect(glob('pss-*/leaf-*', 'rsa/leaf-br')).toBe(false);
        expect(glob('a.b@c', 'aXb@c')).toBe(false);
    });
});

describe('the readers of foreign output (interop-tools)', () => {
    it('should read RFC 4514 names value by value, unescaped', () => {
        const names = parseRfc4514('CN=www.example.com,OU=Ing\\C3\\A9nierie+L=Paris,O=Soci\\,t\\C3\\A9,C=FR,2.5.4.97=#0c0141');
        expect(names.get('CN')).toBe('www.example.com');
        expect(names.get('OU')).toBe('Ingénierie');
        expect(names.get('L')).toBe('Paris');
        expect(names.get('O')).toBe('Soci,té');
        expect(names.has('2.5.4.97')).toBe(false);
    });

    it('should spell an integer one way', () => {
        expect(intHex('00:0A:FF')).toBe('aff');
        expect(intHex('')).toBe('0');
    });

    it('should read openssl ts -query -text', () => {
        const text = 'Version: 1\nHash Algorithm: sha256\nMessage data:\n    0000 - 0b 87 33 b1 61 99 71 8f-ad a0 9d ae f9 1f 5c 4c   ..3.a.q.......\\L\n    0010 - 2b 58   +X\nPolicy OID: unspecified\nNonce: 0x00C0E8\nCertificate required: yes\nExtensions:\n';
        expect(parseTsQueryText(text)).toEqual({ hashOid: '2.16.840.1.101.3.4.2.1', imprint: '0b8733b16199718fada09daef91f5c4c2b58', policy: '', nonce: 'c0e8', certReq: 'true' });
        expect(parseTsQueryText('nothing')).toBeUndefined();
    });

    it('should read openssl ocsp -req_text, the nonce without its inner OCTET STRING header', () => {
        const text = 'OCSP Request Data:\n    Requestor List:\n        Certificate ID:\n          Hash Algorithm: sha1\n          Issuer Name Hash: 22CE01\n          Issuer Key Hash: 97F908\n          Serial Number: 3E33\n    Request Extensions:\n        OCSP Nonce: \n            0402B2C3\n';
        expect(parseOcspReqText(text)).toEqual({ issuerNameHash: '22ce01', issuerKeyHash: '97f908', serial: '3e33', nonce: 'b2c3' });
    });

    it('should take DNS names from certtool\'s subjectAltName block only, never from name constraints', () => {
        const text = '\tExtensions:\n\t\tName Constraints (critical):\n\t\t\tPermitted:\n\t\t\t\tDNSname: example.com\n\t\tSubject Alternative Name (not critical):\n\t\t\tDNSname: www.example.com\n\t\t\tIPAddress: 192.0.2.10\n\t\t\tDNSname: example.com\n\t\tKey Purpose (not critical):\n\t\t\tDNSname: not.a.san\n';
        expect(certtoolSanDns(text)).toBe('example.com,www.example.com');
        expect(certtoolSanDns('\t\tName Constraints:\n\t\t\tDNSname: example.com\n')).toBe('');
    });

    it('should hold only OpenSSL 3 and later to agreement on refusals', () => {
        expect(opensslReference('OpenSSL 3.5.5 27 Jan 2026')).toBe(true);
        expect(opensslReference('OpenSSL 1.1.1w  11 Sep 2023')).toBe(false);
        expect(opensslReference('LibreSSL 3.3.6')).toBe(false);
    });

    it('should call a gpgsm verification good only with a trusted chain', () => {
        expect(gpgsmVerified('[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG\n[GNUPG:] VALIDSIG ABC\n[GNUPG:] TRUST_FULLY 0 shell\n')).toBe(true);
        expect(gpgsmVerified('[GNUPG:] GOODSIG\n[GNUPG:] VALIDSIG ABC\n[GNUPG:] TRUST_UNDEFINED\n')).toBe(false);
    });

    it('should lint the Web PKI shape with the Web PKI sources and everything else with the RFC sources', () => {
        expect(zlintSources(artefact({ shape: 'br', webpki: true }))).toContain('-excludeSources');
        expect(zlintSources(artefact({ shape: 'rich', webpki: true }))).toContain('-includeSources');
        expect(zlintSources(artefact({ shape: 'ca', webpki: false }))).toContain('-includeSources');
    });

    it('should turn a zlint result into findings, dropping pass, NA and NE', () => {
        const line = JSON.stringify({ e_a: { result: 'error' }, w_b: { result: 'warn' }, n_c: { result: 'info' }, e_d: { result: 'pass' }, e_e: { result: 'NA' }, e_f: { result: 'NE' }, e_g: { result: 'fatal' } });
        expect(zlintFindings(line)).toEqual([
            { lint: 'e_a', severity: 'error' }, { lint: 'w_b', severity: 'warning' }, { lint: 'n_c', severity: 'info' }, { lint: 'e_g', severity: 'error' },
        ]);
        expect(normaliseSeverity('NOTICE')).toBe('warning');
    });

    it('should unwrap PEM without pkinative', () => {
        const der = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x05);
        const pem = `junk\n-----BEGIN X509 CRL-----\n${Buffer.from(der).toString('base64')}\n-----END X509 CRL-----\n`;
        expect(pemBlocks(pem, 'X509 CRL')).toEqual([der]);
    });

    it('should translate a host path for WSL', () => {
        expect(toWslPath('C:\\Users\\x\\a b.der')).toBe('/mnt/c/Users/x/a b.der');
        expect(toWslPath('/already/posix')).toBe('/already/posix');
    });
});

describe('the declarations (scripts/lib/interop.ts)', () => {
    const tools = writeTools().map((t) => t.id);

    it('should run every implemented tool, and nothing undeclared', () => {
        expect([...tools].sort()).toEqual([...IMPLEMENTED_TOOLS].sort());
    });

    it('should say where every implemented tool has been proved, and require nothing it was not proved on', () => {
        for (const id of IMPLEMENTED_TOOLS) expect(TOOL_PLATFORMS[id], id).toBeDefined();
        for (const [platform, required] of Object.entries(REQUIRED_TOOLS)) {
            for (const id of required) expect(TOOL_PLATFORMS[id], `${id} is required on ${platform}`).toContain(platform);
        }
    });

    it('should hold every limitation to an implemented tool, with a reason and a proof', () => {
        for (const l of TOOL_LIMITATIONS) {
            expect(IMPLEMENTED_TOOLS, l.tool).toContain(l.tool);
            expect(l.reason.length, l.tool).toBeGreaterThan(60);
            expect(l.proof.length, l.tool).toBeGreaterThan(30);
        }
    });

    it('should declare every case once, under an implemented tool', () => {
        for (const list of [KEY_CONTAINER_CASES, READ_CASES]) {
            expect(new Set(list.map((c) => c.id)).size).toBe(list.length);
            for (const c of list) {
                expect(IMPLEMENTED_TOOLS).toContain(c.tool);
                expect(c.id.startsWith(`${c.tool}:`)).toBe(true);
            }
        }
        expect(PENDING_TOOLS.filter((p) => IMPLEMENTED_TOOLS.includes(p.id))).toEqual([]);
    });

    it('should review every lint warning waiver with a reason', () => {
        const file = JSON.parse(readFileSync(join(process.cwd(), 'scripts', 'data', 'lint-waivers.json'), 'utf8')) as { waivers: LintWaiver[] };
        for (const w of file.waivers) {
            expect(['zlint', 'pkilint']).toContain(w.tool);
            expect(w.reason.length, w.lint).toBeGreaterThan(60);
        }
    });
});
