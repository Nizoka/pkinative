import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    decideNpmDrift, decideReleaseAssets, decideSatelliteDrift, parseNpmView, parseRelease, PLACEHOLDER, releaseAssetNames, releaseTarballUrl,
    RELEASE_ASSET_SUFFIXES, REPOSITORY, type RegistryState, type ReleaseState,
} from '../../scripts/check-npm-drift.js';

// scripts/check-npm-drift.ts reads the registry online; its decision is
// pinned here offline, against registry answers written by hand.

const registry = (latest: string, ...versions: string[]): RegistryState => ({ found: true, distTags: { latest }, versions: versions.length > 0 ? versions : [latest] });

describe('decideNpmDrift', () => {
    it('should pass pre-1.0 when the registry holds the placeholder and nothing else', () => {
        expect(decideNpmDrift('0.8.0', registry(PLACEHOLDER))).toEqual([]);
    });

    it('should fail pre-1.0 on any real 0.x version, even one published under another dist-tag', () => {
        expect(decideNpmDrift('0.8.0', registry('0.8.0', PLACEHOLDER, '0.8.0'))).toEqual([
            expect.stringContaining('pre-1.0 version(s) 0.8.0 reached npm'),
            expect.stringContaining('latest must be the 0.0.1 placeholder'),
        ]);
        const tagged: RegistryState = { found: true, distTags: { latest: PLACEHOLDER, next: '0.9.0' }, versions: [PLACEHOLDER, '0.9.0'] };
        expect(decideNpmDrift('0.9.0', tagged)).toEqual([expect.stringContaining('refusal did not hold')]);
    });

    it('should fail when the name is not reserved at all', () => {
        expect(decideNpmDrift('0.8.0', { found: false })).toEqual([expect.stringContaining('the name is unreserved')]);
    });

    it('should require latest to be the manifest version from 1.0.0, the placeholder staying behind', () => {
        expect(decideNpmDrift('1.0.0', registry('1.0.0', PLACEHOLDER, '1.0.0'))).toEqual([]);
        expect(decideNpmDrift('1.1.0', registry('1.0.0', PLACEHOLDER, '1.0.0'))).toEqual([expect.stringContaining('1.1.0 is not published yet')]);
        expect(decideNpmDrift('1.0.0', registry('1.1.0', PLACEHOLDER, '1.0.0', '1.1.0'))).toEqual([expect.stringContaining('ahead of the manifest')]);
        expect(decideNpmDrift('1.0.0', registry(PLACEHOLDER))).toEqual([expect.stringContaining('1.0.0 is not published yet')]);
    });

    it('should fail on a dist-tag that points at a version the registry does not list', () => {
        expect(decideNpmDrift('0.8.0', { found: true, distTags: { latest: '0.0.2' }, versions: [PLACEHOLDER] })).toEqual([
            expect.stringContaining('dist-tag latest points at 0.0.2'),
            expect.stringContaining('latest must be the 0.0.1 placeholder'),
        ]);
    });
});

describe('parseNpmView', () => {
    it('should read the answer for one version and for several', () => {
        expect(parseNpmView('{"dist-tags":{"latest":"0.0.1"},"versions":"0.0.1"}', '', 0)).toEqual({ found: true, distTags: { latest: '0.0.1' }, versions: ['0.0.1'] });
        expect(parseNpmView('{"dist-tags":{"latest":"1.0.0"},"versions":["0.0.1","1.0.0"]}', '', 0)).toEqual({ found: true, distTags: { latest: '1.0.0' }, versions: ['0.0.1', '1.0.0'] });
    });

    it('should read a 404 as an absent package, and anything else as an error rather than a verdict', () => {
        expect(parseNpmView('{"error":{"code":"E404"}}', 'npm error code E404', 1)).toEqual({ found: false });
        expect(() => parseNpmView('', 'npm error code ETIMEDOUT', 1)).toThrow(/exited 1/);
        expect(() => parseNpmView('{}', '', 0)).toThrow(/no dist-tags/);
    });
});

describe('decideSatelliteDrift', () => {
    it('should agree when latest is the version the manifest records', () => {
        expect(decideSatelliteDrift('pkinative-cli', '1.0.0', registry('1.0.0'))).toEqual([]);
    });

    it('should report a satellite release the manifest does not record yet, and one it records too early', () => {
        expect(decideSatelliteDrift('pkinative-mcp', '1.0.0', registry('1.1.0', '1.0.0', '1.1.0'))).toEqual([expect.stringContaining('ahead of the manifest')]);
        // The message is the next command to run, with the version the registry serves.
        expect(decideSatelliteDrift('pkinative-mcp', '1.0.0', registry('1.1.0', '1.0.0', '1.1.0'))[0]).toContain('npm run satellites:sync -- --expect mcp=1.1.0 --capture --apply --worklist');
        expect(decideSatelliteDrift('pkinative-mcp', '1.1.0', registry('1.0.0'))).toEqual([expect.stringContaining('which is not published')]);
    });

    it('should report a satellite absent from the registry', () => {
        expect(decideSatelliteDrift('pkinative-cli', '1.0.0', { found: false })).toEqual([expect.stringContaining('not on the registry')]);
    });
});

describe('decideReleaseAssets', () => {
    const names = releaseAssetNames('1.1.0');
    const release = (over: Partial<Extract<ReleaseState, { found: true }>> = {}): ReleaseState => ({ found: true, draft: false, assets: names, tarballStatus: 200, ...over });

    it('should name the five files publish.yml attests and attaches, and the URL the README gives', () => {
        expect(names).toEqual(['pkinative-1.1.0.tgz', 'pkinative-1.1.0.cdx.json', 'pkinative-1.1.0.spdx.json', 'pkinative-1.1.0.toolchain.cdx.json', 'pkinative-1.1.0.sigstore.json']);
        // One list, two readers: the upload step of the attest job names the same five files.
        const publish = readFileSync(join(import.meta.dirname, '..', '..', '.github', 'workflows', 'publish.yml'), 'utf8');
        const upload = /gh release upload "v\$\{VERSION\}" \\\n((?:\s+"pkinative-\$\{VERSION\}[^"]*" \\\n)+)/.exec(publish.replace(/\r\n/g, '\n'))?.[1] ?? '';
        expect([...upload.matchAll(/"pkinative-\$\{VERSION\}([^"]*)"/g)].map((m) => m[1])).toEqual([...RELEASE_ASSET_SUFFIXES]);
        expect(releaseTarballUrl('1.1.0')).toBe(`https://github.com/${REPOSITORY}/releases/download/v1.1.0/pkinative-1.1.0.tgz`);
        expect(readFileSync(join(import.meta.dirname, '..', '..', 'README.md'), 'utf8')).toContain(`https://github.com/${REPOSITORY}/releases/download/v`);
    });

    it('should pass a published release that carries its files and serves the tarball', () => {
        expect(decideReleaseAssets('1.1.0', release())).toEqual([]);
        // A file the maintainer added by hand is not a problem; a missing one is.
        expect(decideReleaseAssets('1.1.0', release({ assets: [...names, 'notes.pdf'] }))).toEqual([]);
    });

    it('should report the release of 1.0.0 as it was: published, green, and empty', () => {
        // The case this check exists for (issue 14): the registry agreed and the release carried nothing.
        const problems = decideReleaseAssets('1.0.0', { found: true, draft: false, assets: [], tarballStatus: 404 });
        expect(problems).toEqual([
            expect.stringContaining('does not carry pkinative-1.0.0.tgz, pkinative-1.0.0.cdx.json, pkinative-1.0.0.spdx.json, pkinative-1.0.0.toolchain.cdx.json, pkinative-1.0.0.sigstore.json'),
            expect.stringContaining('releases/download/v1.0.0/pkinative-1.0.0.tgz answers 404'),
        ]);
    });

    it('should report a missing release, a draft, one missing file and a tarball that is not served', () => {
        expect(decideReleaseAssets('1.1.0', { found: false })).toEqual([expect.stringContaining('the GitHub release v1.1.0 does not exist')]);
        expect(decideReleaseAssets('1.1.0', release({ draft: true }))).toEqual([expect.stringContaining('still a draft')]);
        expect(decideReleaseAssets('1.1.0', release({ assets: names.filter((n) => !n.endsWith('.sigstore.json')) }))).toEqual([expect.stringContaining('does not carry pkinative-1.1.0.sigstore.json —')]);
        expect(decideReleaseAssets('1.1.0', release({ tarballStatus: 503 }))).toEqual([expect.stringContaining('answers 503')]);
    });

    it('should hold nothing below 1.0.0, where no release exists', () => {
        expect(decideReleaseAssets('0.9.0', { found: false })).toEqual([]);
    });
});

describe('parseRelease', () => {
    it('should reduce the API answer to the draft flag, the file names and the tarball status', () => {
        const body = JSON.stringify({ draft: false, assets: [{ name: 'pkinative-1.1.0.tgz', size: 1 }, { name: 'pkinative-1.1.0.cdx.json' }, { size: 3 }] });
        expect(parseRelease(200, body, 200)).toEqual({ found: true, draft: false, assets: ['pkinative-1.1.0.tgz', 'pkinative-1.1.0.cdx.json'], tarballStatus: 200 });
    });

    it('should read a 404 as an absent release, and anything else as an error rather than a verdict', () => {
        expect(parseRelease(404, '{"message":"Not Found"}', 0)).toEqual({ found: false });
        // A rate limit or an outage is not "the release is empty".
        expect(() => parseRelease(403, '{"message":"API rate limit exceeded"}', 0)).toThrow('answered 403');
        expect(() => parseRelease(200, '{"assets":[]}', 200)).toThrow('without `draft` or `assets`');
        expect(() => parseRelease(200, '{"draft":false}', 200)).toThrow('without `draft` or `assets`');
    });
});
