#!/usr/bin/env tsx
/**
 * pkinative — the 0.x tags, after the fact
 * =========================================
 * Versions 0.1.0 to 0.9.0 were prepared on one linear history and never
 * published: no GitHub Release, nothing on npm, and no tag either, because
 * the history was built locally before the repository had a remote. 1.0.0 is
 * the first release. The 0.x versions still deserve their tags — a reader of
 * CHANGELOG.md or of `release-notes/v0.X.0.md` must be able to check out the
 * tree each entry describes — so this script puts them where they belong.
 *
 * Which commit a tag names is a decision, written here once: **the last
 * commit of that version's preparation**, the one the release's pull-request
 * body lists (release-notes/draft/PR-v1.0.0.md, step 6). For 0.2 to 0.5 that
 * is the `chore(release): X.Y.Z` bump; for 0.7 to 0.9 the commit that recorded
 * the pull-request body with the gate's figures, two commits after the bump;
 * for 0.1.0 a documentation fix made the day after the bump, the last change
 * before 0.2.0 began. 0.6.0 does not exist: the 0.5 band became 0.7 (M4) when
 * the milestones were renumbered, and no 0.6.0 was ever cut.
 *
 * Every entry is verified before anything is printed or done: the commit
 * exists and is an ancestor of HEAD, its `package.json` carries the version,
 * `release-notes/vX.Y.Z.md` exists with its `# pkinative vX.Y.Z` title, and
 * CHANGELOG.md has the `## [X.Y.Z]` entry. A tag that already exists must
 * point at the listed commit; anything else is refused with nothing written.
 *
 * Usage:
 *   npx tsx scripts/tag-history.ts            # dry run: verify, print the eight commands
 *   npx tsx scripts/tag-history.ts --apply    # create the annotated tags (maintainer, interactive terminal)
 *
 * `--apply` is the maintainer's act (.github/AGENT_RULES.md §5): it requires
 * an interactive terminal, which the agents' shells are not, and it never
 * pushes — `git push origin --tags` is a separate, deliberate step.
 *
 * Exit: 0 verified (and applied), 1 a check failed, 2 `--apply` refused.
 *
 * @module scripts/tag-history
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** One tag of the 0.x line and the commit it names. */
export interface TagEntry {
    readonly tag: string;
    readonly version: string;
    readonly commit: string;
}

/** The 0.x line, in order. The commit is the last of each version's preparation (see the header). */
export const TAG_HISTORY: readonly TagEntry[] = [
    { tag: 'v0.1.0', version: '0.1.0', commit: 'f271a88' },
    { tag: 'v0.2.0', version: '0.2.0', commit: 'adeb55f' },
    { tag: 'v0.3.0', version: '0.3.0', commit: 'de7a7c2' },
    { tag: 'v0.4.0', version: '0.4.0', commit: '0c63bf5' },
    { tag: 'v0.5.0', version: '0.5.0', commit: '87b9ff6' },
    { tag: 'v0.7.0', version: '0.7.0', commit: '448713c' },
    { tag: 'v0.8.0', version: '0.8.0', commit: 'cd9e629' },
    { tag: 'v0.9.0', version: '0.9.0', commit: '353f36e' },
];

/** What the script needs to know from the repository, so the checks can be tested against a fake. */
export interface Repository {
    /** `git rev-parse --verify <commit>^{commit}`; null when it does not exist. */
    readonly resolveCommit: (commit: string) => string | null;
    /** `git merge-base --is-ancestor <commit> HEAD`. */
    readonly isAncestorOfHead: (commit: string) => boolean;
    /** `git show <commit>:<path>`; null when the path is not in that tree. */
    readonly fileAt: (commit: string, path: string) => string | null;
    /** `git rev-parse --verify <tag>^{commit}` on an existing tag; null when there is no such tag. */
    readonly tagTarget: (tag: string) => string | null;
    /** A file of the working tree; null when absent. */
    readonly workingFile: (path: string) => string | null;
}

/** The annotated tag message: the release note's title, then why the tag comes late. */
export function tagMessage(entry: TagEntry, title: string): string {
    return `${title}\n\nTagged after the fact: this version was prepared and never published (no GitHub Release, nothing on npm). See release-notes/${entry.tag}.md.`;
}

/** Every reason this entry cannot be tagged as listed; empty when it can. */
export function checkTagEntry(entry: TagEntry, repo: Repository): string[] {
    const out: string[] = [];
    const sha = repo.resolveCommit(entry.commit);
    if (sha === null) return [`${entry.tag}: commit ${entry.commit} does not exist`];
    if (!repo.isAncestorOfHead(entry.commit)) out.push(`${entry.tag}: commit ${entry.commit} is not an ancestor of HEAD — tags are placed from the branch that holds the whole history`);
    const manifest = repo.fileAt(entry.commit, 'package.json');
    const version = manifest === null ? null : (JSON.parse(manifest) as { version?: unknown }).version;
    if (version !== entry.version) out.push(`${entry.tag}: package.json at ${entry.commit} says ${String(version)}, expected ${entry.version}`);
    const note = repo.workingFile(`release-notes/${entry.tag}.md`);
    if (note === null) out.push(`${entry.tag}: release-notes/${entry.tag}.md is missing`);
    else if (!note.startsWith(`# pkinative ${entry.tag}\n`)) out.push(`${entry.tag}: release-notes/${entry.tag}.md does not open with "# pkinative ${entry.tag}"`);
    const changelog = repo.workingFile('CHANGELOG.md') ?? '';
    if (!changelog.includes(`\n## [${entry.version}] `)) out.push(`${entry.tag}: CHANGELOG.md has no "## [${entry.version}]" entry`);
    const existing = repo.tagTarget(entry.tag);
    if (existing !== null && existing !== sha) out.push(`${entry.tag}: already exists and points at ${existing.slice(0, 7)}, not ${entry.commit} — a tag is never moved (.github/rulesets/tags.json)`);
    return out;
}

/** The verified plan: one `git tag -a` per entry that does not exist yet, or the problems that forbid it. */
export function planTagHistory(repo: Repository, entries: readonly TagEntry[] = TAG_HISTORY): { readonly problems: string[]; readonly commands: string[][] } {
    const problems: string[] = [];
    const commands: string[][] = [];
    for (const entry of entries) {
        const found = checkTagEntry(entry, repo);
        if (found.length > 0) {
            problems.push(...found);
            continue;
        }
        if (repo.tagTarget(entry.tag) !== null) continue; // already where it belongs
        const title = (repo.workingFile(`release-notes/${entry.tag}.md`) ?? '').split('\n')[0]?.replace(/^# /, '') ?? `pkinative ${entry.tag}`;
        commands.push(['tag', '-a', entry.tag, entry.commit, '-m', tagMessage(entry, title)]);
    }
    return { problems, commands };
}

// ── The real repository ──────────────────────────────────────────────

function git(root: string, args: readonly string[]): string | null {
    const r = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
    return r.status === 0 ? r.stdout : null;
}

/** A `Repository` over the git repository at `root`. */
export function openRepository(root: string): Repository {
    return {
        resolveCommit: (c) => git(root, ['rev-parse', '--verify', '--quiet', `${c}^{commit}`])?.trim() ?? null,
        isAncestorOfHead: (c) => spawnSync('git', ['merge-base', '--is-ancestor', c, 'HEAD'], { cwd: root }).status === 0,
        fileAt: (c, p) => git(root, ['show', `${c}:${p}`]),
        tagTarget: (t) => git(root, ['rev-parse', '--verify', '--quiet', `refs/tags/${t}^{commit}`])?.trim() ?? null,
        workingFile: (p) => (existsSync(join(root, p)) ? readFileSync(join(root, p), 'utf8') : null),
    };
}

/** Run one `git …` command; the exit code, so a failure stops the sequence. */
export type GitRunner = (args: readonly string[]) => number;

/**
 * Apply the plan. Refused outside an interactive terminal: creating a tag is the maintainer's act,
 * and the shells agents drive are not interactive.
 */
export function applyTagHistory(commands: readonly string[][], run: GitRunner, interactive: boolean): { readonly ok: boolean; readonly message: string } {
    if (!interactive) return { ok: false, message: 'refused: --apply needs an interactive terminal — tagging is the maintainer\'s act (.github/AGENT_RULES.md §5); run the dry run and hand the commands to a human' };
    for (const args of commands) {
        const code = run(args);
        if (code !== 0) return { ok: false, message: `git ${args.slice(0, 4).join(' ')} exited ${code}; stopped — nothing after it was created` };
    }
    return { ok: true, message: `${commands.length} tag(s) created locally; review with \`git tag -n3\`, then \`git push origin --tags\`` };
}

// ── Entry point ──────────────────────────────────────────────────────

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
    const apply = process.argv.includes('--apply');
    const { problems, commands } = planTagHistory(openRepository(root));
    if (problems.length > 0) {
        for (const p of problems) console.error(`tag-history: ${p}`);
        process.exit(1);
    }
    if (commands.length === 0) {
        console.log(`tag-history: every tag of the 0.x line is already in place (${TAG_HISTORY.length} tags)`);
        process.exit(0);
    }
    for (const c of commands) console.log(`git ${c.slice(0, 4).join(' ')} -m "${c[5]?.split('\n')[0] ?? ''}…"`);
    if (!apply) {
        console.log(`tag-history: dry run — ${commands.length} tag(s) verified and not created; add --apply (interactive terminal) to create them`);
        process.exit(0);
    }
    const result = applyTagHistory(commands, (args) => spawnSync('git', args, { cwd: root, stdio: 'inherit' }).status ?? 1, process.stdin.isTTY === true && process.stdout.isTTY === true);
    console[result.ok ? 'log' : 'error'](`tag-history: ${result.message}`);
    process.exit(result.ok ? 0 : 2);
}
