/**
 * pkinative — the interoperability matrix: finding a foreign tool
 * ================================================================
 * A tool is present when it **runs**, not when a file of its name exists.
 *
 * The first version of this runner looked for `pwsh.exe` on PATH with
 * `existsSync`. On Windows, PowerShell 7 installed from the Store is an App
 * Execution Alias — a reparse point that `stat` cannot open (EACCES) and that
 * spawns perfectly — so the runner printed "PowerShell 7 is not installed" on
 * a machine running 7.6, and a whole case went unrun without anyone noticing.
 * Every probe here therefore spawns the candidate with arguments that must
 * succeed, exactly the way the tool is later invoked.
 *
 * **WSL, on a Windows workstation.** GnuTLS `certtool`, Go and zlint have no
 * maintained Windows build, but a Windows workstation with WSL has all three
 * a command away. When a tool is not found natively on win32, it is looked
 * for inside the default WSL distribution, and every path handed to it is
 * translated (`C:\x` → `/mnt/c/x`). Such a tool is never *required* on
 * Windows — the per-platform required set (scripts/lib/interop.ts) names only
 * native tools — so a CI runner without a distribution skips it, and a
 * workstation with one runs it. `PKINATIVE_INTEROP_WSL=0` turns the bridge off.
 *
 * @module scripts/lib/interop-host
 */

import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import { env, platform } from 'node:process';

/** What one invocation produced. `status` is -1 when the process could not be started at all. */
export interface Ran {
    readonly status: number;
    readonly stdout: string;
    readonly stderr: string;
}

export interface RunOptions {
    readonly env?: Readonly<Record<string, string>>;
    readonly input?: string;
    readonly timeoutMs?: number;
    /** Working directory, as a host path; translated for WSL. */
    readonly cwd?: string;
}

/** A foreign tool that answered its probe. */
export interface Host {
    /** The command that answered, as the report prints it. */
    readonly command: string;
    /** `native`, or `wsl` when it runs inside the Windows Subsystem for Linux. */
    readonly via: 'native' | 'wsl';
    run(args: readonly string[], options?: RunOptions): Ran;
    /** A host path as this tool must be given it. */
    path(local: string): string;
}

/** `C:\Users\x` → `/mnt/c/Users/x`; anything not drive-absolute is returned with its separators turned. */
export function toWslPath(local: string): string {
    const m = /^([A-Za-z]):[\\/](.*)$/.exec(local);
    if (m === null) return local.replace(/\\/g, '/');
    return `/mnt/${(m[1] ?? '').toLowerCase()}/${(m[2] ?? '').replace(/\\/g, '/')}`;
}

function spawn(command: string, args: readonly string[], options: RunOptions = {}): Ran {
    const r = spawnSync(command, [...args], {
        encoding: 'utf8',
        windowsHide: true,
        env: { ...env, ...(options.env ?? {}) },
        timeout: options.timeoutMs ?? 300_000,
        maxBuffer: 64 * 1024 * 1024,
        ...(options.input === undefined ? {} : { input: options.input }),
        ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    });
    return { status: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? (r.error?.message ?? '') };
}

/**
 * Directories a toolchain installs into without putting them on PATH: `go
 * install` writes to `$(go env GOPATH)/bin`, which is `~/go/bin` by default.
 */
const EXTRA_DIRS: readonly string[] = [join(homedir(), 'go', 'bin')];

function native(command: string): Host {
    return {
        command,
        via: 'native',
        run: (args, options) => spawn(command, args, options),
        path: (local) => local,
    };
}

/**
 * The WSL bridge. `sh -c` sets a Linux-only PATH — the places Go installs
 * binaries first (`go install` does not touch the login profile a
 * non-interactive shell skips), and none of the `/mnt/c/...` directories WSL
 * appends by default: looking a command up through sixty Windows directories
 * costs seconds per call, and could find a Windows executable instead of the
 * Linux tool — then `exec`s the tool with its arguments untouched.
 */
function viaWsl(command: string): Host {
    const prefix = ['-e', 'sh', '-c', 'PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; cd "${PKI_CWD:-.}" 2>/dev/null; exec "$@"', 'sh'];
    return {
        command: `wsl:${command}`,
        via: 'wsl',
        run: (args, options = {}) => {
            const extra: Record<string, string> = { ...(options.env ?? {}) };
            if (options.cwd !== undefined) extra['PKI_CWD'] = toWslPath(options.cwd);
            // WSLENV forwards named variables into the distribution; `/u`
            // keeps their values as they are.
            const names = Object.keys(extra);
            if (names.length > 0) extra['WSLENV'] = [env['WSLENV'] ?? '', ...names.map((n) => `${n}/u`)].filter((s) => s !== '').join(':');
            const { cwd: _drop, ...rest } = options;
            return spawn('wsl.exe', [...prefix, command, ...args], { ...rest, env: extra });
        },
        path: toWslPath,
    };
}

let wslUsable: boolean | undefined;

/** Whether the WSL bridge may be used on this machine: win32, not disabled, and a distribution that runs. */
function wslAvailable(): boolean {
    if (platform !== 'win32' || env.PKINATIVE_INTEROP_WSL === '0') return false;
    wslUsable ??= spawn('wsl.exe', ['-e', 'true'], { timeoutMs: 60_000 }).status === 0;
    return wslUsable;
}

/**
 * The first candidate command that answers `probe` with status 0, natively
 * and then — on win32, for the candidates `allowWsl` lets through — inside
 * WSL. `allowNative: false` skips the native lookup — for a Windows build
 * known not to work from here (Git for Windows' MSYS `gpgsm` rewrites every
 * path it is given and cannot start its agent). `accept` may refuse an answer whose output says the tool is not the
 * one meant (a Store stub named `python3`, say).
 */
export function locate(
    candidates: readonly string[],
    probe: readonly string[],
    options: { readonly allowWsl?: boolean; readonly allowNative?: boolean; readonly accept?: (r: Ran) => boolean } = {},
): Host | null {
    const accept = options.accept ?? ((): boolean => true);
    for (const command of options.allowNative === false ? [] : candidates) {
        const r = spawn(command, probe, { timeoutMs: 60_000 });
        if (r.status === 0 && accept(r)) return native(command);
        for (const dir of EXTRA_DIRS) {
            const full = join(dir, platform === 'win32' ? `${command}.exe` : command);
            const e = spawn(full, probe, { timeoutMs: 60_000 });
            if (e.status === 0 && accept(e)) return native(full);
        }
    }
    if (options.allowWsl === true && wslAvailable()) {
        for (const command of candidates) {
            const host = viaWsl(command);
            const r = host.run(probe, { timeoutMs: 120_000 });
            if (r.status === 0 && accept(r)) return host;
        }
    }
    return null;
}

/** The first line a failed command printed, for a report. */
export const firstLine = (r: Ran): string => (r.stderr.trim() || r.stdout.trim()).split(/\r?\n/)[0] ?? `exit ${String(r.status)}`;

/** Every directory of PATH, for a tool that needs a sibling file of its executable. */
export const pathDirs = (): string[] => (env.PATH ?? env.Path ?? '').split(delimiter).filter((d) => d !== '');
