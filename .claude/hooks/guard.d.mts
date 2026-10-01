/** One human-in-the-loop rule: `re` is tried against every candidate after the launch prefixes are stripped; `allow` exempts read-only forms. */
export interface GuardRule {
    readonly re: RegExp;
    readonly what: string;
    readonly allow?: RegExp;
}

export interface GuardVerdict {
    readonly deny: boolean;
    readonly what?: string;
}

export interface DenyPayload {
    readonly hookSpecificOutput: {
        readonly hookEventName: 'PreToolUse';
        readonly permissionDecision: 'deny';
        readonly permissionDecisionReason: string;
    };
}

export const RULES: ReadonlyArray<GuardRule>;

/** Strip `VAR=value`, `env`, `time`, `nohup`, `xargs`, `sudo` (and their flags) from the front of a candidate. */
export function stripPrefixes(candidate: string): string;

/** Every fragment of a Bash command that could be a program by itself. */
export function candidates(command: string): string[];

/** The verdict for one Bash command. */
export function decide(command: string): GuardVerdict;

/** The first shell segment of a candidate, against which an `allow` exemption is also judged; the whole candidate when the cut falls inside a quote. */
export function leadingSegment(candidate: string): string;

export function denyPayload(reason: string): DenyPayload;

export function reasonFor(what: string): string;
