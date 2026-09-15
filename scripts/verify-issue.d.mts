/** The verdict of the draft-issue verifier: errors block submission, warnings advise. */
export interface IssueValidation {
    readonly ok: boolean;
    readonly errors: string[];
    readonly warnings: string[];
}

/** Validate the text of a draft issue against the governance policy. */
export function validateIssueMarkdown(content: string): IssueValidation;
