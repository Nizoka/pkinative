/**
 * Recipe: what hostile input meets — a typed error with a stable code, never
 * a crash, and resource limits a caller can tighten for its own context.
 * Branch on `error.code`, never on the message.
 */
import { decodeAsn1, parseCertificate, PkiEncodingError, PkiError, PkiLimitError, readInteger } from 'pkinative';
import { fixture } from './_fixtures.ts';

function codeOf(action: () => unknown): string {
    try {
        action();
        return 'accepted';
    } catch (error) {
        if (error instanceof PkiLimitError) return `${error.code}:${error.limit}`;
        if (error instanceof PkiError) return error.code;
        throw error;
    }
}

export default function run(): Record<string, string> {
    // 10 000 nested SEQUENCEs: the decoder is iterative, so this is a limit, not a stack overflow.
    const depth = 10_000;
    const nested = new Uint8Array(depth * 2 + 2);
    for (let i = 0; i < depth; i++) nested.set([0x30, 0x80], i * 2);
    const deep = codeOf(() => decodeAsn1(nested, { encodingRules: 'ber', onDiagnostic: () => undefined }));

    // A length that runs past the end of the input.
    const truncated = codeOf(() => decodeAsn1(Uint8Array.of(0x30, 0x84, 0x7f, 0xff, 0xff, 0xff)));

    // A real certificate, cut in half.
    const leaf = fixture('letsencrypt-org-leaf');
    const halved = codeOf(() => parseCertificate(leaf.subarray(0, leaf.length >> 1)));

    // A caller that expects small certificates can say so.
    const tightened = codeOf(() => parseCertificate(leaf, { limits: { maxExtensions: 4 } }));

    let offset = '';
    try {
        readInteger(decodeAsn1(Uint8Array.of(0x02, 0x02, 0x00, 0x01)));
    } catch (error) {
        if (error instanceof PkiEncodingError) offset = `${error.code}@${String(error.offset)}`;
    }

    return { deep, truncated, halved, tightened, nonMinimalInteger: offset };
}
