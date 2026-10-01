"""pkinative — the pkilint driver of the interoperability matrix (lint role).

  python pkilint-driver.py <manifest.json> <out.ndjson>

Runs DigiCert's pkilint over every certificate the manifest lists
(scripts/lib/interop-artefacts.ts): `lint_pkix_cert` on each, and
`lint_pkix_signer_signee_cert_chain` on each leaf with its CA. The two linters
are called through their own command-line entry points — the `main()` the
`python -m pkilint.bin.…` commands run, with the same arguments — in one
process, because importing pkilint costs seconds and the matrix lints dozens
of certificates. One NDJSON record per lint, with every finding at NOTICE or
above; scripts/run-interop.ts decides: any ERROR or FATAL fails, every
WARNING and NOTICE must be reviewed in scripts/data/lint-waivers.json.
"""

import contextlib
import io
import json
import sys
from importlib.metadata import version

from pkilint.bin import lint_pkix_cert, lint_pkix_signer_signee_cert_chain


def run(main, args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = main(['lint', '-s', 'NOTICE', '-f', 'JSON', *args])
    text = out.getvalue().strip()
    findings = []
    for result in json.loads(text)['results'] if text else []:
        for f in result['finding_descriptions']:
            findings.append({'lint': f['code'], 'severity': f['severity'], 'at': result['node_path']})
    return status, findings


def main(manifest_path, out_path):
    with open(manifest_path, encoding='utf-8') as f:
        artefacts = [a for a in json.load(f)['artefacts'] if a['kind'] == 'cert']
    by_id = {a['id']: a for a in artefacts}
    lines = [{'t': 'header', 'tool': 'pkilint', 'version': version('pkilint')}]
    for a in artefacts:
        status, findings = run(lint_pkix_cert.main, [a['pem']])
        lines.append({'id': a['id'], 'check': 'lint.cert', 'ok': True, 'findings': findings, 'status': status})
        if a.get('shape') != 'ca':
            status, findings = run(lint_pkix_signer_signee_cert_chain.main, [by_id[a['issuer']]['pem'], a['pem']])
            lines.append({'id': a['id'], 'check': 'lint.chain', 'ok': True, 'findings': findings, 'status': status})
    lines.append({'t': 'footer', 'count': len(lines) - 1})
    with open(out_path, 'w', encoding='utf-8', newline='\n') as out:
        out.write('\n'.join(json.dumps(line) for line in lines) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: pkilint-driver.py <manifest.json> <out.ndjson>')
    main(sys.argv[1], sys.argv[2])
