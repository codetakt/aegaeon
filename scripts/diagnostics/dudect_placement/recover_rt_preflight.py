"""Authenticate and verify an RT read-only packet before publishing plaintext locally."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rt_runtime


def recover(cipher, key, summary, output, expected_head, expected_plan, openssl='/usr/bin/openssl'):
    if output.exists() or output.is_symlink():
        raise FileExistsError('recovery destination already exists')
    if (summary.get('schema') != 'aegaeon.dudect.rt-preflight-public-summary.v1' or
            summary.get('head') != expected_head or summary.get('plan_sha256') != expected_plan or
            summary.get('execution_admitted') is not False):
        raise ValueError('public summary identity mismatch')
    digest = rt_runtime.digest(cipher, 40 * 1024 * 1024)
    if digest['sha256'] != summary['ciphertext_sha256'] or digest['bytes'] != summary['ciphertext_bytes']:
        raise ValueError('ciphertext digest/size mismatch')
    with tempfile.TemporaryDirectory(prefix='.rt-recovery-', dir=output.parent) as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o700)
        archive = temporary / 'unverified.tar'
        result = rt_runtime.run([openssl, 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                '-in', str(cipher), '-inkey', str(key), '-out', str(archive)], 30)
        if result['returncode']:
            raise ValueError('CMS authentication/decryption failed')
        if archive.stat().st_size > 40 * 1024 * 1024:
            raise ValueError('decrypted archive exceeds bound')
        values, total = {}, 0
        with tarfile.open(archive, 'r:') as stream:
            for member in stream:
                if (not member.isfile() or not re.fullmatch(r'[A-Za-z0-9_.-]+', member.name) or
                        member.name not in {'inspection.json', 'opportunity.json', 'collector.stdout',
                                            'collector.stderr', 'manifest.json'} or
                        member.name in ('.', '..') or member.name in values or len(values) >= 16):
                    raise ValueError('unsafe/duplicate/oversized archive inventory')
                total += member.size
                if member.size < 0 or total > 32 * 1024 * 1024:
                    raise ValueError('decrypted members exceed bound')
                file = stream.extractfile(member)
                raw = file.read(member.size + 1)
                if len(raw) != member.size:
                    raise ValueError('archive member size mismatch')
                values[member.name] = raw
        manifest = json.loads(values.pop('manifest.json'))
        entries = manifest['files']
        if len(entries) != len(values) or len({r['path'] for r in entries}) != len(entries):
            raise ValueError('manifest inventory mismatch')
        for row in entries:
            raw = values[row['path']]
            if row['bytes'] != len(raw) or row['sha256'] != hashlib.sha256(raw).hexdigest():
                raise ValueError('manifest content mismatch')
        receipt = json.loads(values['opportunity.json'])
        opportunity = receipt['opportunity']
        if (opportunity['head'] != expected_head or opportunity['plan_sha256'] != expected_plan or
                opportunity['plan_id'] != summary['plan_id'] or opportunity['run_id'] != summary['run_id'] or
                opportunity['generation'] != summary['generation'] or
                receipt['operation_complete'] != summary['operation_complete'] or
                receipt['execution_admitted'] is not False or receipt['native_invocations'] != 0 or
                receipt['configuration_mutations'] != 0):
            raise ValueError('encrypted receipt identity/boundary mismatch')
        if receipt.get('classification', 'UNKNOWN_NO_EXECUTION') != summary['classification']:
            raise ValueError('public/private classification mismatch')
        output.mkdir(mode=0o700, exist_ok=False)
        values['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
        for name, raw in values.items():
            with (output / name).open('xb') as file:
                file.write(raw)
            (output / name).chmod(0o400)
        result = {'authenticated': True, 'all_manifest_files_match': True,
                  'files': len(entries), 'execution_admitted': False,
                  'classification': summary['classification'],
                  'operation_complete': receipt['operation_complete'],
                  'ciphertext_sha256': digest['sha256']}
        with (output / 'RECOVERY.json').open('x') as file:
            json.dump(result, file, indent=2)
            file.write('\n')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cipher', 'key', 'summary', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-plan-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = recover(args.cipher, args.key, json.loads(args.summary.read_text()), args.output,
                     args.expected_head, args.expected_plan_sha256)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
