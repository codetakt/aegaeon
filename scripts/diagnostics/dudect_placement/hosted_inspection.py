"""Single allocation inspection and encrypted evidence; no measurement launcher."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def command(argv, seconds=5):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=seconds).stdout.strip()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def binding(plan):
    files = {name: sha(ROOT / name) for name in plan['source_sha256']}
    if files != plan['source_sha256']:
        raise RuntimeError('frozen source mismatch')
    paths = [Path('/usr/bin/python3').resolve(), Path('/usr/bin/openssl').resolve(),
             Path('/usr/bin/systemctl').resolve()]
    dependencies = {str(x): sha(x) for x in paths}
    for path in paths:
        linked = command(['/usr/bin/ldd', str(path)])
        for line in linked.splitlines():
            for word in line.split():
                if word.startswith('/'):
                    dependency = Path(word).resolve()
                    dependencies[str(dependency)] = sha(dependency)
    return {'source': files, 'executables_and_libraries': dependencies,
            'python': command(['/usr/bin/python3', '-I', '-B', '--version']),
            'openssl': command(['/usr/bin/openssl', 'version']),
            'systemd': command(['/usr/bin/systemctl', '--version'])}


BOOTSTRAP = r'''
import hashlib,json,os,pathlib,runpy,sys
source, output, runtime = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(source).parent))
sys.argv = [source, '--unit', 'hosted-compute-agent.service', '--output', output]
try:
    runpy.run_path(source, run_name='__main__')
finally:
    modules = {}
    for name, module in list(sys.modules.items()):
        path = getattr(module, '__file__', None)
        if path and pathlib.Path(path).is_file():
            modules[name] = {'path': str(pathlib.Path(path).resolve()),
                            'sha256': hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()}
    pathlib.Path(runtime).write_text(json.dumps({'executable':sys.executable,
        'version':sys.version,'flags':str(sys.flags),'modules':modules}, indent=2)+'\n')
'''


def main():
    os.umask(0o077)
    plan = json.loads((HERE / 'inspection-plan.json').read_text())
    if (os.environ.get('GITHUB_RUN_ATTEMPT') != '1' or
            os.environ.get('GITHUB_REF') != 'refs/heads/' + plan['branch'] or
            os.environ.get('GITHUB_REPOSITORY') != 'codetakt/aegaeon'):
        raise RuntimeError('only the first allocation of the fixed branch is allowed')
    head = command(['git', '-c', 'safe.directory=' + str(ROOT), '-C', str(ROOT), 'rev-parse', 'HEAD'])
    if head != os.environ['GITHUB_SHA']:
        raise RuntimeError('checkout mismatch')
    private = ROOT / 'artifacts/service-inspection-private'
    upload = ROOT / 'artifacts/service-inspection-upload'
    private.mkdir(parents=True, exist_ok=False)
    upload.mkdir(parents=True, exist_ok=False)
    receipt = {'head': head, 'started': time.monotonic(), 'plan_sha256': sha(HERE / 'inspection-plan.json'),
               'allocation': {key: os.environ.get(key) for key in
                              ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REF','ImageOS','ImageVersion')},
               'native_invocations': 0, 'configuration_mutations': 0, 'replacements': 0,
               'timing_admission': False, 'operation_complete': False}
    code = 1
    try:
        receipt['before'] = binding(plan)
        write(private / 'opportunity.json', receipt)
        env = {'PATH':'/usr/bin:/bin', 'LC_ALL':'C', 'LANG':'C'}
        env.update({key:os.environ[key] for key in ('ImageOS','ImageVersion') if key in os.environ})
        result = subprocess.run(['/usr/bin/python3','-I','-B','-c',BOOTSTRAP,
                                 str(HERE/'inspect_environment.py'), str(private/'inspection.json'),
                                 str(private/'collector-runtime.json')], env=env,
                                capture_output=True, text=True, timeout=65)
        (private/'collector.stdout').write_text(result.stdout)
        (private/'collector.stderr').write_text(result.stderr)
        receipt['collector_returncode'] = result.returncode
        receipt['after'] = binding(plan)
        if result.returncode or receipt['before'] != receipt['after']:
            raise RuntimeError('collector failed or binding changed')
        inspection = json.loads((private/'inspection.json').read_text())
        if inspection['timing_admission'] or inspection['native_invocations'] or inspection['configuration_mutations']:
            raise RuntimeError('read-only boundary violated')
        receipt['classification'] = inspection['classification']
        receipt['operation_complete'] = True
        code = 0
    except Exception as error:
        receipt['error'] = repr(error)
    finally:
        receipt['ended'] = time.monotonic()
        write(private/'opportunity.json', receipt)
        records = [{'path':str(f.relative_to(private)), 'size':f.stat().st_size, 'sha256':sha(f)}
                   for f in sorted(private.rglob('*')) if f.is_file()]
        write(private/'manifest.json', {'files': records})
        archive = private.parent/'service-inspection-private.tar'
        with tarfile.open(archive, 'w') as out:
            for file in sorted(private.iterdir()):
                out.add(file, arcname=file.name, recursive=False)
        command(['/usr/bin/openssl','cms','-encrypt','-aes-256-gcm','-binary','-outform','DER',
                 '-in',str(archive),'-out',str(upload/'evidence.cms'),
                 '-recip',str(HERE/'receipt-recipient.pem'),
                 '-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'], 30)
        # Only encrypted bytes are exposed to artifact upload; no plaintext fallback.
        private.parent.chmod(0o755)
        upload.chmod(0o755)
        (upload/'evidence.cms').chmod(0o644)
    print('Finite read-only inspection ended; encrypted receipt retained. No timing admission.')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
