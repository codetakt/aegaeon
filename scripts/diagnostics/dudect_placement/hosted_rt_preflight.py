"""One bounded read-only opportunity with authenticated encrypted recovery."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))  # fixed checkout path, also with isolated Python
import rt_runtime

PLAN = 'rt-inspection-plan.json'
CERT = 'rt-receipt-recipient.pem'
BRANCH = 'test/dudect-rt-readonly-20261018'
WORKFLOW = '.github/workflows/dudect-rt-readonly.yml'
REPO = 'codetakt/aegaeon'
PREFIX = 'scripts/diagnostics/dudect_placement/'
FILES = {PREFIX + name for name in ('rt_preflight.py', 'rt_runtime.py',
         'hosted_rt_preflight.py', 'recover_rt_preflight.py', CERT,
         'test_rt_preflight.py', 'test_rt_transport.py', 'RT-PREFLIGHT.md')} | {WORKFLOW}
LIMITS = {'allocations': 1, 'attempts': 1, 'job_seconds': 600, 'operation_seconds': 170,
          'collector_seconds': 60, 'collector_outer_seconds': 65, 'command_seconds': 5,
          'censuses': 2, 'native_invocations': 0, 'configuration_mutations': 0,
          'replacements': 0}
TOOLS = {'python': '/usr/bin/python3', 'openssl': '/usr/bin/openssl',
         'systemctl': '/usr/bin/systemctl', 'git': '/usr/bin/git'}
CLASSIFICATIONS = {'UNKNOWN_NO_EXECUTION', 'NO_GO_INCOMPATIBLE_CURRENT_CONFIGURATION',
                  'NO_GO_UNDER_PROPOSED_STOP_PROTOCOL',
                  'READ_ONLY_PRECONDITIONS_COMPATIBLE_AUTHORIZATION_UNPROVEN'}


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def write(path, value):
    with path.open('xb') as file:
        file.write(encoded(value))


def read_json(path, limit=1024 * 1024):
    if path.stat().st_size > limit:
        raise ValueError('JSON input exceeds bound')
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError('JSON input exceeds bound')
    def pairs(rows):
        out = {}
        for key, value in rows:
            if key in out:
                raise ValueError('duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def source_binding(plan):
    if set(plan['source_sha256']) != FILES:
        raise ValueError('source inventory mismatch')
    current = {name: rt_runtime.digest(ROOT / name)['sha256'] for name in sorted(FILES)}
    if current != plan['source_sha256']:
        raise ValueError('source digest mismatch')
    return current


def load_plan():
    plan = read_json(HERE / PLAN)
    if (plan.get('schema') != 'aegaeon.dudect.rt-readonly-plan.v1' or
            plan.get('branch') != BRANCH or plan.get('workflow') != WORKFLOW or
            plan.get('unit') != 'hosted-compute-agent.service' or
            plan.get('limits') != LIMITS or plan.get('generation') != 1 or
            plan.get('stage') != 'read_only_acquisition' or plan.get('execution_admitted') is not False):
        raise ValueError('unexpected frozen plan')
    if not re.fullmatch(r'[a-z0-9-]{12,80}', plan.get('plan_id', '')):
        raise ValueError('invalid plan identity')
    source_binding(plan)
    return plan


def admit(plan):
    required = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/' + BRANCH,
                'GITHUB_REPOSITORY': REPO, 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '1',
                'GITHUB_WORKFLOW_REF': REPO + '/' + WORKFLOW + '@refs/heads/' + BRANCH}
    if any(os.environ.get(k) != v for k, v in required.items()):
        raise ValueError('not the fixed first read-only opportunity')
    head = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch(r'[0-9a-f]{40}', head) or os.environ.get('GITHUB_WORKFLOW_SHA') != head:
        raise ValueError('event/workflow commit mismatch')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    if not run_id.isdecimal():
        raise ValueError('missing run identity')
    event = read_json(Path(os.environ['GITHUB_EVENT_PATH']), 4 * 1024 * 1024)
    if (event.get('created') is not True or event.get('deleted') is not False or
            event.get('before') != '0' * 40 or event.get('after') != head or
            event.get('ref') != required['GITHUB_REF'] or
            event.get('repository', {}).get('full_name') != REPO):
        raise ValueError('event is not the fixed branch creation')
    checked = rt_runtime.run([TOOLS['git'], '-c', 'safe.directory=' + str(ROOT),
                              '-C', str(ROOT), 'rev-parse', 'HEAD'])
    if checked['returncode'] or checked['stdout'].decode().strip() != head:
        raise ValueError('checkout/event mismatch')
    return {'head': head, 'workflow_sha': head, 'run_id': run_id, 'attempt': 1,
            'run_number': 1, 'event_created': True,
            'event_sha256': rt_runtime.digest(os.environ['GITHUB_EVENT_PATH'])['sha256'],
            'plan_id': plan['plan_id'], 'generation': 1,
            'plan_sha256': rt_runtime.digest(HERE / PLAN)['sha256'],
            'image': {k: os.environ.get(k, '')[:256] for k in ('ImageOS', 'ImageVersion')}}


def binding(plan, deadline):
    result = {'source': source_binding(plan), 'plan_sha256': rt_runtime.digest(HERE / PLAN)['sha256'],
              'executables': {}}
    for name, executable in TOOLS.items():
        result['executables'][name] = rt_runtime.dependency_snapshot(executable,
                                        min(5, deadline - time.monotonic()))
    return result


def check_files(snapshot):
    for row in snapshot['files']:
        if rt_runtime.digest(row['path']) != row:
            raise ValueError('runtime changed before encrypted publication')


BOOTSTRAP = '''
import pathlib,runpy,sys
source, output, job_pid = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(source).parent))
sys.argv = [source, '--unit', 'hosted-compute-agent.service', '--job-pid', job_pid, '--output', output]
runpy.run_path(source, run_name='__main__')
'''


def invoke_collector(private, deadline):
    return rt_runtime.run([TOOLS['python'], '-I', '-B', '-c', BOOTSTRAP,
                          str(HERE / 'rt_preflight.py'), str(private / 'inspection.json'),
                          str(os.getpid())], min(65, deadline - time.monotonic()), new_group=True)


def archive(private):
    rows, size = [], 0
    for file in sorted(private.iterdir()):
        if file.is_symlink() or not file.is_file():
            raise ValueError('unexpected private evidence entry')
        size += file.stat().st_size
        if size > 32 * 1024 * 1024:
            raise ValueError('private payload exceeds bound')
        rows.append({'path': file.name, **{k: v for k, v in rt_runtime.digest(file).items() if k != 'path'}})
    write(private / 'manifest.json', {'files': rows})
    destination = private.parent / 'rt-preflight-private.tar'
    with tarfile.open(destination, 'x') as out:
        for file in sorted(private.iterdir()):
            out.add(file, arcname=file.name, recursive=False)
    return destination


def encrypt(archive_path, private, upload, plan, before, deadline):
    # Never expose a partial ciphertext or a plaintext fallback to upload.
    source_binding(plan)
    snapshot = before['executables']['openssl']
    check_files(snapshot)
    temporary = private / 'evidence.cms.pending'
    env = {**rt_runtime.ENV, 'LD_DEBUG': 'files'}
    result = rt_runtime.run([TOOLS['openssl'], 'cms', '-encrypt', '-aes-256-gcm', '-binary',
        '-outform', 'DER', '-in', str(archive_path), '-out', str(temporary),
        '-recip', str(HERE / CERT), '-keyopt', 'rsa_padding_mode:oaep',
        '-keyopt', 'rsa_oaep_md:sha256'], min(30, deadline - time.monotonic()), env)
    if result['returncode']:
        raise RuntimeError('authenticated encryption failed')
    trace = rt_runtime.verify_loader_trace(result['stderr'], snapshot)
    check_files(snapshot)
    source_binding(plan)
    if not temporary.is_file() or temporary.stat().st_size < 128:
        raise ValueError('encrypted evidence absent or truncated')
    digest = rt_runtime.digest(temporary)
    os.rename(temporary, upload / 'evidence.cms')
    return {'ciphertext_sha256': digest['sha256'], 'ciphertext_bytes': digest['bytes'],
            'encryption_trace_sha256': sha_bytes(encoded(trace)),
            'encryption_dependencies_sha256': sha_bytes(encoded(snapshot)),
            'runtime_rechecked_after_encryption': True}


def execute(plan, opportunity, base):
    """Shared with local fixtures; production entry admits the event first."""
    started = time.monotonic()
    deadline = started + LIMITS['operation_seconds'] - 5
    private, upload = base / 'rt-preflight-private', base / 'rt-preflight-upload'
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    private.mkdir(mode=0o700, exist_ok=False)
    upload.mkdir(mode=0o700, exist_ok=False)
    receipt = {'opportunity': opportunity, 'started': started, 'native_invocations': 0,
               'configuration_mutations': 0, 'execution_admitted': False,
               'collection_report_saved': False, 'operation_complete': False}
    code, before = 1, None
    try:
        before = binding(plan, deadline)
        receipt['before'] = before
        receipt['boot_before'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        result = invoke_collector(private, deadline - 55)
        for name in ('stdout', 'stderr'):
            (private / ('collector.' + name)).write_bytes(result[name])
        receipt['collector_returncode'] = result['returncode']
        receipt['after'] = binding(plan, deadline - 35)
        receipt['boot_after'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if result['returncode'] or receipt['before'] != receipt['after'] or receipt['boot_before'] != receipt['boot_after']:
            raise RuntimeError('collector failure or binding/boot change')
        inspection = read_json(private / 'inspection.json', 24 * 1024 * 1024)
        if (inspection.get('classification') not in CLASSIFICATIONS or
                inspection.get('execution_admitted') is not False or
                inspection.get('native_invocations') != 0 or inspection.get('configuration_mutations') != 0 or
                inspection.get('job_pid') != os.getpid() or inspection.get('unit') != plan['unit'] or
                inspection.get('source_sha256') != plan['source_sha256'][PREFIX + 'rt_preflight.py']):
            raise RuntimeError('collector report/boundary mismatch')
        receipt['classification'] = inspection['classification']
        receipt['censuses'] = len(inspection['censuses'])
        receipt['collection_report_saved'] = True
        receipt['operation_complete'] = True  # report lifecycle, never RT admission
        code = 0
    except Exception as exc:
        receipt['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        receipt['ended'] = time.monotonic()
        write(private / 'opportunity.json', receipt)
        archive_path = archive(private)
        if before is None:
            # No collection took place. Establish encryption's own binding;
            # do not manufacture a successful acquisition/runtime binding.
            before = {'executables': {'openssl': rt_runtime.dependency_snapshot(TOOLS['openssl'],
                                                   min(5, deadline - time.monotonic()))}}
        transport = encrypt(archive_path, private, upload, plan, before, deadline)
        summary = {'schema': 'aegaeon.dudect.rt-preflight-public-summary.v1',
                   'plan_id': plan['plan_id'], 'generation': 1,
                   'plan_sha256': opportunity['plan_sha256'], 'head': opportunity['head'],
                   'run_id': opportunity['run_id'], 'operation_complete': receipt['operation_complete'],
                   'classification': receipt.get('classification', 'UNKNOWN_NO_EXECUTION'),
                   'execution_admitted': False, 'native_invocations': 0, 'configuration_mutations': 0,
                   **transport}
        write(upload / 'summary.json', summary)
        base.chmod(0o755)
        upload.chmod(0o755)
        for file in upload.iterdir():
            file.chmod(0o644)
    return code


def main():
    os.umask(0o077)
    def expired(*_):
        raise TimeoutError('operation deadline')
    old = signal.signal(signal.SIGALRM, expired)
    signal.alarm(LIMITS['operation_seconds'])
    try:
        plan = load_plan()
        opportunity = admit(plan)
        code = execute(plan, opportunity, ROOT / 'artifacts')
    except Exception:
        # Paths, exception strings and raw subprocess stderr stay private.
        print('Read-only opportunity failed; no plaintext fallback or automatic retry.')
        return 1
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    print('Read-only opportunity ended; encrypted evidence retained. No RT or timing admission.')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
