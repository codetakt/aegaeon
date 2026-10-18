"""Same source-bound analysis worker, real ACKs, owned OTHER collector unit."""
from array import array
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import resource
import socket
import sys
import threading
import time

import runtime as rt
from protocol import Progress, peer


def collect(d):
    cfg = d['collector']
    sys.path.insert(0, cfg['analysis'])
    import analysis_runtime as ar
    from analysis_contract import assess, identity, significant
    from dudect_candidate import canonical
    from dudect_contract import contract_roles
    from dudect_diagnostics import RuntimeCapture, validate_trace
    from dudect_timing import validate_timing

    dest = d['dir'] / 'observations'
    dest.mkdir()
    bindings = {n: cfg['bindings'][n] for n in cfg['cases']}
    analysis = identity('interval-only', cfg['packet'], cfg['id'])
    if analysis != cfg['analysis_identity']:
        raise ValueError('analysis implementation/runtime differs')
    progress = Progress(d)
    ending = threading.Event()
    ident = rt.identity(os.getpid())

    def heartbeat():
        while not ending.wait(.05):
            rt.pulse(d, 'controller', ident)

    rt.pulse(d, 'controller', ident)
    pulse = threading.Thread(target=heartbeat, daemon=True)
    pulse.start()
    result = {'complete': False, 'timing': cfg['timing'], 'ci_admission': False}
    stream = ar.Stream(tuple(bindings), 'pr', bindings=bindings)
    worker = None
    ack_r = ack_w = out_r = out_w = pidfd = None
    try:
        with contextlib.ExitStack() as stack:
            timing = stack.enter_context((dest / 'native.timing').open('xb'))
            errors = stack.enter_context((dest / 'analysis-worker.stderr').open('xb'))
            journal = stack.enter_context((dest / 'sparse-prefixes.jsonl').open('xb'))
            output = stack.enter_context((dest / 'native.stdout').open('xb'))
            context = stack.enter_context((dest / 'runtime.jsonl').open('xb'))
            capture = RuntimeCapture(context)
            capture.snapshot('start')
            worker = ar.Worker(dest / 'native.timing', bindings, errors, analysis=analysis)
            stream.attach(worker, journal)
            transferred = [timing.fileno()]
            if 'ct_eq_128' in bindings:
                samples = stack.enter_context((dest / 'native.samples').open('xb'))
                transferred.append(samples.fileno())
            ack_r, ack_w = os.pipe2(os.O_CLOEXEC)
            out_r, out_w = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(ack_w, False)
            server = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
            server.bind(str(d['dir'] / 'io.sock'))
            os.chmod(d['dir'] / 'io.sock', 0o666)
            server.listen(1)
            server.settimeout(max(.01, d['start_by'] - time.monotonic()))
            rt.write(d['dir'] / 'collector-ready.json', {'at': time.monotonic()})
            conn, _ = server.accept()
            with conn:
                conn.settimeout(max(.01, d['start_by'] - time.monotonic()))
                pid, uid, _ = peer(conn)
                native = rt.identity(pid)
                if (uid != d['uid'] or conn.recv(1024) != d['generation'].encode() or
                        native['cgroup'].strip() != '0::/system.slice/' + d['unit']):
                    raise ValueError('native transport identity mismatch')
                pidfd = os.pidfd_open(pid)
                if select.select([pidfd], [], [], 0)[0] or rt.identity(pid) != native:
                    raise ValueError('native transport PID replaced')
                conn.sendmsg([d['generation'].encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              array('i', [ack_r, out_w, *transferred]))])
                if conn.recv(1024) != b'ready':
                    raise ValueError('native transport not ready')
            os.close(ack_r); ack_r = None
            os.close(out_w); out_w = None
            progress.started()
            rt.write(dest / 'native-identity.json', native)
            buffer = b''
            total = 0
            while True:
                until = min(progress.deadline, d['end_at'], rt.read(d['dir'] / 'progress.json')['until'])
                if time.monotonic() >= until or (rt.closed(d) and progress.state != 'completion'):
                    raise TimeoutError('owned collector case/generation ended')
                ready = select.select([out_r], [], [], min(.1, until - time.monotonic()))[0]
                if not ready:
                    continue
                data = os.read(out_r, 65536)
                if not data:
                    break
                output.write(data); output.flush()
                total += len(data); buffer += data
                if total > 16 * 1024 * 1024 or len(buffer) > 1024 * 1024:
                    raise ValueError('unbounded native output')
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    stream.deadline = progress.validation()
                    if cfg.get('functional_fault') == 'validation-stall':
                        if cfg['timing']:
                            raise ValueError('fault forbidden in timing')
                        time.sleep(30)
                    capture.snapshot('observation', pid, case=cfg['cases'][progress.case], look=progress.look + 1)
                    observed = dict(identity=rt.identity(pid), affinity=sorted(os.sched_getaffinity(pid)),
                        policy=os.sched_getscheduler(pid), priority=os.sched_getparam(pid).sched_priority,
                        rttime=list(resource.prlimit(pid, resource.RLIMIT_RTTIME)),
                        rtprio=list(resource.prlimit(pid, resource.RLIMIT_RTPRIO)),
                        executable=os.readlink(f'/proc/{pid}/exe'), at=time.monotonic())
                    if (observed['identity'] != native or observed['affinity'] != [d['cpu']] or
                            observed['policy'] != (rt.RESET | (os.SCHED_FIFO if d['arm']=='B' else 0)) or
                            observed['priority'] != (1 if d['arm']=='B' else 0) or
                            observed['rttime'] != d['rttime'] or observed['rtprio'] != d['rtprio']):
                        raise ValueError('actual native scheduler/identity changed')
                    if cfg['timing'] and not os.path.samefile(observed['executable'], d['target']):
                        raise ValueError('actual timing ELF differs')
                    with (dest / 'scheduler.jsonl').open('a') as receipt:
                        receipt.write(json.dumps(observed, sort_keys=True) + '\n')
                    # Analysis includes authenticating the current timing prefix and
                    # persisting both original and effective proof before ACK.
                    stream.observe(line)
                    row = json.loads(line)
                    if row['case'] != cfg['cases'][progress.case] or row['look'] != progress.look + 1:
                        raise ValueError('native schedule mismatch')
                    if time.monotonic() >= stream.deadline or rt.closed(d):
                        raise TimeoutError('validation exceeded deadline before ACK')
                    if os.write(ack_w, b'c') != 1:
                        raise OSError('short native ACK')
                    progress.acknowledged(progress.case, row['look'],
                        hashlib.sha256(line).hexdigest(), hashlib.sha256(canonical(stream.effective[-1])).hexdigest())
            if buffer or progress.case != len(bindings):
                raise ValueError('incomplete native stream')
            final_until = min(progress.deadline, d['end_at'], rt.read(d['dir'] / 'progress.json')['until'])
            if not select.select([pidfd], [], [], max(.001, final_until - time.monotonic()))[0]:
                raise TimeoutError('native exit missing')
            # PID1 exit code is checked independently by the owned-unit supervisor.
            stream.deadline = final_until
            stream.finish(0)
            capture.snapshot('end')
            validate_timing(dest / 'native.timing', bindings, 'pr', stream.histories)
            if 'ct_eq_128' in bindings:
                validate_trace(dest / 'native.samples', bindings['ct_eq_128'], 'pr')
            roles = contract_roles(json.loads((Path(cfg['source']) /
                    'tests/constant_time/contracts/case-contract-candidate.json').read_text()))
            assessments = []
            for name in cfg['cases']:
                history = [r for r in stream.effective if r['case'] == name]
                cid = bindings[name]['case_id']
                a = assess(cid, roles[cid], history)
                if cfg['signal'] == 16 and name == 'ct_eq_128':
                    # Signal diagnostics require raw0; crops may not substitute.
                    ok = any(significant(r['tests'][0]) for r in history)
                    a = dict(case_id=cid, role='fixed_signal16_raw0', requirement_satisfied=ok,
                             failure=None if ok else 'required_statistic_0_not_detected')
                assessments.append(a)
            if time.monotonic() >= stream.deadline:
                raise TimeoutError('final evidence verification deadline')
            result.update(complete=True, assessment=assessments,
                          requirements_satisfied=all(a['requirement_satisfied'] for a in assessments))
    except BaseException as exc:
        result['error'] = repr(exc)
        rt.stop(d, 'controller', 'collector-failed', pidfd)
        raise
    finally:
        if worker is not None:
            worker.close()
        ending.set(); pulse.join(timeout=1)
        for fd in (ack_r, ack_w, out_r, out_w, pidfd):
            if fd is not None:
                os.close(fd)
        for name, value in [('observations', stream.histories), ('decisions', stream.decisions),
                            ('effective-decisions', getattr(stream, 'effective', [])), ('result', result)]:
            rt.write(dest / (name + '.json'), value)
