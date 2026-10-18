"""Authenticated descriptor transfer and non-renewing collector progress leases."""
from array import array
import os
import socket
import stat
import struct
import time

import runtime as rt


def peer(sock):
    return struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def progress_valid(d):
    try:
        p = rt.read(d['dir'] / 'progress.json')
        return (p['generation'] == d['generation'] and p['phase'] in
                ('starting', 'native', 'validation', 'completion') and
                d['epoch'] <= p['at'] <= time.monotonic() < p['until'] <= d['end_at'] and
                p['until'] <= p['case_deadline'] and
                (p['phase'] not in ('validation', 'completion') or p['until'] <= p['at'] + 10))
    except (OSError, ValueError, KeyError, TypeError):
        return False


class Progress:
    def __init__(self, d):
        self.d = d
        self.sequence = 0
        self.case = 0
        self.look = 0
        self.deadline = min(d['epoch'] + 900, d['end_at'])
        self.state = 'starting'
        self.emit('starting', d['start_by'])

    def emit(self, phase, until, **details):
        now = time.monotonic()
        if now >= min(until, self.deadline, self.d['end_at']):
            raise TimeoutError('collector progress deadline')
        self.state = phase
        self.sequence += 1
        p = dict(generation=self.d['generation'], sequence=self.sequence,
                 case=self.case, look=self.look, phase=phase, at=now,
                 until=min(until, self.deadline, self.d['end_at']),
                 case_deadline=self.deadline, **details)
        rt.write(self.d['dir'] / 'progress.json', p)
        with (self.d['dir'] / 'progress.jsonl').open('a') as f:
            import json
            f.write(json.dumps(p, sort_keys=True) + '\n')
        return p

    def started(self):
        if self.state != 'starting':
            raise ValueError('duplicate native start')
        self.emit('native', self.deadline)

    def validation(self):
        if self.state != 'native':
            raise ValueError('unexpected validation transition')
        return self.emit('validation', time.monotonic() + 10)['until']

    def acknowledged(self, case, look, row_sha256, proof_sha256):
        if self.state != 'validation' or case != self.case or look != self.look + 1:
            raise ValueError('out-of-order verified acknowledgment')
        # The caller has validated, persisted the proof and sent the actual ACK.
        if not progress_valid(self.d):
            raise TimeoutError('ACK completed after validation deadline')
        self.look = look
        self.emit('native', self.deadline, row_sha256=row_sha256,
                  proof_sha256=proof_sha256, ack_sent=True)
        if look == 8:
            self.case += 1
            self.look = 0
            if self.case == len(self.d['collector']['cases']):
                self.emit('completion', time.monotonic() + 10)
            else:
                self.deadline = min(time.monotonic() + 900, self.d['end_at'])
                self.emit('native', self.deadline, previous_case_complete=True)


def attach_native(d):
    """Only the owned native obtains stdin/stdout and original diagnostic FDs."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(max(.01, d['start_by'] - time.monotonic()))
        s.connect(str(d['dir'] / 'io.sock'))
        pid, uid, _ = peer(s)
        ident = rt.read(d['dir'] / 'controller.heartbeat.json')['identity']
        if uid != 0 or rt.identity(pid) != ident:
            raise ValueError('untrusted collector peer')
        s.send(d['generation'].encode())
        data, ancillary, flags, _ = s.recvmsg(1024, socket.CMSG_SPACE(4 * 4))
        fds = array('i')
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(payload[:len(payload) - len(payload) % fds.itemsize])
        expected = 4 if 'ct_eq_128' in d['collector']['cases'] else 3
        try:
            if data != d['generation'].encode() or flags or len(fds) != expected:
                raise ValueError('invalid native transport descriptors')
            if not all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in fds[:2]):
                raise ValueError('native stdio must be pipes')
            if not all(stat.S_ISREG(os.fstat(fd).st_mode) for fd in fds[2:]):
                raise ValueError('native diagnostics must be regular files')
            os.dup2(fds[0], 0)
            os.dup2(fds[1], 1)
            env = {}
            for fd, name in zip(fds[2:], ('AEGAEON_DUDECT_TIMING_FD', 'AEGAEON_DUDECT_TRACE_FD')):
                os.set_inheritable(fd, True)
                env[name] = str(fd)
            s.send(b'ready')
            return env
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise
        finally:
            for fd in fds[:2]:
                try:
                    os.close(fd)
                except OSError:
                    pass
