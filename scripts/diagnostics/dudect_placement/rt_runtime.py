"""Bounded reads and fixed executable dependency receipts for RT preflight."""
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import time

ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
       'SYSTEMD_PAGERSECURE': '1', 'OPENSSL_CONF': '/dev/null'}
MAX_OUTPUT = 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 384 * 1024 * 1024


def digest(path, limit=MAX_FILE):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('invalid or oversized runtime input')
        result, size = hashlib.sha256(), 0
        while True:
            data = os.read(fd, min(65536, limit + 1 - size))
            if not data:
                break
            size += len(data)
            if size > limit:
                raise ValueError('runtime input exceeds bound')
            result.update(data)
        after = os.fstat(fd)
        current = path.stat()
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('runtime input changed while hashing')
        return {'path': str(path.resolve()), 'bytes': size, 'sha256': result.hexdigest()}
    finally:
        os.close(fd)


def run(argv, seconds=5, env=None, new_group=False):
    """Capture bounded stdout/stderr; reap only this invocation's child/group."""
    if seconds <= 0:
        raise TimeoutError('command deadline already elapsed')
    end = time.monotonic() + seconds
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env or ENV,
                             start_new_session=new_group)
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    size = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                left = end - time.monotonic()
                if left <= 0:
                    raise TimeoutError('command deadline')
                for key, _ in selector.select(left):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(data)
                    if size > MAX_OUTPUT:
                        raise ValueError('command output exceeds bound')
                    chunks[key.data].extend(data)
            child.wait(timeout=max(0.001, end - time.monotonic()))
        return {'returncode': child.returncode,
                **{k: bytes(v) for k, v in chunks.items()}}
    finally:
        if child.returncode is None:
            # Do not poll/reap before group kill: the unreaped leader reserves
            # this PID, avoiding a kill of a later group with a recycled ID.
            if new_group:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            child.wait(timeout=1)
        child.stdout.close()
        child.stderr.close()


def interpreter(executable):
    """Read PT_INTERP from the supported ELF64 little-endian executable."""
    with Path(executable).open('rb') as file:
        header = file.read(64)
        if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
            raise ValueError('unsupported executable format')
        phoff = struct.unpack_from('<Q', header, 32)[0]
        phsize, phnum = struct.unpack_from('<HH', header, 54)
        if phsize != 56 or not 1 <= phnum <= 128 or phoff + phsize * phnum > MAX_OUTPUT:
            raise ValueError('ELF program table outside bound')
        matches = []
        for i in range(phnum):
            file.seek(phoff + i * phsize)
            row = file.read(phsize)
            if len(row) != phsize:
                raise ValueError('truncated ELF program table')
            if struct.unpack_from('<I', row)[0] == 3:
                offset, size = struct.unpack_from('<Q', row, 8)[0], struct.unpack_from('<Q', row, 32)[0]
                if size < 2 or size > 4096 or offset + size > MAX_OUTPUT:
                    raise ValueError('ELF interpreter outside bound')
                file.seek(offset)
                name = file.read(size)
                if not name.endswith(b'\0') or b'\0' in name[:-1]:
                    raise ValueError('invalid interpreter name')
                matches.append(name[:-1].decode())
        if len(matches) != 1 or not matches[0].startswith('/'):
            raise ValueError('exactly one absolute ELF interpreter required')
        return str(Path(matches[0]).resolve())


def dependency_snapshot(executable, seconds=5):
    executable = str(Path(executable).resolve(strict=True))
    loader = interpreter(executable)
    # --list is the glibc loader's dependency query; the executable main is not run.
    result = run([loader, '--list', executable], seconds)
    if result['returncode'] or result['stderr']:
        raise RuntimeError('loader dependency query failed')
    names = {Path(executable).name: executable, Path(loader).name: loader}
    virtual = []
    for line in result['stdout'].decode().splitlines():
        row = line.strip()
        match = re.fullmatch(r'(\S+) => (/\S+) \(0x[0-9a-fA-F]+\)', row)
        direct = re.fullmatch(r'(/\S+) \(0x[0-9a-fA-F]+\)', row)
        if match:
            name, path = match.groups()
        elif direct:
            path = direct.group(1)
            name = Path(path).name
        elif re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-fA-F]+\)', row):
            virtual.append('linux-vdso.so.1: kernel mapping, no file digest')
            continue
        else:
            raise ValueError('unrecognized or unresolved loader output')
        path = str(Path(path).resolve(strict=True))
        if name in names and names[name] != path:
            raise ValueError('ambiguous loader object')
        names[name] = path
    paths = sorted(set(names.values()))
    if len(paths) > 128:
        raise ValueError('dependency count exceeds bound')
    total, files = 0, []
    for path in paths:
        row = digest(path, min(MAX_FILE, MAX_TOTAL - total))
        files.append(row)
        total += row['bytes']
    return {'executable': executable, 'loader': loader, 'names': names,
            'files': files, 'virtual': virtual,
            'scope': 'loader --list fixed dependency set; actual command trace checked separately'}


def verify_loader_trace(stderr, snapshot):
    """Reject observed link maps/init objects outside the prior fixed set.

    LD_DEBUG is loader diagnostics for this child only, not scheduler/kernel
    tracing. Its absence or unrecognized object is a binding failure. It is not
    an in-memory measurement or a proof against adversarial transient changes.
    """
    text = stderr.decode('utf-8', errors='strict')
    paths = {r['path'] for r in snapshot['files']}
    initialized, maps = set(), set()
    for line in text.splitlines():
        init = re.search(r'calling init: (\S+)\s*$', line)
        link = re.search(r'file=(\S+) \[\d+\];\s+generating link map', line)
        if init:
            path = str(Path(init.group(1)).resolve(strict=True))
            if path not in paths:
                raise ValueError('unbound initialized runtime object')
            initialized.add(path)
        if link:
            name = link.group(1)
            path = str(Path(name).resolve(strict=True)) if name.startswith('/') else snapshot['names'].get(name)
            if path not in paths:
                raise ValueError('unbound loaded runtime object')
            maps.add(path)
    if not initialized or not maps or 'transferring control:' not in text:
        raise ValueError('loader trace missing or incomplete')
    return {'initialized_files': sorted(initialized), 'link_map_files': sorted(maps),
            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'bytes': len(stderr),
            'scope': 'observed loader objects covered by before/after file binding'}
