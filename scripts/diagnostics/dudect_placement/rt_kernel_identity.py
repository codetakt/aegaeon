"""Bounded read-only kernel identification under a trusted-provider model.

No package download, installation, execution admission or in-memory attestation.
The archive reference is reviewed offline and pinned in this source version.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

REFERENCE = Path(__file__).with_name('rt-kernel-reference.json')
REFERENCE_SHA256 = '2ba8292a2afb1140a8bcf629de58234798b4ff64b31797b8a06803a003ea8721'
MAX_NOTES = 1024 * 1024
MAX_RECORDS = 1024
MAX_REFERENCE = 16384
MATCH = 'BUILD_ID_AND_ARCHIVE_CONFIG_MATCH_UNDER_TRUSTED_PROVIDER_MODEL'
UNKNOWN = 'UNRESOLVED_KERNEL_CORRESPONDENCE'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reference(read):
    raw = read(REFERENCE, MAX_REFERENCE)
    if sha(raw) != REFERENCE_SHA256:
        raise ValueError('kernel reference digest mismatch')
    return json.loads(raw)


def parse_notes(raw, check=lambda: None):
    if not 0 < len(raw) <= MAX_NOTES:
        raise ValueError('notes size outside bound')
    offset, count, ids = 0, 0, []
    while offset < len(raw):
        check()
        count += 1
        if count > MAX_RECORDS or len(raw) - offset < 12:
            raise ValueError('note record/header bound')
        namesz, descsz, kind = struct.unpack_from('<III', raw, offset)
        offset += 12
        name_end = offset + namesz
        desc_start = (name_end + 3) & ~3
        desc_end = desc_start + descsz
        end = (desc_end + 3) & ~3
        if not namesz or end > len(raw):
            raise ValueError('note payload outside bounds')
        if any(raw[name_end:desc_start]) or any(raw[desc_end:end]):
            raise ValueError('nonzero note alignment padding')
        name = raw[offset:name_end]
        if not name.endswith(b'\0'):
            raise ValueError('unterminated note name')
        if name == b'GNU\0' and kind == 3:
            if not 16 <= descsz <= 64:
                raise ValueError('build ID length outside bound')
            ids.append(raw[desc_start:desc_end].hex())
        offset = end
    if len(ids) != 1:
        raise ValueError('exactly one GNU build ID required')
    return {'build_id': ids[0], 'note_count': count, 'encoding': 'ELF-notes-LE-align4'}


def sysfs_binding(mountinfo, fdinfo, device):
    """Reject covering bind mounts, duplicate mounts and non-root sysfs views."""
    covering = []
    for line in mountinfo.decode('utf-8', errors='strict').splitlines():
        left, sep, right = line.partition(' - ')
        fields, fs = left.split(), right.split()
        if not sep or len(fields) < 6 or len(fs) < 3:
            raise ValueError('malformed mountinfo')
        if fields[4] in ('/sys', '/sys/kernel', '/sys/kernel/notes'):
            covering.append((fields, fs))
    if len(covering) != 1:
        raise ValueError('ambiguous or overmounted notes path')
    fields, fs = covering[0]
    ids = [line.split(':', 1)[1].strip() for line in fdinfo.decode().splitlines()
           if line.startswith('mnt_id:')]
    if (fields[3:5] != ['/', '/sys'] or fs[0] != 'sysfs' or
            ids != [fields[0]] or fields[2] != f'{os.major(device)}:{os.minor(device)}'):
        raise ValueError('notes FD does not belong to the root sysfs mount')
    return {'mount_id': int(fields[0]), 'parent_mount_id': int(fields[1]),
            'device': fields[2], 'root': '/', 'mountpoint': '/sys', 'fstype': 'sysfs',
            'path': '/sys/kernel/notes', 'opened_without_symlinks': True}


def capture(read, check):
    """Open each component without following links; validate the actual open FD."""
    check()
    descriptors = []
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptors.append(os.open('/sys', flags | os.O_DIRECTORY))
        descriptors.append(os.open('kernel', flags | os.O_DIRECTORY, dir_fd=descriptors[-1]))
        descriptors.append(os.open('notes', flags | os.O_NONBLOCK, dir_fd=descriptors[-1]))
        fd = descriptors[-1]
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('notes is not a regular sysfs file')
        def provenance():
            return sysfs_binding(read('/proc/self/mountinfo'),
                                 read(f'/proc/self/fdinfo/{fd}'), before.st_dev)
        binding = provenance()
        chunks, size = [], 0
        while True:
            check()
            chunk = os.read(fd, min(65536, MAX_NOTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_NOTES:
                raise ValueError('notes exceed byte bound')
            chunks.append(chunk)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or binding != provenance()):
            raise ValueError('notes provenance changed while reading')
        check()
        return {'raw_base64': base64.b64encode(raw).decode('ascii'),
                'sha256': sha(raw), 'bytes': len(raw), 'provenance': binding}
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def correspondence(ref, uname, sources, notes, version_signature, errors):
    """Separate receipt: success never authorizes RT/native execution."""
    reasons = list(errors)
    expected = ref['identity']
    for field, actual in (('release', uname.release), ('version', uname.version),
                          ('architecture', uname.machine)):
        if actual != expected[field]:
            reasons.append('archive ' + field + ' mismatch')
    if not sources:
        reasons.append('full kernel config unavailable')
    for source in sources:
        if (source['expanded_sha256'] != expected['config_sha256'] or
                source['expanded_bytes'] != ref['archive_chain']['config_bytes']):
            reasons.append('archive config mismatch: ' + source['source'])
    if not notes or notes.get('parsed', {}).get('build_id') != expected['build_id']:
        reasons.append('archive build ID unavailable or mismatched')
    # Full bytes are retained and must be stable across censuses. Relocatable
    # non-ID notes are not treated as an independent runtime memory checksum.
    if version_signature.get('status') == 'present':
        if version_signature['value'] != ref['version_signature']:
            reasons.append('supporting version_signature mismatch')
    return {'schema': 'aegaeon.kernel-build-correspondence.v1',
            'reference_id': ref['reference_id'], 'reference_sha256': REFERENCE_SHA256,
            'status': UNKNOWN if reasons else MATCH, 'reasons': reasons,
            'execution_admitted': False, 'trust_model': ref['trust_model'],
            'runtime_patch_absence_proven': False}
