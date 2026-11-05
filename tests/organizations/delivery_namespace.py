"""Run packaged delivery with real DNS policy in an isolated, routeless network."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

arguments = sys.argv[1:]
enrollment = "--enrollment" in arguments
arguments = [value for value in arguments if value != "--enrollment"]
# No host network or hosts-file changes. A globally routable address class is
# assigned only to this private loopback; no packet can leave the namespace.
with tempfile.TemporaryDirectory(prefix="aegaeon-delivery-network-") as temporary:
    hosts = Path(temporary) / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost private.example.test admin.example.test\n"
        "8.8.8.8 delivery.example.test wrong.example.test\n"
        "::1 localhost\n"
    )
    nsswitch = Path(temporary) / "nsswitch.conf"
    nsswitch.write_text("hosts: files\npasswd: files\ngroup: files\n")
    script = """
        ip link set lo up
        ip address add 8.8.8.8/32 dev lo
        test -z "$(ip route show)"
        test -z "$(ip -6 route show default)"
        mount --make-rprivate /
        mount --bind "$1" /etc/hosts
        if test -f /etc/nsswitch.conf; then mount --bind "$2" /etc/nsswitch.conf; fi
        # A host nscd socket would answer against the host's hosts file.
        if test -d /run/nscd; then mount -t tmpfs -o mode=755 none /run/nscd; fi
        shift 2
        sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
        exec setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all "$@"
    """
    result = subprocess.run(  # noqa: S603 — fixed namespace tools, explicit argv
        [
            shutil.which("unshare") or "/missing/unshare",
            "--user",
            "--map-current-user",
            "--keep-caps",
            "--net",
            "--mount",
            "--fork",
            "sh",
            "-eu",
            "-c",
            script,
            "aegaeon-delivery-network",
            str(hosts),
            str(nsswitch),
            sys.executable,
            str(Path(__file__).with_name("production_runtime.py")),
            "--packaged-enrollment" if enrollment else "--packaged-delivery",
            *arguments,
        ],
        check=False,
    )
    sys.exit(result.returncode)
