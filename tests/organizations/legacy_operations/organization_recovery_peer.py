"""Local control-host administrator transport; never a TCP fallback."""

from __future__ import annotations

import os
import pwd
from pathlib import Path
from typing import Any

import psycopg
from organization_recovery_store import require


def user_id(name: str) -> int:
    return int(name) if name.isdecimal() else pwd.getpwnam(name).pw_uid


def peer_connection(value: dict[str, Any], options: str) -> psycopg.Connection:
    peer = pwd.getpwnam(value["peer_user"])
    require(os.geteuid() == 0 and peer.pw_uid != 0, "separate local database account required")
    require(
        len(list(Path("/proc/self/task").iterdir())) == 1, "single-threaded peer connector required"
    )
    group, groups = os.getegid(), os.getgroups()
    connection = None
    try:
        # Real/saved root authority is retained only by the offline coordinator.
        # Kernel peer credentials identify this explicitly selected database OS
        # account during connection. No process or command runs under that uid.
        os.setgroups([])
        os.setegid(peer.pw_gid)
        os.seteuid(peer.pw_uid)
        connection = psycopg.connect(
            host=value["socket"],
            port=value["port"],
            dbname=value["dbname"],
            user=value["user"],
            requirepeer=peer.pw_name,
            require_auth="none",
            password="",
            passfile="/dev/null",
            sslmode="disable",
            connect_timeout=5,
            application_name="aegaeon-organization-recovery",
            options=options,
            autocommit=True,
        )
    finally:
        os.seteuid(0)
        os.setegid(group)
        os.setgroups(groups)
    try:
        require(
            connection.execute("SELECT system_user").fetchone()[0] == "peer:" + peer.pw_name,
            "actual peer authentication required",
        )
    except BaseException:
        connection.close()
        raise
    return connection
