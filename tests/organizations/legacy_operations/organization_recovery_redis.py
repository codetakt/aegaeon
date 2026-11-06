"""Offline token-store exclusion; no pending release or activation capability."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from organization_recovery_store import require

if TYPE_CHECKING:
    from organization_recovery_resp import Resp

# Concrete runtime commands only. No expanding category, admin/config, module,
# replication, loading, migration or programmable-function privileges.
WORKER_COMMANDS = frozenset(
    [
        "get",
        "strlen",  # Authorization code version preflight bounds integer parsing.
        "set",
        "waitaof",  # Acknowledge this writer's post-work continuity seal in local AOF.
        "del",
        "exists",
        "expire",
        "pexpire",
        "ttl",
        "pttl",
        "time",  # DPoP nonce scripts use the store clock for finite rotation/expiry.
        "incr",
        "incrby",
        "decr",
        "decrby",
        "mget",
        "mset",
        "setex",
        "psetex",
        "setnx",
        "getdel",
        "getex",
        "ping",
        "echo",
        "select",
        "auth",
        "hello",
        "quit",
        "multi",
        "exec",
        "discard",
        "watch",
        "unwatch",
        "eval",
        "evalsha",
        "script|load",
        "script|exists",
        "client|info",
        "client|setname",
        "client|setinfo",
        "info",
        "unlink",
        "scan",
        "keys",
        "type",
        "hget",
        "hset",
        "hdel",
        "hexists",
        "hgetall",
        "hlen",
        "hmget",
        "hsetnx",
        "hincrby",
        "sadd",
        "srem",
        "smembers",
        "sismember",
        "scard",
        "zadd",
        "zrem",
        "zrange",
        "zrangebyscore",
        "zremrangebyscore",
        "zcard",
        "zscore",
        "zcount",
        "lpush",
        "rpush",
        "lpop",
        "rpop",
        "llen",
        "lrange",
    ]
)
MAX_CLIENTS = 1024
MAX_LOGINS = 64
DATABASE_COUNT = 16
PAIR_SIZE = 2


def pairs(value: list) -> dict[str, Any]:
    require(type(value) is list and len(value) % 2 == 0, "Redis field pairs required")
    result = dict(zip(value[::2], value[1::2], strict=True))
    require(len(result) * 2 == len(value), "duplicate Redis fields")
    return result


def info(value: str) -> dict[str, str]:
    rows = [line.split(":", 1) for line in value.splitlines() if line and not line.startswith("#")]
    require(all(len(row) == PAIR_SIZE for row in rows), "invalid Redis INFO")
    result = dict(rows)
    require(len(result) == len(rows), "duplicate Redis INFO field")
    return result


class RedisStore:
    def __init__(self, connection: Resp, identity: dict, administrator: str, old_logins: list[str]):
        self.connection = connection
        self.identity = identity
        self.administrator = administrator
        self.old_logins = old_logins
        require(
            set(identity) == {"run_id", "database"}
            and type(identity["database"]) is int
            and 0 <= identity["database"] < DATABASE_COUNT,
            "explicit token store identity required",
        )
        require(
            "default" in old_logins
            and administrator not in old_logins
            and 1 <= len(old_logins) <= MAX_LOGINS
            and len(set(old_logins)) == len(old_logins),
            "dedicated Redis login inventory required",
        )
        self.call("SELECT", str(identity["database"]))

    def call(self, *args: str) -> Any:
        return self.connection.call(*args)

    def check(self, *, excluded: bool = False) -> dict:
        observed = info(self.call("INFO", "server", "replication", "persistence", "cluster"))
        require(
            observed.get("run_id") == self.identity["run_id"]
            and observed.get("role") == "master"
            and observed.get("connected_slaves") == "0"
            and observed.get("cluster_enabled") == "0"
            and observed.get("loading") == "0"
            and observed.get("aof_enabled") == "1"
            and observed.get("aof_last_write_status") == "ok",
            "Redis identity, standalone primary or durable AOF differs",
        )
        config = pairs(self.call("CONFIG", "GET", "appendfsync", "aclfile", "databases"))
        modules = [pairs(module) for module in self.call("MODULE", "LIST")]
        # The pinned Redis 8 distribution registers vectorset internally. It has
        # no external path/arguments and none of its commands is allowed above.
        builtins = [{"name": "vectorset", "ver": 1, "path": "", "args": []}]
        require(
            config.get("appendfsync") == "always"
            and config.get("aclfile", "").startswith("/")
            and config.get("databases") == "16"
            and modules in ([], builtins),
            "Redis persistence or command supplier differs",
        )
        current = dict(field.split("=", 1) for field in self.call("CLIENT", "INFO").split())
        require(
            current.get("user") == self.administrator
            and current.get("db") == str(self.identity["database"]),
            "Redis recovery connection identity differs",
        )
        require(
            set(self.call("ACL", "USERS")) == {self.administrator, *self.old_logins},
            "unlisted Redis login",
        )
        admin = pairs(self.call("ACL", "GETUSER", self.administrator))
        require(
            "on" in admin["flags"] and "nopass" not in admin["flags"] and admin["passwords"],
            "authenticated separate Redis administrator required",
        )
        for name in self.old_logins:
            user = pairs(self.call("ACL", "GETUSER", name))
            require(not user["selectors"], "Redis ACL selectors are not a qualified worker")
            commands = user["commands"].split()
            require(
                commands
                and commands[0] == "-@all"
                and all(
                    item.startswith("+") and item[1:] in WORKER_COMMANDS for item in commands[1:]
                ),
                "old Redis login can escape credential exclusion",
            )
            if excluded:
                require(
                    "off" in user["flags"]
                    and "nopass" not in user["flags"]
                    and not user["passwords"]
                    and commands == ["-@all"]
                    and user["keys"] == ""
                    and user["channels"] == "",
                    "old Redis credentials remain usable",
                )
        return {
            "identity": self.identity,
            "administrator": self.administrator,
            "old_logins": self.old_logins,
        }

    def exclude(self) -> dict:
        self.check()
        for name in self.old_logins:
            require(self.call("ACL", "SETUSER", name, "reset") == "OK", "Redis reset refused")
        # Redis persists both the file and its containing directory before OK.
        # A missing reply retains uncertainty; no reconnect or re-enable follows.
        require(self.call("ACL", "SAVE") == "OK", "Redis ACL persistence unconfirmed")
        return self.check(excluded=True)

    def drain(self) -> dict:
        self.check(excluded=True)
        current = str(self.call("CLIENT", "ID"))
        before = self.clients()
        require(
            all(row["id"] == current or row["user"] in self.old_logins for row in before),
            "unexpected Redis client",
        )
        for name in self.old_logins:
            self.call("CLIENT", "KILL", "USER", name, "SKIPME", "yes")
        require(
            [row["id"] for row in self.clients()] == [current],
            "Redis clients remain after termination",
        )
        # Require the always-fsync supplier to have no unfinished persistence.
        # WAITAOF on this connection would not acknowledge other clients' writes.
        persistent = info(self.call("INFO", "persistence"))
        require(
            persistent.get("aof_pending_bio_fsync") == "0"
            and persistent.get("aof_buffer_length") == "0"
            and persistent.get("aof_rewrite_in_progress") == "0"
            and persistent.get("aof_last_write_status") == "ok",
            "Redis persistence completion unconfirmed",
        )
        self.check(excluded=True)
        return {
            "terminated_clients": [row["id"] for row in before if row["id"] != current],
            "clients_remaining": 1,
        }

    def clients(self) -> list[dict[str, str]]:
        rows = self.call("CLIENT", "LIST").splitlines()
        require(len(rows) <= MAX_CLIENTS, "Redis client inventory bound")
        result = [dict(field.split("=", 1) for field in row.split()) for row in rows]
        require(all("id" in row and "user" in row for row in result), "Redis clients incomplete")
        return result
