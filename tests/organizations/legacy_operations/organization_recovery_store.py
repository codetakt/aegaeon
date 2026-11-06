"""Offline SQL recovery primitives; never usable with runtime credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from psycopg import sql

if TYPE_CHECKING:
    from psycopg import Connection


class RecoveryRefusedError(Exception):
    """A recovery prerequisite is absent; retain pending state and exclusions."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise RecoveryRefusedError(message)


class Store:
    def __init__(
        self, connection: Connection, identity: dict[str, Any], old_logins: list[str]
    ) -> None:
        self.connection = connection
        self.identity = identity
        self.old_logins = old_logins

    def rows(self, query: str, arguments: tuple = ()) -> list[tuple]:
        return self.connection.execute(query, arguments).fetchall()

    def one(self, query: str, arguments: tuple = ()) -> Any:
        return self.rows(query, arguments)[0][0]

    def check(self, *, excluded: bool = False) -> dict[str, Any]:
        observed = self.one(
            "SELECT jsonb_build_object('cluster',system_identifier::text,"
            "'database',current_database(),'database_oid',"
            "(SELECT oid::bigint FROM pg_database WHERE datname=current_database())) "
            "FROM pg_control_system()"
        )
        require(observed == self.identity, "SQL store identity differs")
        require(
            not self.one(
                "SELECT EXISTS(SELECT FROM pg_database WHERE NOT datistemplate "
                "AND datname NOT IN (current_database(),'postgres'))"
            ),
            "shared SQL cluster is not an offline recovery target",
        )
        require(
            self.one(
                "SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' "
                "AND current_setting('full_page_writes')='on' "
                "AND current_setting('synchronous_commit')='on' "
                "AND current_setting('transaction_isolation')='read committed' "
                "AND current_setting('transaction_read_only')='off' "
                "AND current_user=session_user AND "
                "(SELECT rolsuper FROM pg_roles WHERE rolname=session_user)"
            ),
            "separate durable offline administrator required",
        )
        admin = self.one("SELECT session_user::text")
        require(admin not in self.old_logins, "recovery credential belongs to old workers")
        # A dedicated cluster has no unlisted login or alternate worker principal.
        allowed = [admin, *self.old_logins]
        require(
            not self.one(
                "SELECT EXISTS(SELECT FROM pg_roles WHERE rolcanlogin AND NOT rolname=ANY(%s))",
                (allowed,),
            ),
            "unlisted login in dedicated store",
        )
        roles = self.rows(
            "SELECT r.rolname::text,r.rolcanlogin,r.rolpassword IS NULL,"
            "r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls "
            "OR EXISTS(SELECT FROM pg_roles p WHERE "
            "(p.rolsuper OR p.rolcreaterole OR p.rolcreatedb OR p.rolreplication OR p.rolbypassrls "
            "OR p.rolname IN ('pg_execute_server_program','pg_write_server_files',"
            "'pg_read_server_files','pg_signal_backend')) "
            "AND pg_has_role(r.oid,p.oid,'MEMBER')) "
            "FROM pg_authid r WHERE r.rolname=ANY(%s) ORDER BY r.rolname",
            (self.old_logins,),
        )
        require(len(roles) == len(self.old_logins), "old login inventory differs")
        require(not any(row[3] for row in roles), "old login can escape credential exclusion")
        if excluded:
            require(all(not row[1] and row[2] for row in roles), "old credentials remain usable")
        require(
            not self.one("SELECT EXISTS(SELECT FROM pg_prepared_xacts)"),
            "prepared SQL transaction remains",
        )
        return {"identity": observed, "administrator": admin, "old_logins": self.old_logins}

    def exclude(self) -> dict[str, Any]:
        # Commit independently of the control CAS; a failed recovery NEVER undoes
        # an acknowledged credential exclusion on a previously visited store.
        with self.connection.transaction():
            for name in self.old_logins:
                self.connection.execute(
                    sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD NULL").format(sql.Identifier(name))
                )
        return self.check(excluded=True)

    def drain(self) -> dict[str, Any]:
        self.check(excluded=True)
        self.connection.execute("SELECT pg_stat_clear_snapshot()")
        backends = self.rows(
            "SELECT pid,usename::text FROM pg_stat_activity "
            "WHERE backend_type='client backend' AND pid<>pg_backend_pid()"
        )
        require(all(name in self.old_logins for _, name in backends), "unexpected client backend")
        for pid, _ in backends:
            # A positive timeout waits for actual exit, not signal delivery.
            require(
                self.one("SELECT pg_terminate_backend(%s,5000)", (pid,)),
                "old backend termination unconfirmed",
            )
        self.connection.execute("SELECT pg_stat_clear_snapshot()")
        require(
            not self.one(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE backend_type='client backend' "
                "AND pid<>pg_backend_pid())"
            ),
            "SQL clients remain after termination",
        )
        self.check(excluded=True)
        return {"terminated_backends": [pid for pid, _ in backends], "clients_remaining": 0}


def fence(control: Store, deployment: str) -> None:
    row = control.rows(
        "SELECT phase FROM organization_witness.deployments WHERE deployment_id=%s FOR UPDATE",
        (deployment,),
    )
    require(row == [("fenced",)], "deployment is not fenced")
    control.rows(
        "SELECT environment_id FROM organization_witness.authorities "
        "WHERE deployment_id=%s ORDER BY environment_id FOR UPDATE",
        (deployment,),
    )
    require(
        not control.one(
            "SELECT EXISTS(SELECT FROM organization_witness.deployment_slots "
            "WHERE deployment_id=%s AND pending) "
            "OR EXISTS(SELECT FROM organization_witness.authorities "
            "WHERE deployment_id=%s AND phase<>'fenced') "
            "OR EXISTS(SELECT FROM organization_witness.slots s "
            "JOIN organization_witness.authorities a USING(environment_id) "
            "WHERE a.deployment_id=%s AND s.pending)",
            (deployment, deployment, deployment),
        ),
        "runtime ownership or non-fenced child remains",
    )


def selected(control: Store, expected: dict[str, Any]) -> dict[str, Any]:
    rows = control.rows(
        "SELECT to_jsonb(s) FROM organization_witness.maintenance_slots s "
        "WHERE deployment_id=%s FOR UPDATE",
        (expected["deployment_id"],),
    )
    require(len(rows) == 1, "maintenance owner missing")
    state = rows[0][0]
    require(
        all(state.get(key) == value for key, value in expected.items()),
        "maintenance generation or plan differs",
    )
    require(state["principal"] in control.old_logins, "pending owner not excluded by inventory")
    require(state["kind"] != "schema-migration", "arbitrary migration work cannot be reconciled")
    return state


def clear(control: Store, expected: dict[str, Any], digest: str) -> dict[str, Any]:
    fence(control, expected["deployment_id"])
    state = selected(control, expected)
    if not state["pending"]:
        require(state["completion_sha256"] == digest, "recovery completion differs")
        return state
    return control.one(
        "UPDATE organization_witness.maintenance_slots SET pending=false,completion_sha256=%s "
        "WHERE deployment_id=%s AND generation=%s AND work_id=%s AND plan_sha256=%s AND pending "
        "RETURNING to_jsonb(maintenance_slots)",
        (
            digest,
            expected["deployment_id"],
            expected["generation"],
            expected["work_id"],
            expected["plan_sha256"],
        ),
    )
