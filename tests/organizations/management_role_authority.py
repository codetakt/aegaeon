"""Real PostgreSQL restrictions for serving and deployment-bootstrap identities."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

FILE_FUNCTIONS = (
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_import",
    "lo_export",
)
HOST_ROLES = ("pg_read_server_files", "pg_write_server_files", "pg_execute_server_program")


@dataclass(frozen=True)
class Case:
    name: str
    kind: str
    changes: tuple[tuple[sql.Composable, sql.Composable], ...]


def membership(group, member, options):
    return (
        sql.SQL("GRANT {} TO {} WITH " + options).format(
            sql.Identifier(group), sql.Identifier(member)
        ),
        sql.SQL("REVOKE {} FROM {} GRANTED BY postgres CASCADE").format(
            sql.Identifier(group), sql.Identifier(member)
        ),
    )


def privilege(object_type, object_name, rights, member):
    grantee = sql.SQL("PUBLIC") if member == "PUBLIC" else sql.Identifier(member)
    return (
        sql.SQL("GRANT " + rights + " ON " + object_type + " {} TO {}").format(
            object_name, grantee
        ),
        sql.SQL("REVOKE " + rights + " ON " + object_type + " {} FROM {}").format(
            object_name, grantee
        ),
    )


def projection(db):
    """Compare only non-secret authority state; never serialize cursor keys or credentials."""
    return db.execute(
        "SELECT jsonb_build_object("
        "'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY "
        "roleid,member,grantor) FROM pg_auth_members m),"
        "'grants',(SELECT "
        "jsonb_agg(jsonb_build_array(id,revision,delegation_epoch,revoked_at) ORDER BY id) "
        "FROM management_authority.grants),"
        "'receipts',(SELECT "
        "jsonb_agg(jsonb_build_array(operation_id,caller_role_oid) ORDER BY operation_id) "
        "FROM management_authority.operation_receipts),"
        "'selectors',(SELECT jsonb_agg(jsonb_build_array(id,state) ORDER BY id) "
        "FROM management_authority.selectors),"
        "'audit',(SELECT count(*) FROM management_authority.audit_events),"
        "'credentials',(SELECT jsonb_agg(jsonb_build_array(role_oid,enabled) ORDER BY role_oid) "
        "FROM management_authority.bootstrap_credentials))"
    ).fetchone()[0]


def acl_projection(db):
    return db.execute(
        "SELECT jsonb_build_object("
        "'functions',(SELECT jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,"
        "coalesce(p.proacl,acldefault('f',p.proowner))::text) ORDER BY p.oid) "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='management_authority' OR "
        "(n.nspname='pg_catalog' AND p.proname=ANY(%s))),"
        "'tables',(SELECT jsonb_agg(jsonb_build_array(c.oid,"
        "coalesce(c.relacl,acldefault('r',c.relowner))::text) ORDER BY c.oid) "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='management_authority' AND c.relkind IN ('r','p','v')),"
        "'columns',(SELECT jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attacl::text) "
        "ORDER BY a.attrelid,a.attnum) FROM pg_attribute a "
        "JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='management_authority' AND cardinality(a.attacl)>0),"
        "'parameters',(SELECT jsonb_agg(jsonb_build_array(parname,paracl::text) ORDER BY parname) "
        "FROM pg_parameter_acl WHERE cardinality(paracl)>0))",
        (list(FILE_FUNCTIONS),),
    ).fetchone()[0]


def capability_projection(db, actor):
    return db.execute(
        "SELECT jsonb_build_object("
        "'roles',(SELECT jsonb_agg(jsonb_build_array(r.rolname,"
        "pg_has_role(%s,r.oid,'MEMBER'),pg_has_role(%s,r.oid,'USAGE'),"
        "pg_has_role(%s,r.oid,'SET'),pg_has_role(%s,r.oid,'MEMBER WITH ADMIN "
        "OPTION')) ORDER BY r.rolname) "
        "FROM pg_roles r WHERE pg_has_role(%s,r.oid,'MEMBER')),"
        "'file_functions',(SELECT jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,"
        "has_function_privilege(%s,p.oid,'EXECUTE')) ORDER BY p.oid::regprocedure::text) "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='pg_catalog' AND p.proname=ANY(%s)),"
        "'replication_parameter',has_parameter_privilege(%s,'session_replication_role','SET'))",
        (actor, actor, actor, actor, actor, actor, list(FILE_FUNCTIONS), actor),
    ).fetchone()[0]


def entry(url, kind, request):
    function = "inventory_v1" if kind == "management" else "bootstrap_v1"
    try:
        with psycopg.connect(url, autocommit=True) as db, db.transaction():
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            db.execute("SET LOCAL statement_timeout='10s'")
            result = db.execute(
                sql.SQL("SELECT management_authority.{}(%s)").format(sql.Identifier(function)),
                (Jsonb(request),),
            ).fetchone()[0]
    except psycopg.Error as error:
        return {
            "accepted": False,
            "sqlstate": error.sqlstate,
            "message": error.diag.message_primary,
        }
    else:
        return {"accepted": True, "result": result}


def bootstrap_request(db, principal):
    installation = db.execute("SELECT id FROM management_authority.installation").fetchone()[0]
    return {
        "installation_id": str(installation),
        "operation_id": str(uuid.uuid4()),
        "grant_id": str(uuid.uuid4()),
        "principal_id": str(principal),
        "principal_kind": "HUMAN",
        "adopt_installation": True,
        "permanent": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "conditions": {},
        "use_selector": {
            "id": str(uuid.uuid4()),
            "mode": "current_and_future_descendants",
            "anchor_kind": "installation",
            "anchor_id": str(installation),
        },
        "use_actions": {
            "policy": "enumerated",
            "registry_version": 1,
            "actions": ["inventory.teams.read"],
        },
    }


def valid_requests(db, urls):
    principal = uuid.uuid4()
    db.execute(
        "INSERT INTO aegaeon.administrators(id,email,password_hash,kind) "
        "VALUES(%s,%s,'fixture','HUMAN')",
        (principal, str(principal) + "@example.invalid"),
    )
    root = bootstrap_request(db, principal)
    first = entry(urls["bootstrap"], "bootstrap", root)
    assert first["accepted"], first
    assert entry(urls["bootstrap"], "bootstrap", root) == first
    namespace = "authority-probe-" + uuid.uuid4().hex
    digest = hashlib.sha256(namespace.encode()).digest()
    db.execute(
        "INSERT INTO aegaeon.runtime_management_session_scopes(namespace) VALUES(%s)", (namespace,)
    )
    db.execute(
        "INSERT INTO aegaeon.runtime_management_sessions "
        "(namespace,token_digest,administrator_id,created_at_epoch_secs,expires_at) "
        "VALUES(%s,%s,%s,floor(extract(epoch FROM "
        "clock_timestamp()))::bigint,clock_timestamp()+interval '1 hour')",
        (namespace, digest, principal),
    )
    inventory = {
        "installation_id": root["installation_id"],
        "grant_id": root["grant_id"],
        "resource_kind": "team",
        "limit": 1,
        "credential": {
            "kind": "HUMAN",
            "namespace": namespace,
            "digest": digest.hex(),
            "session_ttl_seconds": 3600,
        },
    }
    initial_inventory = entry(urls["management"], "management", inventory)
    assert initial_inventory["accepted"], initial_inventory
    return principal, inventory


def role_cases(kind, actor, bridges):
    bridge, _inherited, ordinary = bridges
    for group in HOST_ROLES:
        for suffix, options in (
            ("inherit", "ADMIN FALSE, INHERIT TRUE, SET FALSE"),
            ("set", "ADMIN FALSE, INHERIT FALSE, SET TRUE"),
            ("admin_only", "ADMIN TRUE, INHERIT FALSE, SET FALSE"),
            ("inactive", "ADMIN FALSE, INHERIT FALSE, SET FALSE"),
        ):
            yield Case(
                kind + ":" + group + ":" + suffix, kind, (membership(group, actor, options),)
            )
        for suffix, first in (
            ("indirect", "INHERIT TRUE, SET FALSE"),
            ("mixed", "INHERIT FALSE, SET TRUE"),
        ):
            yield Case(
                kind + ":" + group + ":" + suffix,
                kind,
                (
                    membership(bridge, actor, first),
                    membership(group, bridge, "INHERIT TRUE, SET FALSE"),
                ),
            )
    yield Case(
        kind + ":ordinary_admin:direct",
        kind,
        (membership(ordinary, actor, "ADMIN TRUE, INHERIT FALSE, SET FALSE"),),
    )
    for suffix, options in (
        ("indirect", "INHERIT TRUE, SET FALSE"),
        ("inactive", "INHERIT FALSE, SET FALSE"),
    ):
        yield Case(
            kind + ":ordinary_admin:" + suffix,
            kind,
            (
                membership(bridge, actor, options),
                membership(ordinary, bridge, "ADMIN TRUE, INHERIT FALSE, SET FALSE"),
            ),
        )


def function_cases(kind, actor, bridges, functions):
    bridge, inherited, _ordinary = bridges
    for _name, signature in functions:
        yield Case(
            kind + ":execute:" + signature,
            kind,
            (privilege("FUNCTION", sql.SQL(signature), "EXECUTE", actor),),
        )
    for function in FILE_FUNCTIONS:
        signature = next(signature for name, signature in functions if name == function)
        yield Case(
            kind + ":mixed_execute:" + signature,
            kind,
            (
                membership(bridge, actor, "INHERIT FALSE, SET TRUE"),
                membership(inherited, bridge, "INHERIT TRUE, SET FALSE"),
                privilege("FUNCTION", sql.SQL(signature), "EXECUTE", inherited),
            ),
        )
    for signature in ("pg_read_file(text)", "lo_export(oid,text)"):
        yield Case(
            kind + ":public_execute:" + signature,
            kind,
            (privilege("FUNCTION", sql.SQL(signature), "EXECUTE", "PUBLIC"),),
        )


def parameter_cases(kind, actor, bridges):
    bridge, inherited, _ordinary = bridges
    for pattern in ("direct", "mixed", "public"):
        changes = []
        target = actor if pattern == "direct" else "PUBLIC"
        if pattern == "mixed":
            changes.extend(
                (
                    membership(bridge, actor, "INHERIT FALSE, SET TRUE"),
                    membership(inherited, bridge, "INHERIT TRUE, SET FALSE"),
                )
            )
            target = inherited
        changes.append(
            privilege("PARAMETER", sql.Identifier("session_replication_role"), "SET", target)
        )
        yield Case(kind + ":replication_parameter:" + pattern, kind, tuple(changes))


def table_cases(kind, actor, bridges):
    bridge, inherited, _ordinary = bridges
    for right in ("SELECT", "SELECT (id)", "UPDATE", "UPDATE (adopted_at)"):
        yield Case(
            kind + ":table:" + right,
            kind,
            (
                privilege(
                    "TABLE", sql.Identifier("management_authority", "installation"), right, actor
                ),
            ),
        )
    for right in ("SELECT", "SELECT (id)"):
        yield Case(
            kind + ":mixed_table:" + right,
            kind,
            (
                membership(bridge, actor, "INHERIT FALSE, SET TRUE"),
                membership(inherited, bridge, "INHERIT TRUE, SET FALSE"),
                privilege(
                    "TABLE",
                    sql.Identifier("management_authority", "installation"),
                    right,
                    inherited,
                ),
            ),
        )
    forbidden = "inventory_v1" if kind == "bootstrap" else "bootstrap_v1"
    yield Case(
        kind + ":other_entry",
        kind,
        (
            privilege(
                "FUNCTION",
                sql.SQL("management_authority." + forbidden + "(jsonb)"),
                "EXECUTE",
                actor,
            ),
        ),
    )


def function_inventory(db):
    functions = db.execute(
        "SELECT p.proname,p.oid::regprocedure::text FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='pg_catalog' "
        "AND p.proname=ANY(%s) ORDER BY p.proname,p.oid::regprocedure::text",
        (list(FILE_FUNCTIONS),),
    ).fetchall()
    assert {name for name, _ in functions} == set(FILE_FUNCTIONS)
    assert 6 <= len(functions) <= 32, "bounded built-in overload inventory"
    return functions


def cases(db, names, bridges):
    functions = function_inventory(db)
    records = []
    for kind in ("management", "bootstrap"):
        actor = names[kind]
        records.extend(role_cases(kind, actor, bridges))
        records.extend(function_cases(kind, actor, bridges, functions))
        records.extend(parameter_cases(kind, actor, bridges))
        records.extend(table_cases(kind, actor, bridges))
    records.extend(
        Case(
            "bootstrap:owner_or_database_admin:" + group,
            "bootstrap",
            (membership(group, names["bootstrap"], "INHERIT TRUE, SET TRUE"),),
        )
        for group in ("aegaeon_management_authority_owner", names["migration"])
    )
    # A non-superuser creator already holds ADMIN membership in the bootstrap
    # login. Granting the creator back to that login would form a role cycle.
    # Exercise database-administration attributes through an independent role.
    records.append(
        Case(
            "bootstrap:owner_or_database_admin:independent_createdb",
            "bootstrap",
            (
                (
                    sql.SQL("ALTER ROLE {} CREATEDB").format(sql.Identifier(bridges[2])),
                    sql.SQL("ALTER ROLE {} NOCREATEDB").format(sql.Identifier(bridges[2])),
                ),
                membership(bridges[2], names["bootstrap"], "INHERIT TRUE, SET TRUE"),
            ),
        )
    )
    assert len({case.name for case in records}) == len(records)
    return records, [signature for _, signature in functions]


@dataclass(frozen=True)
class Context:
    fixture: object
    names: dict
    actor_url: str
    urls: dict
    provision: object


def observe_case(db, case, context, requests):
    """Return actual outcomes; caller assertions decide whether they meet policy."""
    before_members = db.execute(
        "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
        "FROM pg_auth_members ORDER BY roleid,member,grantor"
    ).fetchall()
    before_acl = acl_projection(db)
    role_attributes = (
        "SELECT oid,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls "
        "FROM pg_roles ORDER BY oid"
    )
    before_attributes = db.execute(role_attributes).fetchall()
    applied = []
    try:
        for change in case.changes:
            db.execute(change[0])
            applied.append(change)
        injected = projection(db)
        capabilities = capability_projection(db, context.names[case.kind])
        capabilities["acl_rows"] = acl_projection(db)
        capabilities["role_attributes"] = db.execute(role_attributes).fetchall()
        result = context.provision(context.fixture, context.names, context.actor_url)
        provision_unchanged = projection(db) == injected
        before_entry = projection(db)
        observed = entry(context.urls[case.kind], case.kind, requests[case.kind])
        return {
            "case": case.name,
            "capabilities": capabilities,
            "provision": {
                "returncode": result.returncode,
                "unchanged": provision_unchanged,
                "message": result.stderr,
            },
            "entry": observed,
            "entry_state_unchanged": projection(db) == before_entry,
        }
    finally:
        for _, revoke in reversed(applied):
            db.execute(revoke)
        assert (
            db.execute(
                "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
                "FROM pg_auth_members ORDER BY roleid,member,grantor"
            ).fetchall()
            == before_members
        )

        assert acl_projection(db) == before_acl, "owned injection cleanup changed ACLs"
        assert db.execute(role_attributes).fetchall() == before_attributes


def verify_cases(db, context, principal, inventory, selected):
    records = {}
    for case in selected:
        requests = {"management": inventory, "bootstrap": bootstrap_request(db, principal)}
        observed = observe_case(db, case, context, requests)
        assert observed["provision"]["returncode"] != 0, observed
        assert observed["provision"]["unchanged"], observed
        assert not observed["entry"]["accepted"], observed
        assert observed["entry"]["sqlstate"] == "42501", observed
        assert observed["entry_state_unchanged"], observed
        assert context.provision(context.fixture, context.names, context.actor_url).returncode == 0
        recovered = entry(context.urls[case.kind], case.kind, requests[case.kind])
        assert recovered["accepted"], recovered
        if case.kind == "bootstrap":
            assert entry(context.urls[case.kind], case.kind, requests[case.kind]) == recovered
        observed["recovery"] = {"accepted": True, "replay_checked": case.kind == "bootstrap"}
        records[case.name] = observed
    assert len(records) == len(selected)
    return records


def verify_management_role_authority(fixture, names, url, directory, provision):
    """Called by the existing real restricted PostgreSQL suite in both configurations."""
    suppliers = json.loads((directory / "suppliers.json").read_text())
    urls = suppliers["urls"]
    migrated = url.replace("/postgres?", "/" + names["database"] + "?")
    actor_url = migrated.replace("postgres@", "fixture_dba@")
    bridges = ["authority_probe_" + uuid.uuid4().hex for _ in range(3)]
    records = {}
    with psycopg.connect(migrated, autocommit=True) as db:
        for bridge in bridges:
            db.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(bridge)))
        try:
            principal, inventory = valid_requests(db, urls)
            selected, functions = cases(db, names, bridges)
            # These rows represent memberships without authority; they remain usable.
            harmless = membership(
                bridges[2], names["management"], "ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )
            db.execute(harmless[0])
            try:
                assert provision(fixture, names, actor_url).returncode == 0
                assert entry(urls["management"], "management", inventory)["accepted"]
            finally:
                db.execute(harmless[1])
            context = Context(fixture, names, actor_url, urls, provision)
            records.update(verify_cases(db, context, principal, inventory, selected))
            records["builtin_overload_inventory"] = functions
        finally:
            for bridge in reversed(bridges):
                db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(bridge)))
    return records


def verify_pre_migration_authority(db, fixture, names, actor_url, provision):
    bridges = ["authority_pre_" + uuid.uuid4().hex for _ in range(3)]
    records = {}
    for bridge in bridges:
        db.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(bridge)))
    try:
        functions = function_inventory(db)
        selected = []
        for kind in ("management", "bootstrap"):
            selected.extend(role_cases(kind, names[kind], bridges))
            selected.extend(function_cases(kind, names[kind], bridges, functions))
            selected.extend(parameter_cases(kind, names[kind], bridges))
        for case in selected:
            records["before_migration:" + case.name] = pre_migration_case(
                db, case, Context(fixture, names, actor_url, {}, provision)
            )
    finally:
        for bridge in reversed(bridges):
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(bridge)))
    return records


def pre_migration_case(db, case, context):
    before_acl = acl_projection(db)
    before = db.execute(
        "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
        "FROM pg_auth_members ORDER BY roleid,member,grantor"
    ).fetchall()
    applied = []
    try:
        for change in case.changes:
            db.execute(change[0])
            applied.append(change)
        injected = db.execute(
            "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
            "FROM pg_auth_members ORDER BY roleid,member,grantor"
        ).fetchall()
        injected_acl = acl_projection(db)
        result = context.provision(context.fixture, context.names, context.actor_url)
        assert result.returncode != 0, (case.name, "unsafe pre-migration principal accepted")
        assert (
            db.execute(
                "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
                "FROM pg_auth_members ORDER BY roleid,member,grantor"
            ).fetchall()
            == injected
        )
        assert acl_projection(db) == injected_acl
        assert db.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname IN "
            "('aegaeon_management_authority_owner','aegaeon_management_bootstrap')"
        ).fetchone() == (0,)
        return {
            "case": case.name,
            "refused": True,
            "atomic": True,
            "capabilities": capability_projection(db, context.names[case.kind]),
        }
    finally:
        for _, revoke in reversed(applied):
            db.execute(revoke)
        assert (
            db.execute(
                "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
                "FROM pg_auth_members ORDER BY roleid,member,grantor"
            ).fetchall()
            == before
        )
        assert acl_projection(db) == before_acl
