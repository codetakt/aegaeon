"""Bounded exact primary content comparison; no activation or credential output."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from organization_recovery_store import require
from psycopg import sql

if TYPE_CHECKING:
    from psycopg import Connection

POSTGRESQL_MAJOR = 18
MAX_RELATIONS = 512
MAX_COLUMNS = 1024
MAX_ROWS = 1_000_000
MAX_ROW_BYTES = 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024**3
SCHEMAS = ("aegaeon", "public", "aegaeon_lifecycle")


def encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def inventory(connection: Connection) -> list[tuple]:
    require(
        not connection.execute(
            "SELECT EXISTS(SELECT FROM pg_namespace WHERE "
            "nspname !~ '^pg_' AND nspname<>'information_schema' AND NOT nspname=ANY(%s)) "
            "OR EXISTS(SELECT FROM pg_largeobject_metadata)",
            (list(SCHEMAS),),
        ).fetchone()[0],
        "unsupported schema or large object in primary",
    )
    rows = connection.execute(
        "SELECT n.nspname::text,c.relname::text,c.relkind::text,c.relpersistence::text "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=ANY(%s) AND c.relkind NOT IN ('i','I','v','c') "
        'ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C" LIMIT %s',
        (list(SCHEMAS), MAX_RELATIONS + 1),
    ).fetchall()
    require(0 < len(rows) <= MAX_RELATIONS, "primary relation budget exceeded or empty")
    require(
        all(kind in ("r", "p", "S") and persistence == "p" for _, _, kind, persistence in rows),
        "unsupported primary relation or persistence",
    )
    return rows


def columns(connection: Connection, schema: str, table: str) -> list:
    rows = connection.execute(
        "SELECT a.attname::text,format_type(a.atttypid,a.atttypmod),a.attnotnull,"
        "a.attidentity::text,a.attgenerated::text,cn.nspname::text,co.collname::text "
        "FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "LEFT JOIN pg_collation co ON co.oid=a.attcollation "
        "LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace "
        "WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped "
        "ORDER BY a.attnum LIMIT %s",
        (schema, table, MAX_COLUMNS + 1),
    ).fetchall()
    require(0 < len(rows) <= MAX_COLUMNS, "primary column budget exceeded or empty")
    return rows


def table_content(connection: Connection, schema: str, table: str, budget: list[int]) -> dict:
    column_list = columns(connection, schema, table)
    digest = hashlib.sha256(b"aegaeon-primary-content-v1\0" + encoded(column_list))
    statement = sql.SQL(
        "SELECT octet_length(convert_to(value,'UTF8')),"
        "substring(convert_to(value,'UTF8') FROM 1 FOR %s) "
        "FROM (SELECT to_jsonb(t)::text AS value FROM ONLY {} t) rows "
        'ORDER BY value COLLATE "C"'
    ).format(sql.Identifier(schema, table))
    count = 0
    # Server-side iteration never loads a complete table into the operator.
    with connection.cursor(name="aegaeon_restore_rows", binary=True) as cursor:
        cursor.itersize = 1
        cursor.execute(statement, (MAX_ROW_BYTES,))
        for size, payload in cursor:
            require(size <= MAX_ROW_BYTES and len(payload) == size, "primary row byte budget")
            count += 1
            budget[0] += size
            require(count <= MAX_ROWS, "primary row count budget")
            require(budget[0] <= MAX_DATABASE_BYTES, "primary database byte budget")
            digest.update(size.to_bytes(8, "big"))
            digest.update(payload)
    return {"columns": column_list, "count": count, "sha256": digest.hexdigest()}


def sequence_content(connection: Connection, schema: str, name: str) -> dict:
    definition = connection.execute(
        "SELECT format_type(s.seqtypid,NULL),s.seqstart,s.seqincrement,s.seqmax,s.seqmin,"
        "s.seqcache,s.seqcycle FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s",
        (schema, name),
    ).fetchone()
    value = connection.execute(
        sql.SQL("SELECT last_value,is_called FROM {}").format(sql.Identifier(schema, name))
    ).fetchone()
    require(definition is not None and value is not None, "sequence disappeared")
    return {"definition": definition, "value": value}


def observe(connection: Connection) -> dict:
    """Caller owns the offline store; this function closes its read-only snapshot."""
    require(connection.autocommit, "unowned outer transaction refused")
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        connection.execute(
            "SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'; "
            "SET LOCAL DateStyle='ISO, YMD'; SET LOCAL IntervalStyle='postgres'; "
            "SET LOCAL bytea_output='hex'; SET LOCAL extra_float_digits=3; "
            "SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='5s'; "
            "SET LOCAL transaction_timeout='600s'; SET LOCAL work_mem='4MB'; "
            "SET LOCAL temp_file_limit='1GB'; SET LOCAL row_security=off"
        )
        settings = connection.execute(
            "SELECT current_setting('server_version_num')::int/10000,"
            "current_setting('server_encoding'),datcollate,datctype,datlocprovider::text,"
            "datlocale FROM pg_database WHERE datname=current_database()"
        ).fetchone()
        require(
            settings[0] == POSTGRESQL_MAJOR and settings[1] == "UTF8", "PostgreSQL 18 UTF8 required"
        )
        relations = inventory(connection)
        result: dict = {"version": 1, "database": settings, "relations": []}
        budget = [0]
        for schema, name, kind, _ in relations:
            content = (
                sequence_content(connection, schema, name)
                if kind == "S"
                else table_content(connection, schema, name, budget)
            )
            result["relations"].append(
                {"schema": schema, "name": name, "kind": kind, "content": content}
            )
        result["bytes"] = budget[0]
        return result


def compare(source: Connection, target: Connection) -> dict:
    before = observe(source)
    after = observe(target)
    require(before == after, "restored primary content differs from current source")
    return {
        "version": 1,
        "contentSha256": hashlib.sha256(encoded(before)).hexdigest(),
        "relations": len(before["relations"]),
        "rows": sum(r["content"].get("count", 0) for r in before["relations"]),
        "bytes": before["bytes"],
        "activationAuthorized": False,
    }
