"""Compare native-validated independent history to all permanent primary facts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from organization_recovery_store import require

if TYPE_CHECKING:
    from organization_recovery_store import Store

PAGE = 256


def compare(control: Store, primary: Store, native: dict) -> dict:
    """Caller holds the exact drained deployment/child fence and disabled logins."""
    environment = native["environment_id"]
    current = control.one("SELECT organization_witness.history_progress(%s)", (environment,))
    require(current == native and current["sealed"], "native history head changed")
    counts = [0, 0]
    after = 0
    with primary.connection.transaction():
        primary.connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        primary.connection.execute("SET LOCAL statement_timeout='5s'")
        primary.connection.execute("SET LOCAL transaction_timeout='60s'")
        actual = primary.rows(
            "SELECT (SELECT count(*) FROM aegaeon.end_user_identity_owners "
            "WHERE environment_id=%s),"
            "(SELECT count(*) FROM aegaeon.end_user_subject_reservations WHERE environment_id=%s)",
            (environment, environment),
        )[0]
        require(
            actual == (native["owner_count"], native["subject_count"]),
            "primary permanent history counts differ",
        )
        while after < native["sequence"]:
            entries = control.rows(
                "SELECT sequence,kind,owner_id::text,subject FROM "
                "organization_witness.history_entries "
                "WHERE environment_id=%s AND sequence>%s ORDER BY sequence LIMIT %s",
                (environment, after, PAGE),
            )
            require(entries and len(entries) <= native["sequence"] - after, "history page absent")
            require(
                [row[0] for row in entries] == list(range(after + 1, after + len(entries) + 1)),
                "history sequence changed",
            )
            owners = [row[2] for row in entries if row[1] == 0]
            subjects = [(row[3], row[2]) for row in entries if row[1] == 1]
            require(len(owners) + len(subjects) == len(entries), "unknown history entry")
            present = primary.one(
                "SELECT count(*) FROM unnest(%s::uuid[]) e(id) "
                "JOIN aegaeon.end_user_identity_owners o "
                "ON o.owner_id=e.id AND o.environment_id=%s",
                (owners, environment),
            )
            require(present == len(owners), "independent owner missing from primary")
            present = primary.one(
                "SELECT count(*) FROM unnest(%s::text[],%s::uuid[]) e(subject,owner) "
                "JOIN aegaeon.end_user_subject_reservations r ON r.environment_id=%s "
                'AND r.subject=e.subject COLLATE "C" AND r.owner_id=e.owner',
                ([s[0] for s in subjects], [s[1] for s in subjects], environment),
            )
            require(present == len(subjects), "independent subject differs from primary")
            counts[0] += len(owners)
            counts[1] += len(subjects)
            after += len(entries)
        require(
            counts == [native["owner_count"], native["subject_count"]], "history totals changed"
        )
    require(
        control.one("SELECT organization_witness.history_progress(%s)", (environment,)) == native,
        "history changed during primary comparison",
    )
    return {
        "environmentId": environment,
        "sequence": after,
        "historySha256": native["digest"],
        "owners": counts[0],
        "subjects": counts[1],
        "completePermanentFactsCompared": True,
        "completeAuthorizationStateCompared": False,
        "activationAuthorized": False,
    }
