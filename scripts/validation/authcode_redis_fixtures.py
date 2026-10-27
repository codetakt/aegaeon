"""Translate shared finite Redis grant fixtures into F* case obligations.

The numeric/string/cjson adapter is explicitly outside the proof claim. Every
case is checked against the unmodified production Lua by the companion runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/authcode-redis-grant.json"
MODEL = ROOT / "fstar/authcode/AuthCode.RedisGrant.fst"
GENERATED = ROOT / "tests/fstar/property/TestAuthCodeRedisGrant.fst"
LUA_SOURCE = ROOT / "crates/server/src/authcode/store/redis_backend/scripts.rs"
GRANT_SOURCE = LUA_SOURCE.with_name("refresh_grants.rs")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def load_cases(content: bytes | None = None) -> list[dict[str, Any]]:
    document = json.loads(FIXTURE.read_bytes() if content is None else content)
    if document["version"] != 2 or not document["cases"]:
        raise ValueError("unknown or empty fixture selection")
    cases: list[dict[str, Any]] = document["cases"]
    names = [case["name"] for case in cases]
    if len(names) != len(set(names)):
        raise ValueError("duplicate fixture identity")
    for case in cases:
        if not case["requests"] or len(case["requests"]) != len(case["expected_replies"]):
            raise ValueError("incomplete trace")
        for request in case["requests"]:
            if len(request["keys"]) != 21 or len(request["args"]) != 29:
                raise ValueError("invalid key/argument plan")
            if not all(isinstance(v, str) for v in request["keys"] + request["args"]):
                raise ValueError("non-string Redis input")
            if any(not key.startswith("t:") for key in request["keys"]):
                raise ValueError("fixture outside isolated keyspace")
            expired_in_window(request)
    return cases


def expired_in_window(request: dict[str, Any]) -> bool:
    """Supply the clock predicate only when it is constant over a checked window.

    The runner checks Redis TIME before/after each invocation against this window.
    This is an explicit adapter premise, not a proof of wall-clock scheduling.
    """
    low, high = request["clock_window_ns"]
    if type(low) is not int or type(high) is not int or not 0 <= low <= high:
        raise ValueError("invalid clock window")
    seconds, nanos = request["args"][27:29]
    if not re.fullmatch(r"0|[1-9][0-9]*", seconds) or not re.fullmatch(r"0|[1-9][0-9]*", nanos):
        raise ValueError("outside canonical deadline domain")
    if int(nanos) >= 1_000_000_000:
        raise ValueError("invalid nanoseconds")
    deadline = int(seconds) * 1_000_000_000 + int(nanos)
    if (low >= deadline) != (high >= deadline):
        raise ValueError("clock window crosses deadline")
    return low >= deadline


def lua_script(source: str | None = None, grant_source: str | None = None) -> str:
    if source is None:
        source = LUA_SOURCE.read_text()
    matches: list[str] = re.findall(
        r'const COMMIT_AUTHORIZATION_CODE_GRANT: &str = r#"(.*?)"#;', source, re.DOTALL
    )
    if len(matches) != 1:
        raise ValueError("expected one production authorization grant script")
    if grant_source is None:
        grant_source = GRANT_SOURCE.read_text()
    prefixes: list[str] = re.findall(r'const PREPARE: &str = r"(.*?)";', grant_source, re.DOTALL)
    if len(prefixes) != 1 or 'format!("{PREPARE}\\n{body}")' not in grant_source:
        raise ValueError("unsupported production grant composition")
    if "GrantCommit::script(COMMIT_AUTHORIZATION_CODE_GRANT)" not in source:
        raise ValueError("authorization grant no longer uses the common envelope")
    return prefixes[0] + "\n" + matches[0]


def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def sequence(items: list[str]) -> str:
    return "[" + ";".join(items) + "]"


def state_expression(state: dict[str, Any]) -> str:
    entries = []
    for key, entry in sorted(state.items()):
        value = entry["value"]
        match entry["type"]:
            case "string":
                data = "Text " + quote(value)
            case "json":
                data = "Text " + quote(canonical(value))
            case "set":
                data = "Members " + sequence([quote(v) for v in value])
            case "hash" | "zset":
                pairs = [
                    f"({quote(k)},{quote(v) if entry['type'] == 'hash' else v})"
                    for k, v in sorted(value.items())
                ]
                data = ("Fields " if entry["type"] == "hash" else "Scores ") + sequence(pairs)
            case _:
                raise ValueError("unsupported fixture key type")
        entries.append(
            f"({quote(key)},{{data=({data});expiring={str(entry['expiring']).lower()}}})"
        )
    return sequence(entries)


def request_expression(request: dict[str, Any], case: dict[str, Any]) -> str:
    args = request["args"]
    strings = set(args)
    for state in [case["initial"], case["expected"]]:
        for entry in state.values():
            if entry["type"] == "string":
                strings.add(entry["value"])
            elif entry["type"] == "hash":
                strings.update(entry["value"].values())
    strings.update(["0", "1", "2"])
    versions = sorted(
        v
        for v in strings
        if re.fullmatch(r"[0-9]+", v)
        and len(v) <= 19
        and (len(v) < 19 or v <= "9223372036854775806")
    )
    numbers = sorted((v, int(v)) for v in strings if re.fullmatch(r"-?(0|[1-9][0-9]*)", v))
    # Redis INCR accepts signed 64-bit canonical integer strings. Cases include
    # overflow and malformed values, which deliberately lack a successor.
    increments = [(s, str(n + 1)) for s, n in numbers if -(2**63) <= n < 2**63 - 1]
    concatenations = sorted({prefix + value for prefix in args[17:19] for value in strings})
    children = canonical({"refresh_token": args[6], "access_tokens": [args[3]]})
    return (
        "{"
        + ";".join(
            [
                "keys=" + sequence([quote(v) for v in request["keys"]]),
                "args=" + sequence([quote(v) for v in args]),
                "numbers=" + sequence([f"({quote(s)},{n})" for s, n in numbers]),
                "increments=" + sequence([f"({quote(s)},{quote(n)})" for s, n in increments]),
                "concatenations=" + sequence([f"({quote(s)},{quote(s)})" for s in concatenations]),
                "children=" + quote(children),
                "versions=" + sequence([quote(v) for v in versions]),
                "deadline_expired=" + str(expired_in_window(request)).lower(),
            ]
        )
        + "}"
    )


def render(cases: list[dict[str, Any]] | None = None, fixture_digest: str | None = None) -> str:
    if cases is None:
        content = FIXTURE.read_bytes()
        cases = load_cases(content)
        fixture_digest = hashlib.sha256(content).hexdigest()
    if fixture_digest is None:
        raise ValueError("snapshot digest is required")
    lines = [
        "module TestAuthCodeRedisGrant",
        "(* Generated by scripts/validation/authcode_redis_fixtures.py; do not edit. *)",
        "(* Finite trace correspondence only; not a production refinement proof. *)",
        "(* Fixture SHA-256: " + fixture_digest + " *)",
        "open AuthCode.RedisGrant",
    ]
    for index, case in enumerate(cases):
        suffix = str(index)
        requests = sequence([request_expression(req, case) for req in case["requests"]])
        lines += [
            "(* " + case["name"] + " *)",
            f"let requests_{suffix} : list request = {requests}",
            f"let initial_{suffix} : state = {state_expression(case['initial'])}",
            f"let expected_{suffix} : state = {state_expression(case['expected'])}",
            f"let result_{suffix} = matches requests_{suffix} initial_{suffix} "
            + sequence([quote(v) for v in case["expected_replies"]])
            + f" expected_{suffix}",
            f"let case_{suffix} () : Lemma result_{suffix} = assert_norm result_{suffix}",
        ]
    return "\n\n".join(lines) + "\n"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        if not GENERATED.is_file() or GENERATED.read_text() != rendered:
            raise SystemExit("Redis grant F* fixture drift: regenerate before verification")
    else:
        GENERATED.write_text(rendered)
