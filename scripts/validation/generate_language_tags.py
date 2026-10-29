#!/usr/bin/env python3
"""Generate the dated RFC 5646 admission tables; no network access.

Unknown fields are retained while parsing, then ignored only after structural
and type-specific validation. Variant Prefix and Suppress-Script are source
recommendations, not this consumer's mandatory formation constraints.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "crates/server/data/language-tags"
OUTPUT = ROOT / "crates/server/src/metadata/language_tags/registry.rs"
GRANDFATHERED = set(
    (
        "en-gb-oed i-ami i-bnn i-default i-enochian i-hak i-klingon i-lux "
        "i-mingo i-navajo i-pwn i-tao i-tay i-tsu sgn-be-fr sgn-be-nl sgn-ch-de "
        "art-lojban cel-gaulish no-bok no-nyn zh-guoyu zh-hakka zh-min zh-min-nan zh-xiang"
    ).split()
)
REPEATABLE = {"Description", "Prefix", "Comments"}


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def records(raw: bytes) -> tuple[str, list[dict[str, list[str]]]]:
    text = raw.decode("utf-8")
    require("\r" not in text and "\x00" not in text, "unsupported line encoding")
    result: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    last: str | None = None
    for line in text.split("\n"):
        if line == "%%":
            require(bool(current), "empty record")
            result.append(current)
            current, last = {}, None
        elif not line:
            continue
        elif line.startswith((" ", "\t")):
            if last is None:
                raise ValueError("orphan continuation")
            current[last][-1] += "\n" + line
        else:
            match = re.fullmatch(r"([A-Za-z][A-Za-z_0-9-]*): (.+)", line)
            if match is None:
                raise ValueError("invalid field syntax")
            key, value = match.groups()
            require(key not in current or key in REPEATABLE, "duplicate field: " + key)
            current.setdefault(key, []).append(value)
            last = key
    if current:
        result.append(current)
    require(result and set(result[0]) == {"File-Date"}, "missing registry header")
    date(result[0]["File-Date"][0])
    return result[0]["File-Date"][0], result[1:]


def date(value: str) -> None:
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None, "invalid date")
    datetime.date.fromisoformat(value)


def one(record: dict[str, list[str]], name: str) -> str:
    require(name in record and len(record[name]) == 1, "required singleton: " + name)
    return record[name][0]


def subtag(kind: str, value: str) -> None:
    patterns = {
        "language": r"[A-Za-z]{2,8}",
        "extlang": r"[A-Za-z]{3}",
        "script": r"[A-Za-z]{4}",
        "region": r"(?:[A-Za-z]{2}|[0-9]{3})",
        "variant": r"(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3})",
    }
    require(re.fullmatch(patterns[kind], value) is not None, "invalid " + kind + ": " + value)


def ordinary(
    raw: bytes,
) -> tuple[str, dict[str, set[str]], list[tuple[str, str, str]], dict[str, str]]:
    file_date, rows = records(raw)
    tables: dict[str, set[str]] = {
        kind: set()
        for kind in [
            "language",
            "extlang",
            "script",
            "region",
            "variant",
            "grandfathered",
            "redundant",
        ]
    }
    ranges: list[tuple[str, str, str]] = []
    prefixes: dict[str, str] = {}
    references: list[tuple[str, str]] = []
    for record in rows:
        kind = one(record, "Type")
        require(kind in tables, "unsupported registry type: " + kind)
        tagged = kind in ["grandfathered", "redundant"]
        name = one(record, "Tag" if tagged else "Subtag").lower()
        require(("Subtag" if tagged else "Tag") not in record, "wrong identifier field")
        require("Description" in record, "missing Description")
        date(one(record, "Added"))
        if "Deprecated" in record:
            date(one(record, "Deprecated"))
        if tagged:
            require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", name) is not None, "invalid tag")
        elif ".." in name:
            low, high = name.split("..")
            subtag(kind, low)
            subtag(kind, high)
            require(
                kind in ["language", "script", "region"]
                and len(low) == len(high)
                and low < high
                and low.isalpha()
                and high.isalpha(),
                "invalid private range",
            )
            # These are RFC 5646's private-use ranges, not arbitrary supplier ranges.
            require(
                (kind, low, high)
                in {
                    ("language", "qaa", "qtz"),
                    ("script", "qaaa", "qabx"),
                    ("region", "qm", "qz"),
                    ("region", "xa", "xz"),
                },
                "unsupported range",
            )
            require(any("Private use" in v for v in record["Description"]), "range is not private")
            ranges.append((kind, low, high))
        else:
            subtag(kind, name)
        require(name not in tables[kind], "duplicate category identifier")
        tables[kind].add(name)
        if "Prefix" in record:
            require(kind in ["extlang", "variant"], "Prefix on wrong record type")
            for prefix in record["Prefix"]:
                require(
                    re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", prefix) is not None,
                    "invalid Prefix",
                )
        if kind == "extlang":
            prefix = one(record, "Prefix").lower()
            subtag("language", prefix)
            require("-" not in prefix and len(prefix) <= 3, "invalid extlang enclosing primary")
            prefixes[name] = prefix
        if "Suppress-Script" in record:
            require(kind in ["language", "extlang"], "Suppress-Script on wrong record type")
            script = one(record, "Suppress-Script").lower()
            subtag("script", script)
            references.append(("script", script))
        if "Macrolanguage" in record:
            require(kind in ["language", "extlang"], "Macrolanguage on wrong record type")
            language = one(record, "Macrolanguage").lower()
            subtag("language", language)
            references.append(("language", language))
        if "Scope" in record:
            require(kind in ["language", "extlang"], "Scope on wrong record type")
            require(
                one(record, "Scope") in ["macrolanguage", "collection", "special", "private-use"],
                "unsupported Scope",
            )
        if "Preferred-Value" in record:
            value = one(record, "Preferred-Value")
            if tagged:
                require(
                    re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", value) is not None,
                    "invalid preferred tag",
                )
            else:
                subtag("language" if kind == "extlang" else kind, value)
    require(tables["grandfathered"] == GRANDFATHERED, "grandfathered grammar inventory changed")
    for name, prefix in prefixes.items():
        require(prefix in tables["language"], "unregistered extlang Prefix: " + name)
    for kind, name in references:
        require(name in tables[kind], "unregistered record reference: " + name)
    for kind, low, high in ranges:
        require(
            not any(".." not in name and low <= name <= high for name in tables[kind]),
            "range overlaps record",
        )
    require(len(ranges) == 4, "missing private ranges")
    return file_date, tables, sorted(ranges), prefixes


def extensions(raw: bytes) -> tuple[str, list[str]]:
    file_date, rows = records(raw)
    allocated = set()
    for record in rows:
        identifier = one(record, "Identifier").lower()
        require(re.fullmatch("[0-9a-wy-z]", identifier) is not None, "invalid extension singleton")
        require(identifier not in allocated, "duplicate extension allocation")
        for field in ["Description", "RFC", "Authority", "Contact_Email", "Mailing_List", "URL"]:
            require(field in record, "missing extension field: " + field)
        date(one(record, "Added"))
        allocated.add(identifier)
    return file_date, sorted(allocated)


def render() -> str:
    provenance = json.loads((DATA / "provenance.json").read_text())
    sources: dict[str, bytes] = {}
    for source in provenance["sources"]:
        name = source["file"]
        require(
            name in ["language-subtag-registry.txt", "language-tag-extensions-registry.txt"]
            and name not in sources,
            "unexpected source",
        )
        raw = (DATA / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == source["sha256"], "source digest mismatch")
        require(
            source["url"]
            == "https://www.iana.org/assignments/"
            + name.removesuffix(".txt")
            + "/"
            + name.removesuffix(".txt"),
            "source URL mismatch",
        )
        require(records(raw)[0] == source["file_date"], "source date mismatch")
        sources[name] = raw
    require(len(sources) == 2, "missing registry")
    _, tables, ranges, prefixes = ordinary(sources["language-subtag-registry.txt"])
    _, allocated = extensions(sources["language-tag-extensions-registry.txt"])
    out = [
        "// Generated by scripts/validation/generate_language_tags.py; do not edit.",
        "// Pinned official inputs and digests: crates/server/data/language-tags/provenance.json.",
        "",
    ]
    for name in ["language", "script", "region", "variant", "grandfathered"]:
        out.append("#[rustfmt::skip]")
        out.append("pub(super) const " + name.upper() + ": &[&str] = &[")
        out.extend("    " + json.dumps(v) + "," for v in sorted(tables[name]) if ".." not in v)
        out.extend(["];", ""])
    out.extend(["#[rustfmt::skip]", "pub(super) const RANGES: &[(&str, &str, &str)] = &["])
    out.extend("    (" + ", ".join(json.dumps(v) for v in row) + ")," for row in ranges)
    out.extend(["];", "", "#[rustfmt::skip]", "pub(super) const EXTLANG: &[(&str, &str)] = &["])
    out.extend(
        "    (" + json.dumps(k) + ", " + json.dumps(v) + ")," for k, v in sorted(prefixes.items())
    )
    out.extend(
        ["];", "", 'pub(super) const EXTENSIONS: &[u8] = b"' + "".join(allocated) + '";', ""]
    )
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = render().encode()
    if args.check:
        require(OUTPUT.read_bytes() == output, "stale language-tag tables; regenerate and review")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(output)
    print("language-tag registry tables: " + ("checked" if args.check else "generated"))


if __name__ == "__main__":
    main()
