#!/usr/bin/env python3
"""Check the lexical inventory of first-party F* foreign assumptions.

Compare every assume-val in fstar/**/*.fst and .fsti with the foreign-contract
register, including entries outside the proof closure. This checks declaration
identity and normalized declaration text only. It does not establish functional
postconditions, ABI/linkage, imported type/alias meaning, or premise acceptance.

Supported declarations start at column zero with ``assume val name:`` and have
indented continuation lines. Literals, qualifiers/attributes, split headers,
F* line-comment escapes and Unicode line separators are rejected rather than
silently omitted. This is deliberately a bounded inventory, not an F* parser.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import assumption_graph as graph
from fstar_source_lexing import SourceLexingError as InventoryError, lexical_views

IDENT = r"[A-Za-z_][A-Za-z0-9_']*"
MODULE = rf"{IDENT}(?:\.{IDENT})*"
HEADER = re.compile(rf"^assume val ({IDENT})\s*:")
SITE = re.compile(r"(?<![\w'])assume(?![\w'])")
MODULE_DECL = re.compile(rf"^module ({MODULE})\s*$", re.MULTILINE)
NEXT_DECL = re.compile(r"^(?:let|val|type|module|open|include|assume val)\b")
# F* 2025.10.06 Parser_Parse.mly qualifier production. Check the last token,
# including qualifiers appended to a preceding declaration's final line.
QUALIFIERS = (
    "assume",
    "inline",
    "unfoldable",
    "inline_for_extraction",
    "unfold",
    "irreducible",
    "noextract",
    "total",
    "private",
    "noeq",
    "unopteq",
    "new",
    "logic",
    "opaque",
    "reifiable",
    "reflectable",
)
PREFIX = re.compile(r"(?<![\w'])(?:" + "|".join(QUALIFIERS) + r")(?![\w'])\s*$")


def source_declarations(path: Path) -> dict[str, str]:
    clean, masked = lexical_views(path.read_text(encoding="utf-8"))
    sites = list(SITE.finditer(masked))
    if not sites:
        return {}
    # A multi-line attribute may end well before the declaration header; a
    # preceding-line test is insufficient. This bounded inventory deliberately
    # rejects attributes anywhere in a file declaring foreign assumptions.
    if "[@" in masked:
        raise InventoryError(f"{path}: attributes in assumption-bearing files are unsupported")
    modules = list(MODULE_DECL.finditer(masked))
    if len(modules) != 1:
        raise InventoryError(f"{path}: expected one unqualified module declaration")
    module = modules[0].group(1)
    if module != path.stem:
        raise InventoryError(f"{path}: module name does not match filename")
    lines, masks = clean.splitlines(), masked.splitlines()
    result: dict[str, str] = {}
    for site in sites:
        row = masked[: site.start()].count("\n")
        # Path.read_text normalizes CRLF/CR to LF before lexical scanning.
        header = HEADER.match(masks[row])
        if header is None or site.start() != sum(len(s) + 1 for s in masks[:row]):
            raise InventoryError(f"{path}:{row + 1}: unsupported assume-val header")
        previous = next((s for s in reversed(masks[:row]) if s.strip()), "")
        if PREFIX.search(previous):
            raise InventoryError(f"{path}:{row + 1}: unsupported declaration prefix")
        end = row + 1
        while end < len(lines) and (not lines[end].strip() or lines[end][0].isspace()):
            end += 1
        if end < len(lines) and NEXT_DECL.match(masks[end]) is None:
            raise InventoryError(f"{path}:{end + 1}: unsupported assume-val boundary")
        if lines[row:end] != masks[row:end]:
            raise InventoryError(f"{path}:{row + 1}: literals in assume-val are unsupported")
        premise = f"premise:{module}#{header.group(1)}"
        if premise in result:
            raise InventoryError(f"{path}: duplicate declaration {premise}")
        result[premise] = graph.digest_text(graph.normalize_statement(lines[row:end]))
    return result


def registered_declarations(path: Path) -> dict[str, str]:
    register = graph.load_object(path)
    graph.validate_register(register)
    result: dict[str, str] = {}
    for entry in register["entries"]:
        if entry["kind"] != "foreign-contract":
            continue
        ids = entry.get("premise_ids", [])
        statements = entry.get("statements", {})
        if not ids or len(set(ids)) != len(ids) or set(ids) != set(statements):
            raise InventoryError(
                f"{entry['id']}: premise IDs and statement hashes must match exactly"
            )
        for premise in ids:
            if not re.fullmatch(rf"premise:{MODULE}#{IDENT}", premise):
                raise InventoryError(f"{entry['id']}: malformed declaration identity {premise}")
            if premise in result:
                raise InventoryError(f"duplicate registered declaration {premise}")
            result[premise] = statements[premise]
    if not result:
        raise InventoryError("empty foreign-contract inventory")
    return result


def check(root: Path, register: Path) -> int:
    expected = registered_declarations(register)
    actual: dict[str, str] = {}
    directory = root / "fstar"
    if directory.is_symlink():
        raise InventoryError(f"unsupported source symlink: {directory}")
    if not directory.is_dir():
        raise InventoryError("missing first-party fstar directory")
    # Reject directory symlinks too: pathlib traversal must not omit a subtree.
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise InventoryError(f"unsupported source symlink: {path}")
        if path.suffix not in {".fst", ".fsti"} or not path.is_file():
            continue
        for premise, digest in source_declarations(path).items():
            if premise in actual:
                raise InventoryError(f"duplicate source declaration {premise}")
            actual[premise] = digest
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = sorted(key for key in expected.keys() & actual.keys() if expected[key] != actual[key])
    if missing or extra or changed:
        raise InventoryError(
            f"declaration mismatch: missing={missing}, extra={extra}, changed={changed}"
        )
    return len(actual)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--register", type=Path)
    args = parser.parse_args()
    try:
        count = check(args.root, args.register or args.root / "spec/assumption-register.json")
    except (InventoryError, graph.GraphError, OSError, UnicodeError) as error:
        print(f"foreign-assumption inventory FAIL: {error}", file=sys.stderr)
        return 1
    print(f"foreign-assumption source inventory PASS: {count} exact registered declarations")
    print("Lexical identity only; no functional, ABI/linkage, or premise acceptance claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
