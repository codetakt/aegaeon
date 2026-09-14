# ruff: noqa: PT009, PT027 - unittest assertions also run under Python -O
"""Rejection controls for the bounded first-party foreign-assumption inventory."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import check_foreign_assumption_inventory as inventory  # noqa: E402 - sibling source path set above


class ForeignAssumptionInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "fstar").mkdir()
        self.source = self.root / "fstar/Sample.fst"
        self.source.write_text("module Sample\nassume val external: nat\n")
        original = json.loads((ROOT / "spec/assumption-register.json").read_text())
        self.register = {**original, "entries": [copy.deepcopy(original["entries"][0])]}
        entry = self.register["entries"][0]
        entry["id"] = "foreign:external"
        entry["premise_ids"] = ["premise:Sample#external"]
        entry["statements"] = {
            "premise:Sample#external": inventory.graph.digest_text("assume val external: nat")
        }
        self.register_path = self.root / "register.json"

    def run_check(self) -> int:
        self.register_path.write_text(json.dumps(self.register))
        return inventory.check(self.root, self.register_path)

    def reject_source(self, text: str) -> None:
        self.source.write_text(text)
        with self.assertRaises((inventory.InventoryError, inventory.graph.GraphError)):
            self.run_check()

    def test_repository_six_registered_declarations_without_promotion(self) -> None:
        register = ROOT / "spec/assumption-register.json"
        before = register.read_bytes()
        self.assertEqual(inventory.check(ROOT, register), 6)
        self.assertEqual(register.read_bytes(), before)

    def test_positive_inventory_and_closure_external_entry(self) -> None:
        self.register["entries"][0]["expected_in_closure"] = False
        self.assertEqual(self.run_check(), 1)
        self.assertEqual(
            json.loads(self.register_path.read_text())["entries"][0]["status"],
            "specified-not-attested",
        )

    def test_nonindented_continuation_is_not_a_declaration_boundary(self) -> None:
        self.reject_source("module Sample\nassume val external: nat\n-> nat\n")

    def test_blank_lines_do_not_end_declaration(self) -> None:
        self.reject_source("module Sample\nassume val external: nat\n\n  -> nat\n")

    def test_same_count_replacement(self) -> None:
        self.reject_source("module Sample\nassume val replacement: nat\n")

    def test_changed_statement(self) -> None:
        self.reject_source("module Sample\nassume val external: int\n")

    def test_missing_extra_and_duplicate_declarations(self) -> None:
        for body in ("", "assume val extra: nat\n", "assume val external: nat\n"):
            with self.subTest(body=body):
                prefix = "assume val external: nat\n" if body else ""
                self.reject_source("module Sample\n" + prefix + body)

    def test_interface_is_scanned_and_duplicate_is_rejected(self) -> None:
        interface = self.source.with_suffix(".fsti")
        interface.write_text(self.source.read_text())
        with self.assertRaisesRegex(inventory.InventoryError, "duplicate source"):
            self.run_check()
        self.source.unlink()
        self.assertEqual(self.run_check(), 1)
        interface.write_text("module Sample\nassume val extra: nat\n")
        with self.assertRaisesRegex(inventory.InventoryError, "mismatch"):
            self.run_check()

    def test_comments_and_literals_cannot_hide_later_declaration(self) -> None:
        prefixes = (
            'let s = "(*"\n',
            'let s = "\\" (* // assume val fake: nat"\n',
            "let c = '\"'\n",
            "(* outer (* nested *) assume val fake: nat *)\n",
            "// assume val fake: nat\n",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.source.write_text("module Sample\n" + prefix + "assume val external: nat\n")
                self.assertEqual(self.run_check(), 1)
                self.reject_source(self.source.read_text() + "assume val extra: nat\n")

    def test_unterminated_lexemes(self) -> None:
        for tail in ("(*", 'let s = "'):
            with self.subTest(tail=tail):
                self.reject_source("module Sample\nassume val external: nat\n" + tail)

    def test_identifier_apostrophe_cannot_mask_extra_assumption(self) -> None:
        # This exact lexical structure is accepted by the pinned F* verifier.
        # Treating the apostrophe of f' as a character opener hides the extra
        # declaration between two falsely inferred string delimiters.
        prefix = "module Sample\nassume val external: nat\n"
        tail = "let f' (s:string) : Tot string = s\nlet x = f'\"'\"\n"
        tail += "assume val hidden: nat\nlet c = '\"'\nlet witness : nat = hidden\n"
        self.reject_source(prefix + tail)
        self.source.write_text(
            prefix + tail.replace("assume val hidden: nat\n", "").replace("hidden", "external")
        )
        self.assertEqual(self.run_check(), 1)

    def test_multiline_attribute_is_rejected(self) -> None:
        self.reject_source("module Sample\n[@@\n  1\n]\nassume val external: nat\n")

    def test_prime_start_identifiers_use_longest_match(self) -> None:
        for name in ("''", "'f''"):
            with self.subTest(name=name):
                prefix = "module Sample\nassume val external: nat\n"
                tail = f"let {name} (s:string) : Tot string = s\nlet x = {name}" + '"\'"\n'
                tail += "assume val hidden: nat\nlet c = '\"'\nlet witness : nat = hidden\n"
                self.reject_source(prefix + tail)
                self.source.write_text(
                    prefix
                    + tail.replace("assume val hidden: nat\n", "").replace("hidden", "external")
                )
                self.assertEqual(self.run_check(), 1)

    def test_character_ties_and_byte_suffixes_do_not_hide_declarations(self) -> None:
        for literal in ("'a'", "'a'B", "'''", "'\n'", "'\\x22'", "'\\u0022'", "'\\\"'"):
            with self.subTest(literal=literal):
                prefix = "module Sample\nlet c = " + literal + "\n"
                self.source.write_text(prefix + "assume val external: nat\n")
                self.assertEqual(self.run_check(), 1)
                self.reject_source(self.source.read_text() + "assume val hidden: nat\n")

    def test_all_pinned_qualifiers_are_rejected(self) -> None:
        for qualifier in inventory.QUALIFIERS:
            for prefix in (qualifier, "let x = 1 " + qualifier):
                with self.subTest(prefix=prefix):
                    self.reject_source("module Sample\n" + prefix + "\nassume val external: nat\n")
            with self.subTest(order=qualifier):
                self.reject_source("module Sample\nassume " + qualifier + " val external: nat\n")

    def test_escaped_identifiers_are_rejected_only_in_code(self) -> None:
        self.reject_source('module Sample\nlet ``x"`` = 1\nassume val external: nat\n')
        self.source.write_text('module Sample\n(* ``x"`` *)\nassume val external: nat\n')
        self.assertEqual(self.run_check(), 1)

    def test_fstar_executable_comment_escape_is_rejected(self) -> None:
        self.reject_source(
            "module Sample\nassume val external: nat\n// IN F*: assume val extra: nat\n"
        )

    def test_executable_comment_text_in_data_does_not_reject_registered_inventory(self) -> None:
        for prefix in [
            'let marker = "// IN F*: assume val fake: nat"',
            "(* // IN F*: assume val fake: nat *)",
        ]:
            with self.subTest(prefix=prefix):
                self.source.write_text(f"module Sample\n{prefix}\nassume val external: nat\n")
                self.assertEqual(self.run_check(), 1)

    def test_unicode_line_separators_are_rejected(self) -> None:
        for separator in ("\u2028", "\u2029", "\u0085", "\v", "\f"):
            with self.subTest(separator=repr(separator)):
                self.reject_source(
                    "module Sample\nassume val external: nat\n// comment"
                    + separator
                    + "assume val extra: nat\n"
                )

    def test_literal_bearing_assumption_rejected_without_whitespace_collapse(self) -> None:
        for literal in ('"a b"', '"a  b"', "'a'"):
            with self.subTest(literal=literal):
                self.reject_source(
                    "module Sample\nassume val external: x:string{x = " + literal + "}\n"
                )

    def test_unsupported_headers_and_prefixes(self) -> None:
        for header in (
            "assume\nval external: nat",
            "private assume val external: nat",
            "  assume val external: nat",
            "assume (* gap *) val external: nat",
            "[@@ foo]\nassume val external: nat",
            "private\nassume val external: nat",
        ):
            with self.subTest(header=header):
                self.reject_source("module Sample\n" + header + "\n")

    def test_module_identity_is_checked(self) -> None:
        for prefix in ("", "module Other\n", "module Sample\nmodule Other\n"):
            with self.subTest(prefix=prefix):
                self.reject_source(prefix + "assume val external: nat\n")

    def test_duplicate_register_entries_and_premises(self) -> None:
        entry = copy.deepcopy(self.register["entries"][0])
        self.register["entries"].append(entry)
        with self.assertRaises(inventory.graph.GraphError):
            self.run_check()
        entry["id"] = "foreign:duplicate"
        with self.assertRaisesRegex(inventory.InventoryError, "duplicate registered"):
            self.run_check()

    def test_register_requires_matching_identity_and_hash_sets(self) -> None:
        for change in ("missing_ids", "extra_hash", "duplicate_ids", "bad_hash", "bad_id"):
            with self.subTest(change=change):
                original = copy.deepcopy(self.register)
                entry = self.register["entries"][0]
                if change == "missing_ids":
                    entry.pop("premise_ids")
                elif change == "extra_hash":
                    entry["statements"]["premise:Sample#other"] = "0" * 64
                elif change == "duplicate_ids":
                    entry["premise_ids"] *= 2
                elif change == "bad_hash":
                    entry["statements"]["premise:Sample#external"] = "bad"
                else:
                    entry["premise_ids"] = ["not-a-declaration"]
                    entry["statements"] = {"not-a-declaration": "0" * 64}
                with self.assertRaises((inventory.InventoryError, inventory.graph.GraphError)):
                    self.run_check()
                self.register = original

    def test_duplicate_json_key_is_rejected(self) -> None:
        self.register_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(inventory.graph.GraphError, "duplicate JSON"):
            inventory.check(self.root, self.register_path)

    def test_source_directory_symlink_is_rejected(self) -> None:
        (self.root / "fstar/linked").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(inventory.InventoryError, "symlink"):
            self.run_check()

    def test_source_root_symlink_is_rejected(self) -> None:
        (self.root / "fstar").rename(self.root / "actual")
        (self.root / "fstar").symlink_to(self.root / "actual", target_is_directory=True)
        with self.assertRaisesRegex(inventory.InventoryError, "symlink"):
            self.run_check()


if __name__ == "__main__":
    unittest.main()
