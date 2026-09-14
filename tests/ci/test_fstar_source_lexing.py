# ruff: noqa: PT009, PT027 - unittest without a pytest runtime dependency
"""Premise and declaration inventories must distinguish literals from F* syntax."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import admit_fstar_modules as admission  # noqa: E402
import assumption_graph as graph  # noqa: E402


class SourceLexingTests(unittest.TestCase):
    def test_comment_delimiters_in_literals_cannot_hide_later_premises(self):
        for literal in ['"(*"', '"*)"', '"//"', '"\\"(*"', "'\"'"]:
            with self.subTest(literal=literal):
                source = (
                    f"module Example\nlet message = {literal}\n"
                    "assume val trusted: unit\nlet unchecked = admit()\n"
                )
                parsed = graph.parse_fstar_source(source)
                self.assertEqual(
                    [(p["kind"], p["line"]) for p in parsed["premises"]],
                    [("assume-val", 3), ("admit", 4)],
                )

    def test_literals_do_not_create_premises_imports_or_declarations(self):
        source = (
            'module Example\nlet message = "\nassume val forged: unit\n'
            'open Unused\nlet false_proof = admit()\nmodule Fake\n"\n'
            "let real_proof = ()\n"
        )
        parsed = graph.parse_fstar_source(source)
        self.assertEqual(parsed["premises"], [])
        self.assertEqual(parsed["imports"], [])
        self.assertEqual(admission.declared_module(source), "Example")
        self.assertFalse(graph.declares_symbol(source, "false_proof"))
        self.assertTrue(graph.declares_symbol(source, "real_proof"))

    def test_nested_comments_keep_premise_positions_and_token_boundaries(self):
        source = (
            "module Example\n(* outer\n(* nested *)\n*)\nassume(* separator *)val trusted: unit\n"
        )
        parsed = graph.parse_fstar_source(source)
        self.assertEqual(len(parsed["premises"]), 1)
        self.assertEqual(parsed["premises"][0]["name"], "trusted")
        self.assertEqual(parsed["premises"][0]["line"], 5)

    def test_option_strings_are_preserved_only_at_real_directives(self):
        source = 'module Example\n#push-options "--lax"\nlet s = "--lax"\n'
        premises = graph.parse_fstar_source(source)["premises"]
        self.assertEqual(len(premises), 1)
        self.assertEqual(premises[0]["kind"], "lax-option")
        self.assertEqual(premises[0]["statement"], '#push-options "--lax"')

    def test_escaped_option_arguments_fail_closed_before_graph_construction(self):
        for option in [
            r"--admit_smt_queries\x20true",
            r"\x2d\x2dadmit_smt_queries true",
            r"--z3rlimit\x202",
        ]:
            for directive in ["set", "push", "reset"]:
                with (
                    self.subTest(option=option, directive=directive),
                    self.assertRaisesRegex(graph.GraphError, "escaped option directives"),
                ):
                    graph.parse_fstar_source(f'module Example\n#{directive}-options "{option}"\n')
        self.assertEqual(
            graph.parse_fstar_source(
                r"module Example" + "\n" + r'let text = "\x2d\x2dadmit_smt_queries true"'
            )["premises"],
            [],
        )

    def test_plain_option_tokens_and_multiline_directives_are_conservative(self):
        for option in [
            "--admit_smt_queries true",
            "--admit_smt_queries\ttrue",
            "--admit_smt_queries\ntrue",
            "--admit_smt_queries=true",
            "--admit_smt_queries false",
            "--admit_except Example",
        ]:
            with self.subTest(option=option):
                source = f'module Example\nlet x = () #set-options\n"{option}"\nlet f () = ()\n'
                premises = graph.parse_fstar_source(source)["premises"]
                self.assertEqual(len(premises), 1)
                self.assertEqual((premises[0]["kind"], premises[0]["line"]), ("lax-option", 2))
        for directive in ["#push-options", "#reset-options", '#set-options "--z3rlimit 100"']:
            self.assertEqual(
                graph.parse_fstar_source("module Example\n" + directive)["premises"], []
            )

    def test_unsupported_or_unterminated_lexical_forms_fail_closed(self):
        for suffix in ['let s = "unfinished', "// IN F*: assume val x:unit"]:
            with self.subTest(suffix=suffix), self.assertRaises(admission.AdmissionError):
                graph.parse_fstar_source("module Example\n" + suffix)

    def test_executable_comment_marker_is_inert_in_literals_and_block_comments(self):
        for prefix in [
            'let marker = "// IN F*: assume val fake: unit"',
            "(* // IN F*: assume val fake: unit *)",
            "(* outer (* // IN F*: *) comment *)",
            "// ordinary comment with // IN F*: later text",
        ]:
            with self.subTest(prefix=prefix):
                source = f"module Example\n{prefix}\nassume val real: unit\n"
                parsed = graph.parse_fstar_source(source)
                self.assertEqual(
                    [(p["name"], p["line"]) for p in parsed["premises"]], [("real", 3)]
                )
                self.assertEqual(admission.declared_module(source), "Example")

    def test_block_comment_at_eof_matches_the_pinned_verifiers_lexer(self):
        source = "module Example\nlet real = ()\n(*\nassume val skipped: unit\n"
        self.assertEqual(graph.parse_fstar_source(source)["premises"], [])
        self.assertTrue(graph.declares_symbol(source, "real"))
        self.assertFalse(graph.declares_symbol(source, "skipped"))


if __name__ == "__main__":
    unittest.main()
