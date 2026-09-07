#!/usr/bin/env python3
"""Ensure missing obligations cannot disappear behind evidence status labels."""

from __future__ import annotations

import copy
import json
import pathlib
import tempfile
import unittest
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from unittest.mock import patch
from urllib.parse import urlparse

import validate_server_assurance_contract as validator
import yaml
from jsonschema import ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


class ContractIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(validator.CONTRACT.read_text())
        self.matrix = yaml.safe_load(validator.MATRIX.read_text())

    def expect_invalid(self, message: str, source_dir: pathlib.Path | None = None) -> None:
        try:
            validator.validate_contract(self.contract, self.matrix, source_dir)
        except ValidationError as error:
            if message not in str(error):
                self.fail(f"expected {message!r} in validation error: {error}")
        else:
            self.fail("invalid contract was accepted")

    @contextmanager
    def document_contents(self, field: str, transform: Callable[[str], str]) -> Iterator[None]:
        target = validator.ROOT / self.contract[field]
        original_read = pathlib.Path.read_text

        def read_text(path: pathlib.Path, *args: Any, **kwargs: Any) -> str:
            text = original_read(path, *args, **kwargs)
            return transform(text) if path == target else text

        with patch.object(pathlib.Path, "read_text", new=read_text):
            yield

    def test_all_evidence_statuses_can_change_without_changing_obligations(self) -> None:
        for rows in self.matrix.values():
            if isinstance(rows, list):
                for row in rows:
                    row["status"] = "planned"
        validator.validate_contract(self.contract, self.matrix)

    def test_new_matrix_group_requires_a_disposition(self) -> None:
        self.matrix["rfc_99999"] = []
        self.expect_invalid("matrix group dispositions")

    def test_revision_cannot_silently_differ_from_contract_text(self) -> None:
        self.contract["contract_revision"] = "2026-09-07-r99"
        self.expect_invalid("contract revision differs")

    def test_dynamic_op_conflict_cannot_be_silently_admitted(self) -> None:
        self.contract["profile"]["dynamic_op_relationships"] = "admitted"
        self.expect_invalid("requires-separate-resolved-profile")

    def test_companion_revision_drift_is_rejected(self) -> None:
        for field in (
            "statement_document",
            "evaluation_document",
            "status_document",
            "standards_document",
        ):
            old = f"Document revision: **{self.contract['document_revisions'][field]}**."

            def replace_revision(text: str, previous: str = old) -> str:
                return text.replace(previous, "Document revision: **2026-09-07-r99**.")

            with (
                self.subTest(field=field),
                self.document_contents(field, replace_revision),
            ):
                self.expect_invalid(f"document revision missing, duplicated or mismatched: {field}")

    def test_duplicate_document_revision_is_rejected(self) -> None:
        with self.document_contents(
            "statement_document", lambda text: text + "\nDocument revision: **2026-09-07-r99**.\n"
        ):
            self.expect_invalid(
                "document revision missing, duplicated or mismatched: statement_document"
            )

    def test_revision_quoted_in_prose_is_not_metadata(self) -> None:
        marker = (
            f"Document revision: **{self.contract['document_revisions']['statement_document']}**."
        )
        transforms = (
            lambda text: text.replace(marker, "> " + marker),
            lambda text: text.replace(marker, "") + "\n```text\n" + marker + "\n```\n",
        )
        for transform in transforms:
            with (
                self.subTest(transform=transform),
                self.document_contents("statement_document", transform),
            ):
                self.expect_invalid(
                    "document revision missing, duplicated or mismatched: statement_document"
                )

    def test_independent_companion_revision_can_be_pinned(self) -> None:
        old = self.contract["document_revisions"]["evaluation_document"]
        self.contract["document_revisions"]["evaluation_document"] = "2026-09-07-r99"
        with self.document_contents(
            "evaluation_document", lambda text: text.replace(f"**{old}**.", "**2026-09-07-r99**.")
        ):
            validator.validate_contract(self.contract, self.matrix)

    def test_missing_group_disposition_is_rejected(self) -> None:
        self.contract["matrix_groups"].pop(0)
        self.expect_invalid("matrix group dispositions")

    def test_unknown_guarantee_is_rejected(self) -> None:
        self.contract["matrix_groups"][0]["guarantee_ids"].append("G-99")
        self.expect_invalid("guarantee references")

    def test_unknown_source_is_rejected(self) -> None:
        self.contract["matrix_groups"][0]["source_ids"].append("missing-source")
        self.expect_invalid("source references")

    def test_duplicate_pin_is_rejected(self) -> None:
        self.contract["sources"].append(copy.deepcopy(self.contract["sources"][0]))
        self.expect_invalid("duplicate id")

    def test_contract_cannot_be_used_as_an_attestation(self) -> None:
        self.contract["adoption_state"] = "verified"
        self.expect_invalid("specified-not-attested")

    def test_changed_source_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegaeon-contract-test-") as directory:
            source = self.contract["sources"][0]
            filename = pathlib.PurePosixPath(urlparse(source["uri"]).path).name
            (pathlib.Path(directory) / filename).write_bytes(b"altered source archive")
            self.expect_invalid("missing or changed source", pathlib.Path(directory))

    def test_missing_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegaeon-contract-test-") as directory:
            self.expect_invalid("missing or changed source", pathlib.Path(directory))


if __name__ == "__main__":
    unittest.main()
