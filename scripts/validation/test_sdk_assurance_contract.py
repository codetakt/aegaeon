#!/usr/bin/env python3
"""Regression checks for lost SDK obligations, source drift and false attestation."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from unittest.mock import patch
from urllib.parse import urlparse

import validate_sdk_assurance_contract as validator
from jsonschema import ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


class SdkContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(validator.CONTRACT.read_text())
        self.boundary = json.loads(validator.BOUNDARY.read_text())

    def check(self, **kwargs: Any) -> None:
        validator.validate_contract(self.contract, self.boundary, **kwargs)

    def expect_invalid(self, message: str, **kwargs: Any) -> None:
        try:
            self.check(**kwargs)
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

    def test_inventory_is_not_affected_by_release_readiness(self) -> None:
        self.boundary["released_client_claim_active"] = True
        self.check()

    def test_obligation_register_cannot_be_an_attestation(self) -> None:
        self.contract["adoption_state"] = "verified"
        self.expect_invalid("specified-not-attested")

    def test_revision_cannot_silently_differ_from_contract_text(self) -> None:
        self.contract["contract_revision"] = "2026-09-07-r99"
        self.expect_invalid("contract revision differs")

    def test_reference_label_cannot_attest_sdk_implementation(self) -> None:
        self.contract["reference_source_status"] = "conforming"
        self.expect_invalid("unattested-development-reference")

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
            self.check()

    def test_unknown_specification_reference_is_rejected(self) -> None:
        self.contract["specification_groups"][0]["source_ids"].append("missing-source")
        self.expect_invalid("source references")

    def test_profile_cannot_drop_adapter_obligations(self) -> None:
        self.contract["profiles"][0]["guarantee_ids"].remove("C-06")
        self.expect_invalid("retain its packages")

    def test_package_requires_output_profile(self) -> None:
        self.contract["profiles"] = self.contract["profiles"][:-1]
        self.expect_invalid("every package")

    def test_crypto_algorithm_drift_is_rejected(self) -> None:
        self.boundary["profiles"]["aegaeon-rs256"]["jwt_algorithms"].append("ES256")
        self.expect_invalid("crypto selector drift")

    def test_new_crypto_selector_needs_disposition(self) -> None:
        self.boundary["profiles"]["new-profile"] = {}
        self.expect_invalid("selector inventory")

    def test_changed_project_specification_needs_review(self) -> None:
        self.contract["project_sources"][0]["sha256"] = "0" * 64
        self.expect_invalid("project specification changed")

    def test_source_pin_cannot_silently_diverge(self) -> None:
        self.contract["sources"][0]["sha256"] = "0" * 64
        self.expect_invalid("shared source pin differs")

    def test_source_bytes_are_checked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegaeon-sdk-sources-") as directory:
            source = self.contract["sources"][0]
            filename = pathlib.PurePosixPath(urlparse(source["uri"]).path).name
            (pathlib.Path(directory) / filename).write_bytes(b"altered archive")
            self.expect_invalid("changed source bytes", source_dir=pathlib.Path(directory))

    def test_missing_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegaeon-sdk-sources-") as directory:
            self.expect_invalid("changed source bytes", source_dir=pathlib.Path(directory))

    def test_real_workspace_package_addition_requires_disposition(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegaeon-sdk-packages-") as directory:
            workspace = pathlib.Path(directory)
            for package in self.contract["packages"]:
                path = workspace / "packages" / package["id"] / "package.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"name": package["npm_name"]}))
            self.check(sdk_workspace=workspace)
            extra = workspace / "packages" / "new-client" / "package.json"
            extra.parent.mkdir()
            extra.write_text(json.dumps({"name": "@aegaeon/new-client"}))
            self.expect_invalid("package inventory differs", sdk_workspace=workspace)

    def test_reference_paths_cannot_escape_checkout(self) -> None:
        self.contract["packages"][0]["reference_source_paths"] = ["../outside.ts"]
        self.expect_invalid("repository-relative")


if __name__ == "__main__":
    unittest.main()
