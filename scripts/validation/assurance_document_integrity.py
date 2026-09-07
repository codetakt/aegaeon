"""Check each assurance document's declared revision, without attesting its meaning."""

from __future__ import annotations

import pathlib
from typing import Any

from jsonschema import ValidationError

DOCUMENT_FIELDS = (
    "normative_document",
    "standards_document",
    "status_document",
    "evaluation_document",
    "statement_document",
)


def read_assurance_documents(root: pathlib.Path, contract: dict[str, Any]) -> dict[str, str]:
    """Resolve local documents and reject absent, duplicate or mismatched revision metadata."""
    if contract["document_revisions"]["normative_document"] != contract["contract_revision"]:
        raise ValidationError("contract revision differs from normative document revision pin")

    documents: dict[str, str] = {}
    resolved_paths: set[pathlib.Path] = set()
    for field in DOCUMENT_FIELDS:
        path = pathlib.Path(contract[field])
        resolved = (root / path).resolve()
        if path.is_absolute() or ".." in path.parts or not resolved.is_relative_to(root.resolve()):
            raise ValidationError(f"repository-relative document required: {field}: {path}")
        if not resolved.is_file():
            raise ValidationError(f"missing local document: {field}: {path}")
        if resolved in resolved_paths:
            raise ValidationError(f"document roles must have distinct paths: {field}")
        resolved_paths.add(resolved)
        text = resolved.read_text()
        header, status_marker, _ = text.partition("\nStatus:")
        declarations = [line for line in text.splitlines() if line.startswith("Document revision:")]
        expected = f"Document revision: **{contract['document_revisions'][field]}**."
        if not status_marker or declarations != [expected] or expected not in header.splitlines():
            raise ValidationError(f"document revision missing, duplicated or mismatched: {field}")
        documents[field] = text
    return documents
