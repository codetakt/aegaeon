"""Content changes must not disappear behind volatile source-wrapper restoration."""

from __future__ import annotations

import hashlib
import unittest

import pytest
import restore_lti_source_wrapper as subject


class LtiSourceRestorationTests(unittest.TestCase):
    def setUp(self) -> None:
        # Synthetic wrapper only; no third-party specification text is copied.
        self.original = (
            b'<link href="https://www.imsglobal.org/sites/default/x.css?abcdef">'
            b'"https:\\/\\/www.imsglobal.org\\/sites\\/files\\/googleanalytics\\/js?abcdef"'
            b'"ajaxPageState":{"theme":"ims_spec","theme_token":"'
            + b"a" * 43
            + b'","css":{}}<main>normative fixture</main>'
        )
        self.metadata: subject.Wrapper = {
            "sha256": hashlib.sha256(self.original).hexdigest(),
            "cache_token": "abcdef",
            "theme_token": "a" * 43,
            "asset_count": 2,
        }
        self.download = self.original.replace(b"abcdef", b"123abc").replace(b"a" * 43, b"b" * 43)

    def test_restores_exact_original_and_is_idempotent(self) -> None:
        for raw in (self.download, self.original):
            assert subject.restore(raw, **self.metadata) == self.original

    def test_changed_content_markup_host_or_extra_fields_are_rejected(self) -> None:
        for raw in (
            self.download.replace(b"normative", b"altered"),
            self.download.replace(b"<main>", b"<main hidden>"),
            self.download.replace(b"www.imsglobal.org", b"www.imsglobal.org.evil"),
            self.download + b'"theme_token":"' + b"b" * 43 + b'"',
            self.download + b"123abc",
        ):
            with self.subTest(raw=raw), pytest.raises(ValueError, match="LTI"):
                subject.restore(raw, **self.metadata)

    def test_missing_duplicated_and_inconsistent_wrapper_fields_are_rejected(self) -> None:
        for raw in (
            self.download.replace(b"theme_token", b"other_token"),
            self.download.replace(b"123abc", b"456def", 1),
            self.download + self.download,
        ):
            with self.subTest(raw=raw), pytest.raises(ValueError, match="LTI"):
                subject.restore(raw, **self.metadata)

    def test_oversized_download_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="size limit"):
            subject.restore(b"x" * (subject.MAX_BYTES + 1), **self.metadata)


if __name__ == "__main__":
    unittest.main()
