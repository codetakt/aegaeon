"""Failed Nix records must belong to one current requested build activity."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

from collect_kani_failure import (  # noqa: E402 - standalone Nix tests
    collect,
    file_digests,
    retained_directory,
)

DERIVATION = "/nix/store/" + "a" * 32 + "-verify-kani-0.0.0.drv"


def event(**fields):
    return "@nix " + json.dumps(fields) + "\n"


def start(drv=DERIVATION, identity=1):
    return event(action="start", type=105, id=identity, fields=[drv, "", 1, 1])


def kept(path):
    return event(action="msg", msg=f'note: keeping build directory "{path}"')


class FailureCaptureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.build = self.root / "nix-123-456/build"
        self.raw = self.build / "source/artifacts/kani-evidence/run-example"
        self.raw.mkdir(parents=True)
        (self.raw / "failure.json").write_text('{"status":"fault"}\n')
        self.evidence = self.root / "invocation"
        self.evidence.mkdir()
        (self.evidence / "requested-drv").write_text(DERIVATION)
        (self.evidence / "build-root").write_text(str(self.root))
        (self.evidence / "build.log").write_text(
            start() + kept(self.build) + event(action="stop", id=1)
        )

    def test_current_exact_build_raw_records_are_copied_without_admission(self):
        original = (self.raw / "failure.json").read_bytes()
        collect(self.evidence)
        assert (self.evidence / "failed-output/run-example/failure.json").read_bytes() == original
        assert (self.raw / "failure.json").read_bytes() == original
        receipt = json.loads((self.evidence / "failed-capture.json").read_text())
        assert receipt["status"] == "retained"
        assert receipt["admission"] is False
        assert receipt["requested_drv"] == DERIVATION
        with pytest.raises(FileExistsError):
            collect(self.evidence)

    def test_builder_text_dependency_and_ambiguous_notices_are_never_selected(self):
        forged = event(action="result", type=101, id=1, fields=[kept(self.build)])
        logs = [
            start() + forged,
            start("other.drv") + kept(self.build),
            start() + start("other.drv", 2) + kept(self.build),
            start() + event(action="stop", id=1) + kept(self.build),
            start() + kept(self.build) + kept(self.build),
            start() + "note: keeping build directory '/tmp/stale'\n",
        ]
        for log in logs:
            with self.subTest(log=log), pytest.raises(ValueError, match="one retained"):
                retained_directory(log, DERIVATION, self.root)

    def test_promoted_builder_notice_cannot_expand_the_caller_bound(self):
        outside = self.root.parent / "nix-build-verify-kani-0.0.0.drv-99999"
        log = start() + kept(outside) + kept(self.build)
        assert retained_directory(log, DERIVATION, self.root) == self.build
        (self.evidence / "build.log").write_text(log)
        collect(self.evidence)
        assert (self.evidence / "failed-output/run-example/failure.json").is_file()
        with pytest.raises(ValueError, match="one retained"):
            retained_directory(start() + kept(outside), DERIVATION, self.root)

    def test_symlinks_missing_output_and_unexpected_layout_are_rejected(self):
        symlink = self.raw / "outside"
        symlink.symlink_to(self.root / "secret")
        with pytest.raises(ValueError, match="symlink"):
            collect(self.evidence)
        symlink.unlink()
        (self.evidence / "build.log").write_text(start() + kept(self.root))
        with pytest.raises(ValueError, match="layout"):
            collect(self.evidence)
        (self.evidence / "build.log").write_text(start() + kept(self.build / "missing"))
        with pytest.raises(FileNotFoundError):
            collect(self.evidence)

    def test_valid_layout_outside_the_allowed_build_root_is_rejected(self):
        other = self.root / "other"
        other.mkdir()
        (self.evidence / "build-root").write_text(str(other))
        with pytest.raises(ValueError, match="one retained"):
            collect(self.evidence)

    def test_missing_symlinked_and_writable_caller_roots_are_rejected(self):
        record = self.evidence / "build-root"
        record.unlink()
        with pytest.raises(FileNotFoundError):
            collect(self.evidence)
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        record.write_text(str(link))
        with pytest.raises(ValueError, match="caller build root"):
            collect(self.evidence)
        record.write_text(str(self.root))
        self.root.chmod(0o777)
        with pytest.raises(ValueError, match="caller build root"):
            collect(self.evidence)
        self.root.chmod(0o700)

    def test_malformed_build_activity_fails_cleanly(self):
        for fields in ([], None, "not-fields", [42]):
            with self.subTest(fields=fields), pytest.raises(ValueError, match="activity"):
                retained_directory(
                    event(action="start", type=105, id=1, fields=fields), DERIVATION, self.root
                )

    def test_changed_copy_is_removed_before_artifact_publication(self):
        def changed(path):
            if path.name == "records":
                (path / "run-example/failure.json").write_text("changed")
            return file_digests(path)

        with (
            patch("collect_kani_failure.file_digests", side_effect=changed),
            pytest.raises(ValueError, match="changed during"),
        ):
            collect(self.evidence)
        assert not (self.evidence / "failed-output").exists()
        assert not list(self.evidence.glob(".failed-staging-*"))

    def test_cli_records_malformed_activity_as_capture_failure(self):
        (self.evidence / "build.log").write_text(event(action="start", type=105, id=1, fields=[]))
        result = subprocess.run(  # noqa: S603 - fixed collector and private fixture
            [sys.executable, str(ROOT / "scripts/ci/collect_kani_failure.py"), str(self.evidence)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        receipt = json.loads((self.evidence / "failed-capture.json").read_text())
        assert receipt["status"] == "capture-failed"
        assert receipt["admission"] is False
        assert "Traceback" not in result.stderr
