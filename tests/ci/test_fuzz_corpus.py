# ruff: noqa: PT009 - these controls run under unittest discovery
"""Exercise the actual corpus helper, including required metadata/archive writes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class FuzzCorpusTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory(prefix="fuzz-corpus-test-"))
        self.root = Path(temporary) / "source"
        self.root.mkdir()
        self.helper = self.root / "scripts/fuzz/manage_fuzz_corpus.py"
        self.helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/fuzz/manage_fuzz_corpus.py", self.helper)
        fuzz = self.root / "fuzz"
        fuzz.mkdir()
        shutil.copyfile(ROOT / "fuzz/Cargo.toml", fuzz / "Cargo.toml")
        self.artifacts = Path(temporary) / "artifacts"
        self.history = Path(temporary) / "history"
        self.env = {
            **os.environ,
            "FUZZ_RUN_ARTIFACT_DIR": str(self.artifacts),
            "FUZZ_HISTORY_DIR": str(self.history),
        }

    def run_helper(self):
        # The caller's cwd is intentionally unrelated to the helper's repository.
        return subprocess.run(  # noqa: S603 - execute the real wrapper and controlled fixtures
            [sys.executable, str(self.helper)],
            cwd=self.helper.parent,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_root_is_repository_and_all_manifest_targets_get_stats(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads((self.artifacts / "run_summary.json").read_text())
        self.assertEqual(len(summary["targets"]), 7)
        self.assertTrue((self.root / "fuzz/corpus/fuzz_par").is_dir())
        self.assertFalse((self.root / "scripts/fuzz/corpus").exists())

    def test_crashes_and_corpus_are_copied_to_artifacts_and_history(self):
        for name in ("corpus", "artifacts"):
            folder = self.root / "fuzz" / name / "fuzz_par"
            folder.mkdir(parents=True)
            (folder / "input").write_text("preserve these bytes")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads((self.artifacts / "run_summary.json").read_text())
        for key, member in (
            ("corpus_archive", "corpus/fuzz_par/input"),
            ("crash_archive", "fuzz_par/input"),
        ):
            archive = self.artifacts / summary[key]
            self.assertEqual(archive.read_bytes(), (self.history / archive.name).read_bytes())
            with tarfile.open(archive) as tar:
                self.assertEqual(tar.extractfile(member).read(), b"preserve these bytes")

    def copy_archive(self, archive, destination):
        return subprocess.run(  # noqa: S603 - invoke the actual helper with owned path fixtures
            [
                sys.executable,
                "-c",
                (
                    "import pathlib,runpy,sys\n"
                    "helper=runpy.run_path(sys.argv[1])\n"
                    "helper['copy_into'](pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))\n"
                ),
                str(self.helper),
                str(archive),
                str(destination),
            ],
            cwd=self.helper.parent,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_archive_copies_reject_file_aliases_specials_and_parent_aliases(self):
        archive = self.root / "fuzz/archive-control.tar.gz"
        archive.write_bytes(b"owned archive bytes")
        for destination in (self.artifacts, self.history):
            for kind in ("symlink", "dangling-symlink", "hardlink", "parent-symlink", "fifo"):
                with self.subTest(destination=destination.name, alias=kind):
                    external = self.root.parent / f"external-{destination.name}-{kind}"
                    external.mkdir()
                    sentinel = external / archive.name
                    if kind != "dangling-symlink":
                        sentinel.write_bytes(b"external bytes must remain unchanged")
                    original = {path.name: path.read_bytes() for path in external.iterdir()}
                    route = destination / kind
                    if kind == "parent-symlink":
                        route.parent.mkdir(parents=True, exist_ok=True)
                        route.symlink_to(external, target_is_directory=True)
                    else:
                        route.mkdir(parents=True)
                        target = route / archive.name
                        if kind in ("symlink", "dangling-symlink"):
                            target.symlink_to(sentinel)
                        elif kind == "hardlink":
                            os.link(sentinel, target)
                        else:
                            os.mkfifo(target)
                    result = self.copy_archive(archive, route)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in external.iterdir()}, original
                    )
                    self.assertEqual(archive.read_bytes(), b"owned archive bytes")

    def test_archive_copies_create_new_routes_and_replace_owned_single_link_files(self):
        archive = self.root / "fuzz/archive-control.tar.gz"
        archive.write_bytes(b"owned replacement archive")
        for destination in (self.artifacts, self.history):
            route = destination / "fresh" / "nested"
            first = self.copy_archive(archive, route)
            self.assertEqual(first.returncode, 0, first.stderr)
            copied = route / archive.name
            self.assertEqual(copied.read_bytes(), b"owned replacement archive")
            copied.write_bytes(b"old owned archive")
            second = self.copy_archive(archive, route)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(copied.read_bytes(), archive.read_bytes())
            self.assertEqual(copied.stat().st_nlink, 1)

    def test_missing_empty_duplicate_malformed_manifests_fail(self):
        manifest = self.root / "fuzz/Cargo.toml"
        for content in (
            None,
            "[package]\nname='empty'",
            "[[bin]]\nname='fuzz_x'\n[[bin]]\nname='fuzz_x'",
            "[[broken",
        ):
            with self.subTest(content=content):
                if content is None:
                    manifest.unlink()
                else:
                    manifest.write_text(content)
                self.assertNotEqual(self.run_helper().returncode, 0)

    def test_failed_archive_or_history_copy_is_not_silently_ignored(self):
        corpus = self.root / "fuzz/corpus/fuzz_par"
        corpus.mkdir(parents=True)
        (corpus / "seed").write_text("input")
        self.history.write_text("cannot be a destination directory")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "fuzz/corpus_archive").exists())
        self.assertTrue((corpus / "seed").exists())

    def test_archive_retention_cleanup_failure_is_an_error(self):
        corpus = self.root / "fuzz/corpus/fuzz_par"
        corpus.mkdir(parents=True)
        (corpus / "seed").write_text("input")
        archives = self.root / "fuzz/corpus_archive"
        archives.mkdir()
        (archives / "0000.tar.gz").mkdir()
        self.env["CORPUS_ARCHIVE_KEEP"] = "1"
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((corpus / "seed").exists())

    def test_unwritable_summary_is_an_error_even_after_archive_collection(self):
        self.artifacts.mkdir()
        (self.artifacts / "run_summary.json").mkdir()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "fuzz/corpus_meta/latest_run.json").is_file())

    def test_direct_collection_rejects_evidence_alias_and_raw_overlap_before_changes(self):
        external = self.root.parent / "external"
        external.mkdir()
        sentinel = external / "run_summary.json"
        sentinel.write_bytes(b"external private receipt")
        alias = self.root.parent / "alias"
        alias.symlink_to(external, target_is_directory=True)
        raw = self.root / "fuzz/corpus/owned"
        raw.mkdir(parents=True)
        (raw / "run_summary.json").write_bytes(b"raw private input")
        for route in (alias / "nested", raw):
            with self.subTest(route=route):
                self.env["FUZZ_RUN_ARTIFACT_DIR"] = str(route)
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(sentinel.read_bytes(), b"external private receipt")
                self.assertEqual((raw / "run_summary.json").read_bytes(), b"raw private input")
                self.assertFalse((self.root / "fuzz/corpus_meta").exists())
                self.assertFalse((self.root / "fuzz/corpus_archive").exists())

    def test_relative_optional_outputs_are_repository_anchored_with_newlines(self):
        self.env["FUZZ_RUN_ARTIFACT_DIR"] = "collection-evidence\n"
        self.env["FUZZ_HISTORY_DIR"] = "collection-history\n"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "collection-evidence\n/run_summary.json").is_file())
        self.assertTrue((self.root / "collection-history\n/fuzz_runs.jsonl").is_file())
        self.assertFalse((self.helper.parent / "collection-evidence\n").exists())
        self.assertFalse((self.helper.parent / "collection-history\n").exists())

    def test_relative_history_does_not_follow_an_unvalidated_caller_alias(self):
        external = self.root.parent / "external-history"
        external.mkdir()
        sentinel = external / "fuzz_runs.jsonl"
        sentinel.write_bytes(b"preserve external history\n")
        (self.helper.parent / "relative-history").symlink_to(external)
        self.env["FUZZ_HISTORY_DIR"] = "relative-history"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"preserve external history\n")
        self.assertTrue((self.root / "relative-history/fuzz_runs.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
