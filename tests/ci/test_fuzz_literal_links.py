# ruff: noqa: PT009, PT027 - standalone unittest controls remain effective under Python -O
"""Preserve raw symlink spelling while admitting only the exact Kani pointer."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


class FuzzLiteralLinkTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory(prefix="fuzz-literal-links-"))
        self.root = Path(temporary) / "source"
        self.root.mkdir()
        self.outside = Path(temporary) / "outside"
        self.outside.mkdir()
        self.sentinel = self.outside / "private-input"
        self.sentinel.write_bytes(b"external bytes remain private")
        self.helper = runpy.run_path(str(ROOT / "scripts/fuzz/manage_fuzz_corpus.py"))
        self.state = self.helper["raw_inventory"].__globals__
        fuzz = self.root / "fuzz"
        fuzz.mkdir()
        self.enterContext(
            mock.patch.dict(
                self.state,
                ROOT=self.root,
                FUZZ_DIR=fuzz,
                CORPUS_ROOT=fuzz / "corpus",
                CRASH_ROOT=fuzz / "artifacts",
                ARCHIVE_DIR=fuzz / "corpus_archive",
                META_DIR=fuzz / "corpus_meta",
                RUN_ARTIFACT_DIR=None,
                HISTORY_OUT_DIR=None,
            )
        )
        self.enterContext(
            mock.patch.dict(os.environ, CARGO_HOME=str(Path(temporary) / "cargo-home"))
        )
        actual_open = self.state["open_evidence_file"]

        def guarded_open(path, *args, **kwargs):
            path = Path(path)
            self.assertFalse(path.is_symlink(), "link content must never be opened")
            self.assertFalse(path.resolve().is_relative_to(self.outside), "external target read")
            return actual_open(path, *args, **kwargs)

        self.enterContext(mock.patch.dict(self.state, open_evidence_file=guarded_open))

    def seed_links(self, raw_name):
        directory = self.root / "fuzz" / raw_name / "fuzz_par"
        (directory / "dir").mkdir(parents=True)
        (directory / "seed").write_bytes(b"owned seed")
        (directory / "dir/seed").write_bytes(b"owned nested seed")
        targets = {
            "dot-prefix": "./seed",
            "separators": "dir//seed",
            "combined": "./dir///./seed",
            "dangling": "./missing///./seed",
            "undecodable": os.fsdecode(b"./missing///\xff"),
            "external": str(self.outside) + "//./private-input",
        }
        for name, target in targets.items():
            (directory / name).symlink_to(target)
        return directory, targets

    def assert_inventory_links(self, directory, targets):
        inventory = self.helper["raw_inventory"](directory)
        for name, target in targets.items():
            self.assertEqual(inventory[name], {"type": "symlink", "target": target})
            self.assertEqual(os.fsencode(inventory[name]["target"]), os.fsencode(target))
            self.assertEqual(os.fsencode(os.readlink(directory / name)), os.fsencode(target))  # noqa: PTH115
        self.assertEqual(self.sentinel.read_bytes(), b"external bytes remain private")
        return inventory

    def assert_archive_links(self, archive, prefix, targets):
        with tarfile.open(archive) as content:
            for name, target in targets.items():
                member = content.getmember(prefix + "/" + name)
                self.assertTrue(member.issym())
                self.assertEqual(os.fsencode(member.linkname), os.fsencode(target))
            self.assertFalse(any(member.name.endswith("private-input") for member in content))
        self.assertEqual(self.sentinel.read_bytes(), b"external bytes remain private")

    def test_raw_inventory_retains_literal_targets_without_following_links(self):
        for raw_name in ("corpus", "artifacts"):
            with self.subTest(raw_name=raw_name):
                directory, targets = self.seed_links(raw_name)
                self.assert_inventory_links(directory, targets)

    def test_corpus_and_crash_archives_preserve_literal_nested_targets(self):
        corpus, corpus_targets = self.seed_links("corpus")
        crashes, crash_targets = self.seed_links("artifacts")
        archive = self.helper["create_archive"]()
        self.assertIsNotNone(archive)
        self.assert_archive_links(archive, "corpus/fuzz_par", corpus_targets)
        crash_archive = self.helper["archive_crashes"](self.helper["gather_crash_stats"](), None)
        self.assertIsNotNone(crash_archive)
        self.assert_archive_links(crash_archive, "fuzz_par", crash_targets)
        self.assert_inventory_links(corpus, corpus_targets)
        self.assert_inventory_links(crashes, crash_targets)

    def test_upload_inventory_and_archive_preserve_literal_nested_targets(self):
        corpus, corpus_targets = self.seed_links("corpus")
        crashes, crash_targets = self.seed_links("artifacts")
        output = self.root / "artifacts/upload"
        self.helper["package_upload"](output)
        manifest = json.loads((output / "manifest.json").read_text())
        for raw_name, targets in (("corpus", corpus_targets), ("artifacts", crash_targets)):
            with self.subTest(raw_name=raw_name):
                frozen = manifest["roots"]["fuzz/" + raw_name]["entries"]
                for name, target in targets.items():
                    self.assertEqual(frozen["fuzz_par/" + name]["target"], target)
                self.assert_archive_links(
                    output / "security-evidence.tar.gz", "fuzz/" + raw_name + "/fuzz_par", targets
                )
        self.assert_inventory_links(corpus, corpus_targets)
        self.assert_inventory_links(crashes, crash_targets)

    def test_recovery_copy_and_restore_preserve_literal_nested_targets(self):
        corpus, corpus_targets = self.seed_links("corpus")
        crashes, crash_targets = self.seed_links("artifacts")
        recovery = self.root / "artifacts/recovery"
        recovery.mkdir(parents=True)
        records = self.helper["copy_raw_backups"](recovery)
        manifest = json.loads(json.dumps({"raw": records}))
        self.helper["validate_raw_backups"](recovery, manifest)
        for raw_name, targets in (("corpus", corpus_targets), ("artifacts", crash_targets)):
            for name, target in targets.items():
                self.assertEqual(
                    records[raw_name]["inventory"]["fuzz_par/" + name]["target"], target
                )
            self.assert_inventory_links(recovery / "raw" / raw_name / "fuzz_par", targets)
            shutil.rmtree(self.root / "fuzz" / raw_name)
        self.helper["restore_raw_copy"](recovery, manifest)
        self.assert_inventory_links(corpus, corpus_targets)
        self.assert_inventory_links(crashes, crash_targets)
        self.helper["validate_raw_backups"](recovery, manifest)

    def test_kani_requires_exact_literal_target_and_preserves_hash(self):
        (self.root / "Cargo.toml").write_text('[workspace]\nexclude = ["crates/kani-harness"]\n')
        pointer = self.root / "crates/kani-harness/kani"
        pointer.parent.mkdir(parents=True)
        exact = "result/bin/cargo-kani"
        pointer.symlink_to(exact)
        expected = self.helper["kani_output_pointer"]()
        self.assertEqual(expected["target"], exact)
        self.assertEqual(expected["sha256"], hashlib.sha256(os.fsencode(exact)).hexdigest())
        for target in (
            "./result/bin/cargo-kani",
            "result//bin/cargo-kani",
            "result/bin//cargo-kani",
            "result/./bin/cargo-kani",
            "result///bin/./cargo-kani",
        ):
            with self.subTest(target=target):
                pointer.unlink()
                pointer.symlink_to(target)
                with self.assertRaisesRegex(
                    ValueError, "Kani output pointer is missing or changed"
                ):
                    self.helper["kani_output_pointer"]()
        pointer.unlink()
        pointer.symlink_to(exact)
        self.assertEqual(self.helper["kani_output_pointer"](), expected)


if __name__ == "__main__":
    unittest.main()
