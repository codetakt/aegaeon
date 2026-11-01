# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009, PT027
from pathlib import Path
import hashlib
import os
import tempfile
import unittest
from recovery_inventory import inventory


class RecoveryInventoryTests(unittest.TestCase):
    def test_forensic_bytecode_is_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "runtime-drift/nix/store/runtime/__pycache__/case.pyc"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"changed bytecode")
            (root / "native.timing").write_bytes(b"raw observation")
            result = inventory(root, ["runtime-drift", "native.timing", "absent-optional"])
            self.assertEqual(
                {x["path"] for x in result}, {str(path.relative_to(root)), "native.timing"}
            )
            self.assertEqual(result[0]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_symlink_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            (root / "evidence/link").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                inventory(root, ["evidence"])

    def test_external_selection_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            for path in ("../outside", "/outside"):
                with self.assertRaises(ValueError):
                    inventory(temporary, [path])

    def test_symlink_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real").mkdir()
            (root / "real/raw").write_bytes(b"raw")
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(ValueError):
                inventory(root, ["alias/raw"])

    def test_selected_pipe_is_rejected_without_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "pipe")
            with self.assertRaises(ValueError):
                inventory(root, ["pipe"])

    def test_overlapping_selection_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            (root / "evidence/raw").write_bytes(b"raw")
            with self.assertRaises(ValueError):
                inventory(root, ["evidence", "evidence/raw"])


if __name__ == "__main__":
    unittest.main()
