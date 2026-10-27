# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009
"""Runtime immutability must survive a child launched without a -B flag."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from collect_one import inherited_runtime_environment


class BytecodeInheritance(unittest.TestCase):
    def test_child_cache_write_is_prevented(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "owned_probe.py").write_text("value = 1\n")
            env = os.environ.copy()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            subprocess.run(
                [sys.executable, "-c", "import owned_probe"], cwd=root, env=env, check=True
            )
            cache = next((root / "__pycache__").glob("*.pyc"))
            cache.unlink()
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "dont_write_bytecode", False),
            ):
                inherited_runtime_environment()
                subprocess.run([sys.executable, "-c", "import owned_probe"], cwd=root, check=True)
                self.assertFalse(list((root / "__pycache__").glob("*.pyc")))


if __name__ == "__main__":
    unittest.main()
