# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I002, PT009, PT027
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import runtime_dependencies as runtime


class RuntimeDependencies(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binary = Path(self.tmp.name) / "native"
        self.loader = "/nix/store/fixture-glibc/lib/ld-linux-x86-64.so.2"

    def elf(self, path=None, duplicate=False):
        path = (path or self.loader).encode() + b"\0"
        count = 2 if duplicate else 1
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", header, 18, 62)
        struct.pack_into("<Q", header, 32, 64)
        struct.pack_into("<HH", header, 54, 56, count)
        program = bytearray(56)
        struct.pack_into("<I", program, 0, 3)
        struct.pack_into("<Q", program, 8, 64 + 56 * count)
        struct.pack_into("<Q", program, 32, len(path))
        self.binary.write_bytes(header + program * count + path)

    def test_actual_interpreter_field(self):
        self.elf()
        self.assertEqual(runtime.interpreter(self.binary), self.loader)

    def test_wrong_architecture(self):
        self.elf()
        data = bytearray(self.binary.read_bytes())
        struct.pack_into("<H", data, 18, 183)
        self.binary.write_bytes(data)
        with self.assertRaises(ValueError):
            runtime.interpreter(self.binary)

    def test_truncated_header(self):
        self.binary.write_bytes(b"\x7fELF")
        with self.assertRaises(ValueError):
            runtime.interpreter(self.binary)

    def test_invalid_program_range(self):
        self.elf()
        self.binary.write_bytes(self.binary.read_bytes()[:90])
        with self.assertRaises(ValueError):
            runtime.interpreter(self.binary)

    def test_duplicate_interpreter(self):
        self.elf(duplicate=True)
        with self.assertRaises(ValueError):
            runtime.interpreter(self.binary)

    def test_non_store_interpreter(self):
        self.elf("/lib64/ld-linux-x86-64.so.2")
        with self.assertRaises(ValueError):
            runtime.interpreter(self.binary)

    def test_missing_terminator(self):
        self.elf()
        self.binary.write_bytes(self.binary.read_bytes()[:-1] + b"x")
        with self.assertRaises(ValueError):
            runtime.interpreter(self.binary)

    def test_resolution_listing(self):
        text = (
            "linux-vdso.so.1 (0x123)\nlibc.so.6 => /nix/store/fixture-glibc/lib/libc.so.6 (0x234)\n"
            + self.loader
            + " (0x456)\n"
        )
        self.assertEqual(len(runtime.parse_listing(text, self.loader)), 2)

    def test_host_loader_substitution_rejected(self):
        text = self.loader + " => /nix/store/other-glibc/lib/ld-linux-x86-64.so.2 (0x234)\n"
        with self.assertRaises(ValueError):
            runtime.parse_listing(text, self.loader)

    def test_missing_library_rejected(self):
        with self.assertRaises(ValueError):
            runtime.parse_listing("libc.so.6 => not found\n", self.loader)

    def test_ambient_preload_not_forwarded(self):
        self.elf()
        with (
            patch.object(runtime, "sha", return_value="digest"),
            patch.object(runtime.subprocess, "run") as run,
        ):
            run.return_value.stdout = (self.loader + " (0x123)\n").encode()
            run.return_value.stderr = b""
            with patch.dict(runtime.os.environ, {"LD_PRELOAD": "/unexpected.so"}):
                result = runtime.inspect(self.binary)
            self.assertEqual(run.call_args.kwargs["env"], {"LC_ALL": "C"})
            self.assertEqual(run.call_args.args[0][0], self.loader)
            self.assertEqual(result["method"], "elf-pt-interp-list/1")

    def test_binary_change_rejected(self):
        self.elf()
        with (
            patch.object(runtime, "sha", side_effect=["old", "loader", "loader", "changed"]),
            patch.object(runtime.subprocess, "run") as run,
        ):
            run.return_value.stdout = (self.loader + " (0x123)\n").encode()
            run.return_value.stderr = b""
            with self.assertRaises(ValueError):
                runtime.inspect(self.binary)


if __name__ == "__main__":
    unittest.main()
