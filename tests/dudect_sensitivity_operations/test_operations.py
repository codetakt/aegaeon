# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: EM101, I001, I002, PT009, PT027, TRY003
import copy  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
import hashlib  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import chunks
from deadline import enforce, bounded_json_command

AGE = Path("/nix/store/bxhg68dzx0xnxh4fc9nsanxm1l5zxp71-age-1.3.2/bin/age")


class Transport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "identity"
        subprocess.run(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            [str(AGE.parent / "age-keygen"), "-o", str(self.key)], check=True, capture_output=True
        )
        self.recipient = subprocess.check_output(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            [str(AGE.parent / "age-keygen"), "-y", str(self.key)], text=True
        ).strip()
        self.data = os.urandom(3500)
        self.path = self.root / "archive"

    def tearDown(self):
        self.temp.cleanup()

    def pack(self, **kwargs):
        return chunks.encrypt(
            [self.data],
            self.path,
            AGE,
            self.recipient,
            "fixed-generation",
            time.monotonic() + 10,
            chunk_size=1024,
            **kwargs,
        )

    def unpack(self, receipt):
        return b"".join(
            chunks.decrypt_chunks(self.path, AGE, self.key, receipt, time.monotonic() + 10)
        )

    def test_roundtrip_multiple_chunks(self):
        self.assertEqual(self.unpack(self.pack()), self.data)

    def test_ciphertext_corruption(self):
        r = self.pack()
        p = self.path / "000001.age"
        b = bytearray(p.read_bytes())
        b[-1] ^= 1
        p.write_bytes(b)
        with self.assertRaises(ValueError):
            self.unpack(r)

    def test_manifest_corruption(self):
        r = self.pack()
        p = self.path / "manifest.age"
        p.write_bytes(p.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            self.unpack(r)

    def test_other_generation(self):
        r = self.pack()
        r["generation"] = "another"
        with self.assertRaises(ValueError):
            self.unpack(r)

    def test_missing_last_chunk_keeps_verified_prefix(self):
        r = self.pack()
        (self.path / "000003.age").unlink()
        actual = bytearray()
        with self.assertRaises(FileNotFoundError):
            for block in chunks.decrypt_chunks(self.path, AGE, self.key, r, time.monotonic() + 10):
                actual.extend(block)
        self.assertEqual(bytes(actual), self.data[:3072])

    def test_reordered_chunks(self):
        r = self.pack()
        a = self.path / "000000.age"
        b = self.path / "000001.age"
        x = a.read_bytes()
        a.write_bytes(b.read_bytes())
        b.write_bytes(x)
        with self.assertRaises(ValueError):
            self.unpack(r)

    def test_plaintext_capacity(self):
        with self.assertRaisesRegex(ValueError, "Raw capacity"):
            self.pack(raw_limit=3000)

    def test_encrypted_capacity(self):
        with self.assertRaisesRegex(ValueError, "capacity"):
            self.pack(cipher_limit=3000)

    def test_wrong_key(self):
        r = self.pack()
        self.key.write_text("invalid")
        with self.assertRaises(ValueError):
            self.unpack(r)

    def test_expired_decryption(self):
        r = self.pack()
        with self.assertRaisesRegex(ValueError, "deadline"):
            list(chunks.decrypt_chunks(self.path, AGE, self.key, r, time.monotonic() - 1))

    def test_partial_archive(self):
        def broken():
            yield self.data
            raise OSError("producer failed")

        with self.assertRaises(OSError):
            chunks.encrypt(
                broken(),
                self.path,
                AGE,
                self.recipient,
                "fixed-generation",
                time.monotonic() + 10,
                chunk_size=1024,
            )
        # Inspect authenticated manifest rather than treating it as a complete run.
        meta = json.loads(
            subprocess.check_output(  # noqa: S603 -- explicit argv; artifact validation precedes execution
                [str(AGE), "-d", "-i", str(self.key), str(self.path / "manifest.age")]
            )
        )
        self.assertFalse(meta["complete"])
        self.assertEqual(len(meta["chunks"]), 3)

    def test_authentication_even_with_updated_outer_hash(self):
        r = self.pack()
        p = self.path / "000000.age"
        b = bytearray(p.read_bytes())
        b[-1] ^= 1
        p.write_bytes(b)
        meta = json.loads(
            subprocess.check_output(  # noqa: S603 -- explicit argv; artifact validation precedes execution
                [str(AGE), "-d", "-i", str(self.key), str(self.path / "manifest.age")]
            )
        )
        meta["chunks"][0]["cipher_sha256"] = chunks.sha(p)
        encrypted = subprocess.check_output(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            [str(AGE), "-r", self.recipient], input=chunks.canonical(meta)
        )
        (self.path / "manifest.age").write_bytes(encrypted)
        r["manifest_sha256"] = chunks.sha(self.path / "manifest.age")
        r["manifest_bytes"] = len(encrypted)
        with self.assertRaisesRegex(ValueError, "Authenticated"):
            self.unpack(r)


class Guard(unittest.TestCase):
    def test_actual_api_command_timeout(self):
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            bounded_json_command([sys.executable, "-c", "import time;time.sleep(60)"], start + 0.1)
        self.assertLess(time.monotonic() - start, 2)

    def test_actual_api_error(self):
        with self.assertRaises(OSError):
            bounded_json_command(
                [sys.executable, "-c", "raise SystemExit(1)"], time.monotonic() + 2
            )

    def test_actual_api_json(self):
        self.assertEqual(
            bounded_json_command(
                [sys.executable, "-c", 'print("{\\"state\\":\\"stopped\\"}")'], time.monotonic() + 2
            ),
            {"state": "stopped"},
        )

    def test_actual_api_oversize(self):
        with self.assertRaises(OSError):
            bounded_json_command(
                [sys.executable, "-c", 'print("x"*(1024**2+2))'], time.monotonic() + 2
            )

    def run_fake(self, mode):
        now = [0.0]
        calls = []

        class API:
            def identity(self, r, end):
                calls.append("identity")
                if mode == "identity_timeout":
                    raise TimeoutError
                return "wrong" if mode == "reused" else "generation"

            def stop(self, r, end):
                calls.append("stop")
                if mode == "stop_error":
                    raise OSError

            def state(self, r, end):
                calls.append("state")
                if mode == "state_error":
                    raise TimeoutError
                if mode == "late":
                    now[0] = end + 1
                return "running" if mode == "never" else "stopped"

        def sleep(n):
            now[0] += n

        return enforce(API(), "owned", "generation", 1, 2, lambda: now[0], sleep), calls

    def test_stop_confirmed(self):
        self.assertTrue(self.run_fake("ok")[0]["stop_confirmed"])

    def test_identity_reuse_rejected(self):
        result, calls = self.run_fake("reused")
        self.assertFalse(result["stop_confirmed"])
        self.assertNotIn("stop", calls)

    def test_identity_timeout(self):
        self.assertEqual(self.run_fake("identity_timeout")[0]["status"], "stop_unconfirmed")

    def test_stop_failure(self):
        self.assertEqual(self.run_fake("stop_error")[0]["status"], "stop_unconfirmed")

    def test_readback_failure(self):
        self.assertEqual(self.run_fake("state_error")[0]["status"], "stop_unconfirmed")

    def test_never_stops(self):
        self.assertEqual(self.run_fake("never")[0]["status"], "stop_unconfirmed")

    def test_late_success_not_confirmed(self):
        self.assertEqual(self.run_fake("late")[0]["status"], "stop_unconfirmed")

    def test_independent_guard_stops_sigstopped_owner(self):
        with tempfile.TemporaryDirectory() as d:
            child = subprocess.Popen(
                [sys.executable, "-c", "import time;time.sleep(60)"], start_new_session=True
            )
            try:
                start = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                os.kill(child.pid, signal.SIGSTOP)
                output = Path(d) / "result.json"
                guard = subprocess.Popen(  # noqa: S603 -- explicit argv; artifact validation precedes execution
                    [
                        sys.executable,
                        str(Path(__file__).with_name("deadline.py")),
                        "--pid",
                        str(child.pid),
                        "--start",
                        start,
                        "--deadline",
                        str(time.monotonic() + 0.3),
                        "--output",
                        str(output),
                    ],
                    start_new_session=True,
                )
                self.assertEqual(guard.wait(timeout=5), 0)
                self.assertEqual(child.wait(timeout=3), -signal.SIGKILL)
                self.assertTrue(json.loads(output.read_text())["stop_confirmed"])
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    unittest.main()
