"""Exercise the SBOM generator through its CLI with controlled cargo/cosign processes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/release/generate_sbom.py"

CARGO = r"""
import json, os, pathlib, subprocess, sys, time
if '--version' in sys.argv:
    print('cargo-cyclonedx 0.5.9')
    raise SystemExit(0)
mode = os.environ.get('CASE', 'ok')
p = pathlib.Path('crates/server/aegaeon-server.cdx.json')
assert not p.exists(), 'stale generated file reached the snapshot'
if mode == 'timeout':
    child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'])
    pathlib.Path(os.environ['TEST_PID']).write_text(str(child.pid))
    time.sleep(60)
if mode == 'fail':
    p.write_text('{}')
    raise SystemExit(17)
if mode == 'missing':
    raise SystemExit(0)
if mode == 'malformed':
    p.write_text('{')
    raise SystemExit(0)
if mode == 'lock':
    pathlib.Path('Cargo.lock').write_text('modified')
bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
       'metadata': {'component': {'name': 'aegaeon-server', 'version': '1.2.3'}},
       'components': [{'type': 'library', 'name': 'dependency', 'version': '0.1'}]}
if mode == 'wrong-name':
    bom['metadata']['component']['name'] = 'aegaeon-client'
if mode == 'wrong-version':
    bom['metadata']['component']['version'] = '0.9.0-beta'
if mode == 'wrong-format':
    bom['bomFormat'] = 'SPDX'
if mode == 'wrong-shape':
    bom['metadata'] = []
if mode == 'wrong-components':
    bom['components'] = {}
if mode == 'wrong-serial':
    bom['serialNumber'] = 'urn:uuid:garbage'
p.write_text(json.dumps(bom))
if mode == 'symlink':
    p.rename(p.with_suffix('.bak'))
    p.symlink_to(p.with_suffix('.bak').name)
"""

COSIGN = r"""
import os, pathlib, sys
if os.environ.get('SIGN_CASE') == 'fail':
    raise SystemExit(19)
if os.environ.get('SIGN_CASE') != 'missing':
    for flag in ('--output-signature', '--output-certificate'):
        pathlib.Path(sys.argv[sys.argv.index(flag) + 1]).write_text('test output')
"""


class SbomGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sbom-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.output = Path(self.temp.name) / "output"
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        for name, code in (("cargo", CARGO), ("cargo-cyclonedx", CARGO), ("cosign", COSIGN)):
            file = self.bin / name
            file.write_text(f"#!{sys.executable}\n" + code)
            file.chmod(0o700)
        self.git("init", "--quiet")
        (self.root / "crates/server").mkdir(parents=True)
        (self.root / "Cargo.lock").write_text("version = 4\n")
        (self.root / "crates/server/Cargo.toml").write_text(
            '[package]\nname = "aegaeon-server"\nversion = "1.2.3"\n'
        )
        # Even a tracked, valid old SBOM must be absent at generation time.
        (self.root / "crates/server/aegaeon-server.cdx.json").write_text('{"old":true}')
        self.git("add", ".")
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "OUTPUT_DIR": str(self.output),
            "SBOM_TIMEOUT_SECONDS": "5",
            "SBOM_FORMAT": "cyclonedx",
            "SBOM_VERSION": "1.5",
            "ENABLE_COSIGN_SIGNING": "0",
        }

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def run_generator(self, **env):
        return subprocess.run(
            [sys.executable, str(GENERATOR)],
            cwd=self.root,
            env={**self.env, **env},
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def assert_rejected(self, **env):
        result = self.run_generator(**env)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.output / "aegaeon-sbom-latest.json").exists())
        return result

    def test_success_records_actual_inputs_and_preserves_generator_metadata(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = (self.output / "aegaeon-sbom-latest.json").resolve()
        bom = json.loads(artifact.read_text())
        self.assertEqual(bom["metadata"]["component"]["version"], "1.2.3")
        self.assertTrue(bom["serialNumber"].startswith("urn:uuid:"))
        provenance = json.loads((artifact.parent / "provenance.json").read_text())
        self.assertFalse(provenance["release_binary_attestation"])
        inputs = json.loads((artifact.parent / "source-inputs.json").read_text())
        self.assertEqual({x["path"] for x in inputs}, {"Cargo.lock", "crates/server/Cargo.toml"})
        self.assertEqual(
            (self.root / "crates/server/aegaeon-server.cdx.json").read_text(), '{"old":true}'
        )
        self.assertEqual((self.root / "Cargo.lock").read_text(), "version = 4\n")

    def test_generator_failure_does_not_reuse_stale_file(self):
        self.assert_rejected(CASE="fail")

    def test_missing_output_does_not_reuse_stale_file(self):
        self.assert_rejected(CASE="missing")

    def test_malformed_output_is_rejected(self):
        self.assert_rejected(CASE="malformed")

    def test_other_package_is_rejected(self):
        self.assert_rejected(CASE="wrong-name")

    def test_other_version_is_rejected(self):
        self.assert_rejected(CASE="wrong-version")

    def test_wrong_format_is_rejected(self):
        self.assert_rejected(CASE="wrong-format")

    def test_wrong_metadata_shape_is_rejected(self):
        self.assert_rejected(CASE="wrong-shape")

    def test_wrong_components_shape_is_rejected(self):
        self.assert_rejected(CASE="wrong-components")

    def test_invalid_serial_is_rejected(self):
        self.assert_rejected(CASE="wrong-serial")

    def test_generated_symlink_is_rejected(self):
        self.assert_rejected(CASE="symlink")

    def test_lockfile_rewrite_is_rejected_and_original_is_preserved(self):
        self.assert_rejected(CASE="lock")
        self.assertEqual((self.root / "Cargo.lock").read_text(), "version = 4\n")

    def test_timeout_kills_descendant_and_does_not_publish(self):
        pidfile = Path(self.temp.name) / "child.pid"
        self.assert_rejected(CASE="timeout", SBOM_TIMEOUT_SECONDS="1", TEST_PID=str(pidfile))
        pid = int(pidfile.read_text())
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            self.assertEqual(stat.read_text().split()[2], "Z")

    def test_signing_failure_is_fatal(self):
        self.assert_rejected(ENABLE_COSIGN_SIGNING="1", SIGN_CASE="fail")

    def test_signer_success_without_outputs_is_fatal(self):
        self.assert_rejected(ENABLE_COSIGN_SIGNING="1", SIGN_CASE="missing")

    def test_signing_requires_the_tool(self):
        (self.bin / "cosign").unlink()
        # Hide any host cosign without hiding the required git executable.

        (self.bin / "git").symlink_to(shutil.which("git"))
        self.assert_rejected(ENABLE_COSIGN_SIGNING="1", PATH=str(self.bin))

    def test_successful_signing_outputs_are_bound_to_record(self):
        result = self.run_generator(ENABLE_COSIGN_SIGNING="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = (self.output / "aegaeon-sbom-latest.json").resolve()
        record = json.loads((artifact.parent / "provenance.json").read_text())
        self.assertEqual(
            record["artifacts"]["aegaeon-sbom.sig"], record["artifacts"]["aegaeon-sbom.crt"]
        )
        self.assertIn("not performed", record["signature_verification"])

    def test_failed_later_run_preserves_previous_success(self):
        self.assertEqual(self.run_generator().returncode, 0)
        before = (self.output / "aegaeon-sbom-latest.json").resolve()
        self.assertNotEqual(self.run_generator(CASE="fail").returncode, 0)
        self.assertEqual((self.output / "aegaeon-sbom-latest.json").resolve(), before)
        self.assertEqual(len(list(self.output.glob("sbom-*"))), 2)  # run + report link
        self.assertEqual(len(list(self.output.glob("failed-*"))), 1)

    def test_result_record_names_this_run_and_matches_its_digest(self):
        record_path = Path(self.temp.name) / "result.json"
        result = self.run_generator(SBOM_RESULT_FILE=str(record_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(record_path.read_text())
        path = Path(record["sbom"])
        self.assertFalse(path.is_symlink())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), record["sha256"])
        self.assertEqual(path, (self.output / "aegaeon-sbom-latest.json").resolve())

    def test_scan_uses_own_run_when_another_run_changes_shared_pointer(self):
        for relative in (
            "scripts/release/generate_sbom.py",
            "scripts/release/generate_sbom.sh",
            "scripts/security/run_sbom_scan.sh",
        ):
            dest = self.root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((ROOT / relative).read_bytes())
        self.git("add", "scripts")
        marker = Path(self.temp.name) / "scanned.txt"
        grype = self.bin / "grype"
        grype.write_text(
            f"#!{sys.executable}\n"
            r"""
import json, os, pathlib, sys
output = pathlib.Path(os.environ["OUTPUT_DIR"])
if sys.argv[1:3] == ["db", "update"]:
    (output / "different.json").write_text("{}")
    pointer = output / "aegaeon-sbom-latest.json"
    pointer.unlink()
    pointer.symlink_to("different.json")
else:
    pathlib.Path(os.environ["SCAN_MARKER"]).write_text(sys.argv[1])
    print(json.dumps({"matches": []}))
"""
        )
        grype.chmod(0o700)
        result = subprocess.run(
            ["bash", "scripts/security/run_sbom_scan.sh"],
            cwd=self.root,
            env={**self.env, "RUN_TRIVY": "0", "SCAN_MARKER": str(marker)},
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        scanned = Path(marker.read_text().removeprefix("sbom:"))
        self.assertEqual(scanned.name, "aegaeon-sbom.json")
        self.assertFalse(scanned.is_symlink())
        self.assertEqual(
            json.loads(scanned.read_text())["metadata"]["component"]["version"], "1.2.3"
        )
        self.assertEqual((self.output / "aegaeon-sbom-latest.json").read_text(), "{}")

    def test_external_source_symlink_is_rejected(self):
        (self.root / "external").symlink_to("/etc/hostname")
        self.git("add", "external")
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
