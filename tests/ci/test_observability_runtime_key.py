"""Exercise the smoke helper's real shell/Actions environment delivery."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY = "AEGAEON_KEY_ENCRYPTION_KEY"
URL = "postgresql://runtime:fixture-password@localhost/fixture"


class ObservabilityRuntimeKeyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)
        scripts = self.root / "scripts/tests"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/tests/prepare_observability_runtime.sh", scripts)
        (self.root / "consumer.py").write_text(
            "import json, os\n"
            f"keys = ['DATABASE_URL', {KEY!r}]\n"
            "print(json.dumps({key: os.environ[key] for key in keys if key in os.environ}))\n"
        )
        # Replace only PostgreSQL provisioning; execute the actual delivery helper.
        (scripts / "subject_ownership_fixture.py").write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "fixture = Path(sys.argv[2])\n"
            "fixture.mkdir(mode=0o700)\n"
            f"suppliers = {{'urls': {{'runtime': {URL!r}}}}}\n"
            "(fixture / 'suppliers.json').write_text(json.dumps(suppliers))\n"
            "environment = fixture / 'runtime-env.sh'\n"
            f"environment.write_text('export DATABASE_URL={URL}\\n')\n"
            "environment.chmod(int(os.environ.get('FIXTURE_MODE', '600'), 8))\n"
        )

    def prepare(self, name, *, actions=False, mode="600"):
        fixture = self.root / name
        env = {key: value for key, value in os.environ.items() if key != "GITHUB_ENV"}
        env.update({KEY: "inherited-production-key-must-not-be-reused", "FIXTURE_MODE": mode})
        github_env = self.root / (name + "-github-env")
        if actions:
            env["GITHUB_ENV"] = str(github_env)
        result = subprocess.run(  # noqa: S603 - fixed helper in an owned fixture
            [self.bash, "scripts/tests/prepare_observability_runtime.sh", str(fixture)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return fixture, github_env, result

    def delivered_key(self, fixture):
        environment = fixture / "runtime-env.sh"
        result = subprocess.run(  # noqa: S603 - consume only the owned helper's environment
            [
                self.bash,
                "-c",
                'source "$1"; python3 "$2"',
                "fixture-consumer",
                str(environment),
                str(self.root / "consumer.py"),
            ],
            env={key: value for key, value in os.environ.items() if key != KEY},
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        delivered = json.loads(result.stdout)
        self.assertEqual(delivered["DATABASE_URL"], URL)
        self.assertIn(KEY, delivered)
        key = delivered[KEY]
        self.assertEqual(len(base64.urlsafe_b64decode(key + "=")), 32)
        self.assertRegex(key, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(environment.stat().st_mode & 0o777, 0o600)
        return key

    def test_local_shell_receives_private_key_without_logging(self):
        fixture, _, result = self.prepare("local")
        self.assertEqual(result.returncode, 0, result.stderr)
        key = self.delivered_key(fixture)
        self.assertNotIn(key, result.stdout + result.stderr)

    def test_actions_and_shell_receive_same_masked_key(self):
        fixture, github_env, result = self.prepare("actions", actions=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        key = self.delivered_key(fixture)
        delivered = dict(line.split("=", 1) for line in github_env.read_text().splitlines())
        self.assertEqual(delivered[KEY], key)
        self.assertEqual(delivered["AEGAEON_DATABASE_URL"], URL)
        self.assertEqual(delivered["DATABASE_URL"], URL)
        self.assertIn("::add-mask::" + key, result.stdout.splitlines())
        self.assertNotIn(key, result.stderr)

    def test_each_owned_fixture_has_a_fresh_key(self):
        first, _, first_result = self.prepare("first")
        second, _, second_result = self.prepare("second")
        self.assertEqual(first_result.returncode, 0, first_result.stderr)
        self.assertEqual(second_result.returncode, 0, second_result.stderr)
        self.assertNotEqual(self.delivered_key(first), self.delivered_key(second))

    def test_rejects_public_environment_before_writing_key(self):
        fixture, github_env, result = self.prepare("public", actions=True, mode="644")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(KEY, (fixture / "runtime-env.sh").read_text())
        self.assertFalse(github_env.exists())


if __name__ == "__main__":
    unittest.main()
