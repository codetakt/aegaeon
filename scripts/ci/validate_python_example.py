"""Install, exercise and audit the minimal RP's actual Python dependency graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PIP_VERSION = "26.2.1"
AUDIT_VERSION = "2.10.1"
INDEX = "https://pypi.org/simple"
SUPPORTED = {"3.10.20", "3.13.15"}

EXPECTED_TESTS = frozenset(
    [
        "ApplicationSmoke.test_bootstrap_discovery_registration",
        "ApplicationSmoke.test_pkce_rfc7636_and_verifier",
        "ApplicationSmoke.test_landing_and_login_session",
        "ApplicationSmoke.test_callback_decodes_without_signature_verification",
        "ApplicationSmoke.test_missing_code_and_wrong_state",
        "ApplicationSmoke.test_missing_pkce_verifier",
        "ApplicationSmoke.test_missing_or_invalid_expected_state",
        "ApplicationSmoke.test_missing_or_invalid_expected_nonce",
        "ApplicationSmoke.test_malformed_token_payload_rejected",
        "ApplicationSmoke.test_token_transport_failure_rejected",
        "ApplicationSmoke.test_nonce_mismatch_and_missing_claim",
        "ApplicationSmoke.test_protocol_error_does_not_echo_provider_details",
        "ApplicationSmoke.test_token_error_does_not_echo_provider_details",
        "ApplicationSmoke.test_claims_escaping_and_logout",
        "ApplicationSmoke.test_missing_empty_or_malformed_id_token_rejected",
        "HttpProviderContract.test_discovery_registration_and_token_exchange_over_http",
        "PyJwtCryptographyLibraryCheck.test_rs256_es256_sign_verify_and_tamper",
    ]
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_graph(value: Any) -> dict[str, str]:  # noqa: ANN401 - validated tool JSON
    if not isinstance(value, list) or not value:
        raise ValueError("installed dependency graph is empty or malformed")
    graph = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("invalid installed dependency entry")  # noqa: TRY004 - invalid report
        name, version = item.get("name"), item.get("version")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            raise ValueError("invalid installed dependency name")
        if not isinstance(version, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version
        ):
            raise ValueError("invalid installed dependency version")
        key = canonical(name)
        if key in graph:
            raise ValueError("duplicate installed dependency")
        graph[key] = version
    return graph


def audit_verdict(value: Any, graph: dict[str, str], exit_code: int) -> dict[str, object]:  # noqa: ANN401
    """Reject incomplete/unknown audit results as well as vulnerability findings."""
    if not isinstance(value, dict) or not isinstance(value.get("dependencies"), list):
        raise ValueError("audit output has no dependency inventory")  # noqa: TRY004
    entries = value["dependencies"]
    observed = installed_graph(entries)
    if observed != graph:
        raise ValueError("audit inventory differs from the actual installed graph")
    findings = []
    for item in entries:
        if "skip_reason" in item or not isinstance(item.get("vulns"), list):
            raise ValueError("audit skipped a dependency or omitted its verdict")
        for vulnerability in item["vulns"]:
            if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
                raise ValueError("malformed vulnerability finding")
            findings.append({"package": item["name"], "version": item["version"], **vulnerability})
    if exit_code not in (0, 1) or (exit_code == 0) != (not findings):
        raise ValueError("audit exit code disagrees with findings or indicates an error")
    return {"status": "vulnerable" if findings else "passed", "findings": findings}


def require_tests(value: Any, exit_code: int) -> None:  # noqa: ANN401 - validate report
    if not isinstance(value, dict):
        raise ValueError("sample tests omitted their result inventory")  # noqa: TRY004
    outcomes = ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")
    for key in ("tests_run", *outcomes):
        counter = value.get(key)
        if type(counter) is not int or counter < 0:
            raise ValueError("sample test counters must be nonnegative integers")
    identifiers = value.get("test_ids")
    if (
        value.get("status") != "passed"
        or value.get("tests_run") != len(EXPECTED_TESTS)
        or not isinstance(identifiers, list)
        or any(not isinstance(item, str) for item in identifiers)
        or len(identifiers) != len(EXPECTED_TESTS)
        or set(identifiers) != EXPECTED_TESTS
        or any(value.get(key) != 0 for key in outcomes)
        or exit_code != 0
    ):
        raise ValueError("sample tests failed, skipped, or differ from the expected inventory")


class Validation:
    """Keep failed command logs and an explicit final receipt outside the source tree."""

    def __init__(self, root: Path, output: Path, python: Path) -> None:
        self.root, self.output, self.python = root, output, python
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("PIP_", "PYTHON", "_PYTHON", "VIRTUAL_ENV"))
        }
        self.environment.update(
            PIP_CONFIG_FILE=os.devnull,
            PYTHONNOUSERSITE="1",
            PYTHONDONTWRITEBYTECODE="1",
        )
        self.receipt: dict[str, Any] = {
            "schema_version": 1,
            "status": "failed",
            "commands": [],
            "scope": "minimal RP dependency compatibility and installed-graph advisory audit",
            "sample_verifies_id_token_signatures": False,
        }

    def save(self) -> None:
        write_json(self.output / "receipt.json", self.receipt)

    def command(self, label: str, argv: list[str], *, required: bool = True) -> int:
        log = self.output / f"{label}.log"
        started = time.monotonic()
        with log.open("wb") as stream:
            try:
                result = subprocess.run(
                    argv,
                    cwd=self.root,
                    env=self.environment,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    timeout=600,
                    check=False,
                )
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                stream.write(str(error).encode())
                code = 124
        self.receipt["commands"].append(
            {
                "label": label,
                "argv": argv,
                "exit_code": code,
                "elapsed_seconds": time.monotonic() - started,
                "log": log.name,
                "log_sha256": digest(log),
            },
        )
        self.save()
        if required and code:
            raise ValueError(f"{label} failed with exit {code}; see {log.name}")
        return code

    def install(
        self,
        python: Path,
        requirement: Path,
        label: str,
        *,
        installer: Path | None = None,
    ) -> None:
        """Resolve once, hash selected wheels, then install offline with required hashes."""
        report = self.output / f"{label}-resolution.json"
        pip = [
            str(installer or python),
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
        ]
        if installer:
            pip.extend(["--python", str(python)])
        self.command(
            f"{label}-resolve",
            [
                *pip,
                "install",
                "--dry-run",
                "--ignore-installed",
                "--only-binary=:all:",
                "--index-url",
                INDEX,
                "--report",
                str(report),
                "-r",
                str(requirement),
            ],
        )
        resolution = json.loads(report.read_text())
        lock = []
        for item in resolution["install"]:
            metadata, download = item["metadata"], item["download_info"]
            checksum = download["archive_info"]["hashes"]["sha256"]
            if not re.fullmatch(r"[0-9a-f]{64}", checksum) or not download["url"].endswith(".whl"):
                raise ValueError("dependency resolution did not select a hashed wheel")
            graph = installed_graph([{"name": metadata["name"], "version": metadata["version"]}])
            name, version = next(iter(graph.items()))
            lock.append(f"{name}=={version} --hash=sha256:{checksum}")
        if not lock:
            raise ValueError("dependency resolution was empty")
        frozen = self.output / f"{label}.lock"
        frozen.write_text("\n".join(sorted(lock)) + "\n")
        wheels = self.output / f"{label}-wheels"
        wheels.mkdir()
        self.command(
            f"{label}-download",
            [
                *pip,
                "download",
                "--only-binary=:all:",
                "--index-url",
                INDEX,
                "--require-hashes",
                "--dest",
                str(wheels),
                "-r",
                str(frozen),
            ],
        )
        self.receipt[f"{label}_wheels"] = [
            {"name": wheel.name, "sha256": digest(wheel), "bytes": wheel.stat().st_size}
            for wheel in sorted(wheels.iterdir())
        ]
        self.command(
            f"{label}-install",
            [
                *pip,
                "install",
                "--no-index",
                "--find-links",
                str(wheels),
                "--require-hashes",
                "-r",
                str(frozen),
            ],
        )

    def prepare_interpreter(self) -> None:
        probe = (
            "import json,platform,sys; print(json.dumps({'version':platform.python_version(),"
            "'implementation':platform.python_implementation(),'executable':sys.executable,"
            "'platform':platform.platform()}))"
        )
        self.command("interpreter", [str(self.python), "-I", "-c", probe])
        identity = json.loads((self.output / "interpreter.log").read_text())
        if identity["version"] not in SUPPORTED or identity["implementation"] != "CPython":
            raise ValueError("interpreter is not one of the pinned validation versions")
        self.receipt["interpreter"] = {**identity, "binary_sha256": digest(self.python)}
        for label in ["application", "audit"]:
            self.command(
                f"{label}-venv",
                [
                    str(self.python),
                    "-I",
                    "-m",
                    "venv",
                    *(["--without-pip"] if label == "application" else []),
                    str(self.output / label),
                ],
            )

    def prepare_dependencies(self, requirements: Path) -> tuple[Path, Path, dict[str, str]]:
        python = self.output / "application/bin/python"
        auditor = self.output / "audit/bin/python"
        tooling = self.output / "tooling-requirements.txt"
        tooling.write_text(f"pip=={PIP_VERSION}\npip-audit=={AUDIT_VERSION}\n")
        self.install(auditor, tooling, "tooling")
        bootstrap = self.output / "bootstrap-requirements.txt"
        bootstrap.write_text(f"pip=={PIP_VERSION}\n")
        self.install(python, bootstrap, "bootstrap", installer=auditor)
        self.install(python, requirements, "dependencies")
        self.command("pip-check", [str(python), "-I", "-m", "pip", "check"])
        self.command("installed", [str(python), "-I", "-m", "pip", "list", "--format=json"])
        graph = installed_graph(json.loads((self.output / "installed.log").read_text()))
        self.receipt["installed"] = graph
        self.command("audit-tooling", [str(auditor), "-I", "-m", "pip", "list", "--format=json"])
        self.receipt["audit_tooling"] = installed_graph(
            json.loads((self.output / "audit-tooling.log").read_text())
        )
        return python, auditor, graph

    def run(self) -> None:
        app = self.root / "examples/minimal-rp/app.py"
        requirements = app.with_name("requirements.txt")
        tests = self.root / "tests/examples/minimal_rp/check_flow.py"
        self.receipt["source"] = {
            str(path.relative_to(self.root)): digest(path)
            for path in [
                app,
                requirements,
                tests,
                self.root / "scripts/ci/validate_python_example.py",
                self.root / "tests/ci/test_python_example_validation.py",
                self.root / ".github/workflows/python-example-validation.yml",
            ]
        }
        self.prepare_interpreter()
        python, auditor, graph = self.prepare_dependencies(requirements)
        frozen = self.output / "installed.txt"
        frozen.write_text(
            "".join(f"{name}=={version}\n" for name, version in sorted(graph.items()))
        )
        test_code = self.command(
            "sample-tests",
            [str(python), "-I", str(tests), str(app), str(self.output / "tests.json")],
            required=False,
        )
        audit_path = self.output / "audit.json"
        audit_code = self.command(
            "dependency-audit",
            [
                str(auditor),
                "-I",
                "-m",
                "pip_audit",
                "--disable-pip",
                "--no-deps",
                "--progress-spinner",
                "off",
                "--format",
                "json",
                "--output",
                str(audit_path),
                "-r",
                str(frozen),
            ],
            required=False,
        )
        self.receipt["audit"] = audit_verdict(json.loads(audit_path.read_text()), graph, audit_code)
        result = json.loads((self.output / "tests.json").read_text())
        self.receipt["tests"] = result
        require_tests(result, test_code)
        if self.receipt["audit"]["status"] != "passed":
            raise ValueError("installed dependency audit reported vulnerabilities")
        if any(
            digest(self.root / path) != expected
            for path, expected in self.receipt["source"].items()
        ):
            raise ValueError("validation source changed during execution")
        self.receipt["status"] = "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    validation = Validation(
        args.root.resolve(strict=True), output, args.python.resolve(strict=True)
    )
    try:
        validation.run()
    except (OSError, ValueError, KeyError, TypeError) as error:
        validation.receipt["reason"] = str(error)
        print(f"Python example validation failed: {error}", file=sys.stderr)
    finally:
        validation.save()
    return 0 if validation.receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
