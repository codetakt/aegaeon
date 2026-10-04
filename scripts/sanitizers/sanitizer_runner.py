#!/usr/bin/env python3
"""Supervise native sanitizer builds and verify named executable evidence."""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import runpy
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, NoReturn

# Required default-profile targets, independently frozen before this repair.
FFI_TARGETS = {
    "ffi",
    "aead_buffer_boundary_test",
    "dpop_header_test",
    "dpop_proof_test",
    "dpop_uri_test",
    "equivalence_pkce_test",
    "jose_header_runtime_test",
    "oidc_hash_runtime_test",
    "pkce_verifier_test",
}


class Failure(Exception):  # noqa: N818 - retained failure/status interface
    def __init__(self, message: str, status: int = 1) -> None:
        super().__init__(message)
        self.status = status if status > 0 else 128 - status


class Interrupted(Failure):
    """Keep the supervisor's signal separate from child cleanup failures."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"Sanitizer supervisor interrupted by signal {signum}", 128 + signum)


def failure(message: str, status: int = 1) -> NoReturn:
    raise Failure(message, status)


def require(condition: object, message: str, status: int = 1) -> None:
    if not condition:
        failure(message, status)


def duration(value: str) -> float:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", value)
    require(match is not None, f"Invalid sanitizer deadline: {value!r}")
    seconds = float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    require(
        math.isfinite(seconds) and seconds > 0, "Sanitizer deadlines must be positive and finite"
    )
    return seconds


def selection(value: str, label: str) -> list[str]:
    values = value.replace(",", " ").split()
    require(values and len(values) == len(set(values)), f"Empty or duplicate {label} selection")
    require(
        all(re.fullmatch(r"[A-Za-z0-9_-]+", item) for item in values), f"Invalid {label} selection"
    )
    return values


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text: str) -> dict[str, Any]:
    return json.loads(text, object_pairs_hook=unique_object)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def group_alive(pgid: int) -> bool:
    # A reparented zombie has exited; it is not a running descendant. Linux is
    # also the platform of the existing lib/linux ASan runtime configuration.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def terminate(process: subprocess.Popen[bytes], grace: float) -> bool:
    active = group_alive(process.pid)
    if active:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        if group_alive(process.pid):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.01)
    process.wait(timeout=5)
    require(not group_alive(process.pid), "Sanitizer descendants survived cleanup")
    return active


def interrupted(signum: int, _frame: object) -> None:
    raise Interrupted(signum)


@dataclass(frozen=True)
class Settings:
    sanitizer_text: str
    package_text: str
    target_text: str
    artifact_text: str
    cargo: str
    host: str
    base_flags: str
    curve_flags: str
    extra_text: str
    build_extra_text: str
    build_limit_text: str
    run_limit_text: str
    grace_text: str
    runtime_text: str
    link_order: str
    preload: str


def asan_options(link_order: str) -> str:
    return (
        "abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:"
        f"verify_asan_link_order={link_order}:verbosity=0"
    )


class Supervisor:
    """Own command capture, process cleanup and the current evidence receipt."""

    def __init__(self, artifacts: Path, summary: dict[str, Any], kill_grace: float = 1) -> None:
        self.artifacts = artifacts
        self.summary = summary
        self.kill_grace = kill_grace
        self.counter = 0

    def save(self) -> None:
        fd, name = tempfile.mkstemp(prefix=".run-summary-", dir=self.artifacts)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w") as output:
                json.dump(self.summary, output, indent=2)
                output.write("\n")
            temporary.replace(self.artifacts / "run-summary.json")
        finally:
            temporary.unlink(missing_ok=True)

    def capture(
        self,
        process: subprocess.Popen[bytes],
        streams: tuple[BinaryIO, BinaryIO],
        record: dict[str, Any],
        started: float,
        *,
        echo: bool,
    ) -> None:
        """Drain both pipes while enforcing one deadline and descendant cleanup."""
        with selectors.DefaultSelector() as selector:
            for pipe, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            while selector.get_map() or process.poll() is None:
                if (
                    not record["timed_out"]
                    and time.monotonic() - started >= record["deadline_seconds"]
                ):
                    record["timed_out"] = True
                    terminate(process, self.kill_grace)
                elif process.poll() is not None and group_alive(process.pid):
                    record["lingering_descendants"] = terminate(process, self.kill_grace)
                for key, _ in selector.select(0.02):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    index = int(key.data == "stderr")
                    streams[index].write(data)
                    if echo:
                        output = sys.stderr.buffer if index else sys.stdout.buffer
                        output.write(data)
                        output.flush()
            process.wait(timeout=5)
            # Descendants may close their output and outlive a normal leader.
            record["lingering_descendants"] = (
                terminate(process, self.kill_grace) or record["lingering_descendants"]
            )

    def finish_command(
        self, record: dict[str, Any], error: Exception | None, original_status: int | None
    ) -> None:
        status, phase = record.get("exit_code"), record["phase"]
        timed_out, lingering = record["timed_out"], record["lingering_descendants"]
        record["status"] = (
            "failed" if error or timed_out or lingering or status != 0 else "completed"
        )
        # Child termination during cleanup must not replace the signal that
        # interrupted supervision. Other cleanup errors preserve an observed
        # child failure, including errors raised by our own cleanup checks.
        if isinstance(error, Interrupted):
            failure_status = error.status
        elif error:
            failure_status = original_status or getattr(error, "status", 1)
        else:
            failure_status = status or 1
        if timed_out:
            failure_status = 124
        try:
            self.save()
        except Exception as save_error:
            message = f"{phase} evidence write failed: {save_error}"
            raise Failure(message, failure_status) from save_error
        if timed_out:
            failure(f"{phase} exceeded its deadline", 124)
        if error:
            failure(f"{phase} capture/cleanup failed: {error}", failure_status)
        if status != 0:
            failure(f"{phase} failed with exit {status}", status or 1)
        require(not lingering, f"{phase} left running descendants")

    def command(
        self,
        args: list[str],
        environment: dict[str, str],
        seconds: float,
        phase: str,
        *,
        echo: bool = False,
    ) -> str:
        self.counter += 1
        prefix = self.artifacts / f"{self.counter:03d}-{phase}"
        record = {
            "args": args,
            "phase": phase,
            "deadline_seconds": seconds,
            "status": "not-started",
            "timed_out": False,
            "lingering_descendants": False,
        }
        self.summary["commands"].append(record)
        process = None
        started = time.monotonic()
        error = None
        original_status = None
        try:
            with (
                prefix.with_suffix(".stdout.log").open("wb") as out,
                prefix.with_suffix(".stderr.log").open("wb") as err,
            ):
                process = subprocess.Popen(  # noqa: S603 - admitted Cargo/test/tool argv, no shell
                    args,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                record.update(pid=process.pid, status="running")
                self.capture(process, (out, err), record, started, echo=echo)
        except Exception as caught:  # noqa: BLE001 - every capture/interruption failure requires cleanup
            original_status = process.poll() if process is not None else None
            error = caught
        finally:
            if process is not None:
                original_status = process.poll() if original_status is None else original_status
                try:
                    terminate(process, self.kill_grace)
                except Exception as caught:  # noqa: BLE001 - retain a previously observed exit
                    error = error or caught
                record["exit_code"] = process.poll()
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None:
                        pipe.close()
            record.update(
                elapsed_seconds=time.monotonic() - started,
                stdout=str(prefix.with_suffix(".stdout.log")),
                stderr=str(prefix.with_suffix(".stderr.log")),
            )
        self.finish_command(record, error, original_status)
        return prefix.with_suffix(".stdout.log").read_text()

    def execute(self, settings: Settings, workspace: Path) -> None:
        sanitizers = selection(settings.sanitizer_text, "sanitizer")
        packages = selection(settings.package_text, "package")
        require("ffi" in packages, "Package selection must include the required ffi package")
        require(sanitizers == ["address"], "Only the configured address sanitizer is supported")
        build_seconds, run_seconds, kill_grace = map(
            duration, (settings.build_limit_text, settings.run_limit_text, settings.grace_text)
        )
        options = runpy.run_path(
            str(Path(__file__).with_name("sanitizer_options.py")), run_name="sanitizer_options"
        )
        extra, build_extra = options["cargo_flags"](settings.extra_text, settings.build_extra_text)
        self.kill_grace = kill_grace
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.summary.update(
            {
                "sanitizers": sanitizers,
                "packages": packages,
                "build_deadline_seconds": build_seconds,
                "run_deadline_seconds": run_seconds,
                "kill_grace_seconds": kill_grace,
                "runtime_directory": settings.runtime_text,
            }
        )
        metadata = parse_json(
            self.command(
                [settings.cargo, *build_extra, "metadata", "--format-version", "1", "--no-deps"],
                os.environ.copy(),
                build_seconds,
                "metadata",
            )
        )
        require(
            Path(metadata["workspace_root"]).resolve() == workspace,
            "Cargo metadata belongs to a different workspace",
        )
        require(isinstance(metadata.get("packages"), list), "Malformed Cargo metadata packages")
        package_records = {package["name"]: package for package in metadata["packages"]}
        require(
            len(package_records) == len(metadata["packages"]), "Duplicate Cargo metadata package"
        )
        for package_name in packages:
            require(package_name in package_records, f"Unknown sanitizer package: {package_name}")
            self.execute_package(
                settings,
                package_records[package_name],
                (build_seconds, run_seconds),
                (extra, build_extra),
            )

    def execute_package(
        self,
        settings: Settings,
        package: dict[str, Any],
        deadlines: tuple[float, float],
        options: tuple[list[str], list[str]],
    ) -> None:
        extra, build_extra = options
        package_name, sanitizer = package["name"], "address"
        targets = {
            target["name"]: target
            for target in package["targets"]
            if target.get("test") is True and set(target["kind"]) & {"lib", "test"}
        }
        require(
            len(targets)
            == sum(
                target.get("test") is True and bool(set(target["kind"]) & {"lib", "test"})
                for target in package["targets"]
            ),
            "Duplicate Cargo target identity",
        )
        require(
            all(re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in targets),
            "Invalid Cargo target identity",
        )
        require(targets, "Empty required sanitizer target inventory")
        if package_name == "ffi":
            require(set(targets) >= FFI_TARGETS, "Missing required baseline ffi target")
        target_dir = (Path(settings.target_text) / f"{sanitizer}-{package_name}").resolve()
        rustflags = f"{settings.base_flags} -Z sanitizer={sanitizer} {settings.curve_flags}".strip()
        unit = {
            "package": package_name,
            "package_id": package["id"],
            "sanitizer": sanitizer,
            "status": "not-run",
            "rustflags": rustflags,
            "target_directory": str(target_dir),
            "targets": [
                {
                    "name": name,
                    "status": "not-run",
                    "source": str(Path(target["src_path"]).resolve()),
                    "source_sha256": digest(Path(target["src_path"])),
                }
                for name, target in targets.items()
            ],
        }
        self.summary["units"].append(unit)
        build_env = {
            **os.environ,
            "RUSTFLAGS": rustflags,
            "RUSTDOCFLAGS": rustflags,
            "CARGO_TARGET_DIR": str(target_dir),
            "ASAN_OPTIONS": asan_options("0"),
            "LSAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
        }
        build_env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        build_env.pop("CARGO_ENCODED_RUSTDOCFLAGS", None)
        output = self.command(
            [
                settings.cargo,
                *build_extra,
                "test",
                *extra,
                "-p",
                package_name,
                "--lib",
                "--tests",
                "--no-run",
                "--target",
                settings.host,
                "--message-format=json-render-diagnostics",
            ],
            build_env,
            deadlines[0],
            f"build-{sanitizer}-{package_name}",
        )
        found = build_artifacts(output, package, targets, target_dir / settings.host / "debug/deps")
        unit["status"] = "built"
        run_env = {
            **os.environ,
            "ASAN_OPTIONS": asan_options(settings.link_order),
            "LSAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
        }
        if settings.preload:
            run_env["LD_PRELOAD"] = settings.preload + (
                ":" + os.environ["LD_PRELOAD"] if os.environ.get("LD_PRELOAD") else ""
            )
        for target_result in unit["targets"]:
            self.execute_binary(
                target_result,
                found[target_result["name"]],
                run_env,
                deadlines[1],
                package_name=package_name,
            )
        unit["status"] = "completed"

    def execute_binary(
        self,
        target_result: dict[str, Any],
        artifact: tuple[Path, dict[str, Any]],
        run_env: dict[str, str],
        run_seconds: float,
        *,
        package_name: str,
    ) -> None:
        name = target_result["name"]
        binary, record = artifact
        target_result.update(
            {
                "binary": str(binary),
                "binary_sha256": digest(binary),
                "cargo_artifact": record,
                "status": "built",
            }
        )
        symbols = self.command(
            ["nm", str(binary)], os.environ.copy(), run_seconds, f"symbols-{name}"
        )
        require(
            "__asan_init" in symbols
            and "__asan_report_" in symbols
            and ("asan.module_ctor" in symbols or "___asan_gen_" in symbols),
            "Sanitizer binary lacks ASan instrumentation markers",
        )
        elf = self.command(
            ["readelf", "-d", str(binary)], os.environ.copy(), run_seconds, f"runtime-{name}"
        )
        target_result["runtime_linkage"] = "dynamic" if "libclang_rt.asan" in elf else "embedded"
        all_names = listed(
            self.command(
                [str(binary), "--list", "--format", "terse"], run_env, run_seconds, f"list-{name}"
            )
        )
        ignored = listed(
            self.command(
                [str(binary), "--list", "--ignored", "--format", "terse"],
                run_env,
                run_seconds,
                f"ignored-{name}",
            )
        )
        require(ignored <= all_names, "Ignored test identities are not in required inventory")
        inactive = (
            package_name == "ffi"
            and name == "oidc_hash_runtime_test"
            and "lowstar_hash" not in record["features"]
        )
        require(
            all_names - ignored or (inactive and not all_names),
            "Required sanitizer binary has no runnable tests",
        )
        target_result.update(
            {
                "expected_tests": sorted(all_names),
                "ignored_tests": sorted(ignored),
                "applicability": "lowstar_hash feature disabled"
                if inactive and not all_names
                else "required",
            }
        )
        executed = self.command(
            [str(binary), "-Z", "unstable-options", "--format", "json"],
            run_env,
            run_seconds,
            f"run-{name}",
            echo=True,
        )
        require(
            digest(binary) == target_result["binary_sha256"],
            "Sanitizer executable changed during execution",
        )
        target_result.update(completed(executed, all_names, ignored))
        target_result["status"] = "completed"
        self.save()


def listed(text: str) -> set[str]:
    names = []
    for line in text.splitlines():
        if not line.strip():
            continue
        require(
            line.endswith(": test") and line[:-6] and line == line.strip(),
            f"Malformed libtest listing: {line!r}",
        )
        names.append(line[:-6])
    require(len(names) == len(set(names)), "Duplicate libtest identity")
    return set(names)


def completed_test(
    event: dict[str, Any],
    names: set[str],
    started: set[str],
    finished: dict[str, str],
    ignored: set[str],
) -> None:
    name = event.get("name")
    require(isinstance(name, str) and name in names, f"Unknown completed test: {name}")
    if event.get("event") == "started":
        require(name not in started and name not in finished, "Duplicate started test")
        started.add(name)
    else:
        require(name not in finished, "Duplicate completed test")
        require(name in ignored or name in started, "Test completed without starting")
        finished[name] = event.get("event")


SUITE_EVENTS = 2


def completed(text: str, names: set[str], ignored: set[str]) -> dict[str, list[str]]:
    started = set()
    finished = {}
    suites = []
    for line in text.splitlines():
        require(line.strip(), "Empty libtest event")
        event = parse_json(line)
        require(isinstance(event, dict), "Malformed libtest event")
        if event.get("type") == "suite":
            suites.append(event)
            require(len(suites) <= SUITE_EVENTS, "Duplicate libtest suite event")
            expected_event = "started" if len(suites) == 1 else "ok"
            require(event.get("event") == expected_event, "Missing normal libtest suite completion")
            if len(suites) == 1:
                require(
                    type(event.get("test_count")) is int and event["test_count"] == len(names),
                    "Libtest suite discovery count mismatch",
                )
            else:
                require(set(finished) == names, "Suite completed before named test execution")
        elif event.get("type") == "test":
            require(len(suites) == 1, "Test event outside active suite")
            completed_test(event, names, started, finished, ignored)
        else:
            failure("Unknown libtest event type")
    require(len(suites) == SUITE_EVENTS, "Missing normal libtest suite completion")
    require(set(finished) == names and started >= names - ignored, "Missing named test execution")
    require(
        all(finished[name] == ("ignored" if name in ignored else "ok") for name in names),
        "Failed or incorrectly ignored test",
    )
    result = suites[1]
    expected_counts = {
        "passed": len(names - ignored),
        "ignored": len(ignored),
        "failed": 0,
        "filtered_out": 0,
    }
    require(
        all(
            type(result.get(key)) is int and result[key] == value
            for key, value in expected_counts.items()
        ),
        "Libtest totals do not match named execution",
    )
    return {
        "started": sorted(started),
        "completed": sorted(names - ignored),
        "ignored": sorted(ignored),
    }


def artifact_binary(record: dict[str, Any], expected: dict[str, Any], output_dir: Path) -> Path:
    target = record["target"]
    require(type(record.get("fresh")) is bool, "Malformed Cargo artifact freshness")
    features = record.get("features")
    require(
        isinstance(features, list)
        and all(isinstance(feature, str) for feature in features)
        and len(features) == len(set(features)),
        "Malformed Cargo artifact features",
    )
    require(
        target.get("kind") == expected["kind"]
        and Path(target.get("src_path", "")).resolve() == Path(expected["src_path"]).resolve(),
        "Cargo target identity mismatch",
    )
    require(isinstance(record.get("executable"), str), "Missing sanitizer test executable")
    binary = Path(record["executable"]).resolve()
    require(
        binary.is_relative_to(output_dir) and binary.is_file() and os.access(binary, os.X_OK),
        "Missing, stale or outside-target sanitizer executable",
    )
    require(
        isinstance(record.get("filenames"), list) and record["executable"] in record["filenames"],
        "Executable is not bound to Cargo artifact filenames",
    )
    return binary


def build_artifacts(
    output: str, package: dict[str, Any], targets: dict[str, Any], output_dir: Path
) -> dict[str, tuple[Path, dict[str, Any]]]:
    found = {}
    build_finished = []
    for line in output.splitlines():
        if not line.strip():
            continue
        record = parse_json(line)
        require(
            isinstance(record, dict) and isinstance(record.get("reason"), str),
            "Malformed Cargo JSON record",
        )
        if record["reason"] == "build-finished":
            require(type(record.get("success")) is bool, "Malformed Cargo build-finished record")
            build_finished.append(record["success"])
            continue
        require(
            record["reason"] in {"compiler-artifact", "compiler-message", "build-script-executed"},
            "Unknown Cargo JSON record",
        )
        if record["reason"] != "compiler-artifact":
            continue
        profile = record.get("profile")
        require(
            isinstance(profile, dict) and type(profile.get("test")) is bool,
            "Malformed Cargo artifact profile",
        )
        if not profile["test"]:
            continue
        target = record.get("target", {})
        name = target.get("name")
        require(
            record.get("package_id") == package["id"] and name in targets,
            "Unrelated sanitizer test artifact",
        )
        require(name not in found, "Duplicate sanitizer test artifact")
        binary = artifact_binary(record, targets[name], output_dir)
        require(
            all(binary != previous[0] for previous in found.values()),
            "Duplicate sanitizer executable",
        )
        found[name] = (binary, record)
    require(build_finished == [True], "Missing successful Cargo build-finished record")
    require(set(found) == set(targets), "Missing required sanitizer test artifacts")
    return found


def main() -> int:
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    settings = Settings(*sys.argv[1:])
    workspace = Path.cwd().resolve()
    artifacts = Path(settings.artifact_text).resolve()
    summary = {
        "status": "failed",
        "workspace": str(workspace),
        "host": settings.host,
        "commands": [],
        "units": [],
    }
    supervisor = Supervisor(artifacts, summary)
    exit_status = 0
    try:
        supervisor.execute(settings, workspace)
        summary["status"] = "completed"
    except Exception as error:  # noqa: BLE001 - failure receipt covers malformed external evidence
        summary["error"] = str(error)
        exit_status = getattr(error, "status", 1)
        print(f"[FAIL] Sanitizer execution failed: {error}", file=sys.stderr)
    finally:
        try:
            if artifacts.is_dir():
                supervisor.save()
        except Exception as error:  # noqa: BLE001 - final evidence failure cannot succeed
            print(f"[FAIL] Sanitizer evidence write failed: {error}", file=sys.stderr)
            exit_status = exit_status or 1
    if exit_status == 0:
        print(
            f"[INFO] Sanitizer-backed tests completed; evidence: {artifacts / 'run-summary.json'}"
        )
    return exit_status


if __name__ == "__main__":
    raise SystemExit(main())
