"""Qualify two real AppArmor/Nix lifecycle cases; helper stand-ins cannot pass this gate."""

from __future__ import annotations

# ruff: noqa: EM101, TRY003 - fixed CLI rejection diagnostics, as in CI controllers.
import argparse
import contextlib
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
sys.path.insert(0, str(ROOT / "scripts" / "validation"))
import process_cleanup_receipts as nested  # noqa: E402 - fixed repository module.
import with_organization_userns as namespace  # noqa: E402 - fixed repository module.
from database_execution import group_running, stop_process_group  # noqa: E402
from namespace_lifecycle_processes import process_fields  # noqa: E402

STOP = False
CASE_NAMES = ("cancel", "missing-receipt")
STORE = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+")
TOTAL_SECONDS = 360
CASE_SECONDS = 180
CLEANUP_SECONDS = 45


def interrupted(_signum: int, _frame: object) -> None:
    global STOP  # noqa: PLW0603 - record only; cleanup must not be interrupted.
    STOP = True


def write(path: Path, value: Any) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def read(path: Path) -> Any:
    with path.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("qualification evidence exceeds its bound")
    return json.loads(data)


def identity(pid: int) -> dict[str, Any] | None:
    process = Path("/proc") / str(pid)
    try:
        fields = process_fields(pid)
        return {
            "pid": pid,
            "starttime": fields[19],
            "group": int(fields[2]),
            "session": int(fields[3]),
            "uid": process.stat().st_uid,
            "argv_sha256": hashlib.sha256((process / "cmdline").read_bytes()).hexdigest(),
        }
    except (FileNotFoundError, ProcessLookupError):
        return None


def require_setup(report: dict[str, Any]) -> None:
    if not (
        report.get("restriction_before") == "1"
        and report.get("before", {}).get("passed") is False
        and report.get("install_attempted") is True
        and report.get("profile_installed") is True
        and report.get("install", {}).get("returncode") == 0
        and report.get("after", {}).get("passed") is True
    ):
        raise ValueError("actual restricted-host add/probe path was not qualified")


def expected_report(  # noqa: PLR0912 - the two independently checked outcome contracts.
    case: str, report: dict[str, Any], present: bool
) -> None:
    require_setup(report)
    if not isinstance(report.get("cancellation"), str) or not report["cancellation"]:
        raise ValueError("wrapper cancellation was not recorded")
    if case == "cancel":
        if (
            present
            or report.get("profile_removed") is not True
            or report.get("profile_absent") is not True
        ):
            raise ValueError("actual cancellation did not remove its profile")
        if report.get("unconfirmed_groups") != [] or report.get("restriction_after") != "1":
            raise ValueError("actual cancellation cleanup/restriction is inconsistent")
        if report.get("recovery") or report.get("nested_cleanup_unconfirmed"):
            raise ValueError("normal cancellation required unresolved recovery")
    elif case == "missing-receipt":
        if not present or not report.get("nested_cleanup_unconfirmed"):
            raise ValueError("missing registered evidence did not retain the actual profile")
        if not report.get("policy_removal_deferred") or not report.get("recovery"):
            raise ValueError("missing-receipt recovery information was not retained")
        if report.get("profile_removed") or report.get("profile_absent") or report.get("remove"):
            raise ValueError("missing-receipt case attempted premature policy removal")
    else:
        raise ValueError("unexpected qualification case")


class Case:
    """Own one wrapper and its narrowly bound census; all waits share a finite budget."""

    def __init__(self, directory: Path, name: str, end: float):
        self.path, self.name = directory, name
        self.path.mkdir(mode=0o700)
        (self.path / "tmp").mkdir(mode=0o700)
        self.end = min(end, time.monotonic() + CASE_SECONDS)
        self.work_end = self.end - CLEANUP_SECONDS
        self.nonce = uuid.uuid4().hex
        self.events: list[dict[str, Any]] = []
        self.children: list[subprocess.Popen[bytes]] = []
        self.streams: list[Any] = []
        self.worker: subprocess.Popen[bytes] | None = None
        self.wrapper: subprocess.Popen[bytes] | None = None
        self.worker_pid: int | None = None
        self.wrapper_identity: dict[str, Any] | None = None
        self.work_identity: dict[str, Any] | None = None
        self.buffer = bytearray()
        self.profile: str | None = None
        self.policy: Path | None = None
        self.policy_sha: str | None = None
        self.cancelled = False
        self.data: dict[str, Any] = {"case": name, "nonce": self.nonce, "passed": False}

    def record(self, event: str, **fields: Any) -> None:
        self.events.append({"event": event, "monotonic": time.monotonic(), **fields})

    def check(self) -> None:
        if STOP or time.monotonic() >= self.work_end:
            raise TimeoutError("qualification cancellation/work deadline")
        filesystem = os.statvfs(self.path)
        if filesystem.f_bavail * filesystem.f_frsize < 300 * 1024 * 1024:
            raise RuntimeError("qualification storage floor")
        total = sum(path.stat().st_size for path in self.path.iterdir() if path.is_file())
        if total > 16 * 1024 * 1024:
            raise RuntimeError("qualification evidence size bound")

    def start(
        self, command: list[str], label: str, *, env: dict[str, str] | None = None
    ) -> subprocess.Popen[bytes]:
        stdout = (self.path / (label + ".stdout")).open("xb")
        stderr = (self.path / (label + ".stderr")).open("xb")
        self.streams.extend([stdout, stderr])
        process = subprocess.Popen(  # noqa: S603 - fixed tools and owned paths only.
            command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, start_new_session=True
        )
        self.children.append(process)
        self.record("spawn", label=label, command=command, identity=identity(process.pid))
        return process

    def command(self, command: list[str], label: str, *, cleanup: bool = False) -> bytes:
        if cleanup and self.end - time.monotonic() < 9:
            raise TimeoutError("insufficient time for bounded policy recovery")
        process = self.start(command, label)
        try:
            until = min(
                self.end if cleanup else self.work_end, time.monotonic() + (5 if cleanup else 20)
            )
            while process.poll() is None:
                if not cleanup:
                    self.check()
                if time.monotonic() >= until:
                    raise TimeoutError(label + " deadline")
                time.sleep(0.02)
            if process.returncode:
                raise RuntimeError(label + " failed; raw output retained")
        finally:
            stop_process_group(process, grace=0)
        return (self.path / (label + ".stdout")).read_bytes()

    def response(self, seconds: int = 2) -> dict[str, Any]:
        assert self.worker is not None
        assert self.worker.stdout is not None
        until = min(self.end, time.monotonic() + seconds)
        with selectors.DefaultSelector() as watcher:
            watcher.register(self.worker.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                if time.monotonic() >= until:
                    raise TimeoutError("owned census response deadline")
                if watcher.select(timeout=max(0, min(0.1, until - time.monotonic()))):
                    data = os.read(self.worker.stdout.fileno(), 16384)
                    if not data:
                        raise RuntimeError("owned census terminated unexpectedly")
                    self.buffer.extend(data)
                    if len(self.buffer) > 65536:
                        raise ValueError("owned census response exceeds its bound")
        row, _, remaining = self.buffer.partition(b"\n")
        self.buffer[:] = remaining
        return json.loads(row)

    def census(self, operation: str = "snapshot", **fields: Any) -> dict[str, Any]:
        assert self.worker is not None
        assert self.worker.stdin is not None
        if time.monotonic() >= self.end:
            raise TimeoutError("census operation past cleanup deadline")
        if operation == "snapshot" and self.profile is not None:
            fields["profile"] = self.profile
        self.worker.stdin.write((json.dumps({"operation": operation, **fields}) + "\n").encode())
        self.worker.stdin.flush()
        row = self.response()
        if not isinstance(row, dict) or row.get("ok") is not True:
            raise ValueError("owned census did not confirm its result")
        self.record("census_" + operation, response=row)
        return row

    def prepare(self) -> dict[str, Any]:
        expression = (
            'c: let p = c.namespaceCancellationProbe { nonce = "'
            + self.nonce
            + '"; }; in [ c.namespaceProbe.drvPath c.namespaceProbe.outPath '
            "c.namespaceUnshare p.drvPath p.outPath ]"
        )
        values = json.loads(
            self.command(
                ["nix", "eval", "--json", namespace.CHECK, "--apply", expression], "evaluate"
            )
        )
        if (
            not isinstance(values, list)
            or len(values) != 5
            or not all(isinstance(v, str) for v in values)
        ):
            raise ValueError("qualification source identities are malformed")
        probe_drv, probe_out, unshare, payload_drv, payload_out = values
        if not all(STORE.fullmatch(v) for v in (probe_drv, probe_out, payload_drv, payload_out)):
            raise ValueError("qualification store identities are malformed")
        if namespace.UNSHARE.fullmatch(unshare) is None:
            raise ValueError("qualification namespace executable is unpinned")
        for label, drv_path in (("probe", probe_drv), ("payload", payload_drv)):
            document = json.loads(
                self.command(["nix", "derivation", "show", drv_path], label + "-derivation")
            )
            direct_paths = dependency_paths(document, drv_path)
            direct = {"version": 4, "derivations": {}}
            if direct_paths:
                direct = json.loads(
                    self.command(
                        ["nix", "derivation", "show", *direct_paths], label + "-direct-inputs"
                    )
                )
            check_dependencies(document, drv_path, direct)
        if Path(payload_out).exists():
            raise ValueError("fresh qualification output already exists")
        binding = {
            "nonce": self.nonce,
            "scratch": "/run/aegaeon-namespace-" + self.nonce,
            "outputs": {"probe": probe_out, "payload": payload_out},
            "caller_uid": os.getuid(),
            "deadline": self.end,
            "owner_starttime": int(identity(os.getpid())["starttime"]),
            "nix_executable": str(Path(shutil.which("nix") or "").resolve()),
        }
        write(self.path / "census-binding.json", binding)
        stderr = (self.path / "census.stderr").open("xb")
        self.streams.append(stderr)
        self.worker = subprocess.Popen(  # noqa: S603 - owned fixed census helper.
            [  # noqa: S607 - CI supplies sudo; no shell interpolation.
                "sudo",
                "-n",
                sys.executable,
                "-B",
                str(Path(__file__).with_name("namespace_lifecycle_processes.py")),
                "--binding",
                str(self.path / "census-binding.json"),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            start_new_session=True,
        )
        self.children.append(self.worker)
        ready = self.response(5)
        if ready.get("ready") is not True:
            raise RuntimeError("owned census startup refused")
        self.worker_pid = ready["pid"]
        self.data.update(source_identities=values, census_binding=binding, census_ready=ready)
        command = [
            "nix",
            "build",
            "--offline",
            "--no-link",
            "--print-build-logs",
            "--max-jobs",
            "1",
            "--cores",
            "1",
            "--option",
            "substitute",
            "false",
            payload_drv + "^out",
        ]
        write(self.path / "command.json", command)
        return binding

    def start_wrapper(self, binding: dict[str, Any]) -> None:
        environment = dict(os.environ)
        environment.update(
            TMPDIR=str(self.path / "tmp"), AEGAEON_NAMESPACE_LIFECYCLE_CASE=self.nonce
        )
        environment["NIX_CONFIG"] = environment.get("NIX_CONFIG", "") + (
            f"\nbuild-dir = {binding['scratch']}\nbuilders =\nsandbox = true\n"
            "max-jobs = 1\ncores = 1\ntimeout = 90\nsubstitute = false\n"
        )
        command = [
            sys.executable,
            "-B",
            str(ROOT / "scripts/ci/with_organization_userns.py"),
            "--report",
            str(self.path / "wrapper-report.json"),
            "--",
            sys.executable,
            "-B",
            str(Path(__file__).with_name("namespace_lifecycle_work.py")),
            "--case",
            str(self.path),
        ]
        self.wrapper = self.start(command, "wrapper", env=environment)
        self.wrapper_identity = identity(self.wrapper.pid)

    def discover_policy(self) -> None:
        entries = list((self.path / "tmp").glob("aegaeon-userns-*/process-cleanup/owner.json"))
        if not entries:
            return
        if len(entries) != 1:
            raise ValueError("ambiguous private namespace owner")
        owner = read(entries[0])
        if set(owner) != {"version", "owner"} or owner["version"] != 1:
            raise ValueError("unexpected private namespace owner")
        policy = entries[0].parent.parent / "profile"
        if not policy.exists():
            return
        expected = namespace.profile_text(self.data["source_identities"][2], owner["owner"])
        if policy.is_symlink() or policy.read_text() != expected:
            raise ValueError("owned policy source identity differs")
        self.profile, self.policy = owner["owner"], policy
        self.policy_sha = hashlib.sha256(policy.read_bytes()).hexdigest()

    def wait_ready(self) -> Path:
        previous: list[dict[str, Any]] = []
        while True:
            self.check()
            assert self.wrapper is not None
            if self.wrapper.poll() is not None:
                raise RuntimeError("actual namespace wrapper ended before qualification readiness")
            self.discover_policy()
            rows = self.census()
            payload = [row for row in rows["rows"] if row["kind"] == "payload"]
            ready = self.path / "work-ready.json"
            trace = self.path / "build-trace.jsonl"
            if ready.exists() and trace.exists() and payload and payload == previous:
                if "namespace-lifecycle " + self.nonce not in trace.read_text():
                    raise ValueError("actual payload heartbeat is absent")
                if rows.get("profile_present") is not True:
                    raise ValueError("actual kernel profile is absent while payload runs")
                value = read(ready)
                self.work_identity = value["identity"]
                if identity(self.work_identity["pid"]) != self.work_identity:
                    raise ValueError("actual observer identity changed")
                directory = Path(value["directory"])
                self.data["registered_client"] = bind_registered_client(
                    directory, rows["rows"], self.profile
                )
                self.data["active_observation"] = rows
                return directory
            previous = payload
            time.sleep(0.1)

    def cancel(self) -> None:
        if self.cancelled or self.wrapper is None or self.wrapper.poll() is not None:
            return
        current = identity(self.wrapper.pid)
        if current is None or current != self.wrapper_identity:
            if current is None and self.wrapper.poll() is not None:
                self.record("wrapper_exited_before_cancel", identity=self.wrapper_identity)
                return
            raise ValueError("wrapper identity changed before cancellation")
        try:
            os.kill(self.wrapper.pid, signal.SIGTERM)
        except ProcessLookupError:
            if self.wrapper.poll() is None or identity(self.wrapper.pid) is not None:
                raise
            self.record("wrapper_exited_before_cancel", identity=self.wrapper_identity)
            return
        self.cancelled = True
        self.record("wrapper_cancel", identity=self.wrapper_identity)

    def exercise(self) -> None:
        binding = self.prepare()
        self.start_wrapper(binding)
        directory = self.wait_ready()
        if self.name == "missing-receipt":
            self.data["removed_receipt"] = remove_registered_receipt(directory, self.path)
        self.cancel()
        assert self.wrapper is not None
        until = min(self.work_end, time.monotonic() + 25)
        while self.wrapper.poll() is None:
            self.check()
            if time.monotonic() >= until:
                raise TimeoutError("namespace wrapper did not finish its cancellation")
            row = self.census()
            if row["rows"] and row.get("profile_present") is False:
                raise ValueError("policy disappeared while owned work was live")
            time.sleep(0.1)
        if self.wrapper.returncode == 0:
            raise ValueError("cancelled namespace wrapper returned success")
        report = read(self.path / "wrapper-report.json")
        snapshot = self.census()
        expected_report(self.name, report, snapshot["profile_present"])
        if snapshot["rows"] or snapshot["known_remaining"]:
            raise ValueError("owned Nix work survived wrapper completion")
        self.data.update(wrapper_returncode=self.wrapper.returncode, expected_behavior=True)


def derivations(document: Any) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "derivations"}
        or type(document["version"]) is not int
        or document["version"] != 4
        or not isinstance(document["derivations"], dict)
    ):
        raise ValueError("unsupported Nix declaration envelope")
    return document["derivations"]


def dependency_paths(document: Any, selected: str) -> list[str]:
    rows = derivations(document)
    if STORE.fullmatch(selected) is None or set(rows) != {Path(selected).name}:
        raise ValueError("selected qualification declaration identity differs")
    row = rows[Path(selected).name]
    if row["version"] != 4 or set(row["inputs"]) != {"srcs", "drvs"}:
        raise ValueError("unexpected qualification declaration version/inputs")
    paths = []
    for dependency, edge in row["inputs"]["drvs"].items():
        path = "/nix/store/" + dependency
        if STORE.fullmatch(path) is None or not path.endswith(".drv"):
            raise ValueError("invalid direct qualification derivation")
        if set(edge) != {"outputs", "dynamicOutputs"} or edge["dynamicOutputs"]:
            raise ValueError("unsupported dynamic qualification dependency")
        if not edge["outputs"] or len(edge["outputs"]) != len(set(edge["outputs"])):
            raise ValueError("missing or duplicated direct qualification outputs")
        paths.append(path)
    return sorted(paths)


def require_realized(value: str) -> None:
    if STORE.fullmatch("/nix/store/" + value) is None or not Path("/nix/store", value).exists():
        raise ValueError("qualification needs an unrealized direct input; no extra build allowed")


def check_dependencies(document: Any, selected: str, direct: Any) -> None:
    paths = dependency_paths(document, selected)
    rows = derivations(direct)
    if set(rows) != {Path(path).name for path in paths}:
        raise ValueError("direct qualification declaration set differs")
    row = document["derivations"][Path(selected).name]
    for source in row["inputs"]["srcs"]:
        require_realized(source)
    for dependency, edge in row["inputs"]["drvs"].items():
        for name in edge["outputs"]:
            output = rows[dependency]["outputs"].get(name)
            if not isinstance(output, dict) or set(output) != {"path"}:
                raise ValueError("qualification direct output is unbound")
            require_realized(output["path"])
    # Realized direct outputs are sufficient. Their historical source archives
    # and transitive build inputs may have been collected and are not rebuilt.


def bind_registered_client(
    directory: Path, rows: list[dict[str, Any]], profile: str | None
) -> dict[str, Any]:
    with nested.locked(directory) as (descriptor, ledger):
        owner, identifiers = nested.registered(descriptor, ledger)
        if owner["owner"] != profile or len(identifiers) != 1:
            raise ValueError("expected one actual namespace client registration")
        record = nested.read_receipt(descriptor, owner, identifiers[0])
        if record["confirmed"] is not False or type(record["group"]) is not int:
            raise ValueError("expected a started unconfirmed Nix client")
        clients = [row for row in rows if row["kind"] == "client"]
        if len(clients) != 1:
            raise ValueError("actual registered Nix client was not independently identified")
        client = clients[0]
        if not client["pid"] == client["group"] == client["session"] == record["group"]:
            raise ValueError("registered Nix client group/session differs")
        current = identity(client["pid"])
        if current is None or any(client[key] != value for key, value in current.items()):
            raise ValueError("registered Nix client identity changed")
        return {
            "record": record,
            "client": client,
            "directory_identity": nested.identity_of(descriptor, ledger),
            "ledger_sha256": hashlib.sha256((directory / nested.LEDGER).read_bytes()).hexdigest(),
        }


def registered_client_stopped(case: Case) -> bool:
    binding = case.data.get("registered_client")
    if not isinstance(binding, dict):
        return False
    client = binding["client"]
    # A recycled PID or group is uncertainty, never permission to remove policy.
    return identity(client["pid"]) is None and not group_running(client["group"])


def remove_registered_receipt(directory: Path, case: Path) -> dict[str, Any]:
    with nested.locked(directory) as (descriptor, ledger):
        owner, identifiers = nested.registered(descriptor, ledger)
        if len(identifiers) != 1:
            raise ValueError("expected one actual observer registration")
        record = nested.read_receipt(descriptor, owner, identifiers[0])
        if record["confirmed"] is not False or type(record["group"]) is not int:
            raise ValueError("expected a started unconfirmed observer")
        before = nested.identity_of(descriptor, ledger)
        name = identifiers[0] + ".json"
        content = (directory / name).read_bytes()
        with (case / "removed-receipt.json").open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.unlink(name, dir_fd=descriptor)
        os.fsync(descriptor)
        if nested.identity_of(descriptor, ledger) != before:
            raise ValueError("fault injection changed directory/ledger identity")
        return {
            "name": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "identity": before,
            "record": record,
            "ledger_sha256": hashlib.sha256((directory / nested.LEDGER).read_bytes()).hexdigest(),
        }


def recover(case: Case) -> list[str]:  # noqa: C901, PLR0912, PLR0915 - ordered fail-closed recovery.
    """Keep policy loaded unless direct work and independently observed Nix work are stopped."""
    errors: list[str] = []
    try:
        case.cancel()
        until = min(case.end - 20, time.monotonic() + 20)
        while case.wrapper is not None and case.wrapper.poll() is None and time.monotonic() < until:
            time.sleep(0.05)
        case.discover_policy()
        if case.worker is None:
            return ["census unavailable; no cleanup qualification"]
        for signum in (signal.SIGTERM, signal.SIGKILL):
            snapshot = case.census()
            if not snapshot["rows"]:
                break
            case.data["independent_process_recovery_required"] = True
            case.census("stop", signal=int(signum))
            until = min(case.end - 10, time.monotonic() + 2)
            while time.monotonic() < until:
                if not case.census()["rows"]:
                    break
                time.sleep(0.05)
        first = case.census()
        time.sleep(0.05)
        last = case.census()
        wrapper_stopped = case.wrapper is not None and case.wrapper.poll() is not None
        work_stopped = case.work_identity is not None and not group_running(
            case.work_identity["group"]
        )
        case.data["owned_work_stopped"] = (
            wrapper_stopped
            and work_stopped
            and registered_client_stopped(case)
            and not first["rows"]
            and not last["rows"]
            and not last["known_remaining"]
        )
        if not case.data["owned_work_stopped"]:
            errors.append("owned work stop unconfirmed; retain exact policy and recovery evidence")
        elif case.profile is not None and last.get("profile_present"):
            if case.policy is None or case.policy.is_symlink() or not case.policy.is_file():
                raise ValueError("retained policy file is unavailable")  # noqa: TRY301
            if hashlib.sha256(case.policy.read_bytes()).hexdigest() != case.policy_sha:
                raise ValueError("retained policy identity changed")  # noqa: TRY301
            case.command(
                ["sudo", "-n", "apparmor_parser", "--skip-cache", "--remove", str(case.policy)],
                "independent-policy-recovery",
                cleanup=True,
            )
            after = case.census()
            if after["profile_present"]:
                raise RuntimeError("exact recovered profile is still present")  # noqa: TRY301
            case.data["independent_policy_recovery"] = {
                "profile": case.profile,
                "policy_sha256": case.policy_sha,
                "profile_absent": True,
                "original_missing_evidence_unchanged": True,
            }
        if namespace.restriction() != "1":
            errors.append("host restriction changed or qualification capability is absent")
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        errors.append(str(error))
    return errors


def finish_case(case: Case) -> None:
    errors = recover(case)
    if case.worker is not None:
        try:
            case.data["final_census"] = case.census("finish")
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            errors.append("final census: " + str(error))
        if case.worker.stdin is not None:
            with contextlib.suppress(OSError):
                case.worker.stdin.close()
    # A stalled namespace owner may be finishing policy cleanup. Do not kill it
    # or remove its policy on the strength of a stopped Nix client alone.
    remaining = [process.pid for process in case.children]
    worker_absent = False
    try:
        until = min(case.end, time.monotonic() + 2)
        while any(process.poll() is None for process in case.children) and time.monotonic() < until:
            time.sleep(0.02)
        remaining = [process.pid for process in case.children if process.poll() is None]
        worker_absent = case.worker_pid is not None and identity(case.worker_pid) is None
    except (OSError, ValueError) as error:
        errors.append("controller/census termination: " + str(error))
    if remaining or not worker_absent:
        errors.append("owned controller/census termination is unconfirmed")
    case.data.update(
        cleanup_errors=errors,
        remaining_controllers=remaining,
        census_ended=worker_absent,
        events=case.events,
    )
    case.data["passed"] = (
        case.data.get("expected_behavior") is True
        and not errors
        and case.data.get("owned_work_stopped") is True
        and not case.data.get("independent_process_recovery_required")
    )
    for stream in case.streams:
        try:
            stream.close()
        except OSError as error:
            errors.append("evidence close: " + str(error))
            case.data["passed"] = False
    write(case.path / "result.json", case.data)


def run(output: Path) -> int:
    output.mkdir(mode=0o700)
    end = time.monotonic() + TOTAL_SECONDS
    results = []
    for name in CASE_NAMES:
        case = Case(output / name, name, end)
        try:
            case.check()
            enabled = Path("/sys/module/apparmor/parameters/enabled")
            if (
                not enabled.is_file()
                or enabled.read_text().strip() != "Y"
                or namespace.restriction() != "1"
            ):
                raise RuntimeError(  # noqa: TRY301 - record preflight refusal in the case result.
                    "actual restricted AppArmor host is required; not exercised"
                )
            case.exercise()
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            TypeError,
            subprocess.SubprocessError,
        ) as error:
            case.data["error"] = str(error)
        finally:
            finish_case(case)
        results.append(case.data)
        if not case.data["passed"]:
            break
    passed = (
        not STOP and len(results) == len(CASE_NAMES) and all(case["passed"] for case in results)
    )
    write(
        output / "result.json",
        {
            "schema_version": 1,
            "passed": passed,
            "cancellation_recorded": STOP,
            "case_names": list(CASE_NAMES),
            "cases": [{"case": row["case"], "passed": row["passed"]} for row in results],
            "context": {
                key: os.environ.get(key)
                for key in (
                    "GITHUB_REPOSITORY",
                    "GITHUB_SHA",
                    "GITHUB_RUN_ID",
                    "GITHUB_RUN_ATTEMPT",
                    "GITHUB_EVENT_NAME",
                    "RUNNER_OS",
                    "RUNNER_ARCH",
                )
            },
            "qualification": (
                "real AppArmor plus Nix; two finite functional cases, not universal ordering"
            ),
            "source_hashes": {
                str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in [
                    Path(__file__),
                    Path(__file__).with_name("namespace_lifecycle_work.py"),
                    Path(__file__).with_name("namespace_lifecycle_processes.py"),
                    ROOT / "scripts/ci/with_organization_userns.py",
                    ROOT / "scripts/ci/build_observations.py",
                    ROOT / "scripts/validation/process_cleanup_receipts.py",
                ]
            },
        },
    )
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    return run(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
