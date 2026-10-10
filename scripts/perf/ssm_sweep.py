"""Bounded SSM transport and independent, supervised performance invocations."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

EXECUTION_SECONDS = 120
DELIVERY_SECONDS = 60
COMMAND_BUDGET = 210
CALL_BUDGET = 45
POLL_SECONDS = 5
OVERHEAD_SECONDS = 900
MAX_DURATION = 86400
MAX_COMMENT_LENGTH = 100
CLI_ARGUMENT_COUNT = 5


def bash_script(script: str) -> str:
    marker = "AEGAEON_SSM_BASH"
    while marker in script.splitlines():
        marker += "_"
    return f"exec /bin/bash <<'{marker}'\n{script}\n{marker}\n"


def duration(raw: str, *, zero: bool = False) -> int:
    match = re.fullmatch(r"(0|[1-9][0-9]*)([smh]?)", raw)
    if match is None:
        msg = "canonical duration required"
        raise ValueError(msg)
    value = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
    if not (0 if zero else 1) <= value <= MAX_DURATION:
        msg = "duration outside admitted domain"
        raise ValueError(msg)
    return value


class SSM:
    def __init__(self, instance: str, evidence: Path) -> None:
        self.instance = instance
        self.evidence = evidence
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.sequence = 0
        self.pending: str | None = None

    def call(self, *args: str, deadline: float | None = None) -> subprocess.CompletedProcess[str]:
        self.sequence += 1
        stem = self.evidence / f"{self.sequence:05d}-{args[0]}"
        argv = [
            "aws",
            "--region",
            os.environ["AWS_REGION"],
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "30",
            "ssm",
            *args,
        ]
        stem.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        timeout = CALL_BUDGET if deadline is None else min(CALL_BUDGET, deadline - time.monotonic())
        if timeout <= 0:
            msg = "local AWS deadline expired"
            raise TimeoutError(msg)
        try:
            result = subprocess.run(  # noqa: S603 -- fixed AWS executable and explicit argv, no shell
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env={**os.environ, "AWS_MAX_ATTEMPTS": "1"},
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            stem.with_suffix(".error.txt").write_text(str(error) + "\n")
            for name in ("stdout", "stderr"):
                partial = getattr(error, name, None) or b""
                stem.with_suffix("." + name).write_bytes(
                    partial if isinstance(partial, bytes) else partial.encode()
                )
            msg = "bounded AWS call failed"
            raise RuntimeError(msg) from error
        stem.with_suffix(".stdout").write_text(result.stdout)
        stem.with_suffix(".stderr").write_text(result.stderr)
        stem.with_suffix(".exit").write_text(str(result.returncode) + "\n")
        return result

    def cancel(self) -> None:
        if self.pending is not None:
            result = self.call(
                "cancel-command",
                "--command-id",
                self.pending,
                "--instance-ids",
                self.instance,
                "--output",
                "json",
            )
            if result.returncode:
                msg = "SSM cancellation API failed; pending command remains inconclusive"
                raise RuntimeError(msg)
            self.pending = None

    def command(  # noqa: C901, PLR0912, PLR0915 -- explicit terminal/pending/error transport states
        self, script: str, comment: str, *, deadline: float | None = None
    ) -> dict[str, Any]:
        if not isinstance(comment, str) or not 1 <= len(comment) <= MAX_COMMENT_LENGTH:
            msg = "SSM comment must contain 1 through 100 characters"
            raise ValueError(msg)
        deadline = min(time.monotonic() + COMMAND_BUDGET, deadline or float("inf"))
        parameters = json.dumps(
            {"commands": [bash_script(script)], "executionTimeout": [str(EXECUTION_SECONDS)]}
        )
        sent = self.call(
            "send-command",
            "--instance-ids",
            self.instance,
            "--document-name",
            "AWS-RunShellScript",
            "--timeout-seconds",
            str(DELIVERY_SECONDS),
            "--comment",
            comment,
            "--parameters",
            parameters,
            "--query",
            "Command.CommandId",
            "--output",
            "text",
            deadline=deadline,
        )
        if sent.returncode or not re.fullmatch(r"[A-Za-z0-9-]+", sent.stdout.strip()):
            msg = "SSM command dispatch failed or is inconclusive"
            raise RuntimeError(msg)
        self.pending = sent.stdout.strip()
        while time.monotonic() < deadline:
            got = self.call(
                "get-command-invocation",
                "--command-id",
                self.pending,
                "--instance-id",
                self.instance,
                "--output",
                "json",
                deadline=deadline,
            )
            if got.returncode:
                if "InvocationDoesNotExist" not in got.stderr:
                    msg = "SSM status retrieval failed"
                    raise RuntimeError(msg)
            else:
                response = json.loads(got.stdout)
                if not isinstance(response, dict) or not isinstance(response.get("Status"), str):
                    msg = "invalid SSM invocation record"
                    raise ValueError(msg)
                status = response["Status"]
                if status in {"Success", "Failed", "TimedOut", "Cancelled"}:
                    if any(
                        not isinstance(response.get(name), str)
                        for name in ("StandardOutputContent", "StandardErrorContent")
                    ):
                        msg = "invalid SSM invocation output"
                        raise ValueError(msg)
                    if time.monotonic() >= deadline:
                        msg = "local SSM deadline expired before terminal acceptance"
                        raise TimeoutError(msg)
                    self.pending = None
                    return response
                if status not in {"Pending", "InProgress", "Delayed", "Cancelling"}:
                    msg = "unknown SSM status"
                    raise RuntimeError(msg)
            time.sleep(min(POLL_SECONDS, max(0, deadline - time.monotonic())))
        msg = "local SSM command deadline expired"
        raise TimeoutError(msg)


def control_script(identifier: str) -> str:
    # UUID is generated locally; all user configuration is carried as base64 data.
    return f"""set -euo pipefail
umask 077
CONTROL=/etc/aegaeon/.sweep-{identifier}
UNIT=aegaeon-sweep-{identifier}.service
if ! mkdir -m 0700 "$CONTROL" 2>/dev/null; then
  [[ -d "$CONTROL" && ! -L "$CONTROL" && "$(stat -c '%u:%a' "$CONTROL")" == 0:700 ]] || exit 1
fi
[[ "$(id -u)" == 0 ]] || exit 1
[[ ! -L "$CONTROL/control.lock" ]] || exit 1
exec 9>"$CONTROL/control.lock"
flock -x -w 10 9
"""


def runner_script(identifier: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
umask 077
CONTROL=/etc/aegaeon/.sweep-{identifier}
if [[ "${{1:-}}" == cleanup ]]; then
  timeout 30 docker rm --force aegaeon-sweep-{identifier} \\
    >"$CONTROL/docker-cleanup.log" 2>&1 || true
  CLEANUP_EXIT_CODE=0
  REMAINING="$(timeout 10 docker ps -a \\
    --filter 'name=^/aegaeon-sweep-{identifier}$' --format '{{{{.Names}}}}' \\
    2>>"$CONTROL/docker-cleanup.log")" || CLEANUP_EXIT_CODE=1
  [[ -z "$REMAINING" ]] || CLEANUP_EXIT_CODE=1
  printf '%s\\n' "$CLEANUP_EXIT_CODE" >"$CONTROL/cleanup-exit.tmp"
  mv "$CONTROL/cleanup-exit.tmp" "$CONTROL/cleanup-exit"
  exit "$CLEANUP_EXIT_CODE"
fi
DRIVER_EXIT_CODE=0
/usr/local/bin/aegaeon-run-loadtest --config-file "$CONTROL/config.json" || DRIVER_EXIT_CODE=$?
printf 'DRIVER_EXIT_CODE=%s\\n' "$DRIVER_EXIT_CODE"
printf '%s\\n' "$DRIVER_EXIT_CODE" >"$CONTROL/completion.tmp"
mv "$CONTROL/completion.tmp" "$CONTROL/completion"
exit "$DRIVER_EXIT_CODE"
"""


def dispatch_script(identifier: str, payload: str, runtime: int) -> str:
    runner = base64.b64encode(runner_script(identifier).encode()).decode()
    return (
        control_script(identifier)
        + f"""
[[ ! -e "$CONTROL/cancelled" && ! -e "$CONTROL/dispatched" ]] || exit 1
printf '%s' '{payload}' | base64 --decode >"$CONTROL/config.json"
printf '%s' '{runner}' | base64 --decode >"$CONTROL/runner.sh"
chmod 0600 "$CONTROL/config.json" "$CONTROL/runner.sh"
: >"$CONTROL/dispatched"
systemd-run --quiet --unit="$UNIT" --setenv=AEGAEON_SWEEP_ID={identifier} \\
  --property=Type=exec --property=RemainAfterExit=yes \\
  --property=RuntimeMaxSec={runtime} --property=TimeoutStartSec=30 \\
  --property=TimeoutStopSec=45 --property=KillMode=control-group \\
  --property="StandardOutput=append:$CONTROL/stdout.log" \\
  --property="StandardError=append:$CONTROL/stderr.log" \\
  --property="ExecStopPost=/bin/bash $CONTROL/runner.sh cleanup" \\
  /bin/bash "$CONTROL/runner.sh"
"""
    )


def snapshot_script(identifier: str, *, stop: bool = False) -> str:
    action = (
        """
python3 - "$CONTROL" <<'CANCELLED'
import os,sys
from pathlib import Path
root=Path(sys.argv[1])
with (root/'cancelled').open('wb') as marker:
    marker.flush(); os.fsync(marker.fileno())
handle=os.open(root,os.O_DIRECTORY)
try: os.fsync(handle)
finally: os.close(handle)
CANCELLED
timeout 100 systemctl stop "$UNIT" >"$CONTROL/stop.log" 2>&1 || true
"""
        if stop
        else ""
    )
    return (
        control_script(identifier)
        + action
        + """
PROPERTIES="$(systemctl show "$UNIT" -p LoadState -p ActiveState -p SubState \\
  -p Result -p ExecMainStatus)" || exit 1
python3 - "$CONTROL" "$PROPERTIES" <<'SNAPSHOT'
import base64,json,sys
from pathlib import Path
root=Path(sys.argv[1]); properties=dict(line.split('=',1) for line in sys.argv[2].splitlines())
active=properties.get('ActiveState'); sub=properties.get('SubState')
completed=(root/'completion').is_file()
good=properties.get('Result')=='success' and properties.get('ExecMainStatus')=='0'
state='running' if active in {'active','activating','deactivating'} else 'failed'
if active=='active' and sub=='exited': state='complete' if completed and good else 'failed'
if (root/'cancelled').exists():
    stopped=active in {'inactive','failed'} or properties.get('LoadState')=='not-found'
    state='stopped' if stopped else 'cleanup-inconclusive'
    if state=='stopped': (root/'config.json').unlink(missing_ok=True)
record={'state':state,'properties':properties,'completed':completed,
        'cleanup_exit':None}
if (root/'cleanup-exit').is_file(): record['cleanup_exit']=(root/'cleanup-exit').read_text().strip()
for name,limit in [('stdout',9000),('stderr',3000)]:
    path=root/(name+'.log')
    data=b''; size=0
    if path.exists():
        with path.open('rb') as handle:
            handle.seek(0,2); size=handle.tell()
            handle.seek(max(0,size-limit)); data=handle.read(limit)
    record[name]=base64.b64encode(data[-limit:]).decode()
    record[name+'_truncated']=size>limit
print(json.dumps(record))
SNAPSHOT
"""
    )


def snapshot(  # noqa: PLR0912 -- explicit consistency and bounded-output guards
    client: SSM, identifier: str, *, stop: bool = False, deadline: float | None = None
) -> dict[str, Any]:
    response = client.command(
        snapshot_script(identifier, stop=stop),
        "aegaeon: sweep cleanup" if stop else "aegaeon: sweep status",
        deadline=deadline,
    )
    if response.get("Status") != "Success":
        msg = "SSM supervisor query failed"
        raise RuntimeError(msg)
    record = json.loads(response["StandardOutputContent"])
    if not isinstance(record, dict):
        msg = "supervisor object required"
        raise TypeError(msg)
    if record.get("state") not in {
        "running",
        "complete",
        "failed",
        "stopped",
        "cleanup-inconclusive",
    }:
        msg = "unknown supervisor state"
        raise ValueError(msg)
    properties = record.get("properties")
    if (
        not isinstance(properties, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in properties.items()
        )
        or not isinstance(record.get("completed"), bool)
        or record.get("cleanup_exit") not in {None, "0", "1"}
    ):
        msg = "invalid supervisor properties"
        raise ValueError(msg)
    if record["state"] == "complete" and (
        not record["completed"]
        or properties.get("ActiveState") != "active"
        or properties.get("SubState") != "exited"
        or properties.get("Result") != "success"
        or properties.get("ExecMainStatus") != "0"
    ):
        msg = "inconsistent supervisor completion"
        raise ValueError(msg)
    if record["state"] == "stopped" and not (
        properties.get("ActiveState") in {"inactive", "failed"}
        or properties.get("LoadState") == "not-found"
    ):
        msg = "inconsistent supervisor stop"
        raise ValueError(msg)
    for name in ("stdout", "stderr"):
        if not isinstance(record.get(name), str):
            msg = "invalid supervisor output"
            raise TypeError(msg)
        decoded = base64.b64decode(record[name], validate=True)
        if (
            base64.b64encode(decoded).decode() != record[name]
            or len(decoded) > (9000 if name == "stdout" else 3000)
            or not isinstance(record.get(name + "_truncated"), bool)
        ):
            msg = "invalid bounded supervisor output"
            raise ValueError(msg)
    return record


def loadtest(client: SSM, payload: str, comment: str) -> dict[str, Any]:  # noqa: C901, PLR0912, PLR0915 -- one explicit supervision/finalization state machine
    decoded = base64.b64decode(payload, validate=True)
    if base64.b64encode(decoded).decode() != payload:
        msg = "canonical configuration base64 required"
        raise ValueError(msg)
    config = json.loads(decoded)
    runtime = (
        duration(config["RUN_TIME"]) + duration(config["WARMUP"], zero=True) + OVERHEAD_SECONDS
    )
    identifier = str(uuid.uuid4())
    (client.evidence / "identity.json").write_text(
        json.dumps({"uuid": identifier, "runtime_seconds": runtime}) + "\n"
    )
    record: dict[str, Any] = {}
    error = ""
    complete = False
    deadline = time.monotonic() + runtime + COMMAND_BUDGET
    try:
        response = client.command(
            dispatch_script(identifier, payload, runtime), comment, deadline=deadline
        )
        if response.get("Status") != "Success":
            msg = "SSM loadgen dispatch failed"
            raise RuntimeError(msg)  # noqa: TRY301 -- finalization handles every dispatch failure
        while time.monotonic() < deadline:
            record = snapshot(client, identifier, deadline=deadline)
            if time.monotonic() >= deadline:
                msg = "local loadgen deadline expired"
                raise TimeoutError(msg)  # noqa: TRY301 -- finalization handles the explicit global deadline
            if record["state"] == "complete":
                complete = True
                break
            if record["state"] != "running":
                msg = "supervised loadgen failed"
                raise RuntimeError(msg)  # noqa: TRY301 -- finalization handles supervisor failure
            time.sleep(min(POLL_SECONDS, max(0, deadline - time.monotonic())))
        if not complete:
            msg = "local loadgen deadline expired"
            raise TimeoutError(msg)  # noqa: TRY301 -- finalization handles deadline expiry
    except (
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
        InterruptedError,
        TimeoutError,
    ) as exc:
        error = str(exc)
    finally:
        try:
            client.cancel()
        except (RuntimeError, OSError, InterruptedError) as exc:
            (client.evidence / "cancel-error.txt").write_text(str(exc) + "\n")
        try:
            record = snapshot(client, identifier, stop=True)
            if record["state"] != "stopped" or record["cleanup_exit"] != "0":
                error = error or "remote cleanup is inconclusive or failed"
        except (
            RuntimeError,
            ValueError,
            TypeError,
            KeyError,
            OSError,
            InterruptedError,
            TimeoutError,
        ) as exc:
            error = error or f"remote cleanup inconclusive: {exc}"
    (client.evidence / "supervisor-final.json").write_text(
        json.dumps({**record, "error": error, "complete_observed": complete}) + "\n"
    )
    return {
        "Status": "Success" if complete and not error else "Failed",
        "StandardOutputContent": base64.b64decode(record.get("stdout", "")).decode(
            errors="replace"
        ),
        "StandardErrorContent": base64.b64decode(record.get("stderr", "")).decode(errors="replace")
        + ("\n" + error if error else ""),
    }


def interrupted(signum: int, _frame: object) -> None:
    msg = f"interrupted by signal {signum}"
    raise InterruptedError(msg)


def main() -> int:
    if len(sys.argv) != CLI_ARGUMENT_COUNT or sys.argv[1] not in {"command", "loadtest"}:
        print("expected command|loadtest INSTANCE COMMENT EVIDENCE_DIRECTORY", file=sys.stderr)
        return 2
    mode, instance, comment, directory = sys.argv[1:]
    client = SSM(instance, Path(directory))
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        source = sys.stdin.read().strip()
        response = (
            loadtest(client, source, comment)
            if mode == "loadtest"
            else client.command(source, comment)
        )
    except (
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
        InterruptedError,
        TimeoutError,
    ) as error:
        with contextlib.suppress(RuntimeError, OSError, InterruptedError):
            client.cancel()
        response = {
            "Status": "Inconclusive",
            "StandardOutputContent": "",
            "StandardErrorContent": str(error),
        }
    (client.evidence / "result.json").write_text(json.dumps(response) + "\n")
    print(json.dumps(response))
    return 0 if response.get("Status") == "Success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
