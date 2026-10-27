# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Independent absolute-deadline request: never waits for evidence or a journal.

Provider adapters must implement identity readback and an idempotent stop request.
A failed/late readback is stop_unconfirmed, not successful resource destruction.
"""

import time


def bounded_json_command(argv, deadline):
    import json  # noqa: PLC0415 -- retain measured initialization order
    import os  # noqa: PLC0415 -- retain measured initialization order
    import signal  # noqa: PLC0415 -- retain measured initialization order
    import subprocess  # noqa: PLC0415 -- retain measured initialization order
    import tempfile  # noqa: PLC0415 -- retain initialization order of the measured analysis

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Provider request deadline")
    # Regular output files avoid a pipe whose descendants can keep it open.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(argv, stdout=output, stderr=errors, start_new_session=True)  # noqa: S603 -- explicit argv; artifact validation precedes execution
        try:
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as e:
                raise TimeoutError("Provider request deadline") from e
            if code:
                raise OSError("Provider request failed")
            if time.monotonic() >= deadline:
                raise TimeoutError("Provider response too late")
            output.seek(0)
            data = output.read(1024**2 + 1)
            if len(data) > 1024**2:
                raise OSError("Unbounded provider response")
            return json.loads(data)
        finally:
            try:  # noqa: SIM105 -- retain explicit process-loss handling
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


class AwsProvider:
    """Explicit region/profile; immutable instance ID plus launch and generation."""

    def __init__(self, cli, region, profile=None):
        self.argv = [
            str(cli),
            "--region",
            region,
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "10",
        ]
        if profile:
            self.argv += ["--profile", profile]

    def read(self, resource, end):
        data = bounded_json_command(
            self.argv + ["ec2", "describe-instances", "--instance-ids", resource],  # noqa: RUF005 -- retain the measured sequence construction
            min(end, time.monotonic() + 20),
        )
        instances = [i for r in data["Reservations"] for i in r["Instances"]]
        if len(instances) != 1 or instances[0]["InstanceId"] != resource:
            raise OSError("Wrong resource readback")
        return instances[0]

    def identity(self, resource, end):
        row = self.read(resource, end)
        tags = {t["Key"]: t["Value"] for t in row.get("Tags", [])}
        return {
            "instance_id": resource,
            "launch_time": row["LaunchTime"],
            "generation": tags.get("AegaeonGeneration"),
        }

    def stop(self, resource, end):
        bounded_json_command(
            self.argv + ["ec2", "stop-instances", "--instance-ids", resource],  # noqa: RUF005 -- retain the measured sequence construction
            min(end, time.monotonic() + 20),
        )

    def state(self, resource, end):
        return self.read(resource, end)["State"]["Name"]


def local_guard(pid, start, deadline, seconds):
    import os  # noqa: PLC0415 -- retain initialization order of the measured analysis
    import signal  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from pathlib import Path  # noqa: PLC0415 -- retain initialization order of the measured analysis

    # pidfd pins the owned process; a recycled numeric PID cannot be signalled.
    fd = os.pidfd_open(pid)

    class Owned:
        def identity(self, resource, end):
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]

        def stop(self, resource, end):
            signal.pidfd_send_signal(fd, signal.SIGKILL)

        def state(self, resource, end):
            import select  # noqa: PLC0415 -- retain initialization order of the measured analysis

            return "stopped" if select.select([fd], [], [], 0)[0] else "running"

    try:
        return enforce(Owned(), pid, start, deadline, seconds)
    finally:
        os.close(fd)


def enforce(  # noqa: PLR0913, PLR0917 -- explicit fields from the frozen invocation contract
    provider,
    resource,
    identity,
    deadline,
    confirmation_seconds,
    clock=time.monotonic,
    sleep=time.sleep,
):
    if confirmation_seconds <= 0:
        raise ValueError("Finite confirmation budget required")
    while clock() < deadline:
        sleep(min(0.1, deadline - clock()))
    # The adapter has a fixed per-call timeout shorter than this budget. There
    # is no controller lock, mutable campaign state or recovery dependency here.
    end = clock() + confirmation_seconds
    try:
        observed = provider.identity(resource, end)
        if clock() >= end:
            raise TimeoutError("Identity readback deadline")  # noqa: TRY301 -- failure capture preserves partial evidence
        if observed != identity:
            return {"status": "identity_mismatch", "stop_confirmed": False}
        provider.stop(resource, end)
        while clock() < end:
            state = provider.state(resource, end)
            if clock() >= end:
                raise TimeoutError("Stop readback deadline")  # noqa: TRY301 -- failure capture preserves partial evidence
            if state in ("stopped", "terminated"):
                return {"status": state, "stop_confirmed": True}
            sleep(min(0.1, max(0, end - clock())))
    except (OSError, TimeoutError):
        pass
    return {"status": "stop_unconfirmed", "stop_confirmed": False}


if __name__ == "__main__":
    import argparse
    import json
    from pathlib import Path

    p = argparse.ArgumentParser()
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--start", required=True)
    p.add_argument("--deadline", type=float, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = local_guard(a.pid, a.start, a.deadline, 2)
    a.output.write_text(json.dumps(result) + "\n")
