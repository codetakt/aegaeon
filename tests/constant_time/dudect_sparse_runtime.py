"""Bounded, prefix-only PR inference before ACK; retained records are replayable."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO, cast

from dudect_candidate import (
    SPARSE_RUNTIME,
    CandidateAdmission,
    CandidateStream,
    canonical,
    digest,
    validate_binding,
)
from dudect_process import load_json
from dudect_results import BATCH_SIZE
from dudect_sparse_contract import check_runtime_contract
from dudect_sparse_replay import Prefix, augment
from dudect_support import require
from dudect_timing import (
    BATCH,
    CASE_V4,
    CONTROLS,
    INPUTS,
    STRIDES,
    input_width,
    validate_context,
    validate_control_inputs,
)

MAX_MESSAGE = 1024 * 1024
LOOK_SECONDS = cast("int", SPARSE_RUNTIME["look_seconds"])
WORKER_ADDRESS_SPACE_BYTES = cast("int", SPARSE_RUNTIME["worker_address_space_bytes"])


class PrefixReader:
    def __init__(self, path: Path, bindings: dict[str, Any], profile: str) -> None:
        require(profile == "pr", "Runtime sparse inference is PR only")
        contract = check_runtime_contract()
        for name, binding in bindings.items():
            validate_binding(binding, name, profile)
            require(binding["contract_sha256"] == contract, "Unreviewed runtime case contract")
        self.path, self.bindings, self.names = path, bindings, tuple(bindings)
        require(bool(self.names), "Missing runtime case inventory")
        require(
            len({b["build_sha256"] for b in bindings.values()}) == 1, "Mixed native build bindings"
        )
        self.source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        require(
            stat.S_ISREG(os.fstat(self.source).st_mode), "Timing evidence must be a regular file"
        )
        self.offset = 0
        self.hash = hashlib.sha256()
        self.index = 0
        self.prefix: Prefix | None = None
        self.admission: CandidateAdmission | None = None
        self.detected = False
        self.end = None
        self.counters = [0] * 6
        self.case_start = 0

    def close(self) -> None:
        os.close(self.source)

    def read(self, size: int) -> bytes:
        # pread on a regular file never waits for EOF or the next frame.
        data = os.pread(self.source, size, self.offset)
        require(len(data) == size, "Incomplete current raw prefix before ACK")
        self.offset += size
        self.hash.update(data)
        return data

    def push(  # noqa: PLR0915 - one prefix verification transaction
        self, row: dict[str, Any]
    ) -> dict[str, Any]:
        require(self.index < len(self.names), "Unexpected runtime observation")
        inode = os.fstat(self.source)
        current = self.path.stat(follow_symlinks=False)
        require(
            (inode.st_dev, inode.st_ino) == (current.st_dev, current.st_ino), "Timing file replaced"
        )
        name = self.names[self.index]
        binding = self.bindings[name]
        if self.offset == 0:
            header = b"AEGTIM05" + b"".join(
                binding[k].encode("ascii")
                for k in ("build_sha256", "contract_sha256", "numerical_sha256")
            )
            require(self.read(200) == header, "Wrong runtime timing binding or format")
        if self.prefix is None:
            self.case_start = self.offset
            native_name, stride, width, *offsets = CASE_V4.unpack(self.read(CASE_V4.size))
            require(
                native_name == name.encode().ljust(64, b"\0")
                and stride == STRIDES[name]
                and width == input_width(name, b"AEGTIM05"),
                "Wrong runtime case layout",
            )
            require(all(v < 4096 for v in offsets), "Invalid runtime buffer offsets")
            self.prefix = Prefix()
            self.admission = CandidateAdmission(name, "pr", binding=binding)
            self.detected = False
        assert self.admission is not None
        assert self.prefix is not None
        original = self.admission.admit(row)
        width = input_width(name, b"AEGTIM05")
        for batch in range(self.prefix.batch + 1, row["batches"] + 1):
            context = BATCH.unpack(self.read(BATCH.size))
            validate_context(context, batch, self.end, self.counters)
            self.end, self.counters = context[3], list(context[7::2])
            payload = self.read(BATCH_SIZE * (9 + width))
            labels = payload[BATCH_SIZE * 8 : BATCH_SIZE * 9]
            if width:
                inputs = payload[BATCH_SIZE * 9 :]
                if name in CONTROLS:
                    validate_control_inputs(inputs, labels, name)
                else:
                    fixed = bytes([INPUTS[name]]) * width
                    require(
                        all(
                            inputs[i * width : (i + 1) * width] == fixed
                            for i, g in enumerate(labels)
                            if g == 0
                        ),
                        "Wrong fixed-class input in current prefix",
                    )
            self.prefix.push(payload, batch)
        require(
            self.prefix.prepared_counts == row["input_audit"]["class_count"],
            "Prepared class counts differ from prefix",
        )
        evaluated = augment(row, original, self.prefix, self.detected)
        self.detected = evaluated["detected"]
        proof = {
            "schema": SPARSE_RUNTIME["schema"],
            "binding": binding,
            "row_sha256": digest(canonical(row)),
            "case": name,
            "look": row["look"],
            "through_batch": row["batches"],
            "prefix_start": 0,
            "prefix_end": self.offset,
            "case_start": self.case_start,
            "prefix_sha256": self.hash.hexdigest(),
            "pilot": row["pilot"],
            "input_classes_checked": self.prefix.prepared_counts.copy(),
            "all_statistics_counts_checked": 102,
            "history": evaluated,
        }
        if original["collection_complete"]:
            self.prefix = self.admission = None
            self.index += 1
        return proof

    def finish(self) -> dict[str, Any]:
        require(
            self.index == len(self.names) and self.prefix is None,
            "Incomplete runtime inference schedule",
        )
        require(
            os.fstat(self.source).st_size == self.offset,
            "Trailing or truncated runtime timing evidence",
        )
        return {"bytes": self.offset, "sha256": self.hash.hexdigest(), "cases": self.index}


class Worker:
    """Separate address-space ceiling and a hard parent-side wall-clock deadline."""

    def __init__(self, path: Path, bindings: dict[str, Any], errors: BinaryIO) -> None:
        self.process = subprocess.Popen(  # noqa: S603 - fixed isolated verifier entrypoint
            [sys.executable, "-B", "-u", str(Path(__file__).resolve()), "--worker", str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            start_new_session=True,
        )
        self.buffer = b""
        try:
            self.exchange(
                {"bindings": bindings, "case_order": list(bindings)},
                time.monotonic() + LOOK_SECONDS,
            )
        except BaseException:
            self.close()
            raise

    def exchange(  # noqa: PLR0915 - bounded bidirectional pipe transaction
        self, request: dict[str, Any], deadline: float
    ) -> dict[str, Any]:
        require(time.monotonic() < deadline, "Sparse processing deadline reached")
        data = canonical(request) + b"\n"
        require(len(data) <= MAX_MESSAGE, "Unbounded sparse request")
        # Both directions are nonblocking: a stalled worker cannot hang an ACK.
        stdin, stdout = cast("BinaryIO", self.process.stdin), cast("BinaryIO", self.process.stdout)
        os.set_blocking(stdin.fileno(), False)
        os.set_blocking(stdout.fileno(), False)
        sent = 0
        with selectors.DefaultSelector() as selector:
            selector.register(stdin, selectors.EVENT_WRITE)
            selector.register(stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "Sparse processing deadline reached")
                for key, _ in selector.select(min(remaining, 0.1)):
                    if key.fileobj is stdin:
                        try:
                            count = os.write(stdin.fileno(), data[sent:])
                        except BlockingIOError:
                            continue
                        sent += count
                        if sent == len(data):
                            selector.unregister(stdin)
                    else:
                        try:
                            chunk = os.read(stdout.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        require(bool(chunk), "Sparse worker exited before verification")
                        self.buffer += chunk
                        require(len(self.buffer) <= MAX_MESSAGE, "Unbounded sparse response")
        require(sent == len(data), "Sparse reply preceded complete request")
        line, self.buffer = self.buffer.split(b"\n", 1)
        require(not self.buffer, "Unexpected extra sparse response")
        response = load_json(line)
        require(
            response.get("ok") is True, "Sparse evidence rejected: " + str(response.get("error"))
        )
        require(time.monotonic() < deadline, "Sparse processing deadline reached")
        return cast("dict[str, Any]", response["value"])

    def close(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)
        self.process.wait()
        cast("BinaryIO", self.process.stdin).close()
        cast("BinaryIO", self.process.stdout).close()


PROOF_NAME = "sparse-prefixes.jsonl"


class RuntimeStream(CandidateStream):
    def attach(self, worker: Worker, journal: BinaryIO) -> None:
        self.worker, self.journal = worker, journal
        self.effective: list[dict[str, Any]] = []

    def observe(self, line: bytes) -> None:
        # Keep the base admission history even if verification subsequently fails.
        super().observe(line)
        started = time.monotonic()
        require(self.deadline is not None, "Missing case deadline for sparse verification")
        assert self.deadline is not None
        limit = min(self.deadline, started + LOOK_SECONDS)
        proof = self.worker.exchange({"row": load_json(line)}, limit)
        require(proof["history"]["original"] == self.decisions[-1], "Worker/base decision mismatch")
        receipt = {
            "proof": proof,
            "runtime": {
                "seconds": time.monotonic() - started,
                "remaining_case_seconds": self.deadline - started,
                "address_space_ceiling": WORKER_ADDRESS_SPACE_BYTES,
            },
        }
        self.journal.write(canonical(receipt) + b"\n")
        self.journal.flush()
        require(time.monotonic() < limit, "Sparse evidence write exceeded deadline")
        self.effective.append(proof["history"]["effective"])

    def finish(self, code: int) -> None:
        super().finish(code)
        require(self.deadline is not None, "Missing completion deadline")
        assert self.deadline is not None
        self.worker.exchange({"finish": True}, min(self.deadline, time.monotonic() + LOOK_SECONDS))


def replay_runtime(
    output: Path, bindings: dict[str, Any], profile: str, observations: dict[str, Any]
) -> list[dict[str, Any]]:
    """Authenticate every effective decision against raw prefixes, never the receipt alone."""
    if profile != "pr":
        result: list[dict[str, Any]] = []
        for name, binding in bindings.items():
            admission = CandidateAdmission(name, profile, binding=binding)
            result.extend(admission.admit(row) for row in observations[name])
        return result
    result, originals = [], []
    with (output / PROOF_NAME).open("rb") as journal, Path(os.devnull).open("wb") as errors:
        worker = Worker(output / "native.timing", bindings, errors)
        try:
            for name in bindings:
                for row in observations[name]:
                    line = journal.readline(MAX_MESSAGE + 1)
                    require(
                        bool(line) and len(line) <= MAX_MESSAGE,
                        "Missing or unbounded sparse receipt",
                    )
                    receipt = load_json(line)
                    require(set(receipt) == {"proof", "runtime"}, "Invalid sparse receipt")
                    actual = worker.exchange({"row": row}, time.monotonic() + LOOK_SECONDS)
                    require(
                        receipt["proof"] == actual, "Sparse prefix proof differs from raw replay"
                    )
                    timing = receipt["runtime"]
                    require(
                        set(timing)
                        == {"seconds", "remaining_case_seconds", "address_space_ceiling"},
                        "Invalid sparse resource receipt",
                    )
                    require(
                        0
                        <= timing["seconds"]
                        < min(LOOK_SECONDS, timing["remaining_case_seconds"]),
                        "Sparse look exceeded resource budget",
                    )
                    require(
                        timing["address_space_ceiling"] == WORKER_ADDRESS_SPACE_BYTES,
                        "Wrong sparse memory ceiling",
                    )
                    result.append(actual["history"]["effective"])
                    originals.append(actual["history"]["original"])
            require(not journal.read(1), "Trailing sparse receipts")
            worker.exchange({"finish": True}, time.monotonic() + LOOK_SECONDS)
        finally:
            worker.close()
    require(
        load_json((output / "decisions.json").read_bytes()) == originals,
        "Base decisions differ from raw replay",
    )
    require(
        load_json((output / "effective-decisions.json").read_bytes()) == result,
        "Effective decisions differ from raw replay",
    )
    return result


def serve(path: str) -> None:
    ceiling = WORKER_ADDRESS_SPACE_BYTES
    resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
    reader = None
    try:
        first = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
        require(len(first) <= MAX_MESSAGE, "Unbounded worker configuration")
        configuration = load_json(first)
        order, bindings = configuration["case_order"], configuration["bindings"]
        require(
            len(order) == len(bindings) and set(order) == set(bindings), "Invalid worker case order"
        )
        reader = PrefixReader(Path(path), {name: bindings[name] for name in order}, "pr")
        print(json.dumps({"ok": True, "value": {"address_space_ceiling": ceiling}}), flush=True)
        while True:
            line = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
            require(bool(line) and len(line) <= MAX_MESSAGE, "Missing or unbounded worker request")
            request = load_json(line)
            final = request.get("finish") is True
            value = reader.finish() if final else reader.push(request["row"])
            print(
                json.dumps({"ok": True, "value": value}, allow_nan=False, separators=(",", ":")),
                flush=True,
            )
            if final:
                break
    except (OSError, ValueError, MemoryError) as error:
        print(
            json.dumps({"ok": False, "error": type(error).__name__ + ": " + str(error)}), flush=True
        )
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    require(len(sys.argv) == 3 and sys.argv[1] == "--worker", "Explicit worker invocation required")
    serve(sys.argv[2])
