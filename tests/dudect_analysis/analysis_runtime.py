# The authenticated source bundle must be selected before native helper imports.
# ruff: noqa: E402
"""One bounded worker authenticates old prefixes and computes the active research gate."""

from __future__ import annotations

import itertools
import json
import os
import resource
import subprocess
import sys
import time
from array import array
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source" if (HERE / "source").is_dir() else HERE.parents[1]
sys.path.insert(0, str(SOURCE / "tests/constant_time"))
import dudect_sparse_runtime as original_runtime
from analysis_contract import WORKER_ENVIRONMENT, History, identity, interval_test
from distributed import Partition
from dudect_candidate import SPARSE_RUNTIME, CandidateStream, canonical, digest
from dudect_process import load_json
from dudect_sparse_replay import Prefix
from dudect_sparse_runtime import MAX_MESSAGE, PrefixReader, Worker as BaseWorker
from dudect_support import require
from sparse_four import augment as augment_four

JOURNAL = "analysis-prefixes.jsonl"
CONFIG = "analysis-binding.json"


class CompactPrefix(Prefix):
    """Same counts/index operations, uint64 storage for bounded PR counts."""

    def indexed(self):
        if self.sorted_support is None:
            self.sorted_support = []
            for histogram in self.histograms:
                values = sorted(histogram)
                counts = array("Q", itertools.accumulate(histogram[t] for t in values))
                self.sorted_support.append((values, counts))
        return self.sorted_support


class Reader(PrefixReader):
    def __init__(self, path, bindings, analysis):
        super().__init__(path, bindings, "pr")
        self.analysis = analysis
        self.partition = Partition(analysis["packet"], analysis["unit"])
        self.histories = {n: History() for n in bindings}

    def read(self, size):
        data = super().read(size)
        if (
            self.analysis["mode"] == "distributed"
            and self.index < len(self.names)
            and self.names[self.index] == "hmac_sha256"
            and self.prefix is not None
            and size == 65536 * 41
        ):
            self.partition.push(data, self.prefix.batch + 1)
        return data

    def push(self, row, deadline=None):
        # The inherited reader lacks a prefix factory. Inject only during this
        # single-threaded transaction; leave original module/source unchanged.
        factory = original_runtime.Prefix
        captured = [self.prefix]

        def create_prefix():
            captured[0] = CompactPrefix()
            return captured[0]

        original_runtime.Prefix = create_prefix
        try:
            original = super().push(row)
        finally:
            original_runtime.Prefix = factory
        base = original["history"]["effective"]
        replacement = (
            self.analysis["mode"] == "distributed"
            and row["binding"]["case_id"] == "nix/hmac_sha256"
        )
        require(captured[0] is not None, "Missing authenticated prefix")
        tests, four = augment_four(
            row, base["tests"], captured[0], excluded=range(1, 101) if replacement else ()
        )
        distributed = None
        if replacement:
            distributed = self.partition.evaluate(row, original)
            tests[1:101] = distributed["tests"]
        tests = [interval_test(test, deadline) for test in tests]
        effective = self.histories[row["case"]].append(row, base, tests)
        return {
            "schema": "dudect-analysis-prefix/2",
            "analysis_sha256": digest(canonical(self.analysis)),
            "original_sparse_proof": original,
            "four_exception_supplements": four,
            "distributed": distributed,
            "effective": effective,
        }


class Worker(BaseWorker):
    def __init__(self, path, bindings, errors, *, analysis):
        self.buffer = b""
        self.analysis = analysis
        self.analysis_journal = None
        self.process = subprocess.Popen(  # noqa: S603 -- fixed interpreter and bound worker
            [sys.executable, "-B", "-u", str(HERE / "analysis_runtime.py"), "--worker", str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            start_new_session=True,
            env=os.environ | WORKER_ENVIRONMENT,
        )
        try:
            BaseWorker.exchange(
                self,
                {"bindings": bindings, "case_order": list(bindings), "analysis": analysis},
                time.monotonic() + 10,
            )
        except BaseException:
            self.close()
            raise

    def exchange(self, request, deadline):
        value = BaseWorker.exchange(self, {**request, "deadline": deadline}, deadline)
        if "row" in request:
            require(
                value["analysis_sha256"] == digest(canonical(self.analysis)),
                "Analysis binding mismatch",
            )
            require(
                value["original_sparse_proof"]["row_sha256"] == digest(canonical(request["row"])),
                "Wrong analysis row",
            )
        return value

    def close(self):
        try:
            super().close()
        finally:
            if self.analysis_journal is not None:
                self.analysis_journal.close()


class Stream(CandidateStream):
    def attach(self, worker, journal):
        self.worker, self.journal = worker, journal
        self.effective = []
        self.analysis_journal = (Path(journal.name).parent / JOURNAL).open("xb")
        worker.analysis_journal = self.analysis_journal
        (Path(journal.name).parent / CONFIG).write_bytes(canonical(worker.analysis) + b"\n")

    def observe(self, line):
        started = time.monotonic()
        super().observe(line)
        require(self.deadline is not None, "Missing case deadline")
        limit = min(self.deadline, started + SPARSE_RUNTIME["look_seconds"])
        proof = self.worker.exchange({"row": load_json(line)}, limit)
        original = proof["original_sparse_proof"]
        require(
            original["history"]["original"] == self.decisions[-1], "Worker/base original mismatch"
        )
        runtime = {
            "seconds": time.monotonic() - started,
            "remaining_case_seconds": self.deadline - started,
            "address_space_ceiling": SPARSE_RUNTIME["worker_address_space_bytes"],
        }
        for journal, value in ((self.journal, original), (self.analysis_journal, proof)):
            encoded = canonical({"proof": value, "runtime": runtime}) + b"\n"
            require(len(encoded) <= MAX_MESSAGE, "Unbounded analysis receipt")
            require(journal.write(encoded) == len(encoded), "Short evidence write")
            journal.flush()
        require(time.monotonic() < limit, "Evidence save exceeded shared deadline")
        self.effective.append(proof["effective"])

    def finish(self, code):
        super().finish(code)
        self.worker.exchange({"finish": True}, min(self.deadline, time.monotonic() + 10))
        self.analysis_journal.close()


def replay(output, bindings, observations, analysis):
    result = []
    originals = []
    require(load_json((output / CONFIG).read_bytes()) == analysis, "Wrong analysis configuration")
    with Path("/dev/null").open("wb") as errors:
        worker = Worker(output / "native.timing", bindings, errors, analysis=analysis)
        try:
            with (
                (output / JOURNAL).open("rb") as journal,
                (output / "sparse-prefixes.jsonl").open("rb") as old,
            ):
                for name in bindings:
                    for row in observations[name]:
                        record = load_json(journal.readline(MAX_MESSAGE + 1))
                        original_record = load_json(old.readline(MAX_MESSAGE + 1))
                        actual = worker.exchange(
                            {"row": row}, time.monotonic() + SPARSE_RUNTIME["look_seconds"]
                        )
                        require(
                            record["proof"] == actual, "Analysis receipt differs from raw replay"
                        )
                        require(
                            original_record["proof"] == actual["original_sparse_proof"],
                            "Original proof changed",
                        )
                        for entry in (record, original_record):
                            t = entry["runtime"]
                            require(
                                0 <= t["seconds"] < min(10, t["remaining_case_seconds"])
                                and t["address_space_ceiling"]
                                == SPARSE_RUNTIME["worker_address_space_bytes"],
                                "Invalid resource receipt",
                            )
                        result.append(actual["effective"])
                        originals.append(actual["original_sparse_proof"]["history"]["original"])
                require(not journal.read(1) and not old.read(1), "Trailing evidence")
            worker.exchange({"finish": True}, time.monotonic() + SPARSE_RUNTIME["look_seconds"])
        finally:
            worker.close()
    require(
        load_json((output / "effective-decisions.json").read_bytes()) == result,
        "Effective decisions changed",
    )
    require(
        load_json((output / "decisions.json").read_bytes()) == originals,
        "Original decisions changed",
    )
    return result


def serve(path):
    ceiling = SPARSE_RUNTIME["worker_address_space_bytes"]
    resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
    reader = None
    try:
        require(
            all(os.environ.get(k) == v for k, v in WORKER_ENVIRONMENT.items()),
            "Unbound worker locale/encoding environment",
        )
        config = load_json(sys.stdin.buffer.readline(MAX_MESSAGE + 1))
        a = config["analysis"]
        require(
            a == identity(a["mode"], a["packet"], a["unit"]),
            "Wrong implementation/dependency binding",
        )
        bindings, order = config["bindings"], config["case_order"]
        require(len(order) == len(bindings) and set(order) == set(bindings), "Wrong case order")
        reader = Reader(Path(path), {n: bindings[n] for n in order}, a)
        print(json.dumps({"ok": True, "value": {"address_space_ceiling": ceiling}}), flush=True)
        while True:
            data = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
            require(data and len(data) <= MAX_MESSAGE, "Missing or unbounded request")
            request = load_json(data)
            final = request.get("finish") is True
            value = reader.finish() if final else reader.push(request["row"], request["deadline"])
            data = canonical({"ok": True, "value": value})
            require(len(data) < MAX_MESSAGE, "Unbounded reply")
            sys.stdout.buffer.write(data + b"\n")
            sys.stdout.buffer.flush()
            if final:
                break
    except (OSError, ValueError, MemoryError, KeyError) as e:
        print(json.dumps({"ok": False, "error": type(e).__name__ + ": " + str(e)}), flush=True)
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    require(len(sys.argv) == 3 and sys.argv[1] == "--worker", "Explicit worker invocation required")
    serve(sys.argv[2])
