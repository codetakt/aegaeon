# The measured checkpoint remains in the source archive; this is a runtime correction.
# ruff: noqa: I002
"""Absolute acquisition cutoff, checked before allowing the next native case."""

import contextlib
import math
import time

import analysis_runtime
from dudect_support import require

BaseStream = analysis_runtime.Stream


class Stream(BaseStream):
    def __init__(self, *args, absolute_deadline, **kwargs):
        require(
            math.isfinite(absolute_deadline) and time.monotonic() + 900 <= absolute_deadline,
            "Insufficient remaining budget for executable",
        )
        super().__init__(*args, **kwargs)
        self.absolute_deadline = absolute_deadline

    def observe(self, line):
        require(self.deadline is not None, "Missing case deadline")
        self.deadline = min(self.deadline, self.absolute_deadline)
        previous = self.index
        super().observe(line)
        require(time.monotonic() < self.absolute_deadline, "Acquisition cutoff before ACK")
        if previous < self.index < len(self.cases):
            # Native waits for this final-look ACK before starting the next case.
            require(
                time.monotonic() + 900 <= self.absolute_deadline,
                "Insufficient remaining budget for next case; ACK withheld",
            )


@contextlib.contextmanager
def installed(cutoff):
    require(
        math.isfinite(cutoff) and time.monotonic() + 900 <= cutoff,
        "Insufficient initial case budget",
    )

    class CutoffStream(Stream):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, absolute_deadline=cutoff, **kwargs)

    old = analysis_runtime.Stream
    analysis_runtime.Stream = CutoffStream
    try:
        yield
    finally:
        analysis_runtime.Stream = old
