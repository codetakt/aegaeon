"""Use the actual observed Nix command inside the actual namespace wrapper."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from build_observations import run_observed  # noqa: E402 - exact repository observer.
from namespace_lifecycle import identity  # noqa: E402 - sibling owned identity helper.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, type=Path)
    args = parser.parse_args()
    directory = Path(os.environ["AEGAEON_PROCESS_CLEANUP_RECEIPTS"])
    owner = json.loads((directory / "owner.json").read_text())
    with (args.case / "work-ready.json").open("x") as stream:
        json.dump(
            {"directory": str(directory), "owner": owner, "identity": identity(os.getpid())}, stream
        )
        stream.flush()
        os.fsync(stream.fileno())
    command = json.loads((args.case / "command.json").read_text())
    run_observed(command, args.case / "build-trace.jsonl")


if __name__ == "__main__":
    main()
