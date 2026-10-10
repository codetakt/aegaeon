"""Isolated native command execution and retained command evidence."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from infrastructure_support.common import COMMAND_TIMEOUT, require


def isolated_environment(work: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "TF_", "TOFU_"))}
    empty = work / "empty-aws-config"
    empty.write_text("")
    config = work / "tofurc"
    config.write_text("provider_installation { direct {} }\n")
    env.update(
        {
            "TF_CLI_CONFIG_FILE": str(config),
            "TF_DATA_DIR": str(work / "tf-data"),
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "AWS_SHARED_CREDENTIALS_FILE": str(empty),
            "AWS_CONFIG_FILE": str(empty),
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return env


class Commands:
    def __init__(self, output: Path, env: dict[str, str]) -> None:
        self.output = output
        self.env = env
        self.records: list[dict[str, Any]] = []

    def run(self, argv: list[str], cwd: Path, stdin: str | None = None) -> str:
        label = f"{len(self.records):02d}-{Path(argv[0]).name}-{argv[1]}"
        started = time.monotonic()
        record: dict[str, Any] = {
            "argv": argv,
            "cwd": str(cwd),
            "stdout": label + ".stdout",
            "stderr": label + ".stderr",
        }
        self.records.append(record)
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=self.env,
                input=stdin,
                text=True,
                capture_output=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
            )
            record.update(exit=result.returncode, seconds=time.monotonic() - started)
            (self.output / record["stdout"]).write_text(result.stdout)
            (self.output / record["stderr"]).write_text(result.stderr)
            require(
                result.returncode == 0,
                f"Command failed ({result.returncode}): {argv}; see {self.output}",
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(error=str(error), seconds=time.monotonic() - started)
            if isinstance(error, subprocess.TimeoutExpired):
                (self.output / record["stdout"]).write_bytes(error.stdout or b"")
                (self.output / record["stderr"]).write_bytes(error.stderr or b"")
            raise
        else:
            return result.stdout
        finally:
            (self.output / "commands.json").write_text(json.dumps(self.records, indent=2) + "\n")
