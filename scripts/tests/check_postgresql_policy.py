"""Evaluate the actual staging minor-upgrade expression with OpenTofu."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def check(resource: Path, variables: Path) -> None:
    tofu = shutil.which("tofu")
    if tofu is None:
        message = "OpenTofu is required to evaluate the PostgreSQL upgrade policy"
        raise ValueError(message)
    expression = re.search(r"(?m)^\s*auto_minor_version_upgrade\s*=\s*(.+)$", resource.read_text())
    variable = re.search(r'(?ms)^variable "db_engine_version" \{\n.*?^\}', variables.read_text())
    if expression is None or variable is None:
        message = "PostgreSQL upgrade policy is missing"
        raise ValueError(message)
    with tempfile.TemporaryDirectory(prefix="aegaeon-postgresql-policy-") as directory:
        root = Path(directory)
        (root / "main.tf").write_text(
            variable[0] + "\nlocals { automatic_minor = " + expression[1] + " }\n"
        )
        for version, expected in (
            ("18.6", "false"),
            ("16", "true"),
            ("16.11", "false"),
            ("18", "true"),
        ):
            result = subprocess.run(  # noqa: S603 - fixed OpenTofu evaluator and fixture inputs
                [tofu, "console", "-no-color", "-var", f"db_engine_version={version}"],
                input="local.automatic_minor\n",
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            )
            if result.stdout.strip() != expected:
                message = f"PostgreSQL {version}: automatic minor upgrade must be {expected}"
                raise ValueError(message)
            print(f"PostgreSQL {version}: automatic_minor={expected}")


if __name__ == "__main__":
    check(Path(sys.argv[1]), Path(sys.argv[2]))
