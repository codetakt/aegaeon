"""Explicit selected tools and supplier; each authority check stays fresh."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from .io import fail

if TYPE_CHECKING:
    import pathlib


class Supplier(Protocol):
    git: str

    def validate(self) -> tuple[bytes, dict[str, Any], dict[str, Any]]: ...
    def input_paths(self) -> tuple[pathlib.Path, ...]: ...
    def check_files(self, files: dict[str, Any]) -> None: ...
    def admit(self, root: pathlib.Path) -> None: ...
    def validate_urls(self, target: str, issuer: str | None) -> None: ...
    def bind_workload(self, evidence: pathlib.Path, source_sha256: str) -> str: ...
    def verify_workload(
        self, evidence: pathlib.Path, source_sha256: str, binding: dict[str, Any]
    ) -> pathlib.Path: ...


def environment() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
    )
    return env


@dataclass(frozen=True, slots=True)
class Dependencies:
    git: str
    supplier: Supplier | None = None

    def command(
        self,
        root: pathlib.Path,
        *args: str,
        env: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> bytes:
        git = self.git
        result = subprocess.run(  # noqa: S603 - fixed Git plumbing, no shell execution
            [
                git,
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-C",
                str(root),
                *args,
            ],
            input=data,
            capture_output=True,
            env=env or environment(),
            check=False,
        )
        if result.returncode:
            fail("Git source inspection failed")
        return result.stdout


def select(*, supplier: Supplier | None = None, git: str | None = None) -> Dependencies:
    selected = git or (supplier.git if supplier is not None else shutil.which("git"))
    if selected is None:
        fail("Git executable is unavailable")
    return Dependencies(selected, supplier)
