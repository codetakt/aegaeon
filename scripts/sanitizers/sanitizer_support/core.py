"""Shared sanitizer settings, failure statuses and strict JSON primitives."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from pathlib import Path


class Failure(Exception):  # noqa: N818 - retained failure/status interface
    def __init__(self, message: str, status: int = 1) -> None:
        super().__init__(message)
        self.status = status if status > 0 else 128 - status


class Interrupted(Failure):
    """Keep the supervisor's signal separate from child cleanup failures."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"Sanitizer supervisor interrupted by signal {signum}", 128 + signum)


def failure(message: str, status: int = 1) -> NoReturn:
    raise Failure(message, status)


def require(condition: object, message: str, status: int = 1) -> None:
    if not condition:
        failure(message, status)


def duration(value: str) -> float:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", value)
    require(match is not None, f"Invalid sanitizer deadline: {value!r}")
    seconds = float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    require(
        math.isfinite(seconds) and seconds > 0, "Sanitizer deadlines must be positive and finite"
    )
    return seconds


def selection(value: str, label: str) -> list[str]:
    values = value.replace(",", " ").split()
    require(values and len(values) == len(set(values)), f"Empty or duplicate {label} selection")
    require(
        all(re.fullmatch(r"[A-Za-z0-9_-]+", item) for item in values), f"Invalid {label} selection"
    )
    return values


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text: str) -> dict[str, Any]:
    return json.loads(text, object_pairs_hook=unique_object)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass(frozen=True)
class Settings:
    sanitizer_text: str
    package_text: str
    target_text: str
    artifact_text: str
    cargo: str
    host: str
    base_flags: str
    curve_flags: str
    extra_text: str
    build_extra_text: str
    build_limit_text: str
    run_limit_text: str
    grace_text: str
    runtime_text: str
    link_order: str
    preload: str


def asan_options(link_order: str) -> str:
    return (
        "abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:"
        f"verify_asan_link_order={link_order}:verbosity=0"
    )
