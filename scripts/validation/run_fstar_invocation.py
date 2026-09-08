"""Run one F* invocation, preserving its inputs, output and unsuccessful status.

These records describe tool executions, not proof adequacy or release assurance.
Dependency snapshots record the available context, not the effective import graph.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = (".fst", ".fsti", ".hints", ".checked")
PROVIDERS = (
    "HACL_FSTAR_PATH",
    "KRMLLIB_PATH",
    "STEEL_PATH",
    "EVERPARSE_FSTAR_PATH",
    "EVERPARSE_PRELUDE_PATH",
    "EVERPARSE_LOWPARSER_PATH",
)


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def file_identity(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": digest(path)}


def command_context(command: list[str]) -> dict[str, Any]:
    tool = shutil.which(command[0])
    if tool is None:
        raise FileNotFoundError(f"Required verifier not found: {command[0]}")
    tool_path = Path(tool).absolute()
    includes = []
    for index, value in enumerate(command):
        if value == "--include":
            if index + 1 >= len(command):
                # Record a malformed request as a failed invocation, not a crash.
                raise ValueError("--include requires a directory argument")
            includes.append(command[index + 1])
    modules = [value for value in command[1:] if value.endswith((".fst", ".fsti"))]
    if not modules:
        raise ValueError("F* invocation must name at least one source")
    # Local sources, interfaces, hints and caches may affect dependency resolution.
    # External immutable Nix paths identify the provider bytes; non-Nix callers
    # must separately retain their provider trees. Neither is an assumption audit.
    local_roots = (Path.cwd(), Path("../generated/everparse"), Path("../tests/fstar"))
    local_files = sorted(
        {
            path.resolve()
            for root in local_roots
            if root.is_dir()
            for path in root.rglob("*")
            if path.is_file() and path.name.endswith(SOURCE_SUFFIXES)
        }
    )
    return {
        "argv": command,
        "executed_argv": [str(tool_path), *command[1:]],
        "cwd": str(Path.cwd()),
        "recorder": file_identity(Path(__file__).resolve()),
        "tool": file_identity(tool_path),
        "solver": file_identity(Path(solver).resolve()) if (solver := shutil.which("z3")) else None,
        "modules": [file_identity(Path(module)) for module in modules],
        "include_paths": includes,
        "providers": {name: os.environ.get(name) for name in PROVIDERS},
        "local_context": [file_identity(path) for path in local_files],
        "loops_origin": os.environ.get("FSTAR_LOOPS_ORIGIN", "not-specified"),
    }


def emit(log: Path, event: dict[str, Any]) -> None:
    line = "FSTAR-EVIDENCE " + json.dumps(event, separators=(",", ":")) + "\n"
    with log.open("a") as output:
        output.write(line)
    sys.stdout.write(line)
    sys.stdout.flush()


def stream_command(command: list[str], output: Path, combined: Path) -> int:
    # No shell, negated status, pipeline status or textual-success heuristic.
    with output.open("wb") as raw, combined.open("ab") as log:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
            assert child.stdout is not None
            try:
                while chunk := os.read(child.stdout.fileno(), 65536):
                    raw.write(chunk)
                    log.write(chunk)
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
            except BaseException:
                child.kill()
                raise
            return child.wait()


def emit_context(log: Path, pass_id: str, context: dict[str, Any], sha256: str) -> None:
    # One source per line avoids hosted log truncation of large JSON records.
    header = {
        key: value for key, value in context.items() if key not in ("modules", "local_context")
    }
    emit(log, {"event": "start", "pass_id": pass_id, "inputs_sha256": sha256, "inputs": header})
    for field in ("modules", "local_context"):
        for index, source in enumerate(context[field]):
            emit(log, {"event": field, "pass_id": pass_id, "index": index, "source": source})


def run(output: Path, pass_id: str, command: list[str]) -> int:
    # Reusing a pass directory could make old successful evidence look current.
    directory = output / "invocations" / pass_id
    directory.mkdir(parents=True, exist_ok=False)
    result_path = directory / "result.json"
    log = output / "verify.log"
    result: dict[str, Any] = {
        "schema_version": 1,
        "pass_id": pass_id,
        "argv": command,
        "cwd": str(Path.cwd()),
        "status": "incomplete",
        "returncode": None,
    }
    write_json(result_path, result)
    try:
        emit(log, {"event": "request", **result})
        context = command_context(command)
        write_json(directory / "inputs.json", context)
        # Emit the input record as well as saving it: failed Nix builds do not
        # provide an output store path. Hosted build logs retain this context.
        emit_context(log, pass_id, context, digest(directory / "inputs.json"))
        # Execute the file we recorded. Repeating PATH search can fall through
        # to a different verifier when the first one's interpreter is missing.
        returncode = stream_command(context["executed_argv"], directory / "output.log", log)
        result.update(
            returncode=returncode,
            status="succeeded" if returncode == 0 else "failed",
            inputs_sha256=digest(directory / "inputs.json"),
            output_sha256=digest(directory / "output.log"),
        )
        emit(log, {"event": "finish", **result})
        write_json(result_path, result)
        return returncode if returncode >= 0 else 128 - returncode
    except (OSError, ValueError) as error:
        result.update(status="failed", error=str(error))
        write_json(result_path, result)
        try:
            emit(log, {"event": "finish", **result})
        except OSError as log_error:
            print(f"[FAIL] Cannot emit F* failure record: {log_error}", file=sys.stderr)
        print(f"[FAIL] F* {pass_id}: {error}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--pass-id", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command: list[str] = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not args.pass_id.replace("-", "").isalnum():
        parser.error("An argv and an alphanumeric/hyphen pass ID are required")
    try:
        return run(args.out_dir.resolve(), args.pass_id, command)
    except OSError as error:
        print(f"[FAIL] Cannot record F* invocation: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
