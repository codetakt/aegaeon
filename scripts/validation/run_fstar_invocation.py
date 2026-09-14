"""Run one F* invocation, preserving its inputs, output and unsuccessful status.

These records describe tool executions, not proof adequacy or release assurance.
Dependency snapshots record the available context, not the effective import graph.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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


def requested_solver(command: list[str]) -> dict[str, str] | None:
    """Record the explicit solver, never the recorder's unrelated PATH default."""
    indices = [index for index, value in enumerate(command) if value == "--smt"]
    if any(value.startswith("--smt=") for value in command):
        raise ValueError("Use --smt followed by one absolute executable path")
    if not indices:
        return None
    if len(indices) != 1 or indices[0] + 1 >= len(command):
        raise ValueError("Exactly one --smt executable is required")
    path = Path(command[indices[0] + 1])
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("--smt requires an absolute executable file")
    return file_identity(path.resolve())


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
    # Mutable include/provider trees require the same before-invocation digests.
    # Immutable Nix inputs remain within the separately registered store trust.
    external_roots = [Path(value) for value in includes]
    external_roots.extend(Path(os.environ[name]) for name in PROVIDERS if os.environ.get(name))
    external_roots.append(tool_path.parent.parent / "lib" / "fstar")
    local_roots = (
        Path.cwd(),
        Path("../generated/everparse"),
        Path("../tests/fstar"),
        *(path for path in external_roots if not path.resolve().is_relative_to("/nix/store")),
    )
    local_files = sorted(
        {
            path.resolve()
            for root in local_roots
            if root.is_dir()
            for path in root.rglob("*")
            if path.is_file() and path.name.endswith(SOURCE_SUFFIXES)
        }
    )
    # Keep the spelling F* searches as well as the broad canonical context.
    # This anchors unrequested results even for immutable providers and permits
    # replay after include-directory or source-file symlinks have disappeared.
    dependency_files = sorted(
        {
            path.absolute()
            for directory in (Path.cwd(), *(Path(value) for value in includes))
            if directory.is_dir()
            for path in directory.iterdir()
            if path.is_file() and path.suffix in (".fst", ".fsti")
        }
    )
    return {
        "argv": command,
        "executed_argv": [str(tool_path), *command[1:]],
        "cwd": str(Path.cwd()),
        "recorder": file_identity(Path(__file__).resolve()),
        "tool": file_identity(tool_path),
        "solver": requested_solver(command),
        "modules": [file_identity(Path(module)) for module in modules],
        "include_paths": includes,
        "providers": {name: os.environ.get(name) for name in PROVIDERS},
        "local_context": [file_identity(path) for path in local_files],
        "dependency_context": [file_identity(path) for path in dependency_files],
        "loops_origin": os.environ.get("FSTAR_LOOPS_ORIGIN", "not-specified"),
    }


# Pinned F* starts Z3 with exactly these two arguments, in this order.
# Unsupported flags cannot inherit the approved executable's identity.
Z3PROC = re.compile(
    r'Creating new z3proc \(cmd=\[\("([^"\\\r\n]+)", '
    r'\["-smt2", "-in"\]\)\], version=\["([^"\\\r\n]+)"\]\)'
)
PATH_PREPEND = re.compile(r"^PATH='([^']+)'\$PATH\s*$")


def effective_solver(output: Path, tool_path: Path) -> dict[str, Any]:
    """Resolve every solver start; mixed or malformed restart evidence is rejected."""
    output_text = output.read_text(errors="replace")
    matches = [match for line in output_text.splitlines() if (match := Z3PROC.fullmatch(line))]
    if output_text.count("Creating new z3proc") != len(matches):
        raise ValueError("malformed solver process record")
    if not matches:
        return {"observed": False, "name": None, "version": None, "path": None, "sha256": None}
    identities = [_solver_process(match.group(1), match.group(2), tool_path) for match in matches]
    first = identities[0]

    # Names may be aliases of the same executable, but both observed version and
    # resolved bytes must agree. Unknown paths cannot conceal a different name.
    def identity(value: dict[str, Any]) -> tuple[Any, ...]:
        return (value["path"] or value["name"], value["sha256"], value["version"])

    if any(identity(value) != identity(first) for value in identities[1:]):
        raise ValueError("mixed solver process identities in one invocation")
    return {
        **first,
        "arguments": ["-smt2", "-in"],
        "process_count": len(identities),
        "processes": identities,
    }


def _solver_process(name: str, version: str, tool_path: Path) -> dict[str, Any]:
    directories: list[str] = []
    try:
        for line in tool_path.read_text(errors="replace").splitlines():
            if prepend := PATH_PREPEND.match(line):
                directories.append(prepend.group(1))
    except (OSError, UnicodeError):
        pass
    directories.extend(os.environ.get("PATH", "").split(os.pathsep))
    for directory in directories:
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return {
                "observed": True,
                "name": name,
                "version": version,
                "path": str(candidate.resolve()),
                "sha256": digest(candidate),
            }
    return {"observed": True, "name": name, "version": version, "path": None, "sha256": None}


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
        key: value
        for key, value in context.items()
        if key not in ("modules", "local_context", "dependency_context")
    }
    emit(log, {"event": "start", "pass_id": pass_id, "inputs_sha256": sha256, "inputs": header})
    for field in ("modules", "local_context", "dependency_context"):
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
        result["solver_effective"] = effective_solver(
            directory / "output.log", Path(context["executed_argv"][0])
        )
        observed = result["solver_effective"]
        expected = context["solver"]
        if expected and not observed["observed"]:
            raise ValueError("explicit solver pin requires an observed solver process")
        if (
            expected
            and observed["observed"]
            and any(expected[key] != observed[key] for key in ("path", "sha256"))
        ):
            raise ValueError("observed solver process does not match the explicit pin")
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
