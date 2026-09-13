"""Admit F* results per requested module, not per process exit status.

The pinned F* prints ``Verified module: <name>`` for every implementation it
processes, including ones that reported errors and ones reused from ``.checked``
files, so that line alone proves nothing. A module is admitted only when the
invocation exited 0 without any reported error, printed the completion marker,
and printed exactly one result line for each requested source. The records
written here bind that decision to the invocation's input and output digests.
They describe tool executions; they do not establish assumption soundness,
model adequacy, implementation refinement or release assurance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fstar_source_lexing import SourceLexingError, lexical_views
from run_fstar_invocation import Z3PROC

CONTRACT = "fstar-2025.10.06-text-v1"
SCHEMA_VERSION = 1
REQUIRED_PASSES = ("1", "1b", "2a-1", "2a-2", "2b")
# Options that would make a result line meaningless as fresh-check evidence.
DENIED_OPTIONS = frozenset(
    {
        "--already_cached",
        "--cache_dir",
        "--cache_checked_modules",
        "--lax",
        "--admit_smt_queries",
        "--admit_except",
        "--silent",
    }
)
MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
MODULE_DECLARATION = re.compile(r"^module\s+[A-Za-z_][A-Za-z0-9_.]*\s*$")
VERIFIED_IMPLEMENTATION = re.compile(r"^Verified module: (\S+)$")
VERIFIED_INTERFACE = re.compile(r"^Verified i'face \(or impl\+i'face\): (\S+)$")
ERROR_LINE = re.compile(r"^(?:\d+, )?\* Error \d+ at ")
ERRORS_REPORTED = re.compile(r"^\d+ errors? (?:was|were) reported")
DETAILED_ERROR = re.compile(r"^Detailed error report follows")
WARNING_LINE = re.compile(r"^\* Warning \d+ at ")
COMPLETION_MARKER = "All verification conditions discharged successfully"
TOTAL_TIME = re.compile(r"^TOTAL TIME \d+ ms: (.+)$")


class AdmissionError(ValueError):
    """A recorded, expected admission failure."""


def digest_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise AdmissionError(f"{path.name} is not a JSON object")
    return value


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    # A pre-existing record would let stale evidence pose as current.
    data = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with path.open("x") as target:
        target.write(data)


def source_views(text: str) -> tuple[str, str]:
    """Return comment-free and literal-masked views with original positions."""
    try:
        return lexical_views(text, allow_comment_eof=True)
    except SourceLexingError as exc:
        raise AdmissionError(str(exc)) from exc


def strip_comments(text: str) -> str:
    """Remove comments while preserving literals and source positions."""
    return source_views(text)[0]


def declared_module(text: str) -> str:
    """Return the single module name declared first in an F* source."""
    lines = [
        line.strip()
        for line in source_views(text)[1].splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    tokens = lines[0].split() if lines else []
    if len(tokens) < 2 or tokens[0] != "module":
        raise AdmissionError("source does not begin with a module declaration")
    name = tokens[1]
    if not MODULE_NAME.match(name):
        raise AdmissionError(f"unsupported module name {name!r}")
    # `module Alias = Full.Name` is an abbreviation, not a second declaration.
    if any(MODULE_DECLARATION.match(line) for line in lines[1:]):
        raise AdmissionError("source contains more than one module declaration")
    return name


def source_role(path: str) -> str:
    if path.endswith(".fsti"):
        return "interface"
    if path.endswith(".fst"):
        return "implementation"
    raise AdmissionError(f"unsupported source kind: {path}")


def parse_output(text: str) -> dict[str, Any]:
    """Parse the versioned text contract; unknown lines are ignored diagnostics."""
    implementations: list[tuple[str, int]] = []
    interfaces: list[tuple[str, int]] = []
    errors = 0
    warnings = 0
    completion: list[int] = []
    total_time: str | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if match := VERIFIED_IMPLEMENTATION.match(line):
            implementations.append((match[1], number))
        elif match := VERIFIED_INTERFACE.match(line):
            interfaces.append((match[1], number))
        elif ERROR_LINE.match(line) or ERRORS_REPORTED.match(line) or DETAILED_ERROR.match(line):
            errors += 1
        elif WARNING_LINE.match(line):
            warnings += 1
        elif line == COMPLETION_MARKER:
            completion.append(number)
        elif match := TOTAL_TIME.match(line):
            total_time = match[1]
    return {
        "implementations": implementations,
        "interfaces": interfaces,
        "errors": errors,
        "warnings": warnings,
        "completion": completion,
        "total_time_argv": total_time,
    }


def include_directories(inputs: dict[str, Any], source_root: Path) -> list[Path]:
    """Every directory F* may search: the include paths, relative to the source root."""
    directories: list[Path] = []
    for include in inputs.get("include_paths", []):
        directory = Path(include)
        directories.append(directory if directory.is_absolute() else source_root / directory)
    return directories


def search_directories(inputs: dict[str, Any], source_root: Path) -> list[tuple[Path, Path]]:
    """The directories F* searches for a dependency, as (recorded form, local form).

    The pinned verifier resolves a module name in the working directory and the
    ``--include`` directories only; it does not search a source's own directory
    or any subdirectory (tool probes ``search-scope``). The recorded form is
    built from the invocation's recorded working directory so that records read
    the same wherever they are replayed; the local form is read here.
    """
    cwd = Path(str(inputs["cwd"]))
    directories: list[tuple[Path, Path]] = [(cwd, source_root)]
    for include in inputs.get("include_paths", []):
        directory = Path(str(include))
        if directory.is_absolute():
            pair = (directory, directory)
        else:
            pair = (cwd / directory, source_root / directory)
        if pair not in directories:
            directories.append(pair)
    return directories


def outside_search_scope(name: str, kind: str, source: str, inputs: dict[str, Any]) -> str | None:
    """Why a recorded dependency source is not one F* could have used, or None."""
    suffix = ".fst" if kind == "implementation" else ".fsti"
    path = Path(source)
    if path.name != f"{name}{suffix}":
        return f"recorded source {source} is not {name}{suffix}"
    cwd = Path(str(inputs["cwd"]))
    searched = [cwd]
    for include in inputs.get("include_paths", []):
        directory = Path(str(include))
        searched.append(directory if directory.is_absolute() else cwd / directory)
    if path.parent not in searched:
        return f"recorded source {source} is outside the searched directories"
    return None


def resolve_unrequested(
    name: str, kind: str, inputs: dict[str, Any], source_root: Path
) -> tuple[dict[str, str] | None, str]:
    """Bind a result that was not requested to the one source F* could have used.

    The candidate must be the single ``<name>.fst`` (implementation result) or
    ``<name>.fsti`` (interface result) across the searched directories, must
    declare ``name``, and, when it lies in the recorded local context, must
    carry the recorded digest. Several candidates are ambiguous and reject the
    pass; the recorded local context is never searched by file name.
    """
    suffix = ".fst" if kind == "implementation" else ".fsti"
    found: list[tuple[Path, Path]] = []
    for recorded_dir, local_dir in search_directories(inputs, source_root):
        if (local_dir / f"{name}{suffix}").is_file():
            found.append((recorded_dir / f"{name}{suffix}", local_dir / f"{name}{suffix}"))
    if not found:
        return None, f"no {name}{suffix} in the searched directories"
    if len(found) > 1:
        return None, f"{name}{suffix} is ambiguous across {[str(r) for r, _ in found]}"
    recorded_path, local_path = found[0]
    try:
        declared = declared_module(local_path.read_text(errors="replace"))
    except (AdmissionError, OSError, UnicodeError) as error:
        return None, f"{recorded_path}: {error}"
    if declared != name:
        return None, f"{recorded_path} declares module {declared}, not {name}"
    digest = digest_file(local_path)
    identity, note = retained_dependency(name, kind, inputs)
    if identity is None:
        return None, note
    if identity != {"source": str(recorded_path), "sha256": digest}:
        return None, f"{recorded_path} differs from the recorded local context or search snapshot"
    return identity, "resolved"


def retained_dependency(
    name: str, kind: str, inputs: dict[str, Any]
) -> tuple[dict[str, str] | None, str]:
    """Resolve the unique pre-invocation identity without reading source/tool paths."""
    context = inputs.get("dependency_context", inputs.get("local_context", []))
    if not isinstance(context, list):
        return None, "recorded dependency context is not a list"
    found: dict[str, str] = {}
    for item in context:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return None, "recorded dependency context has an invalid path"
        path = item["path"]
        if outside_search_scope(name, kind, path, inputs) is not None:
            continue
        digest = item.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            return None, f"{path} has an invalid recorded dependency digest"
        if path in found and found[path] != digest:
            return None, f"{path} has conflicting recorded dependency digests"
        found[path] = digest
    if len(found) != 1:
        return None, (
            f"{name} has ambiguous recorded dependency candidates: {sorted(found)}"
            if found
            else f"{name} is not in the recorded local context or search snapshot; re-record inputs"
        )
    path, digest = next(iter(found.items()))
    return {"source": path, "sha256": digest}, "resolved from recorded inputs"


def checked_candidates(
    inputs: dict[str, Any], names: list[str], source_root: Path
) -> dict[str, Any]:
    """Scan every directory F* searches for a .checked file of a requested module."""
    directories: list[Path] = []
    for module in inputs.get("modules", []):
        directory = (source_root / str(module["path"])).parent
        if directory not in directories:
            directories.append(directory)
    for directory in include_directories(inputs, source_root):
        if directory not in directories:
            directories.append(directory)
    found: list[str] = []
    for directory in directories:
        for name in names:
            for suffix in (".fst.checked", ".fsti.checked"):
                candidate = directory / f"{name}{suffix}"
                if candidate.exists():
                    found.append(str(candidate))
    return {"directories": [str(d) for d in directories], "candidates": found}


def check_explicit_solver(inputs: dict[str, Any], result: dict[str, Any], output: str) -> None:
    """Bind retained starts to the recorded pin without requiring live tool files.

    Old unpinned records may contain an ambient solver identity. That is not an
    explicit choice and cannot satisfy this contract or establish solver identity.
    """
    argv = inputs["argv"]
    options = [i for i, arg in enumerate(argv) if arg.partition("=")[0] == "--smt"]
    if not options:
        return
    index = options[0]
    if (
        len(options) != 1
        or argv[index] != "--smt"
        or index + 1 >= len(argv)
        or not Path(argv[index + 1]).is_absolute()
    ):
        raise AdmissionError("invalid explicit solver option")
    pin = inputs.get("solver")
    if (
        not isinstance(pin, dict)
        or not isinstance(pin.get("path"), str)
        or not Path(pin["path"]).is_absolute()
        or not isinstance(pin.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is None
    ):
        raise AdmissionError("explicit solver pin is missing its recorded identity")
    starts = [match for line in output.splitlines() if (match := Z3PROC.fullmatch(line))]
    if output.count("Creating new z3proc") != len(starts) or not starts:
        raise AdmissionError("explicit solver pin requires supported observed solver starts")
    observed = result.get("solver_effective")
    if (
        not isinstance(observed, dict)
        or observed.get("observed") is not True
        or observed.get("arguments") != ["-smt2", "-in"]
        or type(observed.get("process_count")) is not int
        or observed["process_count"] != len(starts)
        or any(observed.get(key) != pin[key] for key in ("path", "sha256"))
        or observed.get("name") != starts[0].group(1)
        or observed.get("version") != starts[0].group(2)
    ):
        raise AdmissionError("observed solver summary differs from raw starts or explicit pin")
    processes = observed.get("processes")
    if "processes" not in observed:
        # Older records retain only an aggregate. Identical names are replayable;
        # multiple aliases need the per-start identities retained by new recorders.
        processes = [observed] * len(starts)
    if not isinstance(processes, list) or len(processes) != len(starts):
        raise AdmissionError("observed solver process identities are incomplete")
    for start, process in zip(starts, processes, strict=True):
        if (
            not isinstance(process, dict)
            or process.get("observed") is not True
            or process.get("name") != start.group(1)
            or process.get("version") != start.group(2)
            or process.get("version") != observed["version"]
            or any(process.get(key) != pin[key] for key in ("path", "sha256"))
        ):
            raise AdmissionError("observed solver process identity differs from raw start or pin")
    # An alias is usable only when a retained observed start binds that exact
    # spelling to the canonical pin. Never resolve replay paths on the live host.
    if argv[index + 1] not in {pin["path"], *(process["name"] for process in processes)}:
        raise AdmissionError("explicit solver operand is not bound to the pin or observed aliases")


def reconcile(
    pass_id: str,
    inputs: dict[str, Any],
    result: dict[str, Any],
    output: str,
    source_root: Path | None,
    recorded: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute the per-module record; ``recorded`` replays a modules.json without sources."""
    reasons: list[str] = []
    argv = list(inputs["argv"])
    try:
        check_explicit_solver(inputs, result, output)
    except AdmissionError as error:
        reasons.append(str(error))
    # The invocation record must be the one made for this pass, not a relabelled copy.
    if result.get("pass_id") != pass_id:
        reasons.append(f"result.json records pass {result.get('pass_id')!r}, not {pass_id!r}")
    if result.get("argv") != argv or result.get("cwd") != inputs.get("cwd"):
        reasons.append("result.json argv/cwd differ from inputs.json")
    tool = inputs.get("tool")
    if not isinstance(tool, dict) or inputs.get("executed_argv") != [
        tool.get("path"),
        *argv[1:],
    ]:
        reasons.append("executed argv differs from the recorded command or verifier identity")
    if recorded is not None and recorded.get("pass_id") != pass_id:
        reasons.append(f"modules.json records pass {recorded.get('pass_id')!r}, not {pass_id!r}")
    denied = sorted(option for option in argv if option.partition("=")[0] in DENIED_OPTIONS)
    if denied:
        reasons.append(f"denied options in argv: {' '.join(denied)}")
    if (
        result.get("status") != "succeeded"
        or type(result.get("returncode")) is not int
        or result["returncode"] != 0
    ):
        reasons.append(
            f"invocation status {result.get('status')!r} with return code "
            f"{result.get('returncode')!r}"
        )
    parsed = parse_output(output)
    if parsed["errors"]:
        reasons.append(f"{parsed['errors']} error line(s) reported by the verifier")
    if len(parsed["completion"]) != 1:
        reasons.append(f"completion marker occurs {len(parsed['completion'])} time(s)")
    expected_echo = " ".join(inputs["executed_argv"])
    if "--query_stats" in argv and parsed["total_time_argv"] != expected_echo:
        reasons.append("TOTAL TIME line does not echo the executed argv")

    requested: list[dict[str, Any]] = []
    names: dict[str, list[int]] = {}
    for index, module in enumerate(inputs["modules"]):
        path = str(module["path"])
        entry: dict[str, Any] = {
            "path": path,
            "sha256": module["sha256"],
            "role": source_role(path),
            "module": None,
            "disposition": "unresolved",
            "line": None,
        }
        try:
            if recorded is not None:
                previous = recorded["requested"][index]
                if previous["path"] != path or previous["sha256"] != module["sha256"]:
                    raise AdmissionError("recorded identity does not match the inputs record")
                entry["module"] = previous["module"]
            else:
                if source_root is None:
                    raise AdmissionError("source root is required to establish module identity")
                source = source_root / path
                actual = digest_file(source)
                if actual != module["sha256"]:
                    raise AdmissionError("source digest differs from the invocation record")
                entry["module"] = declared_module(source.read_text(errors="replace"))
                if entry["module"] != Path(path).name.rsplit(".", 1)[0]:
                    raise AdmissionError("declared module name does not match the file name")
        except (AdmissionError, OSError, UnicodeError, IndexError, KeyError, TypeError) as error:
            entry["disposition"] = "identity-error"
            reasons.append(f"{path}: {error}")
            requested.append(entry)
            continue
        names.setdefault(str(entry["module"]), []).append(index)
        requested.append(entry)

    implementations = {
        str(entry["module"])
        for entry in requested
        if entry["role"] == "implementation" and entry["module"] is not None
    }
    for name, indexes in names.items():
        roles = {requested[index]["role"] for index in indexes}
        if len(indexes) > len(roles):
            for index in indexes:
                requested[index]["disposition"] = "ambiguous"
            reasons.append(f"module {name} is requested more than once in this pass")
    impl_lines: dict[str, list[int]] = {}
    for name, line in parsed["implementations"]:
        impl_lines.setdefault(name, []).append(line)
    iface_lines: dict[str, list[int]] = {}
    for name, line in parsed["interfaces"]:
        iface_lines.setdefault(name, []).append(line)

    for entry in requested:
        if entry["disposition"] != "unresolved":
            continue
        name = str(entry["module"])
        if entry["role"] == "implementation":
            lines = impl_lines.get(name, [])
            if len(lines) == 1:
                entry["disposition"] = "verified"
                entry["line"] = lines[0]
            elif not lines:
                entry["disposition"] = "missing"
                reasons.append(f"no result line for implementation {name}")
            else:
                entry["disposition"] = "duplicate"
                reasons.append(f"{len(lines)} result lines for implementation {name}")
        elif name in implementations:
            entry["disposition"] = "paired-interface"
            if iface_lines.get(name):
                entry["disposition"] = "contradictory"
                reasons.append(
                    f"interface line for {name} although its implementation was requested"
                )
        else:
            lines = iface_lines.get(name, [])
            if len(lines) == 1:
                entry["disposition"] = "interface-verified"
                entry["line"] = lines[0]
            elif not lines:
                entry["disposition"] = "missing"
                reasons.append(f"no result line for interface {name}")
            else:
                entry["disposition"] = "duplicate"
                reasons.append(f"{len(lines)} result lines for interface {name}")

    unrequested: list[dict[str, Any]] = []
    for kind, table in (("implementation", impl_lines), ("interface", iface_lines)):
        for name, lines in table.items():
            expected = (
                name in implementations
                if kind == "implementation"
                else name in names and name not in implementations
            )
            if expected:
                continue
            note = None
            if recorded is None:
                if source_root is None:
                    raise AdmissionError("source root is required to classify results")
                identity, note = resolve_unrequested(name, kind, inputs, source_root)
            else:
                # The input snapshot, rather than modules.json itself, anchors
                # dependency identity when the original source is unavailable.
                identity, note = retained_dependency(name, kind, inputs)
                matches = [
                    entry
                    for entry in recorded.get("unrequested", [])
                    if entry.get("module") == name and entry.get("kind") == kind
                ]
                previous = matches[0] if len(matches) == 1 else None
                if previous is None:
                    note = f"recorded dependency {name} is missing or duplicated"
                    identity = None
                elif identity is not None and previous != {
                    "module": name,
                    "kind": kind,
                    "lines": lines,
                    "classification": "dependency",
                    **identity,
                }:
                    source = previous.get("source")
                    note = (
                        outside_search_scope(name, kind, source, inputs)
                        if isinstance(source, str)
                        else None
                    ) or f"recorded dependency {name} differs from the recorded input identity"
                    identity = None
            # A recorded source outside the directories F* searched, or of the
            # wrong kind, is not evidence of the dependency, at admission or on replay.
            if identity is not None:
                note = outside_search_scope(name, kind, identity["source"], inputs)
                if note is not None:
                    identity = None
            unrequested.append(
                {
                    "module": name,
                    "kind": kind,
                    "lines": lines,
                    "classification": "dependency" if identity else "unclassified",
                    "source": identity["source"] if identity else None,
                    "sha256": identity["sha256"] if identity else None,
                }
            )
            if identity is None:
                reasons.append(
                    f"unrequested {kind} result for {name} has no known source"
                    + (f": {note}" if note else "")
                )

    # A .checked file for a requested module anywhere F* searches would let the
    # result line stand for cache reuse instead of a fresh check.
    checked = {Path(item["path"]).name for item in inputs.get("local_context", [])}
    for name in sorted(names):
        if f"{name}.fst.checked" in checked or f"{name}.fsti.checked" in checked:
            reasons.append(f"a checked file for requested module {name} was present")
    if recorded is None:
        if source_root is None:
            raise AdmissionError("source root is required to scan for checked files")
        scan = checked_candidates(inputs, sorted(names), source_root)
    else:
        scan = recorded.get("checked_scan") or {"directories": [], "candidates": ["<unrecorded>"]}
    for candidate in scan["candidates"]:
        reasons.append(f"checked file for requested module found: {candidate}")

    status = "accepted" if not reasons else "rejected"
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "pass_id": pass_id,
        "inputs_sha256": result.get("inputs_sha256"),
        "output_sha256": result.get("output_sha256"),
        "tool": inputs.get("tool"),
        "returncode": result.get("returncode"),
        "requested": requested,
        "unrequested": unrequested,
        "checked_scan": scan,
        "diagnostics": {
            "errors": parsed["errors"],
            "warnings": parsed["warnings"],
            "completion_marker_lines": parsed["completion"],
            "total_time_argv_matches": parsed["total_time_argv"] == expected_echo,
        },
        "status": status,
        "reasons": reasons,
    }


def summary_line(record: dict[str, Any]) -> str:
    counts: dict[str, int] = {}
    for entry in record["requested"]:
        counts[entry["disposition"]] = counts.get(entry["disposition"], 0) + 1
    summary = {
        "event": "pass",
        "pass_id": record["pass_id"],
        "status": record["status"],
        "requested": len(record["requested"]),
        "dispositions": counts,
        "unrequested": len(record["unrequested"]),
        "errors": record["diagnostics"]["errors"],
        "warnings": record["diagnostics"]["warnings"],
        "reasons": record["reasons"],
    }
    return "FSTAR-ADMISSION " + json.dumps(summary, separators=(",", ":"), sort_keys=True)


def emit(out_dir: Path, line: str) -> None:
    print(line, flush=True)
    log = out_dir / "verify.log"
    if log.exists():
        with log.open("a") as target:
            target.write(line + "\n")


def duplicate_evidence(statuses: dict[str, dict[str, Any]]) -> list[str]:
    """Identical invocation records under two pass ids cannot both be that pass's evidence."""
    reasons: list[str] = []
    for field in ("inputs_sha256", "output_sha256"):
        seen: dict[str, str] = {}
        for pass_id, value in statuses.items():
            digest = value.get(field)
            if digest is None:
                continue
            if digest in seen:
                reasons.append(f"passes {seen[digest]} and {pass_id} share the same {field}")
            seen[digest] = pass_id
    return reasons


def load_pass(directory: Path) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    inputs_path = directory / "inputs.json"
    result_path = directory / "result.json"
    output_path = directory / "output.log"
    for path in (inputs_path, result_path, output_path):
        if not path.is_file():
            raise AdmissionError(f"missing invocation record {path.name}")
    result = load_json(result_path)
    if digest_file(inputs_path) != result.get("inputs_sha256"):
        raise AdmissionError("inputs.json digest differs from result.json")
    if digest_file(output_path) != result.get("output_sha256"):
        raise AdmissionError("output.log digest differs from result.json")
    return load_json(inputs_path), result, output_path.read_bytes()


def admit(out_dir: Path, passes: list[str], source_root: Path) -> int:
    admission = out_dir / "admission.json"
    admission.unlink(missing_ok=True)
    statuses: dict[str, dict[str, Any]] = {}
    accepted = True
    for pass_id in passes:
        directory = out_dir / "invocations" / pass_id
        record_path = directory / "modules.json"
        try:
            if record_path.exists():
                raise AdmissionError(
                    "modules.json already exists; evidence directories must be fresh"
                )
            inputs, result, output = load_pass(directory)
            record = reconcile(
                pass_id, inputs, result, output.decode(errors="replace"), source_root
            )
        except (AdmissionError, OSError, KeyError, TypeError, ValueError) as error:
            record = {
                "schema_version": SCHEMA_VERSION,
                "contract": CONTRACT,
                "pass_id": pass_id,
                "requested": [],
                "unrequested": [],
                "diagnostics": {"errors": 0, "warnings": 0},
                "status": "rejected",
                "reasons": [str(error)],
            }
        try:
            write_json_new(record_path, record)
        except OSError as error:
            record["status"] = "rejected"
            record["reasons"].append(f"cannot write modules.json: {error}")
        emit(out_dir, summary_line(record))
        statuses[pass_id] = {
            "status": record["status"],
            "modules_sha256": digest_file(record_path) if record_path.is_file() else None,
            "inputs_sha256": record.get("inputs_sha256"),
            "output_sha256": record.get("output_sha256"),
        }
        accepted = accepted and record["status"] == "accepted"
    duplicated = duplicate_evidence(statuses)
    if duplicated:
        accepted = False
        emit(
            out_dir,
            "FSTAR-ADMISSION "
            + json.dumps(
                {"event": "cross-pass", "status": "rejected", "reasons": duplicated},
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
    overall = {
        "event": "summary",
        "status": "accepted" if accepted else "rejected",
        "passes": {pass_id: value["status"] for pass_id, value in statuses.items()},
    }
    emit(out_dir, "FSTAR-ADMISSION " + json.dumps(overall, separators=(",", ":"), sort_keys=True))
    if not accepted:
        return 1
    document = {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "created_at": datetime.now(UTC).isoformat(),
        "admitter": {"path": str(Path(__file__).resolve()), "sha256": digest_file(Path(__file__))},
        "passes": statuses,
        "status": "accepted",
    }
    temporary = admission.with_suffix(".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temporary.replace(admission)
    return 0


def verify_records(out_dir: Path, passes: list[str]) -> int:
    """Re-check retained records without source access, e.g. on the hosted path."""
    admission = load_json(out_dir / "admission.json")
    if admission.get("status") != "accepted" or admission.get("contract") != CONTRACT:
        raise AdmissionError("admission.json is not an accepted record of this contract")
    seen_digests: dict[str, dict[str, Any]] = {}
    for pass_id in passes:
        directory = out_dir / "invocations" / pass_id
        entry = admission.get("passes", {}).get(pass_id)
        if not entry or entry.get("status") != "accepted":
            raise AdmissionError(f"pass {pass_id} is not accepted in admission.json")
        record_path = directory / "modules.json"
        if digest_file(record_path) != entry.get("modules_sha256"):
            raise AdmissionError(f"pass {pass_id}: modules.json digest differs from admission.json")
        record = load_json(record_path)
        inputs, result, output = load_pass(directory)
        for field in ("inputs_sha256", "output_sha256"):
            if not entry.get(field) or entry[field] != result.get(field):
                raise AdmissionError(
                    f"pass {pass_id}: admission.json {field} differs from result.json"
                )
        if (record.get("inputs_sha256"), record.get("output_sha256")) != (
            result.get("inputs_sha256"),
            result.get("output_sha256"),
        ):
            raise AdmissionError(f"pass {pass_id}: modules.json is bound to different records")
        replay = reconcile(pass_id, inputs, result, output.decode(errors="replace"), None, record)
        if replay["status"] != "accepted":
            raise AdmissionError(f"pass {pass_id}: replay rejected: {'; '.join(replay['reasons'])}")
        for field in ("requested", "unrequested"):
            if replay[field] != record[field]:
                raise AdmissionError(
                    f"pass {pass_id}: recorded {field} identities differ from replay"
                )
        seen_digests[pass_id] = {
            "inputs_sha256": result.get("inputs_sha256"),
            "output_sha256": result.get("output_sha256"),
        }
        print(f"[OK] pass {pass_id}: {len(record['requested'])} requested sources admitted")
    duplicated = duplicate_evidence(seen_digests)
    if duplicated:
        raise AdmissionError("; ".join(duplicated))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, help="invocation evidence directory to admit")
    parser.add_argument("--verify-records", type=Path, help="re-check retained records only")
    parser.add_argument("--passes", nargs="+", default=list(REQUIRED_PASSES))
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if bool(args.out_dir) == bool(args.verify_records):
        parser.error("exactly one of --out-dir or --verify-records is required")
    try:
        if args.verify_records:
            return verify_records(args.verify_records.resolve(), list(args.passes))
        return admit(args.out_dir.resolve(), list(args.passes), args.source_root.resolve())
    except (AdmissionError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"[FAIL] F* module admission: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
