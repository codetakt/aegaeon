"""Admit Tamarin results per requested (theory, lemma), not per exit status or log grep.

The pinned tamarin-prover prints one summary line per lemma of the analysed
theory. With ``--prove=<lemma>`` every other lemma reports ``analysis
incomplete`` and the process exits 0; it also exits 0 when the theory fails
wellformedness, when the requested lemma is falsified, or when a ``--prove``
argument matches no lemma. A request is admitted only when the invocation
completed, the theory is wellformed (or every warning section is a registered,
digest-bound exception), and the requested lemma's own summary line reports
``verified`` with the quantifier declared in the source. The records bind that
decision to the theory digest, the tool identity and the raw log. They describe
tool executions; they do not establish model adequacy, implementation
refinement or release assurance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CONTRACT = "tamarin-1.12.0-summary-v1"
SCHEMA_VERSION = 1
DEFAULT_REGISTRY = Path("spec/tamarin-evidence.json")
LEMMA_DECLARATION = re.compile(
    r"^[ \t]*lemma[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:\[[^\]]*\])?[ \t]*:\s*"
    r"(exists-trace|all-traces)?",
    re.MULTILINE,
)
SUMMARY_LINE = re.compile(
    r"^  (\S+) \((all-traces|exists-trace)\): "
    r"(verified|falsified - found trace|analysis incomplete) \((\d+) steps\)$"
)
SUMMARY_START = "summary of summaries:"
SEPARATOR = "=" * 78
WELLFORMED_OK = "/* All wellformedness checks were successful. */"
WELLFORMED_WARNING = "WARNING: the following wellformedness checks failed!"
SUMMARY_WARNING = re.compile(r"^  WARNING: (\d+) wellformedness checks? failed!$")
VERSION_LINE = re.compile(r"^(Tamarin|Maude) version (\S+)$", re.MULTILINE)


class AdmissionError(ValueError):
    """A recorded, expected admission failure."""


def digest_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise AdmissionError(f"{path.name} is not a JSON object")
    return value


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    # A pre-existing record would let stale evidence pose as current.
    with path.open("x") as target:
        target.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def strip_comments(text: str) -> str:
    """Remove Tamarin block and line comments, keeping line structure."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def declared_lemmas(text: str) -> dict[str, str]:
    """Map each lemma declared exactly once to its trace quantifier."""
    found: dict[str, str] = {}
    for match in LEMMA_DECLARATION.finditer(strip_comments(text)):
        name = match[1]
        if name in found:
            raise AdmissionError(f"lemma {name} is declared more than once")
        found[name] = match[2] or "all-traces"
    return found


def section_digest(body: str) -> str:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    return digest_text("\n".join(lines))


def warning_sections(text: str) -> list[dict[str, str]]:
    """Titled sections of every wellformedness warning block in the log."""
    sections: list[dict[str, str]] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        if lines[index].strip() != WELLFORMED_WARNING:
            index += 1
            continue
        block: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != "*/":
            block.append(lines[index])
            index += 1
        current: dict[str, Any] | None = None
        for position, line in enumerate(block):
            underline = block[position + 1] if position + 1 < len(block) else ""
            if line.strip() and re.fullmatch(r"=+", underline.strip() or "x"):
                current = {"title": line.strip(), "lines": []}
                sections.append(current)
            elif current is not None and not re.fullmatch(r"=+", line.strip() or "x"):
                current["lines"].append(line)
        for section in sections:
            if "lines" in section:
                section["sha256"] = section_digest("\n".join(section.pop("lines")))
    return sections


def parse_log(text: str) -> dict[str, Any]:
    """Parse the versioned text contract; anything unrecognised is reported."""
    versions = dict(VERSION_LINE.findall(text))
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == SUMMARY_START]
    summary: dict[str, Any] = {
        "present": len(starts) == 1,
        "count": len(starts),
        "closed": False,
        "analyzed": None,
        "warnings_failed": None,
        "lemmas": [],
        "unrecognised": [],
    }
    if len(starts) == 1:
        index = starts[0] + 1
        while index < len(lines) and lines[index] != SEPARATOR:
            line = lines[index]
            index += 1
            if not line.strip():
                continue
            if line.startswith("analyzed: "):
                summary["analyzed"] = line[len("analyzed: ") :]
            elif line.strip().startswith("processing time:"):
                continue
            elif match := SUMMARY_WARNING.match(line):
                summary["warnings_failed"] = int(match[1])
            elif line.strip() == "The analysis results might be wrong!":
                summary["caution"] = True
            elif match := SUMMARY_LINE.match(line):
                summary["lemmas"].append(
                    {
                        "name": match[1],
                        "quantifier": match[2],
                        "status": match[3],
                        "steps": int(match[4]),
                    }
                )
            else:
                summary["unrecognised"].append(line)
        summary["closed"] = index < len(lines) and lines[index] == SEPARATOR
    return {
        "tamarin_version": versions.get("Tamarin"),
        "maude_version": versions.get("Maude"),
        "wellformed": WELLFORMED_OK in text,
        "warning_sections": warning_sections(text),
        "summary": summary,
    }


def registered_exceptions(registry: dict[str, Any], theory: str, sha256: str) -> set[str]:
    """Section digests registered for exactly this theory content."""
    digests: set[str] = set()
    for entry in registry.get("wellformedness_exceptions", []):
        if entry.get("theory") == theory and entry.get("sha256") == sha256:
            digests.update(section["sha256"] for section in entry.get("sections", []))
    return digests


def reconcile(
    request: dict[str, Any],
    invocation: dict[str, Any],
    text: str,
    registry: dict[str, Any],
) -> dict[str, Any]:
    """Decide one request from its retained records."""
    reasons: list[str] = []
    parsed = parse_log(text)
    status = invocation.get("returncode")
    if invocation.get("timed_out"):
        reasons.append(f"wall-clock budget of {invocation.get('timeout_seconds')}s exceeded")
    if status != 0:
        reasons.append(f"tamarin-prover exited with {status!r}")
    if invocation.get("theory_sha256_after") != request["theory_sha256"]:
        reasons.append("theory digest changed during the invocation")
    expected = registry["tamarin_version"]
    if parsed["tamarin_version"] != expected:
        reasons.append(f"log reports Tamarin {parsed['tamarin_version']!r}, contract {expected!r}")
    if parsed["maude_version"] != registry["maude_version"]:
        reasons.append(f"log reports Maude {parsed['maude_version']!r}")
    summary = parsed["summary"]
    if not summary["present"]:
        reasons.append(f"expected exactly one summary block, found {summary['count']}")
    elif not summary["closed"]:
        reasons.append("summary block is not closed")
    if summary["unrecognised"]:
        reasons.append(f"unrecognised summary lines: {summary['unrecognised'][:3]}")
    if summary["analyzed"] != request["theory"]:
        reasons.append(f"summary analysed {summary['analyzed']!r}, requested {request['theory']!r}")
    exception_used = False
    if parsed["warning_sections"] or summary["warnings_failed"] or not parsed["wellformed"]:
        allowed = registered_exceptions(registry, request["theory"], request["theory_sha256"])
        digests = [section["sha256"] for section in parsed["warning_sections"]]
        if not digests or not parsed["warning_sections"]:
            reasons.append("theory is not reported wellformed and no warning block was found")
        elif any(digest not in allowed for digest in digests):
            titles = [s["title"] for s in parsed["warning_sections"] if s["sha256"] not in allowed]
            reasons.append(f"unregistered wellformedness warning(s): {titles}")
        elif not summary["warnings_failed"]:
            # Tamarin counts individual failed checks, not sections; the summary
            # must still acknowledge the warning block it printed.
            reasons.append("summary does not acknowledge the wellformedness warning block")
        else:
            exception_used = True
    lines = [entry for entry in summary["lemmas"] if entry["name"] == request["lemma"]]
    if len(lines) != 1:
        reasons.append(f"{len(lines)} summary lines for requested lemma {request['lemma']}")
    else:
        line = lines[0]
        if line["quantifier"] != request["quantifier"]:
            reasons.append(
                "summary quantifier "
                f"{line['quantifier']} differs from declared {request['quantifier']}"
            )
        if line["status"] != "verified":
            reasons.append(f"requested lemma is {line['status']}")
    falsified = [e["name"] for e in summary["lemmas"] if e["status"] == "falsified - found trace"]
    if falsified:
        reasons.append(f"falsified lemma(s) in summary: {falsified}")
    if reasons:
        outcome = "rejected"
    elif exception_used:
        outcome = "accepted-with-registered-exception"
    else:
        outcome = "accepted"
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "request_id": request["id"],
        "theory": request["theory"],
        "lemma": request["lemma"],
        "quantifier": request["quantifier"],
        "parsed": parsed,
        "status": outcome,
        "reasons": reasons,
    }


def load_registry(path: Path) -> dict[str, Any]:
    registry = load_json(path)
    if registry.get("contract") != CONTRACT:
        raise AdmissionError(f"registry contract {registry.get('contract')!r} is not {CONTRACT}")
    return registry


def build_requests(proofs_root: Path, specs: list[str]) -> list[dict[str, Any]]:
    """Normalise ``theory:lemma,…`` specifications into validated requests."""
    requests: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        theory, separator, lemmas = spec.partition(":")
        if not separator or not theory or not lemmas.strip(","):
            raise AdmissionError(f"malformed selection {spec!r}")
        path = proofs_root / theory
        if not path.is_file() or path.suffix != ".spthy":
            raise AdmissionError(f"theory {theory} is not a .spthy file under the proofs root")
        declared = declared_lemmas(path.read_text(errors="replace"))
        sha256 = digest_file(path)
        for lemma in lemmas.split(","):
            if not lemma:
                raise AdmissionError(f"empty lemma name in selection {spec!r}")
            if (theory, lemma) in seen:
                raise AdmissionError(f"duplicate selection {theory}:{lemma}")
            if lemma not in declared:
                raise AdmissionError(f"lemma {lemma} is not declared in {theory}")
            seen.add((theory, lemma))
            requests.append(
                {
                    "id": f"{theory.replace('/', '_').removesuffix('.spthy')}__{lemma}",
                    "theory": theory,
                    "theory_sha256": sha256,
                    "lemma": lemma,
                    "quantifier": declared[lemma],
                }
            )
    if not requests:
        raise AdmissionError("empty selection")
    return requests


def tool_identity(command: list[str]) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        raise AdmissionError(f"verifier not found: {command[0]}")
    version = subprocess.run(
        [*command, "--version"], capture_output=True, text=True, check=False
    ).stdout
    match = re.search(r"tamarin-prover (\S+),", version)
    maude = shutil.which("maude")
    return {
        "argv": command,
        "path": executable,
        "sha256": digest_file(Path(executable)) if len(command) == 1 else None,
        "reported_version": match[1] if match else None,
        "maude_path": maude,
        "maude_sha256": digest_file(Path(maude)) if maude else None,
    }


def emit(log: Path, line: str) -> None:
    print(line, flush=True)
    with log.open("a") as target:
        target.write(line + "\n")


def event(payload: dict[str, Any]) -> str:
    return "TAMARIN-ADMISSION " + json.dumps(payload, separators=(",", ":"), sort_keys=True)


def run_one(
    request: dict[str, Any],
    directory: Path,
    proofs_root: Path,
    tool: dict[str, Any],
    budgets: dict[str, int],
) -> tuple[dict[str, Any], str]:
    """Execute one request and retain its command record and raw output."""
    directory.mkdir(parents=True, exist_ok=False)
    argv = [
        "timeout",
        "--kill-after=10",
        str(budgets["timeout_seconds"]),
        *tool["argv"],
        f"--prove={request['lemma']}",
        f"--derivcheck-timeout={budgets['derivcheck_timeout_seconds']}",
        request["theory"],
    ]
    env = {**os.environ, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    started = datetime.now(UTC).isoformat()
    clock = time.monotonic()
    with (directory / "output.log").open("wb") as output:
        completed = subprocess.run(
            argv, cwd=proofs_root, env=env, stdout=output, stderr=subprocess.STDOUT, check=False
        )
    record = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request["id"],
        "argv": argv,
        "cwd": str(proofs_root),
        "tool": tool,
        "timeout_seconds": budgets["timeout_seconds"],
        "derivcheck_timeout_seconds": budgets["derivcheck_timeout_seconds"],
        "started_at": started,
        "finished_at": datetime.now(UTC).isoformat(),
        "wall_seconds": round(time.monotonic() - clock, 3),
        "returncode": completed.returncode,
        "timed_out": completed.returncode == 124,
        "theory_sha256_before": request["theory_sha256"],
        "theory_sha256_after": digest_file(proofs_root / request["theory"]),
        "output_sha256": digest_file(directory / "output.log"),
    }
    write_json_new(directory / "command.json", record)
    return record, (directory / "output.log").read_text(errors="replace")


def run(args: argparse.Namespace) -> int:
    out_dir: Path = args.out_dir.resolve()
    proofs_root: Path = args.proofs_root.resolve()
    registry_path: Path = args.registry.resolve()
    registry = load_registry(registry_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    admission = out_dir / "admission.json"
    admission.unlink(missing_ok=True)
    log = out_dir / "verify-tamarin.log"
    log.write_text("")
    requests = build_requests(proofs_root, args.spec)
    write_json_new(
        out_dir / "requests.json", {"schema_version": SCHEMA_VERSION, "requests": requests}
    )
    tool = tool_identity(shlex.split(args.tool))
    if tool["reported_version"] != registry["tamarin_version"]:
        raise AdmissionError(
            f"tool reports {tool['reported_version']!r}; contract requires "
            f"{registry['tamarin_version']!r}"
        )
    budgets = {
        "timeout_seconds": int(os.environ.get("TAMARIN_TIMEOUT", registry["timeout_seconds"])),
        "derivcheck_timeout_seconds": int(
            os.environ.get("TAMARIN_DERIVCHECK_TIMEOUT", registry["derivcheck_timeout_seconds"])
        ),
    }
    results: dict[str, dict[str, Any]] = {}
    counts = {"accepted": 0, "accepted-with-registered-exception": 0, "rejected": 0}
    for request in requests:
        label = f"{request['theory']}:{request['lemma']}"
        emit(log, f"=> Proving {label}")
        directory = out_dir / "invocations" / request["id"]
        try:
            invocation, text = run_one(request, directory, proofs_root, tool, budgets)
            result = reconcile(request, invocation, text, registry)
            result["output_sha256"] = invocation["output_sha256"]
            result["command_sha256"] = digest_file(directory / "command.json")
            write_json_new(directory / "result.json", result)
        except (AdmissionError, OSError) as error:
            result = {
                "schema_version": SCHEMA_VERSION,
                "contract": CONTRACT,
                "request_id": request["id"],
                "theory": request["theory"],
                "lemma": request["lemma"],
                "quantifier": request["quantifier"],
                "status": "rejected",
                "reasons": [str(error)],
            }
        counts[result["status"]] += 1
        results[request["id"]] = {
            "status": result["status"],
            "result_sha256": (
                digest_file(directory / "result.json")
                if (directory / "result.json").is_file()
                else None
            ),
        }
        if result["status"] == "rejected":
            emit(log, f"[FAIL] {label} ({'; '.join(result['reasons'])})")
        else:
            emit(log, f"[OK] {label}")
        emit(
            log,
            event(
                {
                    "event": "request",
                    "id": request["id"],
                    "status": result["status"],
                    "reasons": result["reasons"],
                }
            ),
        )
    total = len(requests)
    emit(log, "=== Summary ===")
    emit(log, f"Lemmas verified: {total - counts['rejected']}/{total}")
    emit(log, f"Lemmas failed: {counts['rejected']}/{total}")
    emit(
        log,
        "Registered wellformedness exceptions used: "
        f"{counts['accepted-with-registered-exception']}",
    )
    overall = "rejected" if counts["rejected"] else "accepted"
    emit(log, event({"event": "summary", "status": overall, "counts": counts, "total": total}))
    if overall != "accepted":
        return 1
    write_json_atomic(
        admission,
        {
            "schema_version": SCHEMA_VERSION,
            "contract": CONTRACT,
            "created_at": datetime.now(UTC).isoformat(),
            "admitter": {
                "path": str(Path(__file__).resolve()),
                "sha256": digest_file(Path(__file__)),
            },
            "registry": {"path": str(registry_path), "sha256": digest_file(registry_path)},
            "requests_sha256": digest_file(out_dir / "requests.json"),
            "tool": tool,
            "budgets": budgets,
            "counts": counts,
            "results": results,
            "status": "accepted",
        },
    )
    return 0


def verify_records(directory: Path, registry_path: Path) -> int:
    """Re-derive every decision from retained records without the tool."""
    registry = load_registry(registry_path)
    admission = load_json(directory / "admission.json")
    if admission.get("status") != "accepted" or admission.get("contract") != CONTRACT:
        raise AdmissionError("admission.json is not an accepted record of this contract")
    if admission["registry"]["sha256"] != digest_file(registry_path):
        raise AdmissionError("registry digest differs from the admitted run")
    if admission["requests_sha256"] != digest_file(directory / "requests.json"):
        raise AdmissionError("requests.json digest differs from admission.json")
    requests = load_json(directory / "requests.json")["requests"]
    if {r["id"] for r in requests} != set(admission["results"]):
        raise AdmissionError("admission.json does not cover exactly the requested set")
    for request in requests:
        invocation_dir = directory / "invocations" / request["id"]
        result_path = invocation_dir / "result.json"
        if digest_file(result_path) != admission["results"][request["id"]]["result_sha256"]:
            raise AdmissionError(f"{request['id']}: result.json digest differs from admission.json")
        result = load_json(result_path)
        command = load_json(invocation_dir / "command.json")
        if digest_file(invocation_dir / "command.json") != result["command_sha256"]:
            raise AdmissionError(f"{request['id']}: command.json digest differs from result.json")
        if digest_file(invocation_dir / "output.log") != result["output_sha256"]:
            raise AdmissionError(f"{request['id']}: output.log digest differs from result.json")
        replay = reconcile(
            request, command, (invocation_dir / "output.log").read_text(errors="replace"), registry
        )
        if replay["status"] == "rejected" or replay["status"] != result["status"]:
            raise AdmissionError(
                f"{request['id']}: replay {replay['status']} ({'; '.join(replay['reasons'])})"
            )
    print(f"[OK] {len(requests)} Tamarin requests replay as admitted")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    runner = commands.add_parser("run", help="execute and admit the selection")
    runner.add_argument("--out-dir", type=Path, required=True)
    runner.add_argument("--proofs-root", type=Path, required=True)
    runner.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    runner.add_argument("--tool", default="tamarin-prover", help="verifier command (shell words)")
    runner.add_argument("spec", nargs="+", help="theory:lemma,lemma,… selections")
    verifier = commands.add_parser("verify-records", help="re-check retained records")
    verifier.add_argument("directory", type=Path)
    verifier.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    args = parser.parse_args()
    try:
        if args.command == "run":
            return run(args)
        return verify_records(args.directory.resolve(), args.registry.resolve())
    except (AdmissionError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"[FAIL] Tamarin admission: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
