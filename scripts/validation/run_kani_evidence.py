"""Run the admitted finite Kani slice with exact selection and property checks.

This is a bounded evidence adapter, not the release assurance evaluator. Kani's
versioned per-property report is parsed strictly; exit status or a success string
alone cannot admit a run. Unknown formats, missing checks and vacuity fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import resource
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = pathlib.Path("spec/kani-evidence.json")
PROPERTY = re.compile(
    r"Check (\d+): ([^\n]+)\n"
    r"\t - Status: ([A-Z]+)\n"
    r"\t - Description: \"([^\n]*(?:\n[ ]+[^\n]*)*)\"\n"
    r"(?:\t - Location: [^\n]+\n)?"
)


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def accept_report(
    log: str,
    harness: str,
    exit_code: int,
    unreachable_assertions: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Accept one completed exact harness, retaining each processed property."""
    if exit_code != 0:
        raise ValueError(f"Kani exited with {exit_code}")
    selected = re.findall(r"^Checking harness (.+)\.\.\.$", log, re.MULTILINE)
    if selected != [harness]:
        raise ValueError(f"unexpected harness selection: {selected!r}")
    sections = log.split("\nRESULTS:\n")
    if len(sections) != 2:
        raise ValueError("expected exactly one property report")
    body, separator, summary = sections[1].partition("\nSUMMARY:\n")
    if not separator:
        raise ValueError("missing result summary")
    checks = list(PROPERTY.finditer(body))
    if not checks or PROPERTY.sub("", body).strip():
        raise ValueError("missing or unrecognized property records")
    properties = []
    for number, match in enumerate(checks, 1):
        if int(match[1]) != number:
            raise ValueError("nonconsecutive property records")
        if match[3] not in {"SUCCESS", "UNREACHABLE"}:
            raise ValueError(f"unaccepted property {match[2]}: {match[3]}")
        properties.append({"id": match[2], "status": match[3], "description": match[4]})
    if len({p["id"] for p in properties}) != len(properties):
        raise ValueError("duplicate property identity")
    assertions = [p for p in properties if p["id"].startswith(harness + ".assertion.")]
    if not any(p["status"] == "SUCCESS" for p in assertions):
        raise ValueError("no reachable successful harness assertion")
    unreachable_guards = {
        p["id"]: p["description"] for p in assertions if p["status"] == "UNREACHABLE"
    }
    if unreachable_guards != (unreachable_assertions or {}):
        raise ValueError("unreviewed unreachable harness assertion or changed guard")
    unreachable = sum(p["status"] == "UNREACHABLE" for p in properties)
    expected = f" ** 0 of {len(properties)} failed"
    if unreachable:
        expected += f" ({unreachable} unreachable)"
    if summary.splitlines()[0] != expected:
        raise ValueError("property count/status does not match summary")
    ending = re.fullmatch(
        re.escape(expected)
        + r"\n\nVERIFICATION:- SUCCESSFUL\nVerification Time: [0-9.]+s\n"
        + r"\nManual Harness Summary:\n"
        + r"Complete - 1 successfully verified harnesses, 0 failures, 1 total\.\n?",
        summary,
    )
    if ending is None:
        raise ValueError("missing or unrecognized completion record")
    return properties


def discover_metadata(target: pathlib.Path, harness: dict[str, Any]) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for path in target.rglob("*.kani-metadata.json"):
        data = json.loads(path.read_text())
        proofs = data["proof_harnesses"]
        if [p["pretty_name"] for p in proofs] == [harness["name"]]:
            proof: dict[str, Any] = proofs[0]
            if data["crate_name"] != "ffi" or proof["original_file"] != harness["file"]:
                raise ValueError("compiled package/source identity does not match registry")
            attributes = proof["attributes"]
            if attributes["should_panic"] or attributes["stubs"] or attributes["verified_stubs"]:
                raise ValueError("unexpected panic expectation or proof substitution")
            matches.append({"path": str(path), "sha256": digest(path), "proof": proof})
    if len(matches) != 1:
        raise ValueError(f"expected one compiled harness identity, found {len(matches)}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "artifacts/kani-evidence")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    gate = output / "gate.json"
    gate.unlink(missing_ok=True)
    config: dict[str, Any] = json.loads((ROOT / REGISTRY).read_text())
    if (platform.system(), platform.machine(), config["target"]) != (
        "Linux",
        "x86_64",
        "x86_64-unknown-linux-gnu",
    ):
        raise ValueError("the admitted layout slice requires x86_64 Linux")
    names = [h["name"] for h in config["harnesses"]]
    if not names or len(names) != len(set(names)):
        raise ValueError("empty or duplicate evidence selection")
    kani = shutil.which("cargo-kani")
    if kani is None:
        raise ValueError("cargo-kani is required; compile-only substitutes are not evidence")
    version = subprocess.check_output([kani, "kani", "--version"], text=True).strip()
    if version != f"cargo-kani {config['kani_version']}":
        raise ValueError(f"unsupported Kani version: {version}")
    run = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=output))
    build = tempfile.TemporaryDirectory(prefix="aegaeon-kani-evidence-")
    target = pathlib.Path(build.name)
    env = os.environ.copy()
    for key in ("RUSTC", "CARGO", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    env.update(
        RUSTFLAGS="-C panic=abort -Z panic-abort-tests --cfg kani",
        CARGO_TARGET_DIR=str(target),
        CARGO_TERM_COLOR="never",
    )
    inputs = {str(REGISTRY): digest(ROOT / REGISTRY), "evaluator": digest(pathlib.Path(__file__))}
    for relative in (
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "flake.lock",
        ".cargo/config.toml",
    ):
        inputs[relative] = digest(ROOT / relative)
    for directory in ("crates/ffi", "crates/jose-tlv", "c", "generated", "nix/kani"):
        for source in (ROOT / directory).rglob("*"):
            if source.is_file() and "target" not in source.relative_to(ROOT).parts:
                inputs[str(source.relative_to(ROOT))] = digest(source)
    record: dict[str, Any] = {
        "version": 1,
        "started_at": datetime.now(UTC).isoformat(),
        "kani": {"path": kani, "version": version, "sha256": digest(pathlib.Path(kani))},
        "environment": {key: env[key] for key in ("RUSTFLAGS", "CARGO_TARGET_DIR")},
        "inputs": inputs,
        "policy": config,
        "results": [],
        "status": "incomplete",
    }

    def limits() -> None:
        resource.setrlimit(
            resource.RLIMIT_AS, (config["memory_limit_bytes"], config["memory_limit_bytes"])
        )

    for index, harness in enumerate(config["harnesses"]):
        command = [
            "timeout",
            "--kill-after=10",
            str(config["timeout_seconds"]),
            kani,
            "kani",
            "-p",
            config["package"],
            "--features",
            ",".join(config["features"]),
            "--no-default-features",
            "--exact",
            "--harness",
            harness["name"],
            "--solver",
            config["solver"],
            "--default-unwind",
            str(config["default_unwind"]),
        ]
        log_path = run / f"{index:02d}.log"
        with log_path.open("w") as log:
            process = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                preexec_fn=limits,
                check=False,
            )
        result: dict[str, Any] = {
            "harness": harness,
            "command": command,
            "exit_code": process.returncode,
            "log": str(log_path.relative_to(output)),
            "log_sha256": digest(log_path),
            "status": "rejected",
        }
        try:
            result["properties"] = accept_report(
                log_path.read_text(),
                harness["name"],
                process.returncode,
                harness.get("unreachable_assertions"),
            )
            compiled = discover_metadata(target, harness)
            metadata = run / f"{index:02d}.kani-metadata.json"
            shutil.copy2(compiled["path"], metadata)
            compiled["path"] = str(metadata.relative_to(output))
            result["compiled"] = compiled
            result["status"] = "accepted"
        except (ValueError, KeyError) as error:
            result["reason"] = str(error)
        record["results"].append(result)
        (run / "evaluation.json").write_text(json.dumps(record, indent=2) + "\n")
        print(f"{harness['name']}: {result['status']}", flush=True)
    accepted = all(r["status"] == "accepted" for r in record["results"])
    record.update(
        status="accepted" if accepted else "rejected", completed_at=datetime.now(UTC).isoformat()
    )
    (run / "evaluation.json").write_text(json.dumps(record, indent=2) + "\n")
    if accepted:
        gate.write_text(
            json.dumps(
                {
                    "evaluation": str((run / "evaluation.json").relative_to(output)),
                    "sha256": digest(run / "evaluation.json"),
                },
                indent=2,
            )
            + "\n"
        )
    print(f"Evaluation: {run / 'evaluation.json'}")
    build.cleanup()
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
