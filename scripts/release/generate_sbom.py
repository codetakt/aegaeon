"""Generate a Cargo dependency inventory; this does not attest a release binary."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path

MAX_TIMEOUT_SECONDS = 3600


class GenerationError(Exception):
    pass


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - assertion predicate
    if not condition:
        raise GenerationError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_result(path: Path, completed: Path) -> None:
    """Give the caller this run's artifact, independent of the shared pointer."""
    artifact = completed / "aegaeon-sbom.json"
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temp_path = Path(temporary.name)
    try:
        write_json(temp_path, {"sbom": str(artifact), "sha256": digest(artifact.read_bytes())})
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)


def command(argv: list[str], cwd: Path, log: Path, timeout: int) -> None:
    # A process group also stops cargo/rustc descendants on timeout/interruption.
    with log.open("wb") as output:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            rc = process.wait(timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    require(rc == 0, f"{argv[0]} failed (exit {rc}); see {log.name}")


def snapshot(root: Path, destination: Path) -> list[dict[str, str]]:
    tracked = subprocess.check_output(["git", "ls-files", "--cached", "-z"], cwd=root)
    records = []
    for name in sorted(set(os.fsdecode(tracked).split("\0")) - {""}):
        relative = Path(name)
        require(not (relative.is_absolute() or ".." in relative.parts), "invalid tracked path")
        # Generated Cargo SBOMs can never be an input to this run.
        if name.endswith((".cdx.json", ".cdx.xml")):
            continue
        source, target = root / relative, destination / relative
        require(source.resolve().is_relative_to(root), f"external source path: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            link = os.readlink(source)  # noqa: PTH115 - preserve literal symlink spelling
            require(
                not Path(link).is_absolute() and source.resolve().is_relative_to(root),
                f"external source symlink: {name}",
            )
            target.symlink_to(link)
            records.append({"path": name, "kind": "symlink", "sha256": digest(os.fsencode(link))})
        elif source.is_file():
            data = source.read_bytes()
            target.write_bytes(data)
            shutil.copymode(source, target)
            records.append({"path": name, "kind": "file", "sha256": digest(data)})
        else:
            raise GenerationError(f"missing or non-file tracked input: {name}")
    return records


def validate_bom(path: Path, name: str, version: str, spec_version: str) -> dict:
    require(
        not path.is_symlink() and path.is_file(),
        "generator did not produce the expected server SBOM",
    )
    bom = json.loads(path.read_text())
    require(isinstance(bom, dict), "SBOM must be an object")
    component = bom.get("metadata", {}).get("component", {})
    require(
        not (
            bom.get("bomFormat") != "CycloneDX"
            or bom.get("specVersion") != spec_version
            or type(bom.get("version")) is not int
            or bom["version"] < 1
            or not isinstance(bom.get("components"), list)
            or component.get("name") != name
            or component.get("version") != version
        ),
        "SBOM format or server package identity mismatch",
    )
    require(
        not (
            any(
                not isinstance(c, dict) or not isinstance(c.get("name"), str) or not c["name"]
                for c in bom["components"]
            )
        ),
        "invalid dependency component",
    )
    if "serialNumber" not in bom:
        bom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    serial = bom["serialNumber"]
    require(
        isinstance(serial, str) and serial.startswith("urn:uuid:"),
        "invalid SBOM serialNumber",
    )
    uuid.UUID(serial.removeprefix("urn:uuid:"))
    return bom


def prepare_inventory(
    root: Path, pending: Path, timeout: int, spec_version: str, *, signing: bool
) -> None:
    with tempfile.TemporaryDirectory(prefix="aegaeon-sbom-") as tmp:
        source = Path(tmp)
        records = snapshot(root, source)
        lock_before = (source / "Cargo.lock").read_bytes()
        package = tomllib.loads((source / "crates/server/Cargo.toml").read_text())["package"]
        name, version = package["name"], package["version"]
        require(
            name == "aegaeon-server" and isinstance(version, str) and bool(version),
            "invalid server package identity",
        )
        argv = [
            "cargo",
            "cyclonedx",
            "--manifest-path",
            "crates/server/Cargo.toml",
            "--format",
            "json",
            "--spec-version",
            spec_version,
            "--describe",
            "crate",
        ]
        command(["cargo", "cyclonedx", "--version"], source, pending / "tool-version.txt", timeout)
        command(argv, source, pending / "generation.log", timeout)
        require(
            (source / "Cargo.lock").read_bytes() == lock_before,
            "generation changed the input Cargo.lock",
        )
        generated = source / "crates/server/aegaeon-server.cdx.json"
        bom = validate_bom(generated, name, version, spec_version)
        shutil.copyfile(generated, pending / "rust-sbom.json")
        write_json(pending / "aegaeon-sbom.json", bom)
        write_json(pending / "source-inputs.json", records)
        provenance = {
            "schema_version": 1,
            "scope": "Cargo dependency inventory; default features and generator host target",
            "release_binary_attestation": False,
            "source_kind": (
                "tracked worktree bytes; local edits included; untracked files excluded"
            ),
            "source_inputs_sha256": digest((pending / "source-inputs.json").read_bytes()),
            "cargo_lock_sha256": digest(lock_before),
            "package": {"name": name, "version": version},
            "command": argv,
            "tool_version": (pending / "tool-version.txt").read_text().strip(),
            "signing_requested": signing,
            "signature_verification": "not performed by this generator",
        }
        if signing:
            command(
                [
                    "cosign",
                    "sign-blob",
                    "--yes",
                    "--output-signature",
                    "aegaeon-sbom.sig",
                    "--output-certificate",
                    "aegaeon-sbom.crt",
                    "aegaeon-sbom.json",
                ],
                pending,
                pending / "signing.log",
                timeout,
            )
            for filename in ("aegaeon-sbom.sig", "aegaeon-sbom.crt"):
                p = pending / filename
                require(
                    not p.is_symlink() and p.is_file() and p.stat().st_size > 0,
                    "signer did not produce signature and certificate",
                )
        provenance["artifacts"] = {
            p.name: digest(p.read_bytes()) for p in sorted(pending.iterdir()) if p.is_file()
        }
        write_json(pending / "provenance.json", provenance)
        (pending / "sbom-report.txt").write_text(
            f"Cargo dependency inventory: {name} {version}\n"
            f"Dependency components: {len(bom['components'])}\n"
            "This inventory does not establish release artifact, "
            "conformance, or assurance acceptance.\n"
        )


def generate(root: Path, output: Path, timeout: int, spec_version: str, *, signing: bool) -> Path:
    require(
        not (shutil.which("cargo") is None or shutil.which("cargo-cyclonedx") is None),
        "cargo and cargo-cyclonedx are required; use nix develop .#ci",
    )
    require(
        not (signing and shutil.which("cosign") is None),
        "signing requested but cosign is unavailable",
    )
    output.mkdir(parents=True, exist_ok=True)
    run_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex}"
    pending = output / f".pending-{run_id}"
    pending.mkdir(mode=0o700)
    try:
        prepare_inventory(root, pending, timeout, spec_version, signing=signing)
        completed = output / f"sbom-{run_id}"
        pending.rename(completed)
        for link, filename in (
            ("rust-sbom-latest.json", "rust-sbom.json"),
            ("sbom-report-latest.txt", "sbom-report.txt"),
            ("aegaeon-sbom-latest.json", "aegaeon-sbom.json"),
        ):
            temporary_link = output / f".link-{uuid.uuid4().hex}"
            temporary_link.symlink_to(f"{completed.name}/{filename}")
            temporary_link.replace(output / link)
    except BaseException:
        if pending.exists():
            pending.rename(output / f"failed-{run_id}")
        raise
    else:
        return completed


def main() -> int:
    try:
        require(
            len(sys.argv) == 1,
            "use OUTPUT_DIR, SBOM_VERSION, SBOM_TIMEOUT_SECONDS, ENABLE_COSIGN_SIGNING",
        )
        root = Path(
            subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        ).resolve()
        output = Path(os.environ.get("OUTPUT_DIR", "artifacts/sbom")).resolve()
        spec_version = os.environ.get("SBOM_VERSION", "1.5")
        require(
            not (
                os.environ.get("SBOM_FORMAT", "cyclonedx") != "cyclonedx"
                or spec_version
                not in (
                    "1.3",
                    "1.4",
                    "1.5",
                )
            ),
            "unsupported CycloneDX format/version",
        )
        timeout = int(os.environ.get("SBOM_TIMEOUT_SECONDS", "60"))
        require(
            1 <= timeout <= MAX_TIMEOUT_SECONDS, "SBOM_TIMEOUT_SECONDS must be between 1 and 3600"
        )
        signing = os.environ.get("ENABLE_COSIGN_SIGNING", "0")
        require(signing in ("0", "1"), "ENABLE_COSIGN_SIGNING must be 0 or 1")
        result = generate(root, output, timeout, spec_version, signing=signing == "1")
        if result_file := os.environ.get("SBOM_RESULT_FILE"):
            write_result(Path(result_file).absolute(), result)
        print(f"SBOM generated: {result / 'aegaeon-sbom.json'}")
    except (
        GenerationError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ) as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        return 1
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
