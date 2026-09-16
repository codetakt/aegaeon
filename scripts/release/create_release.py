"""Create a local OpenPGP release tag; publication and assurance remain separate."""
# Fixed argv and human-readable CLI validation errors, matching the CI helpers.
# ruff: noqa: S603, S607

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

RELEASE_CRATES = ("server", "client", "jose", "observability", "loadtest")
HEX_ID = re.compile(r"[0-9a-f]{40}\Z")
SIGNING_KEY = re.compile(r"[0-9A-Fa-f]{40}!?\Z")
SEMVER = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z"
)


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - assertion predicate
    if not condition:
        raise ValueError(message)


def git(repo: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=repo, stderr=subprocess.PIPE)


def validate_version(version: str) -> None:
    match = SEMVER.fullmatch(version)
    require(match is not None, "version must be an explicit v-prefixed SemVer")
    if match is not None and match.group(4):
        for identifier in match.group(4).split("."):
            require(
                not (identifier.isdecimal() and len(identifier) > 1 and identifier.startswith("0")),
                "numeric prerelease identifiers must not have leading zeroes",
            )


def validate_inputs(repo: Path, version: str, commit: str) -> str:
    validate_version(version)
    require(HEX_ID.fullmatch(commit) is not None, "commit must be a full lowercase SHA-1 commit ID")
    require(git(repo, "rev-parse", "HEAD").decode().strip() == commit, "HEAD differs from commit")
    require(
        not git(repo, "status", "--porcelain", "--untracked-files=normal"),
        "release tagging requires a clean checkout, including non-ignored untracked files",
    )
    tags = git(repo, "tag", "--list", version)
    require(not tags, f"tag already exists: {version}")
    for crate in RELEASE_CRATES:
        manifest = tomllib.loads(git(repo, "show", f"{commit}:crates/{crate}/Cargo.toml").decode())
        require(
            manifest.get("package", {}).get("version") == version[1:],
            f"committed package.version mismatch: {crate}",
        )
    return git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()


def tag_message(version: str, commit: str, tree: str, notes_path: Path) -> tuple[bytes, str]:
    notes = notes_path.read_bytes()
    text = notes.decode("utf-8")
    require(bool(text.strip()) and "\x00" not in text, "notes must be nonempty UTF-8 without NUL")
    require("-----BEGIN PGP SIGNATURE-----" not in text, "notes must not contain a signature block")
    notes_digest = hashlib.sha256(notes).hexdigest()
    header = (
        f"Aegaeon {version}\n\nSource-Commit: {commit}\nSource-Tree: {tree}\n"
        f"Release-Notes-SHA256: {notes_digest}\n\n"
    ).encode()
    return header + notes + (b"" if notes.endswith(b"\n") else b"\n"), notes_digest


def verify_tag(repo: Path, tag_object: str, commit: str, signing_key: str) -> str:
    result = subprocess.run(
        ["git", "-c", "gpg.format=openpgp", "verify-tag", "--raw", tag_object],
        cwd=repo,
        capture_output=True,
        check=True,
    )
    signatures = re.findall(rb"^\[GNUPG:\] VALIDSIG ([^\r\n]+)$", result.stderr, flags=re.MULTILINE)
    require(len(signatures) == 1, "expected one valid OpenPGP signature")
    require(
        not re.search(
            rb"^\[GNUPG:\] (?:EXPSIG|EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG) ",
            result.stderr,
            flags=re.MULTILINE,
        ),
        "signature is expired, revoked or invalid",
    )
    fields = signatures[0].decode("ascii").split()
    expected = signing_key.removesuffix("!").upper()
    signer = fields[0].upper()
    primary = fields[-1].upper()
    require(
        signer == expected or (not signing_key.endswith("!") and primary == expected),
        "tag signature does not match the selected signing key",
    )
    require(
        git(repo, "rev-parse", f"{tag_object}^{{commit}}").decode().strip() == commit,
        "signed tag refers to another commit",
    )
    return signer


def verify_message(repo: Path, tag_object: str, version: str, message: bytes) -> None:
    header, body = git(repo, "cat-file", "tag", tag_object).split(b"\n\n", 1)
    require(f"tag {version}".encode() in header.splitlines(), "signed tag name differs")
    require(b"type commit" in header.splitlines(), "signed target must be a commit")
    payload = body.split(b"-----BEGIN PGP SIGNATURE-----", 1)[0]
    require(payload == message, "signed notes or input identity differ")


def signing_program(repo: Path) -> str:
    for setting in ("gpg.openpgp.program", "gpg.program"):
        result = subprocess.run(
            ["git", "config", "--get", setting], cwd=repo, capture_output=True, check=False
        )
        if result.returncode == 0:
            program = result.stdout.decode().strip()
            require(bool(program), "configured signing program is empty")
            return program
        require(result.returncode == 1, "cannot read signing program configuration")
    return "gpg"


def sign_object(repo: Path, version: str, commit: str, message: bytes, signing_key: str) -> str:
    tagger = git(repo, "var", "GIT_COMMITTER_IDENT").rstrip(b"\n")
    payload = (
        f"object {commit}\ntype commit\ntag {version}\ntagger ".encode()
        + tagger
        + b"\n\n"
        + message
    )
    signature = subprocess.run(
        [
            signing_program(repo),
            "--status-fd=2",
            "--armor",
            "--detach-sign",
            "--local-user",
            signing_key,
        ],
        input=payload,
        cwd=repo,
        capture_output=True,
        check=True,
    ).stdout
    # mktag writes an unreachable object, not a public tag ref. Verification comes first.
    return (
        subprocess.run(
            ["git", "mktag"], input=payload + signature, cwd=repo, capture_output=True, check=True
        )
        .stdout.decode()
        .strip()
    )


def create_tag(
    repo: Path, version: str, commit: str, signing_key: str, notes_path: Path
) -> dict[str, str]:
    require(
        SIGNING_KEY.fullmatch(signing_key) is not None,
        "signing-key must be a full OpenPGP fingerprint (optionally ending in !)",
    )
    tree = validate_inputs(repo, version, commit)
    message, notes_digest = tag_message(version, commit, tree, notes_path)
    tag_object = sign_object(repo, version, commit, message, signing_key)
    require(HEX_ID.fullmatch(tag_object) is not None, "invalid signed tag object ID")
    verify_message(repo, tag_object, version, message)
    signer = verify_tag(repo, tag_object, commit, signing_key)
    # Create only if absent, including a concurrent creator after input validation.
    git(repo, "update-ref", "--no-deref", f"refs/tags/{version}", tag_object, "0" * 40)
    return {
        "tag": version,
        "commit": commit,
        "tree": tree,
        "notes_sha256": notes_digest,
        "signature_fingerprint": signer,
        "tag_object": tag_object,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="explicit tag, such as v1.2.3-rc.1")
    parser.add_argument(
        "--commit", required=True, help="full commit SHA matching the clean checkout"
    )
    parser.add_argument(
        "--notes-file", required=True, type=Path, help="reviewed UTF-8 release notes"
    )
    parser.add_argument("--signing-key", required=True, help="authorized full OpenPGP fingerprint")
    arguments = parser.parse_args()
    try:
        repo = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip()).resolve()
        record = create_tag(
            repo, arguments.version, arguments.commit, arguments.signing_key, arguments.notes_file
        )
        print(json.dumps(record, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Release tag creation failed: {error}", file=sys.stderr)
        return 1
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
