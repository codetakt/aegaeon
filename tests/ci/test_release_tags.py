"""Exercise release tagging in disposable Git repositories with private test keys."""
# All subprocesses use explicit argv and test-owned paths, never a shell.
# ruff: noqa: S603, S607

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/create_release.py"
SPEC = importlib.util.spec_from_file_location("release_tags", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
VERSION = "v1.2.3-rc.1"


def command(args, cwd, **kwargs):
    return subprocess.run(args, cwd=cwd, capture_output=True, check=True, **kwargs)


@pytest.fixture(scope="module")
def signing(tmp_path_factory):
    directory = tmp_path_factory.mktemp("release-test-gnupg")
    directory.chmod(0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GNUPG", "GPG_"))}
    env.update(GNUPGHOME=str(directory), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    try:
        command(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Release Test <release@example.invalid>",
                "ed25519",
                "sign",
                "1d",
            ],
            directory,
            env=env,
        )
        listing = command(["gpg", "--batch", "--with-colons", "--list-keys"], directory, env=env)
        fingerprint = next(
            line.split(":")[9]
            for line in listing.stdout.decode().splitlines()
            if line.startswith("fpr:")
        )
        command(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                fingerprint,
                "ed25519",
                "sign",
                "1d",
            ],
            directory,
            env=env,
        )
        yield env, fingerprint
    finally:
        command(["gpgconf", "--homedir", str(directory), "--kill", "gpg-agent"], directory, env=env)
        # pytest retains temporary directories; remove private key material explicitly.
        shutil.rmtree(directory)


@pytest.fixture
def repo(tmp_path, signing):
    env, fingerprint = signing
    source = tmp_path / "repo"
    source.mkdir()
    with patch.dict(os.environ, env, clear=True):
        command(["git", "init", "--quiet"], source)
        command(["git", "config", "user.name", "Release Test"], source)
        command(["git", "config", "user.email", "release@example.invalid"], source)
        command(["git", "config", "commit.gpgsign", "false"], source)
        command(["git", "config", "core.excludesfile", os.devnull], source)
        for crate in release.RELEASE_CRATES:
            manifest = source / f"crates/{crate}/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(f'[package]\nname = "aegaeon-{crate}"\nversion = "1.2.3-rc.1"\n')
        (source / "release-notes.txt").write_text(
            "Selected changes only.\nNo assurance claim is activated.\n"
        )
        command(["git", "add", "."], source)
        command(["git", "commit", "--quiet", "-m", "fixture"], source)
        assert b"release-notes.txt\n" in command(["git", "ls-files"], source).stdout
        commit = command(["git", "rev-parse", "HEAD"], source).stdout.decode().strip()
        yield source, commit, fingerprint


def invoke(repo, *extra):
    source, commit, fingerprint = repo
    return subprocess.run(
        [
            "bash",
            str(ROOT / "scripts/release/create_release.sh"),
            VERSION,
            "--commit",
            commit,
            "--signing-key",
            fingerprint + "!",
            "--notes-file",
            str(source / "release-notes.txt"),
            *extra,
        ],
        cwd=source,
        capture_output=True,
        check=False,
    )


def assert_no_tag(repo):
    assert command(["git", "tag", "--list"], repo[0]).stdout == b""


@pytest.mark.parametrize(
    "version", ["", "1.2.3", "-f", "v01.2.3", "v1.2.3-01", "v1.2.3/a", "v1.2.3\n", "v1.2.3;id"]
)
def test_invalid_version_has_no_side_effect(repo, version):
    source, commit, key = repo
    with pytest.raises(ValueError, match=r"SemVer|leading zeroes"):
        release.create_tag(source, version, commit, key, source / "release-notes.txt")
    assert_no_tag(repo)


def test_cli_requires_all_explicit_inputs(repo):
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/release/create_release.sh")],
        cwd=repo[0],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert_no_tag(repo)


def test_real_signed_tag_binds_commit_tree_notes_and_fingerprint(repo):
    result = invoke(repo)
    assert result.returncode == 0, result.stderr.decode()
    receipt = json.loads(result.stdout)
    source, commit, key = repo
    assert receipt["commit"] == commit
    assert (
        receipt["tree"]
        == command(["git", "rev-parse", "HEAD^{tree}"], source).stdout.decode().strip()
    )
    assert receipt["signature_fingerprint"] == key
    assert (
        receipt["notes_sha256"]
        == hashlib.sha256((source / "release-notes.txt").read_bytes()).hexdigest()
    )
    command(["git", "verify-tag", VERSION], source)
    tag = command(["git", "cat-file", "tag", receipt["tag_object"]], source).stdout
    assert b"Source-Commit: " + commit.encode() in tag
    assert (source / "release-notes.txt").read_bytes() in tag
    assert b"comprehensive RFC compliance" not in tag
    assert command(["git", "remote"], source).stdout == b""


@pytest.mark.parametrize("change", ["tracked", "staged", "untracked"])
def test_dirty_checkout_is_rejected(repo, change):
    source = repo[0]
    path = source / ("release-notes.txt" if change != "untracked" else "extra.txt")
    path.write_text("changed\n")
    if change == "staged":
        command(["git", "add", "."], source)
    result = invoke(repo)
    assert result.returncode == 1
    assert b"clean checkout" in result.stderr
    assert_no_tag(repo)


def test_head_must_equal_full_explicit_commit(repo):
    for commit in (repo[1][:12], "0" * 40):
        result = invoke(repo, "--commit", commit)
        assert result.returncode == 1
    assert_no_tag(repo)


def test_dependency_version_does_not_satisfy_package_version(repo):
    source = repo[0]
    path = source / "crates/server/Cargo.toml"
    path.write_text(
        '[package]\nname = "aegaeon-server"\nversion = "0.1.0"\n'
        '[dependencies]\nother = { version = "1.2.3-rc.1" }\n'
    )
    command(["git", "commit", "-am", "different package version"], source)
    commit = command(["git", "rev-parse", "HEAD"], source).stdout.decode().strip()
    result = invoke(repo, "--commit", commit)
    assert result.returncode == 1
    assert b"package.version mismatch: server" in result.stderr
    assert_no_tag(repo)


def test_existing_tag_is_unchanged(repo):
    command(["git", "tag", VERSION], repo[0])
    before = command(["git", "rev-parse", "refs/tags/" + VERSION], repo[0]).stdout
    result = invoke(repo)
    assert result.returncode == 1
    assert b"tag already exists" in result.stderr
    assert command(["git", "rev-parse", "refs/tags/" + VERSION], repo[0]).stdout == before


@pytest.mark.parametrize(
    "notes", [b"", b" \n", b"bad\x00notes", b"\xff", b"-----BEGIN PGP SIGNATURE-----"]
)
def test_invalid_notes_do_not_create_tag(repo, tmp_path, notes):
    path = tmp_path / "invalid-notes.md"
    path.write_bytes(notes)
    result = invoke(repo, "--notes-file", str(path))
    assert result.returncode == 1
    assert_no_tag(repo)


def test_missing_notes_do_not_create_tag(repo, tmp_path):
    result = invoke(repo, "--notes-file", str(tmp_path / "absent"))
    assert result.returncode == 1
    assert_no_tag(repo)


@pytest.mark.parametrize("key", ["short", "0" * 40])
def test_missing_key_fails_without_unsigned_fallback(repo, key):
    result = invoke(repo, "--signing-key", key)
    assert result.returncode == 1
    assert_no_tag(repo)


def test_verification_failure_publishes_no_tag(repo):
    source, commit, key = repo
    with (
        patch.object(release, "verify_tag", side_effect=ValueError("verification failed")),
        pytest.raises(ValueError, match="verification failed"),
    ):
        release.create_tag(source, VERSION, commit, key, source / "release-notes.txt")
    assert_no_tag(repo)


def test_publication_does_not_replace_concurrently_created_tag(repo):
    source, commit, key = repo

    verifier = release.verify_tag

    def replace_ref(*args):
        signer = verifier(*args)
        command(["git", "update-ref", "refs/tags/" + VERSION, commit], source)
        return signer

    with (
        patch.object(release, "verify_tag", side_effect=replace_ref),
        pytest.raises(subprocess.CalledProcessError),
    ):
        release.create_tag(source, VERSION, commit, key, source / "release-notes.txt")
    assert (
        command(["git", "rev-parse", "refs/tags/" + VERSION], source).stdout.decode().strip()
        == commit
    )


def test_real_signature_rejects_wrong_selected_key_or_target(repo):
    receipt = json.loads(invoke(repo).stdout)
    with pytest.raises(ValueError, match="selected signing key"):
        release.verify_tag(repo[0], receipt["tag_object"], repo[1], "0" * 40)
    with pytest.raises(ValueError, match="another commit"):
        release.verify_tag(repo[0], receipt["tag_object"], "0" * 40, repo[2])


def test_signed_payload_must_match_requested_notes_and_tag(repo):
    receipt = json.loads(invoke(repo).stdout)
    with pytest.raises(ValueError, match="notes or input identity"):
        release.verify_message(repo[0], receipt["tag_object"], VERSION, b"changed notes\n")
    with pytest.raises(ValueError, match="tag name differs"):
        release.verify_message(repo[0], receipt["tag_object"], "v9.9.9", b"changed notes\n")


def test_notes_without_final_newline_keep_original_digest(repo, tmp_path):
    notes = tmp_path / "no-newline.txt"
    notes.write_bytes(b"Selected release notes")
    result = invoke(repo, "--notes-file", str(notes))
    assert result.returncode == 0, result.stderr.decode()
    assert (
        json.loads(result.stdout)["notes_sha256"] == hashlib.sha256(notes.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("version", ["v1.2.3", "v0.0.0-0", "v1.2.3-rc.1+build.01"])
def test_valid_semver(version):
    release.validate_version(version)


@pytest.mark.parametrize("status", ["missing", "multiple", "expired", "revoked"])
def test_verification_status_must_be_one_usable_signature(repo, status):
    key = repo[2]
    valid = f"[GNUPG:] VALIDSIG {key} 2026-09-16 1 0 4 0 22 8 00 {key}\n".encode()
    records = {
        "missing": b"[GNUPG:] GOODSIG fixture\n",
        "multiple": valid + valid,
        "expired": valid + b"[GNUPG:] EXPKEYSIG fixture\n",
        "revoked": valid + b"[GNUPG:] REVKEYSIG fixture\n",
    }
    result = subprocess.CompletedProcess([], 0, stdout=b"", stderr=records[status])
    with (
        patch.object(release.subprocess, "run", return_value=result),
        pytest.raises(ValueError, match=r"one valid|expired, revoked"),
    ):
        release.verify_tag(repo[0], "0" * 40, repo[1], key)


def test_primary_fingerprint_can_select_its_signing_subkey(repo):
    result = invoke(repo, "--signing-key", repo[2])
    assert result.returncode == 0, result.stderr.decode()
    receipt = json.loads(result.stdout)
    assert receipt["signature_fingerprint"] != repo[2]
    with pytest.raises(ValueError, match="selected signing key"):
        release.verify_tag(repo[0], receipt["tag_object"], repo[1], repo[2] + "!")


def test_dangling_symbolic_tag_cannot_redirect_creation_into_a_branch(repo):
    source, commit, key = repo
    verifier = release.verify_tag
    tag = "refs/tags/" + VERSION
    branch = "refs/heads/must-stay-absent"

    def create_symbolic_ref(*args):
        signer = verifier(*args)
        command(["git", "symbolic-ref", tag, branch], source)
        return signer

    with (
        patch.object(release, "verify_tag", side_effect=create_symbolic_ref),
        pytest.raises(subprocess.CalledProcessError),
    ):
        release.create_tag(source, VERSION, commit, key, source / "release-notes.txt")
    assert command(["git", "symbolic-ref", tag], source).stdout.decode().strip() == branch
    result = subprocess.run(
        ["git", "show-ref", "--verify", branch], cwd=source, capture_output=True, check=False
    )
    assert result.returncode != 0
