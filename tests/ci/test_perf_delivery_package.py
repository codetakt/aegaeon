"""Controlled package/route regressions; these do not observe guest or cloud delivery."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.request import Request

import pytest
import validate_infrastructure as infra
from infrastructure_support.guest import GUEST_PACKAGE_ROOT, guest_sections, guest_sources
from infrastructure_support.orchestration import copy_module_inputs
from test_perf_runtime_delivery import MODULE, config

pytest_plugins = ["test_perf_runtime_delivery"]


@pytest.fixture
def aws_route(helper, tmp_path, monkeypatch):
    filesystem = helper.protected_path.__globals__
    route = tmp_path / "usr/bin/aws"
    route.parent.mkdir(parents=True)
    target = tmp_path / "usr/libexec/aws"
    target.parent.mkdir()
    target.write_text("controlled executable; never invoked")
    target.chmod(0o700)
    route.symlink_to("../libexec/aws")
    monkeypatch.setitem(filesystem, "OWNED_ROOT", tmp_path)
    monkeypatch.setitem(filesystem, "OWNER_UID", os.getuid())
    monkeypatch.setitem(filesystem, "AWS_REQUIRED_PATH", route)
    return route, target


def test_aws_fixed_route_resolves_relative_and_absolute_links(helper, aws_route):
    route, target = aws_route
    assert helper.aws_executable() == target
    route.unlink()
    route.symlink_to(target)
    assert helper.aws_executable() == target


def test_aws_parent_after_symlink_matches_kernel_route(helper, aws_route, tmp_path):
    route, _ = aws_route
    vendor = tmp_path / "opt/vendor"
    vendor.mkdir(parents=True)
    (tmp_path / "usr/route").symlink_to(vendor, target_is_directory=True)
    actual = tmp_path / "opt/tool"
    actual.write_text("actual resolved executable")
    actual.chmod(0o700)
    decoy = tmp_path / "usr/tool"
    decoy.write_text("lexical normalization would incorrectly select this")
    decoy.chmod(0o700)
    route.unlink()
    route.symlink_to("../route/../tool")
    assert helper.aws_executable() == actual
    assert route.resolve(strict=True) == actual


@pytest.mark.parametrize(
    "change", ["absent", "parent", "file", "execute", "loop", "directory", "fifo", "owner"]
)
def test_aws_required_route_fails_closed(helper, aws_route, change, monkeypatch):
    route, target = aws_route
    if change == "absent":
        target.unlink()
    elif change == "parent":
        target.parent.chmod(0o777)
    elif change == "file":
        target.chmod(0o722)
    elif change == "execute":
        target.chmod(0o600)
    elif change == "loop":
        target.unlink()
        target.symlink_to(route)
    elif change == "directory":
        target.unlink()
        target.mkdir()
    elif change == "fifo":
        target.unlink()
        os.mkfifo(target)
    else:
        monkeypatch.setitem(helper.protected_path.__globals__, "OWNER_UID", os.getuid() + 1)
    with pytest.raises((OSError, ValueError), match=r"."):
        helper.aws_executable()


def test_aws_does_not_skip_unsafe_parent_before_dotdot(helper, aws_route, tmp_path):
    route, target = aws_route
    unsafe = tmp_path / "usr/unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    route.unlink()
    route.symlink_to("../unsafe/../libexec/aws")
    assert route.resolve(strict=True) == target
    with pytest.raises(ValueError, match="unsafe AWS"):
        helper.aws_executable()


def test_aws_bad_symlink_owner_and_link_bound(helper, aws_route, monkeypatch):
    route, target = aws_route
    original = Path.lstat

    def metadata(path):
        result = original(path)
        if path == route:
            return types.SimpleNamespace(st_uid=os.getuid() + 1, st_mode=result.st_mode)
        return result

    with patch.object(Path, "lstat", metadata), pytest.raises(ValueError, match="unsafe AWS"):
        helper.aws_executable()
    monkeypatch.setitem(helper.protected_path.__globals__, "MAX_SYMLINKS", 1)
    second = target.parent / "second"
    second.symlink_to(target.name)
    route.unlink()
    route.symlink_to(second)
    with pytest.raises(ValueError, match="unsafe AWS"):
        helper.aws_executable()


def test_unsafe_aws_route_stops_before_secret_subprocess(helper):
    cfg = config()
    run = Mock()
    with (
        patch.dict(
            helper.retrieve.__globals__, aws_executable=Mock(side_effect=ValueError("unsafe AWS"))
        ),
        patch.object(helper.subprocess, "run", run),
        pytest.raises(ValueError, match="unsafe AWS"),
    ):
        helper.retrieve(
            "server",
            cfg["server_secret_arn"],
            cfg["server_secret_version"],
            cfg["region"],
            cfg["issuer_url"],
        )
    run.assert_not_called()


@pytest.mark.parametrize(
    "origin",
    [
        "https://issuer.example",
        "HTTPS://issuer.example/",
        "https://issuer.example:443",
        "https://[2001:db8::1]:8443/",
        "\x01 https://issuer.example",
        "https://iss\tuer.example",
        "https://iss\nuer.example",
    ],
)
def test_metrics_preserves_original_request_origin_domain(helper, tmp_path, origin):
    cfg = {
        **config(),
        "issuer_url": origin,
        "metrics_secret_arn": "fixture",
        "metrics_secret_version": "a" * 32,
    }
    opener = Mock()
    opener.open.side_effect = OSError("controlled transport refusal")
    with (
        patch.dict(
            helper.metrics.__globals__,
            prepare_directory=lambda _: None,
            retrieve=lambda *_: {"api_key": "aeg_synthetic"},
            build_opener=lambda *_: opener,
        ),
        pytest.raises(OSError, match="controlled transport refusal"),
    ):
        helper.metrics(cfg, tmp_path, tmp_path)
    request = opener.open.call_args.args[0]
    expected = Request(  # noqa: S310 -- guarded comparison construction; no transport
        helper.https_origin(origin) + "/api/v1/operations/metrics",
        headers={"Authorization": "Bearer aeg_synthetic"},
    )
    assert request.full_url == expected.full_url
    assert request.headers == expected.headers
    assert opener.open.call_args.kwargs == {"timeout": 30}
    assert json.loads((tmp_path / "metrics-status.json").read_text()) == {"status": "incomplete"}


@pytest.mark.parametrize(
    "origin",
    [
        "http://issuer.example",
        "https://user:password@issuer.example",
        "https://issuer.example/path",
        "https://issuer.example?query",
        "https://issuer.example#fragment",
        "https://",
    ],
)
def test_metrics_origin_rejection_precedes_transport(helper, tmp_path, origin):
    opener = Mock()
    cfg = {
        **config(),
        "issuer_url": origin,
        "metrics_secret_arn": "fixture",
        "metrics_secret_version": "a" * 32,
    }
    with (
        patch.dict(
            helper.metrics.__globals__,
            prepare_directory=lambda _: None,
            retrieve=lambda *_: {"api_key": "aeg_synthetic"},
            build_opener=lambda *_: opener,
        ),
        pytest.raises(ValueError, match="HTTPS origin"),
    ):
        helper.metrics(cfg, tmp_path, tmp_path)
    opener.open.assert_not_called()


@pytest.mark.parametrize("role", ["server", "loadgen"])
def test_installed_guest_closure_rejects_extra_and_each_changed_source(role):
    template = infra.source_template(MODULE, role)
    sections, _ = infra.template_sections(template)
    guest_sections(sections)
    with pytest.raises(ValueError, match="inventory"):
        guest_sections({**sections, GUEST_PACKAGE_ROOT + "extra.py": "pass\n"})
    for name in infra.DELIVERY_PACKAGE_SHA256:
        path = GUEST_PACKAGE_ROOT + name
        with pytest.raises(ValueError, match="Changed installed delivery source"):
            guest_sections({**sections, path: sections[path] + "\n"})


def test_guest_physical_closure_selection_and_copy(tmp_path):
    package = tmp_path / "perf-aws-ec2"
    shutil.copytree(MODULE, package)
    sources = guest_sources(package)
    assert len(sources) == 9
    copy = tmp_path / "scratch"
    copy.mkdir()
    copy_module_inputs(package, copy)
    assert guest_sources(copy) == sources
    for name in infra.DELIVERY_PACKAGE_SHA256:
        assert infra.select_modules(
            MODULE.parents[2], ["infra/tofu/perf-aws-ec2/runtime_delivery/" + name]
        ) == [MODULE]
    extra = package / "runtime_delivery/extra.py"
    extra.write_text("pass\n")
    with pytest.raises(ValueError, match="inventory"):
        guest_sources(package)
    with pytest.raises(ValueError, match="inventory"):
        infra.module_inputs(package)


@pytest.fixture
def guest_facade(tmp_path):
    """Controlled owner/root substitutions only; never an actual supplied guest artifact."""
    root = tmp_path / "controlled-guest"
    package = root / "usr/local/lib/aegaeon/runtime_delivery"
    package.mkdir(parents=True)
    executable = root / "usr/bin/aws"
    executable.parent.mkdir(parents=True)
    executable.write_text("controlled preflight target; never executed")
    executable.chmod(0o700)
    pins = {}
    for name in infra.DELIVERY_PACKAGE_SHA256:
        body = (MODULE / "runtime_delivery" / name).read_text()
        if name == "filesystem.py":
            body = body.replace("OWNER_UID = 0", "OWNER_UID = " + str(os.getuid()))
            body = body.replace(
                'OWNED_ROOT = Path("/")', "OWNED_ROOT = Path(" + repr(str(root)) + ")"
            )
            body = body.replace(
                'AWS_REQUIRED_PATH = Path("/usr/bin/aws")',
                "AWS_REQUIRED_PATH = Path(" + repr(str(executable)) + ")",
            )
        path = package / name
        path.write_text(body)
        path.chmod(0o400)
        pins[name] = hashlib.sha256(body.encode()).hexdigest()
    facade = root / "usr/local/bin/aegaeon-deliver-supplies"
    facade.parent.mkdir(parents=True)
    body = (MODULE / "delivery_helper.py").read_text()
    body = body.replace("OWNER_UID = 0", "OWNER_UID = " + str(os.getuid()))
    body = body.replace(
        'Path("/usr/local/lib/aegaeon/runtime_delivery")', "Path(" + repr(str(package)) + ")"
    )
    body = body.replace('current = Path("/")', "current = Path(" + repr(str(root)) + ")")
    body = body.replace("path.parts[1:]", "path.relative_to(Path(" + repr(str(root)) + ")).parts")
    for name, original in infra.DELIVERY_PACKAGE_SHA256.items():
        body = body.replace(original, pins[name])
    facade.write_text(body)
    facade.chmod(0o755)
    return facade, package


def invoke_facade(facade, *, isolated=True, cwd=None, env=None):
    return subprocess.run(  # noqa: S603 -- fixed controlled fixture facade; never AWS/cloud calls
        [sys.executable, *(["-I"] if isolated else []), "-B", str(facade), "preflight-aws"],
        capture_output=True,
        check=False,
        cwd=cwd,
        env=env,
        timeout=10,
    )


def assert_redacted(result):
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"performance supply delivery failed\n"


def test_isolated_facade_ignores_cwd_pythonpath_and_does_not_write_cache(guest_facade, tmp_path):
    facade, package = guest_facade
    shadow = tmp_path / "shadow/runtime_delivery"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text('raise RuntimeError("SENSITIVE_AMBIENT_CODE")\n')
    result = invoke_facade(
        facade, cwd=shadow.parent, env={**os.environ, "PYTHONPATH": str(shadow.parent)}
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""
    assert not list(package.glob("__pycache__"))
    assert_redacted(invoke_facade(facade, isolated=False))


@pytest.mark.parametrize("name", tuple(infra.DELIVERY_PACKAGE_SHA256))
def test_facade_rejects_every_changed_source_before_import(guest_facade, name):
    facade, package = guest_facade
    path = package / name
    path.chmod(0o600)
    path.write_text(path.read_text() + '\nraise RuntimeError("SENSITIVE_CHANGED_SOURCE")\n')
    path.chmod(0o400)
    assert_redacted(invoke_facade(facade))


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "missing",
        "symlink",
        "writable-source",
        "writable-parent",
        "facade-symlink",
        "wrong-owner",
    ],
)
def test_facade_rejects_unsafe_installed_closure(guest_facade, change):
    facade, package = guest_facade
    target = package / "common.py"
    if change == "extra":
        (package / "extra.py").write_text('raise RuntimeError("SENSITIVE_EXTRA_SOURCE")\n')
    elif change == "missing":
        target.unlink()
    elif change == "symlink":
        saved = package.parent / "saved-common.py"
        target.rename(saved)
        target.symlink_to(saved)
    elif change == "writable-source":
        target.chmod(0o422)
    elif change == "writable-parent":
        package.parent.chmod(0o777)
    elif change == "facade-symlink":
        saved = facade.parent / "saved-facade"
        facade.rename(saved)
        facade.symlink_to(saved)
    else:
        facade.write_text(
            facade.read_text().replace(
                "OWNER_UID = " + str(os.getuid()), "OWNER_UID = " + str(os.getuid() + 1)
            )
        )
    assert_redacted(invoke_facade(facade))


def test_verified_package_import_failure_is_redacted(guest_facade):
    facade, package = guest_facade
    target = package / "common.py"
    old = hashlib.sha256(target.read_bytes()).hexdigest()
    target.chmod(0o600)
    target.write_text(target.read_text() + '\nraise RuntimeError("SENSITIVE_IMPORT_ERROR")\n')
    target.chmod(0o400)
    new = hashlib.sha256(target.read_bytes()).hexdigest()
    facade.write_text(facade.read_text().replace(old, new))
    assert_redacted(invoke_facade(facade))


def test_no_redirect_callback_retains_keyword_and_positional_contract(helper):
    handler = helper.NoRedirect()
    assert handler.redirect_request(None, None, 302, "", {}, "https://different.example") is None
    assert (
        handler.redirect_request(
            req=None, fp=None, code=302, msg="", headers={}, newurl="https://different.example"
        )
        is None
    )


@pytest.mark.parametrize("suffix", ["/", "/."])
def test_aws_requires_actual_kernel_route_not_pathlib_normalization(helper, aws_route, suffix):
    route, target = aws_route
    route.unlink()
    route.symlink_to(str(target) + suffix)
    with pytest.raises(OSError, match="Not a directory"):
        route.stat()
    with pytest.raises(OSError, match="Not a directory"):
        helper.aws_executable()


def test_facade_rejects_preloaded_namespace_before_package_import(guest_facade):
    facade, _ = guest_facade
    scope = {"__name__": "controlled_facade_fixture", "__file__": str(facade)}
    exec(compile(facade.read_text(), str(facade), "exec"), scope)  # noqa: S102 -- trusted fixture source, never submitted data
    with (
        patch.dict(
            sys.modules,
            {"runtime_delivery.injected": types.ModuleType("runtime_delivery.injected")},
        ),
        pytest.raises(ValueError, match="preloaded delivery implementation"),
    ):
        scope["package_sources"]()


@pytest.mark.parametrize(
    "error",
    [
        ValueError("SENSITIVE_VALUE"),
        OSError("SENSITIVE_PATH"),
        subprocess.CalledProcessError(
            1, ["/fixture/aws"], output=b"SENSITIVE_SECRET", stderr=b"SENSITIVE_AWS_ERROR"
        ),
    ],
)
def test_public_dispatch_redacts_secret_bearing_failures(helper, capsys, error):
    with patch.dict(helper.main.__globals__, dispatch=Mock(side_effect=error)):
        assert helper.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "performance supply delivery failed\n"
