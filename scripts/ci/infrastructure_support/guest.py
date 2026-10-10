"""Fixed guest package input, interpolation and installed-source contracts."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from infrastructure_support.common import (
    DELIVERY_BODY_SHA256,
    DELIVERY_PACKAGE_FIELDS,
    DELIVERY_PACKAGE_SHA256,
    require,
)

if TYPE_CHECKING:
    from pathlib import Path

GUEST_PACKAGE_ROOT = "/usr/local/lib/aegaeon/runtime_delivery/"


def guest_sources(module: Path) -> dict[str, str]:
    """Read only the complete reviewed physical guest source closure."""
    helper_path = module / "delivery_helper.py"
    require(
        helper_path.is_file() and not helper_path.is_symlink(), "Missing shared delivery helper"
    )
    helper = helper_path.read_bytes().decode("utf-8")
    require(
        hashlib.sha256(helper.encode()).hexdigest() == DELIVERY_BODY_SHA256,
        "Changed strict runtime supply executable",
    )
    package = module / "runtime_delivery"
    require(package.is_dir() and not package.is_symlink(), "Missing fixed delivery package")
    require(
        {entry.name for entry in package.iterdir()} == set(DELIVERY_PACKAGE_SHA256),
        "Changed fixed delivery package inventory",
    )
    sources = {"delivery_helper": helper}
    for field, name in DELIVERY_PACKAGE_FIELDS.items():
        path = package / name
        require(path.is_file() and not path.is_symlink(), "Unsafe delivery package source: " + name)
        raw = path.read_bytes()
        require(
            hashlib.sha256(raw).hexdigest() == DELIVERY_PACKAGE_SHA256[name],
            "Changed delivery package source: " + name,
        )
        sources[field] = raw.decode("utf-8")
    return sources


def source_template(module: Path, role: str) -> str:
    """Bind each fixed physical guest source at its sole active heredoc."""
    require(role in {"server", "loadgen"}, "Unknown performance template role")
    sources = guest_sources(module)
    template = (module / ("user_data_" + role + ".sh.tftpl")).read_text()
    paths = {"delivery_helper": "/usr/local/bin/aegaeon-deliver-supplies"}
    paths.update(
        {field: GUEST_PACKAGE_ROOT + name for field, name in DELIVERY_PACKAGE_FIELDS.items()}
    )
    for field, path in paths.items():
        marker = "cat >" + path + " <<'PYTHON'\n${" + field + "~}\nPYTHON\n"
        require(
            template.count(marker) == 1, "Changed fixed guest source template binding: " + field
        )
        require(template.count(field) == 1, "Duplicate guest source interpolation: " + field)
        template = template.replace("${" + field + "~}\n", sources[field], 1)
    return template


def guest_sections(sections: dict[str, str]) -> dict[str, str]:
    """Verify the complete code actually installed by either rendered role."""
    require(
        {path for path in sections if path.startswith(GUEST_PACKAGE_ROOT)}
        == {GUEST_PACKAGE_ROOT + name for name in DELIVERY_PACKAGE_SHA256},
        "Changed installed delivery package inventory",
    )
    helper = sections.get("/usr/local/bin/aegaeon-deliver-supplies", "")
    require(
        hashlib.sha256(helper.encode()).hexdigest() == DELIVERY_BODY_SHA256,
        "Changed strict runtime supply executable",
    )
    package = {}
    for name, expected in DELIVERY_PACKAGE_SHA256.items():
        raw = sections.get(GUEST_PACKAGE_ROOT + name, "")
        require(
            hashlib.sha256(raw.encode()).hexdigest() == expected,
            "Changed installed delivery source: " + name,
        )
        package[name] = raw
    return package
