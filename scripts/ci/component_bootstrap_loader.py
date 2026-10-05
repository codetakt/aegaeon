"""Retained exclusive source projection and fixed isolated-import seam.

Only authenticate_and_project acquires original input authority. Filesystem
controls and fixture import success establish neither readonly mounts, native
execution admission nor a production original-service/runtime implementation.
"""

from __future__ import annotations

import builtins
import importlib.abc
import importlib.util
import os
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.machinery import BuiltinImporter, FrozenImporter, PathFinder
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from component_bootstrap_origin import (
    path_parts,
    require,
    verify_original_sources,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from importlib.machinery import ModuleSpec
    from pathlib import Path
    from types import ModuleType

    from component_bootstrap_origin import BootstrapPremises, OriginalRead, VerifiedSources

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
WRITE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
PROJECTION_NAME = "bootstrap-package"
Identity = tuple[int, ...]


def _identity(info: os.stat_result) -> Identity:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _anchor_identity(info: os.stat_result) -> Identity:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


@dataclass(frozen=True)
class _Entry:
    descriptor: int
    identity: Identity


class RetainedProjection:
    """FD-retained exact projection; no existing destination is repaired."""

    def __init__(self, original: VerifiedSources, parent: Path) -> None:
        self.original = original
        self.root = parent / PROJECTION_NAME
        self._anchors: list[tuple[int, str, int, Identity]] = []
        self._owned: list[int] = []
        self._directories: dict[str, _Entry] = {}
        self._files: dict[str, _Entry] = {}
        self._closed = False
        contents = {"source/" + name: raw for name, raw in original.sources.items()}
        contents["authority/pr-policy.json"] = original.policy
        contents["authority/component-release.json"] = original.descriptor
        self._contents = MappingProxyType(contents)
        try:
            self._create(parent)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def _open(self, name: str, flags: int, parent: int | None = None) -> int:
        descriptor = os.open(name, flags, dir_fd=parent)
        self._owned.append(descriptor)
        return descriptor

    def _create(self, parent: Path) -> None:  # noqa: PLR0915 - ordered exclusive writes/fsync
        self.original.premises.verify()
        require(
            parent.is_absolute() and ".." not in parent.parts, "absolute original parent required"
        )
        root_anchor = self._open("/", DIRECTORY_FLAGS)
        current = root_anchor
        for part in parent.parts[1:]:
            following = self._open(part, DIRECTORY_FLAGS, current)
            self._anchors.append((current, part, following, _anchor_identity(os.fstat(following))))
            current = following
        os.mkdir(PROJECTION_NAME, mode=0o700, dir_fd=current)
        root = self._open(PROJECTION_NAME, DIRECTORY_FLAGS, current)
        self._anchors.append((current, PROJECTION_NAME, root, _anchor_identity(os.fstat(root))))
        directories: dict[str, int] = {"": root}
        for name in sorted(self._contents):
            parts = path_parts(name)
            for depth in range(1, len(parts)):
                path = "/".join(parts[:depth])
                if path not in directories:
                    parent_fd = directories["/".join(parts[: depth - 1])]
                    os.mkdir(parts[depth - 1], mode=0o700, dir_fd=parent_fd)
                    directories[path] = self._open(parts[depth - 1], DIRECTORY_FLAGS, parent_fd)
            directory = directories["/".join(parts[:-1])]
            descriptor = os.open(parts[-1], WRITE_FLAGS, 0o600, dir_fd=directory)
            self._owned.append(descriptor)
            raw = self._contents[name]
            remaining = memoryview(raw)
            while remaining:
                written = os.write(descriptor, remaining)
                require(written > 0, "exclusive source write stalled")
                remaining = remaining[written:]
            original_name = name.removeprefix("source/")
            mode = 0o555 if self.original.modes.get(original_name) == "100755" else 0o444
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            original_identity = _identity(os.fstat(descriptor))
            readonly = self._open(parts[-1], READ_FLAGS, directory)
            require(
                original_identity
                == _identity(os.fstat(readonly))
                == _identity(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)),
                "exclusive source changed during readonly FD handoff",
            )
            os.close(descriptor)
            self._owned.remove(descriptor)
            self._files[name] = _Entry(readonly, original_identity)
        for name in sorted(directories, key=lambda value: value.count("/"), reverse=True):
            os.fchmod(directories[name], 0o555)
            os.fsync(directories[name])
        for name, descriptor in directories.items():
            self._directories[name] = _Entry(descriptor, _identity(os.fstat(descriptor)))
        # chmod changed only the final root mode; retain the resulting original.
        prior, name, descriptor, _ = self._anchors[-1]
        self._anchors[-1] = (prior, name, descriptor, _anchor_identity(os.fstat(descriptor)))
        for parent_fd, _, _, _ in self._anchors:
            os.fsync(parent_fd)

    def recheck(self) -> None:
        """Recheck held FDs, all ancestor links and the complete named domain."""
        require(not self._closed, "original source projection closed")
        self.original.premises.verify()
        for parent, name, descriptor, identity in self._anchors:
            require(
                _anchor_identity(os.fstat(descriptor))
                == identity
                == _anchor_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                "original projection ancestor replaced",
            )
        for name, entry in {**self._directories, **self._files}.items():
            require(
                _identity(os.fstat(entry.descriptor)) == entry.identity,
                "retained original entry identity changed",
            )
            if name:
                parts = path_parts(name)
                parent = self._directories["/".join(parts[:-1])].descriptor
                require(
                    _identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
                    == entry.identity,
                    "named original entry replaced",
                )
        for name, entry in self._directories.items():
            prefix = name + "/" if name else ""
            expected = {
                path.removeprefix(prefix).split("/")[0]
                for path in {*self._directories, *self._files}
                if path.startswith(prefix) and path != name
            }
            require(
                set(os.listdir(entry.descriptor)) == expected,  # noqa: PTH208 - retain checked FD
                "complete projection entry domain differs",
            )
        for name, entry in self._files.items():
            raw = self._contents[name]
            require(
                stat.S_ISREG(os.fstat(entry.descriptor).st_mode)
                and os.fstat(entry.descriptor).st_nlink == 1
                and os.pread(entry.descriptor, len(raw) + 1, 0) == raw,
                "whole original retained source readback differs",
            )
        self.original.premises.verify()

    def source_bytes(self, path: str) -> bytes:
        self.recheck()
        name = "source/" + path
        require(name in self._files, "unadmitted source module path")
        raw = self._contents[name]
        observed = os.pread(self._files[name].descriptor, len(raw) + 1, 0)
        require(observed == raw, "source changed at load boundary")
        self.recheck()
        return observed

    def close(self) -> None:
        """Close handles; preserve successful or failed owned filesystem state."""
        if not self._closed:
            self._closed = True
            for descriptor in reversed(self._owned):
                os.close(descriptor)


def authenticate_and_project(
    reader: OriginalRead, premises: BootstrapPremises, policy: bytes, parent: Path
) -> RetainedProjection:
    original = verify_original_sources(reader, premises, policy)
    return RetainedProjection(original, parent)


class _FixedLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, projection: RetainedProjection, modules: Mapping[str, str]) -> None:
        self.projection = projection
        self.modules = MappingProxyType(dict(modules))
        self.loaded: dict[str, ModuleType] = {}
        self.original_meta_path = tuple(sys.meta_path)

    def verify_import_state(self) -> None:
        premises = self.projection.original.premises
        self.projection.recheck()
        require(
            sys.flags.isolated == 1
            and sys.executable == premises.interpreter
            and tuple(sys.path) == premises.runtime_import_paths
            and tuple(sys.meta_path) == (self, *self.original_meta_path),
            "fixed isolated runtime/import roots differ",
        )

    def _import(
        self,
        name: str,
        globals: dict[str, Any] | None = None,  # noqa: A002 - exact Python __import__ protocol
        locals: dict[str, Any] | None = None,  # noqa: A002 - exact Python __import__ protocol
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> Any:  # noqa: ANN401 - Python's fixed __import__ protocol
        self.verify_import_state()
        absolute = name
        if level:
            require(
                globals is not None and type(globals.get("__package__")) is str,
                "closed relative package unavailable",
            )
            namespace = cast("dict[str, Any]", globals)
            absolute = importlib.util.resolve_name("." * level + name, namespace["__package__"])
        require(
            absolute in self.modules
            or absolute.split(".")[0] in sys.stdlib_module_names
            or absolute.split(".")[0] in self.projection.original.premises.runtime_packages,
            "import outside independently fixed source/runtime domain",
        )
        return builtins.__import__(name, globals, locals, fromlist, level)

    def find_spec(
        self, fullname: str, path: Sequence[str] | None, target: ModuleType | None = None
    ) -> ModuleSpec | None:
        self.verify_import_state()
        if fullname not in self.modules:
            return None
        require(
            target is None and (path is None or not path),
            "candidate reload or nonvirtual package route rejected",
        )
        source = self.modules[fullname]
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=str(self.projection.root / "source" / source),
            is_package=source.endswith("/__init__.py"),
        )

    def create_module(self, spec: ModuleSpec) -> ModuleType | None:
        require(spec.name in self.modules, "unadmitted module creation")
        return None

    def exec_module(self, module: ModuleType) -> None:
        self.verify_import_state()
        path = self.modules[module.__name__]
        raw = self.projection.source_bytes(path)
        filename = str(self.projection.root / "source" / path)
        code = compile(raw, filename, "exec", dont_inherit=True)
        self.verify_import_state()
        module.__file__ = filename
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": self._import}
        # Package paths are virtual: all local imports go through this fixed map.
        if path.endswith("/__init__.py"):
            module.__path__ = []
        self.loaded[module.__name__] = module
        exec(code, module.__dict__)  # noqa: S102 - only authenticated retained source bytes
        self.verify_import_state()


@contextmanager
def load_admitted_entry(
    projection: RetainedProjection,
) -> Iterator[ModuleType]:
    """Load a fixed protected module map in the independently isolated runtime.

    Module map/entry come from retained protected premises, never the descriptor.
    This seam does not launch consumers, assign NativeAdmission, or bypass richer
    S installer admissions. Invoke that richer installer within this scope so
    lazy source imports retain the same loader and original identity checks.
    A clean independently admitted process is required; FD closure is explicit.
    """
    premises = projection.original.premises
    modules, entry = dict(premises.module_map), premises.entrypoint
    require(
        tuple(sys.meta_path) == (BuiltinImporter, FrozenImporter, PathFinder),
        "ambient or unadmitted runtime import finder",
    )
    for name, path in modules.items():
        require(
            all(part.isidentifier() for part in name.split("."))
            and name.split(".")[0] not in sys.stdlib_module_names
            and name not in sys.modules
            and path in projection.original.sources
            and path.endswith(".py"),
            "ambient collision or unadmitted module map",
        )
    loader = _FixedLoader(projection, modules)
    sys.meta_path.insert(0, loader)
    try:
        loader.verify_import_state()
        result = importlib.import_module(entry)
        loader.verify_import_state()
        yield result
        loader.verify_import_state()
    finally:
        try:
            loader.verify_import_state()
        finally:
            sys.meta_path[:] = loader.original_meta_path
            for name, module in loader.loaded.items():
                if sys.modules.get(name) is module:
                    del sys.modules[name]
