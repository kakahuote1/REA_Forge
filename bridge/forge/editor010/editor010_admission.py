"""Static admission rules for the fixed local 010 Editor 16.0.2 runtime.

This module deliberately does not start 010 Editor.  The later bridge must use
these checks before it can copy a file, template, or script into a token-bound
session or construct a fixed no-UI invocation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from common.hard_deny_policy import HardDenyPolicy
from .configuration import read_configuration


_MAX_INPUT_BYTES = 256 * 1024 * 1024
_MAX_ASSET_BYTES = 1024 * 1024
_ALLOWED_ASSET_SUFFIXES = frozenset({".bt", ".1sc"})


class EditorAdmissionError(RuntimeError):
    """A typed, non-secret admission failure for the 010 Editor bridge."""


@dataclass(frozen=True)
class AdmittedFile:
    path: Path
    sha256: str
    size_bytes: int
    is_pe: bool

    def record(self) -> dict[str, str | int | bool]:
        return {"path": str(self.path), "sha256": self.sha256, "size_bytes": self.size_bytes, "is_pe": self.is_pe}


@dataclass(frozen=True)
class AdmittedAsset:
    path: Path
    sha256: str
    size_bytes: int
    kind: str

    def record(self) -> dict[str, str | int]:
        return {"path": str(self.path), "sha256": self.sha256, "size_bytes": self.size_bytes, "kind": self.kind}


class EditorAdmission:
    """Admit the operator-pinned binary and explicit input/asset roots."""

    def __init__(self, *, policy: HardDenyPolicy | None = None) -> None:
        self.policy = policy or HardDenyPolicy()
        self.configuration = read_configuration()

    def executable(self) -> Path:
        executable = self.configuration.executable
        self.policy.require_local_path(executable)
        if not executable.is_file() or self._sha256(executable) != self.configuration.executable_sha256:
            raise EditorAdmissionError("fixed 010 Editor executable identity drifted")
        return executable

    def input_file(self, value: str | Path) -> AdmittedFile:
        self.policy.require_local_path(value)
        path = Path(value).resolve(strict=True)
        self._require_re_file(path, _MAX_INPUT_BYTES, "input")
        return AdmittedFile(path=path, sha256=self._sha256(path), size_bytes=path.stat().st_size, is_pe=self._is_pe(path))

    def asset_file(self, value: str | Path, *, allow_builtin: bool = True) -> AdmittedAsset:
        self.policy.require_local_path(value)
        path = Path(value).resolve(strict=True)
        suffix = path.suffix.casefold()
        if suffix not in _ALLOWED_ASSET_SUFFIXES:
            raise EditorAdmissionError("010 asset must be a .bt or .1sc file")
        roots = [root.resolve() for root in self.configuration.asset_roots]
        if allow_builtin:
            roots.append((self.configuration.executable.parent / "Data").resolve())
        if not any(self._under(path, root) for root in roots):
            raise EditorAdmissionError("010 asset escaped its admitted local roots")
        if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_ASSET_BYTES:
            raise EditorAdmissionError("010 asset is not an admitted bounded regular local file")
        return AdmittedAsset(path=path, sha256=self._sha256(path), size_bytes=path.stat().st_size, kind="template" if suffix == ".bt" else "script")

    @staticmethod
    def require_non_pe_write(file: AdmittedFile) -> None:
        if file.is_pe:
            raise EditorAdmissionError("010 Editor must not write MZ/PE input; route PE mutation to IDA")

    @staticmethod
    def _is_pe(path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                header = handle.read(64)
                if len(header) < 64 or header[:2] != b"MZ":
                    return False
                pe_offset = int.from_bytes(header[60:64], "little")
                if pe_offset < 64 or pe_offset > path.stat().st_size - 4:
                    return True
                handle.seek(pe_offset)
                return handle.read(4) == b"PE\0\0"
        except OSError as error:
            raise EditorAdmissionError("010 input could not be classified") from error

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _under(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _require_re_file(self, path: Path, limit: int, label: str) -> None:
        if not any(self._under(path, root.resolve()) for root in self.configuration.input_roots):
            raise EditorAdmissionError(f"010 {label} escaped the operator-selected input roots")
        if not path.is_file() or path.is_symlink() or path.stat().st_size > limit:
            raise EditorAdmissionError(f"010 {label} is not an admitted bounded regular local file")
