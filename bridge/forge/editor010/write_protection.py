"""Working-copy and in-place-write protection with durable backup provenance."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .error_codes import ErrorCode
from .configuration import PRIVATE_ROOT


DEFAULT_DATA_ROOT = PRIVATE_ROOT
_StageWriter = Callable[[Path, bytes], None]


class WriteProtectionError(RuntimeError):
    """A controlled write-protection failure; the original target remains recoverable from backup."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code.value


@dataclass(frozen=True)
class FileState:
    path: Path
    sha256: str
    size_bytes: int

    def record(self) -> dict[str, str | int]:
        return {"path": str(self.path), "sha256": self.sha256, "size_bytes": self.size_bytes}

    @classmethod
    def from_path(cls, path: str | Path) -> "FileState":
        file_path = Path(path)
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return cls(path=file_path, sha256=digest.hexdigest(), size_bytes=file_path.stat().st_size)


@dataclass(frozen=True)
class WorkingCopyReceipt:
    original: FileState
    working_copy: FileState


@dataclass(frozen=True)
class InPlaceWriteReceipt:
    target: Path
    before: FileState
    after: FileState
    backup_path: Path
    backup: FileState
    changed: bool
    byte_delta: int


class WriteProtection:
    """Ensure original, working copy, backup, and derived state have explicit durable relationships."""

    def __init__(
        self,
        *,
        ledger_path: str | Path | None = None,
        backup_root: str | Path | None = None,
        stage_writer: _StageWriter | None = None,
    ) -> None:
        self.ledger_path = Path(ledger_path) if ledger_path is not None else DEFAULT_DATA_ROOT / "evidence" / "write-protection.jsonl"
        self.backup_root = Path(backup_root) if backup_root is not None else DEFAULT_DATA_ROOT / "backups"
        self._stage_writer = stage_writer or self._default_stage_writer

    def create_working_copy(self, original_path: str | Path, working_copy_path: str | Path) -> WorkingCopyReceipt:
        original = self._require_file(original_path, "original")
        working_copy = self._require_absolute_output(working_copy_path, "working copy")
        if original.path == working_copy:
            raise WriteProtectionError(ErrorCode.INVALID_REQUEST, "working copy must be distinct from original")
        if working_copy.exists():
            raise WriteProtectionError(ErrorCode.INVALID_REQUEST, "working copy path must not already exist")

        staging_path = self._new_stage_path(working_copy)
        try:
            shutil.copyfile(original.path, staging_path)
            self._fsync_file(staging_path)
            os.replace(staging_path, working_copy)
        except OSError as error:
            self._cleanup_stage(staging_path)
            self._append(
                {
                    "kind": "re_write_protection",
                    "operation": "create_working_copy",
                    "status": "failed",
                    "failure_stage": "copy_or_replace",
                    "original": original.record(),
                    "working_copy_path": str(working_copy),
                }
            )
            raise WriteProtectionError(ErrorCode.EVIDENCE_WRITE_FAILED, "working copy could not be created safely") from error

        result = FileState.from_path(working_copy)
        if result.sha256 != original.sha256:
            raise WriteProtectionError(ErrorCode.INTERNAL_ERROR, "working copy hash does not match the original")
        receipt = WorkingCopyReceipt(original=original, working_copy=result)
        self._append(
            {
                "kind": "re_write_protection",
                "operation": "create_working_copy",
                "status": "completed",
                "relationship": "working_copy_of",
                "original": original.record(),
                "working_copy": result.record(),
            }
        )
        return receipt

    def write_in_place(self, target_path: str | Path, content: bytes) -> InPlaceWriteReceipt:
        if not isinstance(content, bytes):
            raise WriteProtectionError(ErrorCode.INVALID_REQUEST, "in-place content must be bytes")
        before = self._require_file(target_path, "write target")
        self.backup_root.mkdir(parents=True, exist_ok=True)
        backup_path = self.backup_root / f"{before.path.name}.{before.sha256[:16]}.{secrets.token_hex(4)}.bak"
        try:
            shutil.copy2(before.path, backup_path)
            backup = FileState.from_path(backup_path)
        except OSError as error:
            raise WriteProtectionError(ErrorCode.EVIDENCE_WRITE_FAILED, "pre-write backup could not be created") from error
        if backup.sha256 != before.sha256:
            raise WriteProtectionError(ErrorCode.INTERNAL_ERROR, "pre-write backup hash does not match target")

        staging_path = self._new_stage_path(before.path)
        try:
            self._stage_writer(staging_path, content)
            staged = FileState.from_path(staging_path)
            expected_sha256 = hashlib.sha256(content).hexdigest()
            if staged.sha256 != expected_sha256:
                raise OSError("staged content hash mismatch")
            os.replace(staging_path, before.path)
        except OSError as error:
            self._cleanup_stage(staging_path)
            self._append(
                {
                    "kind": "re_write_protection",
                    "operation": "in_place_write",
                    "status": "failed",
                    "failure_stage": "staging",
                    "target_before": before.record(),
                    "backup_relationship": "backup_of",
                    "backup": backup.record(),
                }
            )
            raise WriteProtectionError(ErrorCode.EVIDENCE_WRITE_FAILED, "in-place content could not be staged safely") from error

        after = FileState.from_path(before.path)
        receipt = InPlaceWriteReceipt(
            target=before.path,
            before=before,
            after=after,
            backup_path=backup_path,
            backup=backup,
            changed=before.sha256 != after.sha256,
            byte_delta=after.size_bytes - before.size_bytes,
        )
        self._append(
            {
                "kind": "re_write_protection",
                "operation": "in_place_write",
                "status": "completed",
                "target_before": before.record(),
                "target_after": after.record(),
                "backup_relationship": "backup_of",
                "backup": backup.record(),
                "derived_relationship": "derived_from",
                "diff": {
                    "before_sha256": before.sha256,
                    "after_sha256": after.sha256,
                    "before_size_bytes": before.size_bytes,
                    "after_size_bytes": after.size_bytes,
                    "byte_delta": receipt.byte_delta,
                    "changed": receipt.changed,
                },
            }
        )
        return receipt

    def _append(self, record: dict[str, object]) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"recorded_at": datetime.now(timezone.utc).isoformat(), **record}
        try:
            with self.ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise WriteProtectionError(ErrorCode.EVIDENCE_WRITE_FAILED, "write-protection relationship could not be recorded") from error

    @staticmethod
    def _default_stage_writer(path: Path, content: bytes) -> None:
        with path.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _fsync_file(path: Path) -> None:
        with path.open("r+b") as handle:
            os.fsync(handle.fileno())

    @staticmethod
    def _cleanup_stage(path: Path) -> None:
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass

    @staticmethod
    def _new_stage_path(target_path: Path) -> Path:
        descriptor, raw_path = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".rea-forge-stage", dir=target_path.parent)
        os.close(descriptor)
        return Path(raw_path)

    @staticmethod
    def _require_file(path: str | Path, label: str) -> FileState:
        candidate = Path(path)
        if not candidate.is_absolute() or not candidate.is_file():
            raise WriteProtectionError(ErrorCode.INVALID_REQUEST, f"{label} must be an existing absolute file")
        return FileState.from_path(candidate)

    @staticmethod
    def _require_absolute_output(path: str | Path, label: str) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute() or not candidate.parent.is_dir():
            raise WriteProtectionError(ErrorCode.INVALID_REQUEST, f"{label} must have an existing absolute parent")
        return candidate
