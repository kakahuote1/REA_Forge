"""Bounded project snapshots: copied inputs, fresh outputs, no borrowed edits."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile

from common.hard_deny_policy import HardDenyPolicy
from common.static_files import bounded_file, identity, read_json, sha256_file
from common.paths import PRIVATE_ROOT

WORK = PRIVATE_ROOT / "work" / "android-build"
MAX_FILES, MAX_BYTES = 30000, 256 * 1024 * 1024


def relative(raw: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 1024 or any(ord(char) < 32 or char in '\\:<>"|?*' for char in raw):
        raise ValueError("requires a bounded relative project path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {".", "..", ""} or part.endswith((".", " ")) for part in raw.split("/")):
        raise ValueError("project path escaped its owner or loses Windows identity")
    for part in path.parts:
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL", *["COM" + str(i) for i in range(1, 10)], *["LPT" + str(i) for i in range(1, 10)]}:
            raise ValueError("project path names a reserved Windows object")
    return path.as_posix()


def regular(path: Path, *, directory: bool = False) -> None:
    state = path.lstat()
    if getattr(state, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0) or path.is_symlink():
        raise ValueError("project entries cannot be reparse points or symbolic links")
    if not (stat.S_ISDIR(state.st_mode) if directory else stat.S_ISREG(state.st_mode)):
        raise ValueError("project entry has an unsupported filesystem type")


def tree(root: Path) -> dict:
    regular(root, directory=True)
    files, folders, total, count, names = [], [], 0, 0, set()
    for parent, directories, leaves in os.walk(root, followlinks=False):
        for name in [*directories, *leaves]:
            item = Path(parent) / name
            count += 1
            if count > MAX_FILES:
                raise ValueError("Android project exceeds entry count bound")
            key = relative(item.relative_to(root).as_posix())
            if key.casefold() in names:
                raise ValueError("Android project has case-colliding paths")
            names.add(key.casefold())
            regular(item, directory=name in directories)
            if name in directories:
                folders.append(key)
            if name in leaves:
                total += item.stat().st_size
                if total > MAX_BYTES:
                    raise ValueError("Android project exceeds aggregate byte bound")
                files.append({"relative_path": key, "sha256": sha256_file(item), "size_bytes": item.stat().st_size})
    files.sort(key=lambda value: value["relative_path"])
    folders.sort()
    encoded = json.dumps({"files": files, "directories": folders}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return {"root": str(root), "sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": total, "file_count": len(files), "entry_count": count,
            "files": files, "directories": folders, "digest_kind": "sorted-relative-directories-and-file-sha256-size-json"}


def copy_tree(root: Path, destination: Path) -> dict:
    before = tree(root)
    destination.mkdir()
    for folder in before["directories"]:
        (destination / folder).mkdir(parents=True, exist_ok=True)
    for item in before["files"]:
        output = destination / item["relative_path"]
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / item["relative_path"], output)
    if tree(root)["sha256"] != before["sha256"] or tree(destination)["sha256"] != before["sha256"]:
        raise ValueError("Android project changed during copied snapshot")
    return before


def input_directory(raw: str, selected: dict) -> Path:
    path = Path(raw)
    HardDenyPolicy().require_local_path(path)
    if not path.is_absolute():
        raise ValueError("project input must be an absolute local directory")
    regular(path, directory=True)
    path = path.resolve(strict=True)
    if not any(path.is_relative_to(Path(root).resolve(strict=True)) for root in selected["input_roots"]):
        raise ValueError("project input is outside configured roots")
    return path


def validate_apk(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= MAX_FILES:
            raise ValueError("APK exceeds entry count bound")
        names, total = set(), 0
        for entry in entries:
            name = relative(entry.filename.removesuffix("/")).casefold()
            if name in names or entry.flag_bits & 1 or stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("APK contains an ambiguous, encrypted or symlink entry")
            names.add(name)
            total += entry.file_size
            if total > MAX_BYTES:
                raise ValueError("APK declared expansion exceeds project byte bound")
        if "androidmanifest.xml" not in names:
            raise ValueError("APK has no AndroidManifest.xml")


def load_receipt(values: dict, kinds: set[str] | None = None) -> tuple[Path, dict]:
    path = bounded_file(values["receipt_path"], 16 * 1024 * 1024)
    if not path.is_relative_to(WORK.resolve(strict=True)) or sha256_file(path) != values["receipt_sha256"]:
        raise ValueError("Android receipt changed or escaped retained work")
    record = read_json(path, 16 * 1024 * 1024)
    if record.get("kind") not in (kinds or {"android-project", "android-dex", "android-signature"}):
        raise ValueError("receipt does not identify the required Android artifact")
    if "project" in record:
        root = Path(record["project"]["root"])
        if root.parent != path.parent or tree(root)["sha256"] != record["project"]["sha256"]:
            raise ValueError("Android project changed or escaped receipt ownership; explicitly import edited work as a new snapshot")
    return path, record


def edits(root: Path, changes: list, workspace: Path) -> list:
    if not isinstance(changes, list) or len(changes) > 64:
        raise ValueError("invalid Android text change set")
    diffs = []
    for index, change in enumerate(changes):
        name = relative(change["relative_path"])
        path = bounded_file(root / name, 1024 * 1024)
        if not path.is_relative_to(root) or path.suffix not in {".smali", ".xml", ".json", ".txt", ".properties"}:
            raise ValueError("only ordinary project text assets can be changed")
        if sha256_file(path) != change["expected_sha256"]:
            raise ValueError("Android text change expected a different file identity")
        old, new = change["old_text"], change["new_text"]
        if not isinstance(old, str) or not isinstance(new, str) or not old or old == new or max(len(old), len(new)) > 65536:
            raise ValueError("Android edit must be a real bounded text replacement")
        before = path.read_text(encoding="utf-8")
        if before.count(old) != 1:
            raise ValueError("Android text change requires exactly one occurrence")
        after = before.replace(old, new, 1)
        data = after.encode("utf-8")
        if len(data) > 1024 * 1024:
            raise ValueError("changed Android text exceeds its file bound")
        path.write_bytes(data)  # Only the newly created working snapshot is edited.
        diff = workspace / f"edit-{index}.diff"
        diff.write_text("".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=name, tofile=name)), encoding="utf-8")
        diffs.append({"relative_path": name, "before_sha256": change["expected_sha256"], "after_sha256": sha256_file(path), "diff": identity(diff)})
    return diffs
