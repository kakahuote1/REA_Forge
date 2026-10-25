"""Bounded HAP/APP/HSP inspection, migrated from the existing pure ZIP adapter."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import struct
import zipfile

from common.static_files import identity, read_json, sha256_file

MAX_ENTRIES = 10000
MAX_ENTRY = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024


def relative(name: str) -> PurePosixPath:
    if not name or "\\" in name or name.startswith("/"):
        raise ValueError("package entry is not a relative portable path")
    parts = name.removesuffix("/").split("/")
    if any(not item or item in {".", ".."} or any(char in item for char in '<>:"|?*') or any(ord(char) < 32 for char in item)
           or item.endswith((" ", ".")) or PureWindowsPath(item).is_reserved() for item in parts):
        raise ValueError("package entry is unsafe or ambiguous on Windows")
    return PurePosixPath(*parts)


def inspect_archive(source: Path, output: Path) -> dict:
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= MAX_ENTRIES:
            raise ValueError("package exceeds ZIP member count bound")
        names, expected_total = set(), 0
        for entry in entries:
            name = relative(entry.filename).as_posix().casefold()
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if name in names or entry.flag_bits & 1 or mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError("package has colliding, encrypted or nonordinary members")
            names.add(name)
            if not 0 <= entry.file_size <= MAX_ENTRY:
                raise ValueError("package member exceeds64MiB bound")
            expected_total += entry.file_size
            if expected_total > MAX_TOTAL:
                raise ValueError("package exceeds256MiB expansion bound")
        output.mkdir()
        rows, metadata, abc, resources = [], [], [], []
        actual_total = 0
        for entry in entries:
            path = relative(entry.filename)
            destination = output.joinpath(*path.parts)
            if entry.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            used = 0
            with archive.open(entry) as incoming, destination.open("xb") as outgoing:
                for block in iter(lambda: incoming.read(65536), b""):
                    used += len(block)
                    actual_total += len(block)
                    if used > min(entry.file_size, MAX_ENTRY) or actual_total > MAX_TOTAL:
                        raise ValueError("package actual expansion exceeds declared or resource extent")
                    outgoing.write(block)
            if used != entry.file_size:
                raise ValueError("package actual member extent differs")
            row = {"relative_path": path.as_posix(), **identity(destination)}
            rows.append(row)
            lower = path.as_posix().casefold()
            if lower.endswith(".abc"):
                abc.append(row)
            if "resources" in (item.casefold() for item in path.parts) or lower.endswith("resources.index"):
                resources.append(row)
            if path.name.casefold() in {"pack.info", "module.json", "module.json5", "app.json", "app.json5", "config.json"}:
                facts = {"relative_path": row["relative_path"], "sha256": row["sha256"], "parsed_json": False}
                if used <= 1024 * 1024:
                    try:
                        value = read_json(destination, 1024 * 1024)
                        if isinstance(value, dict):
                            # Preserve selected declarations, never execute scripts or JSON5.
                            module = value.get("module", {}).get("name") if isinstance(value.get("module"), dict) else None
                            bundle = value.get("app", {}).get("bundleName") if isinstance(value.get("app"), dict) else None
                            facts.update(parsed_json=True, declared_module_name=module if isinstance(module, str) and len(module) <= 1024 else None,
                                         declared_bundle_name=bundle if isinstance(bundle, str) and len(bundle) <= 1024 else None)
                    except (UnicodeError, ValueError):
                        facts["interpretation"] = "raw JSON/JSON5 retained; strict JSON interpretation unavailable"
                else:
                    facts["interpretation"] = "metadata exceeds1MiB inline parser extent; exact member retained"
                metadata.append(facts)
    return {"entry_count": len(rows), "expanded_bytes": actual_total, "entries": rows, "metadata": metadata, "abc": abc, "resources": resources}


def abc_header(source: Path) -> dict:
    size = source.stat().st_size
    with source.open("rb") as stream:
        data = stream.read(60)
    if not 60 <= size <= 64 * 1024 * 1024 or len(data) != 60 or data[:8] != b"PANDA\0\0\0":
        raise ValueError("bounded Panda ABC header required")
    fields = struct.unpack_from("<11I", data, 16)
    if fields[0] != size:
        raise ValueError("ABC header file extent differs")
    if fields[3] and (not 60 <= fields[4] <= size or fields[3] > (size - fields[4]) // 4):
        raise ValueError("ABC class-index extent escapes selected bytes")
    return {"bytecode_version": ".".join(map(str, data[12:16])), "file_size": size, "checksum_declared": struct.unpack_from("<I", data, 8)[0],
            "class_count": fields[3], "class_index_offset": fields[4], "foreign_offset": fields[1], "foreign_size": fields[2],
            "line_number_program_count": fields[5], "line_number_index_offset": fields[6], "literal_array_count": fields[7],
            "literal_array_index_offset": fields[8], "index_count": fields[9], "index_section_offset": fields[10],
            "sha256": sha256_file(source), "coverage": "fixed60-byte Panda header and class-index extent only; engine support and checksum validity are separate"}
