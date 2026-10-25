"""Selected DEX/baksmali/smali transforms, never Android target execution."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct
import zipfile
import zlib

from common.static_files import bounded_file, identity, sha256_file, stage_input
from android_build.project_files import copy_tree, edits, input_directory, load_receipt, relative, tree, validate_apk
from android_build.project_ops import engine, java, native


def facts(path: Path) -> dict:
    with path.open("rb") as stream:
        header = stream.read(112)
    if len(header) < 112 or not re.fullmatch(b"dex\n0[0-9]{2}\x00", header[:8]):
        raise ValueError("not an admitted standard DEX container")
    size, header_size = struct.unpack_from("<II", header, 32)
    if size != path.stat().st_size or header_size != 112:
        raise ValueError("DEX header/file size mismatch")
    sha1, checksum = hashlib.sha1(), 1
    with path.open("rb") as stream:
        stream.seek(12)
        position = 12
        for block in iter(lambda: stream.read(65536), b""):
            checksum = zlib.adler32(block, checksum)
            sha1.update(block[max(0, 32 - position):])
            position += len(block)
    return {"version": header[4:7].decode("ascii"), "sha1_signature_matches": sha1.digest() == header[12:32],
            "adler32_matches": checksum & 0xFFFFFFFF == struct.unpack_from("<I", header, 8)[0], "class_count": struct.unpack_from("<I", header, 96)[0]}


def disassemble(values: dict, selected: dict, workspace: Path) -> dict:
    target, source = stage_input(selected, values["path"], workspace, leaf="input.bin", maximum=256 * 1024 * 1024)
    target["kind"] = "file"
    with source.open("rb") as stream:
        is_dex = stream.read(4) == b"dex\n"
    dex = workspace / "input.dex"
    if is_dex:
        if source.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("DEX exceeds analysis byte bound")
        source.rename(dex)
        entry = None
    else:
        validate_apk(source)
        entry = values.get("dex_entry", "classes.dex")
        if not isinstance(entry, str) or not re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", entry):
            raise ValueError("select one exact standard classes DEX entry")
        with zipfile.ZipFile(source) as archive:
            member = archive.getinfo(entry)
            if member.file_size > 64 * 1024 * 1024:
                raise ValueError("selected DEX exceeds analysis byte bound")
            with archive.open(member) as incoming, dex.open("xb") as output:
                total = 0
                while True:
                    block = incoming.read(65536)
                    if not block:
                        break
                    total += len(block)
                    if total > 64 * 1024 * 1024:
                        raise ValueError("selected DEX expanded past its bound")
                    output.write(block)
    observation = facts(dex)
    project = workspace / "project"
    _, _, timing = native([*java(selected, "baksmali", workspace), "disassemble", "--output", str(project), str(dex)], workspace, values, "baksmali")
    if sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("original DEX/APK changed during analysis")
    return {"kind": "android-dex", "target": target, "project": tree(project), "artifacts": [identity(dex)],
            "action": "disassemble", "dex_entry": entry, "dex": observation, "engine": engine(selected, "baksmali", timing)}


def assemble(values: dict, selected: dict, workspace: Path) -> dict:
    project = workspace / "project"
    imported = values.get("source_directory")
    if imported is not None:
        directory = input_directory(imported, selected)
        observed = copy_tree(directory, project)
        source = {"kind": "android-dex", "target": {"path": str(directory), "sha256": observed["sha256"], "size_bytes": observed["size_bytes"], "kind": "tree"}}
    else:
        _, source = load_receipt(values, {"android-project", "android-dex"})
        copy_tree(Path(source["project"]["root"]), project)
    changes = edits(project, values.get("changes", []), workspace)
    subdirectory = values.get("smali_root")
    if subdirectory is None:
        subdirectory = "smali" if source["kind"] == "android-project" else ""
    root = project / relative(subdirectory) if subdirectory else project
    if not root.is_dir() or not root.resolve(strict=True).is_relative_to(project) or not any(root.rglob("*.smali")):
        raise ValueError("selected smali root has no admitted assembly files")
    api = values.get("api_level", 28)
    if isinstance(api, bool) or not isinstance(api, int) or not 1 <= api <= 35:
        raise ValueError("invalid selected Android API level")
    output = workspace / "output.dex"
    _, _, timing = native([*java(selected, "smali", workspace), "assemble", "--api", str(api), "--output", str(output), str(root)], workspace, values, "smali")
    bounded_file(output, 64 * 1024 * 1024)
    observation = facts(output)
    if not observation["sha1_signature_matches"] or not observation["adler32_matches"]:
        raise ValueError("assembled DEX failed its structural digest checks")
    if imported is not None:
        if tree(directory)["sha256"] != observed["sha256"]:
            raise ValueError("imported Smali source changed during assembly")
    else:
        load_receipt(values, {"android-project", "android-dex"})
    return {"kind": "android-dex", "target": source["target"], "project": tree(project), "artifacts": [identity(output), *[item["diff"] for item in changes]],
            "action": "assemble", "changes": changes, "dex": observation, "engine": engine(selected, "smali", timing)}
