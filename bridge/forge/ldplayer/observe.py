"""Fixed LDPlayer list/physical/process observations; no guest/ADB/management writes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as xml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.process_identity import process_start
from common.static_files import identity, pinned, read_json, read_operator_configuration, run_native


def physical(path: Path, *, directory: bool = False) -> dict:
    # Reject ancestor junctions as well as a reparse point at the final anchor.
    for ancestor in (path, *path.parents):
        ancestor_state = ancestor.lstat()
        if ancestor.is_symlink() or getattr(ancestor_state, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("LDPlayer identity path traverses a reparse point")
    state = path.lstat()
    if path.is_symlink() or getattr(state, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise ValueError("LDPlayer identity anchors cannot be reparse points")
    if not (stat.S_ISDIR(state.st_mode) if directory else stat.S_ISREG(state.st_mode)):
        raise ValueError("LDPlayer identity anchor has the wrong filesystem type")
    if not state.st_ino:
        raise ValueError("LDPlayer physical file identity is unavailable")
    # Windows Python3.11 ctime is file creation;3.12+ supplies birthtime.
    born = getattr(state, "st_birthtime_ns", state.st_ctime_ns)
    return {"path": str(path), "device": str(state.st_dev), "fileId": str(state.st_ino), "creationNs": str(born)}


def parse_row(line: str) -> dict:
    # This pinned LDPlayer9 reports ten fields. Parsing the old seven-field
    # layout greedily absorbs handles/state into the title and treats DPI as
    # a VM PID. Bind this producer to its observed/documented layout only.
    match = re.fullmatch(r"([0-9]+),(.*),(-?[0-9]+),(-?[0-9]+),([01]),(-?[0-9]+),(-?[0-9]+),([0-9]+),([0-9]+),([0-9]+)", line)
    if not match:
        raise ValueError("unrecognized pinned LDPlayer list2 row")
    index, name, top, bind, started, player, vm, width, height, dpi = match.groups()
    if not name or len(name) > 256 or any(ord(char) < 32 for char in name):
        raise ValueError("LDPlayer display name is invalid")
    return {"index": int(index), "name": name, "androidStarted": int(started) == 1,
            "runtime": {"playerPid": int(player) if int(player) > 0 else None, "vmPid": int(vm) if int(vm) > 0 else None},
            "runtimeState": int(started), "display": {"width": int(width), "height": int(height), "dpi": int(dpi)}}


def observe_instance(root: Path, row: dict) -> dict:
    index = row["index"]
    if not 1 <= index <= 9999:
        raise ValueError("only an exact nonzero LDPlayer instance is admitted")
    instance = root / "vms" / f"leidian{index}"
    descriptor = instance / "leidian.vbox"
    anchors = [physical(instance, directory=True), physical(descriptor)]
    with descriptor.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("LDPlayer descriptor exceeds identity bound")
    text = raw.decode("utf-8-sig")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("LDPlayer descriptor DTD is unsupported")
    document = xml.fromstring(text)
    machines = document.findall("{*}Machine")
    if len(machines) != 1:
        raise ValueError("LDPlayer descriptor has no unique machine")
    machine = machines[0]
    machine_uuid = machine.get("uuid", "")
    if not re.fullmatch(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}", machine_uuid):
        raise ValueError("LDPlayer machine UUID is malformed")
    disks = machine.findall("{*}MediaRegistry/{*}HardDisks/{*}HardDisk")
    writable = [disk for disk in disks if disk.get("type") == "Normal"]
    if not 1 <= len(writable) <= 8:
        raise ValueError("LDPlayer writable disk identity is unavailable")
    for disk in writable:
        location = Path(disk.get("location", ""))
        if not str(location) or str(location) == ".":
            raise ValueError("LDPlayer writable disk has no location")
        path = location if location.is_absolute() else instance / location
        if not path.resolve(strict=True).is_relative_to(instance.resolve(strict=True)):
            raise ValueError("LDPlayer writable disk escaped the exact selected instance")
        anchors.append(physical(path))
    if physical(instance, directory=True) != anchors[0] or physical(descriptor) != anchors[1]:
        raise ValueError("LDPlayer identity changed during descriptor observation")
    for anchor in anchors[2:]:
        if physical(Path(anchor["path"])) != anchor:
            raise ValueError("LDPlayer disk identity changed during observation")
    runtime = row["runtime"]
    runtime["playerStartTicks"] = process_start(runtime["playerPid"] or 0)
    runtime["vmStartTicks"] = process_start(runtime["vmPid"] or 0)
    generation = hashlib.sha256(json.dumps({"index": index, "machineUuid": machine_uuid.lower(), "anchors": anchors}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"index": index, "name": row["name"], "physicalGeneration": generation, "machineUuid": machine_uuid.lower(), "androidStarted": row["androidStarted"], "runtime": runtime,
            "identityEvidence": {"anchors": anchors, "descriptorSha256": hashlib.sha256(raw).hexdigest(), "processCreationClock": "Windows FILETIME100ns since1601; unavailable is null", "runtimeState": row["runtimeState"], "display": row["display"], "list2Layout": "index,title,top,bind,started,playerPid,vmPid,width,height,dpi"}}


def execute(operation: str, values: dict) -> dict:
    if os.name != "nt":
        raise ValueError("this LDPlayer observation profile requires Windows")
    selected = read_operator_configuration()["ldplayer"]
    console = pinned(selected, "executable")
    root = Path(selected["runtime_root"])
    if console.parent.resolve(strict=True) != root.resolve(strict=True):
        raise ValueError("LDPlayer console does not belong to the selected runtime")
    workspace = Path(sys.argv[1]).resolve(strict=True).parent
    out, error, timing = run_native([str(console), "list2"], workspace, timeout_ms=5000, prefix="list2", maximum=65536)
    data = out.read_bytes()
    try:
        text, encoding = data.decode("utf-8-sig"), "utf-8"
    except UnicodeError:
        text, encoding = data.decode("mbcs"), "Windows ACP"
    rows = [parse_row(line.strip()) for line in text.splitlines() if line.strip()]
    if len(rows) > 64 or len({row["index"] for row in rows}) != len(rows):
        raise ValueError("LDPlayer instance list is duplicate or exceeds bound")
    if operation == "forge_observe_ldplayer_instance":
        index = values["index"]
        rows = [row for row in rows if row["index"] == index and index > 0]
        if len(rows) != 1:
            raise ValueError("selected nonzero LDPlayer instance is missing")
    else:
        rows = [row for row in rows if row["index"] > 0]
    observations = [observe_instance(root, row) for row in rows]
    return {"operation": operation, "target": identity(console), "result": {"instances": observations, "listEncoding": encoding, "timing": timing}, "workspace": str(workspace), "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    try:
        request = read_json(Path(sys.argv[1]), 65536)
        if set(request) != {"operation", "arguments"} or request["operation"] not in {"forge_observe_ldplayer_list", "forge_observe_ldplayer_instance"}:
            raise ValueError("unknown fixed LDPlayer observation")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        print(json.dumps({"ok": False, "error": {"kind": type(cause).__name__, "message": str(cause)}}), flush=True)
        sys.exit(1)
