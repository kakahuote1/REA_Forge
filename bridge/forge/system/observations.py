"""Pinned phlib observation and fixed no-dump Hollows Hunter, no old control plane."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import time

from common.process_identity import BoundProcess
from common.static_files import bounded_file, identity, pinned, read_json, run_native

KINDS = {"processes", "threads", "thread_metadata", "modules", "handles", "regions", "details", "services", "drivers", "kernel_modules", "connections"}
GLOBAL = {"processes", "services", "drivers", "kernel_modules"}
KEYS = {"processes": ("pid", "created_100ns"), "threads": ("tid",), "thread_metadata": ("tid", "created_100ns"), "modules": ("base",), "handles": ("handle",), "regions": ("base",), "details": ("pid",), "services": ("name",), "drivers": ("name",), "kernel_modules": ("path", "base"),
        "connections": ("pid", "protocol", "family", "local_address_hex", "local_port", "local_scope", "remote_address_hex", "remote_port", "remote_scope")}


def wire(value, key=""):
    """Normalize once before JavaScript: FILETIME integers must never lose bits."""
    if type(value) is int and (key.endswith("_100ns") or abs(value) > 9007199254740991):
        return str(value)
    if isinstance(value, dict):
        return {name: wire(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [wire(item) for item in value]
    return value


def si(selected: dict, kind: str, pid: int, workspace: Path, timeout: int) -> dict:
    if kind not in KINDS or (pid == 0 and kind not in GLOBAL) or (pid != 0 and kind in GLOBAL - {"processes"}):
        raise ValueError("fixed System Informer kind/target combination required")
    executable = pinned(selected, "executable")
    out, error, timing = run_native([str(executable), kind, str(pid)], workspace, timeout_ms=min(timeout, 8000), prefix="si", accepted_exit_codes=frozenset({0, 2}))
    data = read_json(out)
    if data.get("ok") is not True or timing["exit_code"] != 0:
        raise ValueError("System Informer query failed: " + str(data.get("ntstatus", "target missing or inaccessible")))
    if data.get("kind") != kind or data.get("source_commit") != selected["source_commit"] or data.get("engine") != "SystemInformer.phlib":
        raise ValueError("System Informer producer contract/source mismatch")
    rows = data.get("rows")
    if not isinstance(rows, list) or len(rows) > 16384 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("System Informer rows exceed fixed output contract")
    if kind == "connections":
        for row in rows:
            row["local_address"] = str(ipaddress.ip_address(bytes.fromhex(row["local_address_hex"])))
            row["remote_address"] = str(ipaddress.ip_address(bytes.fromhex(row["remote_address_hex"]))) if row["remote_address_hex"] else None
    # Do not retain a second lossy raw representation with 64-bit numeric stamps.
    out.unlink()
    data = wire(data)
    return {"kind": kind, "rows": data.pop("rows"), "producer": data, "complete": data.get("complete", True) is True and data.get("truncated") is False,
            "target_process": None, "atomic": False, "timing": timing, "engine": {"executable": identity(executable), "source_commit": selected["source_commit"], "version": selected["version"]},
            "artifacts": [identity(error)], "integer_encoding": "FILETIME/100ns and integers outside exact JavaScript range are decimal strings"}


def observe(selected: dict, values: dict, workspace: Path, *, bound: bool) -> dict:
    pid = values.get("pid", 0)
    if not pid:
        return si(selected, values["kind"], 0, workspace, values.get("timeout_ms", 24000))
    with BoundProcess(pid, values["created_100ns"] if bound else None) as process:
        data = si(selected, values["kind"], pid, workspace, values.get("timeout_ms", 24000))
        process.check()
        expected = process.identity["created_100ns"]
        if "created_100ns" in data["producer"] and data["producer"]["created_100ns"] != expected:
            raise ValueError("System Informer producer process creation identity differs")
        if values["kind"] == "processes" and (len(data["rows"]) != 1 or data["rows"][0].get("created_100ns") != expected):
            raise ValueError("System Informer process row differs from open handle identity")
        data["target_process"] = process.identity
        data["identity_checked_before_after"] = True
        return data


def scanner_summary(text: str) -> dict:
    decoder = json.JSONDecoder()
    for offset, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, end = decoder.raw_decode(text, offset)
        except ValueError:
            continue
        if not isinstance(value, dict) or not {"scanned_count", "failed_count", "suspicious_count"} <= value.keys():
            continue
        if text[end:].strip():
            raise ValueError("scanner has unexpected content after summary")
        if any(type(value[name]) is not int or value[name] < 0 for name in ("scanned_count", "failed_count", "suspicious_count")):
            raise ValueError("scanner count fields are invalid")
        return wire(value)
    raise ValueError("scanner returned no completed JSON count summary")


def scan(selected: dict, values: dict, workspace: Path) -> dict:
    executable = pinned(selected, "executable")
    output = workspace / "scanner"
    output.mkdir()
    with BoundProcess(values["pid"], values["created_100ns"]) as process:
        out, error, timing = run_native([str(executable), "/pid", str(values["pid"]), "/json", "/dir", str(output), "/ofilter", "2"], workspace,
                                        timeout_ms=values.get("timeout_ms", 45000), prefix="hollows", accepted_exit_codes=frozenset({0, 1, 2}))
        process.check()
        summary = scanner_summary(out.read_text(encoding="utf-8", errors="strict"))
        if summary["scanned_count"] != 1:
            raise ValueError("scanner did not complete exactly one selected process")
        if summary.get("pid", values["pid"]) != values["pid"]:
            raise ValueError("scanner summary target differs")
        artifacts = [identity(out), identity(error)]
        total = 0
        for path in output.rglob("*"):
            if path.is_symlink() or len(artifacts) >= 256:
                raise ValueError("scanner output escaped ordinary bounded file contract")
            if path.is_file():
                if path.suffix.lower() not in {".json", ".txt", ".log"}:
                    raise ValueError("no-dump scanner produced an unexpected binary artifact")
                bounded_file(path, 16 * 1024 * 1024)
                total += path.stat().st_size
                if total > 32 * 1024 * 1024:
                    raise ValueError("scanner report aggregate exceeds32MiB")
                artifacts.append(identity(path))
        return {"kind": "hollows_hunter", "target_process": process.identity, "identity_checked_before_after": True, "atomic": False,
                "summary": summary, "complete": summary["failed_count"] == 0, "rows": [], "artifacts": artifacts, "timing": timing,
                "engine": {"executable": identity(executable), "source_commit": selected["source_commit"], "version": selected["version"]},
                "no_dump_filter": 2, "interpretation": "Suspicious results are candidates; a negative scan is not proof of benignness or absence of a rootkit."}


def compare(before: dict, after: dict) -> list[dict]:
    if before["kind"] != after["kind"] or before["target_process"] != after["target_process"]:
        raise ValueError("snapshot comparison requires identical kind and process creation identity")
    if not before["complete"] or not after["complete"] or before["kind"] not in KEYS:
        raise ValueError("incomplete or unsupported snapshots cannot be compared")
    keys = KEYS[before["kind"]]
    def indexed(rows):
        result = {tuple(row[key] for key in keys): row for row in rows}
        if len(result) != len(rows):
            raise ValueError("duplicate row identity cannot be compared")
        return result
    left, right = indexed(before["rows"]), indexed(after["rows"])
    return [{"identity": list(key), "change": "added" if key not in left else "removed" if key not in right else "changed", "before": left.get(key), "after": right.get(key)}
            for key in sorted(left.keys() | right.keys(), key=repr) if left.get(key) != right.get(key)]
