"""Pinned offline native enrichment; no legacy control plane or target launch."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.hard_deny_policy import HardDenyPolicy
from common.paths import CONFIG_PATH, PRIVATE_ROOT

FAMILY = {
    "forge_analyze_capabilities": "capa", "forge_recover_strings": "floss",
    "forge_list_api_hash_types": "api_hashes", "forge_lookup_api_hash": "api_hashes",
    "forge_read_enrichment_result": "enrichment",
}
MAX_INPUT = 32 * 1024 * 1024
MAX_RESULT = 8 * 1024 * 1024
MAX_STDERR = 256 * 1024
WORK_ROOT = PRIVATE_ROOT / "work" / "native-enrichment"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def bounded_file(raw: str | Path, maximum: int) -> Path:
    path = Path(raw)
    HardDenyPolicy().require_local_path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("requires an absolute local non-symlink file")
    result = path.resolve(strict=True)
    if not result.is_file() or result.stat().st_size > maximum:
        raise ValueError("file exceeds its regular-file bound")
    return result


def identity(path: Path) -> dict:
    return {"path": str(path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size}


def read_json(path: Path, maximum: int = MAX_RESULT) -> dict:
    bounded_file(path, maximum)
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("JSON file grew beyond its bound")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def pinned(selected: dict, key: str) -> Path:
    pin = selected[key]
    path = bounded_file(pin["path"], 512 * 1024 * 1024)
    if sha256_file(path) != pin["sha256"]:
        raise ValueError("configured enrichment engine/database identity drifted")
    return path


def stage_input(selected: dict, values: dict, workspace: Path) -> tuple[dict, Path]:
    source = bounded_file(values["path"], MAX_INPUT)
    roots = [Path(root).resolve(strict=True) for root in selected["input_roots"]]
    if not any(source.is_relative_to(root) for root in roots):
        raise ValueError("input is outside configured analysis roots")
    with source.open("rb") as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(MAX_INPUT + 1)
        after = os.fstat(stream.fileno())
    current = source.stat()
    state = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(data) > MAX_INPUT or state(before) != state(after) or state(after) != state(current):
        raise ValueError("input changed during staged read")
    target = {"path": str(source), "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    staged = workspace / ("input" + source.suffix)
    with staged.open("xb") as stream:
        stream.write(data)
    return target, staged


def run_engine(argv: list[str], workspace: Path, timeout: float = 45) -> tuple[dict, dict]:
    """The outer REA Windows job owns this helper and every inherited child."""
    stdout_path, stderr_path = workspace / "result.json", workspace / "stderr.txt"
    environment = dict(os.environ)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "PYTHONPATH", "PYTHONHOME", "IDADIR", "IDAUSR", "IDAPYTHON_VERSION"):
        environment.pop(key, None)
    # The existing REA private-command owner removes extraction temporaries only
    # after its whole job settles. Retained analysis outputs have another owner.
    command_temp = str(Path(sys.argv[1]).resolve(strict=True).parent)
    environment.update({"NO_PROXY": "*", "no_proxy": "*", "TEMP": command_temp, "TMP": command_temp})
    started = time.monotonic()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        child = subprocess.Popen(argv, cwd=workspace, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 env=environment, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        failure = None
        try:
            while child.poll() is None:
                if time.monotonic() - started >= timeout:
                    failure = "engine exceeded its selected deadline"
                    break
                if stdout_path.stat().st_size > MAX_RESULT or stderr_path.stat().st_size > MAX_STDERR:
                    failure = "engine output exceeded its file bound"
                    break
                time.sleep(0.05)
        finally:
            if child.poll() is None:
                child.kill()  # Retained process handle; outer job settles descendants.
            child.wait(timeout=3)
        if failure is not None:
            raise TimeoutError(failure)
        if child.returncode != 0:
            raise ValueError("pinned enrichment engine returned nonzero exit status; diagnostics retained")
    if stdout_path.stat().st_size > MAX_RESULT or stderr_path.stat().st_size > MAX_STDERR:
        raise ValueError("engine output exceeded its file bound")
    return read_json(stdout_path), {"elapsed_seconds": time.monotonic() - started, "exit_code": child.returncode}


def database_result(database: Path, operation: str, values: dict) -> dict:
    started = time.monotonic()
    connection = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=2)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.set_progress_handler(lambda: int(time.monotonic() - started > 2), 1000)
        connection.row_factory = sqlite3.Row
        if operation == "forge_list_api_hash_types":
            rows = [dict(row) for row in connection.execute("SELECT hash_type,hash_size,hash_name FROM hash_types ORDER BY hash_type")]
            return {"kind": "hash_types", "rows": rows}
        raw = values["hash_value"]
        if isinstance(raw, bool):
            raise ValueError("boolean is not a hash")
        value = int(raw, 16) if isinstance(raw, str) else raw
        if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("hash must be a 32-bit value")
        where, arguments = "s.hash_val=?", [value]
        hash_type = values.get("hash_type")
        if hash_type is not None:
            known = connection.execute("SELECT 1 FROM hash_types WHERE hash_type=?", (hash_type,)).fetchone()
            if known is None:
                raise ValueError("hash type is not present in the configured database")
            where += " AND h.hash_type=?"
            arguments.append(hash_type)
        query = ("SELECT s.hash_val,h.hash_type,h.hash_name,l.lib_name,s.symbol_name FROM symbol_hashes s "
                 "JOIN hash_types h ON h.hash_type=s.hash_type JOIN source_libs l ON l.lib_key=s.lib_key WHERE " + where +
                 " ORDER BY h.hash_type,l.lib_name,s.symbol_name")
        # Output is a complete bounded retained result, then the common reader pages it.
        rows = []
        for row in connection.execute(query, arguments):
            item = dict(row)
            item["hash_val"] = f"0x{item['hash_val']:08X}"
            rows.append(item)
            if len(rows) > 10000:
                raise ValueError("hash collision result exceeds its retained row bound")
        return {"kind": "hash_matches", "hash_value": f"0x{value:08X}", "hash_type_filter": hash_type, "rows": rows}
    finally:
        connection.close()


def address(raw: dict) -> dict:
    value = raw.get("value")
    return {"kind": raw.get("type"), "value": hex(value) if isinstance(value, int) and not isinstance(value, bool) else json.dumps(value, ensure_ascii=False)}


def capability_rows(document: dict) -> list[dict]:
    raw = document.get("rules")
    if not isinstance(document.get("meta"), dict) or not isinstance(raw, dict):
        raise ValueError("capa JSON does not match the reviewed rule format")
    rows = []
    for item in raw.values():
        if not isinstance(item, dict) or not isinstance(item.get("meta"), dict):
            raise ValueError("malformed capa rule")
        meta = item["meta"]
        if meta.get("lib") is True:
            continue
        matches = item.get("matches", [])
        addresses = [address(match[0]) for match in matches if isinstance(match, list) and match and isinstance(match[0], dict)]
        rows.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "scopes": meta.get("scopes"),
                     "attack": meta.get("attack"), "mbc": meta.get("mbc"), "match_addresses": addresses[:64],
                     "match_count": len(matches), "addresses_truncated": len(addresses) > 64})
    return sorted(rows, key=lambda item: str(item["name"]))


def string_rows(document: dict) -> list[dict]:
    strings = document.get("strings")
    if not isinstance(document.get("metadata"), dict) or not isinstance(strings, dict):
        raise ValueError("FLOSS JSON does not match the reviewed string format")
    rows = []
    for kind in ("static", "decoded", "stack", "tight"):
        for item in strings.get(kind + "_strings", []):
            if not isinstance(item, dict) or not isinstance(item.get("string"), str):
                raise ValueError("malformed FLOSS string")
            value = item["string"]
            context = {key: (hex(raw) if isinstance(raw, int) and not isinstance(raw, bool) else raw)
                       for key in ("offset", "function", "address", "decoded_at", "address_type", "encoding") if (raw := item.get(key)) is not None}
            rows.append({"kind": kind, "string": value[:8192], "string_truncated": len(value) > 8192, **context})
    return rows


def page_result(record: dict, document: dict, values: dict) -> dict:
    family = record["family"]
    rows = capability_rows(document) if family == "capa" else string_rows(document) if family == "floss" else document["rows"]
    offset, limit = values.get("offset", 0), values.get("limit", 50)
    if isinstance(offset, bool) or isinstance(limit, bool) or not 0 <= offset <= 1_000_000 or not 1 <= limit <= 100:
        raise ValueError("invalid page")
    return {"family": family, "offset": offset, "limit": limit, "total": len(rows), "rows": rows[offset:offset + limit],
            "has_more": offset + limit < len(rows), "full_result": record["full_result"],
            "analysis_parameters": record["analysis_parameters"]}


def retained(values: dict) -> tuple[dict, dict, Path]:
    receipt = bounded_file(values["receipt_path"], 64 * 1024)
    if not receipt.is_relative_to(WORK_ROOT.resolve(strict=True)) or sha256_file(receipt) != values["receipt_sha256"]:
        raise ValueError("retained receipt is outside the workspace or changed")
    record = read_json(receipt, 64 * 1024)
    if record.get("kind") != "forge_native_enrichment" or record.get("family") not in {"capa", "floss", "api_hashes"}:
        raise ValueError("unsupported retained receipt")
    full = bounded_file(record["full_result"]["path"], MAX_RESULT)
    if full.parent != receipt.parent or sha256_file(full) != record["full_result"]["sha256"]:
        raise ValueError("retained full result changed or escaped its receipt workspace")
    return record, read_json(full), receipt


def execute(operation: str, values: dict) -> dict:
    family = FAMILY[operation]
    if operation == "forge_read_enrichment_result":
        record, document, receipt = retained(values)
        result = page_result(record, document, values)
        result.update({"receipt_path": str(receipt), "receipt_sha256": values["receipt_sha256"], "historical_readback": True})
        return {"operation": operation, "target": record["target"], "result": result, "engine": record["engine"],
                "workspace": str(receipt.parent), "sample_execution": False, "network_used": False}
    selected = read_json(CONFIG_PATH, 64 * 1024)[family]
    engine_path = pinned(selected, "database" if family == "api_hashes" else "executable")
    workspace = WORK_ROOT / secrets.token_hex(16)
    workspace.mkdir(parents=True, exist_ok=False)
    engine = {"family": family, "path": str(engine_path), "sha256": selected["database" if family == "api_hashes" else "executable"]["sha256"],
              "version": selected["version"], "owned_wait_completed": True}
    target = None
    if family == "api_hashes":
        document = database_result(engine_path, operation, values)
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(raw) > MAX_RESULT:
            raise ValueError("database result exceeds its retained bound")
        (workspace / "result.json").write_bytes(raw)
    else:
        target, staged = stage_input(selected, values, workspace)
        input_format = values.get("format", "pe" if family == "capa" else "auto")
        if input_format not in ({"pe", "elf", "sc32", "sc64"} if family == "capa" else {"auto", "pe", "sc32", "sc64"}):
            raise ValueError("unsupported engine input format")
        if family == "capa":
            argv = [str(engine_path), "--backend", "vivisect", "--format", input_format, "--json", str(staged)]
        else:
            kinds = values.get("string_kinds", ["static", "decoded", "stack", "tight"])
            minimum = values.get("minimum_length", 4)
            if not isinstance(kinds, list) or not kinds or len(kinds) > 4 or any(kind not in {"static", "decoded", "stack", "tight"} for kind in kinds) or isinstance(minimum, bool) or not isinstance(minimum, int) or not 4 <= minimum <= 128:
                raise ValueError("invalid string selection")
            argv = [str(engine_path), "--json", "--disable-progress", "--minimum-length", str(minimum), "--format", input_format, "--only", *sorted(set(kinds)), "--", str(staged)]
        timeout_ms = values.get("timeout_ms", 45000)
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 45000:
            raise ValueError("invalid engine deadline")
        document, timing = run_engine(argv, workspace, timeout_ms / 1000)
        engine.update(timing)
        engine["observed_version"] = document.get("meta" if family == "capa" else "metadata", {}).get("version")
        if sha256_file(Path(target["path"])) != target["sha256"]:
            raise ValueError("original changed during analysis")
    record = {"kind": "forge_native_enrichment", "family": family, "target": target, "engine": engine,
              "analysis_parameters": {key: value for key, value in values.items() if key not in {"offset", "limit"}},
              "full_result": identity(workspace / "result.json")}
    result = page_result(record, document, values)
    receipt = workspace / "receipt.json"
    receipt.write_text(json.dumps(record, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    result.update({"receipt_path": str(receipt), "receipt_sha256": sha256_file(receipt), "historical_readback": False})
    return {"operation": operation, "target": target, "result": result, "engine": engine, "workspace": str(workspace),
            "sample_execution": False, "network_used": False}


def main() -> None:
    try:
        if len(sys.argv) != 2:
            raise ValueError("one owned request is required")
        value = read_json(Path(sys.argv[1]), 4 * 1024 * 1024)
        if set(value) != {"operation", "arguments"} or value["operation"] not in FAMILY or not isinstance(value["arguments"], dict):
            raise ValueError("invalid static enrichment request")
        print(json.dumps({"ok": True, "value": execute(value["operation"], value["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError) and "value" in locals():
            error["timeout_ms"] = value.get("arguments", {}).get("timeout_ms", 45000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
