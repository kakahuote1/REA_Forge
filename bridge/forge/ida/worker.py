"""Owned static IDA work copies and retained results; no raw script/plugin API."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import PRIVATE_ROOT
from common.static_files import bounded_file, identity, pinned, read_json, read_operator_configuration, run_native, sha256_file, stage_input
from ida.host_profile import prepare

WORK = PRIVATE_ROOT / "work" / "ida-static"
ENGINE_OPERATIONS = {"forge_edit_ida_database", "forge_run_ida_safe_python", "forge_scan_ida_crypto", "forge_ida_enum", "forge_ida_struct_typer", "forge_snapshot_ida_database", "forge_export_ida_data"}
OPERATIONS = ENGINE_OPERATIONS | {"forge_assemble_ida", "forge_compare_ida_snapshots", "forge_restore_ida_database", "forge_read_ida_result"}


def api_source(selected: dict) -> Path:
    root = Path(selected["api_source_root"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("typed IDA library source root is unavailable")
    records, total = [], 0
    for path in sorted((root / "ida_pro_mcp").rglob("*.py"), key=lambda path: path.relative_to(root).as_posix()):
        if "tests" in path.parts or "__pycache__" in path.parts:
            continue
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
            raise ValueError("typed IDA library source escaped its reviewed root")
        total += path.stat().st_size
        if len(records) >= 512 or total > 16 * 1024 * 1024:
            raise ValueError("typed IDA library source exceeds review bound")
        records.append(path.relative_to(root).as_posix() + "\0" + sha256_file(path))
    if not records or hashlib.sha256("\n".join(records).encode()).hexdigest() != selected["api_source_tree_sha256"]:
        raise ValueError("typed IDA library source tree differs from the reviewed pin")
    return root


def pure_module(root: Path, name: str):
    spec = importlib.util.spec_from_file_location("forge_" + name, root / "ida_pro_mcp" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def retained(reference: dict) -> tuple[Path, dict]:
    path = bounded_file(reference["receipt_path"], 16 * 1024 * 1024)
    if not path.is_relative_to(WORK.resolve(strict=True)) or sha256_file(path) != reference["receipt_sha256"]:
        raise ValueError("IDA receipt owner or digest differs")
    record = read_json(path)
    full = bounded_file(record["full_result"]["path"], 16 * 1024 * 1024)
    if record.get("kind") != "ida-static" or full.parent != path.parent or sha256_file(full) != record["full_result"]["sha256"]:
        raise ValueError("retained IDA result owner or digest differs")
    return path, read_json(full)


def execute(operation: str, values: dict) -> dict:
    if operation == "forge_read_ida_result":
        receipt_path, document = retained(values)
        record = read_json(receipt_path)
    else:
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        family = "ida_host" if operation in ENGINE_OPERATIONS else "ida_assembly" if operation == "forge_assemble_ida" else "ida_exchange" if operation == "forge_compare_ida_snapshots" else "ida_results"
        selected = read_operator_configuration()[family]
        document = {"operation": operation, "artifacts": [], "sample_execution": False, "network_used": False}
        if operation in ENGINE_OPERATIONS:
            api = api_source(selected)
            profile = prepare(selected, workspace)
            suffix = ".i64" if Path(values["path"]).suffix.casefold() in {".idb", ".i64"} else ".bin"
            target, source = stage_input(selected, values["path"], workspace, leaf="input" + suffix, maximum=128 * 1024 * 1024)
            if values.get("expected_sha256") and target["sha256"] != values["expected_sha256"]:
                raise ValueError("selected IDA input differs from required preimage")
            request = workspace / "engine-request.json"
            request.write_text(json.dumps({"operation": operation, "arguments": values, "profile": profile, "workspace": str(workspace), "input": str(source), "api_source_root": str(api)}), encoding="utf-8")
            out, error, timing = run_native([str(pinned(selected, "python")), "-B", str(Path(__file__).with_name("engine.py")), str(request)], workspace,
                                           timeout_ms=values.get("timeout_ms", 45000), prefix="ida-engine", accepted_exit_codes=frozenset({0, 1}), maximum=1024 * 1024)
            if not (workspace / "engine-result.json").is_file():
                phase = read_json(workspace / "engine-state.json") if (workspace / "engine-state.json").is_file() else {"phase": "before-engine-entry"}
                raise RuntimeError("IDALib exited without a completed result: " + json.dumps({"timing": timing, **phase}))
            result = read_json(workspace / "engine-result.json")
            if result.get("ok") is not True or timing["exit_code"] != 0:
                raise ValueError("static IDA library operation failed: " + str(result.get("error", {})))
            document.update(target=target, analysis=result["value"], profile=profile, timing=timing)
            for key in ("before_database", "database"):
                if not document["analysis"][key]:
                    continue
                path = bounded_file(document["analysis"][key], 256 * 1024 * 1024)
                if path.parent != workspace:
                    raise ValueError("IDA database output escaped its owner")
                document[key] = identity(path)
            document["artifacts"] = [*[document[key] for key in ("before_database", "database") if key in document], identity(out), identity(error)]
            if sha256_file(Path(target["path"])) != target["sha256"]:
                raise ValueError("original IDA input changed during static analysis")
            api_source(selected)
            source.unlink()  # Engine closed the DB; do not retain a duplicate input binary.
        elif operation == "forge_assemble_ida":
            request = workspace / "engine-request.json"
            request.write_text(json.dumps({"operation": operation, "arguments": values, "workspace": str(workspace), "api_source_root": str(api_source(selected))}), encoding="utf-8")
            out, error, timing = run_native([str(pinned(selected, "python")), "-B", str(Path(__file__).with_name("engine.py")), str(request)], workspace,
                                           timeout_ms=values.get("timeout_ms", 45000), prefix="assembly-engine", accepted_exit_codes=frozenset({0, 1}), maximum=1024 * 1024)
            result = read_json(workspace / "engine-result.json")
            if result.get("ok") is not True or timing["exit_code"] != 0:
                raise ValueError("fixed Keystone operation failed: " + str(result.get("error", {})))
            document.update(analysis=result["value"]["data"], ida_initialized=False, timing=timing, artifacts=[identity(out), identity(error)])
        elif operation == "forge_compare_ida_snapshots":
            _, before = retained(values["before"])
            _, after = retained(values["after"])
            module = pure_module(api_source(selected), "ida_bindiff_core")
            document["analysis"] = module.compare_snapshots(before["analysis"]["data"], after["analysis"]["data"])
        elif operation == "forge_restore_ida_database":
            _, prior = retained(values)
            if "database" not in prior or "before_database" not in prior:
                raise ValueError("selected IDA result has no editable database/before snapshot")
            current, backup = prior["database"], prior["before_database"]
            for item in (current, backup):
                path = bounded_file(item["path"], 256 * 1024 * 1024)
                if path.parent != Path(prior["database"]["path"]).parent or sha256_file(path) != item["sha256"]:
                    raise ValueError("IDA restore preimage changed")
            if current["sha256"] != values["expected_database_sha256"]:
                raise ValueError("selected current IDB differs from required restore preimage")
            restored = workspace / "restored.i64"
            shutil.copyfile(backup["path"], restored)
            if sha256_file(restored) != backup["sha256"]:
                raise ValueError("restored IDB copy differs")
            document.update(target=current, database=identity(restored), analysis={"restored_from": backup, "overwrote_original": False}, artifacts=[identity(restored)])
        else:
            raise ValueError("unknown fixed IDA operation")
        full = workspace / "full-result.json"
        full.write_text(json.dumps(document, ensure_ascii=True, allow_nan=False), encoding="ascii")
        bounded_file(full, 16 * 1024 * 1024)
        document.setdefault("target", identity(full))
        # The result itself is the subject for input-independent assembly/diff.
        record = {"kind": "ida-static", "target": document["target"], "full_result": identity(full), "artifacts": document["artifacts"]}
        receipt_path = workspace / "receipt.json"
        receipt_path.write_text(json.dumps(record, ensure_ascii=True), encoding="ascii")
    facet = values.get("facet", "summary")
    if facet == "summary":
        value = {key: document.get(key) for key in ("operation", "database", "before_database", "timing")}
        value["target"] = record["target"]
        analysis = document.get("analysis", {})
        value["analysis_keys"] = list(analysis)
        if "profile" in document:
            value["plugin_profile"] = {"allowed": list(document["profile"]["allowed_plugins"]), "blocked_count": len(document["profile"]["blocked_plugins"]), "mechanism": document["profile"]["mechanism"]}
    else:
        value = document.get(facet)
    offset, limit = values.get("offset", 0), values.get("limit", 50)
    if isinstance(value, list):
        payload = {"rows": value[offset:offset + limit], "total": len(value), "has_more": offset + limit < len(value)}
    else:
        payload = {"value": value}
    if len(json.dumps(payload, ensure_ascii=True).encode()) > 256 * 1024:
        payload = {"inline_omitted": "facet exceeds256KiB; use retained bytes", "facet_available": value is not None}
    result = {**payload, "facet": facet, "receipt_path": str(receipt_path), "receipt_sha256": sha256_file(receipt_path), "full_result": record["full_result"], "artifacts": record["artifacts"], "historical_readback": operation == "forge_read_ida_result"}
    if values.get("artifact_index") is not None:
        artifacts = [record["full_result"], *record["artifacts"]]
        index = values["artifact_index"]
        if not 0 <= index < len(artifacts):
            raise ValueError("IDA artifact index is outside retained result")
        item = artifacts[index]
        path = bounded_file(item["path"], 256 * 1024 * 1024)
        if not path.is_relative_to(receipt_path.parent) or sha256_file(path) != item["sha256"]:
            raise ValueError("IDA retained artifact identity or owner differs")
        with path.open("rb") as stream:
            stream.seek(values.get("byte_offset", 0))
            data = stream.read(values.get("byte_count", 4096))
        result["artifact_read"] = {"base64": base64.b64encode(data).decode(), "size_bytes": len(data), "has_more": values.get("byte_offset", 0) + len(data) < item["size_bytes"]}
    return {"operation": operation, "target": record["target"], "result": result, "workspace": str(receipt_path.parent), "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    request = {}
    try:
        request = read_json(Path(sys.argv[1]), 1024 * 1024)
        if set(request) != {"operation", "arguments"} or request["operation"] not in OPERATIONS:
            raise ValueError("unknown fixed IDA request")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError):
            error["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 45000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)
