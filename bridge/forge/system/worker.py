"""Native REA live-process observations and digest-bound historical readback."""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import PRIVATE_ROOT
from common.static_files import bounded_file, identity, read_json, read_operator_configuration, sha256_file
from system.observations import compare, observe, scan

WORK = PRIVATE_ROOT / "work" / "system-observation"
FAMILIES = {"forge_inspect_system": "system_informer", "forge_observe_process": "system_informer", "forge_scan_process": "hollows_hunter", "forge_compare_process_snapshots": "system_results", "forge_read_system_result": "system_results"}


def retained(reference: dict) -> tuple[Path, dict, dict]:
    path = bounded_file(reference["receipt_path"], 16 * 1024 * 1024)
    if not path.is_relative_to(WORK.resolve(strict=True)) or sha256_file(path) != reference["receipt_sha256"]:
        raise ValueError("system receipt identity/owner mismatch")
    receipt = read_json(path)
    snapshot = bounded_file(receipt["snapshot"]["path"], 16 * 1024 * 1024)
    if receipt.get("kind") != "system-observation" or snapshot.parent != path.parent or sha256_file(snapshot) != receipt["snapshot"]["sha256"]:
        raise ValueError("system snapshot identity/owner mismatch")
    return path, receipt, read_json(snapshot)


def execute(operation: str, values: dict) -> dict:
    if operation == "forge_read_system_result":
        receipt_path, receipt, document = retained(values)
        historical = True
    else:
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        if operation == "forge_compare_process_snapshots":
            _, before_receipt, before = retained(values["before"])
            _, after_receipt, after = retained(values["after"])
            document = {"kind": "difference", "target_process": before["target_process"], "complete": True, "rows": compare(before, after), "artifacts": [],
                        "parents": {"before": before_receipt["snapshot"], "after": after_receipt["snapshot"]}, "atomic": False,
                        "identity_caveat": "Transient thread/handle/address reuse between observations cannot be excluded."}
        else:
            selected = read_operator_configuration()[FAMILIES[operation]]
            document = scan(selected, values, workspace) if operation == "forge_scan_process" else observe(selected, values, workspace, bound=operation == "forge_observe_process")
        document.update(observed_unix_ns=str(time.time_ns()), operation=operation, target_execution=False, network_io=False)
        snapshot_path = workspace / "snapshot.json"
        encoded = json.dumps(document, ensure_ascii=True, allow_nan=False).encode()
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("system snapshot exceeds16MiB retained bound")
        snapshot_path.write_bytes(encoded)
        receipt = {"kind": "system-observation", "snapshot": identity(snapshot_path)}
        receipt_path = workspace / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=True), encoding="ascii")
        historical = False
    rows = document["rows"]
    query, offset, limit = values.get("query", "").casefold(), values.get("offset", 0), values.get("limit", 50)
    selected = [(index, row) for index, row in enumerate(rows) if query in json.dumps(row, ensure_ascii=True).casefold()]
    metadata = {name: item for name, item in document.items() if name != "rows"}
    result = {"metadata": metadata, "rows": [{"source_index": index, "value": row} for index, row in selected[offset:offset + limit]], "total": len(selected), "has_more": offset + limit < len(selected),
              "receipt_path": str(receipt_path), "receipt_sha256": sha256_file(receipt_path), "snapshot": receipt["snapshot"], "historical_readback": historical}
    if len(json.dumps(result, ensure_ascii=True).encode()) > 256 * 1024:
        result["rows"] = []
        result["inline_omitted"] = "page exceeds256KiB; select fewer rows or read the retained snapshot file"
        result["has_more"] = bool(selected)
        if len(json.dumps(result, ensure_ascii=True).encode()) > 256 * 1024:
            result["metadata"] = {name: document[name] for name in ("kind", "target_process", "complete", "observed_unix_ns", "atomic")}
            result["metadata_inline_omitted"] = True
    return {"operation": operation, "target": receipt["snapshot"], "result": result, "workspace": str(receipt_path.parent), "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    request = {}
    try:
        request = read_json(Path(sys.argv[1]), 1024 * 1024)
        if set(request) != {"operation", "arguments"} or request["operation"] not in FAMILIES:
            raise ValueError("unknown fixed system observation request")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError):
            error["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 45000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)
