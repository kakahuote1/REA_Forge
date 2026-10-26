"""Native REA Android build/transform operations; no old control-plane imports."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.static_files import bounded_file, identity, read_json, read_operator_configuration, sha256_file
from android_build.project_files import WORK, load_receipt, relative
from android_build.project_ops import build, prepare
from android_build.dex_ops import assemble, disassemble
from android_build.signing_ops import sign, verify

OPERATIONS = {
    "forge_prepare_android_project": ("apk_workspace", prepare),
    "forge_build_android_project": ("apk_workspace", build),
    "forge_disassemble_dex": ("smali", disassemble),
    "forge_assemble_dex": ("smali", assemble),
    "forge_sign_apk": ("apk_signing", sign),
    "forge_verify_apk": ("apk_signing", verify),
}


def bytes_window(file: dict, values: dict) -> dict:
    path = bounded_file(file["path"], 256 * 1024 * 1024)
    if sha256_file(path) != file["sha256"]:
        raise ValueError("retained Android artifact identity changed")
    offset, count = values.get("byte_offset", 0), values.get("byte_count", 4096)
    if any(isinstance(item, bool) or not isinstance(item, int) for item in (offset, count)) or offset < 0 or not 1 <= count <= 65536:
        raise ValueError("invalid Android file byte window")
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(count)
    if sha256_file(path) != file["sha256"]:
        raise ValueError("retained Android artifact changed during readback")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        text = None
    return {"byte_offset": offset, "size_bytes": len(data), "base64": base64.b64encode(data).decode("ascii"),
            "text_utf8": text, "text_coverage": "exact-selected-window" if text is not None else "window-not-valid-utf8; use-base64",
            "has_more": offset + len(data) < file["size_bytes"]}


def page(receipt: Path, record: dict, values: dict) -> dict:
    result = {key: value for key, value in record.items() if key not in {"target", "project", "parameters"}}
    if "project" in record:
        project = record["project"]
        result["project"] = {key: value for key, value in project.items() if key not in {"files", "directories"}}
        offset, limit, query = values.get("offset", 0), values.get("limit", 50), values.get("query", "")
        if any(isinstance(item, bool) or not isinstance(item, int) for item in (offset, limit)) or offset < 0 or not 1 <= limit <= 100 or not isinstance(query, str) or len(query) > 512:
            raise ValueError("invalid Android project page")
        rows = [item for item in project["files"] if query.casefold() in item["relative_path"].casefold()]
        result.update(rows=rows[offset:offset + limit], total=len(rows), offset=offset, limit=limit, has_more=offset + limit < len(rows))
        if values.get("relative_path") is not None:
            name = relative(values["relative_path"])
            selected = next((item for item in project["files"] if item["relative_path"] == name), None)
            if selected is None:
                raise ValueError("selected file is not in the bound Android project")
            file = {**selected, "path": str(Path(project["root"]) / name)}
            result["file"] = {"identity": file, **bytes_window(file, values)}
    elif values.get("relative_path") is not None:
        raise ValueError("this Android result has no source project")
    if values.get("artifact_index") is not None:
        artifacts = [identity(receipt), *record.get("artifacts", [])]
        index = values["artifact_index"]
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(artifacts):
            raise ValueError("artifact index is outside the retained Android result")
        selected = artifacts[index]
        if Path(selected["path"]).parent != receipt.parent:
            raise ValueError("Android artifact escaped its receipt workspace")
        result["bytes"] = {"artifact_index": index, **bytes_window(selected, values)}
    result.update(receipt_path=str(receipt), receipt_sha256=sha256_file(receipt))
    return result


def execute(operation: str, arguments: dict) -> dict:
    if operation == "forge_read_android_result":
        receipt, record = load_receipt(arguments)
    else:
        family, function = OPERATIONS[operation]
        selected = read_operator_configuration()[family]
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        record = function(dict(arguments), selected, workspace)
        record["parameters"] = arguments
        receipt = workspace / "receipt.json"
        encoded = json.dumps(record, ensure_ascii=True, allow_nan=False).encode("utf-8")
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("Android result exceeds its retained manifest bound")
        with receipt.open("xb") as output:
            output.write(encoded)
    return {"operation": operation, "target": record["target"], "result": {**page(receipt, record, arguments), "historical_readback": operation == "forge_read_android_result"},
            "workspace": str(receipt.parent), "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    try:
        request = read_json(Path(sys.argv[1]), 8 * 1024 * 1024)
        if set(request) != {"operation", "arguments"} or request["operation"] not in {*OPERATIONS, "forge_read_android_result"} or not isinstance(request["arguments"], dict):
            raise ValueError("invalid owned Android operation")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": "ValueError" if isinstance(cause, zipfile.BadZipFile) else type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError):
            error["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 45000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)
