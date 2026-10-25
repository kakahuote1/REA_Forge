"""Owned Python bytecode analysis, separated from source execution and old routers."""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import CONFIG_PATH, PRIVATE_ROOT
from common.static_files import bounded_file, identity, pinned, read_json, run_native, sha256_file, stage_input
from python_reverse.model_runner import MAGICS, ModelMemoryAdmissionError, require_model_memory

FAMILY = {"forge_disassemble_python": "xdis", "forge_decompile_legacy_python": "python_legacy",
          "forge_decompile_modern_python": "pylingual", "forge_read_python_result": "python_results"}
WORK = PRIVATE_ROOT / "work" / "python-bytecode"


def window(record: dict, document: dict, values: dict) -> dict:
    start, limit = values.get("text_offset", 0), values.get("text_limit", 4096)
    if any(isinstance(item, bool) or not isinstance(item, int) for item in (start, limit)) or start < 0 or not 1 <= limit <= 65536:
        raise ValueError("invalid Python result text window")
    text = document["text"]
    return {**{key: value for key, value in document.items() if key != "text"}, "text": text[start:start + limit],
            "text_offset": start, "text_characters": len(text), "text_has_more": start + limit < len(text), "full_result": record["full_result"]}


def execute(operation: str, values: dict) -> dict:
    if operation == "forge_read_python_result":
        receipt = bounded_file(values["receipt_path"], 65536)
        if not receipt.is_relative_to(WORK.resolve(strict=True)) or sha256_file(receipt) != values["receipt_sha256"]:
            raise ValueError("Python receipt changed or is outside its owned root")
        record = read_json(receipt, 65536)
        if record.get("kind") != "forge_python_bytecode":
            raise ValueError("unsupported Python analysis receipt")
        full = bounded_file(record["full_result"]["path"], 2 * 1024 * 1024)
        if full.parent != receipt.parent or sha256_file(full) != record["full_result"]["sha256"]:
            raise ValueError("retained Python result changed or escaped its owner")
        document = read_json(full, 2 * 1024 * 1024)
    else:
        selected = read_json(CONFIG_PATH, 65536)[FAMILY[operation]]
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        target, source = stage_input(selected, values["path"], workspace, leaf="input.pyc", maximum=8 * 1024 * 1024)
        if operation == "forge_decompile_modern_python":
            with source.open("rb") as stream:
                version = MAGICS.get(stream.read(4).hex())
            if version is None:
                document = {"analysis_status": "unsupported_version", "text": "", "engine": "pylingual",
                            "reason": "only qualified CPython 3.9/3.10/3.11/3.12 magics are supported"}
            else:
                require_model_memory(selected.get("minimum_free_memory_bytes", 3 * 1024 * 1024 * 1024))
                (workspace / "model-selection.json").write_text(json.dumps(selected), encoding="utf-8")
                python = pinned(selected, "python")
                _, _, timing = run_native([str(python), "-I", "-X", "utf8", str(Path(__file__).with_name("model_runner.py")), str(workspace)],
                    workspace, timeout_ms=values.get("timeout_ms", 112000), prefix="model", maximum=2 * 1024 * 1024, maximum_timeout_ms=112000)
                document = read_json(workspace / "model-result.json", 2 * 1024 * 1024)
                document["timing"] = timing
                # Model verification compilation/cache files are disposable, not user data.
                # They remain owned until process-family settlement; no target is executed.
        else:
            parameters = {**values, "mode": "disassemble" if operation == "forge_disassemble_python" else "decompile"}
            (workspace / "library-request.json").write_text(json.dumps({"arguments": parameters, "selected": selected}), encoding="utf-8")
            python = pinned(selected, "python")
            _, _, timing = run_native([str(python), "-I", "-S", "-X", "utf8", str(Path(__file__).with_name("library_runner.py")), str(workspace)],
                workspace, timeout_ms=values.get("timeout_ms", 35000), prefix="library", maximum=2 * 1024 * 1024)
            document = read_json(workspace / "library-result.json", 2 * 1024 * 1024)
            document["timing"] = timing
        if sha256_file(Path(target["path"])) != target["sha256"] or sha256_file(source) != target["sha256"]:
            raise ValueError("Python input changed during analysis")
        full = workspace / "result.json"
        data = json.dumps(document, ensure_ascii=True, allow_nan=False).encode("utf-8")
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Python retained JSON exceeds its bound")
        full.write_bytes(data)
        record = {"kind": "forge_python_bytecode", "target": target, "full_result": identity(full), "parameters": values}
        receipt = workspace / "receipt.json"
        receipt.write_text(json.dumps(record, ensure_ascii=True), encoding="utf-8")
    result = window(record, document, values)
    result.update(receipt_path=str(receipt), receipt_sha256=sha256_file(receipt), historical_readback=operation == "forge_read_python_result")
    return {"operation": operation, "target": record["target"], "result": result, "workspace": str(receipt.parent),
            "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    try:
        request = read_json(Path(sys.argv[1]), 65536)
        if set(request) != {"operation", "arguments"} or request["operation"] not in FAMILY or not isinstance(request["arguments"], dict):
            raise ValueError("invalid owned Python analysis request")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, ModelMemoryAdmissionError):
            error["reported_limits"] = cause.reported_limits
        if isinstance(cause, TimeoutError):
            error["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 112000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)
