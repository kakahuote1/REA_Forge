"""Native REA Harmony static operations with digest-bound retained artifacts."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import PRIVATE_ROOT
from common.static_files import bounded_file, identity, read_json, read_operator_configuration, sha256_file, stage_input
from harmony.archive import abc_header, inspect_archive
from harmony.engines import abc, ark, jadx
from harmony.signing import sign, verify

WORK = PRIVATE_ROOT / "work" / "harmony-static"
FAMILIES = {"forge_inspect_hap": "harmony_packages", "forge_inspect_abc": "abcde", "forge_disassemble_ark": "ark_disasm",
            "forge_render_abc_method": "abcde", "forge_decompile_hap": "jadx_hap", "forge_sign_hap": "hap_signing",
            "forge_verify_hap_signature": "hap_verification", "forge_read_harmony_result": "harmony_results"}
FACETS = {"summary", "package", "entries", "metadata", "abc", "resources", "header", "analysis", "verification", "engine", "artifacts"}


def perform(operation: str, values: dict, selected: dict, workspace: Path) -> dict:
    suffix = ".index" if operation == "forge_inspect_abc" and values.get("action") == "resources" else ".abc" if operation in {"forge_inspect_abc", "forge_disassemble_ark", "forge_render_abc_method"} else ".hap"
    target, source = stage_input(selected, values["path"], workspace, leaf="input" + suffix, maximum=64 * 1024 * 1024 if suffix in {".abc", ".index"} else 256 * 1024 * 1024)
    document = {"target": target, "artifacts": [], "sample_execution": False, "network_used": False}
    if operation == "forge_inspect_hap":
        package = inspect_archive(source, workspace / "package")
        document.update(package={"entry_count": package["entry_count"], "expanded_bytes": package["expanded_bytes"]}, entries=package["entries"], metadata=package["metadata"], abc=package["abc"], resources=package["resources"], artifacts=package["entries"])
    elif operation == "forge_inspect_abc" and values.get("action", "methods") == "header":
        document["header"] = abc_header(source)
    elif operation in {"forge_inspect_abc", "forge_render_abc_method"}:
        action = values.get("render", "disassemble") if operation == "forge_render_abc_method" else values.get("action", "methods")
        document["analysis"], document["artifacts"] = abc(selected, source, workspace, values, action)
        document["header"] = document["analysis"].get("header")
    elif operation == "forge_disassemble_ark":
        document["analysis"], document["artifacts"] = ark(selected, source, workspace, values)
        document["header"] = document["analysis"]["header"]
    elif operation == "forge_decompile_hap":
        document["analysis"], document["artifacts"] = jadx(selected, source, workspace, values)
    elif operation == "forge_sign_hap":
        document["analysis"], document["artifacts"] = sign(selected, source, workspace, values)
        document["verification"] = document["analysis"]["verification"]
    elif operation == "forge_verify_hap_signature":
        document["verification"], document["artifacts"] = verify(selected, source, workspace, values)
    else:
        raise ValueError("unknown fixed Harmony operation")
    if sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("original Harmony input changed during analysis")
    source.unlink()  # The original identity and derived outputs remain; no duplicate input archive retained.
    return document


def delivery(document: dict, values: dict) -> dict:
    facet = values.get("facet", "summary")
    if facet not in FACETS:
        raise ValueError("unknown Harmony result facet")
    if facet == "summary":
        analysis, package = document.get("analysis", {}), document.get("package", {})
        payload = {"package_entry_count": package.get("entry_count"), "abc_count": len(document.get("abc", [])), "metadata": document.get("metadata"), "header": document.get("header"),
                   "action": analysis.get("action"), "row_count": analysis.get("row_count"), "counts_by_kind": analysis.get("counts_by_kind"),
                   "function_count": analysis.get("function_count"), "record_count": analysis.get("record_count"), "line_count": analysis.get("line_count"),
                   "source_output_count": len(analysis.get("source_outputs", [])), "experimental": analysis.get("experimental"), "verification": document.get("verification"),
                   "artifact_count": len(document.get("artifacts", [])), "artifact_preview": document.get("artifacts", [])[:20], "engine": analysis.get("engine")}
    elif facet == "engine":
        payload = document.get("analysis", {}).get("engine")
    else:
        payload = document.get(facet)
    offset, limit, query = values.get("offset", 0), values.get("limit", 50), values.get("query", "")
    if isinstance(payload, list):
        indices = [index for index, item in enumerate(payload) if query.casefold() in json.dumps(item, ensure_ascii=True).casefold()]
        result = {"rows": [{"source_index": index, "value": payload[index]} for index in indices[offset:offset + limit]], "total": len(indices), "has_more": offset + limit < len(indices)}
    else:
        result = {"value": payload}
    if len(json.dumps(result, ensure_ascii=True).encode()) > 256 * 1024:
        result = {"inline_omitted": "selected facet exceeds256KiB; page entries/artifacts or read exact retained bytes", "facet_available": payload is not None}
    return {"facet": facet, "offset": offset, "limit": limit, **result}


def artifact_read(receipt: Path, retained: dict, values: dict) -> dict:
    artifacts = [retained["full_result"], *retained["artifacts"]]
    index = values["artifact_index"]
    if not 0 <= index < len(artifacts):
        raise ValueError("Harmony artifact index is outside retained result")
    selected = artifacts[index]
    path = bounded_file(selected["path"], 256 * 1024 * 1024)
    if not path.is_relative_to(receipt.parent) or sha256_file(path) != selected["sha256"]:
        raise ValueError("Harmony artifact changed or escaped retained owner")
    mode = values.get("mode", "bytes")
    if mode == "bytes":
        offset, count = values.get("byte_offset", 0), values.get("byte_count", 4096)
        with path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(count)
        result = {"artifact_index": index, "byte_offset": offset, "size_bytes": len(data), "base64": base64.b64encode(data).decode("ascii"), "has_more": offset + len(data) < selected["size_bytes"]}
    else:
        offset, limit, rows, extent, more = values.get("line_offset", 0), values.get("line_count", 50), [], 0, False
        with path.open(encoding="utf-8-sig", errors="backslashreplace") as stream:
            for number, line in enumerate(stream):
                if len(line) > 1024 * 1024:
                    raise ValueError("artifact line exceeds1MiB; raw byte readback remains available")
                if number < offset:
                    continue
                if len(rows) == limit or extent + len(line.encode("utf-8")) > 256 * 1024:
                    more = True
                    break
                extent += len(line.encode("utf-8"))
                rows.append(json.loads(line) if mode == "jsonl" else line.rstrip("\r\n"))
        result = {"artifact_index": index, "mode": mode, "line_offset": offset, "rows": rows, "has_more": more, "display_encoding": "UTF-8 with invalid bytes escaped; raw artifact unchanged"}
    if sha256_file(path) != selected["sha256"]:
        raise ValueError("Harmony artifact changed during readback")
    return result


def execute(operation: str, values: dict) -> dict:
    if operation == "forge_read_harmony_result":
        receipt = bounded_file(values["receipt_path"], 16 * 1024 * 1024)
        if not receipt.is_relative_to(WORK.resolve(strict=True)) or sha256_file(receipt) != values["receipt_sha256"]:
            raise ValueError("Harmony receipt identity/owner mismatch")
        retained = read_json(receipt, 16 * 1024 * 1024)
        full = bounded_file(retained["full_result"]["path"], 16 * 1024 * 1024)
        if retained.get("kind") != "harmony-static" or full.parent != receipt.parent or sha256_file(full) != retained["full_result"]["sha256"]:
            raise ValueError("retained Harmony result identity/owner mismatch")
        document = read_json(full)
    else:
        selected = read_operator_configuration()[FAMILIES[operation]]
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        document = perform(operation, dict(values), selected, workspace)
        document["operation"] = operation
        data = json.dumps(document, ensure_ascii=True, allow_nan=False).encode()
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("Harmony metadata result exceeds16MiB retained bound")
        full = workspace / "full-result.json"
        full.write_bytes(data)
        retained = {"kind": "harmony-static", "target": document["target"], "full_result": identity(full), "artifacts": document["artifacts"]}
        receipt = workspace / "receipt.json"
        encoded = json.dumps(retained, ensure_ascii=True).encode()
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("Harmony artifact references exceed16MiB receipt bound")
        receipt.write_bytes(encoded)
    result = {**delivery(document, values), "receipt_path": str(receipt), "receipt_sha256": sha256_file(receipt), "full_result": retained["full_result"],
              "artifacts": retained["artifacts"][:20], "artifact_count": len(retained["artifacts"]), "artifacts_inline_truncated": len(retained["artifacts"]) > 20,
              "historical_readback": operation == "forge_read_harmony_result"}
    if values.get("artifact_index") is not None:
        result["artifact_read"] = artifact_read(receipt, retained, values)
    return {"operation": operation, "target": retained["target"], "result": result, "workspace": str(receipt.parent), "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    request = {}
    try:
        request = read_json(Path(sys.argv[1]), 1024 * 1024)
        if set(request) != {"operation", "arguments"} or request["operation"] not in FAMILIES:
            raise ValueError("unknown fixed Harmony request")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError):
            error["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 45000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)
