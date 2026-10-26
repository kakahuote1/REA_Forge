"""PE facts, static dependency candidates and fixed UPX transforms for REA."""
from __future__ import annotations

import base64
import importlib
import json
from pathlib import Path
import secrets
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import PRIVATE_ROOT
from common.static_files import bounded_file, identity, pinned, read_json, read_operator_configuration, run_native, sha256_file, stage_input

WORK = PRIVATE_ROOT / "work" / "pe-static"
MAXIMUM = 256 * 1024 * 1024
FAMILIES = {"forge_inspect_pe": "pe_parser", "forge_resolve_pe_dependencies": "pe_parser", "forge_test_upx": "upx", "forge_unpack_upx": "upx", "forge_read_pe_result": "pe_results"}
FACETS = {"summary", "headers", "sections", "imports", "delay_imports", "bound_imports", "exports", "resources", "security", "data_directories", "dependencies", "engine", "upx", "artifacts"}


def parser(selected: dict):
    module_file = pinned(selected, "pefile")
    sys.path.insert(0, str(module_file.parent))
    module = importlib.import_module("pefile")
    if Path(module.__file__).resolve(strict=True) != module_file or module.__version__ != selected["version"]:
        raise ValueError("configured PE parser identity/version mismatch")
    return module


def dependencies(selected: dict, values: dict, source: Path, target: dict, workspace: Path) -> dict:
    from pe.dependencies import resolve_dependencies
    roots = []
    for raw in values.get("dependency_roots", []):
        root = Path(raw)
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError("dependency root is not an absolute ordinary directory")
        root = root.resolve(strict=True)
        if not any(root.is_relative_to(Path(admitted).resolve(strict=True)) for admitted in selected["input_roots"]):
            raise ValueError("dependency root is outside configured analysis roots")
        roots.append(root)
    origin = Path(target["path"])
    sidecar = origin.with_name(origin.name + ".manifest")
    paired = None
    if sidecar.exists():
        paired, copied = stage_input(selected, str(sidecar), workspace, leaf=source.name + ".manifest", maximum=1024 * 1024)
    value = resolve_dependencies(source, roots, source_directory=origin.parent, max_depth=values.get("max_depth", 2), max_nodes=values.get("max_nodes", 48))
    value["limits"]["max_depth"] = values.get("max_depth", 2)
    value["limits"]["max_nodes"] = values.get("max_nodes", 48)
    value["paired_manifest_source"] = paired
    if paired and sha256_file(sidecar) != paired["sha256"]:
        raise ValueError("paired manifest changed during dependency reading")
    return value


def native(selected: dict, workspace: Path, values: dict, arguments: list[str], prefix: str):
    deadline = values.setdefault("_deadline", time.monotonic() + values.get("timeout_ms", 45000) / 1000)
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining < 1:
        raise TimeoutError("UPX pipeline exceeded its selected deadline")
    return run_native([str(pinned(selected, "executable")), *arguments], workspace, timeout_ms=remaining,
                      prefix=prefix, environment_overrides={"UPX": ""}, accepted_exit_codes=frozenset({0, 1, 2}))


def perform(operation: str, values: dict, selected: dict, workspace: Path) -> dict:
    target, source = stage_input(selected, values["path"], workspace, leaf="input.exe", maximum=MAXIMUM)
    record = {"target": target, "artifacts": [], "source_execution": False, "network_used": False}
    if operation in {"forge_inspect_pe", "forge_resolve_pe_dependencies"}:
        module = parser(selected)
        from pe.structure import parse_pe
        facts = parse_pe(source)
        # Source format facts refer to the admitted bytes, not the private copy's display path.
        facts["identity"] = target
        record.update(facts=facts, engine={"name": "pefile", "version": module.__version__, "module": identity(pinned(selected, "pefile")), "transitive_dependencies_authenticated": False})
        if operation == "forge_resolve_pe_dependencies":
            if facts["is_pe"] is not True:
                raise ValueError("dependency resolution requires a parsed PE")
            record["dependencies"] = dependencies(selected, values, source, target, workspace)
    else:
        out, diagnostic, timing = native(selected, workspace, values, ["-t", str(source)], "test")
        verified = timing["exit_code"] == 0
        record.update(upx={"test_status": "verified_upx_packed" if verified else "not_verified", "verified_upx_packed": verified, "test": timing,
                           "stdout": identity(out), "stderr": identity(diagnostic)}, engine={"name": "UPX", "version": selected["version"], "executable": identity(pinned(selected, "executable"))})
        if operation == "forge_unpack_upx":
            if not verified:
                raise ValueError("UPX test did not verify a packed input; no unpacking attempted")
            output = workspace / "unpacked.exe"
            out, diagnostic, timing = native(selected, workspace, values, ["-d", "-o", str(output), str(source)], "unpack")
            if timing["exit_code"] != 0:
                raise ValueError("UPX did not successfully unpack the selected file")
            bounded_file(output, MAXIMUM)
            with output.open("rb") as stream:
                header = stream.read(64)
                if len(header) != 64 or header[:2] != b"MZ":
                    raise ValueError("unpacked output is not a PE container")
                offset = int.from_bytes(header[60:64], "little")
                if not 64 <= offset <= min(output.stat().st_size - 4, 1024 * 1024):
                    raise ValueError("unpacked PE header offset is invalid")
                stream.seek(offset)
                if stream.read(4) != b"PE\0\0":
                    raise ValueError("unpacked output has no admitted PE signature")
            record["artifacts"] = [identity(output)]
            record["upx"]["unpack"] = {**timing, "stdout": identity(out), "stderr": identity(diagnostic)}
    if sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("original PE input changed during static operation")
    return record


def summary(document: dict) -> dict:
    facts = document.get("facts", {})
    return {"is_pe": facts.get("is_pe"), "format": facts.get("format"), "machine": facts.get("machine"),
            "headers": facts.get("headers"), "section_count": len(facts.get("sections", [])),
            "import_table_summary": facts.get("import_table_summary"), "collection_limits": facts.get("collection_limits"),
            "dependency_candidate_mode": document.get("dependencies", {}).get("mode"),
            "upx": document.get("upx"), "artifacts": document.get("artifacts", []), "engine": document.get("engine")}


def delivery(document: dict, values: dict) -> dict:
    facet = values.get("facet", "summary")
    if facet not in FACETS:
        raise ValueError("unknown retained PE facet")
    payload = summary(document) if facet == "summary" else document.get(facet, document.get("facts", {}).get(facet))
    offset, limit, query = values.get("offset", 0), values.get("limit", 50), values.get("query", "")
    if isinstance(payload, list):
        matches = [(index, row) for index, row in enumerate(payload) if query.casefold() in json.dumps(row, ensure_ascii=True).casefold()]
        result = {"rows": [{"source_index": index, "value": row} for index, row in matches[offset:offset + limit]], "total": len(matches), "has_more": offset + limit < len(matches)}
    elif facet == "dependencies" and isinstance(payload, dict):
        collection = values.get("collection", "nodes")
        rows = payload.get(collection)
        if collection not in {"nodes", "edges", "missing", "previously_examined_edges", "source_manifest_documents", "sxs_candidates"} or not isinstance(rows, list):
            raise ValueError("unknown static dependency collection")
        matches = [(index, row) for index, row in enumerate(rows) if query.casefold() in json.dumps(row, ensure_ascii=True).casefold()]
        result = {"metadata": {key: value for key, value in payload.items() if key not in {"nodes", "edges", "missing", "previously_examined_edges", "source_manifest_documents", "sxs_candidates"}},
                  "collection": collection, "rows": [{"source_index": index, "value": row} for index, row in matches[offset:offset + limit]], "total": len(matches), "has_more": offset + limit < len(matches)}
    else:
        result = {"value": payload}
    if len(json.dumps(result, ensure_ascii=True).encode()) > 256 * 1024:
        result = {"inline_omitted": "selected result exceeds 256KiB; select a smaller page or read the retained exact bytes", "facet_available": payload is not None}
    return {"facet": facet, "offset": offset, "limit": limit, **result}


def execute(operation: str, values: dict) -> dict:
    if operation == "forge_read_pe_result":
        receipt = bounded_file(values["receipt_path"], 65536)
        if not receipt.is_relative_to(WORK.resolve(strict=True)) or sha256_file(receipt) != values["receipt_sha256"]:
            raise ValueError("PE receipt identity or owner mismatch")
        retained = read_json(receipt, 65536)
        full = bounded_file(retained["full_result"]["path"], 16 * 1024 * 1024)
        if full.parent != receipt.parent or sha256_file(full) != retained["full_result"]["sha256"]:
            raise ValueError("retained PE result identity or owner mismatch")
        document = read_json(full)
    else:
        selected = read_operator_configuration()[FAMILIES[operation]]
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        document = perform(operation, dict(values), selected, workspace)
        document["operation"] = operation
        data = json.dumps(document, ensure_ascii=True, allow_nan=False).encode()
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("PE result exceeded retained byte bound")
        full = workspace / "full-result.json"
        full.write_bytes(data)
        retained = {"kind": "pe-static", "target": document["target"], "full_result": identity(full), "artifacts": document["artifacts"]}
        receipt = workspace / "receipt.json"
        receipt.write_text(json.dumps(retained), encoding="utf-8")
    result = {**delivery(document, values), "receipt_path": str(receipt), "receipt_sha256": sha256_file(receipt), "full_result": retained["full_result"], "artifacts": retained["artifacts"], "historical_readback": operation == "forge_read_pe_result"}
    if values.get("artifact_index") is not None:
        artifacts = [retained["full_result"], *retained["artifacts"]]
        index = values["artifact_index"]
        if not 0 <= index < len(artifacts):
            raise ValueError("PE artifact index is outside retained result")
        item = artifacts[index]
        path = bounded_file(item["path"], MAXIMUM)
        if path.parent != receipt.parent or sha256_file(path) != item["sha256"]:
            raise ValueError("PE artifact changed or escaped retained work")
        offset, count = values.get("byte_offset", 0), values.get("byte_count", 4096)
        with path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(count)
        if sha256_file(path) != item["sha256"]:
            raise ValueError("PE artifact changed during readback")
        result["bytes"] = {"artifact_index": index, "byte_offset": offset, "size_bytes": len(data), "base64": base64.b64encode(data).decode("ascii"), "has_more": offset + len(data) < item["size_bytes"]}
    return {"operation": operation, "target": retained["target"], "result": result, "workspace": str(receipt.parent), "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    request = {}
    try:
        request = read_json(Path(sys.argv[1]), 1024 * 1024)
        if set(request) != {"operation", "arguments"} or request["operation"] not in FAMILIES:
            raise ValueError("unknown fixed PE request")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        failure = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError):
            failure["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 45000)
        print(json.dumps({"ok": False, "error": failure}), flush=True)
        sys.exit(1)
