"""Official Yak MCP request/history subset with private profiles and retained Evidence."""
from __future__ import annotations

import base64
import json
import msvcrt
from pathlib import Path
import re
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import PRIVATE_ROOT
from common.static_files import bounded_file, identity, pinned, read_json, read_operator_configuration, run_native, sha256_file
from yakit.protocol import request_arguments

WORK = PRIVATE_ROOT / "work/yakit"
OPERATIONS = {"forge_yakit_request", "forge_yakit_flows", "forge_read_yakit_result"}


def retained(values):
    path = bounded_file(values["receipt_path"], 16 * 1024 * 1024)
    if not path.is_relative_to(WORK.resolve(strict=True)) or not re.fullmatch(r"[a-f0-9]{32}", path.parent.name) or sha256_file(path) != values["receipt_sha256"]:
        raise ValueError("Yakit receipt owner/digest differs")
    receipt = read_json(path)
    full = bounded_file(receipt["full_result"]["path"], 16 * 1024 * 1024)
    if receipt.get("kind") != "yakit" or full.parent != path.parent or sha256_file(full) != receipt["full_result"]["sha256"]:
        raise ValueError("Yakit retained result identity differs")
    return path, receipt, read_json(full)


def execute(operation, values):
    if operation == "forge_read_yakit_result":
        receipt_path, receipt, document = retained(values)
    else:
        configuration = read_operator_configuration()["yakit"]
        engine, node = pinned(configuration, "engine"), pinned(configuration, "node")
        workspace = WORK / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        profile = values["profile"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", profile):
            raise ValueError("invalid private Yakit profile")
        state = PRIVATE_ROOT / "work/yakit-state" / profile
        marker = {"kind": "forge-yakit-state", "schema": 1, "profile": profile, "engine_sha256": configuration["engine"]["sha256"]}
        try:
            state.mkdir(parents=True, exist_ok=False)
            (state / "owner.json").write_text(json.dumps(marker), encoding="ascii")
        except FileExistsError:
            if state.is_symlink() or read_json(state / "owner.json", 65536) != marker:
                raise ValueError("private Yakit profile ownership/engine changed; use another explicit profile")
        # OS byte-range lock releases on owner exit; no stale PID deletion rule.
        with (state / "profile.lock").open("a+b") as lock:
            if lock.seek(0, 2) == 0:
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as cause:
                raise RuntimeError("private Yakit profile is in use; no engine or request started") from cause
            try:
                tool = "http_fuzzer" if operation == "forge_yakit_request" else "query_http_flow"
                arguments = request_arguments(values) if tool == "http_fuzzer" else {"keyword": values["keyword"], "pagination": {"page": values["page"], "limit": values["count"]}}
                subject = workspace / "input.json"
                subject.write_text(json.dumps({"profile": profile, "tool": tool, "arguments": arguments}, ensure_ascii=True), encoding="ascii")
                target = identity(subject)
                home = state / "home"
                home.mkdir(exist_ok=True)
                output = workspace / "engine-result.json"
                specification = workspace / "driver-request.json"
                specification.write_text(json.dumps({"engine": str(engine), "home": str(home), "temporary": str(workspace), "tool": tool, "arguments": arguments, "output": str(output)}), encoding="utf-8")
                out, error, timing = run_native([str(node), "--max-old-space-size=256", str(Path(__file__).with_name("driver.mjs")), str(specification)], workspace, timeout_ms=values["timeout_ms"], prefix="yakit", maximum=4 * 1024 * 1024, accepted_exit_codes=frozenset({0, 1}), environment_overrides={"NODE_OPTIONS": ""})
                if not output.is_file():
                    raise RuntimeError("official Yak ended without a completed response; request outcome unknown; do not retry blindly")
                result = read_json(output, 8 * 1024 * 1024)
                if result.get("ok") is not True or timing["exit_code"] != 0 or result.get("transport_closed") is not True:
                    raise RuntimeError("official Yak operation/cleanup failed: " + str(result.get("error", "unknown outcome")))
                data = result["data"]
                complete = tool != "http_fuzzer" or all(item.get("ok") is not False and not item.get("isTooLargeResponse") for item in data)
                document = {"operation": operation, "profile": profile, "target": target, "data": data, "upstream": result["upstream"], "server": result["server"], "timing": timing, "complete": complete, "query_total": None, "query_may_have_more": len(data) == values.get("count") if tool == "query_http_flow" else None, "sample_execution": False, "network_used": tool == "http_fuzzer", "artifacts": [target, identity(out), identity(error), identity(output)]}
                full = workspace / "full-result.json"
                full.write_text(json.dumps(document, ensure_ascii=True, allow_nan=False), encoding="ascii")
                bounded_file(full, 16 * 1024 * 1024)
                receipt = {"kind": "yakit", "target": target, "full_result": identity(full), "artifacts": document["artifacts"]}
                receipt_path = workspace / "receipt.json"
                receipt_path.write_text(json.dumps(receipt), encoding="ascii")
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    facet = values["facet"]
    value = {key: document[key] for key in ("profile", "complete", "server", "timing", "query_total", "query_may_have_more")} if facet == "summary" else document[facet]
    if isinstance(value, list):
        offset, limit = values["offset"], values["limit"]
        payload = {"rows": value[offset:offset + limit], "total": len(value), "has_more": offset + limit < len(value)}
    else:
        payload = {"value": value}
    if len(json.dumps(payload, ensure_ascii=True).encode()) > 256 * 1024:
        payload = {"inline_omitted": "facet exceeds256KiB; read retained artifact bytes"}
    result = {**payload, "facet": facet, "receipt_path": str(receipt_path), "receipt_sha256": sha256_file(receipt_path), "full_result": receipt["full_result"], "artifacts": receipt["artifacts"], "historical_readback": operation == "forge_read_yakit_result"}
    if values.get("artifact_index") is not None:
        artifacts = [receipt["full_result"], *receipt["artifacts"]]
        index = values["artifact_index"]
        if not 0 <= index < len(artifacts):
            raise ValueError("Yakit artifact index is outside retained result")
        item = artifacts[index]
        source = bounded_file(item["path"], 16 * 1024 * 1024)
        if source.parent != receipt_path.parent or sha256_file(source) != item["sha256"]:
            raise ValueError("Yakit artifact owner/digest differs")
        with source.open("rb") as stream:
            stream.seek(values["byte_offset"])
            data = stream.read(values["byte_count"])
        result["artifact_read"] = {"base64": base64.b64encode(data).decode(), "size_bytes": len(data), "has_more": values["byte_offset"] + len(data) < item["size_bytes"]}
    return {"operation": operation, "target": receipt["target"], "result": result, "workspace": str(receipt_path.parent), "sample_execution": False, "network_used": document["network_used"] if operation != "forge_read_yakit_result" else False}


if __name__ == "__main__":
    request = {}
    try:
        request = read_json(Path(sys.argv[1]), 1024 * 1024)
        if set(request) != {"operation", "arguments"} or request["operation"] not in OPERATIONS:
            raise ValueError("unknown fixed Yakit request")
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError):
            error["timeout_ms"] = request.get("arguments", {}).get("timeout_ms", 30000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)
