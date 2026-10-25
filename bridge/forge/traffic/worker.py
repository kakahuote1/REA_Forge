"""Offline PCAP extensions and API interchange operations for the existing REA host."""
from __future__ import annotations

import base64
import csv
import hashlib
from io import StringIO
import json
from pathlib import Path
import re
import secrets
import shutil
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import CONFIG_PATH, PRIVATE_ROOT
from common.static_files import bounded_file, identity, json_object, pinned, read_json, run_native, sha256_file, stage_input
from traffic.api_documents import normalize

FAMILY = {
    "forge_inspect_packet_tree": "pcap", "forge_extract_packet_fields": "pcap", "forge_pcap_statistics": "pcap",
    "forge_follow_packet_stream": "pcap", "forge_export_packet_objects": "pcap",
    "forge_inspect_api_asset": "api_documents", "forge_compare_api_assets": "api_documents", "forge_export_api_asset": "api_documents",
    "forge_read_traffic_result": "traffic",
}
WORK_ROOT = PRIVATE_ROOT / "work" / "offline-traffic"
MAX_JSON = 16 * 1024 * 1024


def require_packet_container(path: Path) -> None:
    # Wiretap also guesses several non-PCAP formats from arbitrary byte streams.
    # This operation promises PCAP/PCAPNG, not all of that implicit input surface.
    with path.open("rb") as stream:
        header = stream.read(28)
    classic = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
               b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    endian = classic.get(header[:4])
    if endian is not None:
        if len(header) < 24 or struct.unpack(endian + "HH", header[4:8]) != (2, 4) or struct.unpack(endian + "I", header[16:20])[0] == 0:
            raise ValueError("invalid PCAP global header")
        return
    if len(header) >= 28 and header[:4] == b"\x0a\x0d\x0d\x0a":
        endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12])
        if endian is not None:
            length = struct.unpack(endian + "I", header[4:8])[0]
            if length >= 28 and length % 4 == 0 and length <= path.stat().st_size and struct.unpack(endian + "H", header[12:14])[0] == 1:
                return
    raise ValueError("requires a PCAP/PCAPNG container, not a guessed Wiretap input")


def write_json(path: Path, value: object) -> None:
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > MAX_JSON:
        raise ValueError("retained traffic JSON exceeds its bound")
    with path.open("xb") as output:
        output.write(data)


def keylog(selected: dict, source: str, command_root: Path) -> dict:
    original, staged = stage_input(selected, source, command_root, leaf="session.keys", maximum=1024 * 1024)
    try:
        lines = staged.read_text(encoding="ascii").splitlines()
    except UnicodeError:
        raise ValueError("explicit TLS keylog must be ASCII NSS format") from None
    count = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError("invalid TLS keylog record")
        label, random, secret = parts
        expected = {96} if label == "CLIENT_RANDOM" else {64, 96, 128}
        if not re.fullmatch(r"CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_\d+|SERVER_TRAFFIC_SECRET_\d+|EXPORTER_SECRET|EARLY_EXPORTER_SECRET", label):
            raise ValueError("unsupported TLS keylog label")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", random) or len(secret) not in expected or not re.fullmatch(r"[a-fA-F0-9]+", secret):
            raise ValueError("invalid TLS keylog encoding")
        count += 1
    if count == 0:
        raise ValueError("TLS keylog has no session records")
    return {"path": str(staged), "source_sha256": original["sha256"], "records": count}


def pcap(operation: str, values: dict, selected: dict, workspace: Path) -> tuple[dict, dict, dict]:
    tshark = pinned(selected, "tshark")
    target, capture = stage_input(selected, values["path"], workspace, leaf="input.pcap", maximum=256 * 1024 * 1024)
    require_packet_container(capture)
    command_root = Path(sys.argv[1]).resolve(strict=True).parent
    profile = command_root / "wireshark-profile"
    profile.mkdir()
    for name in ("plugins", "extcap"):
        (profile / name).mkdir()
    environment = {"WIRESHARK_CONFIG_DIR": str(profile), "WIRESHARK_PLUGIN_DIR": str(profile / "plugins"), "WIRESHARK_EXTCAP_DIR": str(profile / "extcap"), "LANG": "C", "LC_ALL": "C"}
    arguments = [str(tshark), "-n", "-r", str(capture)]
    key = None
    if values.get("keylog_path") is not None:
        key = keylog(selected, values["keylog_path"], command_root)
        arguments += ["-o", "tls.keylog_file:" + key["path"]]
    limit = values.get("packet_limit", 2048)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 1000000:
        raise ValueError("invalid packet scan limit")
    if limit:
        arguments += ["-c", str(limit)]
    display_filter = values.get("display_filter", "")
    if not isinstance(display_filter, str) or len(display_filter) > 512 or any(character in display_filter for character in "\0\r\n"):
        raise ValueError("invalid display filter")
    if display_filter:
        arguments += ["-Y", display_filter]
    if operation == "forge_inspect_packet_tree":
        arguments += ["-T", "json", "--no-duplicate-keys"]
    elif operation == "forge_extract_packet_fields":
        fields = values["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= 64 or any(not isinstance(field, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", field) for field in fields):
            raise ValueError("invalid packet field selection")
        arguments += ["-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a"]
        for field in fields:
            arguments += ["-e", field]
    elif operation == "forge_pcap_statistics":
        statistic = values["statistic"]
        if statistic not in {"conv,tcp", "conv,udp", "endpoints,ip", "io,phs", "expert"}:
            raise ValueError("unsupported offline statistic")
        arguments += ["-q", "-z", statistic]
    elif operation == "forge_follow_packet_stream":
        protocol, stream = values["protocol"], values["stream_index"]
        if protocol not in {"tcp", "udp"} or isinstance(stream, bool) or not isinstance(stream, int) or not 0 <= stream <= 4095:
            raise ValueError("invalid follow-stream selection")
        arguments += ["-q", "-z", f"follow,{protocol},raw,{stream}"]
    else:
        protocol = values["protocol"]
        if protocol not in {"http", "imf", "smb", "tftp"}:
            raise ValueError("unsupported object-export protocol")
        export_root = command_root / "objects"
        export_root.mkdir()
        arguments += ["--export-objects", protocol + "," + str(export_root)]
    stdout, stderr, timing = run_native(arguments, workspace, timeout_ms=values.get("timeout_ms", 35000), prefix="tshark", environment_overrides=environment)
    text = stdout.read_text(encoding="utf-8")
    document = {"view": operation, "rows": [], "artifacts": [identity(stdout)], "packet_scan_limit": limit,
                "coverage": "bounded-source-prefix" if limit else "complete-source-scan", "display_filter": display_filter,
                "tls_keylog": None if key is None else {name: key[name] for name in ("source_sha256", "records")}}
    if operation == "forge_inspect_packet_tree":
        packets = json.loads(text, object_pairs_hook=json_object)
        if not isinstance(packets, list):
            raise ValueError("TShark packet output is not an array")
        document["rows"] = packets
    elif operation == "forge_extract_packet_fields":
        document["fields"] = values["fields"]
        document["rows"] = list(csv.DictReader(StringIO(text), delimiter="\t"))
    elif operation == "forge_pcap_statistics":
        document["text"] = text
        document["statistic"] = values["statistic"]
    elif operation == "forge_follow_packet_stream":
        for line in text.splitlines():
            matched = re.fullmatch(r"(\t?)([a-fA-F0-9]+)", line)
            if matched is None:
                continue
            if len(matched[2]) % 2:
                raise ValueError("TShark stream contains odd-length hex")
            payload = bytes.fromhex(matched[2])
            path = workspace / f"segment-{len(document['rows'])}.bin"
            path.write_bytes(payload)
            artifact = identity(path)
            document["artifacts"].append(artifact)
            document["rows"].append({"direction": "responder" if matched[1] else "initiator", "payload": artifact,
                                     "preview_hex": payload[:256].hex(), "preview_truncated": len(payload) > 256})
    else:
        total_bytes = 0
        for source in sorted(export_root.rglob("*")):
            if source.is_symlink() or not source.resolve(strict=True).is_relative_to(export_root):
                raise ValueError("exported object escaped its owned directory")
            if source.is_dir():
                continue
            if not source.is_file():
                raise ValueError("exported object is not regular")
            total_bytes += source.stat().st_size
            if total_bytes > 64 * 1024 * 1024 or len(document["rows"]) >= 1000:
                raise ValueError("object exports exceed aggregate size/count bound")
            destination = workspace / f"object-{len(document['rows'])}.bin"
            shutil.copyfile(source, destination)
            artifact = identity(destination)
            document["artifacts"].append(artifact)
            document["rows"].append({"original_name": str(source.relative_to(export_root)), "file": artifact})
    if sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("original capture changed during analysis")
    return target, document, {"name": "TShark", "version": selected["version"], "sha256": selected["tshark"]["sha256"],
        "owned_wait_completed": True, "stderr": identity(stderr), "user_profile_changed": False, **timing}


def filtered(document: dict, values: dict) -> dict:
    query, method, path_contains = values.get("query", "").casefold(), values.get("method", ""), values.get("path_contains", "")
    if not isinstance(method, str) or method not in {"", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}:
        raise ValueError("invalid API method filter")
    endpoints = [item for item in document["endpoints"] if (not method or item["method"] == method) and path_contains in item["path"] and
                 (not query or query in (item["identity"] + " " + item["label"]).casefold())]
    variables = [item for item in document["variables"] if not query or query in item["name"].casefold()]
    return {**document, "endpoints": endpoints, "variables": variables}


def api_asset(operation: str, values: dict, selected: dict, workspace: Path) -> tuple[dict, dict, dict]:
    target, staged = stage_input(selected, values["path"], workspace, leaf="input.json", maximum=8 * 1024 * 1024)
    def parse_document(path: Path) -> dict:
        try:
            return normalize(read_json(path, 8 * 1024 * 1024))
        except (ValueError, UnicodeError) as cause:
            raise ValueError("invalid API interchange document: " + str(cause)) from cause
    normalized = parse_document(staged)
    document = {"view": operation, "rows": [], "artifacts": [], "format": normalized["format"], "metadata": normalized["metadata"],
                "endpoint_count": len(normalized["endpoints"]), "variable_count": len(normalized["variables"]), "variable_values": "sha256-only"}
    if operation == "forge_compare_api_assets":
        right, right_staged = stage_input(selected, values["right_path"], workspace, leaf="right.json", maximum=8 * 1024 * 1024)
        other = parse_document(right_staged)
        def grouped(items: list[dict]) -> dict:
            groups = {}
            for item in items:
                groups.setdefault(item["identity"], []).append(item)
            return {key: sorted(rows, key=lambda item: json.dumps(item, sort_keys=True)) for key, rows in groups.items()}
        left_rows, right_rows = grouped(normalized["endpoints"]), grouped(other["endpoints"])
        for key in sorted(set(left_rows) | set(right_rows)):
            if left_rows.get(key) == right_rows.get(key):
                continue
            document["rows"].append({"identity": key, "change": "added" if key not in left_rows else "removed" if key not in right_rows else "changed",
                "left": left_rows.get(key, []), "right": right_rows.get(key, [])})
        document["right"] = right
        document["variables_equal"] = normalized["variables"] == other["variables"]
        if sha256_file(Path(right["path"])) != right["sha256"]:
            raise ValueError("right API document changed during comparison")
    else:
        chosen = filtered(normalized, values)
        if operation == "forge_export_api_asset":
            destination = workspace / "normalized-api.json"
            write_json(destination, chosen)
            document["artifacts"].append(identity(destination))
            document["rows"] = chosen["endpoints"]
        else:
            view = values.get("view", "endpoints")
            if view not in {"endpoints", "variables"}:
                raise ValueError("unknown API view")
            document["rows"] = chosen[view]
            document["collection"] = view
    if sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("original API document changed during analysis")
    return target, document, {"name": "documented API interchange reader", "version": "1", "apipost_process_started": False, "owned_wait_completed": True}


def selected_page(record: dict, document: dict, values: dict) -> dict:
    offset, limit = values.get("offset", 0), values.get("limit", 50)
    if isinstance(offset, bool) or isinstance(limit, bool) or not isinstance(offset, int) or not isinstance(limit, int) or not 0 <= offset <= 1000000 or not 1 <= limit <= 100:
        raise ValueError("invalid result page")
    rows = document["rows"]
    inline = []
    for index, row in enumerate(rows[offset:offset + limit], offset):
        serialized = json.dumps(row, ensure_ascii=True)
        inline.append(row if len(serialized) <= 16384 else {"retained_row": index, "inline_omitted": "row exceeds 16 KiB; read the full-result artifact"})
    result = {key: value for key, value in document.items() if key not in {"rows", "text"}}
    result.update({"offset": offset, "limit": limit, "total": len(rows), "rows": inline, "has_more": offset + limit < len(rows), "full_result": record["full_result"]})
    if "text" in document:
        text_offset, text_limit = values.get("text_offset", 0), values.get("text_limit", 4096)
        if not isinstance(text_offset, int) or not isinstance(text_limit, int) or text_offset < 0 or not 1 <= text_limit <= 65536:
            raise ValueError("invalid text window")
        result.update({"text": document["text"][text_offset:text_offset + text_limit], "text_offset": text_offset, "text_characters": len(document["text"]), "text_has_more": text_offset + text_limit < len(document["text"])})
    if "artifact_index" in values:
        files = [record["full_result"], *document.get("artifacts", [])]
        index, position, count = values["artifact_index"], values.get("byte_offset", 0), values.get("byte_count", 4096)
        if any(isinstance(item, bool) or not isinstance(item, int) for item in (index, position, count)) or not 0 <= index < len(files) or position < 0 or not 1 <= count <= 65536:
            raise ValueError("invalid artifact byte selection")
        chosen = files[index]
        path = bounded_file(chosen["path"], 64 * 1024 * 1024)
        if path.parent != Path(record["full_result"]["path"]).parent or sha256_file(path) != chosen["sha256"]:
            raise ValueError("retained artifact changed or escaped its workspace")
        with path.open("rb") as stream:
            stream.seek(position)
            data = stream.read(count)
        result["bytes"] = {"artifact_index": index, "byte_offset": position, "size_bytes": len(data), "base64": base64.b64encode(data).decode("ascii"), "has_more": position + len(data) < chosen["size_bytes"]}
    return result


def execute(operation: str, values: dict) -> dict:
    if operation == "forge_read_traffic_result":
        receipt = bounded_file(values["receipt_path"], 64 * 1024)
        if not receipt.is_relative_to(WORK_ROOT.resolve(strict=True)) or sha256_file(receipt) != values["receipt_sha256"]:
            raise ValueError("traffic receipt changed or is outside retained workspace")
        record = read_json(receipt, 64 * 1024)
        if record.get("kind") != "forge_offline_traffic":
            raise ValueError("unsupported retained traffic receipt")
        full = bounded_file(record["full_result"]["path"], MAX_JSON)
        if full.parent != receipt.parent or sha256_file(full) != record["full_result"]["sha256"]:
            raise ValueError("retained traffic result changed or escaped its workspace")
        document = read_json(full, MAX_JSON)
    else:
        selected = read_json(CONFIG_PATH, 64 * 1024)[FAMILY[operation]]
        workspace = WORK_ROOT / secrets.token_hex(16)
        workspace.mkdir(parents=True, exist_ok=False)
        target, document, engine = pcap(operation, values, selected, workspace) if FAMILY[operation] == "pcap" else api_asset(operation, values, selected, workspace)
        full = workspace / "result.json"
        write_json(full, document)
        record = {"kind": "forge_offline_traffic", "target": target, "engine": engine, "full_result": identity(full), "analysis_parameters": values}
        receipt = workspace / "receipt.json"
        write_json(receipt, record)
    result = selected_page(record, document, values)
    result.update({"receipt_path": str(receipt), "receipt_sha256": sha256_file(receipt), "historical_readback": operation == "forge_read_traffic_result"})
    return {"operation": operation, "target": record["target"], "result": result, "engine": record["engine"], "workspace": str(receipt.parent), "sample_execution": False, "network_used": False}


def main() -> None:
    try:
        if len(sys.argv) != 2:
            raise ValueError("one owned request is required")
        value = read_json(Path(sys.argv[1]), 4 * 1024 * 1024)
        if set(value) != {"operation", "arguments"} or value["operation"] not in FAMILY or not isinstance(value["arguments"], dict):
            raise ValueError("invalid offline traffic request")
        print(json.dumps({"ok": True, "value": execute(value["operation"], value["arguments"])}), flush=True)
    except Exception as cause:
        error = {"kind": type(cause).__name__, "message": str(cause)}
        if isinstance(cause, TimeoutError) and "value" in locals():
            error["timeout_ms"] = value.get("arguments", {}).get("timeout_ms", 35000)
        print(json.dumps({"ok": False, "error": error}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
