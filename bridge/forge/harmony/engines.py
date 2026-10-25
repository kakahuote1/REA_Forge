"""Fixed static ABC/Ark/JADX-HAP/vendor-signing calls; no GUI, target runtime or plugin arguments."""
from __future__ import annotations

import json
from collections import Counter
from itertools import islice
import os
from pathlib import Path
import re
import sys
import time

from common.static_files import bounded_file, identity, pinned, read_json, run_native, sha256_file
from harmony.archive import abc_header, inspect_archive


def native(command: list[str], workspace: Path, values: dict, prefix: str, *, accepted=frozenset({0})):
    deadline = values.setdefault("_deadline", time.monotonic() + values.get("timeout_ms", 45000) / 1000)
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining < 1:
        raise TimeoutError("Harmony pipeline exceeded selected deadline")
    temporary = str(Path(sys.argv[1]).resolve(strict=True).parent)
    return run_native(command, workspace, timeout_ms=remaining, prefix=prefix, accepted_exit_codes=accepted,
                      environment_overrides={"HOME": temporary, "USERPROFILE": temporary, "JADX_CONFIG_DIR": temporary,
                                             "JADX_CACHE_DIR": temporary, "JADX_TMP_DIR": temporary})


def java(selected: dict, workspace: Path) -> list[str]:
    temporary = str(Path(sys.argv[1]).resolve(strict=True).parent)
    return [str(pinned(selected, "java")), "-XX:-UsePerfData", "-Xmx512m", "-XX:ActiveProcessorCount=2", "-Djava.awt.headless=true", "-Dfile.encoding=UTF-8",
            "-Duser.home=" + temporary, "-Djava.io.tmpdir=" + temporary]


def abc(selected: dict, source: Path, workspace: Path, values: dict, action: str) -> tuple[dict, list[dict]]:
    if action == "resources":
        with source.open("rb") as stream:
            magic = stream.read(16)
        if magic.startswith(b"RestoolV2"):
            raise ValueError("pinned abcde does not support RestoolV2; original index retained")
        if not magic.startswith(b"Restool "):
            raise ValueError("unknown resource index format")
        facts = {"format": "legacy Restool resource index", "sha256": sha256_file(source)}
    else:
        facts = abc_header(source)
    jar = pinned(selected, "jar")
    output = workspace / ("abc-result.jsonl" if action in {"methods", "disassemble", "decompile"} else "abc-result.txt" if action == "classes" else "abc-result.json")
    if action in {"classes", "resources"}:
        command = [*java(selected, workspace), "-jar", str(jar), "--cli", "--dump-class" if action == "classes" else "--dump-index", str(source), "--out=" + str(output)]
    else:
        reader = pinned(selected, "reader")
        command = [*java(selected, workspace), "-cp", str(reader.parent) + os.pathsep + str(jar), "AbcdeReader", action, str(source), str(output), str(values.get("method_offset", 0))]
    stdout, stderr, timing = native(command, workspace, values, "abcde", accepted=frozenset({0, 1}))
    if timing["exit_code"] != 0:
        diagnostic = stderr.read_text(encoding="utf-8", errors="replace")
        unsupported = re.search(r"ToJs\$UnImplementedError: 对字节码([a-z0-9_.]+)的解析尚未实现", diagnostic)
        if unsupported:
            raise ValueError("experimental abcde JS does not support instruction: " + unsupported.group(1))
        if "does not support try/catch" in diagnostic:
            raise ValueError("experimental abcde JS does not support try/catch")
        raise ValueError("fixed abcde operation failed; partial output is not a completed result")
    bounded_file(output, 128 * 1024 * 1024)
    if output.stat().st_size == 0:
        raise ValueError("abcde produced an empty artifact")
    rows, kinds = [], Counter()
    if action in {"methods", "disassemble", "decompile"}:
        receipt = read_json(stdout, 4096)
        if receipt.get("ok") is not True or receipt.get("action") != action:
            raise ValueError("abcde reader returned an inconsistent completion receipt")
        row_count = receipt["rows"]
        if row_count > 500000 or receipt.get("output_bytes") != output.stat().st_size:
            raise ValueError("abcde reader output exceeds or differs from its completion extent")
        with output.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream):
                if len(line) > 1024 * 1024:
                    raise ValueError("abcde row exceeds1MiB bound")
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError("abcde row is not an object")
                kinds[str(parsed.get("kind", "unknown"))] += 1
                if number < 100:
                    rows.append(parsed)
        if number + 1 != row_count:
            raise ValueError("abcde result row count differs")
    elif action == "classes":
        row_count = 0
        with output.open(encoding="utf-8-sig") as stream:
            for line in stream:
                if len(line) > 1024 * 1024:
                    raise ValueError("abcde class line exceeds1MiB bound")
                if line.strip():
                    row_count += 1
                    if len(rows) < 100:
                        rows.append(line.rstrip("\r\n"))
    else:
        data = read_json(output)
        row_count = len(data)
        rows = [{"id": key, "value": value} for key, value in islice(data.items(), 100)]
    result = {"header": facts, "action": action, "rows": rows, "row_count": row_count, "counts_by_kind": dict(kinds), "inline_truncated": row_count > len(rows),
              "artifact": identity(output), "timing": timing, "experimental": action == "decompile", "semantics_verified": False,
              "reference_semantics": "encoded method/string operands include definitions and literals; not a resolved runtime call graph",
              "engine": {"jar": identity(jar), "reader": identity(pinned(selected, "reader")) if action in {"methods", "disassemble", "decompile"} else None, "binary_build_commit": "unknown"}}
    return result, [identity(output), identity(stdout), identity(stderr)]


def ark(selected: dict, source: Path, workspace: Path, values: dict) -> tuple[dict, list[dict]]:
    facts = abc_header(source)
    output = workspace / "ark-disassembly.pa"
    executable = pinned(selected, "executable")
    stdout, stderr, timing = native([str(executable), "--verbose", str(source), str(output)], workspace, values, "ark")
    bounded_file(output, 256 * 1024 * 1024)
    if output.stat().st_size == 0:
        raise ValueError("Ark produced an empty disassembly")
    lines = functions = records = 0
    sample = []
    with output.open(encoding="utf-8", errors="backslashreplace") as stream:
        for line in stream:
            lines += 1
            functions += line.lstrip().startswith(".function ")
            records += line.lstrip().startswith(".record ")
            if len(sample) < 40 and len(line) <= 4000:
                sample.append(line.rstrip("\r\n"))
    return {"header": facts, "line_count": lines, "function_count": functions, "record_count": records, "preview": sample,
            "artifact": identity(output), "timing": timing, "display_encoding": "UTF-8 with invalid bytes escaped; artifact byte-exact",
            "engine": {"executable": identity(executable), "version": selected["version"]}}, [identity(output), identity(stdout), identity(stderr)]


def jadx(selected: dict, source: Path, workspace: Path, values: dict) -> tuple[dict, list[dict]]:
    extracted = inspect_archive(source, workspace / "package")
    inputs = extracted["abc"]
    if not 1 <= len(inputs) <= 32:
        raise ValueError("JADX-HAP requires1..32 explicit ABC members; resource-only output is not decompilation")
    for member in inputs:
        abc_header(Path(member["path"]))
    output = workspace / "jadx-output"
    jar = pinned(selected, "jar")
    stdout, stderr, timing = native([*java(selected, workspace), "-cp", str(jar), "jadx.cli.JadxCLI", "--log-level", "ERROR", "--output-dir", str(output), *[member["path"] for member in inputs]], workspace, values, "jadx-hap")
    outputs, total, count = [], 0, 0
    for parent, directories, files in os.walk(output, followlinks=False):
        for name in [*directories, *files]:
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError("JADX-HAP returned a symlink")
            count += 1
            if count > 10000:
                raise ValueError("JADX-HAP output entry count exceeds bound")
            if name in files:
                total += path.stat().st_size
                if total > 256 * 1024 * 1024:
                    raise ValueError("JADX-HAP output exceeds256MiB aggregate")
                outputs.append({"relative_path": path.relative_to(output).as_posix(), **identity(path)})
    source_outputs = [item for item in outputs if item["relative_path"].casefold().endswith((".java", ".kt", ".js", ".ts"))]
    if not source_outputs:
        raise ValueError("JADX-HAP generated no source artifact; resources alone do not pass")
    return {"input_abc": inputs, "outputs": outputs, "source_outputs": source_outputs, "source_reconstruction_verified": False, "timing": timing,
            "engine": {"jar": identity(jar), "binary_build_commit": "unknown"}}, [*outputs, identity(stdout), identity(stderr)]
