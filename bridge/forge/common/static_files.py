"""Bounded files and trusted native commands for short-lived REA static helpers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .hard_deny_policy import HardDenyPolicy

MAX_RESULT = 16 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bounded_file(raw: str | Path, maximum: int) -> Path:
    path = Path(raw)
    HardDenyPolicy().require_local_path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("requires an absolute local non-symlink file")
    selected = path.resolve(strict=True)
    if not selected.is_file() or selected.stat().st_size > maximum:
        raise ValueError("file exceeds its regular-file bound")
    return selected


def identity(path: Path) -> dict:
    return {"path": str(path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size}


def json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def reject_nonfinite(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def read_json(path: Path, maximum: int = MAX_RESULT) -> dict:
    selected = bounded_file(path, maximum)
    with selected.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("JSON file grew beyond its bound")
    try:
        value = json.loads(data, object_pairs_hook=json_object, parse_constant=reject_nonfinite)
    except RecursionError as cause:
        raise ValueError("JSON nesting exceeds parser capacity") from cause
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def pinned(selected: dict, name: str) -> Path:
    pin = selected[name]
    path = bounded_file(pin["path"], 512 * 1024 * 1024)
    if sha256_file(path) != pin["sha256"]:
        raise ValueError("configured static engine/database identity drifted")
    return path


def stage_input(selected: dict, source_path: str, workspace: Path, *, leaf: str, maximum: int) -> tuple[dict, Path]:
    source = bounded_file(source_path, maximum)
    roots = [Path(root).resolve(strict=True) for root in selected["input_roots"]]
    if not any(source.is_relative_to(root) for root in roots):
        raise ValueError("input is outside configured analysis roots")
    if Path(leaf).name != leaf or leaf in {".", ".."}:
        raise ValueError("staged filename must be one fixed leaf")
    staged = workspace / leaf
    state = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    digest = hashlib.sha256()
    total = 0
    with source.open("rb") as stream, staged.open("xb") as output:
        before = os.fstat(stream.fileno())
        while True:
            block = stream.read(min(65536, maximum - total + 1))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise ValueError("input grew beyond its bound")
            output.write(block)
            digest.update(block)
        after = os.fstat(stream.fileno())
    if state(before) != state(after) or state(after) != state(source.stat()) or total != before.st_size:
        raise ValueError("input changed during staged read")
    return {"path": str(source), "sha256": digest.hexdigest(), "size_bytes": total}, staged


def run_native(argv: list[str], workspace: Path, *, timeout_ms: int, prefix: str,
               maximum: int = MAX_RESULT, environment_overrides: dict[str, str] | None = None,
               maximum_timeout_ms: int = 45000, accepted_exit_codes: frozenset[int] = frozenset({0})) -> tuple[Path, Path, dict]:
    """The outer REA job owns this helper and all inherited engine descendants."""
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= maximum_timeout_ms:
        raise ValueError("invalid static engine deadline")
    if Path(prefix).name != prefix:
        raise ValueError("invalid fixed output prefix")
    stdout_path, stderr_path = workspace / (prefix + ".out"), workspace / (prefix + ".stderr")
    environment = dict(os.environ)
    excluded = {key.casefold() for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PYTHONPATH", "PYTHONHOME", "IDADIR", "IDAUSR", "IDAPYTHON_VERSION", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")}
    for key in tuple(environment):
        if key.casefold() in excluded:
            environment.pop(key)
    command_temp = str(Path(sys.argv[1]).resolve(strict=True).parent)
    environment.update({"NO_PROXY": "*", "no_proxy": "*", "TEMP": command_temp, "TMP": command_temp})
    environment.update(environment_overrides or {})
    started = time.monotonic()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        child = subprocess.Popen(argv, cwd=workspace, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 env=environment, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        failure = None
        try:
            while child.poll() is None:
                if time.monotonic() - started >= timeout_ms / 1000:
                    failure = TimeoutError("static engine exceeded its selected deadline")
                    break
                if stdout_path.stat().st_size > maximum or stderr_path.stat().st_size > 256 * 1024:
                    failure = ValueError("static engine output exceeded its file bound")
                    break
                time.sleep(0.025)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
        if failure is not None:
            raise failure
        if child.returncode not in accepted_exit_codes:
            raise ValueError("static engine returned nonzero status; bounded diagnostics retained")
    if stdout_path.stat().st_size > maximum or stderr_path.stat().st_size > 256 * 1024:
        raise ValueError("static engine output exceeded its file bound")
    return stdout_path, stderr_path, {"elapsed_seconds": time.monotonic() - started, "exit_code": child.returncode}
