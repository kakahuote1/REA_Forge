"""Fixed apktool project commands, independent of the user's GUI/cache."""
from __future__ import annotations

from pathlib import Path
import math
import sys
import time

from common.static_files import identity, pinned, sha256_file, stage_input
from android_build.project_files import copy_tree, edits, input_directory, load_receipt, tree, validate_apk
from common.static_files import run_native


def native(arguments: list[str], workspace: Path, values: dict, prefix: str, *, accepted_exit_codes: frozenset[int] = frozenset({0})) -> tuple:
    deadline = values.setdefault("_native_deadline", time.monotonic() + values.get("timeout_ms", 45000) / 1000)
    remaining = math.ceil((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise TimeoutError("Android native pipeline exceeded its selected deadline")
    stdout, stderr, timing = run_native(arguments, workspace, timeout_ms=min(45000, remaining), prefix=prefix, accepted_exit_codes=accepted_exit_codes)
    return stdout, stderr, {**timing, "stdout": identity(stdout), "stderr": identity(stderr)}


def engine(selected: dict, name: str, timing: dict) -> dict:
    return {"name": name, "version": selected["version"], "java_sha256": selected["java"]["sha256"], "jar_sha256": selected[name]["sha256"], **timing}


def java(selected: dict, jar_name: str, workspace: Path) -> list[str]:
    temporary = Path(sys.argv[1]).resolve(strict=True).parent
    return [str(pinned(selected, "java")), "-Xmx512m", "-XX:ActiveProcessorCount=2", "-XX:-UsePerfData", "-Djava.awt.headless=true",
            "-Djava.io.tmpdir=" + str(temporary), "-Duser.home=" + str(temporary), "-jar", str(pinned(selected, jar_name))]


def prepare(values: dict, selected: dict, workspace: Path) -> dict:
    source = Path(values["path"])
    project = workspace / "project"
    timing = {}
    if source.is_dir():
        source = input_directory(values["path"], selected)
        observed = copy_tree(source, project)
        target = {"path": str(source), "sha256": observed["sha256"], "size_bytes": observed["size_bytes"], "kind": "tree"}
        if not (project / "apktool.yml").is_file() or not (project / "AndroidManifest.xml").is_file():
            raise ValueError("import requires a decoded apktool project")
    else:
        target, staged = stage_input(selected, values["path"], workspace, leaf="input.apk", maximum=256 * 1024 * 1024)
        target["kind"] = "file"
        validate_apk(staged)
        framework = Path(sys.argv[1]).resolve(strict=True).parent / "framework"
        _, _, timing = native([*java(selected, "apktool", workspace), "d", "--force", "--frame-path", str(framework), "--output", str(project), str(staged)], workspace, values, "decode")
        if sha256_file(source.resolve(strict=True)) != target["sha256"]:
            raise ValueError("source APK changed while decoding")
    snapshot = tree(project)
    return {"kind": "android-project", "target": target, "project": snapshot, "artifacts": [], "action": "prepare", "engine": engine(selected, "apktool", timing)}


def build(values: dict, selected: dict, workspace: Path) -> dict:
    _, source = load_receipt(values, {"android-project"})
    project = workspace / "project"
    copy_tree(Path(source["project"]["root"]), project)
    changes = edits(project, values.get("changes", []), workspace)
    framework = Path(sys.argv[1]).resolve(strict=True).parent / "framework"
    output = workspace / "unsigned.apk"
    _, _, timing = native([*java(selected, "apktool", workspace), "b", "--force", "--frame-path", str(framework), "--output", str(output), str(project)], workspace, values, "build")
    validate_apk(output)
    # Recheck the borrowed source after the native engine settles.
    load_receipt(values, {"android-project"})
    return {"kind": "android-project", "target": source["target"], "project": tree(project), "artifacts": [identity(output), *[item["diff"] for item in changes]],
            "action": "build", "changes": changes, "engine": engine(selected, "apktool", timing)}
