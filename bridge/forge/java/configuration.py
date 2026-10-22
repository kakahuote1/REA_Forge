"""Explicit engine pins and input roots for the static Java adapter."""
import hashlib
import json
from pathlib import Path

from common.hard_deny_policy import HardDenyPolicy
from common.paths import CONFIG_PATH, PRIVATE_ROOT, PROJECT_ROOT


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def configuration() -> dict:
    if CONFIG_PATH.is_symlink():
        raise ValueError("local configuration must not be a symlink")
    selected = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")).get("java")
    if not isinstance(selected, dict):
        raise ValueError("static Java engines are not configured")
    return selected


def pinned_engine(selected: dict, name: str) -> Path:
    value = selected.get(name)
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError(f"explicit {name} engine identity is missing")
    path = Path(value["path"])
    HardDenyPolicy().require_local_path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or sha256(path) != value["sha256"]:
        raise ValueError(f"{name} engine identity drifted")
    return path


def worker_classes(engine: str) -> Path:
    build = PRIVATE_ROOT / "build" / "java"
    receipt = json.loads((build / "manifest.json").read_text(encoding="utf-8"))
    source = PROJECT_ROOT / "bridge" / "forge" / "java" / engine / "Worker.java"
    selected = receipt[engine]
    if selected["engine_sha256"] != configuration()[engine]["sha256"]:
        raise ValueError("Java engine changed; rebuild the worker first")
    if sha256(source) != selected["source_sha256"]:
        raise ValueError("Java worker source changed; rebuild the worker first")
    classes = build / engine
    for relative, digest in selected["classes"].items():
        path = classes / relative
        if path.is_symlink() or not path.resolve().is_relative_to(classes.resolve()) or sha256(path) != digest:
            raise ValueError("Java worker class identity drifted")
    return classes
