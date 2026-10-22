"""Read explicit operator-owned paths; never discover or start tools implicitly."""

from dataclasses import dataclass
import json
from pathlib import Path


from common.paths import PROJECT_ROOT, PRIVATE_ROOT, CONFIG_PATH


@dataclass(frozen=True)
class EditorConfiguration:
    executable: Path
    executable_sha256: str
    input_roots: tuple[Path, ...]
    asset_roots: tuple[Path, ...]
    workspace_root: Path
    reviewed_template_root: Path


def read_configuration() -> EditorConfiguration:
    if CONFIG_PATH.is_symlink():
        raise ValueError("operator tool configuration must not be a symlink")
    value = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or not isinstance(value.get("editor010"), dict):
        raise ValueError("010 Editor is not configured")
    selected = value["editor010"]
    required = {"executable", "executable_sha256", "input_roots", "asset_roots"}
    if set(selected) != required:
        raise ValueError("010 configuration has missing or unknown settings")
    executable = Path(selected["executable"])
    expected = selected["executable_sha256"]
    if (not executable.is_absolute() or executable.is_symlink()
            or not isinstance(expected, str) or len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)):
        raise ValueError("010 executable requires an absolute path and SHA-256 pin")
    roots = []
    for key in ("input_roots", "asset_roots"):
        items = selected[key]
        if not isinstance(items, list) or not items or not all(isinstance(item, str) for item in items):
            raise ValueError("010 configured roots must be nonempty explicit path arrays")
        paths = tuple(Path(item) for item in items)
        if any(not path.is_absolute() or path.is_symlink() for path in paths):
            raise ValueError("010 roots must be absolute non-symlink paths")
        roots.append(paths)
    workspace = PRIVATE_ROOT / "work" / "010editor"
    return EditorConfiguration(executable, expected, roots[0] + (workspace,),
                               roots[1], workspace, PRIVATE_ROOT / "assets" / "010editor")
