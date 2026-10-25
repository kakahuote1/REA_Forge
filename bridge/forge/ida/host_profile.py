"""Task-owned IDA user profile: official duplicate-name precedence, no install edits."""
from __future__ import annotations

import hashlib
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import stat
import sys

from common.static_files import identity, pinned, read_json

# IDA9.1 searches IDAUSR/plugins before installation plugins, ignoring later
# duplicate stems, including Python versus DLL. This is an application profile,
# not an OS sandbox. Original plugins, user configuration and licenses stay put.
STUB = '''import ida_idaapi
class ForgeSkippedPlugin_PLACEHOLDER(ida_idaapi.plugin_t):
    flags = 0
    comment = "REA Forge static profile"
    help = ""
    wanted_name = "Forge skipped plugin"
    wanted_hotkey = ""
    def init(self):
        return ida_idaapi.PLUGIN_SKIP
    def run(self, arg):
        return None
    def term(self):
        return None
def PLUGIN_ENTRY():
    return ForgeSkippedPlugin_PLACEHOLDER()
'''


def plugin_inventory(root: Path) -> dict[str, Path]:
    plugins = root / "plugins"
    if plugins.is_symlink() or not plugins.is_dir():
        raise ValueError("IDA installation plugin directory is unavailable")
    result = {}
    for path in sorted(plugins.iterdir()):
        state = path.lstat()
        if path.is_symlink() or getattr(state, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("IDA plugin inventory traverses a reparse point")
        if path.is_file() and path.suffix.casefold() in {".py", ".dll"}:
            stem = path.stem.casefold()
            if stem in result or not stem or any(not (char.isalnum() or char in "_-. ") for char in stem):
                raise ValueError("IDA plugin inventory has ambiguous duplicate or unsupported stem")
            result[stem] = path
        if len(result) > 256:
            raise ValueError("IDA plugin inventory exceeds static profile bound")
    # IDA9.1 additionally discovers nested descriptor-based plugins. Inventory
    # their declared entry points, not every utility Python module as a plugin.
    pending, directories, files = [plugins], 0, 0
    while pending:
        directory = pending.pop()
        directories += 1
        if directories > 512:
            raise ValueError("IDA plugin metadata directory bound exceeded")
        for path in directory.iterdir():
            state = path.lstat()
            if path.is_symlink() or getattr(state, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                raise ValueError("IDA plugin metadata traverses a reparse point")
            if path.is_dir():
                if path.name != "__pycache__":
                    pending.append(path)
                continue
            files += 1
            if files > 8192:
                raise ValueError("IDA plugin metadata file bound exceeded")
            if path.name != "ida-plugin.json":
                continue
            descriptor = read_json(path, 65536)
            entry = descriptor.get("plugin", {}).get("entryPoint")
            if not isinstance(entry, str) or not entry or Path(entry).is_absolute() or ".." in Path(entry).parts:
                raise ValueError("IDA plugin descriptor has an unsupported entry point")
            candidate = path.parent / entry
            stem = candidate.stem.casefold()
            if not candidate.is_file() or candidate.suffix.casefold() not in {".py", ".dll"} or not candidate.resolve().is_relative_to(plugins):
                raise ValueError("IDA plugin descriptor entry escaped its installation")
            if not stem or any(not (char.isalnum() or char in "_-. ") for char in stem) or stem in result and result[stem] != candidate:
                raise ValueError("IDA plugin descriptor has an ambiguous stem")
            result[stem] = candidate
            if len(result) > 256:
                raise ValueError("IDA plugin inventory exceeds static profile bound")
    return result


def prepare(selected: dict, workspace: Path) -> dict:
    root = Path(selected["install_root"]).resolve(strict=True)
    library = pinned(selected, "idalib")
    if library.parent != root or library.name.casefold() != "idalib.dll":
        raise ValueError("selected IDALib does not belong to the configured installation")
    package = pinned(selected, "idapro_entry")
    configuration = pinned(selected, "idapro_config")
    if package != root / "idalib" / "python" / "idapro" / "__init__.py" or configuration != package.parent / "config.py":
        raise ValueError("selected IDALib Python initialization differs from the reviewed profile")
    inventory = plugin_inventory(root)
    allowed = {}
    # Approval is explicit file pins, not a prefix matching arbitrary hex*.dll.
    builtins = {"idapython3", "hexx64", "hexarm", "hexarc", "hexmips", "hexppc", "hexrv", "dwarf", "dbg", "eh_parse"}
    for plugin in selected.get("approved_plugins", []):
        path = pinned({"plugin": plugin}, "plugin")
        stem = path.stem.casefold()
        if stem not in builtins or inventory.get(stem) != path or path.suffix.casefold() != ".dll":
            raise ValueError("static profile only admits explicitly pinned installed Python/offline decompiler plugins")
        allowed[stem] = identity(path)
    if "idapython3" not in allowed:
        raise ValueError("static profile requires an explicitly pinned IDAPython runtime")
    profile = workspace / "ida-user"
    plugins = profile / "plugins"
    plugins.mkdir(parents=True)
    blocked = []
    configuration_lines = ["; Task-owned headless exclusions. GUI is an installed IDA9.1 plugins.cfg flag."]
    for stem, path in inventory.items():
        if stem in allowed:
            continue
        # IDAPython registers class names across files: one reused class name
        # produces internal error30602 rather than a harmless skipped plugin.
        class_suffix = hashlib.sha256(stem.encode()).hexdigest()[:16]
        (plugins / (path.stem + ".py")).write_text(STUB.replace("PLACEHOLDER", class_suffix), encoding="utf-8")
        if path.parent != root / "plugins":
            relative = path.relative_to(root / "plugins")
            replacement = plugins / relative
            replacement.parent.mkdir(parents=True, exist_ok=True)
            replacement.write_text(STUB.replace("PLACEHOLDER", class_suffix + "_descriptor"), encoding="utf-8")
            original_descriptor = path.parent / "ida-plugin.json"
            if original_descriptor.is_file():
                descriptor = read_json(original_descriptor, 65536)
                (replacement.parent / "ida-plugin.json").write_text(json.dumps(descriptor), encoding="utf-8")
        configuration_lines.append(f"Forge_skip_{class_suffix} {path.stem} 0 0 GUI SILENT")
        blocked.append({"stem": stem, "original": identity(path)})
    (plugins / "plugins.cfg").write_text("\n".join(configuration_lines) + "\n", encoding="ascii")
    appdata = workspace / "appdata"
    activation = appdata / "Hex-Rays" / "IDA Pro"
    activation.mkdir(parents=True)
    (activation / "ida-config.json").write_text(json.dumps({"Paths": {"ida-install-dir": str(root)}}), encoding="utf-8")
    (appdata / "Local").mkdir()
    return {"ida_user": str(profile), "appdata": str(appdata), "install_root": str(root), "idapro_python": str(package.parent.parent),
            "allowed_plugins": allowed, "blocked_plugins": blocked, "plugin_inventory_sha256": hashlib.sha256(json.dumps({name: identity(path) for name, path in inventory.items()}, sort_keys=True).encode()).hexdigest(),
            "mechanism": "official IDAUSR first duplicate plugin-stem precedence; not an OS sandbox"}


def activate(profile: dict) -> None:
    os.environ.update(IDAUSR=profile["ida_user"], IDADIR=profile["install_root"], APPDATA=profile["appdata"], LOCALAPPDATA=str(Path(profile["appdata"]) / "Local"),
                      IDALOG=str(Path(profile["ida_user"]).parent / "idalib.log"), IDALOG_SILENT="1",
                      IDA_MCP_TRACE="0", IDA_MCP_TOOL_TIMEOUT_SEC="20", PYTHONDONTWRITEBYTECODE="1")


def loaded_plugins(profile: dict) -> list[dict]:
    """Observe this process's actual DLL/Python paths; no target PID is accepted.

    IDA9.1 exposes plugin_info_t but no get_plugin_infos Python accessor. Use
    OS module observations rather than invoking a newer-only SDK operation.
    This observation is not a network sandbox or proof of all past execution.
    """
    if os.name != "nt":
        raise ValueError("this fixed IDA profile requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetModuleFileNameW.restype = wintypes.DWORD
    handles, needed = (wintypes.HMODULE * 2048)(), wintypes.DWORD()
    if not kernel.K32EnumProcessModules(kernel.GetCurrentProcess(), handles, ctypes.sizeof(handles), ctypes.byref(needed)) or needed.value > ctypes.sizeof(handles):
        raise ValueError("current IDALib module observation is unavailable or truncated")
    paths = []
    for index in range(needed.value // ctypes.sizeof(wintypes.HMODULE)):
        text = ctypes.create_unicode_buffer(32768)
        count = kernel.GetModuleFileNameW(handles[index], text, len(text))
        if not count or count == len(text):
            raise ValueError("current IDALib module path is unavailable or truncated")
        paths.append(("native", Path(text.value)))
    for module in tuple(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if isinstance(path, str):
            paths.append(("python", Path(path)))
    original = Path(profile["install_root"]) / "plugins"
    allowed = {str(Path(pin["path"]).resolve()).casefold() for pin in profile["allowed_plugins"].values()}
    observed, refused = [], []
    for kind, path in paths:
        resolved = path.resolve()
        if resolved.is_relative_to(original):
            if str(resolved).casefold() not in allowed:
                refused.append(str(resolved))
            observed.append({"kind": kind, "path": str(resolved)})
    if refused:
        raise ValueError("unapproved original plugins in current IDALib module observation: " + json.dumps(sorted(set(refused))))
    return observed
