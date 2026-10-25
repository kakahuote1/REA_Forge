"""Bounded static PE facts migrated from the local audited workbench.

Source SHA256 1d86f66db64f8f979383c599a970d4e8b105f0ed09520259b3909362b2596e6c.
No legacy control-plane imports; pefile parses data and never loads a PE.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Any

import pefile


_MAX_COLLECTION = 4096
_MAX_RESOURCE_LEAVES = 1024
_MAX_IMPORT_MODULES = 512
_MAX_IMPORT_SYMBOLS_PER_MODULE = 64
_MAX_IMPORT_SYMBOLS_PER_TABLE = 1024
_MAX_EXPORT_SYMBOLS = 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _hex(value: int, width: int = 0) -> str:
    return "0x" + format(int(value), "0%dX" % width if width else "X")


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None:
        return ""
    return str(value)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [count / len(data) for count in Counter(data).values()]
    return round(-sum(item * math.log2(item) for item in frequencies if item), 6)


def _directory(pe: Any, index: int) -> Any:
    directories = getattr(getattr(pe, "OPTIONAL_HEADER", None), "DATA_DIRECTORY", [])
    return directories[index] if 0 <= index < len(directories) else None


def _directory_range(pe: Any, index: int) -> tuple[int, int]:
    directory = _directory(pe, index)
    if directory is None:
        return 0, 0
    return int(directory.VirtualAddress), int(directory.Size)


def _imports(pe: Any, attribute: str, kind: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    remaining_symbols = _MAX_IMPORT_SYMBOLS_PER_TABLE
    for entry in list(getattr(pe, attribute, []) or [])[:_MAX_IMPORT_MODULES]:
        available = list(getattr(entry, "imports", []) or [])
        retained = available[: min(_MAX_IMPORT_SYMBOLS_PER_MODULE, remaining_symbols)]
        symbols = []
        for symbol in retained:
            symbols.append(
                {
                    "name": _text(getattr(symbol, "name", None)),
                    "ordinal": int(getattr(symbol, "ordinal", 0) or 0),
                    "address": _hex(int(getattr(symbol, "address", 0) or 0)),
                    "import_by_ordinal": getattr(symbol, "name", None) is None,
                }
            )
        remaining_symbols -= len(retained)
        records.append(
            {
                "kind": kind,
                "dll": _text(getattr(entry, "dll", None)).casefold(),
                "symbol_count": len(available),
                "symbols": symbols,
                "symbols_truncated": len(retained) < len(available),
            }
        )
    return records


def _import_table_summary(pe: Any, attribute: str) -> dict[str, Any]:
    entries = list(getattr(pe, attribute, []) or [])
    return {"module_count": len(entries), "modules_truncated": len(entries) > _MAX_IMPORT_MODULES}


def _bound_imports(pe: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry in list(getattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT", []) or [])[:_MAX_COLLECTION]:
        records.append(
            {
                "dll": _text(getattr(entry, "name", None)).casefold(),
                "timestamp": _hex(int(getattr(entry, "struct", entry).TimeDateStamp if getattr(entry, "struct", None) else 0), 8),
                "references": [_text(getattr(ref, "name", None)).casefold() for ref in list(getattr(entry, "entries", []) or [])[:128]],
            }
        )
    return records


def _exports(pe: Any) -> dict[str, Any]:
    export_rva, export_size = _directory_range(pe, 0)
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return {"dll": "", "symbol_count": 0, "symbols": [], "symbols_truncated": False}
    symbols = []
    available = list(getattr(directory, "symbols", []) or [])
    for symbol in available[:_MAX_EXPORT_SYMBOLS]:
        address = int(getattr(symbol, "address", 0) or 0)
        forwarder = _text(getattr(symbol, "forwarder", None))
        if not forwarder and export_rva <= address < export_rva + export_size:
            try:
                forwarder = _text(pe.get_string_at_rva(address))
            except (AttributeError, ValueError):
                forwarder = ""
        symbols.append(
            {
                "name": _text(getattr(symbol, "name", None)),
                "ordinal": int(getattr(symbol, "ordinal", 0) or 0),
                "rva": _hex(address, 8),
                "forwarder": forwarder,
            }
        )
    return {
        "dll": _text(getattr(directory, "name", None)).casefold(),
        "symbol_count": len(available),
        "symbols": symbols,
        "symbols_truncated": len(symbols) < len(available),
    }


def _resource_summary(pe: Any) -> list[dict[str, Any]]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return []
    result: list[dict[str, Any]] = []
    for entry in list(getattr(root, "entries", []) or [])[:_MAX_COLLECTION]:
        name = _text(getattr(entry, "name", None)) or str(getattr(entry, "id", "unknown"))
        count = 0
        stack = list(getattr(getattr(entry, "directory", None), "entries", []) or [])
        while stack and count < _MAX_RESOURCE_LEAVES:
            item = stack.pop()
            children = list(getattr(getattr(item, "directory", None), "entries", []) or [])
            if children:
                stack.extend(children)
            elif getattr(item, "data", None) is not None:
                count += 1
        result.append({"type": name, "leaf_count": count, "truncated": bool(stack)})
    return result


def _sections(pe: Any) -> list[dict[str, Any]]:
    result = []
    for section in list(getattr(pe, "sections", []) or [])[:_MAX_COLLECTION]:
        raw_name = bytes(getattr(section, "Name", b"")).split(b"\0", 1)[0]
        data = section.get_data()
        result.append(
            {
                "name": raw_name.decode("ascii", errors="replace"),
                "virtual_address": _hex(int(section.VirtualAddress), 8),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_offset": _hex(int(section.PointerToRawData), 8),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": _hex(int(section.Characteristics), 8),
                "entropy": _entropy(data),
            }
        )
    return result


def _version_info(pe: Any) -> dict[str, Any]:
    fixed = getattr(pe, "VS_FIXEDFILEINFO", None)
    if isinstance(fixed, (list, tuple)):
        fixed = fixed[0] if fixed else None
    if fixed is None:
        return {"present": False, "file_version": "", "product_version": ""}
    try:
        file_ms = int(getattr(fixed, "FileVersionMS", 0) or 0)
        file_ls = int(getattr(fixed, "FileVersionLS", 0) or 0)
        product_ms = int(getattr(fixed, "ProductVersionMS", 0) or 0)
        product_ls = int(getattr(fixed, "ProductVersionLS", 0) or 0)
    except (TypeError, ValueError):
        return {"present": False, "file_version": "", "product_version": ""}

    def render(high: int, low: int) -> str:
        return ".".join(str(value) for value in ((high >> 16) & 0xFFFF, high & 0xFFFF, (low >> 16) & 0xFFFF, low & 0xFFFF))

    return {"present": True, "file_version": render(file_ms, file_ls), "product_version": render(product_ms, product_ls)}


def _security(pe: Any) -> dict[str, Any]:
    optional = pe.OPTIONAL_HEADER
    flags = int(getattr(optional, "DllCharacteristics", 0))
    certificate = _directory(pe, 4)
    load_config = getattr(getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None), "struct", None)
    exception_entries = list(getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []) or [])
    tls = getattr(getattr(pe, "DIRECTORY_ENTRY_TLS", None), "struct", None)
    clr = _directory(pe, 14)
    callbacks: list[str] = []
    if tls is not None:
        try:
            pointer_size = 8 if int(optional.Magic) == 0x20B else 4
            callback_va = int(getattr(tls, "AddressOfCallBacks", 0) or 0)
            callback_rva = callback_va - int(optional.ImageBase) if callback_va >= int(optional.ImageBase) else callback_va
            callback_offset = pe.get_offset_from_rva(callback_rva)
            raw = getattr(pe, "__data__", b"")
            for index in range(256):
                cursor = callback_offset + pointer_size * index
                value = int.from_bytes(raw[cursor : cursor + pointer_size], "little")
                if not value:
                    break
                callbacks.append(_hex(value - int(optional.ImageBase) if value >= int(optional.ImageBase) else value, 8))
        except (AttributeError, TypeError, ValueError):
            callbacks = []
    exception_facts = []
    for entry in exception_entries[:_MAX_COLLECTION]:
        structure = getattr(entry, "struct", None)
        exception_facts.append({"begin_rva": _hex(int(getattr(structure, "BeginAddress", 0) or 0), 8), "end_rva": _hex(int(getattr(structure, "EndAddress", 0) or 0), 8), "unwind_rva": _hex(int(getattr(structure, "UnwindData", 0) or 0), 8)})
    try:
        rich_hash = _text(pe.get_rich_header_hash())
    except (AttributeError, ValueError):
        rich_hash = ""
    return {
        "aslr": {"enabled": bool(flags & 0x0040), "flag": "DYNAMIC_BASE"},
        "dep": {"enabled": bool(flags & 0x0100), "flag": "NX_COMPAT"},
        "cfg": {"enabled": bool(flags & 0x4000), "flag": "GUARD_CF", "guard_flags": _hex(int(getattr(load_config, "GuardFlags", 0) or 0), 8)},
        "seh": {"no_seh": bool(flags & 0x0400), "exception_entry_count": len(exception_entries), "exceptions": exception_facts},
        "tls": {"present": tls is not None, "callback_table_va": _hex(int(getattr(tls, "AddressOfCallBacks", 0) or 0)) if tls is not None else "0x0", "callback_rvas": callbacks},
        "clr": {"present": bool(clr and (clr.VirtualAddress or clr.Size)), "rva": _hex(int(clr.VirtualAddress), 8) if clr else "0x0", "size": int(clr.Size) if clr else 0},
        "certificate": {
            "directory_present": bool(certificate and certificate.Size),
            "file_offset": _hex(int(certificate.VirtualAddress), 8) if certificate else "0x0",
            "size": int(certificate.Size) if certificate else 0,
            "offline_status": "present_not_verified" if certificate and certificate.Size else "absent",
        },
        "rich_header": {"present": bool(rich_hash), "hash": rich_hash},
        "load_config": {"present": load_config is not None, "guard_flags": _hex(int(getattr(load_config, "GuardFlags", 0) or 0), 8), "security_cookie": _hex(int(getattr(load_config, "SecurityCookie", 0) or 0))},
    }


def parse_pe(path: Path) -> dict[str, Any]:
    """Return bounded PE facts or a typed non-PE fact; never execute input."""
    identity = {"path": str(path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size}
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except (OSError, ValueError, pefile.PEFormatError) as error:
        return {"schema_version": "e11-pe-facts-v1", "identity": identity, "is_pe": False, "parse_error": type(error).__name__, "source_execution": False, "network_used": False}
    try:
        directories = []
        for index, directory in enumerate(list(getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", []) or [])):
            directories.append({"index": index, "name": _text(pefile.DIRECTORY_ENTRY.get(index, "UNKNOWN")).removeprefix("IMAGE_DIRECTORY_ENTRY_"), "rva_or_file_offset": _hex(int(directory.VirtualAddress), 8), "size": int(directory.Size), "present": bool(directory.VirtualAddress or directory.Size)})
        overlay_start = pe.get_overlay_data_start_offset()
        imports = _imports(pe, "DIRECTORY_ENTRY_IMPORT", "normal")
        delay_imports = _imports(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", "delay")
        return {
            "schema_version": "e11-pe-facts-v1",
            "identity": identity,
            "is_pe": True,
            "machine": _hex(int(pe.FILE_HEADER.Machine), 4),
            "is_dll": bool(int(pe.FILE_HEADER.Characteristics) & 0x2000),
            "format": "PE32+" if int(pe.OPTIONAL_HEADER.Magic) == 0x20B else "PE32" if int(pe.OPTIONAL_HEADER.Magic) == 0x10B else "unknown",
            "headers": {
                "entry_point_rva": _hex(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint), 8),
                "image_base": _hex(int(pe.OPTIONAL_HEADER.ImageBase)),
                "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
                "timestamp": _hex(int(pe.FILE_HEADER.TimeDateStamp), 8),
                "dll_characteristics": _hex(int(pe.OPTIONAL_HEADER.DllCharacteristics), 4),
            },
            "version_info": _version_info(pe),
            "sections": _sections(pe),
            "collection_limits": {
                "import_modules_per_table": _MAX_IMPORT_MODULES,
                "import_symbols_per_module": _MAX_IMPORT_SYMBOLS_PER_MODULE,
                "import_symbols_per_table": _MAX_IMPORT_SYMBOLS_PER_TABLE,
                "export_symbols": _MAX_EXPORT_SYMBOLS,
            },
            "import_table_summary": {
                "normal": _import_table_summary(pe, "DIRECTORY_ENTRY_IMPORT"),
                "delay": _import_table_summary(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"),
            },
            "data_directories": directories,
            "imports": imports,
            "delay_imports": delay_imports,
            "bound_imports": _bound_imports(pe),
            "exports": _exports(pe),
            "resources": _resource_summary(pe),
            "security": _security(pe),
            "overlay": {"present": overlay_start is not None, "file_offset": _hex(int(overlay_start or 0), 8), "size": max(0, path.stat().st_size - int(overlay_start or path.stat().st_size))},
            "source_execution": False,
            "network_used": False,
        }
    finally:
        pe.close()
