"""Bounded, read-only PE dependency candidate resolver for E11.

This models static candidates only.  It never calls the Windows loader,
launches a binary, changes the registry, contacts a network endpoint, or
claims that a candidate is the actual runtime load result.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import xml.etree.ElementTree as element_tree
from collections import deque
from pathlib import Path
from typing import Any

import pefile

from .structure import _exports, _imports, _text, _version_info, sha256_file
from common.static_files import bounded_file


_SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
_SYSTEM32 = _SYSTEM_ROOT / "System32"
_SYSWOW64 = _SYSTEM_ROOT / "SysWOW64"
_WINSXS = _SYSTEM_ROOT / "WinSxS"
_APISET = _SYSTEM32 / "apisetschema.dll"
_MAX_NODES = 48
_MAX_DEPTH = 10
_MAX_EDGES = 512
_MAX_VALUES = 2048


def _digest_value(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _normal_dll(value: str) -> str:
    if not value or any(ord(char) < 32 or char in '\\/:<>"|?*' for char in value) or value.endswith((".", " ")):
        raise ValueError("dependency name is not one canonical DLL leaf")
    name = value.casefold()
    return name if name.endswith(".dll") else name + ".dll"


def _u16(data: bytes, offset: int, length: int) -> str:
    if offset < 0 or length < 0 or offset + length > len(data) or length % 2:
        return ""
    return data[offset : offset + length].decode("utf-16-le", errors="replace")


def api_set_snapshot() -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Parse ApiSet namespace v6 from the fixed local system schema DLL."""
    if not _APISET.is_file():
        return {}, {"available": False, "reason": "apisetschema_missing"}
    try:
        pe = pefile.PE(str(_APISET), fast_load=False)
        try:
            section = next((item for item in pe.sections if bytes(item.Name).split(b"\0", 1)[0] == b".apiset"), None)
            data = section.get_data() if section is not None else b""
        finally:
            pe.close()
        if len(data) < 28:
            raise ValueError("namespace_too_short")
        version, size, _flags, count, entry_offset, _hash_offset, _hash_factor = struct.unpack_from("<7I", data, 0)
        if version != 6 or size > len(data) or count > _MAX_VALUES:
            raise ValueError("namespace_version_or_bounds")
        data = data[:size]
        mapping: dict[str, list[str]] = {}
        for index in range(count):
            offset = entry_offset + index * 24
            if offset + 24 > size:
                raise ValueError("entry_bounds")
            _entry_flags, name_offset, name_length, _hashed_length, value_offset, value_count = struct.unpack_from("<6I", data, offset)
            contract = _u16(data, name_offset, name_length).casefold()
            if not contract or value_count > 32:
                continue
            hosts: list[str] = []
            for value_index in range(value_count):
                value_entry = value_offset + value_index * 20
                if value_entry + 20 > size:
                    raise ValueError("value_bounds")
                _value_flags, _alias_offset, _alias_length, host_offset, host_length = struct.unpack_from("<5I", data, value_entry)
                host = _u16(data, host_offset, host_length).casefold()
                if host:
                    hosts.append(_normal_dll(host))
            if hosts:
                mapping[_normal_dll(contract)] = sorted(set(hosts))
        metadata = {"available": True, "format": "apiset_namespace_v6", "path": str(_APISET), "sha256": sha256_file(_APISET), "entry_count": len(mapping), "snapshot_sha256": _digest_value(mapping)}
        return mapping, metadata
    except (OSError, ValueError, struct.error, pefile.PEFormatError) as error:
        return {}, {"available": False, "reason": type(error).__name__, "path": str(_APISET), "sha256": sha256_file(_APISET)}


def known_dll_snapshot() -> tuple[dict[str, str], dict[str, Any]]:
    """Read only the KnownDLL mapping; failure remains an explicit fact."""
    try:
        import winreg

        mapping: dict[str, str] = {}
        ignored = []
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs") as key:
            index = 0
            while index < _MAX_VALUES:
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                if isinstance(name, str) and isinstance(value, str) and name and value:
                    try:
                        mapping[_normal_dll(name)] = _normal_dll(value)
                    except ValueError:
                        ignored.append(name)
                index += 1
        return mapping, {"available": True, "source": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", "entry_count": len(mapping), "snapshot_sha256": _digest_value(mapping), "ignored_non_leaf_values": ignored}
    except (ImportError, OSError) as error:
        return {}, {"available": False, "reason": type(error).__name__}


def _manifest_snapshot(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    documents: list[dict[str, Any]] = []
    payloads: list[tuple[str, bytes, str]] = []
    try:
        pe = pefile.PE(str(path), fast_load=False)
        try:
            root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
            if root is not None:
                for item in list(getattr(root, "entries", []) or []):
                    if getattr(item, "id", None) != 24:
                        continue
                    for name in list(getattr(getattr(item, "directory", None), "entries", []) or []):
                        for language in list(getattr(getattr(name, "directory", None), "entries", []) or []):
                            data = getattr(language, "data", None)
                            struct_value = getattr(data, "struct", None)
                            if struct_value is not None:
                                payload = pe.get_data(struct_value.OffsetToData, struct_value.Size)
                                payloads.append(("embedded", payload, "embedded_resource"))
        finally:
            pe.close()
    except (OSError, pefile.PEFormatError, ValueError):
        pass
    sidecar = path.with_name(path.name + ".manifest")
    if sidecar.is_file() and not sidecar.is_symlink() and sidecar.stat().st_size <= 1024 * 1024:
        try:
            payloads.append(("sidecar", sidecar.read_bytes(), str(sidecar)))
        except OSError:
            pass
    identities: list[dict[str, str]] = []
    for kind, payload, location in payloads[:8]:
        document_facts: dict[str, Any] = {"kind": kind, "path": location, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload), "identities": []}
        try:
            if len(payload) > 1024 * 1024 or b"<!doctype" in payload.lower() or b"<!entity" in payload.lower():
                raise ValueError("manifest document declaration or size is unsupported")
            document = element_tree.fromstring(payload)
        except (element_tree.ParseError, ValueError):
            document_facts["parse_error"] = "xml_parse_error"
            documents.append(document_facts)
            continue
        for item in document.findall(".//{*}assemblyIdentity"):
            attributes = {key: value for key, value in item.attrib.items() if key in {"name", "version", "processorArchitecture", "publicKeyToken", "language", "type"}}
            if attributes.get("name"):
                document_facts["identities"].append(attributes)
                identities.append(attributes)
        documents.append(document_facts)
    return documents, identities[:64]


def _sxs_candidates(identities: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not _WINSXS.is_dir():
        return []
    candidates: list[dict[str, Any]] = []
    manifest_root = _WINSXS / "Manifests"
    for identity in identities[:16]:
        name = identity.get("name", "").casefold()
        if not re.fullmatch(r"[a-z0-9_.-]{1,256}", name):
            continue
        for manifest in manifest_root.glob("*_" + name + "_*.manifest"):
            directory = _WINSXS / manifest.stem
            if directory.is_dir():
                candidates.append({"identity": identity, "manifest_path": str(manifest), "manifest_sha256": sha256_file(manifest), "directory_path": str(directory)})
            if len(candidates) >= 16:
                return candidates
    return candidates


def _node(path: Path) -> dict[str, Any]:
    try:
        before = sha256_file(bounded_file(path, 256 * 1024 * 1024))
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(directories=[1, 13, 11, 0, 2])
            parsed_imports = _imports(pe, "DIRECTORY_ENTRY_IMPORT", "normal") + _imports(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", "delay")
            imports = [
                {
                    "kind": item["kind"],
                    "dll": item["dll"],
                    "symbol_count": item["symbol_count"],
                    "symbols_truncated": item["symbols_truncated"],
                }
                for item in parsed_imports
            ]
            exported = _exports(pe)
            forwarders = [symbol["forwarder"] for symbol in exported["symbols"] if symbol.get("forwarder")]
            result = {"path": str(path), "sha256": before, "machine": "0x%04X" % int(pe.FILE_HEADER.Machine), "is_dll": bool(int(pe.FILE_HEADER.Characteristics) & 0x2000), "version_info": _version_info(pe), "imports": imports, "bound_imports": [_text(getattr(item, "name", None)).casefold() for item in list(getattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT", []) or [])[:_MAX_VALUES]], "forwarders": forwarders[:_MAX_VALUES], "offline_signature_status": "not_checked"}
            if sha256_file(path) != before:
                raise ValueError("dependency changed during static read")
            result["coverage"] = {
                "import_modules_truncated": any(len(list(getattr(pe, name, []) or [])) > 512 for name in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT")),
                "forwarders_truncated": exported["symbols_truncated"],
                "signature_verification": "not_performed",
            }
            return result
        finally:
            pe.close()
    except (OSError, ValueError, pefile.PEFormatError) as error:
        return {"path": str(path), "parse_error": type(error).__name__}


def _candidate_paths(name: str, parent: Path, roots: list[Path], api_set: dict[str, list[str]], known_dlls: dict[str, str], sxs_roots: list[Path]) -> tuple[list[Path], str | None]:
    requested = _normal_dll(name)
    hosts = api_set.get(requested, [requested])
    candidates: list[Path] = []
    for host in hosts:
        known = known_dlls.get(host, host)
        candidates.extend([parent / host, *(root / host for root in roots), _SYSTEM32 / known, _SYSWOW64 / known, *(root / host for root in sxs_roots)])
    unique: list[Path] = []
    for candidate in candidates:
        normalized = candidate.resolve(strict=False)
        if normalized not in unique:
            unique.append(normalized)
    return unique[:64], "api_set" if requested in api_set else "known_dll" if requested in known_dlls else None


def _regular_candidate(path: Path) -> bool:
    try:
        state = path.lstat()
        return stat.S_ISREG(state.st_mode) and not path.is_symlink() and not getattr(state, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    except OSError:
        return False


def resolve_dependencies(source: Path, dependency_roots: list[Path], *, source_directory: Path | None = None, max_depth: int = 2, max_nodes: int = 48) -> dict[str, Any]:
    """Build a bounded static candidate closure for one copied PE file."""
    api_set, api_metadata = api_set_snapshot()
    known_dlls, known_metadata = known_dll_snapshot()
    roots = [source_directory or source.parent, *dependency_roots]
    source_manifest_documents, source_manifest_identities = _manifest_snapshot(source)
    source_sxs_candidates = _sxs_candidates(source_manifest_identities)
    source_sxs_roots = [Path(item["directory_path"]) for item in source_sxs_candidates]
    queue: deque[tuple[Path, int]] = deque([(source, 0)])
    seen: set[Path] = set()
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    cycles: list[dict[str, str]] = []
    edge_limit_reached = False
    depth_limit_reached = False
    while queue and len(nodes) < max_nodes and not edge_limit_reached:
        path, depth = queue.popleft()
        canonical = path.resolve(strict=False)
        if canonical in seen:
            continue
        seen.add(canonical)
        node = _node(canonical)
        node["depth"] = depth
        nodes.append(node)
        if "parse_error" in node:
            continue
        if depth >= max_depth:
            depth_limit_reached |= bool(node["imports"] or node["forwarders"])
            continue
        for import_record in node["imports"]:
            if len(edges) >= _MAX_EDGES:
                edge_limit_reached = True
                break
            dll = str(import_record.get("dll", ""))
            if not dll:
                continue
            candidates, route = _candidate_paths(dll, canonical.parent, roots, api_set, known_dlls, source_sxs_roots)
            selected = next((candidate for candidate in candidates if _regular_candidate(candidate)), None)
            edge = {"from_path": str(canonical), "dll": _normal_dll(dll), "kind": import_record.get("kind"), "route": route, "candidate_paths": [str(item) for item in candidates[:16]], "selected_path": str(selected) if selected else None}
            if selected is None:
                missing.append(edge)
            elif selected.resolve(strict=False) in seen:
                cycles.append({"from_path": str(canonical), "to_path": str(selected)})
            else:
                queue.append((selected, depth + 1))
            edges.append(edge)
        if edge_limit_reached:
            break
        for forwarder in node["forwarders"]:
            if len(edges) >= _MAX_EDGES:
                edge_limit_reached = True
                break
            module, separator, _symbol = str(forwarder).partition(".")
            if not separator:
                continue
            candidates, route = _candidate_paths(module, canonical.parent, roots, api_set, known_dlls, source_sxs_roots)
            selected = next((candidate for candidate in candidates if _regular_candidate(candidate)), None)
            edge = {"from_path": str(canonical), "dll": _normal_dll(module), "kind": "export_forwarder", "forwarder": forwarder, "route": route, "candidate_paths": [str(item) for item in candidates[:16]], "selected_path": str(selected) if selected else None}
            if selected is None:
                missing.append(edge)
            elif selected.resolve(strict=False) in seen:
                cycles.append({"from_path": str(canonical), "to_path": str(selected)})
            else:
                queue.append((selected, depth + 1))
            edges.append(edge)
    truncation_reasons = []
    if edge_limit_reached:
        truncation_reasons.append("max_edges")
    if depth_limit_reached:
        truncation_reasons.append("max_depth")
    if queue and len(nodes) >= max_nodes:
        truncation_reasons.append("max_nodes")
    return {"resolver_version": "forge-static-dependency-v1", "mode": "static_candidate_only", "roots": [str(root) for root in roots], "source_manifest_documents": source_manifest_documents, "source_manifest_identities": source_manifest_identities, "sxs_candidates": source_sxs_candidates, "sxs_candidate_roots": [str(root) for root in source_sxs_roots], "api_set_snapshot": api_metadata, "known_dll_snapshot": known_metadata, "limits": {"max_nodes": _MAX_NODES, "max_depth": _MAX_DEPTH, "max_edges": _MAX_EDGES}, "nodes": nodes, "edges": edges, "missing": missing, "previously_examined_edges": cycles, "truncated": bool(truncation_reasons), "truncation_reasons": truncation_reasons, "observation_limits": ["SxS uses bounded identity-name directory candidates, not Windows activation contexts", "candidate order is a static model, not runtime loader resolution", "revisited edges do not establish a directed cycle", "source parser and per-table limits may omit dependencies"]}
