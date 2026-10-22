"""Local 010 algorithms, owned by one REA Forge operation per helper lifetime.

Native invocation uses fixed no-UI arguments. Private copies and receipts persist
for explicit follow-up operations; discovery never starts the editor.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .editor010_admission import AdmittedAsset, AdmittedFile, EditorAdmission, EditorAdmissionError
from common.hard_deny_policy import HardDenyPolicy
from .write_protection import WriteProtection, WriteProtectionError
from .configuration import PRIVATE_ROOT


_DATA_ROOT = PRIVATE_ROOT
_WORK_ROOT = _DATA_ROOT / "work" / "010editor"
_MAX_RANGE_BYTES = 1024 * 1024
_MAX_SEARCH_HITS = 4096
_MAX_EDIT_BYTES = 1024 * 1024
_NATIVE_TIMEOUT_SECONDS = 35
_ANALYZER_VERSION = "forge-010editor-v1"
_DENIED_ASSET_MARKERS = (
    "fileopen(", "filenew(", "openprocess(", "processopen(", "opendrive(",
    "runprogram(", "shell", "http", "ftp", "socket", "registry", "repository", "project",
    "#include", "extern", "dll", "loadlibrary", "makedir(", "findfiles(",
    "directoryexists(", "fileexists(", "renamefile(", "deletefile(", "import", "export",
)
_EXPORT_TEMPLATE_SUFFIX = """\nExpandAll();\nExportCSV(\"{csv_path}\");\n"""
_READ_ASSET_CALLS = frozenset('littleendian bigendian fseek fskip ftell filesize feof readbyte readubyte readshort readushort readint readuint readint64 readuint64 readfloat readdouble readstring readwstring readbytes strlen wstrlen strcmp strncmp memcmp sprintf printf warning exit assert abs min max sqrt pow floor ceil round sizeof startof exists if for while switch'.split())
_WRITE_ASSET_CALLS = frozenset('writebyte writeubyte writeshort writeushort writeint writeuint writeint64 writeuint64 writefloat writedouble writebytes filesave'.split())
# Reviewed complete upstream bytes, not a blanket trust in names or domains.
# ZIP's write callback is only exposed to interactive edits; this fixed no-UI
# path runs the template and exports values, never invokes that callback.
_REVIEWED_READ_TEMPLATES = {
    'b1bad0f7d738d94ba6cc2cd2d421a8f5f4d7b8c01d7b649c5a07723dd6304b2b': 'ZIP.bt 2.5',
    'dc46f786a2d7a646bb84cd0cfd686a772f68c9e553d6717d0e1575b77eaa036f': 'PNG.bt 2.3',
}


class EditorBridgeError(RuntimeError):
    """Typed bridge failure without exposing a command line or secret path."""


@dataclass(frozen=True)
class _Session:
    token: str
    root: Path
    inputs: Path
    assets: Path
    outputs: Path
    evidence: Path


class Editor010Bridge:
    """Operation-owned binary facts and working-copy editing."""

    def __init__(self, workspace_root: Path | None = None, *, policy: HardDenyPolicy | None = None) -> None:
        self.policy = policy or HardDenyPolicy()
        self.admission = EditorAdmission(policy=self.policy)
        self.workspace_root = workspace_root or _WORK_ROOT
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, _Session] = {}
        self._template_exports: dict[str, dict[Path, str]] = {}

    def open_session(self) -> dict[str, Any]:
        token = secrets.token_hex(16)
        root = self.workspace_root / ("session-" + token)
        inputs, assets, outputs, evidence = (root / name for name in ("inputs", "assets", "outputs", "evidence"))
        for directory in (inputs, assets, outputs, evidence):
            directory.mkdir(parents=True, exist_ok=False)
        session = _Session(token, root, inputs, assets, outputs, evidence)
        self._sessions[token] = session
        self._template_exports[token] = {}
        return self._receipt(session, {"opened": True})

    def close_session(self, session_id: str) -> dict[str, Any]:
        session = self._session(session_id)
        self._sessions.pop(session.token)
        self._template_exports.pop(session.token, None)
        return self._receipt(session, {"closed": True, "evidence_retained": True})

    def status(self, session_id: str) -> dict[str, Any]:
        session = self._session(session_id)
        executable = self.admission.executable()
        return self._receipt(session, {"mode": "token_bound_non_pe_binary_workflow", "runtime": {"executable": str(executable), "sha256": self._sha256(executable), "version": "16.0.2"}, "limits": {"max_input_bytes": 256 * 1024 * 1024, "max_asset_bytes": 1024 * 1024, "max_range_bytes": _MAX_RANGE_BYTES, "max_search_hits": _MAX_SEARCH_HITS, "max_edit_bytes": _MAX_EDIT_BYTES}, "native_command_status": "fixed_no_ui_argv", "excluded": ["network", "listener", "project", "drive", "process", "reset", "resetall", "license", "update", "repository", "pe_write"], "sample_execution": False, "network_used": False})

    def create_working_copy(self, session_id: str, source_path: str | Path) -> dict[str, Any]:
        session = self._session(session_id)
        source = self.admission.input_file(source_path)
        target = session.inputs / (source.sha256 + source.path.suffix.casefold())
        if not target.exists():
            shutil.copyfile(source.path, target)
        copied = self._admit_session_file(session, target)
        if copied.sha256 != source.sha256:
            raise EditorBridgeError("working-copy identity mismatch")
        return self._receipt(session, {"relationship": "working_copy_of", "original": source.record(), "working_copy": copied.record()})

    def read_range(self, session_id: str, input_path: str | Path, offset: int, length: int) -> dict[str, Any]:
        session = self._session(session_id)
        source = self._admit_session_file(session, input_path)
        if isinstance(offset, bool) or isinstance(length, bool) or not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or not 0 <= length <= _MAX_RANGE_BYTES or offset + length > source.size_bytes:
            raise ValueError("range is outside the admitted file")
        with source.path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(length)
        return self._receipt(session, {"input": source.record(), "offset": offset, "length": length, "hex": data.hex(), "ascii": data.decode("utf-8", errors="replace")})

    def search_hex(self, session_id: str, input_path: str | Path, needle_hex: str) -> dict[str, Any]:
        session = self._session(session_id)
        source = self._admit_session_file(session, input_path)
        try:
            needle = bytes.fromhex(needle_hex)
        except ValueError as error:
            raise ValueError("needle_hex must be even-length hexadecimal") from error
        if not needle or len(needle) > 4096:
            raise ValueError("needle_hex must contain from 1 through 4096 bytes")
        data = source.path.read_bytes()
        hits: list[int] = []
        cursor = 0
        while len(hits) < _MAX_SEARCH_HITS:
            cursor = data.find(needle, cursor)
            if cursor < 0:
                break
            hits.append(cursor)
            cursor += 1
        return self._receipt(session, {"input": source.record(), "needle_hex": needle.hex(), "offsets": hits, "truncated": cursor >= 0})

    def compare(self, session_id: str, left_path: str | Path, right_path: str | Path) -> dict[str, Any]:
        session = self._session(session_id)
        left, right = self._admit_session_file(session, left_path), self._admit_session_file(session, right_path)
        left_data, right_data = left.path.read_bytes(), right.path.read_bytes()
        first = next((index for index, pair in enumerate(zip(left_data, right_data)) if pair[0] != pair[1]), None)
        if first is None and len(left_data) != len(right_data):
            first = min(len(left_data), len(right_data))
        comparison = "-compare:" + str(left.path) + "::" + str(right.path) + "::\\b"
        native = self._run_native(session, [str(self.admission.executable()), "-noui", "-nowarnings", comparison], ["fixed_010editor", "-noui", "-nowarnings", "-compare"])
        record = {"kind": "010_native_compare", "left": left.record(), "right": right.record(), "identical": left_data == right_data, "first_difference_offset": first, "size_delta": len(right_data) - len(left_data), "native": native}
        self._write_evidence(session, record)
        return self._receipt(session, record)

    def edit_working_copy(self, session_id: str, input_path: str | Path, offset: int, delete_length: int, insert_hex: str, *, save_as: str | None = None) -> dict[str, Any]:
        session = self._session(session_id)
        source = self._admit_session_file(session, input_path)
        EditorAdmission.require_non_pe_write(source)
        if isinstance(offset, bool) or isinstance(delete_length, bool) or not isinstance(offset, int) or not isinstance(delete_length, int) or offset < 0 or delete_length < 0 or offset + delete_length > source.size_bytes:
            raise ValueError("edit range is outside the admitted non-PE working copy")
        try:
            inserted = bytes.fromhex(insert_hex)
        except ValueError as error:
            raise ValueError("insert_hex must be even-length hexadecimal") from error
        if len(inserted) > _MAX_EDIT_BYTES:
            raise ValueError("insert_hex exceeds the fixed edit bound")
        if save_as is None:
            target = session.outputs / (source.sha256[:16] + "-edited" + source.path.suffix.casefold())
        else:
            target = (session.outputs / save_as).resolve(strict=False)
            try:
                target.relative_to(session.outputs.resolve())
            except ValueError as error:
                raise ValueError("save_as escaped the session output directory") from error
        if target.exists():
            raise ValueError("session output name already exists")
        before = source.path.read_bytes()
        after = before[:offset] + inserted + before[offset + delete_length :]
        target.write_bytes(after)
        output = self._admit_session_file(session, target)
        self._write_evidence(session, {"kind": "non_pe_working_copy_edit", "source": source.record(), "output": output.record(), "offset": offset, "delete_length": delete_length, "insert_hex": inserted.hex(), "pe_write_denied": True})
        return self._receipt(session, {"relationship": "derived_from", "source": source.record(), "output": output.record(), "offset": offset, "delete_length": delete_length, "insert_length": len(inserted), "sample_execution": False, "network_used": False})

    def edit_in_place(self, session_id: str, source_path: str | Path, offset: int, delete_length: int, insert_hex: str) -> dict[str, Any]:
        """Safely edit one admitted non-PE D: file with a session-held backup chain."""
        session = self._session(session_id)
        source = self.admission.input_file(source_path)
        EditorAdmission.require_non_pe_write(source)
        if isinstance(offset, bool) or isinstance(delete_length, bool) or not isinstance(offset, int) or not isinstance(delete_length, int) or offset < 0 or delete_length < 0 or offset + delete_length > source.size_bytes:
            raise ValueError("in-place edit range is outside the admitted non-PE source")
        try:
            inserted = bytes.fromhex(insert_hex)
        except ValueError as error:
            raise ValueError("insert_hex must be even-length hexadecimal") from error
        if len(inserted) > _MAX_EDIT_BYTES:
            raise ValueError("insert_hex exceeds the fixed edit bound")
        before = source.path.read_bytes()
        after = before[:offset] + inserted + before[offset + delete_length :]
        try:
            receipt = WriteProtection(
                ledger_path=session.evidence / "write-protection.jsonl",
                backup_root=session.root / "backups",
            ).write_in_place(source.path, after)
        except WriteProtectionError as error:
            raise EditorBridgeError("010 in-place write could not create its backup and evidence chain") from error
        output = self.admission.input_file(source.path)
        record = {"kind": "non_pe_in_place_edit", "source_before": receipt.before.record(), "source_after": output.record(), "backup_relationship": "backup_of", "backup": receipt.backup.record(), "offset": offset, "delete_length": delete_length, "old_hex": before[offset : offset + delete_length].hex(), "insert_hex": inserted.hex(), "byte_delta": receipt.byte_delta, "pe_write_denied": True}
        self._write_evidence(session, record)
        return self._receipt(session, record)

    def list_assets(self, session_id: str, kind: str) -> dict[str, Any]:
        session = self._session(session_id)
        if kind not in {"template", "script"}:
            raise ValueError("kind must be template or script")
        suffix = ".bt" if kind == "template" else ".1sc"
        root = self.admission.executable().parent / "Data"
        records = []
        for path in sorted(root.glob("*" + suffix)):
            asset = self.admission.asset_file(path)
            records.append(asset.record())
        if kind == 'template':
            for name in ('ZIP.bt', 'PNG.bt'):
                path = self.admission.configuration.reviewed_template_root / name
                if path.is_file():
                    asset = self.admission.asset_file(path)
                    if asset.sha256 in _REVIEWED_READ_TEMPLATES:
                        records.append({**asset.record(), 'reviewed_read_only': True})
        return self._receipt(session, {"kind": kind, "assets": records})

    def admit_asset(self, session_id: str, asset_path: str | Path) -> dict[str, Any]:
        session = self._session(session_id)
        asset = self.admission.asset_file(asset_path)
        copied = session.assets / (asset.sha256 + asset.path.suffix.casefold())
        shutil.copyfile(asset.path, copied)
        if self._sha256(copied) != asset.sha256:
            raise EditorBridgeError("010 asset identity changed while copying")
        return self._receipt(session, {"asset": asset.record(), "session_copy_path": str(copied)})

    def run_template(self, session_id: str, input_path: str | Path, template_path: str | Path) -> dict[str, Any]:
        """Run an admitted read-only template with a fixed CSV-export wrapper."""
        session = self._session(session_id)
        source = self._admit_session_file(session, input_path)
        template = self.admission.asset_file(template_path)
        if template.kind != "template":
            raise ValueError("run_template requires a .bt template")
        self._audit_asset(template, allow_current_save=False)
        invocation_id = secrets.token_hex(8)
        relative_csv = Path("outputs") / (source.sha256[:16] + '-' + invocation_id + "-template.csv")
        csv_path = session.root / relative_csv
        copied_template = session.root / ("template-" + template.sha256[:16] + '-' + invocation_id + "-export.bt")
        try:
            template_bytes = template.path.read_bytes()
        except OSError as error:
            raise EditorBridgeError("template could not be copied into its export-only session variant") from error
        csv_literal = str(csv_path).replace("\\", "\\\\")
        if hashlib.sha256(template_bytes).hexdigest() != template.sha256:
            raise EditorBridgeError('template identity changed after admission')
        copied_template.write_bytes(template_bytes)
        export_template_hash = self._sha256(copied_template)
        export_script = session.root / ('export-' + template.sha256[:16] + '.1sc')
        template_literal = str(copied_template).replace('\\', '\\\\')
        export_script.write_text('if (RunTemplate("' + template_literal + '") < 0) Exit(-1);\n' + _EXPORT_TEMPLATE_SUFFIX.format(csv_path=csv_literal), encoding='utf-8')
        invocation = [str(self.admission.executable()), "-noui", "-nowarnings", str(source.path), "-script:" + str(export_script)]
        native = self._run_native(session, invocation, ["fixed_010editor", "-noui", "-nowarnings", "input", "-script:fixed_template_export"])
        rows = self._read_csv_rows(csv_path) if csv_path.is_file() else []
        if native['returncode'] != 0 or not any(row and row[0].strip() for row in rows[1:]):
            raise EditorBridgeError('010 template did not produce verified CSV output; native exit code is not sufficient')
        if self._sha256(source.path) != source.sha256:
            raise EditorBridgeError('read-only template changed its working copy')
        self._template_exports[session.token][csv_path.resolve()] = self._sha256(csv_path)
        page = self.read_template_rows(session_id, str(csv_path), 0, 256)['payload']
        record = {"kind": "010_native_template", "input": source.record(), "template": template.record(), "export_template_session_copy": str(copied_template), "export_template_sha256": export_template_hash, "csv_path": str(csv_path), "csv_sha256": page['csv_sha256'], "csv_rows": page['total_rows'], "native": native}
        self._write_evidence(session, record)
        return self._receipt(session, {"input": source.record(), "template": template.record(), "native": native, "template_rows": page['rows'], "template_export": "csv", "csv_path": str(csv_path), "csv_sha256": page['csv_sha256'], "total_rows": page['total_rows'], "rows_truncated": page['has_more'], "next_offset": page['next_offset'], "last_field_end": page['last_field_end'], "parse_extent": 'partial' if page['last_field_end'] < source.size_bytes else 'reaches_input_end_not_semantic_validation'})

    def read_template_rows(self, session_id: str, csv_path: str, offset: int, limit: int, field_name: str | None = None) -> dict[str, Any]:
        """Page or filter a verified native CSV without rerunning 010."""
        import csv
        session = self._session(session_id)
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= 512:
            raise ValueError('CSV offset/limit is outside its bounded range')
        if field_name is not None and (not isinstance(field_name, str) or len(field_name) > 128):
            raise ValueError('CSV field name is invalid')
        path = Path(csv_path).resolve(strict=True)
        expected = self._template_exports[session.token].get(path)
        if expected is None or path.is_symlink() or self._sha256(path) != expected:
            raise EditorBridgeError('CSV is not an unchanged native export of this session')
        rows, total, matched, last_field_end = [], 0, 0, 0
        deadline = time.monotonic() + 5
        with path.open('r', encoding='utf-8-sig', errors='replace', newline='') as stream:
            for row in csv.reader(stream):
                total += 1
                if len(row) >= 4:
                    try:
                        start, size = (int(cell[:-1], 16) if cell.endswith('h') else int(cell) for cell in row[2:4])
                        last_field_end = max(last_field_end, start + size)
                    except ValueError:
                        pass
                if total % 1024 == 0 and time.monotonic() >= deadline:
                    raise EditorBridgeError('CSV read exceeded its bounded deadline')
                if field_name is None or (row and row[0].strip() == field_name):
                    if offset <= matched < offset + limit:
                        rows.append(row)
                    matched += 1
        more = matched > offset + len(rows)
        return self._receipt(session, {'rows': rows, 'total_rows': total, 'matched_rows': matched, 'offset': offset, 'has_more': more, 'next_offset': offset + len(rows) if more else None, 'csv_sha256': expected, 'last_field_end': last_field_end})

    def run_script(self, session_id: str, input_path: str | Path, script_path: str | Path) -> dict[str, Any]:
        """Run a statically constrained script against one non-PE session copy."""
        session = self._session(session_id)
        source = self._admit_session_file(session, input_path)
        EditorAdmission.require_non_pe_write(source)
        script = self.admission.asset_file(script_path)
        if script.kind != "script":
            raise ValueError("run_script requires a .1sc script")
        self._audit_asset(script, allow_current_save=True)
        copied_script = session.root / ("script-" + script.sha256[:16] + ".1sc")
        shutil.copyfile(script.path, copied_script)
        if self._sha256(copied_script) != script.sha256:
            raise EditorBridgeError("script identity changed while creating a session copy")
        before = self._admit_session_file(session, source.path)
        invocation = [str(self.admission.executable()), "-noui", "-nowarnings", str(source.path), "-script:" + copied_script.name]
        native = self._run_native(session, invocation, ["fixed_010editor", "-noui", "-nowarnings", "input", "-script"])
        if native['returncode'] != 0:
            raise EditorBridgeError('010 script failed with native exit code ' + str(native['returncode']))
        after = self._admit_session_file(session, source.path)
        record = {"kind": "010_native_script", "before": before.record(), "after": after.record(), "script": script.record(), "script_session_copy": str(copied_script), "native": native, "pe_write_denied": True}
        self._write_evidence(session, record)
        return self._receipt(session, {"relationship": "script_modified_current_session_copy", "before": before.record(), "after": after.record(), "script": script.record(), "native": native, "sample_execution": False, "network_used": False})

    def read_retained_template_rows(self, session_id: str, csv_path: str, csv_sha256: str, offset: int, limit: int, field_name: str | None = None) -> dict[str, Any]:
        """Read only an unchanged export linked by its producing native receipt."""
        session = self._session(session_id)
        path = Path(csv_path)
        if not path.is_absolute() or path.is_symlink():
            raise EditorBridgeError("retained CSV requires an absolute non-symlink path")
        path = path.resolve(strict=True)
        path.relative_to(self.workspace_root.resolve())
        if path.parent.name != "outputs" or path.suffix.casefold() != ".csv":
            raise EditorBridgeError("retained CSV is not an owned template export")
        if self._sha256(path) != csv_sha256:
            raise EditorBridgeError("retained CSV content changed")
        receipts = list((path.parent.parent / "evidence").glob("*.json"))
        if len(receipts) > 128:
            raise EditorBridgeError("retained export has too many provenance candidates")
        producer = next((value for receipt in receipts
                         if isinstance(value := json.loads(receipt.read_text(encoding="utf-8")), dict)
                         and value.get("kind") == "010_native_template"
                         and value.get("csv_path") == str(path)
                         and value.get("csv_sha256") == csv_sha256), None)
        if producer is None:
            raise EditorBridgeError("retained CSV has no matching native producer receipt")
        self._template_exports[session.token][path] = csv_sha256
        return self.read_template_rows(session_id, str(path), offset, limit, field_name)

    def restore_backup(self, session_id: str, target_path: str, backup_path: str, expected_sha256: str) -> dict[str, Any]:
        """Restore one recorded backup after checking the current target identity."""
        session = self._session(session_id)
        target = self.admission.input_file(target_path)
        EditorAdmission.require_non_pe_write(target)
        if target.sha256 != expected_sha256:
            raise EditorBridgeError("restore target changed since selection")
        backup = Path(backup_path)
        if not backup.is_absolute() or backup.is_symlink():
            raise EditorBridgeError("backup path is not an admitted absolute file")
        backup = backup.resolve(strict=True)
        backup.relative_to(self.workspace_root.resolve())
        if backup.parent.name != "backups":
            raise EditorBridgeError("backup is not in an owned transaction backup directory")
        digest = self._sha256(backup)
        receipts = list((backup.parent.parent / "evidence").glob("*.json"))
        if len(receipts) > 128:
            raise EditorBridgeError("backup has too many provenance candidates")
        producing = [json.loads(path.read_text(encoding="utf-8")) for path in receipts]
        match = any(isinstance(value, dict)
                    and value.get("kind") == "non_pe_in_place_edit"
                    and value.get("source_before", {}).get("path") == str(target.path)
                    and value.get("backup", {}).get("path") == str(backup)
                    and value.get("backup", {}).get("sha256") == digest
                    for value in producing)
        if not match:
            raise EditorBridgeError("backup has no matching edit provenance")
        restored = WriteProtection(ledger_path=session.evidence / "write-protection.jsonl",
                                   backup_root=session.root / "backups").write_in_place(target.path, backup.read_bytes())
        record = {"kind": "restored_binary_backup", "source_before": target.record(),
                  "source_after": restored.after.record(), "restored_backup": {"path": str(backup), "sha256": digest},
                  "recovery_backup": restored.backup.record()}
        self._write_evidence(session, record)
        return self._receipt(session, record)

    def list_evidence(self, session_id: str, limit: int) -> dict[str, Any]:
        session = self._session(session_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 30:
            raise ValueError("limit must be an integer from 1 through 30")
        records = [{"path": str(path), "sha256": self._sha256(path), "size_bytes": path.stat().st_size} for path in sorted(session.evidence.glob("*.json"), reverse=True)[:limit]]
        return self._receipt(session, {"evidence": records})

    def _admit_session_file(self, session: _Session, value: str | Path) -> AdmittedFile:
        self.policy.require_local_path(value)
        path = Path(value).resolve(strict=True)
        try:
            path.relative_to(session.root.resolve())
        except ValueError as error:
            raise EditorBridgeError("010 operation requires a token-bound session copy") from error
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 256 * 1024 * 1024:
            raise EditorBridgeError("010 session file is not an admitted bounded regular file")
        return AdmittedFile(path=path, sha256=self._sha256(path), size_bytes=path.stat().st_size, is_pe=EditorAdmission._is_pe(path))

    @staticmethod
    def _audit_asset(asset: AdmittedAsset, *, allow_current_save: bool) -> None:
        try:
            raw = asset.path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if asset.sha256 and digest != asset.sha256:
                raise EditorBridgeError('010 asset identity changed before audit')
            if not allow_current_save and asset.kind == 'template' and digest in _REVIEWED_READ_TEMPLATES:
                return
            text = raw.decode('utf-8', errors='strict').casefold()
        except OSError as error:
            raise EditorBridgeError("010 asset could not be statically audited") from error
        text = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*', lambda match: '""' if match.group().startswith(('"', "'")) else ' ', text)
        if '#' in text or re.search(r'\bextern\b', text):
            raise EditorBridgeError('preprocessor and external bindings require a separately audited asset')
        compact = re.sub(r'\s+', '', text)
        if any(marker in compact for marker in _DENIED_ASSET_MARKERS):
            raise EditorBridgeError("010 asset uses a denied external, process, configuration, or arbitrary-file API")
        calls = set(re.findall(r'\b([a-z_]\w*)\s*\(', text))
        allowed = _READ_ASSET_CALLS | (_WRITE_ASSET_CALLS if allow_current_save else frozenset())
        if calls - allowed:
            raise EditorBridgeError('010 asset contains unaudited API calls: ' + ', '.join(sorted(calls - allowed)))
        save_calls = re.findall(r"filesave\s*\(([^)]*)\)", text)
        if save_calls and (not allow_current_save or any(argument.strip() for argument in save_calls)):
            raise EditorBridgeError("010 asset may save only the current token-session file with FileSave()")

    def _run_native(self, session: _Session, argv: list[str], argv_shape: list[str]) -> dict[str, Any]:
        self.policy.require_safe_command(argv)
        log = session.evidence / ("010-native-" + secrets.token_hex(8) + ".log")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        started = time.monotonic()
        with log.open("xb") as handle:
            process = subprocess.Popen(argv, cwd=session.root, stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT, shell=False, creationflags=flags)
            self._write_evidence(session, {"kind": "010_native_started", "pid": process.pid,
                                          "argv_shape": argv_shape})
            try:
                returncode = process.wait(timeout=_NATIVE_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                self._kill_tree(process.pid)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired as error:
                    raise EditorBridgeError("owned 010 Editor process tree could not be recovered") from error
                raise EditorBridgeError("010 Editor no-UI worker exceeded the fixed timeout")
        return {"argv_shape": argv_shape, "returncode": returncode, "elapsed_seconds": round(time.monotonic() - started, 3), "log_path": str(log), "log_sha256": self._sha256(log)}

    @staticmethod
    def _read_csv_rows(path: Path) -> list[list[str]]:
        import csv

        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                return [row for _index, row in zip(range(4096), csv.reader(handle))]
        except OSError as error:
            raise EditorBridgeError("010 template CSV could not be read") from error

    @staticmethod
    def _kill_tree(process_id: int) -> None:
        try:
            subprocess.run(("taskkill", "/PID", str(process_id), "/T", "/F"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError:
            return

    def _session(self, session_id: str) -> _Session:
        if not isinstance(session_id, str) or len(session_id) != 32:
            raise ValueError("session_id is invalid")
        try:
            return self._sessions[session_id]
        except KeyError as error:
            raise KeyError(session_id) from error

    def _write_evidence(self, session: _Session, record: dict[str, Any]) -> None:
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        path = session.evidence / (hashlib.sha256(encoded).hexdigest()[:16] + "-" + secrets.token_hex(8) + ".json")
        path.write_bytes(encoded)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _receipt(session: _Session, payload: dict[str, Any]) -> dict[str, Any]:
        return {"session_id": session.token, "workspace_root": str(session.root), "input_root": str(session.inputs), "evidence_root": str(session.evidence), "sample_execution": False, "network_used": False, "payload": payload}


def default_editor010_workspace() -> Path:
    return _WORK_ROOT
