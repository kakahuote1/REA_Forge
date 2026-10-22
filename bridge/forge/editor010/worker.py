"""One owned, non-listening binary-editor transaction for REA application ports."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# -I -S excludes CWD, user modules and site startup. Add only this authored bridge.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from editor010.editor010_bridge import Editor010Bridge


OPERATIONS = {
    "forge_inspect_binary_structure", "forge_read_binary_bytes", "forge_search_binary_bytes",
    "forge_compare_binary_files", "forge_edit_binary_copy", "forge_edit_binary_in_place",
    "forge_run_binary_script", "forge_list_binary_assets", "forge_restore_binary_backup",
    "forge_read_binary_template_rows",
}


def execute(operation: str, values: dict) -> dict:
    if operation not in OPERATIONS:
        raise ValueError("unknown binary-editor operation")
    bridge = Editor010Bridge()
    opened = bridge.open_session()
    session_id = opened["session_id"]
    target = None
    try:
        path = values.get("path")
        if path is not None:
            target = bridge.admission.input_file(path)
        if operation == "forge_list_binary_assets":
            result = bridge.list_assets(session_id, values["kind"])
        elif operation == "forge_read_binary_template_rows":
            result = bridge.read_retained_template_rows(session_id, values["csv_path"], values["csv_sha256"],
                                                        values["offset"], values["limit"], values.get("field_name"))
        elif operation == "forge_edit_binary_in_place":
            if target is None or target.sha256 != values["expected_sha256"]:
                raise ValueError("in-place edit target identity changed")
            result = bridge.edit_in_place(session_id, path, values["offset"], values["delete_length"], values["insert_hex"])
        elif operation == "forge_restore_binary_backup":
            result = bridge.restore_backup(session_id, path, values["backup_path"], values["expected_sha256"])
        else:
            if target is None:
                raise ValueError("this operation requires a selected input file")
            copied = bridge.create_working_copy(session_id, path)["payload"]["working_copy"]["path"]
            if operation == "forge_read_binary_bytes":
                result = bridge.read_range(session_id, copied, values["offset"], values["length"])
            elif operation == "forge_search_binary_bytes":
                result = bridge.search_hex(session_id, copied, values["needle_hex"])
            elif operation == "forge_compare_binary_files":
                right = bridge.create_working_copy(session_id, values["right_path"])["payload"]["working_copy"]["path"]
                result = bridge.compare(session_id, copied, right)
            elif operation == "forge_edit_binary_copy":
                result = bridge.edit_working_copy(session_id, copied, values["offset"], values["delete_length"],
                                                 values["insert_hex"], save_as=values.get("output_name"))
            elif operation == "forge_run_binary_script":
                result = bridge.run_script(session_id, copied, values["script_path"])
            elif operation == "forge_inspect_binary_structure":
                result = bridge.run_template(session_id, copied, values["template_path"])
                page = bridge.read_template_rows(session_id, result["payload"]["csv_path"],
                                                 values["offset"], values["limit"], values.get("field_name"))
                result["payload"]["template_rows"] = page["payload"]["rows"]
                result["payload"]["page"] = page["payload"]
            else:
                raise ValueError("unimplemented binary-editor operation")
        if target is not None and operation not in {"forge_edit_binary_in_place", "forge_restore_binary_backup"}:
            if bridge.admission.input_file(path).sha256 != target.sha256:
                raise ValueError("selected original changed during the transaction")
        return {"operation": operation, "target": target.record() if target else None,
                "result": result["payload"], "workspace": result["workspace_root"],
                "sample_execution": False, "network_used": False}
    finally:
        bridge.close_session(session_id)


def main() -> None:
    try:
        if len(sys.argv) != 2:
            raise ValueError("one owned request file is required")
        request = Path(sys.argv[1])
        if request.is_symlink() or not request.is_file() or request.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("request file is not an admitted bounded regular file")
        value = json.loads(request.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != {"operation", "arguments"} or not isinstance(value["arguments"], dict):
            raise ValueError("malformed binary-editor request")
        result = execute(value["operation"], value["arguments"])
        print(json.dumps({"ok": True, "value": result}, ensure_ascii=False), flush=True)
    except Exception as cause:
        print(json.dumps({"ok": False, "error": {"kind": type(cause).__name__, "message": str(cause)}}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
