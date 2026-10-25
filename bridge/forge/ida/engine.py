"""Fixed IDALib library operations, always on its initializing main thread."""
from __future__ import annotations

import importlib
import inspect
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.static_files import read_json
from ida.host_profile import activate, loaded_plugins


def checked(value):
    if isinstance(value, dict) and (value.get("error") or value.get("ok") is False or value.get("success") is False or value.get("cancelled") is True):
        raise ValueError("typed IDA operation failed: " + str(value.get("error", "incomplete result")))
    if isinstance(value, list):
        for item in value:
            checked(item)
    return value


def run(request: dict) -> dict:
    def phase(name):
        (Path(request["workspace"]) / "engine-state.json").write_text(json.dumps({"phase": name}), encoding="ascii")
    if request["operation"] == "forge_assemble_ida":
        from ida.worker import pure_module
        module = pure_module(Path(request["api_source_root"]), "ida_keystone_runner")
        values = request["arguments"]
        result = module.KeystoneRunner().assemble(values["architecture"], values["assembly"], address=int(values["address"], 0))
        return {"data": {"architecture": result.architecture, "address": hex(result.address), "encoding_hex": result.encoding_hex, "size": len(result.encoding)}, "ida_initialized": False}
    profile, workspace = request["profile"], Path(request["workspace"])
    activate(profile)  # Before importing/initializing the library, never after.
    phase("profile-active-before-idalib-import")
    sys.path[:0] = [profile["idapro_python"], request["api_source_root"]]
    import idapro
    phase("idalib-imported")
    idapro.enable_console_messages(False)
    source = Path(request["input"])
    # IDALib is already autonomous; follow its shipped Python example rather
    # than initializing command-line autonomous mode a second time.
    if idapro.open_database(str(source), run_auto_analysis=True) != 0:
        raise ValueError("IDALib could not open the private static input")
    phase("private-database-open")
    try:
        import ida_auto
        import ida_bytes
        import ida_funcs
        import ida_idaapi
        import ida_kernwin
        import ida_loader
        import ida_name
        import ida_nalt
        import ida_ua
        import idc
        ida_auto.auto_wait()
        active = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)).resolve()
        if not active.is_relative_to(workspace.resolve()):
            raise ValueError("IDALib active database escaped its exclusive work directory")
        loaded_before = loaded_plugins(profile)
        # Reuse the already reviewed typed functions as a library. No MCP server,
        # HTTP listener, supervisor, GUI installer or raw Python tool is started.
        modules = {name: importlib.import_module("ida_pro_mcp.ida_mcp.api_" + name) for name in ("core", "types", "modify", "analysis", "autoenum", "bindiff", "data_export")}
        from ida import safe_python
        modules["python_safe"] = safe_python
        def call(module: str, name: str, **arguments):
            return checked(inspect.unwrap(getattr(modules[module], name))(**arguments))
        def address(value):
            if isinstance(value, bool):
                raise ValueError("invalid IDB address")
            try:
                ea = int(value, 0) if isinstance(value, str) else int(value)
            except ValueError:
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, value)
            if ea == ida_idaapi.BADADDR or not ida_bytes.is_mapped(ea):
                raise ValueError("selected IDB address or symbol is not mapped")
            return ea
        operation, values = request["operation"], request["arguments"]
        mutating = operation in {"forge_edit_ida_database", "forge_run_ida_safe_python"} or operation == "forge_ida_enum" and bool(values["enum_names"]) or operation == "forge_ida_struct_typer" and bool(values["member_names"])
        before = workspace / "before.i64" if mutating else None
        if before:
            call("core", "idb_save", path=str(before))
        data = {}
        if operation == "forge_edit_ida_database":
            changes = []
            for item in values["edits"]:
                action = item["action"]
                if action == "declaration":
                    changes.append({"action": action, "result": call("types", "declare_type", decls=item["declaration"])})
                    continue
                if action == "enum":
                    changes.append({"action": action, "result": call("types", "enum_upsert", queries={key: value for key, value in item.items() if key != "action"})})
                    continue
                ea = address(item["address"])
                if action == "rename":
                    if not ida_name.set_name(ea, item["name"], ida_name.SN_CHECK):
                        raise ValueError("IDA refused the selected symbol name")
                elif action == "comment":
                    if not idc.set_cmt(ea, item["text"], False):
                        raise ValueError("IDA refused the selected comment")
                elif action == "prototype":
                    if not idc.SetType(ea, item["prototype"]):
                        raise ValueError("IDA refused the selected type/prototype")
                elif action in {"patch", "assemble_patch"}:
                    expected = bytes.fromhex(item["expected_before_hex"])
                    if not expected or any(not ida_bytes.is_mapped(ea + offset) for offset in range(len(expected))) or ida_bytes.get_bytes(ea, len(expected)) != expected:
                        raise ValueError("IDB patch preimage differs or is unmapped")
                    if action == "assemble_patch":
                        result = call("modify", "ida_patch_assembled", addr=hex(ea), architecture=item["architecture"], assembly=item["assembly"], expected_before_hex=item["expected_before_hex"], fill_to_size=item.get("fill_to_size", 0))
                    else:
                        changed = bytes.fromhex(item["data_hex"])
                        if len(changed) != len(expected):
                            raise ValueError("IDB patch extent differs or write failed")
                        ida_bytes.patch_bytes(ea, changed)
                        if ida_bytes.get_bytes(ea, len(changed)) != changed:
                            raise ValueError("IDB patched bytes did not read back")
                        result = {"before_hex": expected.hex(), "after_hex": changed.hex()}
                    changes.append({"action": action, "address": hex(ea), "result": result})
                    continue
                elif action == "undefine":
                    if any(not ida_bytes.is_mapped(ea + offset) for offset in range(item["size"])):
                        raise ValueError("undefined range is not fully mapped")
                    if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, item["size"]):
                        raise ValueError("IDA refused to undefine the selected range")
                elif action == "define_code":
                    if ida_ua.create_insn(ea) == 0:
                        raise ValueError("IDA could not define an instruction at the selected address")
                elif action == "make_data":
                    width = item["width"]
                    if not ida_bytes.create_data(ea, {1: ida_bytes.FF_BYTE, 2: ida_bytes.FF_WORD, 4: ida_bytes.FF_DWORD, 8: ida_bytes.FF_QWORD}[width], width, ida_idaapi.BADADDR):
                        raise ValueError("IDA could not define the selected data item")
                else:
                    raise ValueError("unknown fixed IDB edit")
                changes.append({"action": action, "address": hex(ea), "name": ida_name.get_name(ea), "comment": idc.get_cmt(ea, False), "type": idc.get_type(ea), "disassembly": idc.generate_disasm_line(ea, 0)})
            data = {"changes": changes}
        elif operation == "forge_run_ida_safe_python":
            data = call("python_safe", "ida_python_safe_exec", code=values["code"])
        elif operation == "forge_scan_ida_crypto":
            data = call("analysis", "crypto_scan", max_results=values["max_results"], include_xrefs=True, max_xrefs=values["max_xrefs"], include_decompile_review=values["include_decompile_review"], max_decompile_reviews=values["max_decompile_reviews"])
        elif operation == "forge_ida_enum":
            preview = call("autoenum", "ida_enum_preview", platform=values["platform"], function_names=values.get("function_names"))
            data = {"preview": preview, "applied": call("autoenum", "ida_enum_apply", preview_id=preview["preview_id"], enum_names=values["enum_names"]) if values["enum_names"] else None}
        elif operation == "forge_ida_struct_typer":
            preview = call("types", "ida_flare_struct_preview", struct_name=values["struct_name"])
            data = {"preview": preview, "applied": call("types", "ida_flare_struct_apply", preview_id=preview["preview_id"], member_names=values["member_names"]) if values["member_names"] else None}
        elif operation == "forge_snapshot_ida_database":
            data = call("bindiff", "ida_bindiff_snapshot", max_functions=values["max_functions"])
        elif operation == "forge_export_ida_data":
            data = call("data_export", "ida_data_export", addr=hex(address(values["address"])), length=values["length"], data_kind=values["data_kind"], render=values["render"], endian=values["endian"])
        else:
            raise ValueError("unknown fixed static IDA operation")
        output = workspace / "database.i64" if mutating else None
        if output:
            call("core", "idb_save", path=str(output))
        type_observations = call("types", "type_inspect", queries=[{"name": name, "include_members": True, "max_members": 64} for name in values["inspect_types"]]) if values.get("inspect_types") else []
        return {"data": data, "before_database": str(before) if before else None, "database": str(output) if output else None, "loaded_plugins_before": loaded_before, "loaded_plugins_after": loaded_plugins(profile),
                "type_observations": type_observations,
                "metadata": {"input_path_recorded_by_idb": ida_nalt.get_input_file_path(), "image_base": hex(ida_nalt.get_imagebase()), "kernel_version": ida_kernwin.get_kernel_version()},
                "main_thread": True, "sample_execution": False}
    finally:
        idapro.close_database(save=False)


if __name__ == "__main__":
    request = read_json(Path(sys.argv[1]), 1024 * 1024)
    output = Path(request["workspace"]) / "engine-result.json"
    try:
        result = {"ok": True, "value": run(request)}
    except (Exception, SystemExit) as cause:
        result = {"ok": False, "error": {"kind": type(cause).__name__, "message": str(cause)}}
    encoded = json.dumps(result, ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError("IDA result exceeds16MiB retained bound")
    output.write_bytes(encoded)
    sys.exit(0 if result["ok"] else 1)
