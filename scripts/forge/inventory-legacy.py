"""Read legacy release facts into an operator-local migration inventory.

No legacy code is imported or executed. The result is historical/source evidence,
not an attestation that a tool works through REA Forge. This script never deletes,
copies engines, changes client configuration, or starts an analysis provider.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCOPE = {
    "ida": ("re_ida",),
    "windows-debug": ("re_vm_gateway", "re_vm_ida_full", "re_vm_ida_debug",
                      "re_vm_x64dbg", "re_vm_windbg", "re_x64dbg"),
    "dotnet-java": ("re_dnspy", "re_recaf", "re_vineflower", "re_cfr",
                    "re_bytecode_viewer", "re_javap"),
    "android-static": ("re_jadx", "re_apktool", "re_smali", "re_signing", "re_apk_meta"),
    "android-runtime": ("re_adb", "re_frida", "re_android_dynamic_chain", "re_ldplayer",
                        "re_ldplayer_adb", "re_ldplayer_frida", "re_ldplayer_profile", "re_ldplayer_oneclick"),
    "harmony": ("re_hap_inspect", "re_hap_jadx", "re_hap_abcde", "re_hap_sign",
                "re_ark_disasm", "re_hap_artifact_graph"),
    "pe": ("re_pe_workbench", "re_pe_unpack_workbench", "re_upx"),
    "native-enrichment": ("re_capa", "re_floss", "re_flare_hashes"),
    "python": ("re_python_decompile_router", "re_pyinstaller", "re_pyinstxtractor_ng",
               "re_xdis", "re_pylingual", "re_uncompyle6", "re_decompyle3"),
    "binary-editor": ("re_010editor",),
    "crypto": ("re_cyberchef",),
    "traffic": ("re_wireshark", "re_fiddler", "re_fiddler_live_android", "re_burp",
                "re_apipost_offline", "re_vm_apipost"),
    "system": ("re_systeminformer", "re_hollows_hunter"),
    "workbench": ("re_workbench",),
}
EXCLUDED = {"re_c32asm", "re_gda", "re_dependencies", "re_die", "re_peview",
            "re_hap_viewer", "re_ollydbg", "re_vmprotect", "re_legacy_bundle_admission",
            "re_legacy_worker_descriptors", "re_core_mock", "re_router", "re_jdgui"}
DELIVERY_GROUPS = {
    "G01": ("re_010editor",),
    "G02": ("re_recaf", "re_vineflower", "re_cfr", "re_bytecode_viewer", "re_javap"),
    "G03": ("re_dnspy",),
    "G04": ("re_cyberchef",),
    "G05": ("re_ida",),
    "G06": SCOPE["python"],
    "G07": SCOPE["pe"],
    "G08": SCOPE["native-enrichment"],
    "G09": SCOPE["android-static"],
    "G10": SCOPE["harmony"],
    "G11": ("re_vm_gateway", "re_vm_ida_full", "re_vm_ida_debug"),
    "G12": ("re_vm_x64dbg", "re_vm_windbg", "re_x64dbg"),
    "G13": ("re_adb", "re_android_dynamic_chain", "re_ldplayer", "re_ldplayer_adb",
            "re_ldplayer_profile", "re_ldplayer_oneclick"),
    "G14": ("re_frida", "re_android_dynamic_chain", "re_ldplayer_frida"),
    "G15": ("re_fiddler", "re_fiddler_live_android", "re_android_dynamic_chain"),
    "G16": ("re_wireshark", "re_apipost_offline", "re_vm_apipost"),
    "G17": SCOPE["system"],
    "P4": ("re_workbench",),
    "D01": ("re_burp",),
    "X01": tuple(sorted(EXCLUDED)),
    "X03": ("re_b04_clone_executor", "re_b04_clone_plan", "re_p8_pipeline",
            "re_p9_coverage", "re_p9_global_disposition", "re_p9_inventory_closure",
            "re_p9_sdk_gui_audit", "re_p9_source_audit", "re_p9_stage_gate"),
}
MISSING_FROM_RELEASE_INDEX = {
    "android-static": ["JEB, subject to actual local license and supported interface"],
    "harmony": ["ark_asm", "Linux arkdecompiler", "ReArk/Hyle"],
    "traffic": ["DudeSuite", "Yakit"],
    "system": ["PE-sieve integration scope"],
}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def group_for(adapter_id: str) -> str | None:
    return next((group for group, members in SCOPE.items() if adapter_id in members), None)


def delivery_groups(adapter_id: str) -> list[str]:
    selected = [group for group, members in DELIVERY_GROUPS.items() if adapter_id in members]
    if not selected:
        raise ValueError(f"Unmapped legacy adapter requires an explicit scope decision: {adapter_id}")
    return selected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / ".forge-local/migration-inventory.json")
    args = parser.parse_args()
    legacy = args.legacy_root.resolve(strict=True)
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / ".forge-local").resolve()):
        parser.error("machine-local inventory must remain inside .forge-local")
    releases = legacy / "registry/releases"
    if not releases.is_dir():
        parser.error("legacy root has no release index")
    rows = []
    status_file = output.parent / "migration-status.json"
    current_status = json.loads(status_file.read_text(encoding="utf-8")) if status_file.is_file() else {}
    for manifest in sorted(releases.glob("*.json")):
        if manifest.is_symlink():
            raise ValueError("release index contains a symlink")
        declaration = json.loads(manifest.read_text(encoding="utf-8-sig"))
        adapter = declaration.get("adapter_id", manifest.stem)
        group = group_for(adapter)
        targets = delivery_groups(adapter)
        disposition = ("user-deferred" if targets == ["D01"] else
                       "excluded-or-superseded" if adapter in EXCLUDED else
                       "superseded-governance" if targets == ["X03"] else "assess-migration")
        artifacts = []
        raw_artifacts = declaration.get("artifacts", [])
        artifact_schema_gaps = []
        if not isinstance(raw_artifacts, list):
            artifact_schema_gaps.append("artifacts is not an array; preserve the manifest for review")
            raw_artifacts = []
        for artifact in raw_artifacts:
            if isinstance(artifact, str):
                artifact = {"path": artifact}
            if not isinstance(artifact, dict):
                artifact_schema_gaps.append("unsupported artifact record type")
                continue
            raw_path = artifact.get("path")
            if not isinstance(raw_path, str):
                continue
            path = Path(raw_path)
            selected = path if path.is_absolute() else legacy / path
            present = selected.is_file()
            observed = sha256(selected) if present else None
            expected = artifact.get("sha256")
            artifacts.append({"path": str(selected), "present": present,
                              "sha256": observed, "expected_sha256": expected,
                              "matches_recorded_hash": observed == expected if present and expected else None})
        status = current_status.get(adapter)
        if status is not None:
            receipt = (output.parent / status["receipt"]).resolve(strict=True)
            if not receipt.is_relative_to(output.parent) or json.loads(receipt.read_text(encoding="utf-8"))["status"] != "passed":
                raise ValueError("migration status does not reference a passed local acceptance")
        lock = declaration.get("dependency_lock")
        lock_observation = None
        if isinstance(lock, dict) and isinstance(lock.get("path"), str):
            lock_path = Path(lock["path"])
            selected_lock = lock_path if lock_path.is_absolute() else legacy / lock_path
            regular_lock = selected_lock.is_file() and not selected_lock.is_symlink()
            observed_lock = sha256(selected_lock) if regular_lock else None
            expected_lock = lock.get("sha256")
            lock_observation = {
                "path": str(selected_lock), "present": regular_lock,
                "sha256": observed_lock, "expected_sha256": expected_lock,
                "matches_recorded_hash": observed_lock == expected_lock
                if regular_lock and expected_lock else None,
                "runtime_compatibility": "not_probed", "license": "not_inspected",
            }
        rows.append({"adapter_id": adapter, "group": group, "delivery_groups": targets,
                     "disposition": disposition,
                     "declared_capabilities": declaration.get("capabilities", []),
                     "dependency_lock_observation": lock_observation,
                     "historical_release_status": declaration.get("release_status"),
                     "historical_registration_allowed": declaration.get("codex_registration_allowed"),
                     "pending_scope": declaration.get("pending_scope", []),
                     "known_blockers": declaration.get("known_blockers", []),
                     "manifest_path": str(manifest), "manifest_sha256": sha256(manifest),
                     "artifacts": artifacts, "artifact_schema_gaps": artifact_schema_gaps,
                     "forge_status": "verified-migrated-scope" if status else "not-migrated",
                     "forge_verification": status, "old_directory_deletion_allowed": False})
    inventory = {
        "schema_version": 2, "generated_at": datetime.now(timezone.utc).isoformat(),
        "legacy_root": str(legacy), "scope": SCOPE,
        "unindexed_requirements": MISSING_FROM_RELEASE_INDEX,
        "summary": {"release_records": len(rows),
                    "unmapped_records": 0,
                    "delivery_groups": dict(Counter(target for row in rows for target in row["delivery_groups"])),
                    "dispositions": dict(Counter(row["disposition"] for row in rows)),
                    "historical_release_states": dict(Counter(str(row["historical_release_status"]) for row in rows)),
                    "missing_artifact_references": sum(not artifact["present"]
                                                       for row in rows for artifact in row["artifacts"]),
                    "dependency_lock_mismatches": sum(
                        row["dependency_lock_observation"] is not None and
                        row["dependency_lock_observation"]["matches_recorded_hash"] is False
                        for row in rows),
                    "source_hash_mismatches": sum(artifact["matches_recorded_hash"] is False
                                                  for row in rows for artifact in row["artifacts"])},
        "tools": rows,
        "limitations": ["Historical approval is not a current Forge verification.",
                        "Unindexed requirements need explicit investigation; absence is not exclusion.",
                        "No deletion is authorized by this inventory alone."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"inventory": str(output), **inventory["summary"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
