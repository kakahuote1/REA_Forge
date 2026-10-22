"""File-bound offline recipes, private outputs and digest-checked replay."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.hard_deny_policy import HardDenyPolicy
from common.paths import CONFIG_PATH, PRIVATE_ROOT

OPERATIONS = {"forge_list_cyberchef_operations", "forge_validate_cyberchef_recipe", "forge_run_cyberchef_recipe",
              "forge_replay_cyberchef_recipe", "forge_suggest_cyberchef_steps"}
MAX_INPUT = 8 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def execute(operation: str, values: dict) -> dict:
    if operation not in OPERATIONS:
        raise ValueError("unknown offline CyberChef operation")
    if CONFIG_PATH.is_symlink():
        raise ValueError("operator configuration must not be a symlink")
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))["cyberchef"]
    node = Path(config["node"]["path"])
    engine = Path(config["root"])
    policy = HardDenyPolicy()
    for path in (node, engine):
        policy.require_local_path(path)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("CyberChef runtime paths must be absolute non-symlink paths")
    if digest(node.read_bytes()) != config["node"]["sha256"] or digest((engine / "package-lock.json").read_bytes()) != config["package_lock_sha256"]:
        raise ValueError("CyberChef runtime identity drifted")
    pins = PRIVATE_ROOT / "config" / "cyberchef-entrypoints.json"
    pin_hash = digest(pins.read_bytes())
    workspace = PRIVATE_ROOT / "work" / "cyberchef" / secrets.token_hex(16)
    workspace.mkdir(parents=True)
    target = None
    request: dict = {}
    if "path" in values:
        raw = Path(values["path"])
        policy.require_local_path(raw)
        path = raw.resolve(strict=True)
        roots = [Path(root).resolve() for root in config["input_roots"]] + [PRIVATE_ROOT / "work" / "cyberchef"]
        if not raw.is_absolute() or raw.is_symlink() or not path.is_file() or not any(path.is_relative_to(root) for root in roots) or path.stat().st_size > MAX_INPUT:
            raise ValueError("CyberChef input is not an admitted bounded file")
        data = path.read_bytes()
        if len(data) > MAX_INPUT:
            raise ValueError("CyberChef input grew beyond its bound")
        target = {"path": str(path), "sha256": digest(data), "size_bytes": len(data)}
        (workspace / "input.bin").write_bytes(data)
        request["input_base64"] = base64.b64encode(data).decode("ascii")
    actions = {"forge_list_cyberchef_operations": "catalog", "forge_validate_cyberchef_recipe": "validate_recipe",
               "forge_run_cyberchef_recipe": "run_recipe", "forge_replay_cyberchef_recipe": "run_recipe",
               "forge_suggest_cyberchef_steps": "magic_candidates"}
    request["action"] = actions[operation]
    recipe = values.get("recipe")
    if operation == "forge_replay_cyberchef_recipe":
        raw_receipt = Path(values["receipt_path"])
        receipt = raw_receipt.resolve(strict=True)
        if raw_receipt.is_symlink() or not receipt.is_relative_to(PRIVATE_ROOT / "work" / "cyberchef") or receipt.stat().st_size > 512 * 1024:
            raise ValueError("recipe receipt is outside the retained workspace")
        content = receipt.read_bytes()
        if digest(content) != values["receipt_sha256"]:
            raise ValueError("recipe receipt identity changed")
        previous = json.loads(content)
        if previous.get("kind") != "forge_cyberchef_recipe" or digest(canonical(previous["recipe"])) != previous["recipe_sha256"]:
            raise ValueError("recipe receipt provenance is invalid")
        recipe = previous["recipe"]
    if recipe is not None:
        if not isinstance(recipe, list) or not 1 <= len(recipe) <= 16:
            raise ValueError("recipe must contain 1 through 16 typed steps")
        request["recipe"] = [{"name": step["op"], "args": step.get("args", [])} for step in recipe]
    request_file = workspace / "request.json"
    request_file.write_bytes(canonical(request))
    output_file, error_file = workspace / "response.json", workspace / "stderr.log"
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"NODE_OPTIONS", "NODE_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                                  "http_proxy", "https_proxy", "all_proxy", "npm_config_proxy", "npm_config_https_proxy"}}
    environment.update({"NO_PROXY": "*", "REA_FORGE_CYBERCHEF_ROOT": str(engine),
                        "REA_FORGE_CYBERCHEF_ENTRY_PINS": str(pins)})
    with request_file.open("rb") as source, output_file.open("xb") as output, error_file.open("xb") as error:
        completed = subprocess.run([str(node), "--no-warnings", "--max-old-space-size=384", str(Path(__file__).with_name("engine.mjs"))],
                                   stdin=source, stdout=output, stderr=error, cwd=workspace, env=environment,
                                   timeout=35, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if output_file.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("CyberChef reply exceeds its bound")
    reply = json.loads(output_file.read_text(encoding="utf-8")) if output_file.stat().st_size else {}
    if completed.returncode not in {0, 1} or reply.get("ok") is not True or not isinstance(reply.get("result"), dict):
        reason = str(reply.get("error", "engine failed before producing a reply"))[:512]
        raise ValueError("offline CyberChef rejected the operation or recipe: " + reason)
    result = reply["result"]
    if "recipe" in result:
        result["recipe"] = [{"op": step["name"], "args": step["args"]} for step in result["recipe"]]
        result["recipe_sha256"] = digest(canonical(result["recipe"]))
    if "output_base64" in result:
        output_data = base64.b64decode(result.pop("output_base64"), validate=True)
        if len(output_data) > MAX_OUTPUT or len(output_data) != result["output_bytes"]:
            raise ValueError("CyberChef output identity or size mismatch")
        binary = workspace / "output.bin"
        binary.write_bytes(output_data)
        result.update({"output_path": str(binary), "output_sha256": digest(output_data),
                       "preview_base64": base64.b64encode(output_data[:4096]).decode("ascii"),
                       "preview_truncated": len(output_data) > 4096})
        record = {"kind": "forge_cyberchef_recipe", "recipe": result["recipe"], "recipe_sha256": result["recipe_sha256"],
                  "input": target, "output_sha256": result["output_sha256"], "entry_manifest_sha256": pin_hash}
        receipt = workspace / "recipe.json"
        receipt.write_bytes(canonical(record))
        result.update({"receipt_path": str(receipt), "receipt_sha256": digest(receipt.read_bytes())})
    if target is not None and digest(Path(target["path"]).read_bytes()) != target["sha256"]:
        raise ValueError("CyberChef original changed during the transaction")
    return {"operation": operation, "target": target, "result": result, "workspace": str(workspace),
            "engine": {"version": json.loads((engine / "package.json").read_text(encoding="utf-8"))["version"],
                       "node_sha256": config["node"]["sha256"], "package_lock_sha256": config["package_lock_sha256"],
                       "entry_manifest_sha256": pin_hash, "owned_wait_completed": True},
            "sample_execution": False, "network_used": False}


def main() -> None:
    try:
        if len(sys.argv) != 2:
            raise ValueError("one owned request is required")
        path = Path(sys.argv[1])
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("malformed bounded CyberChef request")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != {"operation", "arguments"} or not isinstance(value["arguments"], dict):
            raise ValueError("malformed CyberChef request shape")
        print(json.dumps({"ok": True, "value": execute(value["operation"], value["arguments"])}), flush=True)
    except Exception as cause:
        print(json.dumps({"ok": False, "error": {"kind": type(cause).__name__, "message": str(cause)}}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
