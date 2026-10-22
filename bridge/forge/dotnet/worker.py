"""One-shot dnSpy static worker. No socket, named pipe, target load or execution."""
from pathlib import Path
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.paths import CONFIG_PATH, PRIVATE_ROOT, PROJECT_ROOT
from common.hard_deny_policy import HardDenyPolicy

MAX_INPUT = 64 * 1024 * 1024


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def no_reparse(path: Path) -> None:
    for part in (path, *path.parents):
        if part.exists() and (part.is_symlink() or getattr(part.stat(follow_symlinks=False), "st_file_attributes", 0) & 1024):
            raise ValueError("reparse path is not admitted")


class Work:
    def __init__(self) -> None:
        self.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["dotnet"]
        self.root = PRIVATE_ROOT / "work/dotnet" / secrets.token_hex(16)
        for folder in ("inputs", "outputs", "tmp", "logs"):
            (self.root / folder).mkdir(parents=True)
        self.inputs: list[dict] = []
        self.native: list[dict] = []
        build = PRIVATE_ROOT / "build/dotnet"
        manifest_path = build / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        source = PROJECT_ROOT / "bridge/forge/dotnet"
        for relative, expected in manifest["sources"].items():
            if sha256(source / relative) != expected:
                raise RuntimeError("dnSpy worker source changed; rebuild before use")
        for key, expected_root in (("runtime", PRIVATE_ROOT / "runtime/dotnet5"), ("worker", build / "bin")):
            tree = manifest["trees"][key]
            if Path(tree["root"]).resolve() != expected_root.resolve():
                raise RuntimeError("dnSpy manifest root mismatch")
            # Authenticate the complete installed engine/runtime tree; no extra loadable DLLs.
            observed = {str(item.relative_to(expected_root)).replace("\\", "/")
                        for item in expected_root.rglob("*") if item.is_file()}
            if observed != set(tree["files"]):
                raise RuntimeError("dnSpy engine/runtime file inventory changed")
            for relative, expected in tree["files"].items():
                candidate = expected_root / relative
                no_reparse(candidate)
                if sha256(candidate) != expected:
                    raise RuntimeError("dnSpy engine/runtime hash mismatch")
        self.runtime = PRIVATE_ROOT / "runtime/dotnet5/dotnet.exe"
        self.assembly = build / "bin/REAForgeDnSpyWorker.dll"
        self.engines = {"manifest_path": str(manifest_path), "manifest_sha256": sha256(manifest_path)}

    def copy(self, raw: str, source: bool = False) -> Path:
        HardDenyPolicy().require_local_path(raw)
        given = Path(raw)
        if not given.is_absolute():
            raise ValueError("absolute input path required")
        no_reparse(given)
        path = given.resolve(strict=True)
        roots = [Path(item).resolve() for item in self.config["input_roots"]] + [PRIVATE_ROOT / "work/dotnet"]
        if (not path.is_file() or not any(path.is_relative_to(root) for root in roots)
                or path.suffix.lower() not in ({".cs"} if source else {".exe", ".dll", ".netmodule"})
                or path.stat().st_size > (1024 * 1024 if source else MAX_INPUT)):
            raise ValueError("input is not an admitted bounded .NET file/source")
        identity = {"path": str(path), "sha256": sha256(path), "size_bytes": path.stat().st_size,
                    "is_pe": not source}
        self.inputs.append(identity)
        output = self.root / "inputs" / (secrets.token_hex(8) + path.suffix)
        shutil.copyfile(path, output)
        if sha256(output) != identity["sha256"]:
            raise ValueError("input changed during copy")
        return output

    def call(self, operation: str, arguments: dict) -> dict:
        tag = secrets.token_hex(8)
        request = self.root / "tmp" / (tag + ".json")
        request.write_text(json.dumps({"operation": operation, **arguments}), encoding="utf-8")
        log = self.root / "logs" / (tag + ".json")
        env = {"SystemRoot": os.environ["SystemRoot"], "WINDIR": os.environ["SystemRoot"],
               "TEMP": str(self.root / "tmp"), "TMP": str(self.root / "tmp"),
               "USERPROFILE": str(self.root / "tmp"), "DOTNET_ROOT": str(self.runtime.parent),
               "DOTNET_MULTILEVEL_LOOKUP": "0", "DOTNET_NOLOGO": "1",
               "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "REA_FORGE_DNSPY_WORKSPACE": str(self.root)}
        started = time.monotonic()
        with log.open("xb") as output:
            process = subprocess.Popen([str(self.runtime), str(self.assembly), str(request)],
                cwd=self.root, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                (self.root / "logs" / (tag + ".owner.json")).write_text(
                    json.dumps({"pid": process.pid, "phase": "native_started"}), encoding="utf-8")
                while True:
                    if time.monotonic() - started > 35 or log.stat().st_size > 8 * 1024 * 1024:
                        raise TimeoutError("owned dnSpy engine time/output limit exceeded")
                    try:
                        code = process.wait(timeout=0.1)
                        break
                    except subprocess.TimeoutExpired:
                        pass
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
        self.native.append({"pid": process.pid, "exit_code": code, "owned_wait_completed": True,
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "log_path": str(log), "log_sha256": sha256(log)})
        response = json.loads(log.read_text(encoding="utf-8-sig"))
        if code != 0 or response.get("ok") is not True or not isinstance(response.get("data"), dict):
            raise ValueError("dnSpy rejected static request: " + str(response.get("error", "invalid reply"))[:2048])
        return response["data"]

    def output(self, name: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}\.(?:exe|dll|netmodule)", name) or name.startswith("."):
            raise ValueError("output_name must be a simple new .NET filename")
        output = self.root / "outputs" / name
        if output.exists():
            raise ValueError("output already exists")
        return output

    def derived(self, output: Path, result: dict) -> dict:
        if not output.is_file() or output.stat().st_size > MAX_INPUT:
            raise ValueError("derived output missing or oversized")
        return {**result, "output": {"path": str(output), "sha256": sha256(output),
            "size_bytes": output.stat().st_size, "is_pe": True},
            "readback": self.call("inspect", {"path": str(output), "limit": 8, "details": True}),
            "metadata": self.call("inspect_metadata", {"path": str(output)})}


def execute(operation: str, arguments: dict) -> dict:
    work = Work()
    if operation == "forge_compile_dotnet":
        source = work.copy(arguments["source_path"], source=True)
        output = work.output(arguments["output_name"])
        result = work.call("compile_source", {"source_path": str(source), "output_path": str(output),
            "output_kind": arguments["output_kind"],
            **{key: value for key, value in arguments.items() if key.startswith("embedded_resource_")}})
        if result.get("compiled") is not True:
            raise ValueError("C# compilation failed: " + json.dumps(result["diagnostics"])[:2048])
        result = work.derived(output, result)
    else:
        source = work.copy(arguments["path"])
        params = {key: value for key, value in arguments.items() if key not in {"path", "view", "action", "output_name"}}
        params["path"] = str(source)
        if operation == "forge_inspect_dotnet":
            result = work.call({"types": "inspect", "metadata": "inspect_metadata", "resources": "list_resources", "capabilities": "status"}[arguments["view"]], params)
        elif operation == "forge_decompile_dotnet":
            result = work.call("decompile_type_as", params)
        elif operation == "forge_read_dotnet_resource":
            result = work.call("read_embedded_resource", params)
        elif operation == "forge_edit_dotnet":
            output = work.output(arguments["output_name"])
            result = work.derived(output, work.call(arguments["action"], {**params, "output_path": str(output)}))
        else:
            raise ValueError("unsupported Forge .NET operation")
    for identity in work.inputs:
        if sha256(Path(identity["path"])) != identity["sha256"]:
            raise ValueError("original input identity changed during analysis")
    return {"operation": operation, "target": work.inputs[0], "inputs": work.inputs,
            "result": result, "native": work.native, "engines": work.engines, "workspace": str(work.root),
            "sample_execution": False, "network_used": False}


if __name__ == "__main__":
    try:
        path = Path(sys.argv[1])
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("request exceeds 8 MiB")
        request = json.loads(path.read_text(encoding="utf-8"))
        print(json.dumps({"ok": True, "value": execute(request["operation"], request["arguments"])}))
    except Exception as error:
        print(json.dumps({"ok": False, "error": {"kind": type(error).__name__, "message": str(error)[:4096]}}))
        sys.exit(2)
