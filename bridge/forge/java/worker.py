"""One bounded static Java transaction. No target classes are executed."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.hard_deny_policy import HardDenyPolicy
from common.paths import PRIVATE_ROOT
from java.configuration import configuration, pinned_engine, sha256, worker_classes

MAX_INPUT = 64 * 1024 * 1024
MAX_TEXT = 512 * 1024
CLASS = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
OPERATIONS = {"forge_inspect_java", "forge_decompile_java", "forge_disassemble_java", "forge_search_java",
              "forge_java_call_graph", "forge_edit_java", "forge_compare_java"}


def class_identity(data: bytes) -> str:
    """Read this_class from bounded classfile data without loading a JVM class."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("malformed Java class header")
    count = int.from_bytes(data[8:10], "big")
    constants = {}
    index, offset = 1, 10
    lengths = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4,
               15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    try:
        while index < count:
            tag = data[offset]
            offset += 1
            if tag == 1:
                length = struct.unpack_from(">H", data, offset)[0]
                offset += 2
                constants[index] = data[offset:offset + length].decode("utf-8", errors="replace")
            else:
                length = lengths[tag]
                if tag == 7:
                    constants[index] = struct.unpack_from(">H", data, offset)[0]
            offset += length
            if offset > len(data):
                raise ValueError("truncated Java constant pool")
            index += 2 if tag in {5, 6} else 1
        selected = struct.unpack_from(">H", data, offset + 2)[0]
        name = constants[constants[selected]]
        if not isinstance(name, str) or not name:
            raise ValueError("invalid Java class name reference")
        return name
    except (IndexError, KeyError, struct.error, TypeError) as cause:
        raise ValueError("malformed Java class identity") from cause


def verify_selected_class(source: Path, requested: str) -> None:
    if source.suffix.lower() == ".class":
        if source.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("selected Java class exceeds its bound")
        data = source.read_bytes()
    else:
        with zipfile.ZipFile(source) as archive:
            entries = archive.infolist()
            matches = [entry for entry in entries if entry.filename == requested + ".class"]
            if len(entries) > 8000 or len(matches) != 1 or matches[0].file_size > 8 * 1024 * 1024:
                raise ValueError("selected Java class is absent, ambiguous or oversized")
            with archive.open(matches[0]) as stream:
                data = stream.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise ValueError("selected Java class exceeds its expanded bound")
    if class_identity(data) != requested:
        raise ValueError("selected JVM class identity does not match its actual classfile")


class Transaction:
    def __init__(self) -> None:
        self.config = configuration()
        self.root = PRIVATE_ROOT / "work" / "java" / secrets.token_hex(16)
        self.root.mkdir(parents=True)
        for name in ("inputs", "outputs", "logs", "tmp"):
            (self.root / name).mkdir()
        self.originals: list[dict] = []
        self.native: list[dict] = []
        self.engines: dict = {}

    def engine(self, name: str) -> Path:
        path = pinned_engine(self.config, name)
        self.engines[name] = self.config[name]
        return path

    def copy(self, raw: str, suffixes: set[str]) -> Path:
        HardDenyPolicy().require_local_path(raw)
        given = Path(raw)
        path = given.resolve(strict=True)
        roots = [Path(item).resolve() for item in self.config["input_roots"]] + [PRIVATE_ROOT / "work" / "java"]
        if (not given.is_absolute() or given.is_symlink() or not path.is_file()
                or not any(path.is_relative_to(root) for root in roots)
                or path.suffix.lower() not in suffixes or path.stat().st_size > MAX_INPUT):
            raise ValueError("Java input is not an admitted bounded file")
        identity = {"path": str(path), "sha256": sha256(path), "size_bytes": path.stat().st_size, "is_pe": False}
        self.originals.append(identity)
        folder = self.root / "inputs" / secrets.token_hex(8)
        folder.mkdir()
        copied = folder / path.name
        shutil.copyfile(path, copied)
        if sha256(copied) != identity["sha256"]:
            raise ValueError("Java working-copy identity changed")
        return copied

    def run(self, argv: list[str], *, payload: dict | None = None, environment: dict | None = None) -> str:
        tag = secrets.token_hex(8)
        log = self.root / "logs" / (tag + ".log")
        request = self.root / "tmp" / (tag + ".json")
        request.write_text(json.dumps(payload or {}), encoding="utf-8")
        started = time.monotonic()
        env = {key: value for key, value in os.environ.items()
               if key not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"}}
        env.update(environment or {})
        with log.open("xb") as output, request.open("rb") as input_stream:
            process = subprocess.Popen(argv, stdin=input_stream, stdout=output, stderr=subprocess.STDOUT,
                                       cwd=self.root, env=env, shell=False,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                while True:
                    if time.monotonic() - started > 30 or log.stat().st_size > 6 * 1024 * 1024:
                        raise TimeoutError("owned Java engine exceeded its time/output bound")
                    try:
                        code = process.wait(timeout=0.1)
                        break
                    except subprocess.TimeoutExpired:
                        continue
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
        text = log.read_text(encoding="utf-8", errors="replace")
        self.native.append({"pid": process.pid, "exit_code": code, "owned_wait_completed": True,
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "log_path": str(log), "log_sha256": sha256(log)})
        if code != 0:
            raise RuntimeError("static Java engine failed: " + text[-2048:])
        return text

    def java_command(self) -> list[str]:
        return [str(self.engine("java")), "-Xmx512m", "-Dfile.encoding=UTF-8",
                f"-Djava.io.tmpdir={self.root / 'tmp'}", "-Djava.net.useSystemProxies=false"]

    def recaf(self, operation: str, arguments: dict) -> dict:
        token = secrets.token_hex(24)
        jar = self.engine("recaf")
        classes = worker_classes("recaf")
        text = self.run(self.java_command() + ["-cp", os.pathsep.join((str(classes), str(jar))), "forge.recaf.Worker"],
                        payload={"token": token, "operation": operation, **arguments},
                        environment={"REA_FORGE_JAVA_TOKEN": token, "REA_FORGE_JAVA_WORKSPACE": str(self.root)})
        # JVM warnings can precede the one worker JSON record.
        start = text.find('{"ok":')
        value = json.loads(text[start:] if start >= 0 else text)
        if not isinstance(value, dict) or value.get("ok") is not True or not isinstance(value.get("data"), dict):
            raise ValueError("Recaf rejected the typed request; no output success is inferred")
        return value["data"]

    def class_tree(self, source: Path, class_name: str) -> tuple[Path, Path]:
        tree = self.root / "tmp" / "class-tree"
        tree.mkdir()
        if source.suffix.lower() == ".class":
            output = tree / (class_name + ".class")
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, output)
        else:
            total = count = 0
            with zipfile.ZipFile(source) as archive:
                if len(archive.infolist()) > 8000:
                    raise ValueError("Java archive has too many entries")
                for entry in archive.infolist():
                    if not entry.filename.endswith(".class"):
                        continue
                    name = entry.filename[:-6]
                    if not CLASS.fullmatch(name) or entry.file_size > 8 * 1024 * 1024:
                        raise ValueError("Java class archive entry is outside the bounded policy")
                    with archive.open(entry) as stream:
                        data = stream.read(8 * 1024 * 1024 + 1)
                    total += len(data)
                    count += 1
                    if total > MAX_INPUT or count > 4000 or len(data) > 8 * 1024 * 1024:
                        raise ValueError("Java class tree exceeds its bound")
                    output = tree / (name + ".class")
                    output.parent.mkdir(parents=True, exist_ok=True)
                    if output.exists():
                        raise ValueError("duplicate Java class entry")
                    output.write_bytes(data)
        chosen = tree / (class_name + ".class")
        if not chosen.is_file():
            raise ValueError("selected class is absent")
        return chosen, tree

    def rendered(self, source: Path, engine: str, class_name: str, dependencies: list[Path]) -> dict:
        verify_selected_class(source, class_name)
        if dependencies and engine not in {"cfr", "vineflower"}:
            raise ValueError("external dependencies are supported only by standalone CFR/Vineflower; they are not silently ignored")
        output = self.root / "outputs" / "rendered"
        output.mkdir()
        if engine.startswith("recaf_"):
            return self.recaf("decompile" if engine in {"recaf_cfr", "recaf_vineflower"} else "disassemble",
                              {"path": str(source), "class_name": class_name,
                               "engine": engine.removeprefix("recaf_")})
        if engine in {"javap", "bcv_procyon", "bcv_jd_core", "bcv_asm_textifier", "bcv_asmifier"}:
            selected, tree = self.class_tree(source, class_name)
            if engine == "javap":
                text = self.run([str(self.engine("javap")), "-J-Dfile.encoding=UTF-8",
                                 "-c", "-p", "-v", "-s", "-constants", str(selected)])
                if len(text.encode("utf-8")) > MAX_TEXT:
                    raise ValueError("javap output exceeds its bound")
                return {"engine": engine, "text": text, "class_name": class_name}
            target = output / "rendered.txt"
            jar = self.engine("bcv")
            classes = worker_classes("bcv")
            self.run(self.java_command() + ["-cp", os.pathsep.join((str(classes), str(jar))), "forge.bcv.Worker",
                    "--input", str(selected), "--output", str(target), "--class-name", class_name,
                    "--class-root", str(tree), "--engine", engine.removeprefix("bcv_")])
            if target.stat().st_size > MAX_TEXT:
                raise ValueError("Bytecode Viewer output exceeds its bound")
            return {"engine": engine, "class_name": class_name, "text": target.read_text(encoding="utf-8"),
                    "output_sha256": sha256(target)}
        jar = self.engine(engine)
        if engine == "cfr":
            args = ["-jar", str(jar), "--silent", "true", "--outputdir", str(output), "--clobber", "false",
                    "--caseinsensitivefs", "false", "--rename", "false", "--antiobf", "false",
                    "--outputencoding", "UTF-8", "--analyseas", "CLASS" if source.suffix == ".class" else "JAR"]
            if source.suffix != ".class":
                args += ["--jarfilter", re.escape(class_name)]
            if dependencies:
                args += ["--extraclasspath", os.pathsep.join(str(path) for path in dependencies)]
            args += [str(source)]
        elif engine == "vineflower":
            args = ["-jar", str(jar), "--silent", "--folder", "--thread-count=1", "--log-level=warn",
                    "--include-runtime=current", "--skip-extra-files=true", "--rename-members=false", f"--only={class_name}"]
            args += [f"--add-external={path}" for path in dependencies]
            args += [str(source), str(output)]
        else:
            raise ValueError("unknown static Java rendering engine")
        self.run(self.java_command() + args)
        rendered = []
        size = 0
        for path in output.rglob("*"):
            if not path.is_file():
                continue
            size += path.stat().st_size
            if path.is_symlink() or size > 8 * 1024 * 1024 or len(rendered) >= 128 or path.stat().st_size > MAX_TEXT:
                raise ValueError("decompiled output exceeds its bounded policy")
            rendered.append({"path": str(path), "relative_path": str(path.relative_to(output)),
                             "sha256": sha256(path), "text": path.read_text(encoding="utf-8", errors="replace")})
        if not any(value["relative_path"].endswith(".java") for value in rendered):
            raise ValueError("decompiler produced no verified Java source")
        return {"engine": engine, "class_name": class_name, "files": rendered}

    def execute(self, operation: str, values: dict) -> dict:
        if operation not in OPERATIONS:
            raise ValueError("unknown Java operation")
        class_name = values.get("class_name")
        if class_name is not None and not CLASS.fullmatch(class_name):
            raise ValueError("malformed JVM internal class name")
        source = self.copy(values["path"], {".class", ".jar", ".war"}) if "path" in values else None
        arguments = {key: value for key, value in values.items() if key not in {"action", "dependency_paths", "engine"}}
        if source:
            arguments["path"] = str(source)
        if operation == "forge_inspect_java":
            result = self.recaf("inspect", arguments)
        elif operation == "forge_compare_java":
            right = self.copy(values["right_path"], {".class", ".jar", ".war"})
            result = self.recaf("diff", {"left_path": str(source), "right_path": str(right)})
        elif operation in {"forge_decompile_java", "forge_disassemble_java"}:
            dependencies = [self.copy(path, {".jar"}) for path in values.get("dependency_paths", [])]
            result = self.rendered(source, values["engine"], class_name, dependencies)
        elif operation in {"forge_search_java", "forge_java_call_graph"}:
            result = self.recaf("search" if operation == "forge_search_java" else "call_graph", arguments)
        else:
            action = values["action"]
            name = values["output_name"]
            if Path(name).name != name or "/" in name or "\\" in name or Path(name).suffix.lower() not in {".class", ".jar", ".war"}:
                raise ValueError("derived Java output must be one new artifact filename")
            arguments["output_path"] = str(self.root / "outputs" / name)
            arguments.pop("output_name", None)
            if action == "compile_java":
                arguments["source_path"] = str(self.copy(values["source_path"], {".java"}))
            elif action == "compile_java_set":
                arguments["source_paths"] = [str(self.copy(path, {".java"})) for path in values["source_paths"]]
                arguments["dependency_paths"] = [str(self.copy(path, {".jar"})) for path in values.get("dependency_paths", [])]
            elif action == "assemble":
                arguments["assembly_path"] = str(self.copy(values["assembly_path"], {".jasm"}))
            result = self.recaf(action, arguments)
            produced = Path(arguments["output_path"])
            if not produced.is_file() or produced.stat().st_size > MAX_INPUT:
                raise ValueError("Java edit produced no bounded output")
            result["derived_artifact"] = {"path": str(produced), "sha256": sha256(produced), "size_bytes": produced.stat().st_size}
        for original in self.originals:
            if sha256(Path(original["path"])) != original["sha256"]:
                raise ValueError("selected Java input changed during the transaction")
        report = {"operation": operation, "target": self.originals[0] if self.originals else None,
                  "result": result, "inputs": self.originals, "native": self.native, "engines": self.engines,
                  "workspace": str(self.root), "sample_execution": False, "network_used": False}
        (self.root / "receipt.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        return report


def main() -> None:
    try:
        if len(sys.argv) != 2:
            raise ValueError("one owned request file is required")
        request = Path(sys.argv[1])
        if not request.is_file() or request.is_symlink() or request.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("request file is outside its bounded policy")
        value = json.loads(request.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != {"operation", "arguments"} or not isinstance(value["arguments"], dict):
            raise ValueError("malformed static Java request")
        report = Transaction().execute(value["operation"], value["arguments"])
        print(json.dumps({"ok": True, "value": report}, ensure_ascii=False), flush=True)
    except Exception as cause:
        print(json.dumps({"ok": False, "error": {"kind": type(cause).__name__, "message": str(cause)}}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
