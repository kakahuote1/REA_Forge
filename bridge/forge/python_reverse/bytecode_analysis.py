"""Direct version-qualified library calls; target modules are never imported."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

from common.hard_deny_policy import HardDenyPolicy


class BoundedText:
    def __init__(self, maximum: int = 1024 * 1024):
        self.maximum, self.used, self.parts = maximum, 0, []

    def write(self, text: str) -> int:
        count = len(text.encode("utf-8"))
        if self.used + count > self.maximum:
            raise ValueError("Python analysis text exceeded its byte bound")
        self.parts.append(text)
        self.used += count
        return len(text)

    def flush(self) -> None:
        pass

    def value(self) -> str:
        return "".join(self.parts)


def admit_package(pin: dict, name: str) -> Path:
    root = Path(pin["path"])
    HardDenyPolicy().require_local_path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("configured Python package must be an absolute local directory")
    root = root.resolve(strict=True)
    digest, total = hashlib.sha256(), 0
    files = sorted(root.rglob("*.py"))
    if not 1 <= len(files) <= 4096:
        raise ValueError("configured Python package exceeds file bounds")
    for file in files:
        if file.is_symlink() or not file.is_file() or not file.resolve(strict=True).is_relative_to(root):
            raise ValueError("Python package contains a non-regular or escaping entry")
        total += file.stat().st_size
        if total > 64 * 1024 * 1024:
            raise ValueError("Python package exceeds total byte bound")
        digest.update(file.relative_to(root).as_posix().encode("utf-8") + b"\0")
        with file.open("rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
        digest.update(b"\n")
    if digest.hexdigest() != pin["sha256"] or root.name != name:
        raise ValueError("configured Python package identity drifted")
    sys.path.insert(0, str(root.parent))
    return root


def analyze(source: Path, values: dict, selected: dict) -> dict:
    admit_package(selected["xdis"], "xdis")
    from xdis.load import load_module
    from xdis.version_info import PythonImplementation
    code_objects = {}
    version, timestamp, magic, code, implementation, source_size, sip_hash, offsets = load_module(
        str(source), code_objects=code_objects, fast_load=False, get_code=True, save_file_offsets=True)
    if code is None:
        raise ValueError("xdis returned no code object")
    facts = {"version": list(version), "implementation": str(implementation), "magic_int": magic,
             "timestamp": timestamp, "source_size_mod_2_32": source_size, "sip_hash": sip_hash}
    if implementation not in (PythonImplementation.CPython, PythonImplementation.PyPy):
        return {"analysis_status": "unsupported_implementation", "pyc": facts, "text": ""}
    rendered = BoundedText()
    if values["mode"] == "disassemble":
        from xdis.disasm import disco
        disco(version_tuple=version, co=code, timestamp=timestamp, out=rendered, magic_int=magic,
              source_size=source_size, sip_hash=sip_hash, asm_format=values.get("format", "classic"),
              show_source=False, methods=tuple(), python_implementation=implementation, file_offsets=offsets)
        return {"analysis_status": "disassembled", "pyc": facts, "text": rendered.value(), "engine": "xdis"}
    pair = tuple(version[:2])
    engine = "uncompyle6" if pair <= (3, 6) else "decompyle3" if pair in {(3, 7), (3, 8)} else None
    explicit = values.get("engine", "auto")
    if engine is None or explicit not in {"auto", engine}:
        return {"analysis_status": "unsupported_version", "pyc": facts, "text": "", "engine": engine,
                "reason": "select a matching legacy engine; CPython 3.9–3.12 uses the separately configured modern model tool"}
    admit_package(selected["spark_parser"], "spark_parser")
    admit_package(selected[engine], engine)
    try:
        if engine == "decompyle3":
            from decompyle3.main import decompile
            decompile(code, bytecode_version=version, out=rendered, timestamp=timestamp, code_objects=code_objects,
                      source_size=source_size, python_implementation=implementation, magic_int=magic,
                      showasm=None, showast={}, showgrammar={}, source_encoding=None, mapstream=None,
                      do_fragments=False, compile_mode="exec", start_offset=0, stop_offset=-1)
        else:
            from uncompyle6.semantics.pysource import SourceWalker, code_deparse

            class LegacySourceWalker(SourceWalker):
                def build_ast(self, tokens, customize, current, *args, **kwargs):
                    # Retain the reviewed compiler-epilogue repair at its token owner.
                    if current.co_name == "<module>" and len(tokens) >= 2:
                        load, ret = tokens[-2:]
                        if (load.kind == "LOAD_CONST" and ret.kind == "RETURN_VALUE" and load.linestart is None
                                and load.pattr is None and isinstance(load.attr, int)
                                and 0 <= load.attr < len(current.co_consts) and current.co_consts[load.attr] is None):
                            load.attr = None
                    return super().build_ast(tokens, customize, current, *args, **kwargs)

            code_deparse(code, version=version, out=rendered, code_objects=code_objects,
                         is_pypy=implementation == PythonImplementation.PyPy, walker=LegacySourceWalker,
                         compile_mode="exec", start_offset=0, stop_offset=-1)
    except Exception as cause:
        return {"analysis_status": "decompile_failed", "pyc": facts, "text": "", "engine": engine,
                "failure": {"kind": type(cause).__name__, "message": str(cause)[:512]}}
    return {"analysis_status": "decompiled", "pyc": facts, "engine": engine, "text": rendered.value(),
            "equivalence_verified": False}
