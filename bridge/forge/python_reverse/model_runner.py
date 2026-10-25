"""Fixed offline model runner using existing operator-supplied PyLingual assets."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.static_files import bounded_file, pinned, read_json, sha256_file
from common.hard_deny_policy import HardDenyPolicy

MAGICS = {"610d0d0a": "3.9", "6f0d0d0a": "3.10", "a70d0d0a": "3.11", "cb0d0d0a": "3.12"}


class ModelMemoryAdmissionError(RuntimeError):
    def __init__(self, minimum: int, available: int):
        super().__init__(f"model memory admission requires {minimum} free bytes; observed {available}; no model was loaded")
        self.reported_limits = {"minimum_free_bytes": minimum, "observed_free_bytes": available}


def require_model_memory(minimum: int) -> None:
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
        raise ValueError("invalid configured model memory admission")
    if sys.platform == "win32":
        import ctypes
        class Status(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                        *[(name, ctypes.c_ulonglong) for name in ("total", "available", "page_total", "page_available", "virtual_total", "virtual_available", "extended")]]
        status = Status()
        status.length = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise RuntimeError("available model memory could not be observed")
        available = status.available
    else:
        available = os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    if available < minimum:
        raise ModelMemoryAdmissionError(minimum, available)


def main() -> None:
    job = Path(sys.argv[1]).resolve(strict=True)
    selected = read_json(job / "model-selection.json", 65536)
    source = job / "input.pyc"
    with source.open("rb") as stream:
        version = MAGICS.get(stream.read(4).hex())
    manifest = read_json(pinned(selected, "models_manifest"), 65536)
    if version not in manifest["qualified_versions"]:
        raise ValueError("PYC has no qualified local model/interpreter")
    executable = bounded_file(sys.executable, 1024 * 1024)
    if sha256_file(executable) != manifest["python_sha256"]:
        raise ValueError("model interpreter identity drifted")
    interpreter = manifest["verification_interpreters"][version]
    verification = bounded_file(interpreter["path"], 1024 * 1024)
    if sha256_file(verification) != interpreter["sha256"]:
        raise ValueError("verification interpreter identity drifted")
    configured_root = Path(selected["root"])
    HardDenyPolicy().require_local_path(configured_root)
    if not configured_root.is_absolute() or configured_root.is_symlink() or not configured_root.is_dir():
        raise ValueError("model root must be an absolute local directory")
    root = configured_root.resolve(strict=True)
    package = root / "pylingual"
    digest = hashlib.sha256()
    for path in sorted(package.rglob("*")):
        if path.is_file() and path.suffix in (".py", ".yaml"):
            if path.is_symlink() or not path.resolve(strict=True).is_relative_to(package):
                raise ValueError("model source contains an escaping entry")
            digest.update(path.relative_to(package).as_posix().encode() + b"\0" + bytes.fromhex(sha256_file(path)))
    if digest.hexdigest() != manifest["source_tree_sha256"]:
        raise ValueError("reviewed PyLingual source identity drifted")
    for name, expected in manifest["runtime_versions"].items():
        if importlib.metadata.version(name) != expected:
            raise ValueError("model runtime dependency version drifted: " + name)
    paths = {}
    for model in manifest["models"]:
        if "/py" + version.replace(".", "") + "-" not in model["repo"]:
            continue
        path = root / "models" / model["repo"].split("/")[-1] / model["commit"]
        for item in model["files"]:
            asset = bounded_file(path / item["name"], 2 * 1024 * 1024 * 1024)
            if asset.stat().st_size != item["size"] or sha256_file(asset) != item["sha256"]:
                raise ValueError("selected model or tokenizer identity drifted")
        paths[model["repo"].rsplit("-", 1)[-1]] = path
    if set(paths) != {"segmenter", "tokenizer", "statement", "tok"}:
        raise ValueError("selected version's local model set is incomplete")
    temporary = Path(os.environ["TEMP"]).resolve(strict=True) / "model-tmp"
    temporary.mkdir()
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1",
                      HF_HOME=str(temporary), TORCH_HOME=str(temporary), TMP=str(temporary), TEMP=str(temporary),
                      USE_TF="0", USE_FLAX="0", TOKENIZERS_PARALLELISM="false")
    def deny_sockets(event, _args):
        if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo", "socket.bind"}:
            raise PermissionError("offline model operation does not use sockets")
    sys.addaudithook(deny_sockets)
    sys.path.insert(0, str(root))
    import torch
    import transformers
    torch.set_num_threads(2)
    from pylingual.models import CacheTranslator
    import pylingual.decompiler as engine
    import pylingual.utils.generate_bytecode as compiler
    pair = tuple(map(int, version.split(".")))
    def load_models(_config, target, redis_cache_server_ip=None, redis_port=None):
        if target.as_tuple() != pair or redis_cache_server_ip is not None:
            raise ValueError("only the selected offline model is admitted")
        segmenter_model = transformers.AutoModelForTokenClassification.from_pretrained(
            str(paths["segmenter"]), local_files_only=True, trust_remote_code=False, use_safetensors=True)
        segmenter_tokenizer = transformers.PreTrainedTokenizerFast(tokenizer_file=str(paths["tokenizer"] / "tokenizer.json"),
            unk_token="[UNK]", pad_token="[PAD]", cls_token="[CLS]", sep_token="[SEP]", mask_token="[MASK]")
        segmenter = transformers.pipeline("token-classification", model=segmenter_model,
            tokenizer=segmenter_tokenizer, aggregation_strategy="none", device=-1)
        translator = transformers.T5ForConditionalGeneration.from_pretrained(
            str(paths["statement"]), local_files_only=True, trust_remote_code=False, use_safetensors=True)
        tokenizer = transformers.RobertaTokenizer.from_pretrained(str(paths["tok"]), local_files_only=True)
        return segmenter, CacheTranslator(translator, tokenizer, python_version=version, device="cpu")
    def compile_local(py_file, out_file, target):
        if target.as_tuple() != pair:
            raise ValueError("verification compiler version mismatch")
        for raw in (py_file, out_file):
            if not Path(raw).resolve().is_relative_to(temporary):
                raise ValueError("verification compiler path escaped temporary owner")
        outcome = subprocess.run([str(verification), "-I", "-c",
            "import py_compile,sys; py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)", str(py_file), str(out_file)],
            capture_output=True, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if outcome.returncode:
            raise compiler.CompileError(outcome.stderr.decode("utf-8", errors="replace")[:2000])
    engine.load_models, engine.compile_version, compiler.compile_version = load_models, compile_local, compile_local
    # compile_version compiles generated source bytes only; it never imports/runs them.
    result = engine.decompile(source, top_k=1, timeout=35)
    text = result.decompiled_source
    if len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("model source output exceeds its bound")
    success = result.calculate_success_rate()
    report = {"analysis_status": "decompiled", "engine": "pylingual", "text": text,
              "pyc": {"version": list(pair), "implementation": "CPython"},
              "equivalence_success_rate": success, "equivalence_verified": success == 1,
              "source_execution": False, "network_used": False}
    (job / "model-result.json").write_text(json.dumps(report, ensure_ascii=True, allow_nan=False), encoding="utf-8")


if __name__ == "__main__":
    main()
