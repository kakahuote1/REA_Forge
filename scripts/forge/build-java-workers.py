"""Build only authored workers against explicitly pinned installed engine APIs."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge" / "forge"))
from java.configuration import configuration, pinned_engine, sha256
from common.paths import PRIVATE_ROOT


def main() -> None:
    selected = configuration()
    compiler = pinned_engine(selected, "javac")
    build = PRIVATE_ROOT / "build" / "java"
    build.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for engine in ("recaf", "bcv"):
        dependency = pinned_engine(selected, engine)
        destination = build / engine
        destination.mkdir(exist_ok=True)
        source = ROOT / "bridge" / "forge" / "java" / engine / "Worker.java"
        completed = subprocess.run([str(compiler), "-encoding", "UTF-8", "-proc:none", "-cp", str(dependency),
                                    "-d", str(destination), str(source)], cwd=ROOT, stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=40,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if completed.returncode != 0:
            sys.stderr.buffer.write(completed.stderr[:16384])
            raise RuntimeError(f"{engine} worker compilation failed")
        manifest[engine] = {"source_sha256": sha256(source), "engine_sha256": sha256(dependency),
                            "classes": {str(path.relative_to(destination)).replace("\\", "/"): sha256(path)
                                        for path in destination.rglob("*.class")}}
    (build / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"built": True, "workers": list(manifest), "manifest": str(build / "manifest.json")}))


if __name__ == "__main__":
    main()
