"""One fixed trusted library child, bounded by the existing owned native helper."""
from __future__ import annotations

import contextlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.static_files import read_json
from python_reverse.bytecode_analysis import BoundedText, analyze


if __name__ == "__main__":
    job = Path(sys.argv[1]).resolve(strict=True)
    request = read_json(job / "library-request.json", 65536)
    logs = BoundedText(256 * 1024)
    try:
        with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs):
            result = analyze(job / "input.pyc", request["arguments"], request["selected"])
        data = json.dumps(result, ensure_ascii=True, allow_nan=False).encode("utf-8")
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Python retained result exceeds its byte bound")
        (job / "library-result.json").write_bytes(data)
    finally:
        (job / "engine.log").write_text(logs.value(), encoding="utf-8")
