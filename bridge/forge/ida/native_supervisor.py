"""Configure the existing IDA MCP dependency for REA's unchanged native reader."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.paths import PRIVATE_ROOT
from common.static_files import read_operator_configuration
from ida.host_profile import activate, prepare
from ida.worker import api_source


def main() -> None:
    if len(sys.argv) != 1:
        raise ValueError("the native IDA reader has no caller command-line options")
    selected = read_operator_configuration()["ida_host"]
    source = api_source(selected)
    # A small retained startup manifest/profile, not an input/engine installation
    # copy. P6 retention handles these explicit artifacts; no unverified worker
    # release is converted into permission to delete its runtime dependencies.
    workspace = PRIVATE_ROOT / "work" / "ida-native-profiles" / secrets.token_hex(16)
    workspace.mkdir(parents=True, exist_ok=False)
    profile = prepare(selected, workspace)
    (workspace / "profile.json").write_text(json.dumps(profile, ensure_ascii=True), encoding="ascii")
    activate(profile)
    for name in ("TEMP", "TMP", "TMPDIR"):
        os.environ[name] = str(workspace)
    os.environ.update(IDA_MCP_ALLOWED_ROOT=str(PRIVATE_ROOT / "tmp"), IDA_MCP_OPEN_TIMEOUT="40", IDA_MCP_WORKER_CALL_TIMEOUT="40", IDA_MCP_TOOL_TIMEOUT_SEC="35", IDA_MCP_WEDGED_GRACE_SEC="50", PYTHONUTF8="1")
    sys.path.insert(0, str(source))
    from ida_pro_mcp import idalib_supervisor
    sys.argv = ["idalib-mcp", "--stdio", "--max-workers", "1", "--profile", str(Path(__file__).with_name("native-read-tools.txt"))]
    idalib_supervisor.main()


if __name__ == "__main__":
    main()
