"""Prepare integrity-pinned local build artifacts without global installation.

The Windows addon restore follows native/windows/README.md. This does not
execute samples, start MCP servers, change PATH, or register host services.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / ".forge-local"
NODE_VERSION = "24.18.0"
NODE_SHA256 = "0ae68406b42d7725661da979b1403ec9926da205c6770827f33aac9d8f26e821"
REA_VERSION = "6.7.0"
REA_SHA512 = "yhIx2ioJYYT1C/tONfYeitC6LhnKmCh+ZwRUOgYuhSc733lGhkkt73zhug9WmLgxoMdKuqIYGCoBfD4fXkOhFw=="


def digest(path: Path, algorithm: str) -> bytes:
    with path.open("rb") as source:
        return hashlib.file_digest(source, algorithm).digest()


def download(url: str, target: Path, algorithm: str, expected: bytes) -> None:
    if target.exists():
        if digest(target, algorithm) != expected:
            raise ValueError(f"Existing download failed integrity: {target.name}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".partial")
    if partial.exists():
        raise FileExistsError(f"Inspect previous partial download first: {partial.name}")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    result = subprocess.run(
        ["curl.exe" if os.name == "nt" else "curl", "--connect-timeout", "8",
         "--max-time", "45", "--fail", "--silent", "--show-error", "--location",
         "--output", str(partial), url],
        capture_output=True, text=True, timeout=50, creationflags=flags)
    if result.returncode:
        raise RuntimeError(f"Download failed ({result.returncode}): {result.stderr[-1500:]}")
    if digest(partial, algorithm) != expected:
        raise ValueError(f"Downloaded bytes failed integrity: {target.name}")
    partial.replace(target)


def install_node() -> dict:
    archive = LOCAL / "downloads" / f"node-v{NODE_VERSION}-win-x64.zip"
    download(f"https://nodejs.org/dist/v{NODE_VERSION}/{archive.name}", archive,
             "sha256", bytes.fromhex(NODE_SHA256))
    destination = LOCAL / "runtime"
    destination.mkdir(parents=True, exist_ok=True)
    prefix = f"node-v{NODE_VERSION}-win-x64/"
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            relative = Path(member.filename)
            if (not member.filename.startswith(prefix) or relative.is_absolute()
                    or ".." in relative.parts or "\\" in member.filename
                    or (member.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("Unexpected Node archive member")
        package.extractall(destination)
    node_root = destination / prefix.rstrip("/")
    npm = json.loads((node_root / "node_modules/npm/package.json").read_text(encoding="utf-8"))
    return {"node": str(node_root / "node.exe"), "node_version": NODE_VERSION,
            "npm_version": npm["version"], "archive_sha256": NODE_SHA256}


def restore_native() -> dict:
    current = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    if current["version"] != REA_VERSION:
        raise ValueError("Checkout package version changed; review the native restore pin")
    archive = LOCAL / "downloads" / f"rea-agents-{REA_VERSION}.tgz"
    download(f"https://registry.npmjs.org/rea-agents/-/{archive.name}", archive,
             "sha512", base64.b64decode(REA_SHA512))
    destination = ROOT / "native/windows/build"
    destination.mkdir(parents=True, exist_ok=True)
    selected = {}
    with tarfile.open(archive, "r:gz") as package:
        for name in ("manifest.json", "rea-windows-x64.node"):
            member = package.getmember("package/native/windows/build/" + name)
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError("Unexpected native package member")
            source = package.extractfile(member)
            assert source is not None
            content = source.read()
            target = destination / name
            if target.exists() and target.read_bytes() != content:
                raise FileExistsError(f"Refusing to replace different native artifact: {name}")
            target.write_bytes(content)
            selected[name] = hashlib.sha256(content).hexdigest()
    return {"package_version": REA_VERSION, "artifacts_sha256": selected,
            "source": "exact-version published npm artifact; not a new native source build"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=("node", "native"))
    args = parser.parse_args()
    result = install_node() if args.component == "node" else restore_native()
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
