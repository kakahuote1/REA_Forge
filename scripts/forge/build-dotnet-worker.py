"""Offline build of authored dnSpy adapter; only installed, operator-selected SDK/APIs."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / ".forge-local"


def digest(path: Path) -> str:
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--dnspy-bin", type=Path, required=True)
    args = parser.parse_args()
    sdk = args.sdk.resolve(strict=True)
    dnspy = args.dnspy_bin.resolve(strict=True)
    source = ROOT / "bridge/forge/dotnet"
    build = PRIVATE / "build/dotnet"
    build.mkdir(parents=True, exist_ok=True)
    temporary = PRIVATE / "tmp/dotnet-build"
    temporary.mkdir(parents=True, exist_ok=True)
    env = {"SystemRoot": os.environ["SystemRoot"], "WINDIR": os.environ["SystemRoot"],
           "TEMP": str(temporary), "TMP": str(temporary), "DOTNET_ROOT": str(sdk),
           "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
           "DOTNET_CLI_HOME": str(PRIVATE / "cache/dotnet"), "DOTNET_NOLOGO": "1", "DOTNET_CLI_UI_LANGUAGE": "en",
           "NUGET_PACKAGES": str(PRIVATE / "cache/nuget"), "DOTNET_MULTILEVEL_LOOKUP": "0"}
    for key in ("SystemDrive", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "ALLUSERSPROFILE", "OS", "PROCESSOR_ARCHITECTURE"):
        if key in os.environ:
            env[key] = os.environ[key]
    for key, folder in (("USERPROFILE", "profile"), ("APPDATA", "profile/AppData/Roaming"), ("LOCALAPPDATA", "profile/AppData/Local")):
        location = temporary / folder
        location.mkdir(parents=True, exist_ok=True)
        env[key] = str(location)
    completed = subprocess.run([str(sdk / "dotnet.exe"), "build", str(source / "Worker.csproj"),
        "--configuration", "Release", "--output", str(build / "bin"), "--nologo", "--verbosity", "minimal",
        "--configfile", str(source / "NuGet.Config"), "-maxcpucount:1", "-nodeReuse:false",
        "-p:UseSharedCompilation=false", f"-p:DnSpyBin={dnspy}",
        f"-p:BaseIntermediateOutputPath={build / 'obj'}/"],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print(completed.stdout.decode("utf-8", errors="replace")[-16384:])
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace")[-4096:])
    # Runtime only: do not duplicate the SDK, WPF/ASP.NET packs or old framework.
    runtime = PRIVATE / "runtime/dotnet5"
    runtime.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sdk / "dotnet.exe", runtime / "dotnet.exe")
    for directory in ("host/fxr", "shared/Microsoft.NETCore.App"):
        shutil.copytree(sdk / directory, runtime / directory, dirs_exist_ok=True)
    trees = {"runtime": runtime, "worker": build / "bin"}
    manifest = {"sources": {str(path.relative_to(source)): digest(path)
                            for path in source.iterdir() if path.is_file()},
                "trees": {key: {"root": str(folder), "files": {
                    str(path.relative_to(folder)).replace("\\", "/"): digest(path)
                    for path in folder.rglob("*") if path.is_file()}}
                    for key, folder in trees.items()}}
    (build / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"built": True, "manifest": str(build / "manifest.json"), "runtime": str(runtime)}))


if __name__ == "__main__":
    main()
