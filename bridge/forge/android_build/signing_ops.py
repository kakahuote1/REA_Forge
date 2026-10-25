"""Fixed apksigner/keytool calls; no CA installation or password transport."""
from __future__ import annotations

import json
from pathlib import Path
import re

from common.static_files import bounded_file, identity, pinned, sha256_file, stage_input
from android_build.project_files import load_receipt, validate_apk
from android_build.project_ops import engine, java, native


def verification(path: Path, selected: dict, workspace: Path, values: dict) -> dict:
    stdout, stderr, timing = native([*java(selected, "apksigner", workspace), "verify", "--verbose", "--print-certs", str(path)],
        workspace, values, "verify", accepted_exit_codes=frozenset({0, 1}))
    text = stdout.read_text(encoding="utf-8", errors="replace") + "\n" + stderr.read_text(encoding="utf-8", errors="replace")
    passed = timing["exit_code"] == 0 and bool(re.search(r"(?m)^Verifies\s*$", text))
    invalid = timing["exit_code"] == 1 and "DOES NOT VERIFY" in text
    certificates = re.findall(r"certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", text)
    return {"status": "verified" if passed else "invalid" if invalid else "indeterminate", "verified": passed,
            "certificate_sha256": [value.lower() for value in certificates],
            "schemes": {name: state == "true" for name, state in re.findall(r"Verified using (v[0-9.]+) scheme[^\r\n]*:\s*(true|false)", text)},
            "stdout": identity(stdout), "stderr": identity(stderr), **timing}


def verify(values: dict, selected: dict, workspace: Path) -> dict:
    target, source = stage_input(selected, values["path"], workspace, leaf="input.apk", maximum=256 * 1024 * 1024)
    target["kind"] = "file"
    validate_apk(source)
    result = verification(source, selected, workspace, values)
    if sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("original APK changed during verification")
    return {"kind": "android-signature", "action": "verify", "target": target, "verification": result, "artifacts": [], "engine": engine(selected, "apksigner", {})}


def test_key(selected: dict, workspace: Path, values: dict) -> tuple[Path, str, list[str], dict]:
    if "key_receipt_path" in values:
        reference = {"receipt_path": values["key_receipt_path"], "receipt_sha256": values["key_receipt_sha256"]}
        receipt, record = load_receipt(reference, {"android-test-key"})
        key = bounded_file(record["keystore"]["path"], 1024 * 1024)
        if key.parent != receipt.parent or sha256_file(key) != record["keystore"]["sha256"]:
            raise ValueError("test signing key changed or escaped its owner")
    else:
        key = workspace / "test-key.p12"
        native([str(pinned(selected, "keytool")), "-genkeypair", "-storetype", "PKCS12", "-keystore", str(key),
                "-storepass", "android", "-keypass", "android", "-alias", "forge-test", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "3650", "-dname", "CN=REA Forge Local Test,O=Local Test,C=ZZ", "-noprompt"], workspace, values, "keytool")
        receipt = workspace / "test-key-receipt.json"
        record = {"kind": "android-test-key", "keystore": identity(key), "alias": "forge-test", "test_only": True,
                  "password_policy": "public standard Android test password; not a production identity"}
        receipt.write_text(json.dumps(record), encoding="utf-8")
    return key, "forge-test", ["--ks-pass", "pass:android", "--key-pass", "pass:android"], {"receipt_path": str(receipt), "receipt_sha256": sha256_file(receipt), "test_only": True}


def signing_key(selected: dict, workspace: Path, values: dict) -> tuple:
    profile_name = values.get("profile", "test")
    if profile_name == "test":
        return test_key(selected, workspace, values)
    profile = selected.get("profiles", {}).get(profile_name)
    if not isinstance(profile, dict) or "key_receipt_path" in values:
        raise ValueError("select one configured signing profile or an owned test key, not both")
    alias = profile["alias"]
    if not isinstance(alias, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", alias):
        raise ValueError("configured key alias is invalid")
    key = pinned(profile, "keystore")
    password = bounded_file(profile["password_file"], 4096)
    key_password = bounded_file(profile.get("key_password_file", profile["password_file"]), 4096)
    # Only file selectors cross argv. Credential contents are never read into
    # this process, Evidence, the receipt, or a command-line password argument.
    return key, alias, ["--ks-pass", "file:" + str(password), "--key-pass", "file:" + str(key_password)], {"profile": profile_name, "test_only": False}


def sign(values: dict, selected: dict, workspace: Path) -> dict:
    target, source = stage_input(selected, values["path"], workspace, leaf="input.apk", maximum=256 * 1024 * 1024)
    target["kind"] = "file"
    validate_apk(source)
    key, alias, passwords, reference = signing_key(selected, workspace, values)
    before_key = sha256_file(key)
    output = workspace / "signed.apk"
    native([*java(selected, "apksigner", workspace), "sign", "--ks", str(key), "--ks-key-alias", alias,
            *passwords, "--out", str(output), str(source)], workspace, values, "sign")
    bounded_file(output, 256 * 1024 * 1024)
    result = verification(output, selected, workspace, values)
    if not result["verified"] or not result["certificate_sha256"]:
        raise ValueError("signed output did not pass cryptographic verification")
    if sha256_file(key) != before_key or sha256_file(Path(target["path"])) != target["sha256"]:
        raise ValueError("signing changed a borrowed key or original APK")
    artifacts = [identity(output)]
    sidecar = output.with_name(output.name + ".idsig")
    if sidecar.is_file():
        artifacts.append(identity(bounded_file(sidecar, 16 * 1024 * 1024)))
    return {"kind": "android-signature", "action": "sign", "target": target, "verification": result,
            "signing_identity": reference, "artifacts": artifacts, "engine": engine(selected, "apksigner", {})}
