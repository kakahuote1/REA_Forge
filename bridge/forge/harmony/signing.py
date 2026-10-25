"""Offline local-JKS HAP signing; no trust-store, CA installation or cloud signing."""
from __future__ import annotations

import json
from pathlib import Path
import re

from common.static_files import bounded_file, identity, pinned, sha256_file
from harmony.engines import java, native

ALGORITHMS = {"SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA256withRSA/PSS", "SHA384withRSA/PSS", "SHA512withRSA/PSS", "SHA256withRSAANDMGF1", "SHA384withRSAANDMGF1", "SHA512withRSAANDMGF1"}


def redact(paths: list[Path], passwords: list[str]) -> None:
    # This vendor accepts password values, not password-file selectors. Remove
    # explicitly supplied values from retained diagnostics; never dump argv.
    for path in paths:
        if not path.is_file():
            continue
        data = path.read_bytes()
        for password in passwords:
            for encoding in ("utf-8", "utf-16le"):
                encoded = password.encode(encoding)
                if encoded:
                    data = data.replace(encoded, b"<redacted>")
        path.write_bytes(data)


def verify(selected: dict, source: Path, workspace: Path, values: dict, prefix: str = "verify") -> tuple[dict, list[dict]]:
    chain, profile, proof = [workspace / (prefix + suffix) for suffix in ("-chain.pem", "-profile.bin", "-proof.bin")]
    stdout, stderr, timing = native([*java(selected, workspace), "-jar", str(pinned(selected, "jar")), "verify", "-inputFile", str(source),
                                    "-outcertchain", str(chain), "-outprofile", str(profile), "-outproof", str(proof)], workspace, values, prefix, accepted=frozenset({0, 1, 2, 255}))
    text = stdout.read_text(encoding="utf-8", errors="replace") + "\n" + stderr.read_text(encoding="utf-8", errors="replace")
    passed = timing["exit_code"] == 0 and "verify: Verify success" in text and chain.is_file() and profile.is_file()
    artifacts = [identity(stdout), identity(stderr)]
    if passed:
        for path in (chain, profile, proof):
            if path.is_file():
                artifacts.append(identity(bounded_file(path, 16 * 1024 * 1024)))
    return {"verified": passed, "status": "verified" if passed else "not_verified", "timing": timing,
            "certificate_chain": identity(chain) if passed else None, "profile": identity(profile) if passed else None,
            "proof": identity(proof) if passed and proof.is_file() else None,
            "trust_semantics": "local vendor signature/profile consistency; not platform deployment authorization, trusted issuer, revocation check or code benignness"}, artifacts


def test_material(selected: dict, workspace: Path, values: dict) -> tuple:
    # Public test-only password and self-signed identity. No user key is read,
    # and none of the generated private material enters public readback.
    password, alias = "forge-local-test-password", "forgefixture"
    key, cert, store, profile_json, profile = [workspace / name for name in ("test-private.key", "test-cert.pem", "test-store.p12", "test-profile.json", "test-profile.p7b")]
    openssl = str(pinned(selected, "openssl"))
    native([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=REA-Forge-Local-Test", "-keyout", str(key), "-out", str(cert)], workspace, values, "test-cert")
    native([openssl, "pkcs12", "-export", "-inkey", str(key), "-in", str(cert), "-name", alias, "-out", str(store), "-passout", "pass:" + password], workspace, values, "test-store")
    pem = cert.read_text(encoding="ascii").replace("\r\n", "\n")
    profile_json.write_text(json.dumps({"type": "debug", "bundle-info": {"development-certificate": pem}, "forge_test_only": "self-signed local conformance, not a deployment provisioning profile"}), encoding="utf-8")
    native([openssl, "smime", "-sign", "-binary", "-in", str(profile_json), "-signer", str(cert), "-inkey", str(key), "-outform", "DER", "-out", str(profile), "-nodetach"], workspace, values, "test-profile")
    return store, cert, profile, alias, password, password, {"test_only": True, "identity": "self-signed non-deployment test identity"}


def signing_material(selected: dict, workspace: Path, values: dict) -> tuple:
    profile_name = values.get("profile", "test")
    if profile_name == "test":
        return test_material(selected, workspace, values)
    profile = selected.get("profiles", {}).get(profile_name)
    if not isinstance(profile, dict) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile.get("alias", "")):
        raise ValueError("select one operator-configured local signing profile")
    store, certificate, provisioning = [pinned(profile, name) for name in ("keystore", "certificate", "provisioning_profile")]
    passwords = []
    for name in ("password_file", "key_password_file"):
        path = bounded_file(profile.get(name, profile["password_file"]), 4096)
        password = path.read_text(encoding="utf-8").rstrip("\r\n")
        if not password or "\0" in password:
            raise ValueError("configured local signing password is empty or invalid")
        passwords.append(password)
    return store, certificate, provisioning, profile["alias"], *passwords, {"test_only": False, "profile": profile_name}


def sign(selected: dict, source: Path, workspace: Path, values: dict) -> tuple[dict, list[dict]]:
    algorithm = values.get("algorithm", "SHA256withRSA/PSS")
    if algorithm not in ALGORITHMS:
        raise ValueError("unsupported local-JKS signing algorithm")
    store, cert, profile, alias, password, key_password, reference = signing_material(selected, workspace, values)
    originals = {str(path): sha256_file(path) for path in (store, cert, profile)}
    output = workspace / "signed.hap"
    try:
        stdout, stderr, timing = native([*java(selected, workspace), "-jar", str(pinned(selected, "jar")), "sign", "-mode", "localjks", "-privatekey", alias,
            "-inputFile", str(source), "-outputFile", str(output), "-keystore", str(store), "-keystorepasswd", password, "-keyaliaspasswd", key_password,
            "-certpath", str(cert), "-signAlg", algorithm, "-profile", str(profile)], workspace, values, "sign", accepted=frozenset({0, 1, 2, 255}))
    finally:
        redact([workspace / "sign.out", workspace / "sign.stderr"], [password, key_password])
    if timing["exit_code"] != 0:
        raise ValueError("local-JKS signing did not complete; redacted diagnostics retained")
    bounded_file(output, 256 * 1024 * 1024)
    verification, artifacts = verify(selected, output, workspace, values, "signed-verify")
    if not verification["verified"]:
        raise ValueError("new signed HAP did not pass actual vendor cryptographic verification")
    if any(sha256_file(Path(path)) != digest for path, digest in originals.items()):
        raise ValueError("signing changed borrowed signing material")
    return {"algorithm": algorithm, "signing_identity": reference, "verification": verification, "signing_timing": timing,
            "password_handling": "operator file values forwarded only to bounded vendor argv; explicit values removed from retained sign diagnostics"}, [identity(output), *artifacts, identity(stdout), identity(stderr)]
