"""Explicitly record the installed offline engine entries; never updates them."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".forge-local" / "config"
OPERATIONS = ("FromBase64", "ToBase64", "FromHex", "ToHex", "URLDecode", "URLEncode", "EncodeText", "DecodeText",
              "Gzip", "Gunzip", "ZlibDeflate", "ZlibInflate", "SHA2", "HMAC", "CRCChecksum", "XOR",
              "AESEncrypt", "AESDecrypt", "JSONBeautify", "JSONMinify")
selected = json.loads((CONFIG / "tools.json").read_text(encoding="utf-8-sig"))["cyberchef"]
engine = Path(selected["root"])
if not engine.is_absolute() or engine.is_symlink():
    raise ValueError("CyberChef requires an explicit absolute engine root")
if hashlib.sha256((engine / "package-lock.json").read_bytes()).hexdigest() != selected["package_lock_sha256"]:
    raise ValueError("CyberChef lockfile identity drifted")
names = ["src/core/Dish.mjs", "src/core/Utils.mjs"] + [f"src/core/operations/{name}.mjs" for name in OPERATIONS]
result = {name: hashlib.sha256((engine / name).read_bytes()).hexdigest() for name in names}
(CONFIG / "cyberchef-entrypoints.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"recorded_entries": len(result), "network_used": False}))
