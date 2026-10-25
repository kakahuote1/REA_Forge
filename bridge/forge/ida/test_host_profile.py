"""Pure profile precedence/ownership tests; no IDA is initialized here."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ida.host_profile import plugin_inventory, prepare


class HostProfileTests(unittest.TestCase):
    def test_all_unapproved_install_plugins_are_shadowed_without_editing_originals(self):
        with tempfile.TemporaryDirectory(prefix="forge-ida-profile-") as temporary:
            root = Path(temporary)
            install, workspace = root / "install", root / "work"
            (install / "plugins").mkdir(parents=True)
            (install / "idalib/python/idapro").mkdir(parents=True)
            workspace.mkdir()
            selected = {"install_root": str(install), "approved_plugins": []}
            for key, relative in [("idalib", "idalib.dll"), ("idapro_entry", "idalib/python/idapro/__init__.py"), ("idapro_config", "idalib/python/idapro/config.py")]:
                path = install / relative
                path.write_text(key)
                selected[key] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for leaf in ("idapython3.dll", "hexx64.dll", "WPeChatGPT.py", "binexport12_ida64.dll"):
                path = install / "plugins" / leaf
                path.write_text("source-owned inert fixture")
                if leaf in {"idapython3.dll", "hexx64.dll"}:
                    selected["approved_plugins"].append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            nested = install / "plugins/feeds"
            nested.mkdir()
            (nested / "feeds_plugin.py").write_text("inert nested fixture")
            (nested / "ida-plugin.json").write_text(json.dumps({"plugin": {"name": "Feeds fixture", "entryPoint": "feeds_plugin.py"}}))
            before = {path: path.read_bytes() for path in (install / "plugins").rglob("*") if path.is_file()}
            profile = prepare(selected, workspace)
            self.assertTrue((Path(profile["ida_user"]) / "plugins/WPeChatGPT.py").is_file())
            self.assertTrue((Path(profile["ida_user"]) / "plugins/binexport12_ida64.py").is_file())
            self.assertFalse((Path(profile["ida_user"]) / "plugins/hexx64.py").exists())
            self.assertEqual(len(profile["blocked_plugins"]), 3)
            self.assertEqual(json.loads((Path(profile["ida_user"]) / "plugins/feeds/ida-plugin.json").read_text())["plugin"]["name"], "Feeds fixture")
            self.assertNotIn("inert nested fixture", (Path(profile["ida_user"]) / "plugins/feeds/feeds_plugin.py").read_text())
            exclusions = (Path(profile["ida_user"]) / "plugins/plugins.cfg").read_text()
            self.assertIn("binexport12_ida64 0 0 GUI SILENT", exclusions)
            self.assertNotEqual((Path(profile["ida_user"]) / "plugins/WPeChatGPT.py").read_text(), (Path(profile["ida_user"]) / "plugins/binexport12_ida64.py").read_text())
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)

    def test_ambiguous_same_stem_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="forge-ida-duplicate-") as temporary:
            root = Path(temporary)
            (root / "plugins").mkdir()
            (root / "plugins/duplicate.py").write_text("inert")
            (root / "plugins/duplicate.dll").write_text("inert")
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                plugin_inventory(root)

    def test_nested_descriptor_entry_is_included_and_escape_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="forge-ida-descriptor-") as temporary:
            root = Path(temporary)
            nested = root / "plugins/feeds"
            nested.mkdir(parents=True)
            entry = nested / "feeds_plugin.py"
            entry.write_text("inert")
            descriptor = nested / "ida-plugin.json"
            descriptor.write_text(json.dumps({"plugin": {"entryPoint": entry.name}}))
            self.assertEqual(plugin_inventory(root)["feeds_plugin"], entry)
            descriptor.write_text(json.dumps({"plugin": {"entryPoint": "../../outside.py"}}))
            with self.assertRaisesRegex(ValueError, "entry point"):
                plugin_inventory(root)


if __name__ == "__main__":
    unittest.main()
