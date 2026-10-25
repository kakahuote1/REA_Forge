"""Explicit configuration ownership does not exempt target reads or Codex paths."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.static_files import read_json, read_operator_configuration
from common.hard_deny_policy import PolicyViolation


class ConfigurationTests(unittest.TestCase):
    def test_only_configuration_owner_reads_the_private_config_root(self):
        with tempfile.TemporaryDirectory(prefix="forge-config-owner-") as temporary:
            root = Path(temporary)
            path = root / "config/tools.json"
            path.parent.mkdir()
            path.write_text('{"ida_host":{"version":"fixture"}}')
            with patch("common.paths.CONFIG_PATH", path), patch("common.hard_deny_policy.PRIVATE_ROOT", root):
                with self.assertRaises(PolicyViolation):
                    read_json(path)
                self.assertEqual(read_operator_configuration()["ida_host"]["version"], "fixture")
                path.write_text('{"repeated":1,"repeated":2}')
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    read_operator_configuration()
                path.write_bytes(b" " * 65537)
                with self.assertRaisesRegex(ValueError, "bound"):
                    read_operator_configuration()

    def test_operator_selection_cannot_exempt_actual_codex_configuration(self):
        with patch("common.paths.CONFIG_PATH", Path.home() / ".codex/nonexistent-fixture.json"):
            with self.assertRaises(PolicyViolation):
                read_operator_configuration()


if __name__ == "__main__":
    unittest.main()
