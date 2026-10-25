"""Pure Harmony format/output boundaries; engines are exercised once as a group."""
import io
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harmony.archive import abc_header, inspect_archive, relative
from harmony.engines import abc
from harmony.signing import redact
from harmony.worker import delivery


class HarmonyBoundaries(unittest.TestCase):
    def test_engine_facet_is_owned_by_analysis_not_a_duplicate_top_level_value(self):
        engine = {"jar": {"sha256": "a" * 64}, "binary_build_commit": "unknown"}
        self.assertEqual(delivery({"analysis": {"engine": engine}}, {"facet": "engine"})["value"], engine)

    def test_windows_archive_paths_and_collision_rejection(self):
        for path in ("../escape", "/absolute", "a\\b", "CON", "a/./b", "a/b.", "a/x:stream", "a//b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                relative(path)
        with tempfile.TemporaryDirectory(prefix="harmony-archive-") as temporary:
            root = Path(temporary)
            package = root / "input.hap"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("A.txt", "one")
                archive.writestr("a.txt", "two")
            with self.assertRaisesRegex(ValueError, "colliding"):
                inspect_archive(package, root / "output")
            self.assertFalse((root / "output").exists())

    def test_symlinks_are_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory(prefix="harmony-link-") as temporary:
            root = Path(temporary)
            package = root / "input.hap"
            with zipfile.ZipFile(package, "w") as archive:
                link = zipfile.ZipInfo("link")
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "outside")
            with self.assertRaisesRegex(ValueError, "nonordinary"):
                inspect_archive(package, root / "output")

    def test_package_occurrences_and_metadata_do_not_become_source_claims(self):
        with tempfile.TemporaryDirectory(prefix="harmony-members-") as temporary:
            root = Path(temporary)
            package = root / "input.hap"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("module.json", '{"module":{"name":"entry"}}')
                archive.writestr("entry/ets/modules.abc", b"not real ABC")
                archive.writestr("entry/resources/a.txt", "same bytes")
                archive.writestr("entry/resources/b.txt", "same bytes")
            result = inspect_archive(package, root / "output")
            self.assertEqual(result["entry_count"], 4)
            self.assertEqual(result["metadata"][0]["declared_module_name"], "entry")
            self.assertEqual(len(result["abc"]), 1)
            self.assertEqual(len(result["resources"]), 2)
            self.assertEqual(result["resources"][0]["sha256"], result["resources"][1]["sha256"])

    def test_abc_header_extent_is_checked_without_executing_bytecode(self):
        with tempfile.TemporaryDirectory(prefix="harmony-header-") as temporary:
            source = Path(temporary) / "input.abc"
            header = bytearray(64)
            header[:8] = b"PANDA\0\0\0"
            header[12:16] = bytes([13, 0, 1, 0])
            struct.pack_into("<I", header, 16, len(header))
            struct.pack_into("<II", header, 28, 1, 60)
            source.write_bytes(header)
            self.assertEqual(abc_header(source)["class_count"], 1)
            struct.pack_into("<I", header, 32, 63)
            source.write_bytes(header)
            with self.assertRaisesRegex(ValueError, "class-index"):
                abc_header(source)

    def test_restool_v2_refuses_before_any_native_command(self):
        with tempfile.TemporaryDirectory(prefix="harmony-index-") as temporary:
            source = Path(temporary) / "resources.index"
            source.write_bytes(b"RestoolV2" + b"\0" * 100)
            with patch("harmony.engines.native") as run, self.assertRaisesRegex(ValueError, "RestoolV2"):
                abc({}, source, Path(temporary), {}, "resources")
            run.assert_not_called()

    def test_only_explicit_password_values_are_removed_from_diagnostics(self):
        with tempfile.TemporaryDirectory(prefix="harmony-redact-") as temporary:
            output = Path(temporary) / "sign.stderr"
            output.write_bytes(b"public profile label; secret-test-password")
            redact([output, Path(temporary) / "absent"], ["secret-test-password"])
            self.assertEqual(output.read_bytes(), b"public profile label; <redacted>")


if __name__ == "__main__":
    unittest.main()
