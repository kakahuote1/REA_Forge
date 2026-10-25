"""Owned fixture tests for format admission and the shared native boundary."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from android_build.project_files import copy_tree, edits, relative, tree, validate_apk
from common.static_files import run_native


class ProjectBoundaries(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="android-boundary-", dir=Path(os.environ["REA_FORGE_DATA_ROOT"]) / "tmp"))

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_canonical_path_rejections(self):
        for name in ("../a", "a/../b", "/a", "a//b", "a/./b", "a\\b", "a:", "CON.txt", "a/COM1", "a. ", "a\x01"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                relative(name)
        self.assertEqual(relative("smali/forge/Answer.smali"), "smali/forge/Answer.smali")

    def test_copy_and_edit_preserve_borrowed_source_and_empty_directories(self):
        source = self.root / "source"
        source.mkdir()
        (source / "empty").mkdir()
        (source / "test.smali").write_text("const/16 v0, 0x2a\n", encoding="utf-8")
        observed = tree(source)
        project = self.root / "project"
        copy_tree(source, project)
        change = {"relative_path": "test.smali", "expected_sha256": observed["files"][0]["sha256"], "old_text": "0x2a", "new_text": "0x2b"}
        result = edits(project, [change], self.root)
        self.assertEqual(tree(source)["sha256"], observed["sha256"])
        self.assertNotEqual(tree(project)["sha256"], observed["sha256"])
        self.assertTrue((project / "empty").is_dir())
        self.assertNotEqual(result[0]["before_sha256"], result[0]["after_sha256"])
        with self.assertRaises(ValueError):
            edits(project, [change], self.root)

    def test_ambiguous_text_and_nontext_edits_refused(self):
        source = self.root / "project"
        source.mkdir()
        for name, text in (("a.smali", "same same"), ("a.dex", "same")):
            (source / name).write_text(text, encoding="utf-8")
        for item in tree(source)["files"]:
            with self.subTest(name=item["relative_path"]), self.assertRaises(ValueError):
                edits(source, [{**item, "expected_sha256": item["sha256"], "old_text": "same", "new_text": "changed"}], self.root)

    def test_archive_traversal_collision_and_missing_manifest_refused(self):
        for index, names in enumerate((("../a", "AndroidManifest.xml"), ("A.txt", "a.txt", "AndroidManifest.xml"), ("classes.dex",))):
            path = self.root / f"bad-{index}.apk"
            with zipfile.ZipFile(path, "w") as archive:
                for name in names:
                    archive.writestr(name, "fixture")
            with self.subTest(names=names), self.assertRaises(ValueError):
                validate_apk(path)

    def test_native_default_exit_policy_and_case_insensitive_environment_scrub(self):
        request = self.root / "request.json"
        request.write_text("{}", encoding="utf-8")
        names = ("http_proxy", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "PYTHONPATH")
        with patch.object(sys, "argv", [sys.argv[0], str(request)]), patch.dict(os.environ, {name: "must-not-reach-child" for name in names}):
            out, _, timing = run_native([sys.executable, "-I", "-c", "import os,json; print(json.dumps({key:value for key,value in os.environ.items() if key.casefold() in {'http_proxy','java_tool_options','jdk_java_options','_java_options','classpath','pythonpath'}}))"], self.root, timeout_ms=5000, prefix="env")
            self.assertEqual(json.loads(out.read_text()), {})
            self.assertEqual(timing["exit_code"], 0)
            with self.assertRaises(ValueError):
                run_native([sys.executable, "-I", "-c", "raise SystemExit(1)"], self.root, timeout_ms=5000, prefix="default")
            _, _, timing = run_native([sys.executable, "-I", "-c", "raise SystemExit(1)"], self.root, timeout_ms=5000, prefix="verify", accepted_exit_codes=frozenset({0, 1}))
            self.assertEqual(timing["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
