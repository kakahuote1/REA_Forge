"""Pure parser-boundary regressions; real engines are exercised as one group."""
import math
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pe.dependencies import _normal_dll, _manifest_snapshot, resolve_dependencies
from pe.structure import _entropy


class PeBoundaries(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="pe-boundary-", dir=Path(os.environ["REA_FORGE_DATA_ROOT"]) / "tmp"))

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_entropy_known_vectors(self):
        self.assertEqual(_entropy(b""), 0)
        self.assertEqual(_entropy(b"A" * 100), 0)
        self.assertTrue(math.isclose(_entropy(bytes(range(256)) * 100), 8))

    def test_dependency_names_do_not_become_paths(self):
        self.assertEqual(_normal_dll("KERNEL32"), "kernel32.dll")
        for raw in ("../secret", "C:\\secret", "a/b", "a\\b", "x:", "a*", "a?", "bad\x00", "x. "):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                _normal_dll(raw)

    def test_manifest_documents_preserve_unicode_and_refuse_dtd(self):
        source = self.root / "not-a-pe.exe"
        source.write_bytes(b"not a PE")
        sidecar = self.root / "not-a-pe.exe.manifest"
        sidecar.write_bytes('<?xml version="1.0" encoding="utf-16"?><assembly><assemblyIdentity name="fixture.library" version="1.0.0.0"/></assembly>'.encode("utf-16"))
        documents, identities = _manifest_snapshot(source)
        self.assertEqual(identities[0]["name"], "fixture.library")
        self.assertIn("sha256", documents[0])
        sidecar.write_bytes(b'<!DOCTYPE a [<!ENTITY x "fixture">]><assembly><assemblyIdentity name="&x;"/></assembly>')
        documents, identities = _manifest_snapshot(source)
        self.assertEqual(identities, [])
        self.assertEqual(documents[0]["parse_error"], "xml_parse_error")

    def test_depth_boundary_is_not_exhaustive_or_a_cycle_claim(self):
        source = self.root / "fixture.exe"
        source.write_bytes(b"owned fixture")
        node = {"path": str(source), "imports": [{"dll": "fixture.dll"}], "forwarders": []}
        with patch("pe.dependencies.api_set_snapshot", return_value=({}, {"available": False})), patch("pe.dependencies.known_dll_snapshot", return_value=({}, {"available": False})), patch("pe.dependencies._node", return_value=node):
            value = resolve_dependencies(source, [], max_depth=0)
        self.assertTrue(value["truncated"])
        self.assertIn("max_depth", value["truncation_reasons"])
        self.assertNotIn("cycles", value)
        self.assertEqual(value["previously_examined_edges"], [])


if __name__ == "__main__":
    unittest.main()
