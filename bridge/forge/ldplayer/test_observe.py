"""Pure observation boundaries. No emulator, ADB or management commands."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("forge_ld_observe", Path(__file__).with_name("observe.py"))
observe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observe)


class ObservationBoundaries(unittest.TestCase):
    def test_display_name_commas_and_nonready_states_are_facts(self):
        row = observe.parse_row("2,我的雷电,练习机,0,0,-1,327,412")
        self.assertEqual(row["name"], "我的雷电,练习机")
        self.assertFalse(row["androidStarted"])
        self.assertEqual(row["runtime"]["playerPid"], 327)

    def test_unknown_list_shape_is_not_silently_admitted(self):
        for row in ("2,bad,0", "2,,0,0,0,0,0", "2,bad\x01,0,0,0,0,0"):
            with self.assertRaises(ValueError):
                observe.parse_row(row)

    def test_generation_uses_physical_anchor_not_display_name(self):
        with tempfile.TemporaryDirectory(prefix="forge-ld-identity-") as selected:
            root = Path(selected)
            instance = root / "vms" / "leidian2"
            instance.mkdir(parents=True)
            descriptor = instance / "leidian.vbox"
            descriptor.write_text('<VirtualBox xmlns="urn:test"><Machine uuid="{20160302-aaaa-aaaa-31e2-000000000002}"><MediaRegistry><HardDisks><HardDisk type="Normal" location="data.vmdk"/></HardDisks></MediaRegistry></Machine></VirtualBox>', encoding="utf-8")
            disk = instance / "data.vmdk"
            disk.write_bytes(b"owned inert fixture")
            with patch.object(observe, "process_start", return_value=None):
                first = observe.observe_instance(root, observe.parse_row("2,old,0,0,0,0,0"))
                renamed = observe.observe_instance(root, observe.parse_row("2,renamed,0,0,0,0,0"))
                self.assertEqual(first["physicalGeneration"], renamed["physicalGeneration"])
                previous = instance / "retained-original.vmdk"
                disk.rename(previous)
                disk.write_bytes(b"replacement fixture")
                replaced = observe.observe_instance(root, observe.parse_row("2,renamed,0,0,0,0,0"))
                self.assertNotEqual(first["physicalGeneration"], replaced["physicalGeneration"])

    def test_external_writable_disk_and_dtd_are_refused(self):
        with tempfile.TemporaryDirectory(prefix="forge-ld-external-") as selected:
            root = Path(selected)
            instance = root / "vms" / "leidian2"
            instance.mkdir(parents=True)
            outside = root / "outside.vmdk"
            outside.write_bytes(b"not owned")
            descriptor = instance / "leidian.vbox"
            descriptor.write_text('<VirtualBox><Machine uuid="{20160302-aaaa-aaaa-31e2-000000000002}"><MediaRegistry><HardDisks><HardDisk type="Normal" location="../../outside.vmdk"/></HardDisks></MediaRegistry></Machine></VirtualBox>', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escaped"):
                observe.observe_instance(root, observe.parse_row("2,test,0,0,0,0,0"))
            descriptor.write_text('<!DOCTYPE test><VirtualBox/>', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DTD"):
                observe.observe_instance(root, observe.parse_row("2,test,0,0,0,0,0"))


if __name__ == "__main__":
    unittest.main()
