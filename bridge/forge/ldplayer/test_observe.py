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
        row = observe.parse_row("2,我的雷电,练习机,0,0,0,327,412,1280,720,240")
        self.assertEqual(row["name"], "我的雷电,练习机")
        self.assertFalse(row["androidStarted"])
        self.assertEqual(row["runtime"]["playerPid"], 327)
        self.assertEqual(row["runtime"]["vmPid"], 412)
        self.assertEqual(row["display"], {"width": 1280, "height": 720, "dpi": 240})

    def test_real_stopped_ten_column_shape_never_uses_resolution_as_pids(self):
        row = observe.parse_row("2,recore-p6-recovery-4a51363c5e,0,0,0,-1,-1,1280,720,240")
        self.assertEqual(row["name"], "recore-p6-recovery-4a51363c5e")
        self.assertEqual(row["runtime"], {"playerPid": None, "vmPid": None})
        self.assertFalse(row["androidStarted"])
        running = observe.parse_row("2,雷电,1048,2048,1,327,412,1280,720,240")
        self.assertTrue(running["androidStarted"])
        self.assertEqual(running["runtime"], {"playerPid": 327, "vmPid": 412})

    def test_unknown_list_shape_is_not_silently_admitted(self):
        for row in ("2,bad,0", "2,old-seven-columns,0,0,0,-1,-1", "2,,0,0,0,0,0,1280,720,240", "2,bad\x01,0,0,0,0,0,1280,720,240", "2,unknown-state,0,0,2,-1,-1,1280,720,240"):
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
                first = observe.observe_instance(root, observe.parse_row("2,old,0,0,0,0,0,1280,720,240"))
                renamed = observe.observe_instance(root, observe.parse_row("2,renamed,0,0,0,0,0,1280,720,240"))
                self.assertEqual(first["physicalGeneration"], renamed["physicalGeneration"])
                previous = instance / "retained-original.vmdk"
                disk.rename(previous)
                disk.write_bytes(b"replacement fixture")
                replaced = observe.observe_instance(root, observe.parse_row("2,renamed,0,0,0,0,0,1280,720,240"))
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
                observe.observe_instance(root, observe.parse_row("2,test,0,0,0,0,0,1280,720,240"))
            descriptor.write_text('<!DOCTYPE test><VirtualBox/>', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DTD"):
                observe.observe_instance(root, observe.parse_row("2,test,0,0,0,0,0,1280,720,240"))


if __name__ == "__main__":
    unittest.main()
