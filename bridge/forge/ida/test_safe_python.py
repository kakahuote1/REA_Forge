"""Facade producer tests with inert SDK imports; no IDA/native process starts."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


def facade():
    path = Path(__file__).with_name("safe_python.py")
    spec = importlib.util.spec_from_file_location("forge_safe_facade_test", path)
    module = importlib.util.module_from_spec(spec)
    inert = {name: types.ModuleType(name) for name in ("ida_funcs", "ida_loader", "ida_name", "idaapi", "idc")}
    with patch.dict(sys.modules, {**inert, spec.name: module}):
        spec.loader.exec_module(module)
    return module


class FacadeTests(unittest.TestCase):
    def test_write_budget_is_checked_before_calling_sdk(self):
        module = facade()
        from unittest.mock import Mock
        module.ida_loader.save_database = Mock(return_value=True)
        value = module._Facade(writes=[{"kind": "fixture"}] * 32)
        with self.assertRaisesRegex(module.SafePythonError, "write budget"):
            value.save()
        module.ida_loader.save_database.assert_not_called()

    def test_counting_and_over_budget_loops(self):
        module = facade()
        value = module.ida_python_safe_exec("result=0\nfor i in range(8):\n result+=1")
        self.assertEqual(value["result"], 8)
        self.assertEqual(value["loop_steps"], 8)
        value = module.ida_python_safe_exec("result=0\nwhile True:\n result+=1")
        self.assertFalse(value["ok"])
        self.assertIn("loop step budget", value["error"])

    def test_private_counter_and_authority_names_cannot_be_rebound(self):
        module = facade()
        for code in ("_safe_tick=str\nfor i in range(2):\n pass", "db=1\nresult=db", "range=str\nresult=0"):
            self.assertFalse(module.ida_python_safe_exec(code)["ok"])

    def test_augmented_power_and_import_reflection_are_rejected(self):
        module = facade()
        for code in ("result=2\nresult **= 100000000", "import os\nresult=0", "result=db.__class__", "result=open('x')"):
            self.assertFalse(module.ida_python_safe_exec(code)["ok"])


if __name__ == "__main__":
    unittest.main()
