"""Format/identity/coverage tests; native engines are verified once as a group."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from system.observations import compare, scanner_summary, wire


class ObservationTests(unittest.TestCase):
    def test_exact_filetime_is_normalized_before_javascript(self):
        self.assertEqual(wire({"rows": [{"created_100ns": 134000000000000001, "pid": 1234}]}),
                         {"rows": [{"created_100ns": "134000000000000001", "pid": 1234}]})

    def test_scanner_counts_and_trailing_output_are_validated(self):
        self.assertEqual(scanner_summary('banner\n{"scanned_count":1,"failed_count":0,"suspicious_count":0}')["scanned_count"], 1)
        for value in ('{"scanned_count":true,"failed_count":0,"suspicious_count":0}',
                      '{"scanned_count":1,"failed_count":0,"suspicious_count":0} ignored'):
            with self.assertRaises(ValueError):
                scanner_summary(value)

    def test_diff_rejects_identity_change_incomplete_and_duplicate_rows(self):
        before = {"kind": "handles", "target_process": {"pid": 1234, "created_100ns": "134000000000000001"}, "complete": True, "rows": [{"handle": "0x4", "access": 1}]}
        after = {**before, "rows": [{"handle": "0x4", "access": 2}, {"handle": "0x8", "access": 1}]}
        self.assertEqual([row["change"] for row in compare(before, after)], ["changed", "added"])
        for invalid in ({**after, "complete": False}, {**after, "target_process": {"pid": 1234, "created_100ns": "134000000000000002"}}, {**after, "rows": [*after["rows"], after["rows"][0]]}):
            with self.assertRaises(ValueError):
                compare(before, invalid)


if __name__ == "__main__":
    unittest.main()
