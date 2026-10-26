"""Request construction only; no engine, socket or process starts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from yakit.protocol import request_arguments


class ProtocolTests(unittest.TestCase):
    def values(self, **changes):
        return {"url": "http://127.0.0.1:8080/test?a=1&a=2", "method": "POST", "headers": [], "body": "中文 {{file(/not/read)}}", "request_timeout_seconds": 5, **changes}

    def test_single_literal_request_preserves_utf8_size_and_duplicate_query_values(self):
        selected = self.values()
        result = request_arguments(selected)
        self.assertEqual(result["actualAddr"], "127.0.0.1:8080")
        self.assertIn("/test?a=1&a=2 HTTP/1.1", result["request"])
        self.assertIn("Content-Length: " + str(len(selected["body"].encode())), result["request"])
        self.assertTrue(result["request"].endswith(selected["body"]))
        self.assertEqual(result["fuzzTagMode"], "close")
        self.assertEqual(result["concurrent"], 1)
        self.assertNotIn("repeatTimes", result)
        self.assertTrue(result["request"].startswith("POST "))
        self.assertTrue(result["noSystemProxy"] and result["noFollowRedirect"])

    def test_ipv6_and_https_defaults_are_explicit(self):
        result = request_arguments(self.values(url="https://[::1]/"))
        self.assertEqual(result["actualAddr"], "[::1]:443")
        self.assertTrue(result["isHttps"])

    def test_authority_line_injection_and_unbounded_wire_are_refused(self):
        for values in [self.values(url="http://user:password@127.0.0.1/"), self.values(url="http://127.0.0.1/x#fragment"), self.values(url="http://127.0.0.1/\nHost:evil"), self.values(headers=[{"name": "Host", "value": "other"}]), self.values(headers=[{"name": "X-Test", "value": "a\r\nb"}]), self.values(headers=[{"name": "X-Test", "value": "x" * 8192}] * 40)]:
            with self.assertRaises(ValueError):
                request_arguments(values)


if __name__ == "__main__":
    unittest.main()
