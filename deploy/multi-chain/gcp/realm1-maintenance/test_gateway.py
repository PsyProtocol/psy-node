import io
import json
import unittest
from unittest.mock import Mock, patch
import gateway as g


class GateTests(unittest.TestCase):
    def call(self, replies):
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps(replies).encode())
        with patch.object(g.urllib.request, "build_opener", return_value=opener):
            g.gate_check()

    def test_both_denied_and_query_passes(self):
        self.call([{"id": 3, "error": {"code": -32098}}, {"id": 1, "result": 100},
                   {"id": 2, "error": {"code": -32098}}])

    def test_wrong_error_is_not_closed(self):
        with self.assertRaises(RuntimeError):
            self.call([{"id": 1, "result": 100}, {"id": 2, "error": {"code": -32602}},
                       {"id": 3, "error": {"code": -32098}}])

    def test_failed_query_is_not_healthy(self):
        with self.assertRaises(RuntimeError):
            self.call([{"id": 1, "error": {"code": -32001}}, {"id": 2, "error": {"code": -32098}},
                       {"id": 3, "error": {"code": -32098}}])


if __name__ == "__main__":
    unittest.main()
