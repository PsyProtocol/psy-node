import base64
import struct
import unittest
import reconcile as r


def message():
    raw = bytearray(244)
    struct.pack_into("<BQBIIIBB", raw, 0, 0, 123, 6, 32, 0, 65536, 0, 0)
    struct.pack_into("<Q", raw, 192, 65536)
    raw[64:96] = bytes(range(32))
    return {"subject": "realm_1.pq.r1.rs1.uabcd.qt20.g0", "seq": 19,
            "time": "2026-10-13T13:00:00Z", "data": base64.b64encode(raw).decode()}


class DecodeTests(unittest.TestCase):
    def test_commit_boundary(self):
        self.assertTrue(r.committed(9, 10, 11))
        self.assertFalse(r.committed(11, 10, 12))
        self.assertFalse(r.committed(11, 12, 10))
        self.assertFalse(r.committed(None, 12, 12))
        self.assertFalse(r.committed(True, 12, 12))

    def test_retention_coverage(self):
        self.assertTrue(r.retained_without_holes(dict(first_seq=1, last_seq=10, messages=10), 5))
        self.assertFalse(r.retained_without_holes(dict(first_seq=1, last_seq=10, messages=9), 5))
        self.assertFalse(r.retained_without_holes(dict(first_seq=6, last_seq=10, messages=5), 5))

    def test_decode(self):
        result = r.decode(message())
        self.assertEqual(result["user_id"], 65536)
        self.assertEqual(result["pending"], 123)
        self.assertEqual(result["new_hash"], bytes(range(31, -1, -1)).hex())

    def test_reject_other_queue(self):
        value = message()
        value["subject"] = value["subject"].replace("qt20", "qt41")
        with self.assertRaises(ValueError):
            r.decode(value)

    def test_reject_truncated(self):
        value = message()
        value["data"] = base64.b64encode(bytes(243)).decode()
        with self.assertRaises(ValueError):
            r.decode(value)

    def test_reject_disagreeing_user(self):
        value = message()
        raw = bytearray(base64.b64decode(value["data"]))
        struct.pack_into("<Q", raw, 192, 65537)
        value["data"] = base64.b64encode(raw).decode()
        with self.assertRaises(ValueError):
            r.decode(value)


if __name__ == "__main__":
    unittest.main()
