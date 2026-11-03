"""Worker label rules; they must match psy_node_common::worker_whitelist."""
import unittest

import worker_labels

A = "02" + "1" * 64
B = "03" + "2" * 64


def require(condition, message):
    if not condition:
        raise ValueError(message)


class WorkerLabelTests(unittest.TestCase):
    def check(self, labels, keys=(A, B)):
        return worker_labels.check_labels({"enabled": True, "secp256k1": list(keys), "labels": labels}, require)

    def test_absent_labels_keep_the_two_field_policy(self):
        policy = {"enabled": True, "secp256k1": [A]}
        self.assertEqual(worker_labels.policy_fields(policy), ("enabled", "secp256k1"))
        self.assertEqual(worker_labels.check_labels(policy, require), {})

    def test_valid_labels_map_canonical_keys(self):
        result = self.check({"0X" + A.upper(): "c4d-coordinator", B: "x" * worker_labels.MAX_LABEL_LEN})
        self.assertEqual(result, {A: "c4d-coordinator", B: "x" * worker_labels.MAX_LABEL_LEN})
        self.assertEqual(self.check({}), {})

    def test_invalid_labels_rejected(self):
        for labels, message in (({"03" + "9" * 64: "outsider"}, "not whitelisted"),
                                ({A: ""}, "worker label must be"),
                                ({A: "has space"}, "worker label must be"),
                                ({A: "na\u00efve"}, "worker label must be"),
                                ({A: "x" * (worker_labels.MAX_LABEL_LEN + 1)}, "worker label must be"),
                                ({A: 7}, "worker label must be"),
                                ({A: "same", B: "same"}, "duplicate worker label"),
                                ({A: "a", "0x" + A: "b"}, "labelled twice"),
                                ({"not-a-key": "name"}, "invalid worker label key"),
                                ([A], "must be an object")):
            with self.subTest(labels=labels), self.assertRaisesRegex(ValueError, message):
                self.check(labels)


if __name__ == "__main__":
    unittest.main()
