import importlib.util
from pathlib import Path
import tomllib
import unittest

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("collector.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CollectorTests(unittest.TestCase):
    def test_move_only_processor(self):
        text = 'secret = "unchanged"\n' + m.TARGET + '''[[targets.services]]
id = "edge"
unit = "edge.service"
'''
        data = tomllib.loads(m.transform(text, "source"))
        self.assertEqual(data["secret"], "unchanged")
        self.assertEqual(data["targets"][0]["services"], [{"id": "edge", "unit": "edge.service"}])

    def test_add_target_without_changing_existing(self):
        text = 'secret = "unchanged"\n[[targets]]\nid = "realm-0"\nkind = "realm"\n'
        data = tomllib.loads(m.transform(text, "target"))
        self.assertEqual(data["targets"][0], {"id": "realm-0", "kind": "realm"})
        self.assertEqual(data["targets"][1]["services"], [m.SERVICE])
        self.assertEqual(data["secret"], "unchanged")

    def test_already_moved_refused(self):
        with self.assertRaises(ValueError):
            m.transform(m.TARGET, "target")


if __name__ == "__main__":
    unittest.main()
