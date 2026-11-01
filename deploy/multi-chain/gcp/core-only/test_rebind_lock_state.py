import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import rebind_lock_state as m

OLD_TOOLS = {"a.py": "1" * 64, "b.py": "2" * 64}
NEW_TOOLS = {"a.py": "1" * 64, "b.py": "3" * 64}


class RebindTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.release, self.private = self.root / "release", self.root / "private"
        (self.private / "state").mkdir(parents=True)
        self.release.mkdir()
        self.previous = self.root / "previous-lock.json"
        self.old = {"release_id": "r", "paths": ["x"], "tool_sha256": OLD_TOOLS}
        self.write_locks(self.old, {**self.old, "tool_sha256": NEW_TOOLS})

    def write_locks(self, old, new):
        self.previous.write_text(json.dumps(old))
        (self.release / "release-lock.json").write_text(json.dumps(new))
        self.old_sha = hashlib.sha256(self.previous.read_bytes()).hexdigest()
        self.new_sha = hashlib.sha256((self.release / "release-lock.json").read_bytes()).hexdigest()

    def state(self, name, document):
        path = self.private / "state" / name
        path.write_text(json.dumps(document))
        return path

    def run_rebind(self, apply=True):
        return m.rebind(self.release, self.private, self.previous, apply)

    def test_tool_only_change_moves_every_state_file_bound_to_the_previous_lock(self):
        baseline = self.state("retained_baseline.json", {"lock_sha256": self.old_sha, "hosts": {"h": 1}})
        deploy = self.state("deploy_l1.json", {"lock_sha256": self.old_sha, "chains": {}})
        deploy_hash = hashlib.sha256(deploy.read_bytes()).hexdigest()
        bridge = self.state("prepare_bridge_packages.json", {"lock_sha256": self.old_sha, m.DOCUMENT_HASH: deploy_hash})
        report = self.run_rebind()
        self.assertEqual(report["rebound"], ["deploy_l1.json", "prepare_bridge_packages.json", "retained_baseline.json"])
        self.assertEqual(json.loads(baseline.read_text()), {"lock_sha256": self.new_sha, "hosts": {"h": 1}})
        self.assertEqual(json.loads(deploy.read_text())["lock_sha256"], self.new_sha)
        new_deploy_hash = hashlib.sha256(deploy.read_bytes()).hexdigest()
        self.assertEqual(json.loads(bridge.read_text())[m.DOCUMENT_HASH], new_deploy_hash)
        self.assertEqual(oct(baseline.stat().st_mode & 0o777), "0o600")

    def test_dry_run_changes_nothing(self):
        path = self.state("retained_baseline.json", {"lock_sha256": self.old_sha})
        before = path.read_bytes()
        report = self.run_rebind(apply=False)
        self.assertEqual(report["rebound"], ["retained_baseline.json"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_value_change_in_the_lock_is_refused(self):
        self.write_locks(self.old, {**self.old, "paths": ["y"], "tool_sha256": NEW_TOOLS})
        self.state("retained_baseline.json", {"lock_sha256": self.old_sha})
        with self.assertRaisesRegex(ValueError, "beyond tool_sha256: paths, tool_sha256"):
            self.run_rebind()

    def test_a_lock_with_other_tools_or_no_change_is_refused(self):
        self.write_locks(self.old, {**self.old, "tool_sha256": {**NEW_TOOLS, "c.py": "4" * 64}})
        with self.assertRaisesRegex(ValueError, "other tools"):
            self.run_rebind()
        self.write_locks(self.old, self.old)
        with self.assertRaisesRegex(ValueError, "nothing to move"):
            self.run_rebind()

    def test_files_bound_to_a_third_lock_are_left_alone_and_named(self):
        path = self.state("start_faucet.json", {"lock_sha256": "9" * 64})
        before = path.read_bytes()
        report = self.run_rebind()
        self.assertEqual(report["bound_to_other_locks"], ["start_faucet.json"])
        self.assertEqual(path.read_bytes(), before)

    def test_the_command_line_prints_names_only(self):
        self.state("retained_baseline.json", {"lock_sha256": self.old_sha})
        code = m.main(["--release-dir", str(self.release), "--private-dir", str(self.private),
                       "--previous-lock", str(self.previous), "--apply"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
