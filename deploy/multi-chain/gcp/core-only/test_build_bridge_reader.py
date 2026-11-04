"""build_bridge_reader.sh against a stub docker; no container or Cargo runs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "build_bridge_reader.sh"
IMAGE = "sha256:02a4dd5c2ea776982084a4a856610836fc9f944203e85948fd4b475177f6b4af"
STUB = f"""#!/usr/bin/env bash
if [ "$1" = image ]; then echo {IMAGE}; exit 0; fi
printf '%s\\n' "$@" > "$STUB_LOG"
target=$(printf '%s\\n' "$@" | sed -n 's#^\\(.*\\):/build/target$#\\1#p')
mkdir -p "$target/release" && printf 'reader' > "$target/release/psy-bridge-reader"
"""


class BuildBridgeReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "psy-node"
        self.source.mkdir()
        git = lambda *args: subprocess.run(["git", "-C", str(self.source), *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        (self.source / "Cargo.toml").write_text("[workspace]\n")
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "source")
        self.commit = git("rev-parse", "HEAD")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (bin_dir / "docker").write_text(STUB)
        (bin_dir / "docker").chmod(0o755)
        (self.root / "cargo").mkdir()
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(self.root), "STUB_LOG": str(self.root / "docker.log"),
                    "READER_BUILD_CARGO_HOME": str(self.root / "cargo"), "READER_BUILD_COMMIT": self.commit}

    def run_script(self, env=None):
        return subprocess.run(["bash", str(SCRIPT), str(self.source), str(self.root / "target"), str(self.root / "out")],
                              env=env or self.env, capture_output=True, text=True, timeout=60)

    def test_builds_only_the_reader_offline_and_records_its_hash(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = (self.root / "docker.log").read_text().splitlines()
        self.assertEqual(argv[-7:], ["cargo", "build", "--release", "--locked", "--offline", "-p", "psy_bridge_reader_cli"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn(f"{self.source}:/build/source:ro", argv)
        self.assertEqual((self.root / "out/psy-bridge-reader").read_text(), "reader")
        self.assertIn("psy-bridge-reader", (self.root / "out/SHA256SUMS").read_text())

    def test_refuses_another_commit_or_a_dirty_source(self):
        result = self.run_script(dict(self.env, READER_BUILD_COMMIT="0" * 40))
        self.assertEqual(result.returncode, 1)
        self.assertIn("not at READER_BUILD_COMMIT", result.stderr)
        (self.source / "Cargo.toml").write_text("[workspace]\nchanged = true\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("uncommitted", result.stderr)
        self.assertFalse((self.root / "docker.log").exists())


if __name__ == "__main__":
    unittest.main()
