#!/usr/bin/env python3
"""Isolated Docker bind-remount experiment; never touches nostr-caddy lifecycle."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def run(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def main():
    os.umask(0o077)
    image = run("docker", "inspect", "nostr-caddy", "--format", "{{.Image}}")
    name = "realm1-bind-test-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="realm1-bind-test-") as directory:
        source = Path(directory) / "config"
        source.write_text("before")
        created = False
        try:
            run("docker", "create", "--name", name, "--network", "none", "--read-only",
                "--memory", "32m", "--pids-limit", "16", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sleep",
                "--mount", f"type=bind,source={source},target=/test-config,readonly",
                image, "120")
            created = True
            run("docker", "start", name)
            before = run("docker", "exec", name, "cat", "/test-config")
            candidate = Path(directory) / "candidate"
            candidate.write_text("after")
            os.replace(candidate, source)
            old_mount = run("docker", "exec", name, "cat", "/test-config")
            run("docker", "restart", "--time", "1", name)
            restarted = run("docker", "exec", name, "cat", "/test-config")
            if (before, old_mount, restarted) != ("before", "before", "after"):
                raise RuntimeError("unexpected bind-mount behavior")
            print(json.dumps(dict(isolated_bind_restart_test=True, original_inode_until_restart=True,
                                  new_inode_after_restart=True, production_restarted=False)))
        finally:
            if created:
                run("docker", "rm", "-f", name)


if __name__ == "__main__":
    main()
