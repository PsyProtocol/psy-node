#!/usr/bin/env python3
"""Create three local Guardian keystores without logging or persisting passwords in plaintext."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import stat
import subprocess
import termios
import time


SOURCE = "de539f565ec1a92f91bb4e9686e1442e89ba8639"
USER_CLI_SHA256 = "a5dc1e3b4ad93af22c9843f8695fb0d25d5e155210ee43d07d287517dd92811d"


def reject_symlink_components(path):
    for component in [*reversed(path.parents), path]:
        if component.is_symlink():
            raise RuntimeError("symlink in custody or executable path")


def create_wallet(binary, home, keystore, result, password):
    master, slave = pty.openpty()
    attributes = termios.tcgetattr(slave)
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attributes)

    def terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}
    process = None
    try:
        process = subprocess.Popen(
            [str(binary), "wallet", "create", "--output", str(keystore),
             "--result-file", str(result)],
            stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal,
            env=environment, cwd=home,
        )
        os.close(slave)
        slave = None
        output = b""
        sent = False
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                output = (output + chunk)[-16384:]
                if not sent and b"Enter password for wallet:" in output:
                    os.write(master, password + b"\n")
                    sent = True
            if process.poll() is not None:
                break
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError("wallet creation timed out; retained custody must be inspected")
        if process.returncode != 0 or not sent:
            raise RuntimeError("wallet creation failed; output withheld to protect custody")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        if slave is not None:
            os.close(slave)


def provision(binary, root):
    reject_symlink_components(binary)
    reject_symlink_components(root)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != USER_CLI_SHA256:
        raise RuntimeError("unexpected User CLI binary")
    if root.exists():
        raise RuntimeError("custody directory exists; refusing overwrite or silent resume")
    if not root.parent.is_dir():
        raise RuntimeError("custody parent must already exist")
    os.umask(0o077)
    root.mkdir(mode=0o700)
    keystores = root / "home" / ".psy" / "keystore"
    keystores.mkdir(mode=0o700, parents=True)
    commitments = []
    for guardian_id in (1, 2, 3):
        name = f"psy-guardian-{guardian_id}-password"
        encrypted = root / f"{name}.cred"
        password = secrets.token_urlsafe(48).encode("ascii")
        subprocess.run(
            ["systemd-creds", "--user", "--with-key=host", f"--name={name}",
             "encrypt", "-", str(encrypted)],
            input=password, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True,
        )
        recovered = subprocess.run(
            ["systemd-creds", "--user", f"--name={name}", "decrypt", str(encrypted), "-"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
        if recovered != password:
            raise RuntimeError("encrypted password round-trip mismatch")
        key = keystores / f"guardian-{guardian_id}.keystore.json"
        result = root / f"guardian-{guardian_id}-public.json"
        create_wallet(binary, root / "home", key, result, password)
        metadata = key.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError("unsafe keystore ownership or mode")
        public = json.loads(result.read_text())
        commitment = public.get("public_key_hash", "")
        if not isinstance(commitment, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,64}", commitment) or int(commitment, 16) == 0:
            raise RuntimeError("invalid public commitment")
        if any(int(previous, 16) == int(commitment, 16) for previous in commitments):
            raise RuntimeError("duplicate public commitment")
        commitments.append(commitment)
        print(f"Guardian {guardian_id}: encrypted keystore and host-bound password saved", flush=True)
    summary = {"node_source": SOURCE, "user_cli_sha256": USER_CLI_SHA256,
               "guardian_initial_member_hashes": commitments,
               "password_storage": "systemd user-scoped host-bound encrypted credentials"}
    with (root / "public-commitments.json").open("x") as output:
        json.dump(summary, output, indent=2)
        output.write("\n")
    print("Public commitments ready; no cloud changes or Genesis generated")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        provision(args.binary.absolute(), args.root.absolute())
    except subprocess.CalledProcessError:
        raise SystemExit("Credential operation failed; retained custody must be inspected, not overwritten")


if __name__ == "__main__":
    main()
