#!/usr/bin/env python3
"""Unit-only credential adapter; no password arguments, files or diagnostics."""

import os
from pathlib import Path
import resource
import stat
import sys


def launch(guardian_id):
    if guardian_id not in (1, 2, 3):
        raise ValueError("invalid Guardian ID")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    name = f"psy-guardian-{guardian_id}-password"
    directory = os.open(os.environ["CREDENTIALS_DIRECTORY"],
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("unsafe credential")
        password = source.read(4097)
    if not 1 <= len(password) <= 4096 or any(c in password for c in (b"\0", b"\r", b"\n")):
        raise ValueError("invalid credential")
    value = password.decode("utf-8")
    if value.startswith("\ufeff"):
        raise ValueError("invalid credential")
    release = Path(__file__).absolute().parent
    state = Path("/var/lib/psy-guardian/core-testnet-20261026") / f"guardian-{guardian_id}"
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("GUARDIAN_")}
    environment[f"GUARDIAN_{guardian_id}_KEYSTORE_PASSWORD"] = value
    argv = [str(release / "psy_relayer_cli"), "guardian-service", "--guardian-id", str(guardian_id),
            "--rpc-config", str(release / "rpc.json"), "--guardian-root", str(state)]
    for chain in ("sepolia", "bscTestnet", "baseSepolia"):
        argv.extend(["--l1-config", str(release / chain / "deployed-contracts.json")])
    os.execve(argv[0], argv, environment)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("1", "2", "3"):
            raise ValueError("invalid arguments")
        launch(int(sys.argv[1]))
    except Exception:
        raise SystemExit("Guardian credential adapter failed; details withheld") from None
