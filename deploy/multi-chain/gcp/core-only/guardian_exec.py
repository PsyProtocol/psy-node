#!/usr/bin/env python3
"""Unit-only credential adapter; no password arguments, files or diagnostics."""

import errno
import os
from pathlib import Path
import resource
import stat
import struct
import sys


def check_credential_access(fd, *, directory=False):
    info = os.fstat(fd)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    permission = 5 if directory else 4
    uid = os.geteuid()
    if not kind(info.st_mode):
        raise ValueError("unsafe credential type")
    try:
        acl = os.getxattr(fd, "system.posix_acl_access")
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.EOPNOTSUPP):
            raise
        acl = None
    if info.st_uid == uid and stat.S_IMODE(info.st_mode) == permission << 6 and acl is None:
        return
    # systemd 255 grants the service UID access through a named-user ACL.
    undefined = 0xffffffff
    expected = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perm, identifier)
        for tag, perm, identifier in (
            (1, permission, undefined), (2, permission, uid), (4, 0, undefined),
            (16, permission, undefined), (32, 0, undefined)))
    if (uid == 0 or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != (permission << 6 | permission << 3)
            or acl != expected):
        raise ValueError("unsafe credential access")


def launch(guardian_id):
    if guardian_id not in (1, 2, 3):
        raise ValueError("invalid Guardian ID")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    name = f"psy-guardian-{guardian_id}-password"
    directory = os.open(os.environ["CREDENTIALS_DIRECTORY"],
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        check_credential_access(directory, directory=True)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as source:
        check_credential_access(source.fileno())
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
