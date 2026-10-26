#!/usr/bin/env python3
"""Unit-only L1 password adapter; no keys/passwords in arguments or diagnostics."""

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


def launch():
    if len(sys.argv) != 1:
        raise ValueError("unexpected launcher arguments")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    directory = os.open(os.environ["CREDENTIALS_DIRECTORY"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        check_credential_access(directory, directory=True)
        fd = os.open("psy-core-relayer-l1-password", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as stream:
        check_credential_access(stream.fileno())
        password = stream.read(4097)
    if not 1 <= len(password) <= 4096 or any(value in password for value in (b"\0", b"\r", b"\n")):
        raise ValueError("invalid credential")
    value = password.decode("utf-8")
    if value.startswith("\ufeff"):
        raise ValueError("invalid credential")
    release = Path(__file__).absolute().parent
    environment = {"PATH": "/usr/bin:/usr/sbin", "HOME": str(release / "home"), "PSY_NETWORK": "testnet",
                   "PSY_CONFIG_PATH": str(release / "canonical.json"),
                   "PSY_DEPLOYMENTS_DIR": str(release / "deployments"),
                   "RUST_LOG": "info", "RUST_MIN_STACK": "134217728",
                   "PSY_CORE_RELAYER_L1_PASSWORD": value}
    argv = [str(release / "psy_relayer_cli"), "--config", str(release / "daemon.toml")]
    for name in ("sepolia", "bscTestnet", "baseSepolia"):
        argv.extend(["--l1-config", str(release / "deployments" / name / "deployed-contracts.json")])
    os.execve(argv[0], argv, environment)


if __name__ == "__main__":
    try:
        launch()
    except Exception:
        raise SystemExit("Relayer credential adapter failed; details withheld") from None
