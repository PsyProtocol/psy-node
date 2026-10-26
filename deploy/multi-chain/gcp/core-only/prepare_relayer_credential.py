#!/usr/bin/env python3
"""Create one host-bound Relayer credential; never edits the retained env/key.

Requires Python 3.11+, root, an existing systemd host key and reviewed install_relayer.py
and install_guardian.py siblings. Source env must be root-owned mode 0600/0640.
Only simple literal shell assignments are supported; no shell evaluation occurs.
Single quotes support special characters; double/unquoted shell expansions and
escape sequences and inline comments are rejected rather than guessed. This is
literal shell-env syntax (optional export), not general systemd EnvironmentFile
parsing. Unsupported input stays intact.
Output must not exist. Only its immediate parent may be created, mode 0700.
Use --apply after approval. Do not use shell tracing or pipe plaintext elsewhere.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shlex
import stat
import subprocess


_spec = importlib.util.spec_from_file_location("relayer_install_files", Path(__file__).with_name("install_relayer.py"))
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)
HOST_KEY = Path("/var/lib/systemd/credential.secret")
ENCRYPT = Path("/usr/bin/systemd-creds")


def password_from_env(path, variable):
    r.g.require(re.fullmatch(r"[A-Z_][A-Z0-9_]*", variable), "invalid password variable")
    parent = r.g.directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        r.g.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                    and stat.S_IMODE(info.st_mode) in (0o600, 0o640), "unsafe retained env")
        raw = stream.read(1024 * 1024 + 1)
    r.g.require(len(raw) <= 1024 * 1024, "retained env too large")
    values = []
    for line in raw.decode("utf-8").split("\n"):
        match = re.fullmatch(r"\s*(?:export\s+)?" + re.escape(variable) + r"=(.*)", line)
        if match:
            r.g.require(re.fullmatch(r'''(?:'[^'\r\n]*'|"[^"\\$`\r\n]*"|[A-Za-z0-9_@%+=:.,/-]+)[ \t]*''', match[1]),
                        "unsupported password assignment")
            words = shlex.split(match[1], comments=False, posix=True)
            r.g.require(len(words) == 1, "unsupported password assignment")
            values.append(words[0])
    r.g.require(len(values) == 1, "one literal password assignment required")
    password = values[0].encode("utf-8")
    r.g.require(1 <= len(password) <= 4096 and not any(c in password for c in (b"\0", b"\r", b"\n"))
                and not values[0].startswith("\ufeff"), "invalid password")
    return password


def prepare(env_file, variable, output, apply=False):
    r.g.require(apply and os.geteuid() == 0, "credential preparation requires root and --apply")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env_file, output = r.g.path_value(str(env_file)), r.g.path_value(str(output))
    r.g.require(not os.path.lexists(output), "credential output exists; never overwrite")
    for parent in (HOST_KEY.parent, *HOST_KEY.parent.parents, ENCRYPT.parent, *ENCRYPT.parent.parents):
        r.g.trusted_directory(parent)
    key = HOST_KEY.stat(follow_symlinks=False)
    r.g.require(stat.S_ISREG(key.st_mode) and key.st_uid == 0 and stat.S_IMODE(key.st_mode) in (0o400, 0o600),
                "existing root-owned systemd host key required; no key generation")
    executable = ENCRYPT.stat(follow_symlinks=False)
    r.g.require(stat.S_ISREG(executable.st_mode) and executable.st_uid == 0
                and executable.st_mode & 0o111 and not executable.st_mode & 0o022, "unsafe systemd-creds executable")
    for parent in output.parent.parents:
        r.g.trusted_directory(parent)
    if os.path.lexists(output.parent):
        r.g.trusted_directory(output.parent, private=True)
    password = password_from_env(env_file, variable)
    result = subprocess.run([str(ENCRYPT), "encrypt", "--with-key=host", "--name=" + r.CREDENTIAL, "-", "-"],
                            input=password, capture_output=True, timeout=30,
                            env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"})
    r.g.require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, "systemd credential encryption failed")
    if not os.path.lexists(output.parent):
        r.g.mkdir(output.parent, mode=0o700)
    r.g.write(output, result.stdout)
    return {"credential_sha256": r.g.digest(result.stdout), "created": True,
            "source_modified": False, "started": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--variable", default="WALLET_PASSWORD")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(prepare(args.env_file, args.variable, args.output, args.apply), sort_keys=True))
    except Exception:
        raise SystemExit("Relayer credential preparation failed; details withheld; source unchanged") from None


if __name__ == "__main__":
    main()
