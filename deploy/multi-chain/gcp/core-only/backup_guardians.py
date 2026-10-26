#!/usr/bin/env python3
"""Back up each Guardian only to its assigned host; never start services.

Run from the deployment worktree with --guardian-id 1 (then 2 and 3).
Existing destinations, including partial backups, are refused without changes.
The public identity is checked against the provisioning records, not re-derived
from the encrypted wallet. Wallet possession was established during provisioning.
Only passwords in memory/pipes cross SSH; local host-bound credentials are never
copied. Python cannot guarantee erasure of all memory copies or prevent swapping.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import resource
import shlex
import stat
import subprocess
import sys


SOURCE = "de539f565ec1a92f91bb4e9686e1442e89ba8639"
USER_CLI_SHA256 = "a5dc1e3b4ad93af22c9843f8695fb0d25d5e155210ee43d07d287517dd92811d"
HOSTS = {1: "10.148.0.39", 2: "10.148.0.40", 3: "10.148.0.41"}
REMOTE_ROOT = Path("/var/lib/psy-guardian-custody")
DEFAULT_SOURCE = Path(".private/guardian-custody-testnet-20261026")
MAX_FILE = 65536
MAX_MESSAGE = 131072


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def guardian_name(guardian_id):
    require(type(guardian_id) is int and guardian_id in HOSTS, "invalid Guardian ID")
    return f"psy-guardian-{guardian_id}-password"


def public_commitment(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,64}", value),
            "invalid public commitment")
    number = int(value, 16)
    require(number != 0, "zero public commitment")
    return f"{number:064x}"


def decode_json(raw):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError):
        raise RuntimeError("invalid JSON input") from None


def directory(path):
    """Walk with dirfds so no ancestor or final symlink is followed."""
    path = Path(path).absolute()
    require(".." not in path.parts, "parent traversal is forbidden")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def require_directory(descriptor, mode=0o700):
    info = os.fstat(descriptor)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == mode, "unsafe custody directory")


def read_file(descriptor, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=descriptor)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600,
                "unsafe custody file")
        require(info.st_size <= MAX_FILE, "custody file exceeds size limit")
        value = source.read(MAX_FILE + 1)
        require(len(value) <= MAX_FILE, "custody file exceeds size limit")
        return value


def read_child_directory(parent, name):
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent)
    try:
        require_directory(child)
        return child
    except Exception:
        os.close(child)
        raise


def read_source(root):
    fd = directory(root)
    try:
        require_directory(fd)
        summary = decode_json(read_file(fd, "public-commitments.json"))
        require(summary.get("node_source") == SOURCE
                and summary.get("user_cli_sha256") == USER_CLI_SHA256,
                "unexpected provisioning provenance")
        commitments = summary.get("guardian_initial_member_hashes")
        require(isinstance(commitments, list) and len(commitments) == 3,
                "three public commitments required")
        commitments = [public_commitment(value) for value in commitments]
        require(len(set(commitments)) == 3, "duplicate public commitments")
        key_fd = os.dup(fd)
        try:
            for name in ("home", ".psy", "keystore"):
                child = read_child_directory(key_fd, name)
                os.close(key_fd)
                key_fd = child
            records = {}
            for guardian_id in HOSTS:
                public = decode_json(read_file(fd, f"guardian-{guardian_id}-public.json"))
                commitment = public_commitment(public.get("public_key_hash"))
                require(commitment == commitments[guardian_id - 1], "public commitment mismatch")
                key = read_file(key_fd, f"guardian-{guardian_id}.keystore.json")
                validate_keystore(key)
                records[guardian_id] = {
                    "commitment": commitment,
                    "keystore": key,
                    "keystore_sha256": hashlib.sha256(key).hexdigest(),
                    "credential": read_file(fd, guardian_name(guardian_id) + ".cred"),
                }
            require(len({row["keystore_sha256"] for row in records.values()}) == 3,
                    "duplicate Guardian keystores")
            return records
        finally:
            os.close(key_fd)
    finally:
        os.close(fd)


def validate_keystore(raw):
    key = decode_json(raw)
    require(isinstance(key, dict) and key.get("version") == 3
            and isinstance(key.get("crypto", key.get("Crypto")), dict)
            and bool(key.get("crypto", key.get("Crypto"))), "invalid encrypted keystore")


def command(argv, payload=None, timeout=60):
    # Never propagate subprocess exceptions/output: they may retain input bytes.
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                   "HOME": os.environ.get("HOME", "/root"), "LANG": "C.UTF-8"}
    for name in ("XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        if name in os.environ:
            environment[name] = os.environ[name]
    try:
        result = subprocess.run(argv, input=payload, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
                                env=environment)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("custody subprocess failed; output withheld") from None
    require(result.returncode == 0, "custody subprocess failed; output withheld")
    require(len(result.stdout) <= MAX_MESSAGE, "custody subprocess output too large")
    return result.stdout


def validate_password(password):
    require(isinstance(password, bytes) and 1 <= len(password) <= 4096,
            "invalid credential size")
    require(b"\0" not in password and b"\n" not in password and b"\r" not in password,
            "invalid credential encoding")


def acknowledgement(guardian_id, commitment, digest):
    return {"guardian_id": guardian_id, "host": HOSTS[guardian_id],
            "public_key_hash": commitment, "keystore_sha256": digest,
            "destination": str(REMOTE_ROOT / f"guardian-{guardian_id}"),
            "password_storage": "systemd system-scoped host-bound encrypted credential"}


def backup(root, guardian_id, identity, helper_source):
    name = guardian_name(guardian_id)
    record = read_source(root)[guardian_id]
    password = command(["systemd-creds", "--user", f"--name={name}", "decrypt", "-", "-"],
                       record["credential"])
    validate_password(password)
    envelope = {"version": 1, "node_source": SOURCE, "guardian_id": guardian_id,
                "host": HOSTS[guardian_id], "public_key_hash": record["commitment"],
                "keystore_sha256": record["keystore_sha256"],
                "keystore": base64.b64encode(record["keystore"]).decode("ascii"),
                "password": base64.b64encode(password).decode("ascii")}
    payload = json.dumps(envelope, separators=(",", ":")).encode("ascii")
    require(len(payload) <= MAX_MESSAGE, "custody message too large")
    remote = shlex.join(["sudo", "-n", "--", "/usr/bin/python3", "-I", "-c",
                         helper_source, "--receive", str(guardian_id)])
    reply = command(["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                     "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=15",
                     "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
                     "-J", "gcp-gateway", "-i", str(identity),
                     f"ubuntu@{HOSTS[guardian_id]}", remote], payload, timeout=180)
    expected = acknowledgement(guardian_id, record["commitment"], record["keystore_sha256"])
    require(decode_json(reply) == expected, "remote custody acknowledgement mismatch")
    return expected


def require_remote_host(guardian_id):
    require(os.geteuid() == 0, "receiver must run as root")
    interfaces = decode_json(command(["ip", "-j", "-4", "address", "show"]))
    addresses = {entry.get("local") for interface in interfaces
                 for entry in interface.get("addr_info", [])}
    require(HOSTS[guardian_id] in addresses, "wrong Guardian destination host")


def write_file(descriptor, name, value):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=descriptor)
    with os.fdopen(fd, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def receive(raw, guardian_id):
    name = guardian_name(guardian_id)
    require_remote_host(guardian_id)
    require(len(raw) <= MAX_MESSAGE, "custody message too large")
    message = decode_json(raw)
    require(set(message) == {"version", "node_source", "guardian_id", "host", "public_key_hash",
                             "keystore_sha256", "keystore", "password"}, "invalid custody message fields")
    require(type(message["version"]) is int and message["version"] == 1
            and type(message["guardian_id"]) is int
            and message["guardian_id"] == guardian_id and message["host"] == HOSTS[guardian_id]
            and message["node_source"] == SOURCE, "custody identity mismatch")
    commitment = public_commitment(message["public_key_hash"])
    try:
        key = base64.b64decode(message["keystore"], validate=True)
        password = base64.b64decode(message["password"], validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("invalid custody encoding") from None
    require(len(key) <= MAX_FILE, "keystore too large")
    validate_keystore(key)
    validate_password(password)
    digest = hashlib.sha256(key).hexdigest()
    require(message["keystore_sha256"] == digest, "keystore checksum mismatch")

    parent = directory(REMOTE_ROOT.parent)
    try:
        info = os.fstat(parent)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0,
                "unsafe backup parent")
        try:
            os.mkdir(REMOTE_ROOT.name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        root = read_child_directory(parent, REMOTE_ROOT.name)
        os.fsync(parent)
    finally:
        os.close(parent)
    try:
        target = f"guardian-{guardian_id}"
        try:
            os.stat(target, dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("backup already exists; refusing overwrite or silent resume")
        encrypted = command(["systemd-creds", "--with-key=host", f"--name={name}",
                             "encrypt", "-", "-"], password)
        require(0 < len(encrypted) <= MAX_FILE, "invalid encrypted credential size")
        recovered = command(["systemd-creds", f"--name={name}", "decrypt", "-", "-"], encrypted)
        require(hmac.compare_digest(recovered, password), "remote credential round-trip mismatch")

        # Atomic reservation prevents concurrent overwrites. Failures retain a
        # partial directory for operator inspection; they never delete custody.
        os.mkdir(target, 0o700, dir_fd=root)
        target_fd = read_child_directory(root, target)
        try:
            write_file(target_fd, f"guardian-{guardian_id}.keystore.json", key)
            write_file(target_fd, name + ".cred", encrypted)
            result = acknowledgement(guardian_id, commitment, digest)
            public = dict(result, node_source=SOURCE)
            write_file(target_fd, "public.json", json.dumps(public, sort_keys=True).encode("ascii") + b"\n")
            os.fsync(target_fd)
            require(hashlib.sha256(read_file(target_fd, f"guardian-{guardian_id}.keystore.json")).hexdigest() == digest,
                    "saved keystore checksum mismatch")
            require(decode_json(read_file(target_fd, "public.json")) == public,
                    "saved public commitment mismatch")
            saved_credential = read_file(target_fd, name + ".cred")
            require(saved_credential == encrypted, "saved credential mismatch")
        finally:
            os.close(target_fd)
        os.fsync(root)
        return result
    finally:
        os.close(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--guardian-id", type=int, choices=HOSTS)
    parser.add_argument("--receive", type=int, choices=HOSTS, help=argparse.SUPPRESS)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    try:
        if args.receive is not None:
            require(args.guardian_id is None, "conflicting Guardian modes")
            result = receive(sys.stdin.buffer.read(MAX_MESSAGE + 1), args.receive)
        else:
            require(args.guardian_id is not None, "--guardian-id is required")
            result = backup(args.source, args.guardian_id,
                            Path.home() / ".ssh/id_bridge_google", Path(__file__).read_text())
        print(json.dumps(result, sort_keys=True))
    except Exception:
        # No exception text, subprocess output, payload or traceback may escape.
        raise SystemExit("Guardian backup failed; output withheld. Existing custody was not overwritten; inspect any partial destination.") from None


if __name__ == "__main__":
    main()
