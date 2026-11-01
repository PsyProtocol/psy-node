#!/usr/bin/env python3
"""SSH layer and shared step types for the release orchestrator; standard library plus release_lock."""
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
import json
import re
import shlex
import subprocess
import time

import release_lock


CONNECT_TIMEOUT_SECONDS = 15
COPY_TIMEOUT_SECONDS = 600
ERROR_TAIL_CHARS = 400
MAX_POLL_SECONDS = 30
MAX_READ_BYTES = 4 * 1024 * 1024
ROOT_KILL_AFTER_SECONDS = 30
ROOT_LOCAL_MARGIN_SECONDS = 15
ROOT_LIMIT_EXIT_CODES = (124, 137)
CONNECTION_EXIT_CODE = 255
SUDO_MODES = ("passwordless", "operator")
HERE_DOCUMENT_MARKER = "PSY_ROOT_STDIN_END"
# Broad pattern for free-form text where a false positive only hides a line.
SECRET_TEXT = re.compile(r"private|secret|passw|passphrase|token|mnemonic|credential|cookie", re.IGNORECASE)
USERINFO_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s@]*@")
PEM_HEADER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
NAMED_VALUE = re.compile(r"""(?<![A-Za-z0-9_-])-*([A-Za-z][A-Za-z0-9_-]*)["']?\s*[=:]\s*\S""")
SAFE_LAST_WORDS = frozenset(("sha256", "hash", "digest", "fingerprint", "address", "addresses", "id", "ids", "count",
                             "symbol", "decimals", "ip", "opened", "mode"))
SECRET_WORDS = frozenset(("password", "passwd", "secret", "secrets", "mnemonic", "cookie", "credential",
                          "credentials", "privatekey", "privatekeys", "passphrase"))
PATH_FLAG_WORDS = frozenset(("path", "file", "env"))
TOKEN_PREFIX_WORDS = frozenset(("api", "auth", "access", "bearer", "jwt", "refresh", "session"))


class RemoteError(RuntimeError):
    """A remote command or copy failed; the message carries the host, never the raw output."""

    def __init__(self, message, host=None, exit_code=None):
        super().__init__(message)
        self.host, self.exit_code = host, exit_code


class RemoteConnectionError(RemoteError):
    """ssh itself failed (exit 255): the host was not reached or the connection dropped."""


class ResultRefused(ValueError):
    """A step result was refused; the message names a location, never a value."""


def looks_secret(text):
    return bool(SECRET_TEXT.search(text) or USERINFO_URL.search(text))


def redact_tail(text, limit=ERROR_TAIL_CHARS):
    lines = ["[redacted line]" if looks_secret(line) else line for line in str(text).splitlines()]
    return "\n".join(lines)[-limit:].strip()


def key_words(key):
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key)))
    return [word for word in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if word]


def secret_name(name):
    """Word classifier shared by result keys, NAME=value text and command flags."""
    words = key_words(name)
    if not words or words[-1] in SAFE_LAST_WORDS:
        return False
    if SECRET_WORDS.intersection(words) or any(
            pair[0] == "private" and pair[1] in ("key", "keys") for pair in zip(words, words[1:])):
        return True
    return "token" in words and (words == ["token"] or any(
        before in TOKEN_PREFIX_WORDS and after == "token" for before, after in zip(words, words[1:])))


def secret_text(text):
    if USERINFO_URL.search(text) or PEM_HEADER.search(text):
        return True
    return any(secret_name(match.group(1)) for match in NAMED_VALUE.finditer(text))


def find_secret(value, path=""):
    """Return the location of the first secret-looking key or value, or None; never returns the value.

    Step results must never contain raw RPC URLs: a key inside a URL path cannot be pattern-detected.
    """
    if isinstance(value, Mapping):
        for key, child in value.items():
            if secret_text(str(key)):
                return f"{path}.<unsafe key>" if path else "<unsafe key>"
            where = f"{path}.{key}" if path else str(key)
            if not isinstance(child, (bool, type(None))) and secret_name(key):
                return where
            found = find_secret(child, where)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found = find_secret(child, f"{path}[{index}]")
            if found:
                return found
    elif isinstance(value, str) and secret_text(value):
        return f"{path or '<root>'} (secret-looking text)"
    return None


def command_secret(command):
    """True when a command line carries a secret flag, NAME=value or URL userinfo; paths are ignored.

    A flag is judged by its name only: a bare flag such as --start-private has no value to leak.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return True
    for index, token in enumerate(tokens):
        if USERINFO_URL.search(token):
            return True
        if token.startswith("/") or not (token.startswith("--") or "=" in token):
            continue
        name, equals, value = token.lstrip("-").partition("=")
        if not equals and token.startswith("--") and index + 1 < len(tokens):
            value = tokens[index + 1]
        if name and secret_name(name) and not (key_words(name)[-1] in PATH_FLAG_WORDS and value.startswith("/")):
            return True
    return False


class OperatorPending(Exception):
    """A step needs an operator to run a printed command on a host without passwordless sudo."""

    def __init__(self, host, command, result_path):
        if command_secret(command):
            raise ValueError("operator command must carry hashes only, not a secret")
        super().__init__(f"operator action pending on {host}")
        self.host, self.command, self.result_path = host, command, result_path


@dataclass(frozen=True)
class DeployContext:
    lock: Mapping
    lock_sha256: str
    release_dir: Path
    run_dir: Path
    remote: "Remote"
    private_dir: Path
    state_dir: Path


@dataclass(frozen=True)
class Step:
    name: str
    check: Callable[[DeployContext], None]
    apply: Callable[[DeployContext], None]
    verify: Callable[[DeployContext], dict]
    requires_complete: bool = True
    cutover: bool = False


def wait_until(is_ready, read_failure, poll_seconds, timeout_seconds, label):
    if not (isinstance(poll_seconds, int) and 1 <= poll_seconds <= MAX_POLL_SECONDS):
        raise ValueError(f"poll_seconds must be 1..{MAX_POLL_SECONDS}")
    deadline = time.monotonic() + timeout_seconds
    while True:
        failure = read_failure()
        if failure:
            raise RuntimeError(f"{label}: failed while waiting: {redact_tail(failure)}")
        if is_ready():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{label}: not ready after {timeout_seconds}s")
        time.sleep(min(poll_seconds, remaining))


class Remote:
    def __init__(self, access, lock, runner=subprocess.run, *, topology_hosts=None):
        self._hosts = self._read_access(access)
        self._known_hosts = access["known_hosts"]
        self._runner = runner
        self._check_jump_targets(lock["hosts"], topology_hosts or {})

    @staticmethod
    def _read_access(access):
        if not isinstance(access, Mapping) or not isinstance(access.get("hosts"), Mapping):
            raise ValueError("access file needs a hosts object")
        if not isinstance(access.get("known_hosts"), str) or not access["known_hosts"]:
            raise ValueError("access file needs known_hosts")
        hosts = access["hosts"]
        for alias, host_access in hosts.items():
            for field in ("ssh", "identity"):
                if not isinstance(host_access.get(field), str) or not host_access[field]:
                    raise ValueError(f"access host {alias}: {field} must be a non-empty string")
            if not Path(host_access["identity"]).expanduser().is_file():
                raise ValueError(f"access host {alias}: identity file not found")
            if host_access.get("sudo") not in SUDO_MODES:
                raise ValueError(f"access host {alias}: sudo must be one of {SUDO_MODES}")
            if "jump" not in host_access:
                raise ValueError(f"access host {alias}: jump is required (null for a direct host)")
            jump = host_access["jump"]
            if jump is not None and (jump not in hosts or hosts[jump].get("jump") is not None):
                raise ValueError(f"access host {alias}: jump must name a direct host in the access file")
        return hosts

    def _check_jump_targets(self, lock_hosts, topology_hosts):
        for alias, host_access in self._hosts.items():
            if host_access["jump"] is None:
                continue
            expected = lock_hosts.get(alias, topology_hosts.get(alias))
            if expected is None or host_access["ssh"].rsplit("@", 1)[-1] != expected:
                raise ValueError(f"access host {alias}: target differs from the release address")

    def ssh_config(self):
        """OpenSSH config text for every access-file host, for tools that ssh by alias."""
        blocks = []
        for alias in sorted(self._hosts):
            host_access = self._hosts[alias]
            user, _, address = host_access["ssh"].rpartition("@")
            identity = str(Path(host_access["identity"]).expanduser())
            lines = [f"Host {alias}", f"  HostName {address}", *([f"  User {user}"] if user else []),
                     f'  IdentityFile "{identity}"', "  IdentitiesOnly yes", "  BatchMode yes",
                     "  StrictHostKeyChecking yes", f'  UserKnownHostsFile "{self._known_hosts}"',
                     "  GlobalKnownHostsFile /dev/null", f"  ConnectTimeout {CONNECT_TIMEOUT_SECONDS}"]
            # Tools open many short connections; reuse one per host so the jump host is not throttled.
            lines += ["  ControlMaster auto", "  ControlPath /tmp/psyssh-%C", "  ControlPersist 120"]
            if host_access["jump"] is not None:
                lines.append("  ProxyJump " + host_access["jump"])
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks) + "\n"

    def missing_aliases(self, aliases):
        return sorted(alias for alias in set(aliases) if alias not in self._hosts)

    def sudo_mode(self, host):
        return self._access_of(host)["sudo"]

    def _access_of(self, host):
        if host not in self._hosts:
            raise RemoteError(f"host not in the access file: {host}", host=host)
        return self._hosts[host]

    def _options(self, host_access):
        return ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self._known_hosts}",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "IdentitiesOnly=yes", "-i", str(Path(host_access["identity"]).expanduser())]

    def _connection(self, host_access):
        options = self._options(host_access)
        if host_access["jump"] is not None:
            jump = self._hosts[host_access["jump"]]
            proxy = shlex.join(["ssh", *self._options(jump), "-W", "%h:%p", jump["ssh"]])
            options += ["-o", f"ProxyCommand={proxy}"]
        return options

    def _run(self, host, argv, *, stdin, timeout, should_show_stderr=True, remote_limit_codes=()):
        if type(timeout) is not int or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        try:
            done = self._runner(argv, input=stdin, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise RemoteError(f"{host}: timed out after {timeout}s", host=host) from None
        if done.returncode in remote_limit_codes:
            raise RemoteError(f"{host}: timed out on the remote (exit {done.returncode})", host=host,
                              exit_code=done.returncode)
        if done.returncode != 0:
            tail = "details withheld"
            if should_show_stderr:
                # A tool that fails after printing its own JSON reason on stdout leaves stderr empty.
                shown = done.stderr or done.stdout
                tail = redact_tail(shown.decode("utf-8", errors="replace"))
            kind = RemoteConnectionError if done.returncode == CONNECTION_EXIT_CODE else RemoteError
            raise kind(f"{host}: exit {done.returncode}: {tail}", host=host, exit_code=done.returncode)
        return done.stdout

    def _run_script_bytes(self, host, script, timeout_seconds, **options):
        host_access = self._access_of(host)
        argv = ["ssh", *self._connection(host_access), host_access["ssh"], "/usr/bin/bash", "-s"]
        return self._run(host, argv, stdin=script.encode(), timeout=timeout_seconds, **options)

    def run_script(self, host, script, timeout_seconds):
        return self._run_script_bytes(host, script, timeout_seconds).decode("utf-8", errors="replace")

    def run_root_text(self, host, argv, timeout_seconds, *, stdin_text=None, show_stderr=True):
        host_access = self._access_of(host)
        if type(timeout_seconds) is not int or timeout_seconds <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        if host_access["sudo"] != "passwordless":
            raise RemoteError(f"operator host {host} cannot run sudo without a prompt; raise OperatorPending instead",
                              host=host)
        # timeout runs as root under sudo, so it can signal the root tool; a local timeout fires later still.
        limit = f"/usr/bin/timeout --signal=TERM --kill-after={ROOT_KILL_AFTER_SECONDS} {timeout_seconds} "
        command = "sudo -n -- " + limit + shlex.join(argv)
        if stdin_text is not None:
            release_lock.require(HERE_DOCUMENT_MARKER not in stdin_text, "stdin text collides with the here-document marker")
            command += f" <<'{HERE_DOCUMENT_MARKER}'\n{stdin_text}{'' if stdin_text.endswith(chr(10)) else chr(10)}"
            command += HERE_DOCUMENT_MARKER
        output = self._run_script_bytes(host, "set -euo pipefail\n" + command + "\n",
                                        timeout_seconds + ROOT_KILL_AFTER_SECONDS + ROOT_LOCAL_MARGIN_SECONDS,
                                        should_show_stderr=show_stderr, remote_limit_codes=ROOT_LIMIT_EXIT_CODES)
        return output.decode("utf-8", errors="replace")

    def run_root_json(self, host, argv, timeout_seconds, *, show_stderr=True):
        output = self.run_root_text(host, argv, timeout_seconds, show_stderr=show_stderr)
        try:
            root_report = json.loads(output, object_pairs_hook=release_lock.unique_object)
        except ValueError:
            root_report = None
        if not isinstance(root_report, dict):
            raise RemoteError(f"{host}: root command did not print a JSON object ({len(output)} bytes)", host=host)
        return root_report

    def copy_files(self, host, sources, destination, *, timeout_seconds=COPY_TIMEOUT_SECONDS):
        host_access = self._access_of(host)
        if not sources:
            raise ValueError("no files to copy")
        if not destination.startswith("/"):
            raise ValueError("copy destination must be absolute")
        paths = [str(source) for source in sources]
        if any(not path.startswith("/") for path in paths):
            raise ValueError("copy sources must be absolute paths")
        argv = ["scp", "-q", *self._connection(host_access), *paths, f"{host_access['ssh']}:{destination}"]
        self._run(host, argv, stdin=None, timeout=timeout_seconds)

    def read_text(self, host, path):
        raw = self._run_script_bytes(host, f"set -euo pipefail\nhead -c {MAX_READ_BYTES + 1} -- "
                                     + shlex.quote(path) + "\n", 60)
        if len(raw) > MAX_READ_BYTES:
            raise RemoteError(f"{host}: file exceeds {MAX_READ_BYTES} bytes", host=host)
        return raw.decode("utf-8", errors="replace")
