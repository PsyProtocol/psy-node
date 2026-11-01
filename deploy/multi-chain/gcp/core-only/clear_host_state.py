#!/usr/bin/env python3
"""Root tool that stops listed units, removes listed containers and deletes listed paths; standard library only.

Run as `python3 -I -B -` (script on stdin) or from a file. Without --apply nothing is changed.
Every refusal happens before the first change; a retained secret whose hash moves fails the run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MAX_JSON_BYTES = 4 * 1024 * 1024
STOP_TIMEOUT_SECONDS = 180
COMMAND_TIMEOUT_SECONDS = 120
ACTIVE_STATES = frozenset(("active", "activating", "reloading", "deactivating"))
ENABLED_STATES = frozenset(("enabled", "enabled-runtime", "linked", "linked-runtime", "alias"))
UNIT_TYPES = ("service", "timer", "socket")
UNIT_ORDER = {"timer": 0, "socket": 1, "service": 2}
BUSINESS_UNIT = re.compile(r"(parth|psy)-[^/\s]+\.(service|timer|socket)")
# release_lock.UNIT_NAME is a copy of this pattern; a test pins them equal.
UNIT_NAME = re.compile(r"[A-Za-z0-9:_.@\\-]+\.(service|timer|socket)")
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
GLOB_CHARACTERS = frozenset("*?[]")
SYSTEMCTL, DOCKER = "/usr/bin/systemctl", "/usr/bin/docker"
# Names that look like key material; a clear target holding one is refused unless the path is allowed.
SECRET_NAME = re.compile(
    r"operator|keystore|mnemonic|seed|wallet|(^|[._-])keys?($|[._-])|\.pem$|\.p12$|\.pfx$|\.cred|cred(ential)?|secret"
    r"|passw|passphrase|jwt|^id_(rsa|dsa|ecdsa|ed25519)|^wg\d*\.conf$|wireguard|^\.ssh$|authorized_keys|^\.env|\.env$"
    r"|identity|signer|^UTC--|privkey|private|^\.psy$|validator-\d", re.IGNORECASE)
# The only places a clear entry may live; a pattern never matches the directory that holds the entries.
CLEARABLE = [re.compile(pattern) for pattern in (
    r"/etc/systemd/system/[^/]+(/.*)?",
    r"/etc/psy-[^/]+/[^/]+(/.*)?",
    r"/opt/psy-[^/]+(/.*)?",
    r"/opt/nostr-relay[A-Za-z0-9._-]*/[^/]+(/.*)?",
    r"/var/lib/psy-[^/]+(/.*)?",
    r"/var/lib/parth-[^/]+(/.*)?",
    r"/var/lib/parth/[^/]+(/.*)?",
)]
SYSTEMD_ROOT = "/etc/systemd/system"
MOUNTINFO = "/proc/self/mountinfo"
FIB_TRIE = "/proc/net/fib_trie"
LISTING_DEPTH = 3


class ClearRefused(Exception):
    """The run was refused before any change; the message names paths, never contents."""


def read_input(spec, expected_sha256=None):
    """Return the bytes of a file path or of an `inline:` text, optionally checked against a hash."""
    if spec.startswith("inline:"):
        raw = spec[len("inline:"):].encode()
    else:
        with open(spec, "rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ClearRefused("input too large")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ClearRefused("input hash mismatch")
    return raw


def parse_json(raw, label):
    try:
        return json.loads(raw)
    except ValueError:
        raise ClearRefused(f"{label} is not valid JSON") from None


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ClearRefused(f"{label} must be a list of strings")
    if len(value) != len(set(value)):
        raise ClearRefused(f"{label} lists an entry twice")
    return value


def absolute_paths(value, label):
    for item in string_list(value, label):
        if not item.startswith("/") or ".." in item.split("/") or "//" in item or (item != "/" and item.endswith("/")):
            raise ClearRefused(f"{label} entry must be an absolute normal path: {item}")
        if GLOB_CHARACTERS & set(item):
            raise ClearRefused(f"{label} entry holds a glob character: {item}")
    return value


def related(first, second):
    """True when the paths are equal or one contains the other."""
    first, second = Path(first), Path(second)
    return first == second or first in second.parents or second in first.parents


def inside(path, root):
    return Path(path) == Path(root) or Path(root) in Path(path).parents


def mount_points(read=lambda: Path(MOUNTINFO).read_text()):
    points = []
    for line in read().splitlines():
        fields = line.split(" ")
        if len(fields) > 4:
            points.append(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4]))
    return points


def local_addresses(read=lambda: Path(FIB_TRIE).read_text()):
    """IPv4 addresses assigned to this machine, from the kernel's routing table."""
    found, last = set(), None
    for line in read().splitlines():
        match = re.search(r"\|-- (\d+\.\d+\.\d+\.\d+)$", line)
        if match:
            last = match.group(1)
        elif "/32 host LOCAL" in line and last:
            found.add(last)
    return found


def protected_lock_paths(lock):
    """Paths of the new release; no clear entry may overlap them."""
    found = []
    for group in lock["paths"].values():
        found += [group["release"], group["config"], group["state"]]
    found += [lock["services"]["backups"], lock["services"]["mirror"], lock["l1"]["output_root"]]
    return found


def walk_names(target):
    """Yield (path, name, is_dir) for the target and everything below it without following symlinks."""
    info = os.lstat(target)
    yield target, os.path.basename(target), stat.S_ISDIR(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        return
    pending = [(target, info.st_dev)]
    while pending:
        directory, device = pending.pop()
        try:
            entries = os.scandir(directory)
        except FileNotFoundError:
            continue  # a live store removed it while we looked; it is going anyway
        with entries:
            for entry in entries:
                child = entry.path
                try:
                    child_info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                is_dir = stat.S_ISDIR(child_info.st_mode)
                yield child, entry.name, is_dir
                if is_dir:
                    if child_info.st_dev != device:
                        raise ClearRefused(f"clear target holds another filesystem: {child}")
                    pending.append((child, child_info.st_dev))


def is_allowed(path, allow):
    return any(inside(path, allowed) for allowed in allow)


def scan_target(target, plan, links, mounts):
    """Return the reasons this one target must be refused."""
    reasons = [f"touches a retained path: {target} ~ {kept}" for kept in plan["retained"] if related(target, kept)]
    reasons += [f"a retained path resolves into the target: {target} ~ {real}"
                for real in plan["retained_real"] if related(target, real)]
    reasons += [f"retained secret holds a symlink into the clear target: {link} -> {target}"
                for link, real in links if inside(real, target)]
    if not any(pattern.fullmatch(target) for pattern in CLEARABLE):
        return reasons + [f"outside the clearable locations: {target}"]
    parent = os.path.dirname(target)
    if os.path.realpath(parent) != parent:
        reasons.append(f"parent resolves through a symlink: {target}")
    if os.path.islink(target):
        resolved = os.path.realpath(target)
        if any(related(resolved, kept) for kept in plan["retained"] + plan["retained_real"]):
            reasons.append(f"symlink points into a retained path: {target}")
        return reasons
    if not os.path.lexists(target):
        return reasons
    if any(inside(point, target) for point in mounts):
        reasons.append(f"mount point at or below the target: {target}")
    try:
        for path, name, _ in walk_names(target):
            if SECRET_NAME.search(name) and not is_allowed(path, plan["allow"]):
                reasons.append(f"key-like name under a clear target: {path}")
            if os.path.islink(path) and any(related(os.path.realpath(path), kept)
                                            for kept in plan["retained"] + plan["retained_real"]):
                reasons.append(f"symlink points into a retained path: {path}")
    except ClearRefused as error:
        reasons.append(str(error))
    except OSError as error:
        reasons.append(f"cannot scan {target}: {error.strerror}")
    return reasons


def listing(directory, depth=LISTING_DEPTH):
    """Return (rows, links): names, kinds, sizes and mtimes down to a depth, and every symlink with its real path."""
    pending, rows, links = [(directory, 0)], [], []
    while pending:
        current, level = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                is_link = stat.S_ISLNK(info.st_mode)
                target = os.readlink(entry.path) if is_link else ""
                if is_link:
                    links.append((entry.path, os.path.realpath(entry.path)))
                rows.append(f"{os.path.relpath(entry.path, directory)}\0{stat.S_IFMT(info.st_mode)}\0{info.st_size}"
                            f"\0{info.st_mtime_ns}\0{target}\n")
                if stat.S_ISDIR(info.st_mode) and level + 1 < depth:
                    pending.append((entry.path, level + 1))
    return sorted(rows), links


def listing_hash(directory, depth=LISTING_DEPTH):
    """Hash of names, kinds, sizes and mtimes down to a depth; contents are never read."""
    digest = hashlib.sha256()
    for row in listing(directory, depth)[0]:
        digest.update(row.encode())
    return digest.hexdigest()


def hash_secret(path):
    """Return (kind, sha256, links) of a retained secret; a symlink is followed because its target is what matters."""
    real = os.path.realpath(path)
    if not os.path.exists(real):
        return "missing", None, []
    info = os.stat(real)
    if stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256()
        with open(real, "rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                digest.update(block)
        return "file", digest.hexdigest(), []
    if stat.S_ISDIR(info.st_mode):
        rows, links = listing(real)
        return "directory", hashlib.sha256("".join(rows).encode()).hexdigest(), links
    return "other", hashlib.sha256(str(stat.S_IFMT(info.st_mode)).encode()).hexdigest(), []


def kind_of(path):
    """Existence and kind from lstat alone; infrastructure paths are never read or walked."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return "missing"
    return "directory" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else "other"


def hash_all(plan):
    """Secrets are hashed; infrastructure paths only have to keep existing as the same kind."""
    found = {path: hash_secret(path) for path in plan["secret"]}
    for path in plan["infrastructure"]:
        found[path] = (kind_of(path), None, [])
    return found


def request_digest(host, plan, retained_sha256, lock_sha256):
    """Digest that ties a result to the exact request that produced it."""
    request = {"host": host, "clear": plan["clear"], "allow": plan["allow"], "stop": plan["stop"],
               "keep": plan["keep"], "containers": plan["containers"], "retained": retained_sha256,
               "lock": lock_sha256}
    return hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def delete_tree(target):
    """Delete one entry; never follows a symlink and never removes anything above the target."""
    if os.path.islink(target) or not os.path.isdir(target):
        os.unlink(target)
        return
    for directory, names, files in os.walk(target, topdown=False, followlinks=False):
        for name in files:
            os.unlink(os.path.join(directory, name))
        for name in names:
            child = os.path.join(directory, name)
            if os.path.islink(child):
                os.unlink(child)
            else:
                os.rmdir(child)
    os.rmdir(target)


def remove_dangling_links(cleared):
    """Remove the .wants/.requires links that still name a unit file this run deleted."""
    names = {os.path.basename(path) for path in cleared if path.endswith(tuple("." + kind for kind in UNIT_TYPES))}
    removed = 0
    if not os.path.isdir(SYSTEMD_ROOT):
        return removed
    with os.scandir(SYSTEMD_ROOT) as groups:
        for group in sorted(groups, key=lambda item: item.name):
            if not (group.name.endswith((".wants", ".requires")) and group.is_dir(follow_symlinks=False)):
                continue
            for link in os.scandir(group.path):
                if link.is_symlink() and link.name in names and not os.path.exists(link.path):
                    os.unlink(link.path)
                    removed += 1
    return removed


def run_command(argv, timeout=COMMAND_TIMEOUT_SECONDS):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def active_units(run=run_command):
    done = run([SYSTEMCTL, "list-units", "--type=" + ",".join(UNIT_TYPES), "--all", "--no-legend", "--plain",
                "--no-pager"])
    if done.returncode != 0:
        raise ClearRefused("systemctl list-units failed")
    active = set()
    for line in done.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] in ACTIVE_STATES:
            active.add(fields[0])
    return active


def unit_file_names(run=run_command):
    done = run([SYSTEMCTL, "list-unit-files", "--no-legend", "--plain", "--no-pager"])
    if done.returncode != 0:
        raise ClearRefused("systemctl list-unit-files failed")
    return {line.split()[0] for line in done.stdout.splitlines() if line.split()}


def classify_units(active, stop, keep):
    business = {unit for unit in active if BUSINESS_UNIT.fullmatch(unit)}
    return (sorted(business & set(stop)), sorted(business - set(stop) - set(keep)), sorted(business & set(keep)))


def unit_exists(unit, files, active):
    return unit in files or unit in active or re.sub(r"@[^.@]*\.", "@.", unit) in files


def stop_units(stop, run=run_command):
    """Disable and stop the listed units, timers and sockets before services; return (stopped, disabled)."""
    ordered = sorted(stop, key=lambda unit: (UNIT_ORDER[unit.rsplit(".", 1)[1]], unit))
    active_before, files = active_units(run), unit_file_names(run)
    disabled = []
    for unit in ordered:
        if not unit_exists(unit, files, active_before):
            continue
        if run([SYSTEMCTL, "disable", "--now", "--", unit], STOP_TIMEOUT_SECONDS).returncode != 0:
            raise ClearRefused(f"systemctl disable failed for {unit}")
        disabled.append(unit)
    still = sorted(set(stop) & active_units(run))
    if still:
        raise ClearRefused("units still active after stop: " + ", ".join(still))
    enabled = [unit for unit in disabled
               if run([SYSTEMCTL, "is-enabled", "--", unit]).stdout.strip() in ENABLED_STATES]
    if enabled:
        raise ClearRefused("units still enabled after disable: " + ", ".join(enabled))
    return sorted(set(stop) & active_before), disabled


def existing_containers(run=run_command):
    done = run([DOCKER, "ps", "-a", "--format", "{{.Names}}"])
    if done.returncode != 0:
        raise ClearRefused("docker ps failed")
    return set(done.stdout.split())


def remove_containers(names, run=run_command):
    if not names:
        return []
    present = sorted(set(names) & existing_containers(run))
    for name in present:
        done = run([DOCKER, "rm", "-f", "--", name])
        if done.returncode != 0:
            raise ClearRefused(f"docker rm failed for {name}")
    left = sorted(set(names) & existing_containers(run))
    if left:
        raise ClearRefused("containers still present: " + ", ".join(left))
    return present


def plan_run(args, retained_document):
    host = args.host
    entries = [item for item in retained_document["paths"] if item.get("host") == host]
    if len(entries) != len(retained_document["paths"]):
        raise ClearRefused("retained paths hold another host")
    retained = absolute_paths([item["path"] for item in entries], "retained paths")
    clear = absolute_paths(parse_json(args.clear_paths, "clear paths"), "clear paths")
    allow = absolute_paths(parse_json(args.clear_allow, "clear allow"), "clear allow")
    for first in range(len(clear)):
        for second in range(first + 1, len(clear)):
            if related(clear[first], clear[second]):
                raise ClearRefused(f"clear entries are nested: {clear[first]} ~ {clear[second]}")
    for item in allow:
        if not any(inside(item, target) and item != target for target in clear):
            raise ClearRefused(f"clear allow entry must be strictly inside a clear target: {item}")
    stop = string_list(parse_json(args.stop_units, "stop units"), "stop units")
    keep = string_list(parse_json(args.keep_units, "keep units"), "keep units")
    containers = string_list(parse_json(args.containers, "containers"), "containers")
    if not all(UNIT_NAME.fullmatch(unit) for unit in stop + keep):
        raise ClearRefused("unit names must be service, timer or socket names")
    if not all(CONTAINER_NAME.fullmatch(name) for name in containers):
        raise ClearRefused("container names must be plain names")
    if set(stop) & set(keep):
        raise ClearRefused("a unit is both stopped and kept")
    return {"clear": clear, "allow": allow, "stop": stop, "keep": keep, "containers": containers,
            "retained": retained, "retained_real": [os.path.realpath(path) for path in retained],
            "secret": [item["path"] for item in entries if item["kind"] == "secret"],
            "infrastructure": [item["path"] for item in entries if item["kind"] != "secret"]}


def refusals(plan, lock, mounts, unlisted, before):
    reasons = []
    protected = protected_lock_paths(lock)
    links = [link for _, _, found in before.values() for link in found]
    for target in plan["clear"]:
        reasons += scan_target(target, plan, links, mounts)
        reasons += [f"overlaps the new release: {target} ~ {new}" for new in protected if related(target, new)]
    if plan["clear"]:
        reasons += [f"unlisted business unit is active: {unit}" for unit in unlisted]
    reasons += [f"retained secret is missing: {path}" for path in plan["secret"] if before.get(path, ("",))[0] == "missing"]
    return reasons


def build_report(args):
    return {"host": args.host, "applied": args.apply, "cleared": [], "absent": [], "refused": [], "stopped": [],
            "disabled": [], "containers_removed": [], "active_listed": [], "unlisted_active": [], "active_kept": [],
            "retained": [], "retained_unchanged": None, "wants_links_removed": 0, "request_sha256": None,
            "lock_sha256": None, "error": None}


def fill_retained(report, before, plan):
    report["retained"] = [{"path": path, "kind": kind, "class": "secret" if path in plan["secret"] else "infrastructure",
                           "sha256": digest, "sha256_after": None} for path, (kind, digest, _) in before.items()]


def delete_all(plan, existing, report, run):
    touches_units = any(inside(target, SYSTEMD_ROOT) for target in plan["clear"])
    reload_code = 0
    try:
        for target in existing:
            delete_tree(target)
    finally:
        if touches_units:
            reload_code = run([SYSTEMCTL, "daemon-reload"]).returncode
            run([SYSTEMCTL, "reset-failed"])
    report["wants_links_removed"] = remove_dangling_links(existing)
    if reload_code != 0:
        raise ClearRefused("systemctl daemon-reload failed")


def execute(args, plan, report, before, run=run_command):
    if not args.apply:
        return
    report["stopped"], report["disabled"] = stop_units(plan["stop"], run)
    report["containers_removed"] = remove_containers(plan["containers"], run)
    delete_all(plan, report["cleared"], report, run)
    if args.skip_retained_hash:
        return
    after = hash_all(plan)
    for item in report["retained"]:
        item["sha256_after"] = after[item["path"]][1]
        item["kind_after"] = after[item["path"]][0]
    report["retained_unchanged"] = all(before[path][:2] == after[path][:2] for path in before)
    if not report["retained_unchanged"]:
        raise ClearRefused("a retained secret changed during the clear")


def write_result(path, report):
    """Write the result readable only by the owner of its directory, so the operator can read it back."""
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    temporary = path + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)
    owner = os.stat(os.path.dirname(path) or ".")
    try:
        os.chown(temporary, owner.st_uid, owner.st_gid)
    except PermissionError:
        pass
    os.replace(temporary, path)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--release-lock", required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    parser.add_argument("--retained-paths", required=True)
    parser.add_argument("--retained-paths-sha256", required=True)
    parser.add_argument("--clear-paths", default="[]")
    parser.add_argument("--clear-allow", default="[]")
    parser.add_argument("--stop-units", default="[]")
    parser.add_argument("--keep-units", default="[]")
    parser.add_argument("--containers", default="[]")
    parser.add_argument("--result")
    parser.add_argument("--address", help="the address the lock holds for this host; it must be local")
    parser.add_argument("--skip-retained-hash", action="store_true",
                        help="unprivileged dry run: retained paths are neither read nor hashed")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--exit-zero-with-report", action="store_true",
                        help="exit 0 after printing a report even when the run failed; its error field says so")
    return parser.parse_args(argv)


def main(argv=None, run=run_command, read_mounts=mount_points, read_addresses=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report = {"host": args.host, "applied": False, "error": None}
    code = 0
    try:
        lock = parse_json(read_input(args.release_lock, args.release_lock_sha256), "release lock")
        retained_document = parse_json(read_input(args.retained_paths, args.retained_paths_sha256), "retained paths")
        if args.apply and args.skip_retained_hash:
            raise ClearRefused("--skip-retained-hash is for a dry run only")
        plan = plan_run(args, retained_document)
        report = build_report(args)
        report["lock_sha256"] = args.release_lock_sha256
        report["request_sha256"] = request_digest(args.host, plan, args.retained_paths_sha256, args.release_lock_sha256)
        if args.address and args.address not in (read_addresses or local_addresses)():
            raise ClearRefused(f"{args.address} is not an address of this machine")
        report["cleared"] = [target for target in plan["clear"] if os.path.lexists(target)]
        report["absent"] = [target for target in plan["clear"] if target not in report["cleared"]]
        report["active_listed"], report["unlisted_active"], report["active_kept"] = classify_units(
            active_units(run), plan["stop"], plan["keep"])
        before = {} if args.skip_retained_hash else hash_all(plan)
        fill_retained(report, before, plan)
        report["refused"] = refusals(plan, lock, read_mounts(), report["unlisted_active"], before)
        if report["refused"]:
            raise ClearRefused(f"{len(report['refused'])} refusal(s); nothing was changed")
        execute(args, plan, report, before, run)
    except ClearRefused as error:
        report["error"], code = str(error), 2
    except (OSError, KeyError, subprocess.SubprocessError) as error:
        report["error"], code = f"{type(error).__name__}: {getattr(error, 'strerror', None) or 'failed'}", 1
    if args.result:
        write_result(args.result, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if args.exit_zero_with_report else code


if __name__ == "__main__":
    sys.exit(main())
