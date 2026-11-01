#!/usr/bin/env python3
"""Move recorded state from the release lock it was written under to the current lock, after a tool-only change.

State files in the private state directory carry the hash of the lock they were written under, and every step
refuses a file bound to another lock. When a tool fix changes only tool_sha256 in the lock, the recorded
facts are still true. This command proves that the previous lock differs from the current one only in
tool_sha256 and then rewrites the binding, so nobody edits state by hand. It is a dry run unless --apply is given.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import release_lock
from release_lock import require

DOCUMENT_HASH = "l1_documents_sha256"
DEPLOY_STATE = "deploy_l1.json"


def tool_only_difference(previous, current):
    names = sorted(set(previous) | set(current))
    changed = [name for name in names if previous.get(name) != current.get(name)]
    require("tool_sha256" in changed and changed == ["tool_sha256"],
            "the previous lock differs from the current lock beyond tool_sha256: " + ", ".join(changed or ["nothing"]))
    require(set(previous["tool_sha256"]) == set(current["tool_sha256"]), "the previous lock lists other tools")


def write_state(path, document):
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def plan_rebind(state_dir, previous_sha256, current_sha256):
    """Rows (path, document) to rewrite, and the names left alone because another lock owns them."""
    rewrite, foreign = [], []
    for path in sorted(state_dir.glob("*.json")):
        document = release_lock.read_document(path)
        recorded = document.get("lock_sha256")
        if recorded == previous_sha256:
            rewrite.append((path, dict(document, lock_sha256=current_sha256)))
        elif recorded not in (None, current_sha256):
            foreign.append(path.name)
    return rewrite, foreign


def apply_rebind(state_dir, rewrite):
    """Write the rewritten files; documents that pin the hash of the deployment record follow it."""
    deploy_path = state_dir / DEPLOY_STATE
    old_deploy_hash = hashlib.sha256(deploy_path.read_bytes()).hexdigest() if deploy_path.is_file() else None
    for path, document in rewrite:
        write_state(path, document)
    if old_deploy_hash is None:
        return []
    new_deploy_hash = hashlib.sha256(deploy_path.read_bytes()).hexdigest()
    followed = []
    for path in sorted(state_dir.glob("*.json")):
        document = release_lock.read_document(path)
        if document.get(DOCUMENT_HASH) == old_deploy_hash and old_deploy_hash != new_deploy_hash:
            write_state(path, dict(document, **{DOCUMENT_HASH: new_deploy_hash}))
            followed.append(path.name)
    return followed


def rebind(release_dir, private_dir, previous_lock, apply):
    current_raw = release_lock.read_regular(release_dir / "release-lock.json")
    previous_raw = release_lock.read_regular(previous_lock)
    previous_sha256, current_sha256 = hashlib.sha256(previous_raw).hexdigest(), hashlib.sha256(current_raw).hexdigest()
    require(previous_sha256 != current_sha256, "the previous lock is the current lock; nothing to move")
    tool_only_difference(release_lock.parse(previous_raw), release_lock.parse(current_raw))
    state_dir = private_dir / "state"
    require(state_dir.is_dir(), "state directory not found")
    rewrite, foreign = plan_rebind(state_dir, previous_sha256, current_sha256)
    followed = apply_rebind(state_dir, rewrite) if apply else []
    return {"applied": apply, "rebound": [path.name for path, _ in rewrite], "followed": followed,
            "bound_to_other_locks": foreign}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--previous-lock", type=Path, required=True, help="the release-lock.json the state was written under")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = rebind(args.release_dir.resolve(), args.private_dir.resolve(), args.previous_lock, args.apply)
    except (ValueError, OSError) as error:
        print(f"rebind_lock_state: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
