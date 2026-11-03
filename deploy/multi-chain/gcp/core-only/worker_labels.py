"""Optional operator labels on the worker whitelist.

A policy may carry "labels": {compressed public key: name}. Labels name workers in Edge logs and
never change admission. The rules mirror psy_node_common::worker_whitelist, which refuses to load a
policy that breaks them, so a bad label must be caught here before it reaches an Edge.
"""
import re

MAX_LABEL_LEN = 64
KEY = re.compile(r"(?:0[xX])?0[23][0-9a-fA-F]{64}")
LABEL = re.compile(r"[A-Za-z0-9._-]{1,%d}" % MAX_LABEL_LEN)


def policy_fields(policy):
    """The exact field set a whitelist policy may have."""
    base = ("enabled", "secp256k1")
    return base + ("labels",) if isinstance(policy, dict) and "labels" in policy else base


def canonical_key(key):
    return key.lower().removeprefix("0x")


def check_labels(policy, require):
    """Validate policy["labels"] if present; `require(condition, message)` raises on failure."""
    if "labels" not in policy:
        return {}
    labels = policy["labels"]
    require(isinstance(labels, dict), "worker labels must be an object")
    keys = {canonical_key(key) for key in policy["secp256k1"] if isinstance(key, str)}
    seen_keys, seen_names = set(), set()
    for key, name in labels.items():
        require(isinstance(key, str) and KEY.fullmatch(key) is not None, "invalid worker label key")
        encoded = canonical_key(key)
        require(encoded in keys, "worker label names a key that is not whitelisted")
        require(encoded not in seen_keys, "worker key labelled twice")
        require(isinstance(name, str) and LABEL.fullmatch(name) is not None,
                f"worker label must be 1-{MAX_LABEL_LEN} characters of [A-Za-z0-9._-]")
        require(name not in seen_names, "duplicate worker label")
        seen_keys.add(encoded)
        seen_names.add(name)
    return {canonical_key(key): name for key, name in labels.items()}
