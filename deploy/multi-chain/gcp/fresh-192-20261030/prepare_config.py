#!/usr/bin/env python3
"""Create an offline testnet config candidate from hash-pinned public inputs."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

import preflight


RETAINED_FIELDS = ("guardian_initial_member_hashes", "guardian_configs",
                   "realm_configs", "whitelist")


def read_pinned(path, digest):
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid public input digest")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular public input required")
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("public input hash/size mismatch")
    value = json.loads(raw, object_pairs_hook=preflight.unique_object)
    if not isinstance(value, dict):
        raise ValueError("public config object required")
    return value


def build_config(canonical, retained, release):
    candidate = copy.deepcopy(canonical)
    network = candidate["networks"]["testnet"]
    if network.get("magic") != release["network_magic"] or network.get("p2p") != {
            "checkpoints_per_epoch": release["checkpoints_per_epoch"]}:
        raise ValueError("canonical consensus differs from the release")
    previous = retained["networks"]["testnet"]
    if retained.get("defaultNetwork") != "testnet" or previous.get("magic") != network["magic"]:
        raise ValueError("retained identity network mismatch")
    if "guardian_history" in previous and previous["guardian_history"] != []:
        raise ValueError("fresh config cannot import Guardian governance history")
    network.pop("guardian_history", None)
    guardians = previous["guardian_configs"]
    if guardians != release["guardian_configs"] or len(guardians) != 3:
        raise ValueError("Guardian endpoints differ from the approved ordered placement")
    for guardian, identifier in zip(guardians, (1, 2, 3)):
        fields(guardian, ("id", "listen_address", "rpc_url"))
        if type(guardian["id"]) is not int or guardian["id"] != identifier:
            raise ValueError("ordered Guardian ids required")
        public_url(guardian["rpc_url"])
    fields(previous["whitelist"], ("enabled", "secp256k1"))
    for realm in previous["realm_configs"]:
        fields(realm, ("id", "rpc_url", "validators"))
        urls = realm["rpc_url"]
        if not isinstance(urls, list) or len(urls) != 3:
            raise ValueError("three retained Realm RPC URLs required")
        for url in urls:
            public_url(url)
        if len(set(urls)) != 3:
            raise ValueError("distinct retained Realm RPC URLs required")
        for member in realm["validators"]:
            fields(member, ("validator_user_id", "processor_node_id", "bls_public_key",
                            "processor_addresses", "edge_nodes"))
            for edge in member["edge_nodes"]:
                fields(edge, ("node_id", "addresses"))
    for field in RETAINED_FIELDS:
        network[field] = copy.deepcopy(previous[field])
    candidate["defaultNetwork"] = "testnet"
    preflight.config_checks(candidate, release)
    return candidate


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("unexpected or missing public identity fields")


def public_url(value):
    if not isinstance(value, str):
        raise ValueError("public RPC URL required")
    url = urlsplit(value)
    if url.scheme not in ("http", "https") or not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("credential-free RPC URL required")
    _ = url.port


def write_new(path, value):
    raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical", required=True, type=Path)
    parser.add_argument("--canonical-sha256", required=True)
    parser.add_argument("--retained", required=True, type=Path)
    parser.add_argument("--retained-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        release = preflight.document(preflight.HERE / "release.json")
        if args.canonical_sha256 != release["canonical_config_sha256"] or args.retained_sha256 != release["retained_public_config_sha256"]:
            raise ValueError("input hashes differ from the approved preparation profile")
        config = build_config(read_pinned(args.canonical, args.canonical_sha256),
                              read_pinned(args.retained, args.retained_sha256), release)
        args.output.mkdir(mode=0o700)
        digest = write_new(args.output / "config.json", config)
        report = {"mode": "offline-config-candidate", "release_id": release["release_id"],
                  "canonical_sha256": args.canonical_sha256, "retained_sha256": args.retained_sha256,
                  "config_sha256": digest, "identity_fields": list(RETAINED_FIELDS),
                  "deployment_ready": False, "activation_authorized": False,
                  "native_validation_passed": False, "private_key_files_opened": False}
        write_new(args.output / "manifest.json", report)
    except (ValueError, OSError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
        print(json.dumps({"status": "rejected", "deployment_ready": False,
                          "error": "Config preparation failed; retained output, if any, was not removed"}))
        return 2
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
