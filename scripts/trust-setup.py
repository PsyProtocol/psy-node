#!/usr/bin/env python3
"""Pack, verify, and publish the official four-cohort Groth16 trust setup."""

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PART_BYTES = 268435456
BUFFER_BYTES = 1024 * 1024
MAX_SIZE = 2**53 - 1
COHORTS = ("deposit_append", "withdrawal_claim", "reward_claim")
NAMES = ("circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin")
UNCOMPRESSED = tuple(prefix + name for prefix in ("", *(c + "/" for c in COHORTS)) for name in NAMES)
CHUNKED = ("pk_groth16.bin.zst", *(c + ".tar.zst" for c in COHORTS))
SINGLES = ("circuit_groth16.bin.zst", "vk_groth16.bin.zst")
MANIFEST = "sha256sums.json"
BUCKET = "psy-proving-keystores"
PUBLIC_URL = "https://pub-23b7764b3820454094ce80557ab38d0b.r2.dev"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular_file(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular, non-symlink file: {path.name}")


def digest_stream(handle):
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: handle.read(BUFFER_BYTES), b""):
        size += len(block)
        digest.update(block)
    return {"size": size, "sha256": digest.hexdigest()}


def digest_file(path):
    regular_file(path)
    with path.open("rb") as handle:
        return digest_stream(handle)


def run(command, **kwargs):
    # Never expose raw CLI output: Wrangler may include authentication details.
    result = subprocess.run(command, stderr=subprocess.DEVNULL, **kwargs)
    require(result.returncode == 0, f"{Path(command[0]).name} failed (exit {result.returncode})")
    return result


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate manifest key")
        result[key] = value
    return result


def read_manifest(package):
    path = package / MANIFEST
    regular_file(path)
    require(path.stat().st_size <= 16384, "manifest exceeds 16 KiB")
    raw = path.read_bytes()
    manifest = json.loads(raw, object_pairs_hook=unique_keys)
    require(type(manifest) is dict and set(manifest) == {"version", "files"}, "invalid manifest keys")
    require(type(manifest["version"]) is int and manifest["version"] == 1, "invalid manifest version")
    files = manifest["files"]
    require(type(files) is dict and set(files) == set(UNCOMPRESSED + CHUNKED), "require exactly sixteen fixed manifest paths")
    for name, entry in files.items():
        require(type(entry) is dict and set(entry) == {"sha256", "size"}, f"invalid entry: {name}")
        require(type(entry["size"]) is int and 0 < entry["size"] <= MAX_SIZE, f"invalid size: {name}")
        require(type(entry["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]), f"invalid hash: {name}")
    return raw, files


def part_names(name, size):
    return [f"{name}.part-{index:02d}" for index in range((size + PART_BYTES - 1) // PART_BYTES)]


def package_objects(package, files):
    names = list(SINGLES)
    for name in CHUNKED:
        # Check the count before allocating a list from an untrusted size.
        count = (files[name]["size"] + PART_BYTES - 1) // PART_BYTES
        require(count <= len(tuple(package.iterdir())), f"missing parts: {name}")
        names.extend(part_names(name, files[name]["size"]))
    actual = {path.name for path in package.iterdir()}
    required = set(names) | {MANIFEST}
    require(required <= actual and actual <= required | set(CHUNKED), "unexpected or missing package files/part names")
    for name in actual:
        regular_file(package / name)
    return names


def verify_archive(path, cohort, files):
    expected = {f"{cohort}/{name}" for name in NAMES}
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        require(len(members) == 3 and {member.name for member in members} == expected, f"unexpected archive members: {cohort}")
        for member in members:
            require(member.isfile() and not member.issparse(), f"unsafe archive member: {cohort}")
            require(member.size == files[member.name]["size"], f"archive member size mismatch: {member.name}")
        # Validate ALL names and types before opening any member; never extract paths.
        for member in members:
            with archive.extractfile(member) as handle:
                require(digest_stream(handle) == files[member.name], f"uncompressed hash mismatch: {member.name}")


def verify_compressed(path, name, files, work):
    output = work / "decompressed"
    with output.open("xb") as handle:
        run(["zstd", "-q", "-d", "-c", "--", str(path)], stdout=handle)
    try:
        if name.endswith(".tar.zst"):
            verify_archive(output, name.removesuffix(".tar.zst"), files)
        else:
            rel = name.removesuffix(".zst")
            require(digest_file(output) == files[rel], f"uncompressed hash mismatch: {rel}")
    finally:
        output.unlink()


def verify(package):
    package = package.resolve(strict=True)
    raw, files = read_manifest(package)
    names = package_objects(package, files)
    objects = {}
    with tempfile.TemporaryDirectory(prefix="psy-trust-verify-") as directory:
        work = Path(directory)
        for name in SINGLES:
            objects[name] = digest_file(package / name)
            verify_compressed(package / name, name, files, work)
        for name in CHUNKED:
            assembled = work / name
            with assembled.open("xb") as output:
                for index, part in enumerate(part_names(name, files[name]["size"])):
                    expected_size = min(PART_BYTES, files[name]["size"] - index * PART_BYTES)
                    require((package / part).stat().st_size == expected_size, f"part size mismatch: {part}")
                    objects[part] = digest_file(package / part)
                    with (package / part).open("rb") as handle:
                        shutil.copyfileobj(handle, output, BUFFER_BYTES)
            require(digest_file(assembled) == files[name], f"compressed concatenation mismatch: {name}")
            if (package / name).exists():
                require(digest_file(package / name) == files[name], f"full compressed object mismatch: {name}")
            verify_compressed(assembled, name, files, work)
            assembled.unlink()
    require(set(objects) == set(names), "object coverage mismatch")
    return raw, objects


def compress_archive(source, cohort, destination):
    command = ["tar", "-C", str(source), "-cf", "-", "--", *(f"{cohort}/{name}" for name in NAMES)]
    with destination.open("xb") as output:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as archive:
            try:
                run(["zstd", "-q", "-c"], stdin=archive.stdout, stdout=output)
            finally:
                archive.stdout.close()
            require(archive.wait() == 0, "tar failed")


def pack(source, package):
    source = source.resolve(strict=True)
    # Refuse even empty existing directories, symlinks, and source descendants.
    require(not package.exists() and not package.is_symlink(), "package output must not already exist")
    require(not any(parent.is_symlink() for parent in (package, *package.parents)), "symlink output path is forbidden")
    package = package.resolve()
    require(package != source and source not in package.parents and package not in source.parents, "package and source must be disjoint")
    files = {}
    for name in UNCOMPRESSED:
        path = source / name
        require(not any((source / parent).is_symlink() for parent in Path(name).parents), "symlink source directory is forbidden")
        require(path.resolve().is_relative_to(source), f"source escapes keystore: {name}")
        files[name] = digest_file(path)
        require(0 < files[name]["size"] <= MAX_SIZE, f"invalid source size: {name}")
    package.mkdir(mode=0o700)
    for name in NAMES:
        with (package / (name + ".zst")).open("xb") as output:
            run(["zstd", "-q", "-c", "--", str(source / name)], stdout=output)
    for cohort in COHORTS:
        compress_archive(source, cohort, package / (cohort + ".tar.zst"))
    for name in CHUNKED:
        files[name] = digest_file(package / name)
        with (package / name).open("rb") as handle:
            for part in part_names(name, files[name]["size"]):
                with (package / part).open("xb") as output:
                    remaining = PART_BYTES
                    while remaining:
                        block = handle.read(min(BUFFER_BYTES, remaining))
                        if not block:
                            break
                        output.write(block)
                        remaining -= len(block)
    with (package / MANIFEST).open("x") as output:
        json.dump({"version": 1, "files": files}, output, indent=2)
        output.write("\n")
    verify(package)
    print("Packed and verified twelve files, six compressed objects, and sixteen manifest entries.")


def curl_status(prefix, name, output=None):
    command = ["curl", "-q", "--silent", "--proto", "=https", "--proto-redir", "=https",
               "--connect-timeout", "30", "--max-time", "1800", "--write-out", "%{http_code}"]
    if output is None:
        command.extend(["--head", "--output", "/dev/null"])
    else:
        command.extend(["--output", str(output)])
    command.append(f"{PUBLIC_URL}/{prefix}/{name}")
    return run(command, stdout=subprocess.PIPE).stdout.decode("ascii")


def require_absent(prefix, name):
    require(curl_status(prefix, name) == "404", f"object not proven absent (requires HTTP 404): {name}")


def upload(prefix, name, package):
    require_absent(prefix, name)
    run(["wrangler", "r2", "object", "put", f"{BUCKET}/{prefix}/{name}",
         "--file", str(package / name), "--remote"], stdout=subprocess.DEVNULL)


def publish(package, prefix, check_only):
    require(re.fullmatch(r"[A-Za-z0-9._-]{1,128}", prefix) and ".." not in prefix, "invalid one-segment prefix")
    require(shutil.which("wrangler") is not None, "installed official wrangler is required")
    package = package.resolve(strict=True)
    raw, files = read_manifest(package)
    names = package_objects(package, files)
    # Private snapshot prevents changes to the caller's package during publication.
    with tempfile.TemporaryDirectory(prefix="psy-trust-publish-") as directory:
        snapshot = Path(directory) / "package"
        snapshot.mkdir(mode=0o700)
        for name in [*names, *(name for name in CHUNKED if (package / name).exists())]:
            shutil.copyfile(package / name, snapshot / name)
        (snapshot / MANIFEST).write_bytes(raw)
        manifest, objects = verify(snapshot)
        # Complete the whole vacancy gate before the first possible write.
        for name in [*objects, MANIFEST]:
            require_absent(prefix, name)
        if check_only:
            for name in objects:
                print(f"PLAN upload + public size/SHA-256 readback: {name}")
            print(f"PLAN LAST upload + exact public readback: {MANIFEST}")
            print("Check only: no uploads performed; not publication evidence.")
            return
        readback = Path(directory) / "readback"
        for name, expected in objects.items():
            upload(prefix, name, snapshot)
            require(curl_status(prefix, name, readback) == "200", f"public readback failed: {name}")
            require(digest_file(readback) == expected, f"public readback mismatch: {name}")
            readback.unlink()
        upload(prefix, MANIFEST, snapshot)
        require(curl_status(prefix, MANIFEST, readback) == "200", "manifest public readback failed")
        require(readback.read_bytes() == manifest, "manifest public readback differs")
        print(f"Published and verified {len(objects)} data objects; manifest last: {prefix}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack_parser = commands.add_parser("pack", help="create a new offline package from twelve source files")
    pack_parser.add_argument("--source", type=Path, required=True)
    pack_parser.add_argument("--package", type=Path, required=True)
    verify_parser = commands.add_parser("verify", help="verify package without modifying it or extracting paths")
    verify_parser.add_argument("--package", type=Path, required=True)
    publish_parser = commands.add_parser("publish", help="publish to an exclusively reserved fresh immutable prefix")
    publish_parser.add_argument("--package", type=Path, required=True)
    publish_parser.add_argument("--prefix", required=True)
    publish_parser.add_argument("--check-only", action="store_true", help="verify and preflight all public keys; print plan without uploads")
    args = parser.parse_args()
    try:
        if args.command == "pack":
            pack(args.source, args.package)
        elif args.command == "verify":
            _, objects = verify(args.package)
            print(f"Verified sixteen manifest entries, twelve uncompressed files, and {len(objects)} publication data objects.")
        else:
            publish(args.package, args.prefix, args.check_only)
    except (OSError, ValueError, tarfile.TarError, EOFError) as error:
        print(f"trust-setup: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
