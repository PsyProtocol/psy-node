#!/usr/bin/env python3
"""Pinned local-lab build preparation. Never installs, deploys, resets or pushes."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^[a-zA-Z0-9./_-]+@sha256:[0-9a-f]{64}$")


def run(argv, *, capture=False, cwd=None, env=None):
    result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                            check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temp.replace(path)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def policy(path):
    data = json.loads(Path(path).read_text())
    if data.get("schema_version") != 1 or data.get("stage") != "localhost":
        raise ValueError("Only the explicit localhost lab build policy is supported")
    if data.get("deployment_authorized") is not False:
        raise ValueError("This entrypoint is build-only")
    for spec in data["sources"].values():
        if not SHA.fullmatch(spec["commit"]):
            raise ValueError("Source pins must be full commit IDs")
        if spec["repository"] not in {"PsyProtocol/psy-node", "PsyProtocol/psy-services", "PsyProtocol/psy-genesis"}:
            raise ValueError("Unexpected source repository")
        for key, value in spec.items():
            if key.endswith("_sha256") and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Invalid source input hash")
    for key in ("builder_base", "runtime_base"):
        if not IMAGE_DIGEST.fullmatch(data["toolchain"][key]):
            raise ValueError("Base images must be pinned by registry digest")
    for ref in data["dependency_images"].values():
        if not IMAGE_DIGEST.fullmatch(ref):
            raise ValueError("Dependency images must be pinned by registry digest")
    if data["toolchain"]["rustflags"] != "-C target-cpu=x86-64" or data["toolchain"]["goamd64"] != "v1":
        raise ValueError("This profile only supports explicit portable CPU targets")
    for name, item in data["components"].items():
        if not all(re.fullmatch(r"[a-zA-Z0-9_-]+", value) for value in (name, item["binary"], item["image"])):
            raise ValueError("Unsafe component/image/binary name")
        if item["source"] not in data["sources"]:
            raise ValueError("Unknown component source")
    limits = data["build_limits"]
    if not all(isinstance(limits[key], int) and limits[key] > 0 for key in ("jobs", "cpus", "minimum_free_gib")):
        raise ValueError("Build limits must be positive integers")
    return data


def git(repo, *args):
    return run(["git", "--no-optional-locks", "-C", repo, *args], capture=True)


def repository_name(repo):
    url = git(repo, "remote", "get-url", "origin").removesuffix(".git")
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if url.startswith(prefix):
            return url[len(prefix):]
    raise ValueError("Source origin must be a canonical GitHub repository")


def source_check(root, name, spec):
    repo = root / "sources" / name
    if git(repo, "rev-parse", "HEAD") != spec["commit"]:
        raise ValueError(f"{name}: source commit changed")
    if repository_name(repo) != spec["repository"]:
        raise ValueError(f"{name}: source origin changed")
    if git(repo, "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=all"):
        raise ValueError(f"{name}: frozen source contains changes")
    if "lock_sha256" in spec and sha(repo / "Cargo.lock") != spec["lock_sha256"]:
        raise ValueError(f"{name}: Cargo.lock hash mismatch")
    return repo


def inputs_check(root, config):
    paths = {name: source_check(root, name, spec) for name, spec in config["sources"].items()}
    genesis = paths["genesis"]
    for field, filename in (("config_sha256", "config.json"), ("contracts_sha256", "genesis_contracts.json")):
        if sha(genesis / filename) != config["sources"]["genesis"][field]:
            raise ValueError(f"Genesis {filename} hash mismatch")
    for name in ("node", "services", "indexer"):
        toolchain = tomllib.loads((paths[name] / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        if toolchain != config["toolchain"]["rust"]:
            raise ValueError(f"{name}: toolchain differs from build policy")
    link = git(paths["node"], "ls-tree", "HEAD", "psy-genesis").split()
    if not link or link[2] != config["sources"]["genesis"]["commit"]:
        raise ValueError("Node Genesis gitlink does not match the pinned Genesis")
    return paths


def prepare(args, config):
    root = args.output.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("Prepare requires a new empty output directory; existing outputs are preserved")
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o750)
    local = {"node": args.node_repo, "services": args.services_repo,
             "indexer": args.services_repo, "genesis": args.genesis_repo}
    origins = {}
    for name, spec in config["sources"].items():
        source = local[name].resolve()
        if repository_name(source) != spec["repository"]:
            raise ValueError(f"{name}: local object source origin mismatch")
        git(source, "cat-file", "-e", spec["commit"] + "^{commit}")
        if "lock_sha256" in spec:
            content = subprocess.check_output(["git", "-C", str(source), "show", spec["commit"] + ":Cargo.lock"])
            if hashlib.sha256(content).hexdigest() != spec["lock_sha256"]:
                raise ValueError(f"{name}: selected committed lock hash mismatch")
        destination = root / "sources" / name
        run(["git", "clone", "--shared", "--no-checkout", source, destination])
        git(destination, "checkout", "--detach", spec["commit"])
        git(destination, "remote", "set-url", "origin", "https://github.com/" + spec["repository"] + ".git")
        common = Path(git(source, "rev-parse", "--git-common-dir"))
        common = (source / common).resolve() if not common.is_absolute() else common.resolve()
        origins[name] = str(common / "objects")
    # Genesis remains its own pinned checkout. A read-only container mount provides
    # /src/psy-genesis without mutating the node gitlink or the original worktrees.
    inputs_check(root, config)
    write_json(root / "prepared.json", {"created_utc": utc(), "policy_sha256": sha(args.versions),
               "sources": config["sources"], "object_directories": origins,
               "note": "Local object stores are read-only build dependencies; keep them until the build finishes"})
    print(root / "prepared.json")


def prepared(root, args, config):
    receipt = json.loads((root / "prepared.json").read_text())
    if receipt["policy_sha256"] != sha(args.versions):
        raise ValueError("Build policy changed after source preparation; prepare a new output directory")
    inputs_check(root, config)
    return receipt


def inspect_image(image):
    item = json.loads(run(["docker", "image", "inspect", image], capture=True))[0]
    if item["Architecture"] != "amd64" or item["Os"] != "linux":
        raise ValueError("This build profile requires linux/amd64 images")
    return item


def docker_env():
    # Prefer BuildKit when available; do not silently install a host plugin.
    available = subprocess.run(["docker", "buildx", "version"], capture_output=True).returncode == 0
    return dict(os.environ, DOCKER_BUILDKIT="1" if available else "0")


def builder(args, config):
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.use_builder:
        image_id = inspect_image(args.use_builder)["Id"]
    else:
        tools = config["toolchain"]
        tag = "psy-k8s-builder:" + sha(args.versions)[:12]
        command = ["docker", "build", "--platform", "linux/amd64", "-f", HERE / "Dockerfile.builder", "-t", tag]
        for key, value in {"BUILDER_BASE": tools["builder_base"], "GO_VERSION": tools["go"],
                           "GO_SHA256": tools["go_archive_sha256"], "RUST_TOOLCHAIN": tools["rust"]}.items():
            command += ["--build-arg", key + "=" + value]
        # The context contains only the Dockerfile, never a developer workspace.
        with tempfile.TemporaryDirectory(prefix="psy-builder-") as temp:
            shutil.copyfile(HERE / "Dockerfile.builder", Path(temp) / "Dockerfile")
            run(command + [temp], env=docker_env())
        image_id = inspect_image(tag)["Id"]
    tools = config["toolchain"]
    identity = run(["docker", "run", "--rm", "--network", "none", "-e", "RUSTUP_TOOLCHAIN=" + tools["rust"],
                    image_id, "sh", "-c", "rustc --version && cargo --version && go version && ldd --version | head -1"], capture=True)
    if not identity.startswith(tools["rust_version_prefix"]) or "go version go" + tools["go"] + " " not in identity:
        raise ValueError("Builder compiler identities do not match the pinned policy")
    write_json(root / "builder.json", {"image_id": image_id, "identity": identity, "policy_sha256": sha(args.versions),
               "recipe_sha256": sha(HERE / "Dockerfile.builder"), "created_utc": utc(),
               "basis": "verified-existing-image" if args.use_builder else "built-from-pinned-bases"})
    print(root / "builder.json")


def select_components(args, config):
    if args.component == "all":
        return list(config["components"])
    names = args.component.split(",")
    if not names or len(set(names)) != len(names) or any(x not in config["components"] for x in names):
        raise ValueError("Unknown or duplicate component; choose " + ",".join(config["components"]))
    return names


def compile_plan(args, config):
    groups = {}
    for name in select_components(args, config):
        item = config["components"][name]
        groups.setdefault(item["source"], []).append(item["binary"])
    return {"stage": config["stage"], "toolchain": config["toolchain"], "limits": config["build_limits"],
            "groups": groups, "sources": config["sources"], "remaining_images": config["remaining_images"],
            "deployment_authorized": False}


def object_mounts(receipt):
    directories = sorted(set(receipt["object_directories"].values()))
    return [value for path in directories for value in ["-v", path + ":" + path + ":ro"]]


def container_identity(directory, image_id, uid, gid):
    """Provide NSS identity without modifying the builder image or host accounts."""
    directory.mkdir(parents=True, exist_ok=True)
    mounts = []
    for filename, number, entry in (
        ("passwd", uid, f"psy-build-{uid}:x:{uid}:{gid}:Psy build:/cache/home:/bin/sh"),
        ("group", gid, f"psy-build-{gid}:x:{gid}:"),
    ):
        original = run(["docker", "run", "--rm", "--network", "none", "--read-only",
                        "--entrypoint", "/bin/cat", image_id, "/etc/" + filename], capture=True)
        rows = original.splitlines()
        if not any(len(row.split(":")) >= 3 and row.split(":")[2] == str(number) for row in rows):
            rows.append(entry)
        path = directory / filename
        path.write_text("\n".join(rows) + "\n")
        path.chmod(0o644)
        mounts += ["-v", f"{path}:/etc/{filename}:ro"]
    return mounts


def compile_sources(args, config):
    root = args.output.resolve()
    receipt = prepared(root, args, config)
    b = json.loads((root / "builder.json").read_text())
    if b["policy_sha256"] != sha(args.versions):
        raise ValueError("Builder policy hash mismatch")
    image_id = inspect_image(b["image_id"])["Id"]
    free = shutil.disk_usage(root).free / 2**30
    if free < config["build_limits"]["minimum_free_gib"]:
        raise ValueError(f"Only {free:.1f} GiB free; this full build profile requires at least {config['build_limits']['minimum_free_gib']} GiB")
    groups = compile_plan(args, config)["groups"]
    for name, binaries in groups.items():
        cache = root / "cache" / (name + "-" + sha(args.versions)[:12])
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "home").mkdir(exist_ok=True)
        tools, limits = config["toolchain"], config["build_limits"]
        command = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--cpus", str(limits["cpus"]), "--memory", limits["memory"], "--memory-swap", limits["memory"],
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-v", f"{cache}:/cache",
                   "-v", f"{root / 'sources' / name}:/src:ro", "-v", f"{root / 'sources' / 'genesis'}:/genesis:ro"]
        if name == "node":
            command += ["-v", f"{root / 'sources' / 'genesis'}:/src/psy-genesis:ro"]
        command += object_mounts(receipt)
        command += container_identity(cache / "identity", image_id, os.getuid(), os.getgid())
        environment = {"RUSTUP_TOOLCHAIN": tools["rust"], "CARGO_HOME": "/cache/cargo", "CARGO_TARGET_DIR": "/cache/target",
                       "CARGO_BUILD_JOBS": str(limits["jobs"]), "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
                       "RUSTFLAGS": tools["rustflags"], "PSY_NETWORK": config["stage"], "PSY_CONFIG_PATH": "/genesis/config.json",
                       "GOAMD64": tools["goamd64"], "GOTOOLCHAIN": "local", "GOCACHE": "/cache/go-build",
                       "GOMODCACHE": "/cache/go-mod", "GIT_OPTIONAL_LOCKS": "0", "HOME": "/cache/home"}
        # Private Cargo Git dependencies use an agent socket, never copied key material.
        if args.ssh_agent:
            if not args.known_hosts or not args.known_hosts.is_file():
                raise ValueError("SSH forwarding requires an explicit verified known_hosts file")
            if not Path(args.ssh_agent).is_socket():
                raise ValueError("SSH agent path is not a socket")
            command += ["-v", args.ssh_agent + ":/run/build-agent", "-v", str(args.known_hosts.resolve()) + ":/run/known_hosts:ro"]
            environment.update(SSH_AUTH_SOCK="/run/build-agent", GIT_SSH_COMMAND="ssh -F /dev/null -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/known_hosts")
        for key, value in environment.items():
            command += ["-e", key + "=" + value]
        cargo = ["cargo", "build", "--locked", "--release", "--target", tools["target"]]
        if args.offline:
            cargo += ["--offline"]
        for binary in binaries:
            cargo += ["--bin", binary]
        command += ["-w", "/src", image_id, *cargo]
        run(command)
        inputs_check(root, config)
        for component in select_components(args, config):
            item = config["components"][component]
            if item["source"] != name:
                continue
            path = root / "artifacts" / component
            path.mkdir(parents=True, exist_ok=True)
            target = path / item["binary"]
            shutil.copyfile(cache / "target" / tools["target"] / "release" / item["binary"], target)
            target.chmod(0o755)
            header = run(["readelf", "-h", target], capture=True)
            if "Advanced Micro Devices X86-64" not in header:
                raise ValueError("Artifact is not an x86-64 ELF binary")
            dynamic = run(["objdump", "-T", target], capture=True)
            versions = {tuple(int(x) for x in v.split(".")) for v in re.findall(r"GLIBC_([0-9.]+)", dynamic)}
            maximum = max(versions) if versions else ()
            if not maximum or maximum > tuple(map(int, tools["max_glibc"].split("."))):
                raise ValueError(f"{component}: unsupported GLIBC requirement")
            write_json(path / "artifact.json", {"component": component, "binary": item["binary"], "binary_sha256": sha(target),
                       "source": config["sources"][name], "builder_image_id": image_id, "policy_sha256": sha(args.versions),
                       "toolchain": tools, "stage": config["stage"], "genesis": config["sources"]["genesis"],
                       "max_glibc": ".".join(map(str, maximum)), "created_utc": utc(), "business_validation": "not-run"})
        print(f"Compiled {name}: {', '.join(binaries)}")


def artifact_check(root, name, args, config):
    item = config["components"][name]
    path = root / "artifacts" / name
    receipt = json.loads((path / "artifact.json").read_text())
    expected = {"component": name, "binary": item["binary"], "policy_sha256": sha(args.versions),
                "source": config["sources"][item["source"]], "stage": config["stage"],
                "toolchain": config["toolchain"], "genesis": config["sources"]["genesis"]}
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError(f"{name}: artifact receipt field mismatch: {key}")
    binary = path / item["binary"]
    if not binary.is_file() or binary.is_symlink() or sha(binary) != receipt["binary_sha256"]:
        raise ValueError(f"{name}: binary hash/type mismatch")
    if not DIGEST.fullmatch(receipt["builder_image_id"]):
        raise ValueError("Missing immutable builder identity")
    builder_receipt = json.loads((root / "builder.json").read_text())
    if builder_receipt["policy_sha256"] != sha(args.versions) or receipt["builder_image_id"] != builder_receipt["image_id"]:
        raise ValueError("Artifact was built with a different builder")
    return receipt


def copy_tracked_resources(source, destination):
    paths = git(source, "ls-files", "-z", "migrations", "genesis_contracts").split("\0")
    for relative in filter(None, paths):
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or (source / path).is_symlink():
            raise ValueError("Unsafe public resource path")
        if path.suffix not in {".json", ".sql", ".md", ".txt"}:
            raise ValueError(f"Unexpected runtime resource type: {relative}")
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / path, target)


def build_images(args, config):
    root = args.output.resolve()
    prepared(root, args, config)
    names = select_components(args, config)
    artifacts = {name: artifact_check(root, name, args, config) for name in names}
    runtime_tag = "psy-k8s-runtime:" + sha(args.versions)[:12]
    with tempfile.TemporaryDirectory(prefix="psy-runtime-base-") as temp:
        shutil.copyfile(HERE / "Dockerfile.runtime-base", Path(temp) / "Dockerfile")
        run(["docker", "build", "--platform", "linux/amd64", "--build-arg", "RUNTIME_BASE=" + config["toolchain"]["runtime_base"],
             "-t", runtime_tag, temp], env=docker_env())
    runtime_id = inspect_image(runtime_tag)["Id"]
    packages = run(["docker", "run", "--rm", "--network", "none", runtime_id, "dpkg-query", "-W"], capture=True)
    write_json(root / "runtime-base.json", {"image_id": runtime_id, "packages": packages,
               "policy_sha256": sha(args.versions), "recipe_sha256": sha(HERE / "Dockerfile.runtime-base")})
    images = {}
    for name in names:
        item, receipt = config["components"][name], artifacts[name]
        source = config["sources"][item["source"]]
        tag = args.image_prefix + "/" + item["image"] + ":local-" + source["commit"][:12] + "-" + sha(args.versions)[:8]
        with tempfile.TemporaryDirectory(prefix="psy-image-") as temp:
            context = Path(temp)
            app = context / "app"
            app.mkdir()
            shutil.copy2(root / "artifacts" / name / item["binary"], app / item["binary"])
            write_json(app / "BUILD-MANIFEST.json", receipt)
            # Explicit public runtime resources only; no copy of an entire source tree.
            if name in ("services", "indexer"):
                src = root / "sources" / item["source"]
                copy_tracked_resources(src, app)
            recipe = (HERE / "Dockerfile.runtime").read_text()
            recipe += "\nENTRYPOINT " + json.dumps(["/app/" + item["binary"]]) + "\n"
            (context / "Dockerfile").write_text(recipe)
            run(["docker", "build", "--platform", "linux/amd64", "--build-arg", "RUNTIME_IMAGE=" + runtime_id,
                 "--label", "org.opencontainers.image.revision=" + source["commit"],
                 "--label", "org.opencontainers.image.source=https://github.com/" + source["repository"],
                 "--label", "org.psy.build.policy-sha256=" + sha(args.versions), "-t", tag, context], env=docker_env())
        image_id = inspect_image(tag)["Id"]
        # No business traffic, keys or state; verify dynamic linking and CLI startup only.
        run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1", image_id, "--help"])
        images[name] = {"tag": tag, "image_id": image_id, "registry_digest": None,
                        "artifact_sha256": receipt["binary_sha256"], "source_commit": source["commit"],
                        "validation": "CLI-help-only; no proofs or E2E"}
    existing = root / "images.json"
    previous = json.loads(existing.read_text()) if existing.exists() else {"images": {}}
    if previous.get("policy_sha256", sha(args.versions)) != sha(args.versions):
        raise ValueError("Existing image receipt belongs to a different build policy")
    previous["images"].update(images)
    previous.update(policy_sha256=sha(args.versions), created_utc=utc(), deployment_authorized=False,
                    remaining_images=config["remaining_images"], registry_push="not-performed")
    write_json(existing, previous)
    print(existing)


def verify(args, config):
    root = args.output.resolve()
    prepared(root, args, config)
    for name in select_components(args, config):
        artifact_check(root, name, args, config)
    print("Source, policy, stage, Genesis, toolchain and binary hashes verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "prepare", "builder", "compile", "images", "verify"])
    parser.add_argument("--versions", type=Path, default=HERE / "versions.json")
    parser.add_argument("--output", type=Path, default=HERE.parents[2] / "dist" / "kubernetes-build")
    parser.add_argument("--component", default="all")
    parser.add_argument("--image-prefix", default="psy-local")
    parser.add_argument("--node-repo", type=Path)
    parser.add_argument("--services-repo", type=Path)
    parser.add_argument("--genesis-repo", type=Path)
    parser.add_argument("--use-builder", help="An existing builder image, verified and frozen to its image ID")
    parser.add_argument("--ssh-agent", help="Optional SSH agent socket for private Cargo dependencies")
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    config = policy(args.versions)
    select_components(args, config)
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*", args.image_prefix):
        raise ValueError("Invalid local image prefix")
    if args.command == "plan":
        print(json.dumps(compile_plan(args, config), indent=2))
    elif args.command == "prepare":
        if not all((args.node_repo, args.services_repo, args.genesis_repo)):
            parser.error("prepare requires --node-repo, --services-repo and --genesis-repo")
        prepare(args, config)
    else:
        {"builder": builder, "compile": compile_sources, "images": build_images, "verify": verify}[args.command](args, config)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f"build preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
