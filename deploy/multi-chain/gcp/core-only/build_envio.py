#!/usr/bin/env python3
"""Build the Envio package from a prepared source directory with no network access.

usage: build_envio.py <prepared source dir> <new output dir>

Environment: PSY_ENVIO_NODE is the pinned Node binary, PSY_ENVIO_PNPM_STORE the populated pnpm store and
PSY_ENVIO_WORKSPACE_LOCK the reviewed pnpm lock that includes the generated workspace; nothing under them is modified. The output holds the source files, the bundled Node, the frozen dependencies,
the generated and patched indexer and build.json, the evidence the controller and install_envio.py check.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import yaml

import install_envio as install

NODE_VERSION = "v22.23.4"
PNPM_VERSION = "10.15.0"
STEP_SECONDS = 1800
PENDING_FLAGS = ("l1_documents_pending", "placement_pending", "rpc_routes_pending", "dependency_lock_pending")
PNPM_INSTALL = ["pnpm", "install", "--offline", "--frozen-lockfile", "--ignore-scripts", "--package-import-method=copy"]
PATCHES = ("history.py", "polling.py", "reorg.py")
PROBE = r"""
require('net').Socket.prototype.connect = () => { throw Error('Network forbidden in build check'); };
require('ts-node').register({transpileOnly:true,compilerOptions:{module:'CommonJS',moduleResolution:'node'}});
const assert=require('assert/strict');
const g=require('./src/Generated.res.js'), cm=require('envio/src/ChainMap.res.js');
const expected=JSON.parse(process.argv[1]);
const actual=cm.values(g.configWithoutRegistrations.chainMap);
assert.equal(actual.length,expected.length);
for(const n of expected){
 const c=actual.find(c=>c.id===n.id); assert(c);
 assert.equal(c.startBlock,n.start_block); assert.equal(c.maxReorgDepth,n.confirmed_block_threshold);
 for(const contract of n.contracts){
  const generated=c.contracts.find(x=>x.name===contract.name); assert(generated);
  assert.deepEqual(generated.addresses.map(a=>a.toLowerCase()),contract.address.map(a=>a.toLowerCase()));
 }
 assert.deepEqual(c.sources.map(s=>s.sourceFor),n.rpc.map(s=>s.for==='sync'?'Sync':'Fallback'));
 assert(c.sources.every(s=>s.pollingInterval===12000));
}
g.registerAllHandlers();
console.log(JSON.stringify({generated_config_verified:true,handlers_registered:true,chains:actual.map(c=>c.id)}));
process.exit(0);
"""


class Build:
    def __init__(self, output, node, store):
        self.output = output
        self.logs = output.with_name(output.name + ".logs")
        self.steps = 0
        self.environment = {
            "PATH": f"{output / 'node/bin'}:/usr/bin:/bin", "HOME": str(self.logs), "CI": "true",
            "ENVIO_RPC_POLLING_INTERVAL_MILLIS": "12000", "PSY_ENVIO_FRESH_REORG_PARENT": "1",
            "npm_config_offline": "true", "npm_config_frozen_lockfile": "true", "npm_config_store_dir": str(store),
            "TS_NODE_COMPILER_OPTIONS": '{"module":"CommonJS","moduleResolution":"node","noImplicitAny":false}'}

    def run(self, argv, cwd=None):
        self.steps += 1
        result = subprocess.run([str(part) for part in argv], cwd=cwd or self.output, env=self.environment,
                                capture_output=True, timeout=STEP_SECONDS, check=False)
        (self.logs / f"step-{self.steps:02d}.log").write_bytes(result.stdout + result.stderr)
        install.require(result.returncode == 0, f"build step {self.steps} failed: {Path(str(argv[0])).name}; see {self.logs.name}")
        return result.stdout.decode()


def read_source(source):
    manifest = json.loads(install.read(source / "manifest.json"))
    install.require(not any(manifest[name] for name in PENDING_FLAGS), "complete prepared inputs required")
    for name, expected in manifest["files"].items():
        install.require(install.sha(install.read(source / name)) == expected, f"prepared input changed: {name}")
    return manifest


def read_importers(root):
    return yaml.safe_load(install.read(root / "pnpm-lock.yaml"))["importers"]


def pinned_node(path):
    node = Path(path)
    install.require(node.is_file(), "PSY_ENVIO_NODE does not name a file")
    version = subprocess.run([str(node), "--version"], capture_output=True, text=True, check=False).stdout.strip()
    install.require(version == NODE_VERSION, "Node version differs from the pinned one")
    return node


def apply_patches(build, runtime):
    for name in PATCHES:
        argv = ["python3", "-B", build.output / "patches" / name]
        if name in ("history.py", "polling.py"):
            argv.append("--home")
        build.run([*argv, build.output])
    if runtime["PSY_ENVIO_ORDERED_FAILOVER"] == "1":
        build.run(["python3", "-B", build.output / "patches/ordered.py", build.output])


def check_patches(build, runtime):
    names = PATCHES + (("ordered.py",) if runtime["PSY_ENVIO_ORDERED_FAILOVER"] == "1" else ())
    for name in names:
        argv = ["python3", "-B", build.output / "patches" / name]
        if name in ("history.py", "polling.py"):
            argv.append("--home")
        build.run([*argv, build.output, "--check"])


def install_workspace_lock(output, workspace_lock, root_importer):
    """Codegen adds the generated workspace; offline pnpm cannot resolve it, so the reviewed complete lock replaces the source lock."""
    raw = install.read(workspace_lock)
    importers = yaml.safe_load(raw)["importers"]
    install.require(set(importers) == {".", "generated"} and importers["."] == root_importer,
                    "the workspace lock differs from the reviewed root dependencies")
    (output / "pnpm-lock.yaml").write_bytes(raw)


def run_build(build, runtime, workspace_lock):
    install.require(build.run(["pnpm", "--version"]).strip() == PNPM_VERSION, "pnpm version differs from the pinned one")
    build.run(PNPM_INSTALL)
    root_importer = read_importers(build.output)["."]
    build.run([build.output / "node/bin/node", "node_modules/envio/bin.js", "codegen"])
    install_workspace_lock(build.output, workspace_lock, root_importer)
    build.run(PNPM_INSTALL)
    apply_patches(build, runtime)
    generated = build.output / "generated"
    build.run(["pnpm", "exec", "rescript", "build"], generated)
    check_patches(build, runtime)
    build.run([build.output / "node/bin/node", "node_modules/ts-node/dist/bin.js", "src/Index.res.js", "--help"], generated)
    config = yaml.safe_load(install.read(build.output / "config.yaml"))
    probe = json.loads(build.run([build.output / "node/bin/node", "-e", PROBE, json.dumps(config["networks"])], generated))
    install.require(probe.get("generated_config_verified") is True, "generated config probe failed")


def build_package(source, output, node, store, workspace_lock):
    manifest = read_source(source)
    install.require(not os.path.lexists(output) and not os.path.lexists(output.with_name(output.name + ".logs")),
                    "a new output directory is required")
    install.require(Path(store).is_dir(), "PSY_ENVIO_PNPM_STORE does not name a directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    build = Build(output, pinned_node(node), store)
    build.logs.mkdir(mode=0o700)
    shutil.copytree(source, output, symlinks=True)
    bundled = output / "node/bin/node"
    bundled.parent.mkdir(parents=True)
    shutil.copyfile(node, bundled)
    bundled.chmod(0o700)
    runtime = json.loads(install.read(output / "runtime-env.json"))
    run_build(build, runtime, workspace_lock)
    lock_hash = install.sha(install.read(output / "pnpm-lock.yaml"))
    evidence = {"source_commit": manifest["source_commit"], "node_sha256": install.sha(install.read(bundled)),
                "node_version": NODE_VERSION.lstrip("v"), "pnpm_version": PNPM_VERSION, "pnpm_lock_sha256": lock_hash,
                "prepared_manifest_sha256": install.sha(install.read(source / "manifest.json")),
                "frozen_install_verified": True, "patches_verified": True, "native_help_verified": True,
                "generated_config_verified": True, "installed": False, "started": False, "host_checks_passed": False,
                "deployment_ready": False, "release_approved": False, "files": install.inventory(output)}
    path = output / "build.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return install.sha(install.read(path))


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: build_envio.py <prepared source dir> <new output dir>")
    node, store = os.environ.get("PSY_ENVIO_NODE"), os.environ.get("PSY_ENVIO_PNPM_STORE")
    workspace_lock = os.environ.get("PSY_ENVIO_WORKSPACE_LOCK")
    if not node or not store or not workspace_lock:
        raise SystemExit("PSY_ENVIO_NODE, PSY_ENVIO_PNPM_STORE and PSY_ENVIO_WORKSPACE_LOCK must be set")
    os.umask(0o077)
    print(json.dumps({"build_sha256": build_package(Path(argv[1]).absolute(), Path(argv[2]).absolute(), node, store, workspace_lock)}))


if __name__ == "__main__":
    main(sys.argv)
