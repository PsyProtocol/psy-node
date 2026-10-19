#!/usr/bin/env python3
"""Envio 2.32.10 opt-in reorg guard: read each fetch range's parent block from the RPC, not the block cache.

Enabled at runtime by PSY_ENVIO_FRESH_REORG_PARENT=1; otherwise the upstream expression runs.
Usage: fresh-reorg-parent.py <envio-home> [--check]
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

ENVIO_VERSION = "2.32.10"
MARKER = "psyFreshReorgParent"
ENV_NAME = "PSY_ENVIO_FRESH_REORG_PARENT"
JS_FUNCTION = 'function () { return process.env.' + ENV_NAME + ' === "1"; }'

RES_EDITS = [
    (
        "let getKnownBlock = (provider, blockNumber) =>\n",
        "let " + MARKER + ": unit => bool = %raw(`" + JS_FUNCTION + "`)\n\n"
        "let getKnownBlock = (provider, blockNumber) =>\n",
    ),
    (
        "? blockLoader.contents->LazyLoader.get(fromBlock - 1)->Promise.thenResolve(res => res->Some)",
        "? (\n"
        "            " + MARKER + "()\n"
        "              ? getKnownBlockWithBackoff(\n"
        "                  ~provider,\n"
        "                  ~sourceName=name,\n"
        "                  ~chain,\n"
        "                  ~backoffMsOnFailure=1000,\n"
        "                  ~blockNumber=fromBlock - 1,\n"
        "                  ~lowercaseAddresses,\n"
        "                )\n"
        "              : blockLoader.contents->LazyLoader.get(fromBlock - 1)\n"
        "          )->Promise.thenResolve(res => res->Some)",
    ),
]
JS_EDITS = [
    (
        "function getKnownBlock(provider, blockNumber) {\n",
        "var " + MARKER + " = " + JS_FUNCTION + ";\n\n"
        "function getKnownBlock(provider, blockNumber) {\n",
    ),
    (
        "fromBlock > 0 ? LazyLoader.get(blockLoader.contents, fromBlock - 1 | 0).then(",
        "fromBlock > 0 ? (" + MARKER + "() ? getKnownBlockWithBackoff(provider, name, chain, fromBlock - 1 | 0, 1000, lowercaseAddresses)"
        " : LazyLoader.get(blockLoader.contents, fromBlock - 1 | 0)).then(",
    ),
]
# The ReScript compiler re-emits the .res.js from the patched .res, so the checks accept its layout too.
RES_CHECKS = [
    r"let psyFreshReorgParent: unit => bool = %raw\(`" + re.escape(JS_FUNCTION) + r"`\)",
    r"psyFreshReorgParent\(\)\s*\?\s*getKnownBlockWithBackoff\(\s*~provider,\s*~sourceName=name,\s*~chain,"
    r"\s*~backoffMsOnFailure=1000,\s*~blockNumber=fromBlock - 1,\s*~lowercaseAddresses,\s*\)"
    r"\s*:\s*blockLoader\.contents->LazyLoader\.get\(fromBlock - 1\)\s*\)->Promise\.thenResolve",
]
JS_CHECKS = [
    r"var psyFreshReorgParent = \(?" + re.escape(JS_FUNCTION) + r"\)?;",
    r"fromBlock > 0 \? \(\s*psyFreshReorgParent\(\)\s*\?\s*getKnownBlockWithBackoff\(provider, name, chain,"
    r" fromBlock - 1 \| 0, 1000, lowercaseAddresses\)\s*:\s*LazyLoader\.get\(blockLoader\.contents, fromBlock - 1 \| 0\)\s*\)\.then\(",
]


def apply_edit_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("Unexpected upstream RpcSource layout; anchor must occur exactly once: " + old.splitlines()[0])
    return text.replace(old, new)


def check_patched(text, checks, path):
    for pattern in checks:
        if len(re.findall(pattern, text)) != 1:
            raise RuntimeError(str(path) + ": fresh reorg parent patch missing or duplicated: " + pattern)


def find_envio_packages(home):
    packages = set()
    for base in (home / "node_modules", home / "generated/node_modules"):
        package = base / "envio"
        if package.exists():
            resolved = package.resolve()
            if not resolved.is_relative_to(home):
                raise RuntimeError("Envio dependency resolves outside the Envio home: " + str(resolved))
            packages.add(resolved)
    if not packages:
        raise RuntimeError("No installed Envio dependency under " + str(home))
    return sorted(packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("home", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    home = args.home.resolve()
    patched_files = []
    for package in find_envio_packages(home):
        version = json.loads((package / "package.json").read_text(encoding="utf-8"))["version"].lstrip("v")
        if version != ENVIO_VERSION:
            raise RuntimeError("Envio " + version + " is not " + ENVIO_VERSION + "; review the patch against it first")
        for name, edits, checks in (("RpcSource.res", RES_EDITS, RES_CHECKS), ("RpcSource.res.js", JS_EDITS, JS_CHECKS)):
            path = package / "src/sources" / name
            text = path.read_text(encoding="utf-8")
            is_applied = MARKER in text
            if not is_applied:
                if args.check:
                    raise RuntimeError(str(path) + ": fresh reorg parent patch is not applied")
                for old, new in edits:
                    text = apply_edit_once(text, old, new)
            check_patched(text, checks, path)
            patched_files.append((path, text, is_applied))
    for path, text, is_applied in patched_files:
        if not is_applied:
            staged = path.with_name(path.name + ".fresh-reorg-parent-next")
            staged.write_text(text, encoding="utf-8")
            staged.chmod(path.stat().st_mode & 0o777)
            staged.replace(path)
    reports = []
    for path, text, _ in patched_files:
        if path.name.endswith(".js"):
            subprocess.run(["node", "--check", str(path)], check=True)
        reports.append({"file": str(path.relative_to(home)), "sha256": hashlib.sha256(text.encode()).hexdigest()})
    print(json.dumps({"patch": "fresh-reorg-parent", "check": args.check, "files": reports}))


if __name__ == "__main__":
    main()
