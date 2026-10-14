#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys
import tarfile

lock = json.loads(Path("assets.lock.json").read_text())["assets"]
for name in ("metallb.tgz", "traefik.tgz", "prometheus.tgz", "gateway-api.yaml", "helm.tgz"):
    with open(name, "rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != lock[name]["sha256"]:
            sys.exit("Asset checksum mismatch: " + name)
with tarfile.open("helm.tgz") as archive:
    expected = hashlib.sha256(archive.extractfile("linux-amd64/helm").read()).hexdigest()
with open("helm", "rb") as stream:
    if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
        sys.exit("Helm executable checksum mismatch")
