#!/usr/bin/env python3
"""Validate generated verifiers offline and record the matching setup files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

MAGIC = "0x1337CF514544CF69"
COHORTS = {
    "bridge_agg": "GnarkGroth16Verifier.sol",
    "deposit_append": "DepositBatchVerifier.sol",
    "withdrawal_claim": "WithdrawalClaimVerifier.sol",
    "reward_claim": "RewardClaimVerifier.sol",
}
KEY_FILES = ("circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin")
OUTPUTS = ("evm-verification.json", "setup-manifest.json", "verifiers.json")
CHECKER = Path(__file__).resolve().parent / "verify_bridge_setup.cjs"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value, mode="x"):
    with path.open(mode) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def export_verifier(binary, config, keystore, target):
    env = {**os.environ, "PSY_NETWORK": "testnet", "PSY_CONFIG_PATH": str(config)}
    subprocess.run([str(binary), "export-solidity-verifier", str(keystore), str(target)],
                   env=env, check=True, capture_output=True, timeout=600)


def check_inputs(setup, contracts, binary, config, build, export):
    if build.get("network") != "testnet":
        raise ValueError("build network is not testnet")
    if build.get("network_magic") != MAGIC:
        raise ValueError("build network magic is not " + MAGIC)
    if digest(binary) != build["binaries"]["psy_relayer_cli"]:
        raise ValueError("binary hash differs from the build manifest")
    if digest(config) != build["config_sha256"]:
        raise ValueError("config hash differs from the build manifest")
    verifiers, files = {}, {}
    for cohort, verifier in COHORTS.items():
        log = (setup / (cohort + ".log")).read_text()
        if "[prove] groth16.Verify took " not in log:
            raise ValueError(cohort + ": native verification missing")
        if sum(line.startswith("proofString ") for line in log.splitlines()) != 1:
            raise ValueError(cohort + ": expected exactly one proof")
        verifiers[cohort] = digest(setup / verifier)
        if digest(contracts / "src" / verifier) != verifiers[cohort]:
            raise ValueError(cohort + ": contract source differs from the export")
        keystore = setup / "keystore" / ("" if cohort == "bridge_agg" else cohort)
        with tempfile.TemporaryDirectory() as scratch:
            export(binary, config, keystore, Path(scratch) / verifier)
            if digest(Path(scratch) / verifier) != verifiers[cohort]:
                raise ValueError(cohort + ": keystore re-export differs from the verifier")
        for name in KEY_FILES:
            relative = name if cohort == "bridge_agg" else cohort + "/" + name
            path = setup / "keystore" / relative
            if path.stat().st_size == 0:
                raise ValueError(relative + " is empty")
            files[relative] = {"sha256": digest(path), "size": path.stat().st_size}
    return verifiers, files


def finalize(setup, contracts, binary, config, build_manifest, checker=CHECKER,
             run=subprocess.run, export=export_verifier):
    setup, contracts = Path(setup), Path(contracts)
    for name in OUTPUTS:
        if (setup / name).exists():
            raise ValueError(name + " already exists; inspect before a rerun")
    build = json.loads(Path(build_manifest).read_text())
    verifiers, files = check_inputs(setup, contracts, Path(binary), Path(config), build, export)
    completed = run(["node", str(checker), str(contracts), str(setup)],
                    text=True, capture_output=True, timeout=600)
    evidence = "evm-verification.json" if completed.returncode == 0 else "evm-verification.failed.json"
    save(setup / evidence, {
        "exit_code": completed.returncode, "stdout": completed.stdout,
        "stderr": completed.stderr, "checker_sha256": digest(checker),
        "verifier_solidity_sha256": verifiers,
    }, "x" if completed.returncode == 0 else "w")
    if completed.returncode:
        print(completed.stderr)
        raise SystemExit(completed.returncode)
    common = {field: build[field] for field in (
        "source_commit", "config_sha256", "local_circuits_sha256")}
    save(setup / "setup-manifest.json", {
        "version": 1, "network": "testnet", "magic": MAGIC,
        "consumer": {**common, "binary_sha256": build["binaries"]["psy_user_cli"]},
        "generator": {**common, "binary_sha256": digest(binary)},
        "verifier_solidity_sha256": verifiers, "files": files,
    })
    save(setup / "verifiers.json", {"src/" + COHORTS[c]: v for c, v in verifiers.items()})
    return digest(setup / "setup-manifest.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("setup", "contracts", "binary", "config", "build-manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    print("setup manifest sha256:", finalize(
        args.setup, args.contracts, args.binary, args.config, args.build_manifest))


if __name__ == "__main__":
    main()
