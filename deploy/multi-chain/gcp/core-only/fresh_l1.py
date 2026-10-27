#!/usr/bin/env python3
"""Prepare/check a fresh, offline L1 bundle; never reuse old deployment records.

pack --contracts DIR --verifiers JSON --verifiers-sha256 SHA --output NEW_DIR
  JSON is exactly {"src/<Verifier>.sol": "sha256", ...} for all four verifiers.
  Requires frozen pnpm dependencies and freshly compiled Hardhat artifacts.
check --bundle DIR --manifest-sha256 SHA
status --rpc-config /etc/parth/bridge-relayer.toml [--secret-env FILE ...]
prepare --bundle DIR --manifest-sha256 SHA --output NEW_DIR
deploy --bundle DIR --manifest-sha256 SHA --output PREPARED_DIR --network NAME
       --policy JSON --policy-sha256 SHA --execute --node /path/to/node
       --gas-budget JSON --gas-budget-sha256 SHA
       [--secret-env /etc/parth/relayer.env] [--rpc-config FILE] [--keystore FILE]

Only deploy can broadcast. It requires an explicit reviewed public policy:
{"version":1,"deposit_rate_limit":"legacy-amount-bucket-absent-deposits-paused",
 "pause_deposits":true,
 "governance":"deployer-admin-proxy-timelock","networks":{
 "sepolia":{"native":{...},"PSY":{...},"pUSDT":{...}},
 "bscTestnet":{...},"baseSepolia":{...}}}.
Each token has the exact TokenFlowConfig fields (five uint128 amount strings,
three uint32 delay strings, configured:true). No policy defaults are supplied.
The old pUSDT 40,000 amount bucket/refill is not expressible in aee3b39e.
Deposits MUST remain contract-paused; withdrawal registration/claims stay open.
All initial owners/admins/proposer and timelock admin are the verified signer;
only DefaultProxyAdmin transfers to the 48-hour timelock. No role revocations.
Native is keyed by address zero; historical withdrawal totals are zero.

Run on the retained signer's host with sudo and a provisioned Node >=18.
There is no target-side dependency install, compilation, service action, SSH,
automatic deployment retry, reset, or resume. A failed attempt needs review.
Gas budget JSON has exactly maxGasPriceWei, maxGasPerTransaction, maxTotalGas,
maxNativeSpendWei, l1FeeReserveWeiPerTransaction (unsigned decimal strings).
The last is mandatory and positive for Base, a conservative reserve, NOT an
oracle-enforced L1 data-fee cap. Main must review estimates before --execute.
Own-node RPC uses the private gateway in existing relayer config, ports
18545/18645/18945. Fallbacks, if needed, come ONLY from explicitly supplied
protected env files: SEPOLIA_RPC_FALLBACK_URL, BSC_TESTNET_RPC_FALLBACK_URL,
BASE_SEPOLIA_RPC_FALLBACK_URL. RPC URLs and child diagnostics are never printed.
No secrets belong in the bundle, policy, output files, or command arguments.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shlex
import shutil
import stat
import subprocess
import time
import tomllib
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
BASE = "aee3b39ed08f4f4838b63207df3ee5fbb55c53bc"
SOURCE = "5ba12a360c29243b687076997f97e80c2050895b"
SIGNER = "0x490f8192725255C2C3dE0CbCE66312335Ca019Ad"
NETWORKS = {"sepolia": (11155111, 0, 18545, "SEPOLIA"),
            "bscTestnet": (97, 1, 18645, "BSC_TESTNET"),
            "baseSepolia": (84532, 2, 18945, "BASE_SEPOLIA")}
VERIFIERS = {"src/" + name for name in ("GnarkGroth16Verifier.sol", "DepositBatchVerifier.sol",
                                        "WithdrawalClaimVerifier.sol", "RewardClaimVerifier.sol")}
SOURCE_DIRS = {"src", "deploy", "helpers", "protocol-config", "tasks", "scripts", "config"}
SOURCE_FILES = {"package.json", "pnpm-lock.yaml", "tsconfig.json", "hardhat.config.ts",
                "helper-hardhat-config.ts"}
AMOUNTS = ("minDepositAmount", "depositCap", "smallWithdrawalMax", "mediumWithdrawalMax", "totalWithdrawalCap")
DELAYS = ("smallWithdrawalDelay", "mediumWithdrawalDelay", "largeWithdrawalDelay")


class GateError(ValueError):
    pass


def require(value, message):
    if not value:
        raise GateError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path, expected=None):
    if expected is not None:
        require(re.fullmatch(r"[0-9a-f]{64}", expected) and digest(path) == expected, "JSON hash mismatch")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def write_json(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def safe_root(path, new=False):
    path = Path(os.path.abspath(path))
    require(not any(part.startswith("parth") for part in path.parts), "old parth paths forbidden")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symlink directory forbidden")
    if new:
        require(not path.exists(), "output must be a new directory")
        path.mkdir(mode=0o700)
    else:
        require(path.is_dir(), "directory missing")
        s = path.stat()
        require(s.st_uid in (0, os.getuid()) and not s.st_mode & 0o022, "unsafe directory ownership/mode")
    return path


def inventory(root):
    """pnpm relative links are allowed only inside node_modules, never outside it."""
    root = Path(root).resolve()
    result = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = Path(parent) / name
            rel = p.relative_to(root).as_posix()
            s = p.lstat()
            if p.is_symlink():
                target = os.readlink(p)
                module_root = root / "contracts/node_modules"
                require(rel.startswith("contracts/node_modules/") and not os.path.isabs(target)
                        and p.resolve().is_relative_to(module_root) and p.exists(), "unsafe bundle symlink")
                result[rel] = {"link": target}
            elif stat.S_ISREG(s.st_mode):
                require(s.st_uid in (0, os.getuid()) and not s.st_mode & 0o022, "unsafe bundle file")
                result[rel] = {"sha256": digest(p), "size": s.st_size}
            else:
                require(stat.S_ISDIR(s.st_mode), "special bundle file forbidden")
    return result


def validate_build(contracts, exports):
    require(set(exports) == VERIFIERS, "exactly four exported verifier hashes required")
    for name, expected in exports.items():
        require(re.fullmatch(r"[0-9a-f]{64}", expected) and digest(contracts / name) == expected,
                "exported verifier hash mismatch")
    artifacts = list((contracts / "artifacts/hardhat/src").rglob("*.dbg.json"))
    require(artifacts, "compiled source artifacts missing")
    checked = set()
    for debug_file in artifacts:
        artifact = debug_file.with_name(debug_file.name.replace(".dbg.json", ".json"))
        artifact_data = read_json(artifact)
        name = artifact_data["sourceName"]
        debug = read_json(debug_file)
        build_path = (artifact.parent / debug["buildInfo"]).resolve()
        require(build_path.is_relative_to(contracts / "artifacts/hardhat/build-info"), "invalid build-info path")
        build = read_json(build_path)
        if build_path not in checked:
            require(build["solcVersion"] == "0.8.24", "unexpected Solidity compiler")
            for input_name, content in build["input"]["sources"].items():
                if input_name.startswith("src/"):
                    require(PurePosixPath(input_name).as_posix() == input_name and ".." not in PurePosixPath(input_name).parts,
                            "invalid build source path")
                    require(content["content"].encode() == (contracts / input_name).read_bytes(), "stale source compilation")
            checked.add(build_path)
        compiled = build["output"]["contracts"][name][artifact_data["contractName"]]
        require(compiled["evm"]["bytecode"]["object"] == artifact_data["bytecode"].removeprefix("0x")
                and compiled["abi"] == artifact_data["abi"], "artifact/build-info mismatch")
    for name in VERIFIERS:
        require((contracts / "artifacts/hardhat" / name / "Verifier.json").is_file(), "verifier artifact missing")


def pack(args):
    source = Path(args.contracts).resolve()
    def git(*cmd):
        p = subprocess.run(["git", "-C", str(source), *cmd], capture_output=True, check=False)
        require(p.returncode == 0, "contracts Git verification failed")
        return p.stdout
    commit = SOURCE
    require(git("rev-parse", "HEAD").decode().strip() == commit, "wrong contracts commit")
    require(not git("status", "--porcelain", "--untracked-files=no").strip(), "contracts tracked worktree must be clean")
    changed = set(git("diff", "--name-only", BASE, commit).decode().splitlines())
    require(changed.issubset(VERIFIERS), "candidate changes more than four exported verifiers")
    exports = read_json(args.verifiers, args.verifiers_sha256)
    tracked = git("ls-files", "-z").decode().split("\0")
    selected = [name for name in tracked if name and
                (name in SOURCE_FILES or PurePosixPath(name).parts[0] in SOURCE_DIRS)]
    require(SOURCE_FILES.issubset(selected), "incomplete contracts source")
    for name in selected:
        require(not (source / name).is_symlink(), "source symlink forbidden")
        if name not in VERIFIERS:
            require((source / name).read_bytes() == git("show", f"{BASE}:{name}"), "modified contracts base")
    require(not (source / ".env").exists(), "contracts .env forbidden")
    require((source / "node_modules/.pnpm/lock.yaml").is_file(), "frozen pnpm install missing")
    validate_build(source, exports)
    output = safe_root(args.output, new=True)
    for name in selected:
        dest = output / "contracts" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, dest)
    for name in ("node_modules", "artifacts/hardhat"):
        shutil.copytree(source / name, output / "contracts" / name, symlinks=True)
    shutil.copyfile(HERE / "fresh_l1.cjs", output / "fresh_l1.cjs")
    shutil.copyfile(HERE / "fresh_l1.py", output / "fresh_l1.py")
    manifest = {"version": 1, "contracts_base": BASE, "contracts_commit": commit, "signer": SIGNER,
                "verifiers": exports, "files": inventory(output)}
    write_json(output / "manifest.json", manifest)
    return {"prepared": True, "manifest_sha256": digest(output / "manifest.json"), "broadcast": False}


def verify_bundle(bundle, expected):
    bundle = safe_root(bundle)
    manifest = read_json(bundle / "manifest.json", expected)
    require(set(manifest) == {"version", "contracts_base", "contracts_commit", "signer", "verifiers", "files"}
            and manifest["version"] == 1 and manifest["contracts_base"] == BASE
            and manifest["contracts_commit"] == SOURCE
            and manifest["signer"] == SIGNER, "bundle identity mismatch")
    actual = inventory(bundle)
    actual.pop("manifest.json")
    require(actual == manifest["files"], "bundle contents/hash mismatch")
    validate_build(bundle / "contracts", manifest["verifiers"])
    return bundle


def validate_policy(policy):
    require(set(policy) == {"version", "deposit_rate_limit", "pause_deposits", "governance", "networks"}
            and policy["version"] == 1
            and policy["deposit_rate_limit"] == "legacy-amount-bucket-absent-deposits-paused"
            and policy["pause_deposits"] is True
            and policy["governance"] == "deployer-admin-proxy-timelock", "explicit policy approval required")
    require(set(policy["networks"]) == set(NETWORKS), "policy must cover exactly three testnets")
    for tokens in policy["networks"].values():
        require(set(tokens) == {"native", "PSY", "pUSDT"}, "policy token set mismatch")
        for token, cfg in tokens.items():
            require(set(cfg) == set(AMOUNTS + DELAYS) | {"configured"}
                    and cfg["configured"] is True, "invalid token policy fields")
            for field in AMOUNTS + DELAYS:
                value = cfg[field]
                require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value)
                        and int(value) < 2 ** (128 if field in AMOUNTS else 32), "invalid policy integer")
            v = {field: int(cfg[field]) for field in AMOUNTS + DELAYS}
            require(0 < v["minDepositAmount"] <= v["depositCap"]
                    and v["smallWithdrawalMax"] <= v["mediumWithdrawalMax"]
                    and v[DELAYS[0]] <= v[DELAYS[1]] <= v[DELAYS[2]], "invalid flow-limit ordering")
            if token == "PSY":
                require(v["depositCap"] > 10**18, "PSY cap must allow deposits above initial Bridge inventory")


def protected_text(path):
    p = Path(path)
    s = p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid in (0, os.getuid())
            and not s.st_mode & 0o027, "unsafe secret source")
    return p.read_text()


def secret_env(paths):
    result = {}
    allowed = {"WALLET_PASSWORD"} | {n[3] + "_RPC_FALLBACK_URL" for n in NETWORKS.values()}
    for path in paths:
        for line in protected_text(path).splitlines():
            key, sep, value = line.strip().removeprefix("export ").partition("=")
            if sep and key in allowed:
                words = shlex.split(value, comments=False)
                require(len(words) == 1 and "\x00" not in words[0], "unsupported protected env syntax")
                result[key] = words[0]
    return result


def own_rpc(config, network):
    require(network in NETWORKS, "network forbidden")
    cfg = tomllib.loads(protected_text(config))
    row = next(row for row in cfg["chains"] if row["network_id"] == "sepolia")
    entry = next(p for p in row["rpc_providers"] if p.get("operator") == "local-reth")
    url = urllib.parse.urlsplit(entry["url"])
    ip = ipaddress.ip_address(url.hostname)
    require(ip.version == 4 and ip in ipaddress.ip_network("10.0.0.0/8"), "private own-node gateway required")
    return f"http://{ip}:{NETWORKS[network][2]}"


def rpc(url, method, params):
    require(method in {"eth_chainId", "eth_getBalance", "eth_gasPrice", "eth_getBlockByNumber", "eth_syncing"},
            "read-only RPC method required")
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme in ("http", "https") and parsed.hostname, "invalid RPC endpoint")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1,
                                    "method": method, "params": params}).encode(),
                                    headers={"Content-Type": "application/json"})
    with opener.open(request, timeout=10) as response:
        value = json.loads(response.read(1024 * 1024))
    require(value.get("id") == 1 and "error" not in value and "result" in value, "RPC read failed")
    return value["result"]


def status(network, primary, fallback=None, rpc_preference="own-node"):
    require(rpc_preference in ("own-node", "protected-env-backup"), "invalid RPC preference")
    providers = (("own-node", primary), ("protected-env-backup", fallback))
    if rpc_preference == "protected-env-backup":
        require(bool(fallback), "protected-env backup required by RPC preference")
        providers = (("protected-env-backup", fallback),)
    for label, url in providers:
        if not url:
            continue
        try:
            require(int(rpc(url, "eth_chainId", []), 16) == NETWORKS[network][0], "wrong RPC chain")
            block = rpc(url, "eth_getBlockByNumber", ["latest", False])
            age = int(time.time()) - int(block["timestamp"], 16)
            require(-30 <= age <= 180 and rpc(url, "eth_syncing", []) is False, "RPC stale or syncing")
            report = {"network": network, "provider": label, "chain_id": NETWORKS[network][0],
                      "block": int(block["number"], 16), "block_age_seconds": age,
                      "balance_wei": str(int(rpc(url, "eth_getBalance", [SIGNER, "latest"]), 16)),
                      "gas_price_wei": str(int(rpc(url, "eth_gasPrice", []), 16))}
            return report, url
        except Exception:
            pass
    raise GateError("no healthy provider for selected RPC preference")


def child(node, bundle, output, network, request):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(output), "TS_NODE_TRANSPILE_ONLY": "1"}
    result = subprocess.run([node, str(bundle / "fresh_l1.cjs"), str(bundle / "contracts"),
                             str(output), network], input=json.dumps(request), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, check=False)
    response = json.loads(result.stdout)
    if result.returncode != 0:
        stage = response.get("stage")
        require(stage in {"input", "wallet", "runtime", "bridge", "pause", "gateways", "flow", "complete", "readback"},
                "L1 helper failed; inspect stage journal; no automatic retry")
        raise GateError(f"L1 helper failed at stage {stage}; inspect stage journal/receipts; no automatic retry")
    require(response == {"ok": True, "address": SIGNER, "network": network}, "unexpected helper result")
    return response


def deploy(args):
    require(args.execute, "broadcast requires --execute after independent review")
    policy = read_json(args.policy, args.policy_sha256)
    validate_policy(policy)
    budget = read_json(args.gas_budget, args.gas_budget_sha256)
    require(set(budget) == {"maxGasPriceWei", "maxGasPerTransaction", "maxTotalGas", "maxNativeSpendWei",
                            "l1FeeReserveWeiPerTransaction"}, "explicit gas budget required")
    for name, value in budget.items():
        require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value)
                and (int(value) > 0 or name == "l1FeeReserveWeiPerTransaction"), "invalid gas budget")
    require(args.network != "baseSepolia" or int(budget["l1FeeReserveWeiPerTransaction"]) > 0,
            "Base L1 data-fee reserve required")
    bundle = verify_bundle(args.bundle, args.manifest_sha256)
    output = safe_root(args.output)
    require(read_json(output / "prepared.json") == {"manifest_sha256": args.manifest_sha256},
            "output belongs to another bundle")
    if args.network != "sepolia":
        require(read_json(output / "completed-sepolia.json") == {
            "manifest_sha256": args.manifest_sha256, "policy_sha256": args.policy_sha256},
            "Sepolia completion required before the other two authorized testnets")
    require(not (output / f"attempt-{args.network}.json").exists()
            and not (output / "deployments" / args.network).exists(), "attempt/records already exist; manual review required")
    secrets = secret_env(args.secret_env)
    require(bool(secrets.get("WALLET_PASSWORD")), "retained wallet password unavailable")
    # The root operator must be able to read retained parth-owned 0640 custody.
    key = Path(args.keystore)
    require(key.is_file() and not key.is_symlink() and not key.stat().st_mode & 0o027, "unsafe keystore")
    primary = own_rpc(args.rpc_config, args.network)
    report, endpoint = status(args.network, primary, secrets.get(NETWORKS[args.network][3] + "_RPC_FALLBACK_URL"),
                              args.rpc_preference)
    require(int(report["balance_wei"]) >= int(budget["maxNativeSpendWei"]), "balance below full approved gas budget")
    require(int(report["gas_price_wei"]) <= int(budget["maxGasPriceWei"]), "current gas price exceeds approved cap")
    request = {"execute": False, "password": secrets["WALLET_PASSWORD"], "keystore": str(key),
               "rpc": endpoint, "public_rpc": primary, "policy": policy["networks"][args.network],
               "pause_deposits": True, "budget": budget}
    child(args.node, bundle, output, args.network, request)
    write_json(output / f"attempt-{args.network}.json", {"manifest_sha256": args.manifest_sha256,
               "policy_sha256": args.policy_sha256, "gas_budget_sha256": args.gas_budget_sha256,
               "status": "attempted-no-automatic-retry", "preflight": report, "gas_budget": budget})
    write_json(output / f"policy-{args.network}.json", policy)
    request["execute"] = True
    child(args.node, bundle, output, args.network, request)
    write_json(output / f"completed-{args.network}.json", {"manifest_sha256": args.manifest_sha256,
                                                           "policy_sha256": args.policy_sha256})
    return {"network": args.network, "completed": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("pack")
    for name in ("contracts", "verifiers", "verifiers-sha256", "output"):
        p.add_argument("--" + name, required=True)
    for name in ("check", "prepare", "deploy"):
        p = commands.add_parser(name)
        p.add_argument("--bundle", required=True)
        p.add_argument("--manifest-sha256", required=True)
        if name != "check":
            p.add_argument("--output", required=True)
        if name == "deploy":
            p.add_argument("--network", choices=NETWORKS, required=True)
            p.add_argument("--policy", required=True)
            p.add_argument("--policy-sha256", required=True)
            p.add_argument("--execute", action="store_true")
            p.add_argument("--node", required=True)
            p.add_argument("--gas-budget", required=True)
            p.add_argument("--gas-budget-sha256", required=True)
            p.add_argument("--keystore", default="/var/lib/parth/.psy/keystore/bridge-relayer-dev")
    commands.add_parser("status")
    for name in ("status", "deploy"):
        p = commands.choices[name]
        p.add_argument("--rpc-preference", choices=("own-node", "protected-env-backup"), default="own-node")
        p.add_argument("--rpc-config", default="/etc/parth/bridge-relayer.toml")
        p.add_argument("--secret-env", action="append", default=None)
    args = parser.parse_args(argv)
    if hasattr(args, "secret_env"):
        args.secret_env = args.secret_env or ["/etc/parth/relayer.env"]
    if args.command == "pack":
        return pack(args)
    if args.command == "status":
        secrets = secret_env(args.secret_env)
        return [status(n, own_rpc(args.rpc_config, n), secrets.get(v[3] + "_RPC_FALLBACK_URL"),
                       args.rpc_preference)[0]
                for n, v in NETWORKS.items()]
    if args.command == "deploy":
        return deploy(args)
    verify_bundle(args.bundle, args.manifest_sha256)
    if args.command == "prepare":
        output = safe_root(args.output, new=True)
        write_json(output / "prepared.json", {"manifest_sha256": args.manifest_sha256})
    return {"verified": True, "broadcast": False}


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    try:
        print(json.dumps(main(), sort_keys=True))
    except GateError as error:
        print(str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
    except Exception:
        # Exceptions from RPC, ethers and Hardhat can include credentialed URLs.
        print("fresh L1 gate failed; no raw diagnostics emitted", file=__import__("sys").stderr)
        raise SystemExit(1)
