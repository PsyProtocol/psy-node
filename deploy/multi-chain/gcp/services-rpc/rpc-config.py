#!/usr/bin/env python3
"""Export protected Relayer providers, or probe them from the Services host.

Export stdout contains credentials: pipe it ONLY into a protected remote file.
Probe stdout contains only labels, capability flags and timings.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import tomllib
import urllib.request


def providers_from_relayer(config):
    result = {}
    for chain in config["chains"]:
        index = chain["chain_index"]
        if index not in (0, 1, 2):
            raise ValueError("unexpected chain")
        providers = []
        if index in (0, 1):
            providers.append(dict(name="self-hosted", url=f"http://10.148.0.32:{28545 if index == 0 else 28645}",
                                  operator="psy-self-hosted", quota_group=f"local-{index}"))
        for provider in chain["rpc_providers"]:
            if provider.get("operator") == "alchemy":
                providers.append({k: provider[k] for k in ("name", "url", "operator", "quota_group")})
        assert len(providers) == (3 if index in (0, 1) else 2), "expected two Alchemy backups"
        result[str(index)] = providers
    assert set(result) == {"0", "1", "2"}
    return result


def runtime_chains():
    pid = subprocess.check_output(["systemctl", "show", "parth-psy-services.service", "-p", "MainPID", "--value"], text=True).strip()
    env = dict(s.split("=", 1) for s in Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0") if "=" in s)
    return json.loads(env["PSY_L1_CHAINS"])


def rpc(url, method, params):
    request = urllib.request.Request(url, data=json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=3) as response:
        value = json.loads(response.read(2 * 1024 * 1024 + 1))
    if "error" in value:
        error = value["error"]
        if (method == "eth_getBlockByNumber" and params == ["0x1", False]
                and error.get("code") == 4444
                and str(error.get("message", "")).startswith("pruned history unavailable:")):
            return None
        # Do not surface server-controlled messages or URLs.
        raise ValueError("RPC returned error")
    return value["result"]


def probe(profiles):
    failures = 0
    for chain in runtime_chains():
        index = chain["chain_index"]
        for provider in profiles[str(index)]:
            out = dict(chain_index=index, provider=provider["name"])
            start = time.monotonic()
            try:
                url = provider["url"]
                chain_id = int(rpc(url, "eth_chainId", []), 16)
                assert chain_id == {0: 11155111, 1: 97, 2: 84532}[index]
                head = rpc(url, "eth_getBlockByNumber", ["latest", False])
                age = int(time.time()) - int(head["timestamp"], 16)
                assert -30 <= age <= (120 if index == 0 else 30), "stale head"
                address = chain.get("state_manager", chain.get("state_manager_address"))
                anchor = dict(blockHash=head["hash"], requireCanonical=True)
                for selector in ("0xcae81d60", "0x3590a6a3", "0x7cd34bf4"):
                    value = rpc(url, "eth_call", [dict(to=address, data=selector), anchor])
                    assert isinstance(value, str) and len(value) == 66
                    if selector == "0xcae81d60":
                        assert int(value, 16) == index
                same = rpc(url, "eth_getBlockByNumber", [head["number"], False])
                assert same["hash"] == head["hash"]
                out.update(chain_id=chain_id, head=int(head["number"], 16), age_seconds=age,
                           canonical_context=True, block_1_present=rpc(url, "eth_getBlockByNumber", ["0x1", False]) is not None)
            except Exception as error:
                failures += 1
                out["failure_class"] = type(error).__name__
            out["elapsed_ms"] = round(1000 * (time.monotonic() - start))
            print(json.dumps(out), flush=True)
    return int(failures > 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["export", "probe"])
    parser.add_argument("path")
    args = parser.parse_args()
    if args.action == "export":
        with open(args.path, "rb") as file:
            print(json.dumps(providers_from_relayer(tomllib.load(file))))
    else:
        raise SystemExit(probe(json.loads(Path(args.path).read_text())))
