#!/usr/bin/env python3
"""Open or close the deposit pause of one L1 Bridge as the Bridge administrator, on the signer host, as root.

The request names the chain, the target (0 opens deposits, 1 pauses them) and whether to broadcast; without execute
the tool only simulates and reports. Reads and the one transaction go through the host's private gateway port on
loopback. Gas is measured live (estimate plus a margin) and checked against the ceiling in the request; fixed caps
from earlier releases are not used. The result carries flags, hashes and numbers, never the keystore or its secret.
Run it as `python3 -I -B /dev/stdin --request-base64 B64 --request-sha256 HASH`, its source on stdin.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import resource
import shlex
import signal
import subprocess
import sys
import time

ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
CHAINS = {"sepolia": 11155111, "bscTestnet": 97, "baseSepolia": 84532}
FIELDS = {"chain", "target", "execute", "signer", "chain_id", "port", "bridge", "acl", "tokens", "keystore", "env_file", "node",
          "ethers", "max_gas", "max_fee_gwei", "lock_path", "lock_wait_seconds", "pending_polls", "pending_poll_ms"}
PASSWORD_NAME = "WALLET_" + "PASSWORD"
NODE_TIMEOUT_SECONDS = 300
JS = r'''
const ethers = require(process.env.ETHERS);
const ABI = new ethers.utils.Interface(['function getPauseFlags(address) view returns(uint8,uint8,uint8)','function setGlobalPauseFlags(uint8)','function isBridgeAdmin(address) view returns(bool)']);
let stage='input';
(async()=>{ let s='';for await(const c of process.stdin) s+=c; const r=JSON.parse(s); const C=r.cfg; const ADMIN=C.signer;
 stage='rpc'; const p=new ethers.providers.JsonRpcProvider('http://127.0.0.1:'+C.port);
 if(Number(BigInt(await p.send('eth_chainId',[])))!==C.chainId) throw Error('chain id');
 const rd=async(to,n,a=[])=>ABI.decodeFunctionResult(n,await p.call({to,data:ABI.encodeFunctionData(n,a)}));
 const sleep=ms=>new Promise(x=>setTimeout(x,ms));
 // Latest and pending nonce of the signer agree once nothing of ours is still in the pool; null when they never do.
 const settled=async()=>{for(let i=0;i<C.pendingPolls;i++){const n=await p.getTransactionCount(ADMIN,'latest'); if(n===await p.getTransactionCount(ADMIN,'pending'))return n; await sleep(C.pendingPollMs);} return null;};
 // A pause must act on the state after an earlier unpause that may still be in the pool has mined or been dropped.
 stage='pending'; if(r.target===1&&await settled()===null) throw Error('signer has a pending transaction that did not settle');
 stage='baseline'; const flags=async()=>{const o=[];for(const t of C.tokens)o.push(Array.from(await rd(C.bridge,'getPauseFlags',[t]),Number));return o;};
 const before=await flags();
 if(r.target===1&&before.every(f=>f[0]===1&&f[1]===0&&f[2]===1)) {console.log(JSON.stringify({ok:true,flagsBefore:before,flags:before,broadcast:false}));return;}
 if(r.target===0) for(const f of before) if(JSON.stringify(f)!==JSON.stringify([1,0,1])) throw Error('open requires a paused baseline: '+JSON.stringify(before));
 stage='admin'; if(!(await rd(C.acl,'isBridgeAdmin',[ADMIN]))[0]) throw Error('signer is not bridge admin');
 const data=ABI.encodeFunctionData('setGlobalPauseFlags',[r.target]); const tx={from:ADMIN,to:C.bridge,data,value:0};
 stage='simulate'; await p.call(tx); const gas=await p.estimateGas(tx);
 if(gas.gt(C.maxGas)) throw Error('gas estimate '+gas+' is above the ceiling '+C.maxGas);
 // A re-pause (target 1) is never refused by the fee cap or the balance margin: it must go out whenever gas can be paid.
 const restoring=r.target===1;
 const price=(await p.getGasPrice()).mul(2); if(!restoring&&price.gt(ethers.utils.parseUnits(String(C.maxFeeGwei),'gwei'))) throw Error('fee above the cap');
 const gasLimit=gas.mul(125).div(100).add(5000);
 stage='nonce'; const nonce=await settled(); if(nonce===null) throw Error('signer has a pending transaction');
 const bal=await p.getBalance(ADMIN); if(bal.lt(gasLimit.mul(price).mul(restoring?1:3))) throw Error('signer balance is low');
 const rep={estimate:gas.toString(),gasLimit:gasLimit.toString(),gasPrice:price.toString(),nonce,signerBalance:bal.toString()};
 if(!r.execute){console.log(JSON.stringify({ok:true,dry:true,flagsBefore:before,flags:before,broadcast:false,...rep}));return;}
 stage='unlock'; const w=await ethers.Wallet.fromEncryptedJson(r.encrypted,r.password); if(w.address.toLowerCase()!==ADMIN.toLowerCase()) throw Error('keystore is not the signer');
 const raw=await w.signTransaction({to:C.bridge,data,value:0,nonce,chainId:C.chainId,gasLimit,gasPrice:price});
 const hash=ethers.utils.keccak256(raw); stage='broadcast'; console.error(JSON.stringify({sent:hash}));
 await p.sendTransaction(raw); stage='receipt'; const rc=await p.waitForTransaction(hash,1,240000);
 if(!rc||rc.status!==1) throw Error('transaction failed'); stage='readback'; const after=await flags();
 for(const f of after) if(JSON.stringify(f)!==JSON.stringify([r.target,0,r.target])) throw Error('readback mismatch '+JSON.stringify(after));
 console.log(JSON.stringify({ok:true,hash,block:rc.blockNumber,gasUsed:rc.gasUsed.toString(),effectiveGasPrice:rc.effectiveGasPrice.toString(),nonce,flagsBefore:before,flags:after,broadcast:true,...rep}));
})().catch(e=>{console.log(JSON.stringify({ok:false,stage,msg:String(e.message||e).slice(0,160)}));process.exitCode=1;});
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_request(encoded, expected_sha256):
    raw = base64.b64decode(encoded, validate=True)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "request hash mismatch")
    request = json.loads(raw)
    require(isinstance(request, dict) and set(request) == FIELDS, "request fields differ from the expected set")
    require(request["chain"] in CHAINS and request["chain_id"] == CHAINS[request["chain"]], "unknown chain or chain id")
    require(request["target"] in (0, 1) and type(request["target"]) is int, "target must be 0 or 1")
    require(type(request["execute"]) is bool, "execute must be a boolean")
    require(all(isinstance(request[name], str) and ADDRESS.fullmatch(request[name]) for name in ("signer", "bridge", "acl")),
            "addresses must be 20-byte hex")
    require(isinstance(request["tokens"], list) and len(request["tokens"]) == 3
            and all(isinstance(token, str) and ADDRESS.fullmatch(token) for token in request["tokens"]), "three token addresses required")
    require(type(request["port"]) is int and 1024 <= request["port"] <= 65535, "port out of range")
    require(type(request["max_gas"]) is int and request["max_gas"] > 0 and type(request["max_fee_gwei"]) is int and request["max_fee_gwei"] > 0,
            "gas ceiling and fee cap must be positive integers")
    for name in ("lock_wait_seconds", "pending_polls", "pending_poll_ms"):
        require(type(request[name]) is int and request[name] > 0, f"{name} must be a positive integer")
    for name in ("keystore", "env_file", "node", "ethers", "lock_path"):
        require(isinstance(request[name], str) and request[name].startswith("/") and ".." not in request[name].split("/"),
                f"{name} must be an absolute path")
    return request


def read_password(env_file):
    with open(env_file) as stream:
        for line in stream.read().splitlines():
            name, equals, value = line.strip().removeprefix("export ").partition("=")
            if equals and name == PASSWORD_NAME:
                words = shlex.split(value)
                require(len(words) == 1, "unsupported env syntax")
                return words[0]
    raise ValueError("the signer password is not in the env file")


def run_node(request):
    config = {key: request[key] for key in ("signer", "port", "bridge", "acl", "tokens")}
    config.update(chainId=request["chain_id"], maxGas=request["max_gas"], maxFeeGwei=request["max_fee_gwei"],
                  pendingPolls=request["pending_polls"], pendingPollMs=request["pending_poll_ms"])
    payload = {"cfg": config, "target": request["target"], "execute": request["execute"]}
    if request["execute"]:
        with open(request["keystore"]) as stream:
            payload.update(encrypted=stream.read(), password=read_password(request["env_file"]))
    process = subprocess.Popen([request["node"], "-e", JS], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env={"PATH": "/usr/bin:/bin", "HOME": "/root", "ETHERS": request["ethers"]},
                               start_new_session=True)
    try:
        out, err = process.communicate(json.dumps(payload), timeout=NODE_TIMEOUT_SECONDS)
    finally:
        # Whatever ends this process (timeout, TERM, a failure), the script must not outlive it and broadcast later.
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    sys.stderr.write(err[-300:])
    return out.strip(), process.returncode


def acquire_lock(path, wait_seconds, sleep=time.sleep, clock=time.monotonic):
    """One pause run at a time on the host. An earlier run whose ssh client died may still be running; a later run
    (the re-pause) waits for it to finish, then reads the state it left."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    deadline = clock() + wait_seconds
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            if clock() >= deadline:
                os.close(descriptor)
                raise ValueError("another pause run still holds the lock") from None
            sleep(1)


def end_on_signal(signum, frame):
    raise SystemExit(128 + signum)


def main(argv=None, geteuid=os.geteuid):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-base64", required=True)
    parser.add_argument("--request-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        require(geteuid() == 0, "root is required")
        request = read_request(args.request_base64, args.request_sha256)
        for number in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, end_on_signal)
        lock = acquire_lock(request["lock_path"], request["lock_wait_seconds"])
        try:
            out, code = run_node(request)
        finally:
            os.close(lock)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "stage": "request", "msg": str(error)[:160]}))
        return 1
    print(out)
    return code


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    sys.exit(main())
