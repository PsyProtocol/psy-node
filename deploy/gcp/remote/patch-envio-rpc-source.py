#!/usr/bin/env python3
"""Version-pinned, rebuild-safe Envio RPC polling patch. Never touches the DB."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

MARKER = "PSY_RPC_POLICY_V1"
RUNTIME_PROBE = r'''
const rpc = require(process.argv[1]);
const original = process.env.ENVIO_RPC_POLLING_INTERVAL_MILLIS;
function interval(value) {
  if (value === undefined) delete process.env.ENVIO_RPC_POLLING_INTERVAL_MILLIS;
  else process.env.ENVIO_RPC_POLLING_INTERVAL_MILLIS = value;
  return rpc.make({chain:97,url:'http://127.0.0.1:1',syncConfig:{},contracts:[],
    eventRouter:{},allEventSignatures:[],sourceFor:0,lowercaseAddresses:true,
    shouldUseHypersyncClientDecoder:false}).pollingInterval;
}
for (const [value, expected] of [[undefined,1000],['12000',12000],['23456',23456]]) {
  if (interval(value) !== expected) throw new Error('Runtime polling policy is not variable-driven');
}
for (const value of ['bad','0','-1','Infinity']) {
  let rejected = false;
  try { interval(value); } catch (_) { rejected = true; }
  if (!rejected) throw new Error('Invalid polling interval accepted');
}
const effective = interval(original);
console.log(JSON.stringify({runtime_policy_verified:true,effective_interval_ms:effective}));
process.exit(0);
'''
FUNCTIONS = {
    "psyRpcPollingInterval": ("unit => int", '''function () {
  var value = Number(process.env.ENVIO_RPC_POLLING_INTERVAL_MILLIS || "1000");
  if (!Number.isSafeInteger(value) || value < 100 || value > 300000) {
    throw new Error("Invalid ENVIO_RPC_POLLING_INTERVAL_MILLIS (100..300000 ms required)");
  }
  return value;
}'''),
    "psyRpcHeightMeter": ("int => unit", '''function (chain) {
  var interval = psyRpcPollingInterval();
  var key = "__psyEnvioHeight_" + String(chain);
  var count = globalThis[key] = (globalThis[key] || 0) + 1;
  if (count === 1) {
    console.info("[psy-rpc-policy] chain=" + String(chain) + " pollingIntervalMs=" + String(interval));
  }
  var every = Number(process.env.ENVIO_RPC_HEIGHT_LOG_EVERY || "300");
  if (process.env.ENVIO_RPC_METERING !== "0" && every > 0 && count % every === 0) {
    console.info("[psy-rpc-meter] method=eth_blockNumber chain=" + String(chain) + " count=" + String(count));
  }
}'''),
    "psyRpcLogsMeter": ("unit => unit", '''function () {
  var count = globalThis.__psyEnvioLogs = (globalThis.__psyEnvioLogs || 0) + 1;
  var every = Number(process.env.ENVIO_RPC_GET_LOGS_LOG_EVERY || "100");
  if (process.env.ENVIO_RPC_METERING !== "0" && every > 0 && count % every === 0) {
    console.info("[psy-rpc-meter] method=eth_getLogs count=" + String(count));
  }
}'''),
}


def once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("Envio source layout changed; expected exactly one patch anchor")
    return text.replace(old, new, 1)


def transformed(text, kind):
    if MARKER in text:
        verify(text, kind)
        return text
    if "__psyRpcMeter" in text:
        raise RuntimeError("Legacy generated-only patch detected; rebuild dependency before applying V1")
    if kind == "res":
        declarations = "// " + MARKER + "\n" + "\n".join(
            f"let {name}: {ty} = %raw(`{js}`)\n" for name, (ty, js) in FUNCTIONS.items())
        text = once(text, "exception QueryTimout(string)\n", "exception QueryTimout(string)\n\n" + declarations)
        text = once(text, "    pollingInterval: 1000,", "    pollingInterval: psyRpcPollingInterval(),")
        text = once(text, "    getHeightOrThrow: () => Rpc.GetBlockHeight.route->Rest.fetch((), ~client),",
                    "    getHeightOrThrow: () => {\n      psyRpcHeightMeter(chain->ChainMap.Chain.toChainId)\n      Rpc.GetBlockHeight.route->Rest.fetch((), ~client)\n    },")
        text = once(text, "  let logsPromise =\n", "  psyRpcLogsMeter()\n  let logsPromise =\n")
    else:
        declarations = "// " + MARKER + "\n" + "\n".join(f"var {name} = {js};\n" for name, (_, js) in FUNCTIONS.items())
        text = once(text, "'use strict';\n", "'use strict';\n\n" + declarations)
        text = once(text, "pollingInterval: 1000,", "pollingInterval: psyRpcPollingInterval(),")
        text = once(text, "              return Rest.$$fetch(Rpc.GetBlockHeight.route, undefined, client);",
                    "              psyRpcHeightMeter(chain);\n              return Rest.$$fetch(Rpc.GetBlockHeight.route, undefined, client);")
        text = once(text, "  var logsPromise = provider.getLogs(", "  psyRpcLogsMeter();\n  var logsPromise = provider.getLogs(")
    verify(text, kind)
    return text


def verify(text, kind):
    # ReScript removes comments but preserves the raw functions and their calls.
    for value in ("ENVIO_RPC_POLLING_INTERVAL_MILLIS", "psyRpcPollingInterval", "psyRpcHeightMeter", "psyRpcLogsMeter", "[psy-rpc-policy]"):
        if value not in text:
            raise RuntimeError("Missing Envio polling patch component: " + value)
    import re
    if not re.search(r"pollingInterval:\s*psyRpcPollingInterval\(", text) or re.search(r"pollingInterval:\s*1000\b", text):
        raise RuntimeError("Effective pollingInterval does not use the configured value")
    if kind == "res" and "psyRpcHeightMeter(chain->ChainMap.Chain.toChainId)" not in text:
        raise RuntimeError("Missing ReScript height call instrumentation")
    if kind == "js" and "psyRpcHeightMeter(chain)" not in text:
        raise RuntimeError("Missing runtime height call instrumentation")


def packages(home):
    result = set()
    for base in (home / "node_modules", home / "generated/node_modules"):
        pkg = base / "envio"
        if pkg.exists():
            result.add(pkg.resolve())
    if not result:
        raise RuntimeError("No installed Envio dependency; refusing silent skip")
    return sorted(result)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", required=True, type=Path)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    changes = []
    for pkg in packages(args.home):
        version = json.loads((pkg / "package.json").read_text())["version"]
        if version.lstrip("v") != "2.32.10":
            raise RuntimeError("Unsupported Envio version; review patch against new dependency first")
        for kind, name in (("res", "RpcSource.res"), ("js", "RpcSource.res.js")):
            path = pkg / "src/sources" / name
            text = path.read_text()
            if args.check:
                verify(text, kind)
                new = text
            elif "psyRpcPollingInterval" in text:
                verify(text, kind)
                new = text
            else:
                new = transformed(text, kind)
            changes.append((path, text, new))
    # Validate all layouts before writing. Atomic replacement avoids modifying
    # other releases sharing a pnpm store inode through hard links.
    for path, old, new in changes:
        if old != new:
            tmp = path.with_name(path.name + ".psy-tmp")
            tmp.write_text(new)
            tmp.chmod(path.stat().st_mode & 0o777)
            tmp.replace(path)
        if path.suffix == ".js":
            subprocess.run(["node", "--check", str(path)], check=True)
            subprocess.run(["node", "-e", RUNTIME_PROBE, str(path)], check=True, timeout=30)
    print(json.dumps({"verified": True, "mode": "check" if args.check else "apply",
                      "files": [{"path": str(p), "sha256": hashlib.sha256(n.encode()).hexdigest()} for p, _, n in changes]}))


if __name__ == "__main__":
    main()
