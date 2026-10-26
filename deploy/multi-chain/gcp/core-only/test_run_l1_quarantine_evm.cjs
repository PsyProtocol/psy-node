"use strict";
// In-process EVM only: no fork URL, sockets, production signer or private keys.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const local = createRequire(path.resolve(process.argv[2], "contracts/package.json"));
const { createHardhatNetworkProvider } = local("hardhat/internal/hardhat-network/provider/provider");
const { ethers } = local("ethers");
const planner = require("./prepare_l1_reset.cjs");
const artifact = name => JSON.parse(fs.readFileSync(path.resolve(process.argv[2], `contracts/artifacts/hardhat/src/${name}.sol/${name}.json`)));
const proxy = local("hardhat-deploy/extendedArtifacts/TransparentUpgradeableProxy.json");
const implSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const adminSlot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

async function main() {
  const provider = await createHardhatNetworkProvider({ hardfork: "cancun", chainId: 31337, networkId: 31337,
    blockGasLimit: 30000000, minGasPrice: 0n, automine: true, intervalMining: 0, mempoolOrder: "priority",
    chains: new Map(), genesisAccounts: [], allowUnlimitedContractSize: false, throwOnTransactionFailures: true,
    throwOnCallFailures: true, allowBlocksWithSameTimestamp: false, initialBaseFeePerGas: 1,
    enableTransientStorage: true, enableRip7212: false }, { enabled: false });
  const rpc = (method, params) => provider.request({ method, params });
  await rpc("hardhat_impersonateAccount", [planner.SIGNER]);
  await rpc("hardhat_setBalance", [planner.SIGNER, "0xde0b6b3a7640000"]);
  let count = 0;
  for (const network of Object.keys(planner.CHAINS)) {
    const doc = planner.pinnedJson(path.join(process.argv[3], network, "deployed-contracts.json"), planner.CHAINS[network][1]);
    const interfaces = {};
    for (const name of ["StateManager", "Bridge", "PsyACLManager", "PsyAddressesProvider"]) {
      const a = artifact(name), implementation = doc.implementations[name + "_Implementation"];
      interfaces[name] = new ethers.utils.Interface(a.abi);
      await rpc("hardhat_setCode", [implementation, a.deployedBytecode]);
      await rpc("hardhat_setCode", [doc.core[name], proxy.deployedBytecode]);
      await rpc("hardhat_setStorageAt", [doc.core[name], implSlot, ethers.utils.hexZeroPad(implementation, 32)]);
      await rpc("hardhat_setStorageAt", [doc.core[name], adminSlot, ethers.utils.hexZeroPad(doc.core.DefaultProxyAdmin, 32)]);
    }
    const send = async (name, method, args) => {
      const hash = await rpc("eth_sendTransaction", [{ from: planner.SIGNER, to: doc.core[name],
        data: interfaces[name].encodeFunctionData(method, args), gas: "0x100000", gasPrice: "0x3b9aca00" }]);
      const r = await rpc("eth_getTransactionReceipt", [hash]);
      assert.equal(r.status, "0x1");
      return r;
    };
    await send("PsyAddressesProvider", "initialize", [planner.SIGNER]);
    await send("PsyACLManager", "initialize", Array(5).fill(planner.SIGNER));
    await send("PsyAddressesProvider", "setAddress", [ethers.utils.id("ACL_MANAGER"), doc.core.PsyACLManager]);
    await send("StateManager", "initialize", [planner.SIGNER, doc.core.PsyAddressesProvider, Object.keys(planner.CHAINS).indexOf(network)]);
    await send("Bridge", "initialize", [planner.SIGNER, doc.core.PsyAddressesProvider, doc.core.DepositBatchVerifier, doc.core.WithdrawalClaimVerifier]);
    await send("Bridge", "setGlobalPauseFlags", [1]);
    const checkState = async (clean, flags) => {
      const read = async (name, field, args) => interfaces[name].decodeFunctionResult(field,
        await rpc("eth_call", [{ to: doc.core[name], data: interfaces[name].encodeFunctionData(field, args) }, "latest"]));
      assert.equal((await read("StateManager", "checkpointTreeRootsClean", []))[0], clean);
      for (const token of [ethers.constants.AddressZero, doc.core.PsyToken, doc.core.USDTToken]) {
        assert.deepEqual([...(await read("Bridge", "getPauseFlags", [token]))], flags);
      }
    };
    await checkState(true, [1, 0, 1]);
    const sm = await send("StateManager", "setCheckpointTreeRootsClean", [false]);
    assert.deepEqual(sm.logs, []);
    await checkState(false, [1, 0, 1]);
    const bridge = await send("Bridge", "setGlobalPauseFlags", [7]);
    assert.equal(bridge.logs.length, 1);
    const event = interfaces.Bridge.parseLog(bridge.logs[0]);
    assert.equal(event.name, "GlobalPauseFlagsUpdated");
    assert.deepEqual([...event.args], [1, 7]);
    await checkState(false, [7, 0, 7]);
    count += 2;
  }
  console.log(JSON.stringify({ verified: true, in_process_only: true, custody_accessed: false, exact_calls: count, sm_logs: 0, bridge_event: [1, 7] }));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
