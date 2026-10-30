'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const ethers = require('/opt/psy-l1-bundles/5ba12a36-20261026-r1/contracts/node_modules/ethers');
const input = process.argv[2];
const ports = {sepolia:18545,bscTestnet:18645,baseSepolia:18945};
const implSlot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const adminSlot = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';
const abi = new ethers.utils.Interface([
  'function owner() view returns(address)',
  'function getAdmin() view returns(address)',
  'function getDelay() view returns(uint256)',
  'function GRACE_PERIOD() view returns(uint256)',
  'function addressesProvider() view returns(address)',
  'function l1ToL2Token(address) view returns(bytes32)',
  'function l2ToL1Token(bytes32) view returns(address)',
  'function tokenToGateway(address) view returns(address)',
  'function getPauseFlags(address) view returns(uint8,uint8,uint8)',
  'function pendingDepositCount() view returns(uint256)',
  'function provedDepositCount() view returns(uint256)',
]);
(async()=>{
  assert(Object.hasOwn(ports,input));
  const bytes=fs.readFileSync('/opt/psy-deposit-acceptance-r3-20261027/public-l1-r3.json');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),'13c06d9ccc0f5c67d8a90c5ced736b6f1c681965cc113b39471f428f9dde62fa');
  const chain=JSON.parse(bytes).l1_chains.find(c=>c.network===input);
  const rpc=new ethers.providers.JsonRpcProvider({url:'http://127.0.0.1:'+ports[input],timeout:15000});
  assert.equal(Number(BigInt(await rpc.send('eth_chainId',[]))),chain.chain_id);
  const block=await rpc.getBlock('latest');
  const call=async(address,name,args=[])=>abi.decodeFunctionResult(name,await rpc.call({to:address,data:abi.encodeFunctionData(name,args)},block.number));
  const router=chain.contracts.Router;
  const implementation=ethers.utils.getAddress('0x'+(await rpc.getStorageAt(router,implSlot,block.number)).slice(-40));
  const admin=ethers.utils.getAddress('0x'+(await rpc.getStorageAt(router,adminSlot,block.number)).slice(-40));
  assert.notEqual(implementation,ethers.constants.AddressZero);
  assert.notEqual(admin,ethers.constants.AddressZero);
  const implementationCode=await rpc.getCode(implementation,block.number);
  const adminOwner=(await call(admin,'owner'))[0];
  const ownerCode=await rpc.getCode(adminOwner,block.number);
  const timelock=ownerCode==='0x'?null:{address:adminOwner,admin:(await call(adminOwner,'getAdmin'))[0],delay:(await call(adminOwner,'getDelay'))[0].toString(),gracePeriod:(await call(adminOwner,'GRACE_PERIOD'))[0].toString()};
  const tokens={};
  for(const [name,token] of [['native',ethers.constants.AddressZero],['PSY',chain.contracts.PsyToken],['pUSDT',chain.contracts.USDTToken]]) {
    const id=(await call(router,'l1ToL2Token',[token]))[0];
    tokens[name]={token,id,reverse:(await call(router,'l2ToL1Token',[id]))[0],gateway:(await call(router,'tokenToGateway',[token]))[0],pause:Array.from(await call(chain.contracts.Bridge,'getPauseFlags',[token]))};
  }
  console.log(JSON.stringify({ok:true,at:new Date().toISOString(),chain:input,chainId:chain.chain_id,block:block.number,blockHash:block.hash,
    router,implementation,implementationCodeHash:ethers.utils.keccak256(implementationCode),implementationCode,
    admin,adminCodeHash:ethers.utils.keccak256(await rpc.getCode(admin,block.number)),adminOwner,timelock,
    routerOwner:(await call(router,'owner'))[0],addressesProvider:(await call(router,'addressesProvider'))[0],
    bridge:chain.contracts.Bridge,pending:(await call(chain.contracts.Bridge,'pendingDepositCount'))[0].toString(),
    proved:(await call(chain.contracts.Bridge,'provedDepositCount'))[0].toString(),tokens}));
})().catch(()=>{console.log(JSON.stringify({ok:false,readOnly:true}));process.exitCode=1;});
