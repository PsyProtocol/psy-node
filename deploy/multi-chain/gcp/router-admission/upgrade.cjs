'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const ethers = require('/opt/psy-l1-bundles/5ba12a36-20261026-r1/contracts/node_modules/ethers');
const PACKAGE = '/opt/psy-router-admission-20261030-r2';
const ROOT = '/var/lib/psy-router-admission-20261030-r2';
const ADMIN = '0x490f8192725255C2C3dE0CbCE66312335Ca019Ad';
const IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';
const PORTS = {sepolia:18545,bscTestnet:18645,baseSepolia:18945};
const DEPLOY_GAS = Object.freeze({sepolia:8000000,bscTestnet:2000000,baseSepolia:2000000});
const CONFIRMATIONS = 10;
const ABI = new ethers.utils.Interface([
  'function owner() view returns(address)', 'function addressesProvider() view returns(address)',
  'function l1ToL2Token(address) view returns(bytes32)', 'function l2ToL1Token(bytes32) view returns(address)',
  'function tokenToGateway(address) view returns(address)', 'function getPauseFlags(address) view returns(uint8,uint8,uint8)',
  'function upgrade(address,address)',
  'function getAdmin() view returns(address)', 'function getDelay() view returns(uint256)',
  'function GRACE_PERIOD() view returns(uint256)', 'function isActionQueued(bytes32) view returns(bool)',
  'function queueTransaction(address,uint256,string,bytes,uint256) returns(bytes32)',
  'function executeTransaction(address,uint256,string,bytes,uint256) payable returns(bytes)',
  'event QueuedAction(bytes32 indexed actionHash,address indexed target,uint256 value,string signature,bytes data,uint256 executionTime)',
  'event ExecutedAction(bytes32 indexed actionHash,address indexed target,uint256 value,string signature,bytes data,uint256 executionTime,bytes resultData)',
]);
let stage = 'input';
function save(file,value) {
  const fd=fs.openSync(file,'wx',0o600);
  try { fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd); } finally {fs.closeSync(fd);}
  const directory=fs.openSync(ROOT,'r');try {fs.fsyncSync(directory);} finally {fs.closeSync(directory);}
}
const digest=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function actionHash(admin,calldata,eta) {
  return ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
    ['address','uint256','string','bytes','uint256'],[admin,0,'',calldata,eta]));
}
function buildUpgradeCalldata(router,implementation) {
  assert.notEqual(ethers.utils.getAddress(router),ethers.constants.AddressZero);
  assert.notEqual(ethers.utils.getAddress(implementation),ethers.constants.AddressZero);
  return ABI.encodeFunctionData('upgrade',[router,implementation]);
}
function verifyReceipt(intent,tx,receipt,canonicalHash,head) {
  assert(tx && receipt && [0,1].includes(receipt.status),'Unknown transaction: do not resend');
  assert.equal(tx.hash,intent.hash);assert.equal(receipt.transactionHash,intent.hash);
  assert.equal(receipt.blockHash,canonicalHash,'Receipt was reorged');
  assert(head-receipt.blockNumber+1>=CONFIRMATIONS,'Receipt needs more confirmations');
  assert.equal(tx.chainId,intent.chainId);
  assert.equal(tx.from,ADMIN);assert.equal(tx.to,intent.to);assert.equal(tx.data,intent.data);
  assert.equal(tx.nonce,intent.nonce);assert(tx.value.isZero());
  return {failed:receipt.status===0};
}
async function run(request) {
  assert.equal(process.getuid(),0);
  assert(Object.hasOwn(PORTS,request.chain));
  const deployGasLimit=DEPLOY_GAS[request.chain];
  assert(['audit','queue','reconcile','activate','idle'].includes(request.mode));
  const writing=['queue','activate'].includes(request.mode);
  assert(!writing || request.relayerQuiesced===true);
  const manifest=JSON.parse(fs.readFileSync(PACKAGE+'/manifest.json'));
  const artifactBytes=fs.readFileSync(PACKAGE+'/Router.json');
  assert.equal(digest(artifactBytes),manifest.artifactSha256);
  const artifact=JSON.parse(artifactBytes);
  assert.equal(ethers.utils.keccak256(artifact.bytecode),manifest.creationCodeHash);
  assert.equal(ethers.utils.keccak256(artifact.deployedBytecode),manifest.runtimeCodeHash);
  const expected=manifest.chains[request.chain];
  const config=fs.readFileSync('/opt/psy-deposit-acceptance-r3-20261027/public-l1-r3.json');
  assert.equal(digest(config),'13c06d9ccc0f5c67d8a90c5ced736b6f1c681965cc113b39471f428f9dde62fa');
  const chain=JSON.parse(config).l1_chains.find(c=>c.network===request.chain);
  assert.equal(chain.contracts.Router,expected.router);
  assert.equal(chain.chain_id,expected.chainId);
  const provider=new ethers.providers.JsonRpcProvider({url:'http://127.0.0.1:'+PORTS[request.chain],timeout:15000});
  assert.equal(Number(BigInt(await provider.send('eth_chainId',[]))),expected.chainId);
  const read=async(to,name,args=[])=>ABI.decodeFunctionResult(name,await provider.call({to,data:ABI.encodeFunctionData(name,args)}));
  const addressAt=async(slot)=>ethers.utils.getAddress('0x'+(await provider.getStorageAt(expected.router,slot)).slice(-40));
  const codeHash=async(address)=>ethers.utils.keccak256(await provider.getCode(address));
  const nonceIdle=async()=>{
    const nonce=await provider.getTransactionCount(ADMIN,'latest');
    assert.equal(nonce,await provider.getTransactionCount(ADMIN,'pending'),'Signer has pending transactions');
    return nonce;
  };
  const checkState=async()=>{
    stage='proxy-admin-state';
    assert.equal(await addressAt(ADMIN_SLOT),expected.admin);
    assert.equal((await read(expected.admin,'owner'))[0],expected.timelock.address);
    assert.equal(await codeHash(expected.admin),expected.adminCodeHash);
    stage='timelock-state';
    assert.equal((await read(expected.timelock.address,'getAdmin'))[0],ADMIN);
    assert.equal((await read(expected.timelock.address,'getDelay'))[0].toString(),expected.timelock.delay);
    assert.equal((await read(expected.timelock.address,'GRACE_PERIOD'))[0].toString(),expected.timelock.gracePeriod);
    stage='router-state';
    assert.equal((await read(expected.router,'owner'))[0],expected.routerOwner);
    assert.equal((await read(expected.router,'addressesProvider'))[0],expected.addressesProvider);
    for(const token of Object.values(expected.tokens)) {
      stage='token-state-'+token.token;
      assert.equal((await read(expected.router,'l1ToL2Token',[token.token]))[0],token.id);
      assert.equal((await read(expected.router,'l2ToL1Token',[token.id]))[0],token.reverse);
      assert.equal((await read(expected.router,'tokenToGateway',[token.token]))[0],token.gateway);
      assert.deepEqual(Array.from(await read(expected.bridge,'getPauseFlags',[token.token])),token.pause);
    }
    assert(expected.tokens.native.pause[2]&1,'Native pause must remain enabled');
  };
  stage='preflight';await checkState();
  stage='implementation-state';
  const implementation=await addressAt(IMPL_SLOT);
  const proposalFile=ROOT+'/'+request.chain+'.proposal.json';
  const proposal=fs.existsSync(proposalFile)?JSON.parse(fs.readFileSync(proposalFile)):null;
  if(request.mode==='idle') return {ok:true,chain:request.chain,nonce:await nonceIdle(),implementation,broadcast:false};
  const oldActive=implementation===expected.implementation;
  assert(oldActive || (proposal && implementation===proposal.implementation));
  assert.equal(await codeHash(implementation),oldActive?manifest.oldRuntimeCodeHash:manifest.runtimeCodeHash);
  const status=async()=>{
    const queued=proposal?(await read(expected.timelock.address,'isActionQueued',[proposal.actionHash]))[0]:false;
    const chainTimestamp=(await provider.getBlock('latest')).timestamp;
    return {ok:true,chain:request.chain,at:new Date().toISOString(),implementation,active:!oldActive,
      chainTimestamp,activateReady:Boolean(proposal && queued && chainTimestamp>=proposal.executionTime
        && chainTimestamp<=proposal.executionTime+Number(expected.timelock.gracePeriod)),
      proposal:proposal?{implementation:proposal.implementation,actionHash:proposal.actionHash,
        executionTime:proposal.executionTime,executeAfterUTC:new Date(proposal.executionTime*1000).toISOString(),queued}:null,broadcast:false};
  };
  if(request.mode==='audit') {
    stage='gas-preflight';
    const gasPrice=await provider.getGasPrice();
    assert(gasPrice.lte(ethers.utils.parseUnits('1','gwei')));
    assert((await provider.getBalance(ADMIN)).gte(gasPrice.mul(proposal?500000:deployGasLimit+400000)));
    if(!proposal) {
      stage='bounded-creation-simulation';
      const runtime=await provider.call({from:ADMIN,data:artifact.bytecode,value:0,gasLimit:deployGasLimit});
      assert.equal(runtime.toLowerCase(),artifact.deployedBytecode.toLowerCase());
    }
    return {...await status(),fixedGasLimits:{deploy:deployGasLimit,queue:400000,activate:500000},
      boundedCreationSimulation:!proposal,gasPrice:gasPrice.toString(),confirmationPolicy:{blocks:CONFIRMATIONS,finalized:false}};
  }
  if(request.mode==='reconcile') {
    const transactions=[];
    for(const name of ['deploy','queue','activate']) {
      const path=ROOT+'/'+request.chain+'.'+name+'.intent.json';
      if(fs.existsSync(path)) transactions.push(await reconcile(JSON.parse(fs.readFileSync(path))));
    }
    return {...await status(),transactions};
  }
  stage='custody';
  const wallet=await ethers.Wallet.fromEncryptedJson(request.encrypted,request.password);
  delete request.encrypted;delete request.password;
  assert.equal(wallet.address,ADMIN);
  async function reconcile(intent) {
    assert.equal(intent.chain,request.chain);assert.equal(intent.chainId,expected.chainId);
    const tx=await provider.getTransaction(intent.hash);
    const receipt=await provider.getTransactionReceipt(intent.hash);
    const canonical=receipt?await provider.getBlock(receipt.blockNumber):null;
    verifyReceipt(intent,tx,receipt,canonical?.hash,await provider.getBlockNumber());
    if(intent.name==='deploy') {
      assert.equal(intent.data,artifact.bytecode);
      assert.equal(intent.to,null);
      if(receipt.status===1) {
        assert.equal(receipt.contractAddress,ethers.utils.getContractAddress({from:ADMIN,nonce:intent.nonce}));
        assert.equal(await codeHash(receipt.contractAddress),manifest.runtimeCodeHash);
      }
    } else {
      assert(proposal || fs.existsSync(proposalFile));
      const p=JSON.parse(fs.readFileSync(proposalFile));
      const method=intent.name==='queue'?'queueTransaction':'executeTransaction';
      assert.equal(intent.to,expected.timelock.address);
      assert.equal(intent.data,ABI.encodeFunctionData(method,[expected.admin,0,'',p.calldata,p.executionTime]));
    }
    const output={hash:intent.hash,status:receipt.status,failed:receipt.status===0,confirmations:CONFIRMATIONS,
      blockNumber:receipt.blockNumber,blockHash:receipt.blockHash,
      contractAddress:receipt.contractAddress,gasUsed:receipt.gasUsed.toString()};
    const path=ROOT+'/'+request.chain+'.'+intent.name+'.receipt.json';
    if(!fs.existsSync(path)) save(path,output);
    return output;
  }
  async function send(name,to,data,limit) {
    const path=ROOT+'/'+request.chain+'.'+name+'.intent.json';
    if(fs.existsSync(path)) {
      const result=await reconcile(JSON.parse(fs.readFileSync(path)));
      assert(!result.failed,'Known failed transaction; recover signer, do not resend');
      return result;
    }
    await checkState();
    stage='nonce-'+name;
    const nonce=await nonceIdle();
    stage='fee-'+name;
    const gasPrice=await provider.getGasPrice();
    assert(gasPrice.lte(ethers.utils.parseUnits('1','gwei')),'Gas price exceeds approved package ceiling');
    const gasLimit=ethers.BigNumber.from(limit);
    stage='balance-'+name;
    assert((await provider.getBalance(ADMIN)).gte(gasLimit.mul(gasPrice)));
    stage='nonce-recheck-'+name;
    assert.equal(await nonceIdle(),nonce);
    const raw=await wallet.signTransaction({...(to?{to}:{}),data,value:0,chainId:expected.chainId,nonce,gasLimit,gasPrice});
    const intent={name,chain:request.chain,chainId:expected.chainId,to:to||null,data,nonce,
      hash:ethers.utils.keccak256(raw),gasLimit:gasLimit.toString(),gasPrice:gasPrice.toString(),at:new Date().toISOString()};
    stage='save-'+name;save(path,intent);
    stage='broadcast-'+name;await provider.sendTransaction(raw);
    stage='receipt-'+name;await provider.waitForTransaction(intent.hash,CONFIRMATIONS,180000);
    const result=await reconcile(intent);
    assert(!result.failed,'Known failed transaction; recover signer, do not resend');
    return result;
  }
  if(request.mode==='queue') {
    assert(oldActive,'Already activated; no replacement proposal');
    const deployment=await send('deploy',null,artifact.bytecode,deployGasLimit);
    let next=proposal;
    if(!next) {
      const block=await provider.getBlock('latest');
      const eta=block.timestamp+Number(expected.timelock.delay)+120;
      const calldata=buildUpgradeCalldata(expected.router,deployment.contractAddress);
      next={chain:request.chain,implementation:deployment.contractAddress,oldImplementation:expected.implementation,
        calldata,executionTime:eta,actionHash:actionHash(expected.admin,calldata,eta),
        artifactSha256:manifest.artifactSha256,at:new Date().toISOString()};
      save(proposalFile,next);
    }
    assert.equal(next.implementation,deployment.contractAddress);assert.equal(next.artifactSha256,manifest.artifactSha256);
    assert.equal(next.chain,request.chain);assert.equal(next.oldImplementation,expected.implementation);
    assert.equal(next.calldata,buildUpgradeCalldata(expected.router,next.implementation));
    assert.equal(next.actionHash,actionHash(expected.admin,next.calldata,next.executionTime));
    const receipt=await send('queue',expected.timelock.address,ABI.encodeFunctionData('queueTransaction',
      [expected.admin,0,'',next.calldata,next.executionTime]),400000);
    assert((await read(expected.timelock.address,'isActionQueued',[next.actionHash]))[0]);
    assert.equal(await addressAt(IMPL_SLOT),expected.implementation);await checkState();
    return {ok:true,chain:request.chain,queued:true,active:false,implementation:next.implementation,
      actionHash:next.actionHash,executionTime:next.executionTime,executeAfterUTC:new Date(next.executionTime*1000).toISOString(),receipt};
  }
  assert(proposal,'No reviewed queued proposal');
  assert.equal(proposal.artifactSha256,manifest.artifactSha256);
  assert.equal(proposal.actionHash,actionHash(expected.admin,proposal.calldata,proposal.executionTime));
  assert.equal(proposal.calldata,buildUpgradeCalldata(expected.router,proposal.implementation));
  assert.equal(await codeHash(proposal.implementation),manifest.runtimeCodeHash);
  if(oldActive) {
    const block=await provider.getBlock('latest');
    assert(block.timestamp>=proposal.executionTime,'Timelock has not elapsed');
    assert(block.timestamp<=proposal.executionTime+Number(expected.timelock.gracePeriod),'Proposal expired');
    assert((await read(expected.timelock.address,'isActionQueued',[proposal.actionHash]))[0]);
  }
  const receipt=await send('activate',expected.timelock.address,ABI.encodeFunctionData('executeTransaction',
    [expected.admin,0,'',proposal.calldata,proposal.executionTime]),500000);
  assert.equal(await addressAt(IMPL_SLOT),proposal.implementation);await checkState();
  assert.equal((await read(expected.timelock.address,'isActionQueued',[proposal.actionHash]))[0],false);
  return {ok:true,chain:request.chain,active:true,implementation:proposal.implementation,receipt};
}
if(require.main===module) (async()=>{
  let input='';for await(const chunk of process.stdin){input+=chunk;assert(input.length<=1048576);}
  return run(JSON.parse(input));
})().then(result=>console.log(JSON.stringify(result)),()=>{
  console.log(JSON.stringify({ok:false,stage,noRetry:true,preserveEvidence:true}));process.exitCode=1;
});
module.exports={actionHash,buildUpgradeCalldata,verifyReceipt,DEPLOY_GAS};
