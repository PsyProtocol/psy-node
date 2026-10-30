'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ethers = require('ethers');
const exported = {exports:{}};
const importModule = id => id.startsWith('/opt/psy-l1-bundles/') ? ethers : require(id);
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'upgrade.cjs'),'utf8'), {
  module:exported, require:importModule, process, console,
});
const {actionHash,buildUpgradeCalldata,verifyReceipt} = exported.exports;
const router='0x1111111111111111111111111111111111111111';
const implementation='0x2222222222222222222222222222222222222222';
const admin='0x3333333333333333333333333333333333333333';
test('uses the live ProxyAdmin upgrade entry, without an empty initialization delegatecall',()=>{
  const abi=new ethers.utils.Interface(['function upgrade(address,address)']);
  const data=buildUpgradeCalldata(router,implementation);
  assert.equal(data,abi.encodeFunctionData('upgrade',[router,implementation]));
  const decoded=abi.decodeFunctionData('upgrade',data);
  assert.equal(decoded[0],router);assert.equal(decoded[1],implementation);
});
test('refuses a zero proxy or implementation',()=>{
  assert.throws(()=>buildUpgradeCalldata(ethers.constants.AddressZero,implementation));
  assert.throws(()=>buildUpgradeCalldata(router,ethers.constants.AddressZero));
});
test('governance hash matches the Timelock ABI and binds target, bytes and execution time',()=>{
  const data=buildUpgradeCalldata(router,implementation),eta=2000000000;
  const hash=actionHash(admin,data,eta);
  assert.equal(hash,ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
    ['address','uint256','string','bytes','uint256'],[admin,0,'',data,eta])));
  assert.notEqual(hash,actionHash(router,data,eta));
  assert.notEqual(hash,actionHash(admin,data,eta+1));
  assert.notEqual(hash,actionHash(admin,buildUpgradeCalldata(router,admin),eta));
});
function receiptFixture(status=1) {
  const intent={hash:'0x'+'aa'.repeat(32),chainId:11155111,to:router,data:'0x1234',nonce:7};
  const tx={...intent,from:'0x490f8192725255C2C3dE0CbCE66312335Ca019Ad',value:ethers.BigNumber.from(0)};
  const receipt={transactionHash:intent.hash,blockNumber:100,blockHash:'0x'+'bb'.repeat(32),status};
  return {intent,tx,receipt};
}
test('a confirmed status-zero receipt is known failed and can release signer recovery',()=>{
  const {intent,tx,receipt}=receiptFixture(0);
  assert.equal(verifyReceipt(intent,tx,receipt,receipt.blockHash,109).failed,true);
});
test('fewer than ten confirmations cannot release signer recovery',()=>{
  const {intent,tx,receipt}=receiptFixture();
  assert.throws(()=>verifyReceipt(intent,tx,receipt,receipt.blockHash,108),/more confirmations/);
  assert.equal(verifyReceipt(intent,tx,receipt,receipt.blockHash,109).failed,false);
});
test('unknown or reorged receipts cannot release signer recovery',()=>{
  const {intent,tx,receipt}=receiptFixture();
  assert.throws(()=>verifyReceipt(intent,tx,null,null,200),/Unknown transaction/);
  assert.throws(()=>verifyReceipt(intent,tx,receipt,'0x'+'cc'.repeat(32),200),/reorged/);
});
test('receipt and transaction identities must match retained intent',()=>{
  const {intent,tx,receipt}=receiptFixture();
  for(const changed of [{hash:'0x'+'cc'.repeat(32)},{nonce:8},{chainId:97},{to:admin},{data:'0xabcd'}]) {
    assert.throws(()=>verifyReceipt(intent,{...tx,...changed},receipt,receipt.blockHash,200));
  }
  assert.throws(()=>verifyReceipt(intent,tx,{...receipt,transactionHash:'0x'+'dd'.repeat(32)},receipt.blockHash,200));
});
