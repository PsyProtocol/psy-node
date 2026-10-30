'use strict';
const fs=require('node:fs');
const path=require('node:path');
const cp=require('node:child_process');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const [contracts,evidence,destination]=process.argv.slice(2);
assert(contracts && evidence && destination,'Usage: package.cjs CONTRACTS_ROOT AUDIT_DIRECTORY NEW_BUNDLE_DIRECTORY');
const ethers=require(path.join(path.resolve(contracts),'node_modules/ethers'));
const sourceCommit='394153fa7b4eb1b5f041131d15036a38321620f0';
assert.equal(cp.execFileSync('git',['rev-parse','HEAD'],{cwd:contracts,encoding:'utf8'}).trim(),sourceCommit);
assert.equal(cp.execFileSync('git',['status','--porcelain','--untracked-files=no'],{cwd:contracts,encoding:'utf8'}).trim(),'');
const artifactPath=path.join(contracts,'artifacts/hardhat/src/Router.sol/Router.json');
const artifactBytes=fs.readFileSync(artifactPath),artifact=JSON.parse(artifactBytes);
const before=JSON.parse(fs.readFileSync(path.join(evidence,'Router-before.json')));
const inputs=fs.readdirSync(path.join(contracts,'artifacts/hardhat/build-info')).map(file=>
  JSON.parse(fs.readFileSync(path.join(contracts,'artifacts/hardhat/build-info',file))))
  .filter(info=>info.output.contracts['src/Router.sol']?.Router);
const output=info=>info.output.contracts['src/Router.sol'].Router;
const old=inputs.find(info=>'0x'+output(info).evm.deployedBytecode.object===before.deployedBytecode);
const next=inputs.find(info=>'0x'+output(info).evm.deployedBytecode.object===artifact.deployedBytecode);
assert(old && next && old!==next);
const layout=info=>({storage:output(info).storageLayout.storage.map(({astId,...entry})=>entry),types:output(info).storageLayout.types});
assert.deepEqual(layout(next),layout(old));
assert.equal(next.solcVersion,'0.8.24');
const source=fs.readFileSync(path.join(contracts,'src/Router.sol'));
assert.equal(ethers.utils.keccak256(source),JSON.parse(output(next).metadata).sources['src/Router.sol'].keccak256);
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const chains={};
for(const [network,file] of [['sepolia','sepolia'],['bscTestnet','bsc'],['baseSepolia','base']]) {
  const {implementationCode,...state}=JSON.parse(fs.readFileSync(path.join(evidence,file+'-governance.json')));
  assert.equal(implementationCode,before.deployedBytecode);
  assert.equal(state.timelock.delay,'172800');
  assert(state.tokens.native.pause[2]&1);
  chains[network]=state;
}
const manifest={contractsSource:sourceCommit,contractsBase:'aee3b39ed08f4f4838b63207df3ee5fbb55c53bc',
  compiler:next.solcLongVersion,sourceSha256:sha(source),artifactSha256:sha(artifactBytes),
  creationCodeHash:ethers.utils.keccak256(artifact.bytecode),runtimeCodeHash:ethers.utils.keccak256(artifact.deployedBytecode),
  oldRuntimeCodeHash:ethers.utils.keccak256(before.deployedBytecode),storageLayoutCompatible:true,chains,files:{}};
fs.mkdirSync(destination,{mode:0o700});
fs.writeFileSync(path.join(destination,'Router.json'),artifactBytes,{flag:'wx',mode:0o600});
for(const name of ['upgrade.py','upgrade.cjs']) {
  const bytes=fs.readFileSync(path.join(__dirname,name));
  fs.writeFileSync(path.join(destination,name),bytes,{flag:'wx',mode:0o600});
  manifest.files[name]=sha(bytes);
}
const bytes=Buffer.from(JSON.stringify(manifest,null,2)+'\n');
fs.writeFileSync(path.join(destination,'manifest.json'),bytes,{flag:'wx',mode:0o600});
const hashes={...manifest.files,'Router.json':sha(artifactBytes),'manifest.json':sha(bytes)};
fs.writeFileSync(path.join(destination,'SHA256SUMS'),Object.entries(hashes).map(([name,hash])=>hash+'  '+name).join('\n')+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({ok:true,destination,contractsSource:sourceCommit,runtimeCodeHash:manifest.runtimeCodeHash,manifestSha256:sha(bytes)}));
