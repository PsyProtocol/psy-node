const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');

const script = path.resolve(__dirname, '../remote/deploy-l1-contracts.sh');
const source = fs.readFileSync(script, 'utf8');
const marker = "<<'HARDHAT_CONFIRMATIONS_CONFIG'\n";
const template = source.split(marker)[1]?.split('\nHARDHAT_CONFIRMATIONS_CONFIG')[0];
assert.ok(template, 'the test must execute the actual emitted config');

async function check(defaultExport) {
  const base = { networks: { baseSepolia: { chainId: 84532 } } };
  const calls = [];
  const deployments = {};
  for (const name of ['deploy', 'execute']) {
    deployments[name] = async function (...args) {
      assert.equal(this, deployments);
      calls.push({ name, args });
      return 'receipt';
    };
  }
  const context = {
    process: { env: { L1_DEPLOY_WAIT_CONFIRMATIONS: '5' } },
    module: { exports: {} },
    require(name) {
      if (name === './hardhat.config') return defaultExport ? { default: base } : base;
      assert.equal(name, 'hardhat/config');
      return { extendEnvironment: (fn) => fn({ deployments }) };
    },
  };
  vm.runInNewContext(template, context);
  assert.equal(context.module.exports, base);
  const options = { from: 'operator', proxy: { owner: 'operator' } };
  assert.equal(await deployments.deploy('Bridge', options), 'receipt');
  assert.equal(calls[0].args[1].waitConfirmations, 5);
  assert.equal(calls[0].args[1].proxy, options.proxy);
  assert.equal(options.waitConfirmations, undefined, 'do not mutate caller options');
  await deployments.execute('Bridge', { waitConfirmations: 8 }, 'setAddress', 'target');
  assert.equal(calls[1].args[1].waitConfirmations, 8, 'retain stronger caller policy');
  assert.equal(calls[1].args[2], 'setAddress');
  assert.equal(calls[1].args[3], 'target');
}

(async () => {
  await check(true);
  await check(false);
  for (const value of ['0', '-1', '1.5', '100', 'abc', '1;false']) {
    const result = spawnSync('bash', [script], {
      env: { ...process.env, L1_RPC_URL: 'http://unused', L1_DEPLOY_WAIT_CONFIRMATIONS: value },
      encoding: 'utf8',
    });
    assert.equal(result.status, 1, value);
    assert.match(result.stderr, /must be an integer/, value);
  }
  assert.match(source, /args\+=\(--config hardhat\.deploy-confirmations\.config\.ts\)/);
  console.log('L1 deployment confirmation wrapper and input validation passed');
})().catch((error) => { console.error(error); process.exitCode = 1; });
