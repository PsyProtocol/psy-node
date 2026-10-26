import fs from 'node:fs';
import assert from 'node:assert/strict';

const [input, output, portText = '9080'] = process.argv.slice(2);
assert(input && output, 'usage: render-config.mjs INPUT OUTPUT [HASURA_PORT]');
const port = Number(portText);
assert(Number.isInteger(port) && port >= 1024 && port <= 65535);
const config = JSON.parse(fs.readFileSync(input, 'utf8'));
const stage = structuredClone(config.networks.testnet);
assert.equal(stage.magic, '0x1337CF514544CF69');
for (const key of ['coordinator_configs', 'realm_configs', 'prove_proxy_url',
    'system_prove_proxy_url', 'faucet_rpc_url', 'api_services_url', 'explorer_url',
    'nostr_relay_url', 'l1_rpc_urls', 'bridge_url', 'l1_config_url']) {
    assert(key in config.networks.localhost, `missing localhost ${key}`);
    stage[key] = structuredClone(config.networks.localhost[key]);
}
stage.indexer_graphql_url = [`http://127.0.0.1:${port}/v1/graphql`];
delete stage.anvilForkSourceUrlEnv;
// Drop unselected remote stages so an accidental selection fails closed.
const result = {networks: {testnet: stage}, defaultNetwork: 'testnet'};
function checkLocal(value) {
    if (typeof value === 'string' && /^(https?|wss?):/.test(value)) {
        assert.equal(new URL(value).hostname, '127.0.0.1', `nonlocal endpoint: ${value}`);
    } else if (value && typeof value === 'object') Object.values(value).forEach(checkLocal);
}
checkLocal(result);
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', {mode: 0o600});
