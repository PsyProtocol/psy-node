#!/usr/bin/env python3
"""Read-only rollout verification; prints summaries, never proof or key payloads."""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location('rollout', '/tmp/envio-timestamps-staged/update-envio-timestamps.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def request(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)


values = m.env_values(m.NEW)
headers = {'Content-Type': 'application/json', 'x-hasura-admin-secret':
           values['HASURA_GRAPHQL_ADMIN_SECRET'].strip('"\'')}


def gql(query):
    result = request('http://127.0.0.1:18080/v1/graphql', json.dumps({'query': query}).encode(), headers)
    if 'errors' in result:
        raise RuntimeError('Hasura timestamp query failed')
    return result['data']


pid = subprocess.check_output(['systemctl', 'show', m.UNIT, '-p', 'MainPID', '--value'], text=True).strip()
runtime_env = dict(x.split(b'=', 1) for x in Path('/proc', pid, 'environ').read_bytes().split(b'\0') if b'=' in x)
assert runtime_env[b'ENVIO_RPC_POLLING_INTERVAL_MILLIS'] == b'12000'
m.policy()
before = json.loads((m.ROOT / 'before-activation.json').read_text())
after = m.snapshot('envio_bridge')
current = {d['id']: d['digest'] for d in after['deposits']}
assert all(current.get(d['id']) == d['digest'] for d in before['deposits'])
summary = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'polling_interval_ms': 12000, 'envio_pid': pid,
           'old_deposits_preserved': len(before['deposits']), 'chains': []}
summary['columns'] = json.loads(m.pg('envio_bridge', '''SELECT json_agg(row_to_json(c)) FROM (
 SELECT table_name, data_type, is_nullable FROM information_schema.columns
 WHERE table_schema='envio' AND table_name IN ('Deposit','envio_history_Deposit')
 AND column_name='block_timestamp') c;'''))
summary['populated_rows'] = int(m.pg('envio_bridge', 'SELECT count(*) FROM envio."Deposit" WHERE block_timestamp IS NOT NULL;'))
for chain in range(3):
    data = gql('{ Deposit(where:{chain_index:{_eq:%d}},order_by:{deposit_index:desc},limit:1)'
               '{deposit_index shield_address block_timestamp block_number} '
               'DepositTreeMeta(where:{chain_index:{_eq:%d}}){last_count} }' % (chain, chain))
    row = data['Deposit'][0]
    count = int(data['DepositTreeMeta'][0]['last_count'])
    total = gql('{ Deposit_aggregate(where:{chain_index:{_eq:%d},shield_address:{_eq:%s}}){aggregate{count}} }'
                % (chain, json.dumps(row['shield_address'])))['Deposit_aggregate']['aggregate']['count']
    params = urllib.parse.urlencode({'chain_index':chain, 'shield_address':row['shield_address'],
                                     'limit':1, 'offset':int(total)-1})
    listed = request('https://services-stg.psy-protocol.xyz/api/v1/get/bridge/deposits?' + params)
    assert listed['success'] and len(listed['data']['items']) == 1
    item = listed['data']['items'][0]
    assert int(item['deposit_index']) == int(row['deposit_index']) and item['created_at'], {
        'chain': chain, 'listed_index': item['deposit_index'],
        'indexed_index': row['deposit_index'], 'created_at': item.get('created_at')}
    if row['block_timestamp'] is not None:
        assert int(datetime.datetime.fromisoformat(item['created_at'].replace('Z','+00:00')).timestamp()) == int(row['block_timestamp'])
    params = urllib.parse.urlencode({'source_chain_index':chain, 'deposit_index':row['deposit_index'], 'snapshot_deposit_count':count})
    proof = request('https://services-stg.psy-protocol.xyz/api/v1/bridge/deposit-claim-proof?' + params)
    assert proof['success'] and proof['data']['found']
    summary['chains'].append({'chain_index':chain, 'latest_deposit_index':row['deposit_index'],
         'snapshot_count':count, 'indexed_timestamp':row['block_timestamp'],
         'list_created_at':item['created_at'], 'proof_found':proof['data']['found']})
(m.ROOT / 'live-verification.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
