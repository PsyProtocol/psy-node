-- Registered read shapes for the Services direct PostgreSQL reader (design
-- section 6, phase 2), checked by run_plan_test.py against Envio's own DDL.
--
-- Block format, one statement per block:
--   -- name: <identifier>          prepared statement name
--   -- class: bridge | interactive | background
--   -- params: <type>, ...         PREPARE parameter types, in $n order
--   -- index: <name>[, <name>]     every listed index must appear in the plan
--   -- max_buffers: <n>            shared buffers hit+read must stay <= n at
--                                  every scale (the O(log n) check)
--   -- gate: yes | report          report = measured and printed, never fails
-- Tables are unqualified; the runner sets search_path to the Envio schema.
-- A Seq Scan on any table except DepositTreeMeta (one row per chain) fails a
-- gated shape.

-- name: deposit_list_page
-- class: interactive
-- params: text, int4, int4
-- index: Deposit_shield_address_chain_index_chain_local_deposit_index
-- max_buffers: 200
-- gate: yes
SELECT chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
       l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash,
       block_number, block_timestamp, tx_hash
FROM "Deposit"
WHERE shield_address = $1 AND chain_index = $2 AND chain_id = $3
ORDER BY chain_local_deposit_index
LIMIT 100;

-- Measured 205 buffers at 100,000 rows (custom plan) and 106 at 1,000,000, so the
-- old bound of 200 failed the 100,000-row run on an unchanged tree; 400 still
-- catches a scan.
-- name: deposit_list_next_page
-- class: interactive
-- params: text, int4, int4, int4
-- index: Deposit_shield_address_chain_index_chain_local_deposit_index
-- max_buffers: 400
-- gate: yes
SELECT chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
       l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash,
       block_number, block_timestamp, tx_hash
FROM "Deposit"
WHERE shield_address = $1 AND chain_index = $2 AND chain_id = $3
  AND chain_local_deposit_index > $4
ORDER BY chain_local_deposit_index
LIMIT 100;

-- Today's wallet API pages with limit/offset; an offset costs O(offset).
-- name: deposit_list_offset_page
-- class: interactive
-- params: text, int4, int4, int8
-- index: Deposit_shield_address_chain_index_chain_local_deposit_index
-- max_buffers: 0
-- gate: report
SELECT chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
       l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash,
       block_number, block_timestamp, tx_hash
FROM "Deposit"
WHERE shield_address = $1 AND chain_index = $2 AND chain_id = $3
ORDER BY chain_local_deposit_index
LIMIT 100 OFFSET $4;

-- name: account_deposit_stats
-- class: interactive
-- params: text
-- index: AccountDepositStats_pkey
-- max_buffers: 10
-- gate: yes
SELECT deposit_count, last_chain_local_deposit_index, last_block_number, chain_id
FROM "AccountDepositStats"
WHERE id = $1;

-- name: deposit_by_deposit_index
-- class: bridge
-- params: int4, int4, int4
-- index: Deposit_chain_index_deposit_index
-- max_buffers: 10
-- gate: yes
SELECT chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
       l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash,
       block_number, block_timestamp
FROM "Deposit"
WHERE chain_index = $1 AND chain_id = $2 AND deposit_index = $3;

-- Global-to-local conversion: the chain-local count below a global
-- deposit_index is the last such row's chain_local_deposit_index + 1.
-- name: global_to_local_probe
-- class: bridge
-- params: int4, int4, int4
-- index: Deposit_chain_index_deposit_index
-- max_buffers: 10
-- gate: yes
SELECT chain_local_deposit_index + 1 AS chain_local_count
FROM "Deposit"
WHERE chain_index = $1 AND chain_id = $2 AND deposit_index < $3
ORDER BY deposit_index DESC
LIMIT 1;

-- Replaces Services' foreign-prefix count. A chain_index keeps one chain_id
-- (asserted by the handler), so another chain_index shares the global prefix
-- of chain_id $2 only if its first leaf is on $2 and below $3.
-- name: foreign_prefix_probe
-- class: bridge
-- params: int4, int4, int4
-- index: DepositLeaf_pkey
-- max_buffers: 20
-- gate: yes
SELECT EXISTS (
  SELECT 1
  FROM "DepositTreeMeta" m
  JOIN "DepositLeaf" l ON l.id = m.chain_index || '-0'
  WHERE m.chain_index <> $1 AND l.chain_id = $2 AND l.deposit_index < $3
) AS has_foreign_deposits;

-- Replaces the frontends' direct Hasura lookup (same filter and order).
-- name: deposit_by_tx_hash
-- class: interactive
-- params: text, int4
-- index: Deposit_tx_hash
-- max_buffers: 20
-- gate: yes
SELECT chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
       l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash,
       block_number, block_timestamp, tx_hash
FROM "Deposit"
WHERE tx_hash = $1 AND chain_index = $2
ORDER BY deposit_index DESC
LIMIT 10;

-- One tree block (B = 1024 leaves) for a proof or a partial-block root.
-- name: leaf_range_1024
-- class: bridge
-- params: int4, int4
-- index: DepositLeaf_chain_index_chain_local_deposit_index
-- max_buffers: 200
-- gate: yes
SELECT chain_local_deposit_index, poseidon_leaf_hash
FROM "DepositLeaf"
WHERE chain_index = $1
  AND chain_local_deposit_index >= $2 AND chain_local_deposit_index < $2 + 1024
ORDER BY chain_local_deposit_index;

-- Startup and follow: stream leaves in key order, one page per query.
-- name: leaf_stream_page
-- class: background
-- params: int4, int4
-- index: DepositLeaf_chain_index_chain_local_deposit_index
-- max_buffers: 1500
-- gate: yes
SELECT chain_local_deposit_index, poseidon_leaf_hash
FROM "DepositLeaf"
WHERE chain_index = $1 AND chain_local_deposit_index >= $2
ORDER BY chain_local_deposit_index
LIMIT 10000;

-- name: withdrawal_claims_by_nullifier
-- class: interactive
-- params: int4, text[]
-- index: WithdrawalClaim_chain_id_nullifier
-- max_buffers: 1000
-- gate: yes
SELECT nullifier, block_number, tx_hash
FROM "WithdrawalClaim"
WHERE chain_id = $1 AND nullifier = ANY ($2);

-- name: watermark
-- class: bridge
-- params: int4
-- index:
-- max_buffers: 10
-- gate: yes
SELECT last_count, poseidon_deposit_tree_root
FROM "DepositTreeMeta"
WHERE chain_index = $1;

-- Explorer feed rewritten onto the chain's deposit order (within a
-- chain_index, deposit_index follows block order).
-- name: explorer_latest_deposits
-- class: background
-- params: int4
-- index: Deposit_chain_index_deposit_index
-- max_buffers: 200
-- gate: yes
SELECT chain_id, deposit_index, shield_address, token, amount, block_number, tx_hash
FROM "Deposit"
WHERE chain_index = $1
ORDER BY deposit_index DESC
LIMIT 100;

-- Today's explorer feed (explorer_bridge.rs). No index orders it; reported to
-- show the cost phase 2 must remove.
-- name: explorer_feed_current
-- class: background
-- params: int4
-- index:
-- max_buffers: 0
-- gate: report
SELECT chain_id, deposit_index, shield_address, token, amount, block_number, tx_hash
FROM "Deposit"
WHERE chain_id = $1
ORDER BY block_number DESC, id DESC
LIMIT 100;

-- Follow-loop shapes of the Bridge Reader (psy_bridge_reader). Each reads the
-- next page after a cursor; the cursor for claims and batches is the pair
-- (block_number, id). The runner binds LIMIT = 1000 (the page maximum) and a
-- cursor one third into chain 0. max_buffers of each follow_* shape is twice
-- the buffers measured at --rows 1000000 (the value is in the shape's comment).
-- Measured 91 buffers at 1,000,000 rows.
-- name: follow_deposits
-- class: background
-- params: int4, int4, int8
-- index: Deposit_chain_index_deposit_index
-- max_buffers: 182
-- gate: yes
SELECT id, chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
       l2_token_contract_id, amount::text, note_commitment, chain_index, leaf_hash,
       block_number, block_timestamp::text, tx_hash
FROM "Deposit"
WHERE chain_index = $1 AND deposit_index >= $2
ORDER BY deposit_index
LIMIT $3;

-- Measured 29 buffers at 1,000,000 rows.
-- name: follow_leaves
-- class: background
-- params: int4, int4, int8
-- index: DepositLeaf_chain_index_chain_local_deposit_index
-- max_buffers: 58
-- gate: yes
SELECT chain_local_deposit_index, deposit_index, chain_id, poseidon_leaf_hash, block_number
FROM "DepositLeaf"
WHERE chain_index = $1 AND chain_local_deposit_index >= $2
ORDER BY chain_local_deposit_index
LIMIT $3;

-- Measured 78 buffers at 1,000,000 rows.
-- name: follow_claims
-- class: background
-- params: int4, int4, text, int8
-- index: WithdrawalClaim_chain_id_block_number_id
-- max_buffers: 156
-- gate: yes
SELECT id, chain_id, nullifier, recipient, token, amount::text, block_number, tx_hash
FROM "WithdrawalClaim"
WHERE chain_id = $1 AND (block_number, id) > ($2, $3)
ORDER BY block_number, id
LIMIT $4;

-- Measured 55 buffers at 1,000,000 rows.
-- name: follow_batches
-- class: background
-- params: int4, int4, text, int8
-- index: FinalizedBatch_chain_id_block_number_id
-- max_buffers: 110
-- gate: yes
SELECT id, chain_id, finalized_checkpoint_id::text, deposit_tree_root, withdrawal_tree_root,
       block_number, tx_hash
FROM "FinalizedBatch"
WHERE chain_id = $1 AND (block_number, id) > ($2, $3)
ORDER BY block_number, id
LIMIT $4;

-- One row per chain, like the watermark but for every chain at once.
-- name: tree_meta_all
-- class: background
-- params:
-- index:
-- max_buffers: 10
-- gate: yes
SELECT chain_index, last_count, poseidon_deposit_tree_root
FROM "DepositTreeMeta"
ORDER BY chain_index;

-- Envio's own progress table; reported only.
-- name: chain_progress
-- class: background
-- params:
-- index:
-- max_buffers: 0
-- gate: report
SELECT id, progress_block, max_reorg_depth
FROM envio_chains
ORDER BY id;

-- Identifies the Envio schema instance the Reader is following (it changes
-- when the schema is dropped and re-created); reported only.
-- name: envio_identity
-- class: background
-- params:
-- index:
-- max_buffers: 0
-- gate: report
SELECT 'envio_chains'::regclass::oid::int8 AS chains_oid, '"Deposit"'::regclass::oid::int8 AS deposit_oid;
