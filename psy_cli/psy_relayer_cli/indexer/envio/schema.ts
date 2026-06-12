// PSY relayer indexer schema (Envio)
// Keep table names aligned with psy_relayer_cli SQL:
// - deposits
// - finalized_batches

export const Deposit = {
  chain_id: "Int",
  deposit_index: "Int",
  shield_address: "String",
  token: "String",
  l2_token_contract_id: "String",
  amount: "BigInt",
  chain_index: "Int",
  note_secret_hash: "String",
  leaf_hash: "String",
  block_number: "Int",
  tx_hash: "String",
};

export const DepositBatchAppend = {
  chain_id: "Int",
  from_index: "Int",
  to_index: "Int",
  deposit_root: "String",
  old_frontier_json: "String",
  leaf_hashes_json: "String",
  block_number: "Int",
  tx_hash: "String",
};

export const FinalizedBatch = {
  chain_id: "Int",
  finalized_checkpoint_id: "BigInt",
  deposit_tree_root: "String",
  withdrawal_tree_root: "String",
  block_number: "Int",
  tx_hash: "String",
};
