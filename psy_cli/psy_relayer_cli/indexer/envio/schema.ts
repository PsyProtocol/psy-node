// PSY relayer indexer schema (Envio)
// Keep table names aligned with psy_relayer_cli SQL:
// - deposits
// - finalized_batches
// - deposit_tree_meta
// - deposit_tree_nodes

export const Deposit = {
  chain_id: "Int",
  deposit_index: "Int",
  chain_local_deposit_index: "Int",
  shield_address: "String",
  token: "String",
  l2_token_contract_id: "String",
  amount: "BigInt",
  chain_index: "Int",
  note_commitment: "String",
  leaf_hash: "String",
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

export const DepositTreeMeta = {
  chain_index: "Int",
  chain_id: "Int",
  last_count: "Int",
  poseidon_deposit_tree_root: "String",
  deposit_tree_root: "String",
  finalized_keccak_deposit_tree_root: "String",
  last_finalized_checkpoint_id: "BigInt",
  block_number: "Int",
  tx_hash: "String",
};

export const DepositTreeNode = {
  chain_index: "Int",
  level: "Int",
  node_index: "BigInt",
  hash: "String",
  block_number: "Int",
  tx_hash: "String",
};
