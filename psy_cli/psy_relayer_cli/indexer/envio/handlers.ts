// @ts-nocheck
import generated from "./generated/index.js";

const { Bridge, StateManager } = generated;

Bridge.DepositRecorded.handler(async ({ event, context }) => {
  const chainId = Number(event.chainId);
  const depositIndex = Number(event.params.index);
  const chainIndex = Number(event.params.chainIndex);
  const blockNumber = Number(event.block.number);
  context.Deposit.set({
    id: `${chainId}-${depositIndex}`,
    chain_id: chainId,
    deposit_index: depositIndex,
    shield_address: event.params.shieldAddress.toString(),
    token: event.params.token.toString(),
    l2_token_contract_id: event.params.l2TokenContractId.toString(),
    amount: event.params.amount,
    note_secret_hash: event.params.noteSecretHash.toString(),
    chain_index: chainIndex,
    leaf_hash: event.params.leafHash.toString(),
    block_number: blockNumber,
    tx_hash: event.transaction.hash.toString(),
  });
});

Bridge.DepositBatchAppended.handler(async ({ event, context }) => {
  const chainId = Number(event.chainId);
  const fromIndex = Number(event.params.fromIndex);
  const toIndex = Number(event.params.toIndex);
  const blockNumber = Number(event.block.number);
  const oldFrontier = event.params.oldFrontier.map((x) => x.toString());
  const leafHashes = event.params.leafHashes.map((x) => x.toString());

  // DepositBatchAppend entity (raw event data, for backward compat)
  context.DepositBatchAppend.set({
    id: `${chainId}-${fromIndex}-${toIndex}`,
    chain_id: chainId,
    from_index: fromIndex,
    to_index: toIndex,
    deposit_root: event.params.newRoot.toString(),
    old_frontier_json: JSON.stringify(oldFrontier),
    leaf_hashes_json: JSON.stringify(leafHashes),
    block_number: blockNumber,
    tx_hash: event.transaction.hash.toString(),
  });

  // Incremental deposit tree nodes: upsert level=0 (leaf) for each deposit
  // in this batch. Higher-level nodes are computed by psy-services which
  // has access to Rust's PoseidonHash. Psy-services reads DepositBatchAppend
  // via GraphQL and then upserts level 1-32 nodes via a REST API or directly
  // into its own DB (if shared) or this table (if Envio PG exposes a write API).
  //
  // For now, store just the leaf-level nodes. The full tree computation will
  // be done in a separate psy-services background task (see bridge/deposit.rs).
  for (let offset = 0; offset < leafHashes.length; offset++) {
    const leafIndex = fromIndex + offset;
    const leafHash = leafHashes[offset];
    if (leafHash === "0x0000000000000000000000000000000000000000000000000000000000000000") {
      continue; // skip padding leaves
    }
    context.DepositTreeNode.set({
      id: `${chainId}:0:${leafIndex}`,
      source_chain_id: chainId,
      level: 0,
      node_index: leafIndex,
      hash: leafHash,
    });
  }
});

StateManager.Finalized.handler(async ({ event, context }) => {
  const chainId = Number(event.chainId);
  const checkpointId = event.params.newLastFinalizedCheckpointId;
  const blockNumber = Number(event.block.number);
  context.FinalizedBatch.set({
    id: `${chainId}-${checkpointId.toString()}`,
    chain_id: chainId,
    finalized_checkpoint_id: checkpointId,
    deposit_tree_root: event.params.depositTreeRoot.toString(),
    withdrawal_tree_root: event.params.withdrawalTreeRoot.toString(),
    block_number: blockNumber,
    tx_hash: event.transaction.hash.toString(),
  });
});
