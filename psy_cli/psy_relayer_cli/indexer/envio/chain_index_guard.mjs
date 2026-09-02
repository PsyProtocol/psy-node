/**
 * Fail closed when two EVM networks share a protocol chain_index in one Envio.
 * Tree entity ids stay "{chain_index}:…" to match L2 set_chain_root.
 */

export function assertChainIndexOwner(existingMeta, chainIndex, chainId) {
  if (existingMeta == null) {
    return;
  }
  const owned = existingMeta.chain_id;
  if (owned == null || owned === "") {
    return;
  }
  const ownedId = Number(owned);
  const incomingId = Number(chainId);
  if (!Number.isFinite(ownedId) || !Number.isFinite(incomingId)) {
    return;
  }
  if (ownedId !== incomingId) {
    throw new Error(
      `DepositTreeMeta for chain_index=${chainIndex} is owned by EVM chain_id=${ownedId}, refusing event from chain_id=${incomingId}. Each L1 must have a unique l1ChainIndex.`,
    );
  }
}
