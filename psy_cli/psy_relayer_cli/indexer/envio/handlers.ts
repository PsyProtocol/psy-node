// @ts-nocheck
import generated from "./generated/index.js";
import { hashNoPad } from 'poseidon-goldilocks-lite';
import { assertChainIndexOwner } from "./chain_index_guard.mjs";

const { Bridge, StateManager } = generated;

// ── Helpers shared by deposit ingestion / finalized audit metadata ───────────

// ── Helper: convert a 32-byte hex string to 8 big-endian u32 bigints ──────────
function hexToU32x8(hex: string): bigint[] {
  const raw = hex.startsWith('0x') ? hex.slice(2) : hex;
  const padded = raw.padStart(64, '0');
  const result: bigint[] = [];
  for (let i = 0; i < 8; i++) {
    result.push(BigInt('0x' + padded.slice(i * 8, (i + 1) * 8)));
  }
  return result;
}

// ── Helper: convert a 20-byte hex address to 8 u32 bigints (zero-padded left) ─
function addressToU32x8(hex: string): bigint[] {
  const raw = hex.startsWith('0x') ? hex.slice(2) : hex;
  const padded = raw.padStart(64, '0');  // pad to 32 bytes (left-pad with zeros)
  const result: bigint[] = [];
  for (let i = 0; i < 8; i++) {
    result.push(BigInt('0x' + padded.slice(i * 8, (i + 1) * 8)));
  }
  return result;
}

// ── Helper: convert a bigint amount to 8 u32 big-endian words ─────────────────
function u256ToU32x8BE(value: bigint | number): bigint[] {
  const hex = BigInt(value).toString(16);
  if (hex.length > 64) {
    throw new Error(`uint256 amount exceeds 32 bytes: 0x${hex}`);
  }
  const padded = hex.padStart(64, '0');  // right-aligned in 32 bytes
  const result: bigint[] = [];
  for (let i = 0; i < 8; i++) {
    result.push(BigInt('0x' + padded.slice(i * 8, (i + 1) * 8)));
  }
  return result;
}

// ── Helper: decompose a QHashOut (4 u64 limbs) into 8 u32 words ──────────────
// Takes [e0, e1, e2, e3] and returns [e0_hi, e0_lo, e1_hi, e1_lo, ...]
// This matches the Rust `qhash_to_frontend_internal_hex` convention.
function qhashToU32x8(hash: [bigint, bigint, bigint, bigint]): bigint[] {
  return [
    (hash[0] >> 32n) & 0xffffffffn,
    hash[0] & 0xffffffffn,
    (hash[1] >> 32n) & 0xffffffffn,
    hash[1] & 0xffffffffn,
    (hash[2] >> 32n) & 0xffffffffn,
    hash[2] & 0xffffffffn,
    (hash[3] >> 32n) & 0xffffffffn,
    hash[3] & 0xffffffffn,
  ];
}

// ── Helper: convert QHashOut to display hex (e3-first BE) ────────────────────
function qhashToDisplayHex(hash: [bigint, bigint, bigint, bigint]): string {
  return '0x' + [hash[3], hash[2], hash[1], hash[0]]
    .map(v => v.toString(16).padStart(16, '0'))
    .join('');
}

function displayHexToQHash(hex: string): [bigint, bigint, bigint, bigint] {
  const raw = (hex || '').startsWith('0x') ? hex.slice(2) : hex;
  const padded = raw.padStart(64, '0');
  return [
    BigInt('0x' + padded.slice(48, 64)),
    BigInt('0x' + padded.slice(32, 48)),
    BigInt('0x' + padded.slice(16, 32)),
    BigInt('0x' + padded.slice(0, 16)),
  ];
}

function twoToOneHash(left: [bigint, bigint, bigint, bigint], right: [bigint, bigint, bigint, bigint]): [bigint, bigint, bigint, bigint] {
  return hashNoPad([
    left[0], left[1], left[2], left[3],
    right[0], right[1], right[2], right[3],
  ]) as [bigint, bigint, bigint, bigint];
}

const ZERO_HASHES: [bigint, bigint, bigint, bigint][] = (() => {
  const values: [bigint, bigint, bigint, bigint][] = [[0n, 0n, 0n, 0n]];
  for (let level = 0; level < 32; level++) {
    values[level + 1] = twoToOneHash(values[level], values[level]);
  }
  return values;
})();

function zeroHash(level: number): [bigint, bigint, bigint, bigint] {
  return ZERO_HASHES[level] || ZERO_HASHES[ZERO_HASHES.length - 1];
}

// ── Compute Poseidon deposit leaf hash from raw deposit fields ────────────────
// Matches the Rust implementation in psy_relayer_cli/src/bridge/compute_deposit_leaf.rs
// Words: [shield_address(8), token(8), l2_token_contract_id(8), amount(8), chain_index(1), note_commitment(8)] = 41
function computePoseidonDepositLeaf(
  shieldAddressHex: string,
  tokenHex: string,
  l2TokenContractIdHex: string,
  amount: bigint | number,
  chainIndex: number,
  noteCommitmentHex: string,
): [bigint, bigint, bigint, bigint] {
  // Parse 32-byte fields as u32x8
  const shieldWords = hexToU32x8(shieldAddressHex);
  const tokenWords = addressToU32x8(tokenHex);
  const l2IdWords = hexToU32x8(l2TokenContractIdHex);
  const amountWords = u256ToU32x8BE(amount);
  const noteWords = hexToU32x8(noteCommitmentHex);

  // All 41 elements as field elements (bigints within Goldilocks range)
  const felts = [
    ...shieldWords,
    ...tokenWords,
    ...l2IdWords,
    ...amountWords,
    BigInt(chainIndex),
    ...noteWords,
  ];

  return hashNoPad(felts) as [bigint, bigint, bigint, bigint];
}

async function getDepositTreeNodeHash(context: any, chainIndex: number, level: number, nodeIndex: number): Promise<[bigint, bigint, bigint, bigint] | null> {
  const existing = await context.DepositTreeNode.get(`${chainIndex}:${level}:${nodeIndex}`);
  if (!existing?.hash) return null;
  return displayHexToQHash(existing.hash.toString());
}

async function upsertDepositTreeNode(
  context: any,
  chainIndex: number,
  level: number,
  nodeIndex: number,
  hash: [bigint, bigint, bigint, bigint],
  blockNumber: number,
  txHash: string,
) {
  context.DepositTreeNode.set({
    id: `${chainIndex}:${level}:${nodeIndex}`,
    chain_index: chainIndex,
    level,
    node_index: nodeIndex,
    hash: qhashToDisplayHex(hash),
    block_number: blockNumber,
    tx_hash: txHash,
  });
}

async function appendCurrentDepositLeaf(
  context: any,
  chainIndex: number,
  leafIndex: number,
  leafHash: [bigint, bigint, bigint, bigint],
  blockNumber: number,
  txHash: string,
): Promise<[bigint, bigint, bigint, bigint]> {
  let curIdx = leafIndex;
  let curHash = leafHash;
  await upsertDepositTreeNode(context, chainIndex, 0, curIdx, curHash, blockNumber, txHash);

  for (let level = 0; level < 32; level++) {
    const siblingIdx = (curIdx % 2 === 0) ? curIdx + 1 : curIdx - 1;
    const sibling = (await getDepositTreeNodeHash(context, chainIndex, level, siblingIdx)) || zeroHash(level);
    const parent = (curIdx % 2) === 0
      ? twoToOneHash(curHash, sibling)
      : twoToOneHash(sibling, curHash);
    curIdx = Math.floor(curIdx / 2);
    curHash = parent;
    await upsertDepositTreeNode(context, chainIndex, level + 1, curIdx, curHash, blockNumber, txHash);
  }

  return curHash;
}

// ── DepositRecorded handler ─────────────────────────────────────────────────────
// Writes the raw deposit event and incrementally advances the CURRENT per-chain
// Poseidon helper tree. Historical roots / proofs for older counts are derived
// later from the current helper-tree nodes plus the requested snapshot boundary.
Bridge.DepositRecorded.handler(async ({ event, context }) => {
  const chainId = Number(event.chainId);
  const depositIndex = Number(event.params.index);
  const chainIndex = Number(event.params.chainIndex);
  const blockNumber = Number(event.block.number);
  const leafHash = event.params.leafHash.toString();
  const txHash = event.transaction.hash.toString();
  const shieldAddress = event.params.shieldAddress.toString();
  const token = event.params.token.toString();
  const l2TokenContractId = event.params.l2TokenContractId.toString();
  const amount = event.params.amount;
  const noteCommitment = event.params.noteCommitment.toString();

  const metaId = `${chainIndex}`;
  const existingMeta = await context.DepositTreeMeta.get(metaId);
  assertChainIndexOwner(existingMeta, chainIndex, chainId);
  const nextTreeIndex = existingMeta != null ? Number(existingMeta.last_count || 0) : 0;
  context.Deposit.set({
    id: `${chainId}-${depositIndex}`,
    chain_id: chainId,
    deposit_index: depositIndex,
    chain_local_deposit_index: nextTreeIndex,
    shield_address: shieldAddress,
    token: token,
    l2_token_contract_id: l2TokenContractId,
    amount: amount,
    note_commitment: noteCommitment,
    chain_index: chainIndex,
    leaf_hash: leafHash,
    block_number: blockNumber,
    tx_hash: txHash,
  });
  const poseidonLeaf = computePoseidonDepositLeaf(
    shieldAddress,
    token,
    l2TokenContractId,
    amount,
    chainIndex,
    noteCommitment,
  );
  const poseidonRoot = await appendCurrentDepositLeaf(
    context,
    chainIndex,
    nextTreeIndex,
    poseidonLeaf,
    blockNumber,
    txHash,
  );
  const poseidonRootHex = qhashToDisplayHex(poseidonRoot);

  context.DepositTreeMeta.set({
    id: metaId,
    chain_index: chainIndex,
    chain_id: chainId,
    last_count: nextTreeIndex + 1,
    poseidon_deposit_tree_root: poseidonRootHex,
    deposit_tree_root: poseidonRootHex,
    finalized_keccak_deposit_tree_root: existingMeta?.finalized_keccak_deposit_tree_root?.toString()
      ?? "0x0000000000000000000000000000000000000000000000000000000000000000",
    last_finalized_checkpoint_id: existingMeta?.last_finalized_checkpoint_id?.toString() ?? "0",
    block_number: blockNumber,
    tx_hash: txHash,
  });
});

// ── WithdrawalClaimed handler ───────────────────────────────────────────────────
// Records raw on-chain withdrawal claims so the API can list claimable state
// without re-scanning the chain. ID = "{chainId}-{nullifier}".
Bridge.WithdrawalClaimed.handler(async ({ event, context }) => {
  const chainId = Number(event.chainId);
  const blockNumber = Number(event.block.number);
  const txHash = event.transaction.hash.toString();
  const nullifier = event.params.nullifier.toString();
  const recipient = event.params.recipient.toString();
  const token = event.params.token.toString();
  const amount = event.params.amount;

  context.WithdrawalClaim.set({
    id: `${chainId}-${nullifier}`,
    chain_id: chainId,
    nullifier,
    recipient,
    token,
    amount,
    block_number: blockNumber,
    tx_hash: txHash,
  });
});

// ── Finalized handler ───────────────────────────────────────────────────────────
// Records finalized checkpoints for audit/debug. The current per-chain Poseidon
// helper tree is maintained incrementally on DepositRecorded, so Finalized no
// longer mutates DepositTreeNode / DepositTreeMeta counts or roots.
StateManager.Finalized.handler(async ({ event, context }) => {
  const chainId = Number(event.chainId);
  const checkpointId = event.params.newLastFinalizedCheckpointId;
  const blockNumber = Number(event.block.number);
  const depositTreeRoot = event.params.depositTreeRoot != null
    ? event.params.depositTreeRoot.toString()
    : "0x0000000000000000000000000000000000000000000000000000000000000000";
  const withdrawalTreeRoot = event.params.withdrawalTreeRoot != null
    ? event.params.withdrawalTreeRoot.toString()
    : "0x0000000000000000000000000000000000000000000000000000000000000000";
  const txHash = event.transaction.hash.toString();

  const safeBlockNumber = isNaN(blockNumber) ? 0 : blockNumber;

  context.FinalizedBatch.set({
    id: `${chainId}-${checkpointId.toString()}`,
    chain_id: chainId,
    finalized_checkpoint_id: String(checkpointId),
    deposit_tree_root: depositTreeRoot,
    withdrawal_tree_root: withdrawalTreeRoot,
    block_number: safeBlockNumber,
    tx_hash: txHash,
  });
});
