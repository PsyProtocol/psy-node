use std::{array, fs, path::PathBuf, str::FromStr, sync::Arc, sync::OnceLock};

use anyhow::Context;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut, protocol::core_types::QNetworkTreeConstants};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::hash_types::HashOut,
    plonk::{circuit_data::CommonCircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_client_data::traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync};
use psy_core::{constants::chain_id::PsyChainNetworkType, job::job_id::ProvingJobCircuitType, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafCompact},
};
use serde::Deserialize;
use crate::bridge::prove_proxy_client::{BridgeAggCheckpointLeaf, BridgeAggDeltaProof, BridgeAggSlotWitness, BridgeDepositBatchGroth16Proof, BridgeDepositBatchWitnessInput, BridgeDepositLeafInput as ProxyDepositLeafInput, ProveProxyClient};
use psy_plonky2_circuits::{
    bridge::{
        circuits::{
            bridge_agg_final::BridgeAggFinalCircuit,
            bridge_agg::BridgeAggProveResult,
            bridge_wrap::{BridgeWrapCircuit, DepositBatchWrapCircuit, UncompressedGroth16ProofData},
        },
        gadgets::{
            tree_root_in_contract_state::TreeRootInContractStateWitnessInput,
        },
    },
    circuit_library::get_plonky2_circuit_library_and_prover_for_network,
    coordinator::coordinator_helper::QEDCoordinatorCircuitManager,
    proof_minifier::pm_chain::QEDProofMinifierChain,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;
use psy_plonky2_common_circuits::bridge::deposit_batch_append_circuit::{
    BatchAppendInputs as CircuitBatchAppendInputs,
    BatchAppendPreimage,
    compute_batch_append_preimage,
    compute_batch_slot_data_words,
    DepositBatchAppendCircuit,
    DepositLeafData as CircuitDepositLeafData,
    DEPOSIT_BATCH_APPEND_SLOT_WORDS,
    MAX_DEPOSIT_BATCH_SIZE,
};
use psy_provider::provider::RpcProvider;
use serde::Serialize;

use crate::bridge::constants::{
    BRIDGE_USER_ID_U64, DEPOSIT_TREE_AGG_SLOT_BASE, DEPOSIT_TREE_CHAIN_ROOT_SLOT_BASE,
    DEPOSIT_TREE_CONTRACT_ID, MAX_CONCURRENT_PROXY_PROOFS, TOP_TREE_HEIGHT,
    WITHDRAWAL_TREE_AGG_SLOT_BASE, WITHDRAWAL_TREE_CHAIN_ROOT_SLOT_BASE,
    WITHDRAWAL_TREE_CONTRACT_ID,
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

type ClientQHashOut = psy_client_common::data::qhashout::QHashOut<F>;

const CHECKPOINT_TREE_HEIGHT: usize = 32;
const DEPOSIT_BATCH_TREE_HEIGHT: usize = 32;
const NETWORK_TYPE: PsyChainNetworkType = PsyChainNetworkType::LocalDevnet;
const GLOBAL_USER_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::GLOBAL_USER_TREE_HEIGHT_USIZE;
const GLOBAL_CONTRACT_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE;
const DEPOSIT_CONTRACT_STATE_TREE_HEIGHT: usize =
    psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize;
const WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT: usize =
    psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize;

fn bridge_contract_state_tree_height(contract_id: u32) -> anyhow::Result<u8> {
    match contract_id {
        DEPOSIT_TREE_CONTRACT_ID => Ok(DEPOSIT_CONTRACT_STATE_TREE_HEIGHT as u8),
        WITHDRAWAL_TREE_CONTRACT_ID => Ok(WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT as u8),
        _ => anyhow::bail!("unsupported bridge tree contract id: {}", contract_id),
    }
}

pub(crate) fn cached_bridge_coordinator_circuits() -> anyhow::Result<&'static QEDCoordinatorCircuitManager<C, D>> {
    static CACHE: OnceLock<QEDCoordinatorCircuitManager<C, D>> = OnceLock::new();
    if let Some(cached) = CACHE.get() {
        return Ok(cached);
    }
    eprintln!("Building QEDCoordinatorCircuitManager via get_plonky2_circuit_library_and_prover_for_network...");
    let (_, circuits) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(NETWORK_TYPE)
        .map_err(|e| anyhow::anyhow!("failed to build bridge coordinator circuits: {}", e))?;
    let _ = CACHE.set(circuits);
    CACHE.get().ok_or_else(|| anyhow::anyhow!("bridge coordinator circuit cache is unexpectedly empty"))
}

#[derive(Deserialize)]
struct BridgeProxyReceipt {
    #[serde(rename = "blockNumber")]
    block_number: u64,
}

#[derive(Deserialize)]
struct BridgeProxyArtifact {
    receipt: BridgeProxyReceipt,
}

#[derive(Clone)]
struct L1DeploymentConfig {
    bridge_address: Address,
    deployment_block: BlockNumberOrTag,
    l1_chain_index: u8,
}

fn load_l1_deployment_config(deployments_network: &str) -> anyhow::Result<L1DeploymentConfig> {
    let deployed =
        crate::bridge::api_client::load_deployed_contracts(deployments_network)
            .with_context(|| format!("failed to load deployed-contracts.json for {deployments_network}"))?;

    let bridge_addr = deployed
        .core
        .get("Bridge")
        .or_else(|| deployed.contracts.get("Bridge"))
        .ok_or_else(|| {
            anyhow::anyhow!("Bridge address not found in deployments for {deployments_network}")
        })?;
    let bridge_address = Address::from_str(bridge_addr).with_context(|| {
        format!("invalid Bridge address in deployments: {bridge_addr}")
    })?;

    let l1_chain_index = match &deployed.protocol {
        Some(p) => p.chain.l1_chain_index,
        None if deployments_network == "localhost" => 0,
        None => anyhow::bail!(
            "missing protocol.chain.l1ChainIndex in deployed-contracts.json for {deployments_network}"
        ),
    };

    let proxy_path =
        crate::bridge::api_client::resolve_deployments_file(deployments_network, "Bridge_Proxy.json");
    let deployment_block = match fs::read_to_string(&proxy_path) {
        Ok(raw) => match serde_json::from_str::<BridgeProxyArtifact>(&raw) {
            Ok(a) => BlockNumberOrTag::Number(a.receipt.block_number),
            Err(_) => {
                tracing::warn!(
                    path = %proxy_path.display(),
                    "Bridge_Proxy.json parse failed; falling back to earliest log scan"
                );
                BlockNumberOrTag::Earliest
            }
        },
        Err(_) => {
            tracing::warn!(
                path = %proxy_path.display(),
                "missing Bridge_Proxy.json; falling back to earliest log scan"
            );
            BlockNumberOrTag::Earliest
        }
    };

    Ok(L1DeploymentConfig {
        bridge_address,
        deployment_block,
        l1_chain_index,
    })
}

sol! {
    function getDepositFrontier() external view returns (bytes32[32] memory);
    function provedDepositCount() external view returns (uint256);
    function pendingDepositCount() external view returns (uint256);
    function batchAppend(
        uint256[8] proof,
        uint256[] publicInputs,
        uint256[1312] slotData
    );
}

fn to_core_hash(h: ClientQHashOut) -> QHashOut<F> {
    QHashOut(h.0)
}

fn to_core_merkle_proof(
    p: psy_crypto::hash::merkle::core::MerkleProofCore<ClientQHashOut>,
) -> parth_core::crypto::hash::merkle_proof::MerkleProofCore<QHashOut<F>> {
    parth_core::crypto::hash::merkle_proof::MerkleProofCore {
        root: to_core_hash(p.root),
        value: to_core_hash(p.value),
        index: p.index,
        siblings: p.siblings.into_iter().map(to_core_hash).collect(),
    }
}

fn to_core_user_leaf(leaf: psy_client_data::qdata::user::PsyUserLeaf<F>) -> psy_data::v1::qdata::user::PQEDUserLeaf<F, QHashOut<F>> {
    psy_data::v1::qdata::user::PQEDUserLeaf {
        public_key: to_core_hash(leaf.public_key),
        user_state_tree_root: to_core_hash(leaf.user_state_tree_root),
        balance: leaf.balance,
        nonce: leaf.nonce,
        last_checkpoint_id: leaf.last_checkpoint_id,
        event_index: leaf.event_index,
        user_id: leaf.user_id,
    }
}

async fn fetch_tree_root_witness(
    provider: &RpcProvider,
    checkpoint_id: u64,
    owner_user_id: u64,
    contract_id: u32,
) -> anyhow::Result<TreeRootInContractStateWitnessInput<F>> {
    let contract_state_tree_height = bridge_contract_state_tree_height(contract_id)?;
    let slot0_proof = provider
        .get_user_contract_state_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id, contract_state_tree_height, 0)
        .await?;
    let slot1_proof = provider
        .get_user_contract_state_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id, contract_state_tree_height, 1)
        .await?;
    let contract_proof = provider
        .get_user_contract_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id)
        .await?;
    let user_leaf = provider.get_user_leaf_data(checkpoint_id, owner_user_id).await?;
    let user_tree_proof = provider.get_user_tree_merkle_proof(checkpoint_id, owner_user_id).await?;

    Ok(TreeRootInContractStateWitnessInput {
        owner_user_id,
        contract_id: contract_id as u64,
        user_leaf: to_core_user_leaf(user_leaf),
        slot0_proof: to_core_merkle_proof(slot0_proof),
        slot1_proof: to_core_merkle_proof(slot1_proof),
        contract_proof: to_core_merkle_proof(contract_proof),
        user_tree_proof: to_core_merkle_proof(user_tree_proof),
    })
}

fn slot_value_to_u32x4(value: ClientQHashOut) -> [u32; 4] {
    let elems = value.0.elements;
    [
        elems[0].to_canonical_u64() as u32,
        elems[1].to_canonical_u64() as u32,
        elems[2].to_canonical_u64() as u32,
        elems[3].to_canonical_u64() as u32,
    ]
}

fn u32x8_to_bytes32(words: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

async fn fetch_slot_pair_as_b256(
    provider: &RpcProvider,
    checkpoint_id: u64,
    owner_user_id: u64,
    contract_id: u32,
    slot_lo: u64,
) -> anyhow::Result<B256> {
    let contract_state_tree_height = bridge_contract_state_tree_height(contract_id)?;
    let slot0 = provider
        .get_user_contract_state_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id, contract_state_tree_height, slot_lo)
        .await?;
    let slot1 = provider
        .get_user_contract_state_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id, contract_state_tree_height, slot_lo + 1)
        .await?;
    let lo = slot_value_to_u32x4(slot0.value);
    let hi = slot_value_to_u32x4(slot1.value);
    Ok(B256::from(u32x8_to_bytes32([
        lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3],
    ])))
}

async fn fetch_tree_subroot_and_top_proof(
    provider: &RpcProvider,
    checkpoint_id: u64,
    owner_user_id: u64,
    contract_id: u32,
    chain_index: u8,
) -> anyhow::Result<(B256, [B256; 9])> {
    let (chain_root_slot_base, agg_slot_base) = if contract_id == WITHDRAWAL_TREE_CONTRACT_ID {
        (WITHDRAWAL_TREE_CHAIN_ROOT_SLOT_BASE, WITHDRAWAL_TREE_AGG_SLOT_BASE)
    } else {
        (DEPOSIT_TREE_CHAIN_ROOT_SLOT_BASE, DEPOSIT_TREE_AGG_SLOT_BASE)
    };

    let subtree_root = fetch_slot_pair_as_b256(
        provider,
        checkpoint_id,
        owner_user_id,
        contract_id,
        chain_root_slot_base + (chain_index as u64) * 2,
    )
    .await?;

    let mut proof = [B256::ZERO; 9];
    proof[0] = subtree_root;

    let mut node = 256u64 + chain_index as u64;
    for level in 0..TOP_TREE_HEIGHT {
        let sibling = if (node & 1) == 0 { node + 1 } else { node - 1 };
        proof[level + 1] =
            fetch_slot_pair_as_b256(provider, checkpoint_id, owner_user_id, contract_id, agg_slot_base + sibling * 2).await?;
        node >>= 1;
    }

    Ok((subtree_root, proof))
}

#[derive(Serialize)]
pub struct ProveBridgeAggOutput {
    pub from_checkpoint: u64,
    pub to_checkpoint: u64,
    pub num_checkpoints_aggregated: u64,
    /// L1 chain index used for this proof (read from config; no longer a circuit PI).
    pub l1_chain_index: u64,
    pub bridge_agg_public_inputs_count: usize,
    pub bridge_agg_public_inputs: Vec<String>,
    pub groth16_proof: UncompressedGroth16ProofData,
    pub solidity_proof: [String; 8],
    pub solidity_public_inputs: [String; 2],
    pub checkpoint_roots: Vec<String>,
    pub deposit_tree_root: String,
    pub deposit_subtree_root: String,
    pub deposit_merkle_proof: [String; 9],
    pub withdrawal_tree_root: String,
    pub withdrawal_subtree_root: String,
    pub withdrawal_merkle_proof: [String; 9],
    pub end_checkpoint_index: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DepositLeafData {
    pub shield_address: [u32; 8],
    pub token: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub amount: [u32; 8],
    pub chain_index: u32,
    pub note_commitment: [u32; 8],
}

#[derive(Clone, Debug)]
pub struct DepositBatchAppendInputs {
    pub from_index: u32,
    pub to_index: u32,
    pub old_frontier: Vec<QHashOut<F>>,
    pub leaves: Vec<DepositLeafData>,
}

#[derive(Clone, Debug)]
pub struct DepositBatchAppendCall {
    pub from_index: u32,
    pub to_index: u32,
    pub batch_commit: [u32; 8],
    pub slot_data: Vec<U256>,
    pub call_data: Bytes,
}

#[derive(Clone, Debug)]
pub struct BridgeProveResult {
    pub from_checkpoint: u64,
    pub to_checkpoint: u64,
    pub num_checkpoints_aggregated: u64,
    pub proof_path: PathBuf,
    pub deposit_tree_root: String,
    pub withdrawal_tree_root: String,
}

fn with_0x(s: &str) -> String {
    if s.starts_with("0x") {
        s.to_string()
    } else {
        format!("0x{}", s)
    }
}

async fn call_frontier<P: Provider>(provider: &P, to: Address) -> anyhow::Result<[B256; 32]> {
    let tx = TransactionRequest::default()
        .to(to)
        .input(getDepositFrontierCall {}.abi_encode().into());
    let raw = provider.call(tx).await.context("getDepositFrontier eth_call failed")?;
    let frontier = getDepositFrontierCall::abi_decode_returns(&raw)
        .context("failed to decode getDepositFrontier return")?;
    Ok(frontier)
}

fn u256_to_u32(label: &str, value: U256) -> anyhow::Result<u32> {
    anyhow::ensure!(value <= U256::from(u32::MAX), "{label} exceeds u32 range: {value}");
    Ok(value.to::<u32>())
}

fn bytes32_to_u32x8(bytes32: B256) -> [u32; 8] {
    let bytes = bytes32.as_slice();
    array::from_fn(|i| {
        let start = i * 4;
        u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
    })
}

fn u256_to_u32x8(value: U256) -> [u32; 8] {
    let bytes = value.to_be_bytes::<32>();
    array::from_fn(|i| {
        let start = i * 4;
        u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
    })
}

fn address_to_u32x8(address: Address) -> [u32; 8] {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    bytes32_to_u32x8(B256::from(bytes))
}

fn keccak_u32_words_be(words: &[u32]) -> [u32; 8] {
    use tiny_keccak::{Hasher as _, Keccak};
    let mut buf = Vec::with_capacity(words.len() * 4);
    for word in words {
        buf.extend_from_slice(&word.to_be_bytes());
    }
    let mut keccak = Keccak::v256();
    keccak.update(&buf);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    array::from_fn(|i| {
        let start = i * 4;
        u32::from_be_bytes(out[start..start + 4].try_into().unwrap())
    })
}

fn bytes32_to_qhashout(bytes32: B256) -> QHashOut<F> {
    let bytes = bytes32.as_slice();
    let f3 = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let f2 = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let f1 = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let f0 = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    QHashOut(HashOut {
        elements: [
            F::from_noncanonical_u64(f0),
            F::from_noncanonical_u64(f1),
            F::from_noncanonical_u64(f2),
            F::from_noncanonical_u64(f3),
        ],
    })
}

fn deposit_leaf_to_circuit(leaf: &DepositLeafData) -> CircuitDepositLeafData {
    CircuitDepositLeafData {
        shield_address: leaf.shield_address,
        token: leaf.token,
        l2_token_contract_id: leaf.l2_token_contract_id,
        amount: leaf.amount,
        chain_index: leaf.chain_index,
        note_commitment: leaf.note_commitment,
    }
}

fn build_deposit_batch_append_call(
    frontier: [QHashOut<F>; DEPOSIT_BATCH_TREE_HEIGHT],
    from_index: u32,
    leaves: &[DepositLeafData],
) -> anyhow::Result<(DepositBatchAppendCall, [QHashOut<F>; DEPOSIT_BATCH_TREE_HEIGHT])> {
    anyhow::ensure!(!leaves.is_empty(), "deposit batch append chunk is empty");
    anyhow::ensure!(
        leaves.len() <= MAX_DEPOSIT_BATCH_SIZE,
        "deposit batch append chunk exceeds max size: {} > {}",
        leaves.len(),
        MAX_DEPOSIT_BATCH_SIZE
    );

    let deposits = leaves.iter().map(deposit_leaf_to_circuit).collect::<Vec<_>>();
    let inputs = CircuitBatchAppendInputs {
        frontier,
        from_index,
        deposits,
        bridge_user_id: BRIDGE_USER_ID_U64 as u32,
    };
    let deposit_batch = DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, DEPOSIT_BATCH_TREE_HEIGHT);
    let deposit_batch_proof = deposit_batch.generate_proof(&inputs)?;
    let preimage = compute_batch_append_preimage(&inputs);
    let deposit_batch_minifier =
        QEDProofMinifierChain::<D, F, C>::new(&deposit_batch.circuit_data.verifier_only, &deposit_batch.circuit_data.common, 2);
    let minified_deposit_batch_proof = deposit_batch_minifier.prove(&deposit_batch_proof)?;
    let fingerprint = QHashOut(deposit_batch_minifier.get_fingerprint());
    let deposit_batch_wrap = DepositBatchWrapCircuit::new(
        deposit_batch_minifier.get_common_data(),
        fingerprint,
        deposit_batch_minifier.get_verifier_data().constants_sigmas_cap.height(),
    );
    let deposit_batch_groth16_wrapper = DepositBatchWrapCircuit::new(
        deposit_batch_minifier.get_common_data(),
        fingerprint,
        deposit_batch_minifier.get_verifier_data().constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/.psy/keystore/deposit_append/", home::home_dir().unwrap().display()));
    let wrapped = deposit_batch_wrap.prove_groth16_with_shared_wrapper(
        &deposit_batch_groth16_wrapper,
        deposit_batch_minifier.get_verifier_data(),
        &minified_deposit_batch_proof,
    )?;
    let solidity = [
        with_0x(&wrapped.pi_a[0]),
        with_0x(&wrapped.pi_a[1]),
        with_0x(&wrapped.pi_b[0][1]),
        with_0x(&wrapped.pi_b[0][0]),
        with_0x(&wrapped.pi_b[1][1]),
        with_0x(&wrapped.pi_b[1][0]),
        with_0x(&wrapped.pi_c[0]),
        with_0x(&wrapped.pi_c[1]),
    ];
    let mut proof = [U256::ZERO; 8];
    for (i, value) in solidity.iter().enumerate() {
        proof[i] = U256::from_str_radix(value.trim_start_matches("0x"), 16)
            .with_context(|| format!("invalid batchAppend proof word {i}: {value}"))?;
    }
    let public_inputs = preimage
        .to_u32_words()
        .into_iter()
        .map(U256::from)
        .collect::<Vec<_>>();
    let slot_data_vec = compute_batch_slot_data_words(&inputs.deposits)
        .into_iter()
        .map(U256::from)
        .collect::<Vec<_>>();
    let slot_data: [U256; 1312] = slot_data_vec
        .clone()
        .try_into()
        .map_err(|v: Vec<U256>| anyhow::anyhow!("invalid deposit slot data len: {}", v.len()))?;
    let call = batchAppendCall {
        proof,
        publicInputs: public_inputs,
        slotData: slot_data,
    };
    Ok((
        DepositBatchAppendCall {
            from_index: preimage.from_index,
            to_index: preimage.to_index,
            batch_commit: preimage.batch_commit,
            slot_data: slot_data_vec,
            call_data: Bytes::from(call.abi_encode()),
        },
        preimage.new_frontier,
    ))
}

async fn fetch_deposit_batch_inputs(
    target_deposit_count: u32,
    l1_rpc_url: &str,
    config: &L1DeploymentConfig,
    deployments_network: &str,
) -> anyhow::Result<DepositBatchAppendInputs> {
    let bridge = config.bridge_address;
    let from_block = &config.deployment_block;
    let rpc_url = l1_rpc_url
        .parse()
        .with_context(|| format!("invalid L1 rpc url: {}", l1_rpc_url))?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    let proved_count = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
    let pending_count = crate::bridge::api_client::eth_call_u256(&provider, bridge, pendingDepositCountCall {}).await?;
    let from_index = u256_to_u32("provedDepositCount", proved_count)?;
    let pending_index = u256_to_u32("pendingDepositCount", pending_count)?;
    let to_index = target_deposit_count;
    anyhow::ensure!(
        from_index <= to_index,
        "target_deposit_count {} < current provedDepositCount {}",
        to_index,
        from_index
    );
    anyhow::ensure!(
        to_index <= pending_index,
        "target_deposit_count {} > pendingDepositCount {}",
        to_index,
        pending_index
    );

    let frontier_words = call_frontier(&provider, bridge).await?;
    let old_frontier = frontier_words.iter().copied().map(bytes32_to_qhashout).collect::<Vec<_>>();

    let current_head = provider
        .get_block_number()
        .await
        .with_context(|| "failed to fetch current L1 block number")?;
    let safe_from_block = match *from_block {
        BlockNumberOrTag::Number(n) if n > current_head => {
            tracing::warn!(
                deployment_block = n,
                current_head,
                "Bridge deployment block > current head; falling back to Earliest"
            );
            BlockNumberOrTag::Earliest
        }
        other => other,
    };

    let records = crate::bridge::deposit_logs::bulk_fetch_deposit_records(
        &provider,
        bridge,
        safe_from_block,
        from_index,
        to_index,
    )
    .await?;

    let mut leaves = Vec::with_capacity((to_index - from_index) as usize);
    for index in from_index..to_index {
        let event = records.get(&index).ok_or_else(|| {
            anyhow::anyhow!("missing DepositRecorded log for index {}", index)
        })?;
        let leaf = DepositLeafData {
            shield_address: bytes32_to_u32x8(event.shieldAddress),
            token: address_to_u32x8(event.token),
            l2_token_contract_id: bytes32_to_u32x8(event.l2TokenContractId),
            amount: u256_to_u32x8(event.amount),
            chain_index: u32::from(event.chainIndex),
            note_commitment: bytes32_to_u32x8(event.noteCommitment),
        };
        // Verify decoded data matches the on-chain leaf hash.
        let reconstructed = keccak_u32_words_be(&deposit_leaf_to_circuit(&leaf).to_u32_words());
        let expected = bytes32_to_u32x8(event.leafHash);
        anyhow::ensure!(
            reconstructed == expected,
            "DepositRecorded decode mismatch at index {}: reconstructed leaf {:?} != event leaf {:?}",
            index,
            reconstructed,
            expected
        );
        leaves.push(leaf);
    }

    Ok(DepositBatchAppendInputs {
        from_index,
        to_index,
        old_frontier,
        leaves,
    })
}

pub async fn build_deposit_batch_append_calls(
    l1_rpc_url: &str,
    deployments_network: &str,
    target_deposit_count: u32,
) -> anyhow::Result<Vec<DepositBatchAppendCall>> {
    let l1_config = load_l1_deployment_config(deployments_network)?;
    let inputs = fetch_deposit_batch_inputs(
        target_deposit_count,
        l1_rpc_url,
        &l1_config,
        deployments_network,
    )
    .await?;
    if inputs.leaves.is_empty() {
        // target equals current provedDepositCount: nothing to append.
        return Ok(Vec::new());
    }
    let expected_len = (inputs.to_index - inputs.from_index) as usize;
    anyhow::ensure!(
        inputs.leaves.len() == expected_len,
        "deposit batch input length mismatch: expected {} got {}",
        expected_len,
        inputs.leaves.len()
    );
    anyhow::ensure!(
        inputs.old_frontier.len() == DEPOSIT_BATCH_TREE_HEIGHT,
        "deposit frontier length mismatch: expected {}, got {}",
        DEPOSIT_BATCH_TREE_HEIGHT,
        inputs.old_frontier.len()
    );

    let mut frontier: [QHashOut<F>; DEPOSIT_BATCH_TREE_HEIGHT] = inputs
        .old_frontier
        .try_into()
        .map_err(|v: Vec<QHashOut<F>>| anyhow::anyhow!("invalid frontier length: {}", v.len()))?;
    let mut from_index = inputs.from_index;
    let mut calls = Vec::new();
    for chunk in inputs.leaves.chunks(MAX_DEPOSIT_BATCH_SIZE) {
        let (call, new_frontier) = build_deposit_batch_append_call(frontier, from_index, chunk)?;
        tracing::info!(
            from_index = call.from_index,
            to_index = call.to_index,
            chunk_size = chunk.len(),
            "built deposit batchAppend Groth16 calldata"
        );
        from_index = call.to_index;
        frontier = new_frontier;
        calls.push(call);
    }
    anyhow::ensure!(
        from_index == inputs.to_index,
        "deposit batch append chunking ended at {}, expected {}",
        from_index,
        inputs.to_index
    );
    Ok(calls)
}

pub async fn run_prove_bridge_agg_with_result(
    from_checkpoint: u64,
    to_checkpoint: u64,
    rpc_config: String,
    out_json: PathBuf,
    deployments_network: String,
) -> anyhow::Result<BridgeProveResult> {
    // Checkpoint 0 uses genesis transition proof path, not the normal
    // checkpoint_root_transition format; verified proofs start from cp 1.
    let from_checkpoint = from_checkpoint.max(1);
    anyhow::ensure!(from_checkpoint <= to_checkpoint, "from_checkpoint must be <= to_checkpoint");
    let num_checkpoints_aggregated = to_checkpoint - from_checkpoint + 1;
    anyhow::ensure!(
        num_checkpoints_aggregated >= 1,
        "bridge aggregation requires at least 1 checkpoint, got {} (from={} to={})",
        num_checkpoints_aggregated,
        from_checkpoint,
        to_checkpoint
    );

    let coordinator_circuits = cached_bridge_coordinator_circuits()?;

    let checkpoint_common_data: &CommonCircuitData<F, D> = coordinator_circuits.checkpoint_root_transition.get_common_circuit_data_ref();
    let checkpoint_verifier_data = coordinator_circuits.checkpoint_root_transition.get_verifier_config_ref();
    let cap_height = checkpoint_verifier_data.constants_sigmas_cap.height();
    let checkpoint_state_transition_fingerprint = coordinator_circuits.checkpoint_root_transition.get_fingerprint();
    // For step_commit, use the SAME fingerprint that RCP circuit used during genesis proving.
    // This is NOT base_fingerprint or minifier fingerprint, but the cached library fingerprint
    // for GenerateRollupStateTransitionProof (circuit type 32).
    use psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library;
    let cached_lib = get_cached_circuit_library::<F>();
    let checkpoint_step_commit_fingerprint = cached_lib
        .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
        .expect("GenerateRollupStateTransitionProof not found in cached circuit library");
    let l1_config = load_l1_deployment_config(&deployments_network)?;

    let provider = RpcProvider::new_with_config_path(&rpc_config)?;

    eprintln!(
        "Pre-fetching checkpoint proofs and merkle data for checkpoints {} to {}...",
        from_checkpoint, to_checkpoint
    );

    let final_checkpoint_proof: ProofWithPublicInputs<F, C, D> = {
        let proof_bytes = provider.get_checkpoint_state_transition_proof(to_checkpoint).await?;
        bincode::deserialize(&proof_bytes)
            .map_err(|e| anyhow::format_err!("failed to deserialize final checkpoint proof: {}", e))?
    };
    let pi_hash = QHashOut::<F>::from_felt_slice(&final_checkpoint_proof.public_inputs);
    tracing::info!("Fetched final checkpoint {} proof PI hash: {:?}", to_checkpoint, pi_hash);

    let mut delta_merkle_proofs = Vec::new();
    let mut pre_delta_merkle_proofs = Vec::new();
    for cp_id in from_checkpoint..=to_checkpoint {
        let leaf_hash = provider.get_checkpoint_tree_leaf_hash(cp_id, cp_id).await?;
        let merkle_proof = provider.get_checkpoint_tree_merkle_proof(cp_id, cp_id).await?;
        let delta_proof = DeltaMerkleProofCore::from_params::<plonky2::hash::poseidon::PoseidonHash>(
            cp_id,
            QHashOut::default(),
            to_core_hash(leaf_hash),
            merkle_proof.siblings.into_iter().map(to_core_hash).collect(),
        );
        tracing::info!(
            "Delta proof checkpoint {}: old_root={:?} new_root={:?} new_value={:?}",
            cp_id,
            delta_proof.old_root,
            delta_proof.new_root,
            delta_proof.new_value
        );
        delta_merkle_proofs.push(delta_proof);

        anyhow::ensure!(cp_id > 0, "from_checkpoint must be > 0 to supply pre-checkpoint merkle proofs");
        let pre_id = cp_id - 1;
        let pre_leaf_hash = provider.get_checkpoint_tree_leaf_hash(pre_id, pre_id).await?;
        let pre_merkle_proof = provider.get_checkpoint_tree_merkle_proof(pre_id, pre_id).await?;
        let pre_delta_proof = DeltaMerkleProofCore::from_params::<plonky2::hash::poseidon::PoseidonHash>(
            pre_id,
            QHashOut::default(),
            to_core_hash(pre_leaf_hash),
            pre_merkle_proof.siblings.into_iter().map(to_core_hash).collect(),
        );
        pre_delta_merkle_proofs.push(pre_delta_proof);
    }

    let leaf_data = provider.get_checkpoint_leaf_data(to_checkpoint).await?;
    let leaf_compact = leaf_data.to_compact::<psy_client_data::config::store_config::PsyHasher>();
    let final_checkpoint_leaf = PQEDCheckpointLeafCompact {
        global_chain_root: to_core_hash(leaf_compact.global_chain_root),
        stats_hash: to_core_hash(leaf_compact.stats_hash),
    };

    // start_chain_hash must be the chain hash immediately before `from_checkpoint`.
    // For from_checkpoint == 1, this is the genesis checkpoint transition PI = H(H(root_0, leaf_0), genesis_fingerprint).
    // For from_checkpoint > 1, this is checkpoint (from_checkpoint - 1)'s proof public input hash.
    let genesis_fingerprint = coordinator_circuits.genesis_checkpoint_root_transition.get_fingerprint();
    let start_chain_hash = if from_checkpoint <= 1 {
        use plonky2::hash::poseidon::PoseidonHash;
        use plonky2::plonk::config::Hasher;
        let genesis_root = to_core_hash(provider.get_checkpoint_tree_root(0).await?);
        let genesis_leaf = to_core_hash(provider.get_checkpoint_tree_leaf_hash(0, 0).await?);
        let root_leaf = PoseidonHash::two_to_one(genesis_root.0, genesis_leaf.0);
        QHashOut(PoseidonHash::two_to_one(root_leaf.into(), genesis_fingerprint.0))
    } else {
        let prev_proof_bytes = provider
            .get_checkpoint_state_transition_proof(from_checkpoint - 1)
            .await?;
        let prev_proof: ProofWithPublicInputs<F, C, D> =
            bincode::deserialize(&prev_proof_bytes)
                .map_err(|e| anyhow::format_err!("failed to deserialize previous checkpoint proof: {}", e))?;
        QHashOut::from_felt_slice(&prev_proof.public_inputs[..4])
    };

    let deposit_root_witness =
        fetch_tree_root_witness(&provider, to_checkpoint, BRIDGE_USER_ID_U64, DEPOSIT_TREE_CONTRACT_ID).await?;

    let withdrawal_root_witness =
        fetch_tree_root_witness(&provider, to_checkpoint, BRIDGE_USER_ID_U64, WITHDRAWAL_TREE_CONTRACT_ID).await?;

    let l1_chain_index = l1_config.l1_chain_index;

    // Fetch global state roots to bind the gadget's user_tree_root to the checkpoint leaf.
    let checkpoint_global_state_roots = {
        let roots = provider.get_checkpoint_global_state_roots(to_checkpoint).await?;
        PQEDCheckpointGlobalStateRoots {
            contract_tree_root: to_core_hash(roots.contract_tree_root),
            deposit_tree_root: to_core_hash(roots.deposit_tree_root),
            user_tree_root: to_core_hash(roots.user_tree_root),
            withdrawal_tree_root: to_core_hash(roots.withdrawal_tree_root),
            user_registration_tree_root: to_core_hash(roots.user_registration_tree_root),
            validator_tree_root: to_core_hash(roots.validator_tree_root),
        }
    };

    eprintln!("Pre-fetching complete. Proving bridge aggregation...");

    let result = BridgeAggFinalCircuit::<C, D>::prove_range(
        from_checkpoint,
        to_checkpoint,
        start_chain_hash,
        checkpoint_common_data,
        cap_height,
        checkpoint_state_transition_fingerprint,
        checkpoint_step_commit_fingerprint,
        &final_checkpoint_proof,
        &checkpoint_verifier_data,
        &delta_merkle_proofs,
        &pre_delta_merkle_proofs,
        &final_checkpoint_leaf,
        &checkpoint_global_state_roots,
        &deposit_root_witness,
        &withdrawal_root_witness,
        CHECKPOINT_TREE_HEIGHT,
        GLOBAL_USER_TREE_HEIGHT,
        GLOBAL_CONTRACT_TREE_HEIGHT,
        DEPOSIT_CONTRACT_STATE_TREE_HEIGHT,
        WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT,
    )?;
    eprintln!(
        "Bridge aggregation proof generated successfully. step_count: {}",
        to_checkpoint - from_checkpoint + 1
    );

    let bridge_agg_proof = result.proof;
    let bridge_agg_common = result.common_data;
    let bridge_agg_fingerprint = result.fingerprint;
    let bridge_agg_verifier_data = result.verifier_data;

    anyhow::ensure!(
        bridge_agg_proof.public_inputs.len() == 26,
        "BridgeAgg proof public inputs width must be 26, got {}",
        bridge_agg_proof.public_inputs.len()
    );
    anyhow::ensure!(
        bridge_agg_proof.public_inputs[25].to_canonical_u64() == num_checkpoints_aggregated,
        "BridgeAgg public input num_checkpoints_aggregated mismatch: pi={} expected={}",
        bridge_agg_proof.public_inputs[25].to_canonical_u64(),
        num_checkpoints_aggregated
    );
    eprintln!("BridgeAgg proof public inputs: {:?}", bridge_agg_proof.public_inputs);
    let felt4_to_bytes32_hex = |start: usize| -> String {
        let mut out = [0u8; 32];
        for i in 0..4 {
            let v = bridge_agg_proof.public_inputs[start + (3 - i)].to_canonical_u64();
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
        }
        format!("0x{}", hex::encode(out))
    };
    let u32x8_to_bytes32_hex = |start: usize| -> String {
        let mut out = [0u8; 32];
        for i in 0..8 {
            let v = bridge_agg_proof.public_inputs[start + i].to_canonical_u64() as u32;
            out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
        }
        format!("0x{}", hex::encode(out))
    };
    let mut checkpoint_roots = Vec::with_capacity(2);
    checkpoint_roots.push(felt4_to_bytes32_hex(0));
    checkpoint_roots.push(felt4_to_bytes32_hex(20));
    let deposit_tree_root = u32x8_to_bytes32_hex(4);
    let withdrawal_tree_root = u32x8_to_bytes32_hex(12);
    let end_checkpoint_index = bridge_agg_proof.public_inputs[24].to_canonical_u64();
    anyhow::ensure!(
        end_checkpoint_index == to_checkpoint,
        "BridgeAgg public input end_checkpoint_index mismatch: pi={} expected={}",
        end_checkpoint_index,
        to_checkpoint
    );
    tracing::info!(
        deployments_network,
        l1_chain_index,
        "resolved L1 chain index for bridge top-tree proofs"
    );
    let (deposit_subtree_root, deposit_merkle_proof_b256) = fetch_tree_subroot_and_top_proof(
        &provider,
        to_checkpoint,
        BRIDGE_USER_ID_U64,
        DEPOSIT_TREE_CONTRACT_ID,
        l1_chain_index,
    )
    .await?;
    let (withdrawal_subtree_root, withdrawal_merkle_proof_b256) = fetch_tree_subroot_and_top_proof(
        &provider,
        to_checkpoint,
        BRIDGE_USER_ID_U64,
        WITHDRAWAL_TREE_CONTRACT_ID,
        l1_chain_index,
    )
    .await?;
    let b256_array_to_hex = |arr: [B256; 9]| arr.map(|x| format!("{:#066x}", x));
    eprintln!("Building BridgeWrapCircuit...");
    let bridge_wrap = BridgeWrapCircuit::new(
        &bridge_agg_common,
        bridge_agg_fingerprint,
        bridge_agg_verifier_data.constants_sigmas_cap.height(),
    );
    let bridge_groth16_wrapper = BridgeWrapCircuit::new(
        &bridge_agg_common,
        bridge_agg_fingerprint,
        bridge_agg_verifier_data.constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/.psy/keystore/", home::home_dir().unwrap().display()));

    eprintln!("Proving BridgeWrapCircuit (Stage 2: Groth16 wrap)...");
    let groth16_proof = bridge_wrap.prove_groth16_with_shared_wrapper(&bridge_groth16_wrapper, &bridge_agg_verifier_data, &bridge_agg_proof)?;
    eprintln!("Groth16 proof generated successfully.");

    let solidity_proof = [
        with_0x(&groth16_proof.pi_a[0]),
        with_0x(&groth16_proof.pi_a[1]),
        with_0x(&groth16_proof.pi_b[0][1]),
        with_0x(&groth16_proof.pi_b[0][0]),
        with_0x(&groth16_proof.pi_b[1][1]),
        with_0x(&groth16_proof.pi_b[1][0]),
        with_0x(&groth16_proof.pi_c[0]),
        with_0x(&groth16_proof.pi_c[1]),
    ];
    let solidity_public_inputs = [with_0x(&groth16_proof.public_inputs[0]), with_0x(&groth16_proof.public_inputs[1])];
    let output = ProveBridgeAggOutput {
        from_checkpoint,
        to_checkpoint,
        num_checkpoints_aggregated,
        l1_chain_index: u64::from(l1_chain_index),
        bridge_agg_public_inputs_count: bridge_agg_proof.public_inputs.len(),
        bridge_agg_public_inputs: bridge_agg_proof
            .public_inputs
            .iter()
            .map(|x| x.to_canonical_u64().to_string())
            .collect(),
        groth16_proof,
        solidity_proof,
        solidity_public_inputs,
        checkpoint_roots,
        deposit_tree_root,
        deposit_subtree_root: format!("{:#066x}", deposit_subtree_root),
        deposit_merkle_proof: b256_array_to_hex(deposit_merkle_proof_b256),
        withdrawal_tree_root,
        withdrawal_subtree_root: format!("{:#066x}", withdrawal_subtree_root),
        withdrawal_merkle_proof: b256_array_to_hex(withdrawal_merkle_proof_b256),
        end_checkpoint_index,
    };
    let out_str = serde_json::to_string_pretty(&output)?;
    fs::write(&out_json, &out_str).with_context(|| format!("failed to write output: {}", out_json.display()))?;
    eprintln!("Output written to {}", out_json.display());

    Ok(BridgeProveResult {
        from_checkpoint,
        to_checkpoint,
        num_checkpoints_aggregated,
        proof_path: out_json,
        deposit_tree_root: output.deposit_tree_root.clone(),
        withdrawal_tree_root: output.withdrawal_tree_root.clone(),
    })
}

/// Build deposit batchAppend calls using a remote Prove Proxy instead of local Plonky2+Groth16.
/// Fetches L1 data locally, sends frontier+leaves to Prove Proxy, and returns calldata.
pub async fn build_deposit_batch_append_calls_remote(
    l1_rpc_url: &str,
    deployments_network: &str,
    target_deposit_count: u32,
    prove_proxy_url: &str,
) -> anyhow::Result<Vec<DepositBatchAppendCall>> {
    let l1_config = load_l1_deployment_config(deployments_network)?;
    let inputs = fetch_deposit_batch_inputs(
        target_deposit_count,
        l1_rpc_url,
        &l1_config,
        deployments_network,
    )
    .await?;
    if inputs.leaves.is_empty() {
        // target equals current provedDepositCount: nothing to append.
        return Ok(Vec::new());
    }
    let expected_len = (inputs.to_index - inputs.from_index) as usize;
    anyhow::ensure!(
        inputs.leaves.len() == expected_len,
        "deposit batch input length mismatch: expected {} got {}",
        expected_len,
        inputs.leaves.len()
    );

    // ── Phase 1: compute all chunk preimages locally (pure compute, no I/O) ──
    // This gives us from_index/to_index/new_frontier/batch_commit for each chunk.
    struct ChunkPrep {
        from_index: u32,
        to_index: u32,
        batch_commit: [u32; 8],
        preimage: BatchAppendPreimage,
        circuit_deposits: Vec<DepositLeafData>,
        proxy_deposits: Vec<ProxyDepositLeafInput>,
        old_frontier_str: Vec<String>,
    }

    let mut frontier = inputs.old_frontier.clone();
    let mut from_index = inputs.from_index;
    let mut prep_list: Vec<ChunkPrep> = Vec::new();

    for chunk in inputs.leaves.chunks(MAX_DEPOSIT_BATCH_SIZE) {
        let old_frontier_str: Vec<String> = frontier.iter().map(|h| {
            format!("0x{:016x}{:016x}{:016x}{:016x}",
                h.0.elements[3].to_canonical_u64(),
                h.0.elements[2].to_canonical_u64(),
                h.0.elements[1].to_canonical_u64(),
                h.0.elements[0].to_canonical_u64())
        }).collect();

        let circuit_deposits: Vec<DepositLeafData> = chunk.to_vec();
        let circuit_deposits_ref: Vec<CircuitDepositLeafData> = circuit_deposits.iter().map(deposit_leaf_to_circuit).collect();

        let preimage = {
            let mut frontier_q: [QHashOut<F>; DEPOSIT_BATCH_TREE_HEIGHT] = frontier.clone().try_into()
                .map_err(|v: Vec<QHashOut<F>>| anyhow::anyhow!("frontier len: {}", v.len()))?;
            let inputs: CircuitBatchAppendInputs<F> = CircuitBatchAppendInputs {
                frontier: frontier_q,
                from_index,
                deposits: circuit_deposits_ref,
                bridge_user_id: BRIDGE_USER_ID_U64 as u32,
            };
            compute_batch_append_preimage(&inputs)
        };

        let proxy_deposits: Vec<ProxyDepositLeafInput> = chunk.iter().map(|leaf| ProxyDepositLeafInput {
            shield_address: leaf.shield_address,
            token: leaf.token,
            l2_token_contract_id: leaf.l2_token_contract_id,
            amount: leaf.amount,
            chain_index: leaf.chain_index,
            note_commitment: leaf.note_commitment,
        }).collect();

        prep_list.push(ChunkPrep {
            from_index,
            to_index: preimage.to_index,
            batch_commit: preimage.batch_commit,
            preimage,
            circuit_deposits,
            proxy_deposits,
            old_frontier_str,
        });

        // Use the values before preimage was moved
        let last_prep = prep_list.last().unwrap();
        from_index = last_prep.to_index;
        frontier = last_prep.preimage.new_frontier.to_vec();
    }

    anyhow::ensure!(
        from_index == inputs.to_index,
        "deposit batch append chunking ended at {}, expected {}",
        from_index,
        inputs.to_index
    );

    // ── Phase 2 + 3: fire all proxy requests concurrently via FuturesUnordered ──
    // Each chunk is independent (preimages already computed locally), so we can
    // send up to 4 concurrent proxy requests using FuturesUnordered.
    let proxy_client = Arc::new(ProveProxyClient::new(prove_proxy_url));
    use futures::stream::FuturesUnordered;
    use futures::StreamExt;

    let mut pending = FuturesUnordered::new();
    let mut outstanding: usize = 0;
    let mut prep_idx: usize = 0;
    let mut proxy_outputs: Vec<Option<BridgeDepositBatchGroth16Proof>> = vec![None; prep_list.len()];
    tracing::info!(
        "[remote] Sending {} deposit chunk(s) to Prove Proxy at {} (max {} concurrent)",
        prep_list.len(),
        prove_proxy_url,
        MAX_CONCURRENT_PROXY_PROOFS
    );

    loop {
        // Spawn new requests while we have chunks and haven't hit concurrency limit
        while outstanding < MAX_CONCURRENT_PROXY_PROOFS && prep_idx < prep_list.len() {
            let prep = &prep_list[prep_idx];
            let client = Arc::clone(&proxy_client);
            let witness = BridgeDepositBatchWitnessInput {
                from_index: prep.from_index,
                bridge_user_id: BRIDGE_USER_ID_U64 as u32,
                old_frontier: prep.old_frontier_str.clone(),
                deposits: prep.proxy_deposits.clone(),
            };
            let idx = prep_idx;
            pending.push(async move {
                let result = client.prove_deposit_batch_append_groth16(witness).await;
                (idx, result)
            });
            outstanding += 1;
            prep_idx += 1;
        }

        if outstanding == 0 {
            break;
        }

        if let Some((idx, result)) = pending.next().await {
            outstanding -= 1;
            let proof = result?;
            proxy_outputs[idx] = Some(proof);
            tracing::debug!(
                "[remote] Deposit chunk {} received from Prove Proxy (from_index {})",
                idx,
                prep_list[idx].from_index,
            );
        }
    }

    // Collect in order
    let proxy_outputs: Vec<BridgeDepositBatchGroth16Proof> = proxy_outputs
        .into_iter()
        .map(|opt| opt.ok_or_else(|| anyhow::anyhow!("missing proxy output for chunk")))
        .collect::<anyhow::Result<_>>()?;

    // ── Phase 4: assemble calldata from proxy outputs + preimages ──
    let mut calls = Vec::with_capacity(proxy_outputs.len());
    for (prep, proxy_output) in prep_list.into_iter().zip(proxy_outputs.into_iter()) {
        let mut proof = [U256::ZERO; 8];
        for (i, value) in proxy_output.solidity_proof.iter().enumerate() {
            proof[i] = U256::from_str_radix(value.trim_start_matches("0x"), 16)?;
        }

        let slot_data_u32 = compute_batch_slot_data_words(
            &prep.circuit_deposits.iter().map(deposit_leaf_to_circuit).collect::<Vec<_>>(),
        );
        let slot_data: [U256; 1312] = {
            let mut arr = [U256::ZERO; 1312];
            for (i, &v) in slot_data_u32.iter().enumerate() {
                arr[i] = U256::from(v);
            }
            arr
        };

        let call = batchAppendCall {
            proof,
            publicInputs: proxy_output.public_inputs.iter().map(|v| U256::from(*v)).collect(),
            slotData: slot_data,
        };
        let call_data = Bytes::from(call.abi_encode());
        let slot_data_u256: Vec<U256> = slot_data_u32.iter().map(|v| U256::from(*v)).collect();
        calls.push(DepositBatchAppendCall {
            from_index: prep.from_index,
            to_index: prep.to_index,
            batch_commit: prep.batch_commit,
            slot_data: slot_data_u256,
            call_data,
        });
    }

    Ok(calls)
}

/// Bridge aggregation proof generation using a remote Prove Proxy.
/// Fetches all witness data locally, then sends to Prove Proxy for Groth16 proof.
pub async fn run_prove_bridge_agg_with_result_remote(
    from_checkpoint: u64,
    to_checkpoint: u64,
    rpc_config: String,
    out_json: PathBuf,
    deployments_network: String,
    prove_proxy_url: &str,
) -> anyhow::Result<BridgeProveResult> {
    let from_checkpoint = from_checkpoint.max(1);
    anyhow::ensure!(from_checkpoint <= to_checkpoint, "from_checkpoint must be <= to_checkpoint");
    let num_checkpoints_aggregated = to_checkpoint - from_checkpoint + 1;
    anyhow::ensure!(
        num_checkpoints_aggregated >= 1,
        "bridge aggregation requires at least 1 checkpoint, got {} (from={} to={})",
        num_checkpoints_aggregated,
        from_checkpoint,
        to_checkpoint
    );

    let l1_config = load_l1_deployment_config(&deployments_network)?;
    let provider = RpcProvider::new_with_config_path(&rpc_config)?;

    eprintln!(
        "[remote] Pre-fetching checkpoint proofs and merkle data for checkpoints {} to {}...",
        from_checkpoint, to_checkpoint
    );

    let final_checkpoint_proof_hex = {
        let proof_bytes = provider.get_checkpoint_state_transition_proof(to_checkpoint).await?;
        hex::encode(&proof_bytes)
    };

    let mut delta_merkle_proofs = Vec::new();
    let mut pre_delta_merkle_proofs = Vec::new();
    for cp_id in from_checkpoint..=to_checkpoint {
        let leaf_hash = provider.get_checkpoint_tree_leaf_hash(cp_id, cp_id).await?;
        let merkle_proof = provider.get_checkpoint_tree_merkle_proof(cp_id, cp_id).await?;
        let new_value_hex = format!("0x{:016x}{:016x}{:016x}{:016x}",
            leaf_hash.0.elements[3].to_canonical_u64(),
            leaf_hash.0.elements[2].to_canonical_u64(),
            leaf_hash.0.elements[1].to_canonical_u64(),
            leaf_hash.0.elements[0].to_canonical_u64());
        let siblings_hex: Vec<String> = merkle_proof.siblings.iter().map(|h| {
            format!("0x{:016x}{:016x}{:016x}{:016x}",
                h.0.elements[3].to_canonical_u64(),
                h.0.elements[2].to_canonical_u64(),
                h.0.elements[1].to_canonical_u64(),
                h.0.elements[0].to_canonical_u64())
        }).collect();
        delta_merkle_proofs.push(BridgeAggDeltaProof {
            index: cp_id,
            new_value: new_value_hex.clone(),
            siblings: siblings_hex.clone(),
        });

        anyhow::ensure!(cp_id > 0, "from_checkpoint must be > 0");
        let pre_id = cp_id - 1;
        let pre_leaf_hash = provider.get_checkpoint_tree_leaf_hash(pre_id, pre_id).await?;
        let pre_merkle_proof = provider.get_checkpoint_tree_merkle_proof(pre_id, pre_id).await?;
        let pre_new_value_hex = format!("0x{:016x}{:016x}{:016x}{:016x}",
            pre_leaf_hash.0.elements[3].to_canonical_u64(),
            pre_leaf_hash.0.elements[2].to_canonical_u64(),
            pre_leaf_hash.0.elements[1].to_canonical_u64(),
            pre_leaf_hash.0.elements[0].to_canonical_u64());
        let pre_siblings_hex: Vec<String> = pre_merkle_proof.siblings.iter().map(|h| {
            format!("0x{:016x}{:016x}{:016x}{:016x}",
                h.0.elements[3].to_canonical_u64(),
                h.0.elements[2].to_canonical_u64(),
                h.0.elements[1].to_canonical_u64(),
                h.0.elements[0].to_canonical_u64())
        }).collect();
        pre_delta_merkle_proofs.push(BridgeAggDeltaProof {
            index: pre_id,
            new_value: pre_new_value_hex,
            siblings: pre_siblings_hex,
        });
    }

    let leaf_data = provider.get_checkpoint_leaf_data(to_checkpoint).await?;
    let leaf_compact = leaf_data.to_compact::<psy_client_data::config::store_config::PsyHasher>();
    let final_checkpoint_leaf = BridgeAggCheckpointLeaf {
        global_chain_root: format!("0x{:016x}{:016x}{:016x}{:016x}",
            leaf_compact.global_chain_root.0.elements[3].to_canonical_u64(),
            leaf_compact.global_chain_root.0.elements[2].to_canonical_u64(),
            leaf_compact.global_chain_root.0.elements[1].to_canonical_u64(),
            leaf_compact.global_chain_root.0.elements[0].to_canonical_u64()),
        stats_hash: format!("0x{:016x}{:016x}{:016x}{:016x}",
            leaf_compact.stats_hash.0.elements[3].to_canonical_u64(),
            leaf_compact.stats_hash.0.elements[2].to_canonical_u64(),
            leaf_compact.stats_hash.0.elements[1].to_canonical_u64(),
            leaf_compact.stats_hash.0.elements[0].to_canonical_u64()),
    };

    // start_chain_hash must be the chain hash immediately before `from_checkpoint`.
    // For from_checkpoint == 1, this is the genesis checkpoint transition PI = H(H(root_0, leaf_0), genesis_fingerprint).
    // For from_checkpoint > 1, this is checkpoint (from_checkpoint - 1)'s proof public input hash.
    let genesis_fingerprint = {
        let cached_lib = psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
        cached_lib
            .get_fingerprint(ProvingJobCircuitType::GenesisBlockCheckpointStateTransition)
            .map_err(|e| anyhow::anyhow!("GenesisBlockCheckpointStateTransition fingerprint not found in cached circuit library: {e}"))?
    };
    let start_chain_hash = if from_checkpoint <= 1 {
        use plonky2::hash::poseidon::PoseidonHash;
        use plonky2::plonk::config::Hasher;
        let genesis_root = to_core_hash(provider.get_checkpoint_tree_root(0).await?);
        let genesis_leaf = to_core_hash(provider.get_checkpoint_tree_leaf_hash(0, 0).await?);
        let root_leaf = PoseidonHash::two_to_one(genesis_root.0, genesis_leaf.0);
        QHashOut(PoseidonHash::two_to_one(root_leaf.into(), genesis_fingerprint.0))
    } else {
        let prev_proof_bytes = provider
            .get_checkpoint_state_transition_proof(from_checkpoint - 1)
            .await?;
        let prev_proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&prev_proof_bytes)
            .map_err(|e| anyhow::format_err!("failed to deserialize previous checkpoint proof: {}", e))?;
        QHashOut::from_felt_slice(&prev_proof.public_inputs[..4])
    };
    let chain_start_hex = format!("0x{:016x}{:016x}{:016x}{:016x}",
        start_chain_hash.0.elements[3].to_canonical_u64(),
        start_chain_hash.0.elements[2].to_canonical_u64(),
        start_chain_hash.0.elements[1].to_canonical_u64(),
        start_chain_hash.0.elements[0].to_canonical_u64());

    let qhash_to_hex = |h: parth_core::pgoldilocks::QHashOut<F>| -> String {
        format!("0x{:016x}{:016x}{:016x}{:016x}",
            h.0.elements[3].to_canonical_u64(),
            h.0.elements[2].to_canonical_u64(),
            h.0.elements[1].to_canonical_u64(),
            h.0.elements[0].to_canonical_u64())
    };
    async fn merkle_proof_to_witness(
        provider: &RpcProvider,
        cp: u64,
        uid: u64,
        contract_id: u32,
    ) -> anyhow::Result<BridgeAggSlotWitness> {
        let contract_state_tree_height = bridge_contract_state_tree_height(contract_id)?;
        let qhash_to_hex = |h: parth_core::pgoldilocks::QHashOut<F>| -> String {
            format!("0x{:016x}{:016x}{:016x}{:016x}",
                h.0.elements[3].to_canonical_u64(),
                h.0.elements[2].to_canonical_u64(),
                h.0.elements[1].to_canonical_u64(),
                h.0.elements[0].to_canonical_u64())
        };

        let slot0_proof = provider
            .get_user_contract_state_tree_merkle_proof(cp, uid, contract_id, contract_state_tree_height, 0)
            .await?;
        let slot1_proof = provider
            .get_user_contract_state_tree_merkle_proof(cp, uid, contract_id, contract_state_tree_height, 1)
            .await?;
        let contract_proof = provider
            .get_user_contract_tree_merkle_proof(cp, uid, contract_id)
            .await?;
        let user_leaf = provider.get_user_leaf_data(cp, uid).await?;
        let user_tree_proof = provider.get_user_tree_merkle_proof(cp, uid).await?;

        Ok(BridgeAggSlotWitness {
            owner_user_id: uid,
            contract_id: contract_id as u64,
            user_leaf_public_key: qhash_to_hex(to_core_hash(user_leaf.public_key)),
            user_leaf_user_state_tree_root: qhash_to_hex(to_core_hash(user_leaf.user_state_tree_root)),
            user_leaf_balance: user_leaf.balance.to_canonical_u64(),
            user_leaf_nonce: user_leaf.nonce.to_canonical_u64(),
            user_leaf_last_checkpoint_id: user_leaf.last_checkpoint_id.to_canonical_u64(),
            user_leaf_event_index: user_leaf.event_index.to_canonical_u64(),
            user_leaf_user_id: user_leaf.user_id.to_canonical_u64(),
            slot0_root: qhash_to_hex(to_core_hash(slot0_proof.root)),
            slot0_value: qhash_to_hex(to_core_hash(slot0_proof.value)),
            slot0_index: slot0_proof.index,
            slot0_siblings: slot0_proof.siblings.iter().map(|s| qhash_to_hex(to_core_hash(*s))).collect(),
            slot1_root: qhash_to_hex(to_core_hash(slot1_proof.root)),
            slot1_value: qhash_to_hex(to_core_hash(slot1_proof.value)),
            slot1_index: slot1_proof.index,
            slot1_siblings: slot1_proof.siblings.iter().map(|s| qhash_to_hex(to_core_hash(*s))).collect(),
            contract_root: qhash_to_hex(to_core_hash(contract_proof.root)),
            contract_value: qhash_to_hex(to_core_hash(contract_proof.value)),
            contract_index: contract_proof.index,
            contract_siblings: contract_proof.siblings.iter().map(|s| qhash_to_hex(to_core_hash(*s))).collect(),
            user_tree_root: qhash_to_hex(to_core_hash(user_tree_proof.root)),
            user_tree_value: qhash_to_hex(to_core_hash(user_tree_proof.value)),
            user_tree_index: user_tree_proof.index,
            user_tree_siblings: user_tree_proof.siblings.iter().map(|s| qhash_to_hex(to_core_hash(*s))).collect(),
        })
    }
    let deposit_root_witness = merkle_proof_to_witness(&provider, to_checkpoint, BRIDGE_USER_ID_U64, DEPOSIT_TREE_CONTRACT_ID).await?;
    let withdrawal_root_witness = merkle_proof_to_witness(&provider, to_checkpoint, BRIDGE_USER_ID_U64, WITHDRAWAL_TREE_CONTRACT_ID).await?;

    // Fetch global state roots to bind user_tree_root to checkpoint leaf
    let qhash_to_hex = |h: parth_core::pgoldilocks::QHashOut<F>| -> String {
        format!("0x{:016x}{:016x}{:016x}{:016x}",
            h.0.elements[3].to_canonical_u64(),
            h.0.elements[2].to_canonical_u64(),
            h.0.elements[1].to_canonical_u64(),
            h.0.elements[0].to_canonical_u64())
    };
    let state_roots = provider.get_checkpoint_global_state_roots(to_checkpoint).await?;
    let global_state_roots = crate::bridge::prove_proxy_client::BridgeAggGlobalStateRoots {
        contract_tree_root: qhash_to_hex(to_core_hash(state_roots.contract_tree_root)),
        deposit_tree_root: qhash_to_hex(to_core_hash(state_roots.deposit_tree_root)),
        user_tree_root: qhash_to_hex(to_core_hash(state_roots.user_tree_root)),
        withdrawal_tree_root: qhash_to_hex(to_core_hash(state_roots.withdrawal_tree_root)),
        user_registration_tree_root: qhash_to_hex(to_core_hash(state_roots.user_registration_tree_root)),
        validator_tree_root: qhash_to_hex(to_core_hash(state_roots.validator_tree_root)),
    };

    // Get checkpoint fingerprint from cached circuit library (avoids building
    // the full QEDCoordinatorCircuitManager — saves ~2GB RSS when prove proxy
    // is configured and the relayer doesn't need local proving).
    let remote_checkpoint_fp = {
        let cached_lib = psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
        let fp = cached_lib
            .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
            .map_err(|e| anyhow::anyhow!("GenerateRollupStateTransitionProof fingerprint not found in cached circuit library: {e}"))?;
        qhash_to_hex(fp)
    };

    let input = crate::bridge::prove_proxy_client::BridgeAggWitnessInput {
        from_checkpoint,
        to_checkpoint,
        final_checkpoint_proof_hex,
        delta_merkle_proofs,
        pre_delta_merkle_proofs,
        chain_start: chain_start_hex,
        checkpoint_fp: remote_checkpoint_fp,
        final_checkpoint_leaf,
        final_checkpoint_global_state_roots: global_state_roots,
        deposit_witness: deposit_root_witness,
        withdrawal_witness: withdrawal_root_witness,
    };

    eprintln!("[remote] Sending bridge agg to Prove Proxy at {}...", prove_proxy_url);
    let proxy_client = ProveProxyClient::new(prove_proxy_url);
    let proxy_output = proxy_client
        .prove_bridge_agg_groth16(deployments_network.clone(), input)
        .await?;
    eprintln!("[remote] Bridge agg proof received from Prove Proxy.");
    anyhow::ensure!(
        proxy_output.end_checkpoint_index == to_checkpoint,
        "BridgeAgg proxy output end_checkpoint_index mismatch: got={} expected={}",
        proxy_output.end_checkpoint_index,
        to_checkpoint
    );

    let (deposit_subtree_root, deposit_merkle_proof_b256) = fetch_tree_subroot_and_top_proof(
        &provider,
        to_checkpoint,
        BRIDGE_USER_ID_U64,
        DEPOSIT_TREE_CONTRACT_ID,
        l1_config.l1_chain_index,
    )
    .await?;
    let (withdrawal_subtree_root, withdrawal_merkle_proof_b256) = fetch_tree_subroot_and_top_proof(
        &provider,
        to_checkpoint,
        BRIDGE_USER_ID_U64,
        WITHDRAWAL_TREE_CONTRACT_ID,
        l1_config.l1_chain_index,
    )
    .await?;
    let b256_array_to_hex = |arr: [B256; 9]| arr.map(|x| format!("{:#066x}", x));

    let output = ProveBridgeAggOutput {
        from_checkpoint: proxy_output.from_checkpoint,
        to_checkpoint: proxy_output.to_checkpoint,
        num_checkpoints_aggregated: proxy_output.num_checkpoints_aggregated,
        l1_chain_index: u64::from(l1_config.l1_chain_index),
        bridge_agg_public_inputs: proxy_output.bridge_agg_public_inputs,
        bridge_agg_public_inputs_count: proxy_output.bridge_agg_public_inputs_count,
        groth16_proof: proxy_output.groth16_proof,
        solidity_proof: proxy_output.solidity_proof.clone(),
        solidity_public_inputs: proxy_output.solidity_public_inputs,
        checkpoint_roots: proxy_output.checkpoint_roots,
        deposit_tree_root: proxy_output.deposit_tree_root,
        deposit_subtree_root: format!("{:#066x}", deposit_subtree_root),
        deposit_merkle_proof: b256_array_to_hex(deposit_merkle_proof_b256),
        withdrawal_tree_root: proxy_output.withdrawal_tree_root,
        withdrawal_subtree_root: format!("{:#066x}", withdrawal_subtree_root),
        withdrawal_merkle_proof: b256_array_to_hex(withdrawal_merkle_proof_b256),
        end_checkpoint_index: proxy_output.end_checkpoint_index,
    };
    let out_str = serde_json::to_string_pretty(&output)?;
    fs::write(&out_json, &out_str).with_context(|| format!("failed to write output: {}", out_json.display()))?;
    eprintln!("Output written to {}", out_json.display());

    Ok(BridgeProveResult {
        from_checkpoint,
        to_checkpoint,
        num_checkpoints_aggregated,
        proof_path: out_json,
        deposit_tree_root: output.deposit_tree_root,
        withdrawal_tree_root: output.withdrawal_tree_root,
    })
}
