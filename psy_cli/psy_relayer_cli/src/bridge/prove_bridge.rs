use std::{array, fs, path::{Path, PathBuf}, str::FromStr, sync::Arc, sync::OnceLock};

use anyhow::Context;
use alloy_primitives::{keccak256, Address, B256, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use parth_core::{crypto::hash::merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, pgoldilocks::QHashOut, protocol::core_types::QNetworkTreeConstants};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::hash_types::HashOut,
    plonk::{circuit_data::CommonCircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_client_data::traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync};
use psy_core::{constants::chain_id::PsyChainNetworkType, job::job_id::ProvingJobCircuitType, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafCompact},
};
use serde::{Deserialize, Serialize};
use crate::bridge::prove_proxy_client::{BridgeDepositBatchGroth16Proof, BridgeDepositBatchWitnessInput, BridgeDepositLeafInput as ProxyDepositLeafInput, ProveProxyClient};
use psy_plonky2_circuits::{
    bridge::{
        aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits},
        circuits::{
            bridge_agg_final::{bridge_agg_final_pi_len, BridgeAggFinalCircuit, BridgeAggProveResult},
            bridge_aggregate::bridge_aggregate_pi_len,
            bridge_wrap::DepositBatchWrapCircuit,
            bridge_claim::{
                BridgeRewardClaimInput, BridgeRewardClaimWitness,
                BridgeTokenPolicy, BridgeWithdrawalClaimCircuit, BridgeWithdrawalClaimInput,
                BridgeWithdrawalClaimWitness, BRIDGE_CLAIM_CAPACITY, BRIDGE_REWARD_CLAIM_STATEMENT_LEN,
                BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN,
            },
            reward_chain::REWARD_ROOT_STATEMENT_LEN,
            reward_claim_batch::{RewardClaimBatchMode, RewardClaimBatchWitness, REWARD_CLAIM_BATCH_STATEMENT_LEN},
        },
        gadgets::tree_root_in_contract_state::TreeRootInContractStateWitnessInput,
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
use psy_client_data::bridge_aggregate::{DepositAggregateOpening, DepositLeaf, Hash4, NetworkConfig};
use psy_plonky2_common_circuits::bridge::deposit_spiderman_append::{DepositSpidermanAppendInputs, DEPOSIT_SPIDERMAN_PAGE_CAPACITY};
use parth_core::{pgoldilocks::PoseidonHasher, crypto::hash::{spiderman::SpidermanUpdateProof, traits::{FieldQHasher, MerkleZeroHasher}}};
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


fn deposit_leaf_hash(record: &DepositLeaf) -> anyhow::Result<QHashOut<F>> {
    Ok(QHashOut(HashOut { elements: record.poseidon_hash()?.map(F::from_canonical_u64) }))
}

fn append_deposit_leaf(frontier: &mut [QHashOut<F>; 32], index: u32, leaf: QHashOut<F>) -> QHashOut<F> {
    let mut current = leaf;
    let mut zero = QHashOut::ZERO;
    for (level, left) in frontier.iter_mut().enumerate() {
        if (index >> level) & 1 == 0 { *left = current; current = PoseidonHasher::q_two_to_one(current, zero); }
        else { current = PoseidonHasher::q_two_to_one(*left, current); }
        zero = PoseidonHasher::q_two_to_one(zero, zero);
    }
    current
}

pub(crate) fn build_deposit_spiderman_inputs(config: &NetworkConfig, opening: &DepositAggregateOpening, deposit_prefixes: &[crate::guardian::verify_l1::VerifiedDepositPrefix]) -> anyhow::Result<Vec<DepositSpidermanAppendInputs>> {
    use plonky2::field::types::PrimeField64;
    opening.validate(config)?;
    anyhow::ensure!(deposit_prefixes.len() == config.chains.len(), "one deposit prefix per configured chain required");
    let count = opening.deposit_leaves.len() as u32;
    let mut first_record = 0u32;
    let mut pages = Vec::new();
    for (ordinal, prefix) in deposit_prefixes.iter().enumerate() {
        let transition = &opening.deposits[ordinal];
        anyhow::ensure!(prefix.matches_opening(transition.chain_index, transition.old_count, transition.old_root), "retained prefix differs from opening");
        anyhow::ensure!(prefix.occupied_partial_page_hashes().len() == (transition.old_count % 32) as usize, "occupied partial-page hash count mismatch");
        if transition.old_count == transition.new_count { continue; }
        let records = transition.new_count.checked_sub(transition.old_count).context("deposit prefix count underflow")?;
        let suffix = first_record.checked_add(records).context("deposit record prefix overflow")?;
        anyhow::ensure!(suffix <= count, "deposit record prefix exceeds opening");
        let added = &opening.deposit_leaves[first_record as usize..suffix as usize];
        let mut frontier = prefix.frontier.map(to_core_hash);
        let mut root = to_core_hash(prefix.root);
        let mut web = prefix.occupied_partial_page_hashes().iter().copied().map(to_core_hash).collect::<Vec<_>>();
        let mut cursor = transition.old_count;
        while cursor < transition.new_count {
            let room = 32 - cursor % 32;
            let remaining = transition.new_count - cursor;
            let width = room.min(remaining);
            let end = cursor.checked_add(width).context("deposit page boundary overflow")?;
            let mut hashes = Vec::with_capacity(width as usize);
            for index in cursor..end {
                let record = &added[(index - transition.old_count) as usize];
                anyhow::ensure!(record.chain_index == transition.chain_index && record.absolute_index == index, "deposit prefix is not consecutive");
                hashes.push(deposit_leaf_hash(record)?);
            }
            let mut zero = QHashOut::ZERO;
            let siblings = frontier.iter().enumerate().map(|(level, left)| {
                let sibling = if (cursor >> level) & 1 == 0 { zero } else { *left };
                zero = PoseidonHasher::q_two_to_one(zero, zero);
                sibling
            }).collect();
            let path = MerkleProofCore { root, value: QHashOut::ZERO, index: u64::from(cursor), siblings };
            anyhow::ensure!(web.len() == (cursor % 32) as usize && web.len() + hashes.len() <= 32, "invalid deposit page boundary");
            let append_proof = SpidermanUpdateProof::append_from_from_old_new_values::<PoseidonHasher>(&path, &web, &hashes, 5);
            let old_root = root;
            for (offset, hash) in hashes.iter().enumerate() { root = append_deposit_leaf(&mut frontier, cursor + offset as u32, *hash); }
            anyhow::ensure!(append_proof.top_line_proof.old_root == old_root && append_proof.top_line_proof.new_root == root, "deposit page root mismatch");
            pages.push(DepositSpidermanAppendInputs { chain_index: transition.chain_index, old_count: cursor, first_leaf: first_record, leaf_count: width, append_proof });
            first_record += width;
            web.extend(hashes);
            if end % 32 == 0 { web.clear(); }
            cursor = end;
        }
        anyhow::ensure!(root.0.elements.map(|value| value.to_canonical_u64()) == transition.new_root, "new deposit-tree root mismatch");
    }
    anyhow::ensure!(first_record == count, "deposit record prefix mismatch");
    anyhow::ensure!(pages.len() <= DEPOSIT_SPIDERMAN_PAGE_CAPACITY, "deposit page capacity exceeded");
    Ok(pages)
}

pub(crate) fn build_deposit_aggregate(config: &NetworkConfig, opening: &DepositAggregateOpening, pages: &[DepositSpidermanAppendInputs], circuits: &AggregateCircuits) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    circuits.validate_config(config)?;
    opening.validate(config)?;
    anyhow::ensure!(pages.len() <= DEPOSIT_SPIDERMAN_PAGE_CAPACITY, "deposit page capacity exceeded");
    let mut first = 0u32;
    let mut cursor = None;
    for page in pages {
        let transition = opening.deposits.iter().find(|transition| transition.chain_index == page.chain_index).context("deposit page chain absent")?;
        let start = opening.deposits.iter().take_while(|row| row.chain_index != page.chain_index).try_fold(0u32, |sum, row| -> anyhow::Result<u32> {
            sum.checked_add(row.new_count.checked_sub(row.old_count).context("deposit page count underflow")?).context("deposit page ordinal overflow")
        })?;
        let end = page.old_count.checked_add(page.leaf_count).context("deposit page count overflow")?;
        anyhow::ensure!(page.leaf_count > 0 && page.old_count >= transition.old_count && end <= transition.new_count, "deposit page leaves its chain");
        anyhow::ensure!(page.old_count % 32 + page.leaf_count <= 32, "deposit page crossing");
        let ordinal = start.checked_add(page.old_count - transition.old_count).context("deposit page ordinal overflow")?;
        anyhow::ensure!(page.first_leaf == first && page.first_leaf == ordinal, "deposit page order mismatch");
        if let Some((chain, count)) = cursor {
            anyhow::ensure!(page.chain_index > chain || (page.chain_index == chain && page.old_count == count), "deposit pages are not canonical");
        }
        cursor = Some((page.chain_index, end));
        first = first.checked_add(page.leaf_count).context("deposit page ordinal overflow")?;
    }
    anyhow::ensure!(first as usize == opening.deposit_leaves.len(), "missing deposit pages");
    circuits.deposit_aggregate.prove(config, opening, pages)
}

pub(crate) fn prove_withdrawal_claims(
    circuit: &BridgeWithdrawalClaimCircuit,
    input: &BridgeWithdrawalClaimInput,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    anyhow::ensure!(input.claims.len() <= BRIDGE_CLAIM_CAPACITY, "withdrawal claim capacity is 32");
    let proof = circuit.prove(input)?;
    circuit.circuit_data.verify(proof.clone())?;
    anyhow::ensure!(proof.public_inputs.len() == BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN, "withdrawal claim public width mismatch");
    anyhow::ensure!(proof.public_inputs[0] == F::from_canonical_usize(input.claims.len()), "withdrawal claim count mismatch");
    Ok(proof)
}

fn hash_siblings<const N: usize>(proof: &psy_crypto::hash::merkle::core::MerkleProofCore<ClientQHashOut>) -> anyhow::Result<[HashOut<F>; N]> {
    anyhow::ensure!(proof.siblings.len() == N, "merkle path height {N} got {}", proof.siblings.len());
    Ok(std::array::from_fn(|index| to_core_hash(proof.siblings[index]).0))
}

pub(crate) fn withdrawal_burn_key(nonce: [u32; 8]) -> HashOut<F> {
    use plonky2::plonk::config::Hasher;
    let nonce_hash = plonky2::hash::poseidon::PoseidonHash::hash_no_pad(&nonce.map(F::from_canonical_u32));
    let mut inputs = vec![F::from_canonical_u64(6)];
    inputs.extend(nonce_hash.elements);
    plonky2::hash::poseidon::PoseidonHash::hash_no_pad(&inputs)
}

pub(super) fn be_u32_words(bytes: &[u8; 32]) -> [u32; 8] {
    std::array::from_fn(|index| {
        let start = 4 * index;
        u32::from_be_bytes([bytes[start], bytes[start + 1], bytes[start + 2], bytes[start + 3]])
    })
}

pub(super) fn recipient_words(address: &[u8; 20]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for index in 0..5 {
        let start = 4 * index;
        words[3 + index] = u32::from_be_bytes([address[start], address[start + 1], address[start + 2], address[start + 3]]);
    }
    words
}

fn validate_withdrawal_words(recipient: [u32; 8], amount: [u32; 8]) -> anyhow::Result<()> {
    anyhow::ensure!(recipient[..3].iter().all(|limb| *limb == 0), "recipient exceeds 160 bits");
    anyhow::ensure!(amount[..6].iter().all(|limb| *limb == 0), "withdrawal amount exceeds 64 bits");
    let amount_value = (u64::from(amount[6]) << 32) | u64::from(amount[7]);
    anyhow::ensure!(amount_value > 0 && amount_value < 0xffff_ffff_0000_0001, "withdrawal amount is outside Goldilocks");
    Ok(())
}

pub(super) fn amount_words(bytes: &[u8; 32]) -> anyhow::Result<[u32; 8]> {
    let words = be_u32_words(bytes);
    validate_withdrawal_words([0; 8], words)?;
    Ok(words)
}

pub(super) fn withdrawal_policy_ordinals(policies: &[BridgeTokenPolicy], records: &[psy_client_data::bridge_aggregate::WithdrawalBurnRecord]) -> anyhow::Result<Vec<u8>> {
    let mut installed = std::collections::HashMap::<(u8, u32), u8>::with_capacity(policies.len());
    for (position, policy) in policies.iter().enumerate() {
        let ordinal = u8::try_from(position).context("withdrawal policy ordinal exceeds u8")?;
        anyhow::ensure!(installed.insert((policy.chain_index, policy.token_contract_id), ordinal).is_none(), "withdrawal policy match is ambiguous");
    }
    records.iter().map(|record| installed.get(&(record.chain_index, record.contract_id)).copied().context("withdrawal policy is not installed")).collect()
}

pub(crate) async fn fetch_withdrawal_claim_witness(
    provider: &RpcProvider,
    policies: &[BridgeTokenPolicy],
    checkpoint_id: u64,
    user_id: u64,
    policy_ordinal: u8,
    nonce: [u32; 8],
    recipient: [u32; 8],
    amount: [u32; 8],
) -> anyhow::Result<BridgeWithdrawalClaimWitness> {
    let policy = policies.get(policy_ordinal as usize).context("withdrawal policy ordinal is not installed")?;
    validate_withdrawal_words(recipient, amount)?;
    let key = withdrawal_burn_key(nonce);
    let request = psy_provider::request::QIMTMembershipProofRPCRequest {
        checkpoint_id, user_id, contract_id: policy.token_contract_id, key: psy_client_common::data::qhashout::QHashOut(key),
        state_slot_base: u64::from(policy.map_base), capacity: u64::from(policy.capacity),
    };
    let burned = provider.get_withdrawal_burn_proof(request).await?;
    anyhow::ensure!(burned.checkpoint_id == checkpoint_id && burned.user_leaf.user_id.to_canonical_u64() == user_id, "burn proof identifies another user or checkpoint");
    anyhow::ensure!(burned.contract_path.index == u64::from(policy.token_contract_id), "burn contract path is not the approved token contract");
    anyhow::ensure!(burned.global_contract_path.index == u64::from(policy.token_contract_id), "global contract path is not the approved token contract");
    let member = burned.record_membership;
    anyhow::ensure!(member.merkle_proof.index > u64::from(policy.map_base), "burn membership includes the sentinel slot");
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    let map_base = u64::from(policy.map_base);
    let sentinel = provider.contract_state_imt_get_leaf_preimage(checkpoint_id, user_id, u64::from(policy.token_contract_id), map_base).await?;
    let sentinel_proof = provider.get_user_contract_state_tree_merkle_proof(checkpoint_id, user_id, policy.token_contract_id, bridge_contract_state_tree_height(policy.token_contract_id)?, map_base).await?;
    let user_contract = psy_client_data::qdata::user_contract_state::UserContractState {
        checkpoint_tree_root: burned.checkpoint_path.root,
        user_leaf: burned.user_leaf,
        start_contract_state_root: burned.contract_path.value,
        contract_id: F::from_canonical_u32(policy.token_contract_id),
        checkpoint_id: F::from_canonical_u32(u32::from(policy.chain_index)),
    };
    Ok(BridgeWithdrawalClaimWitness {
        policy_ordinal,
        user_contract,
        user_siblings: hash_siblings(&burned.user_path)?,
        contract_siblings: hash_siblings(&burned.contract_path)?,
        global_contract_siblings: hash_siblings(&burned.global_contract_path)?,
        member_index: u32::try_from(member.merkle_proof.index).context("burn membership index exceeds u32")?,
        member: member.leaf,
        member_siblings: hash_siblings(&member.merkle_proof)?,
        sentinel,
        sentinel_siblings: hash_siblings(&sentinel_proof)?,
        recipient,
        token_address: policy.token_address,
        amount,
        nonce,
    })
}

pub(crate) fn prove_reward_claims(
    circuits: &AggregateCircuits,
    input: &BridgeRewardClaimInput,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let batch_count = input.batch_proof.public_inputs.first().context("reward batch statement missing")?.to_canonical_u64() as usize;
    anyhow::ensure!(input.claims.len() == batch_count && batch_count <= BRIDGE_CLAIM_CAPACITY, "reward claim count differs from its batch proof");
    let proof = circuits.reward_claim.prove(input)?;
    anyhow::ensure!(proof.public_inputs.len() == BRIDGE_REWARD_CLAIM_STATEMENT_LEN, "reward claim public width mismatch");
    anyhow::ensure!(proof.public_inputs[0] == F::from_canonical_usize(batch_count), "reward claim count mismatch");
    Ok(proof)
}

pub(crate) fn prove_empty_reward_batch(circuits: &AggregateCircuits) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let proof = circuits.reward_batch.prove(&RewardClaimBatchWitness {
        mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None,
    })?;
    anyhow::ensure!(proof.public_inputs.len() >= REWARD_CLAIM_BATCH_STATEMENT_LEN, "empty reward batch statement missing");
    anyhow::ensure!(proof.public_inputs[0] == F::ZERO, "empty reward batch count is not zero");
    anyhow::ensure!(proof.public_inputs[1..REWARD_CLAIM_BATCH_STATEMENT_LEN].iter().all(|field| *field == F::ZERO), "empty reward batch statement is not zero");
    Ok(proof)
}

pub(crate) fn prove_reward_root_batch(
    circuits: &AggregateCircuits,
    roots: &[ProofWithPublicInputs<F, C, D>],
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    anyhow::ensure!(!roots.is_empty() && roots.len() <= BRIDGE_CLAIM_CAPACITY, "nonempty reward batch requires 1..=32 root proofs");
    let mut proofs = Vec::with_capacity(roots.len());
    for root in roots {
        anyhow::ensure!(root.public_inputs.len() == REWARD_ROOT_STATEMENT_LEN, "reward root statement is not 30 fields");
        proofs.push(circuits.reward_batch.prove(&RewardClaimBatchWitness {
            mode: RewardClaimBatchMode::Leaf,
            statements: vec![std::array::from_fn(|index| root.public_inputs[index])],
            tip: Some(root.clone()),
            children: None,
        })?);
    }
    while proofs.len() > 1 {
        let mut folded = Vec::new();
        let mut index = 0;
        while index < proofs.len() {
            if index + 1 == proofs.len() {
                folded.push(proofs[index].clone());
                break;
            }
            let left = child_statements(&proofs[index])?;
            let right = child_statements(&proofs[index + 1])?;
            let mut combined = left.1;
            combined.extend_from_slice(&right.1[..right.0]);
            let proof = circuits.reward_batch.prove(&RewardClaimBatchWitness {
                mode: RewardClaimBatchMode::Pair,
                statements: combined,
                tip: None,
                children: Some([proofs[index].clone(), proofs[index + 1].clone()]),
            })?;
            anyhow::ensure!(proof.public_inputs[0].to_canonical_u64() as usize == left.0 + right.0, "folded reward batch count mismatch");
            folded.push(proof);
            index += 2;
        }
        proofs = folded;
    }
    let proof = proofs.pop().unwrap();
    circuits.reward_batch.circuit_data.verify(proof.clone())?;
    anyhow::ensure!(proof.public_inputs[0].to_canonical_u64() as usize == roots.len(), "reward batch does not cover every root proof");
    Ok(proof)
}

fn child_statements(proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<(usize, Vec<[F; REWARD_ROOT_STATEMENT_LEN]>)> {
    let count = proof.public_inputs.first().context("reward batch child has no count")?.to_canonical_u64() as usize;
    anyhow::ensure!(count > 0 && count <= BRIDGE_CLAIM_CAPACITY, "reward batch child count is outside 1..=32");
    anyhow::ensure!(proof.public_inputs.len() >= 1 + count * REWARD_ROOT_STATEMENT_LEN, "reward batch child statement is truncated");
    Ok((count, (0..count).map(|slot| {
        let start = 1 + slot * REWARD_ROOT_STATEMENT_LEN;
        std::array::from_fn(|index| proof.public_inputs[start + index])
    }).collect()))
}

pub(crate) fn prove_bridge_aggregate(
    circuits: &AggregateCircuits,
    deposit: &ProofWithPublicInputs<F, C, D>,
    withdrawal: &ProofWithPublicInputs<F, C, D>,
    reward: &ProofWithPublicInputs<F, C, D>,
    finalizations: &[ProofWithPublicInputs<F, C, D>],
    zero_span: &[bool],
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let chain_count = circuits.checkpoint_final.configured_chain_indices().len();
    anyhow::ensure!(finalizations.len() == chain_count && zero_span.len() == chain_count, "one selected finalization per configured chain required");
    let width = bridge_agg_final_pi_len(chain_count);
    for (index, (proof, &membership)) in finalizations.iter().zip(zero_span).enumerate() {
        let verifier = if membership { &circuits.checkpoint_membership.circuit_data } else { &circuits.checkpoint_final.circuit_data };
        verifier.verify(proof.clone()).with_context(|| format!("selected finalization {index} failed verification"))?;
        let span = proof.public_inputs[17];
        anyhow::ensure!(membership == (span == F::ZERO), "zero span must select the membership finalizer");
    }
    let proof = circuits.bridge_aggregate.prove(deposit, withdrawal, reward, finalizations, zero_span)?;
    circuits.bridge_aggregate.circuit_data.verify(proof.clone())?;
    anyhow::ensure!(proof.public_inputs.len() == bridge_aggregate_pi_len(chain_count), "bridge aggregate width differs from 8316+128*C");
    anyhow::ensure!(proof.public_inputs[..4] == [F::from_canonical_u32(4), F::from_canonical_u32(12), F::ZERO, F::ZERO], "bridge aggregate prefix is not version 4");
    Ok(proof)
}

pub(crate) fn build_bridge_circuits<N: parth_core::protocol::core_types::QNetworkCircuitConstants>(
    coordinator: &QEDCoordinatorCircuitManager<C, D>,
    chain_indices: &[u8],
    withdrawal_policies: Vec<BridgeTokenPolicy>,
    ethereum_index: u8,
) -> anyhow::Result<AggregateCircuits> {
    let checkpoint = &coordinator.checkpoint_root_transition;
    AggregateCircuits::build::<N>(
        chain_indices,
        checkpoint.get_common_circuit_data_ref(),
        checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(),
        checkpoint.get_fingerprint(),
        AggregateCircuitHeights { deposit_state_tree: DEPOSIT_CONTRACT_STATE_TREE_HEIGHT },
        withdrawal_policies,
        ethereum_index,
    )
}

pub(crate) struct OpeningProof {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub opening_bytes: Vec<u8>,
    pub opening_digest: [u8; 32],
}

pub(crate) fn bind_opening_digest(proof: &ProofWithPublicInputs<F, C, D>, opening_bytes: &[u8], opening_digest: [u8; 32]) -> anyhow::Result<OpeningProof> {
    use tiny_keccak::{Hasher as _, Keccak};
    let decoded = psy_client_data::bridge_aggregate::BridgeOpening::decode(opening_bytes).map_err(|error| anyhow::anyhow!("opening bytes: {error:?}"))?;
    let canonical = decoded.encode().map_err(|error| anyhow::anyhow!("opening bytes: {error:?}"))?;
    anyhow::ensure!(canonical == opening_bytes, "opening bytes are not canonical");
    let digest = decoded.opening_digest().map_err(|error| anyhow::anyhow!("opening digest: {error:?}"))?;
    anyhow::ensure!(digest == opening_digest, "opening digest differs from opening bytes");
    let mut domain_hasher = Keccak::v256();
    domain_hasher.update(b"PsyBridge/Opening/4");
    let mut domain = [0u8; 32];
    domain_hasher.finalize(&mut domain);
    let mut outer = Keccak::v256();
    outer.update(&domain);
    outer.update(opening_bytes);
    let mut actual = [0u8; 32];
    outer.finalize(&mut actual);
    anyhow::ensure!(actual == opening_digest, "opening digest preimage mismatch");
    anyhow::ensure!(proof.public_inputs.len() >= 4, "opening proof has no prefix");
    Ok(OpeningProof { proof: proof.clone(), opening_bytes: opening_bytes.to_vec(), opening_digest })
}


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
    tracing::info!("building bridge coordinator circuits");
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
    slots: [u64; 2],
) -> anyhow::Result<TreeRootInContractStateWitnessInput<F>> {
    let contract_state_tree_height = bridge_contract_state_tree_height(contract_id)?;
    let slot0_proof = provider
        .get_user_contract_state_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id, contract_state_tree_height, slots[0])
        .await?;
    let slot1_proof = provider
        .get_user_contract_state_tree_merkle_proof(checkpoint_id, owner_user_id, contract_id, contract_state_tree_height, slots[1])
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

async fn fetch_finalize_endpoints(provider: &RpcProvider, checkpoint: u64, indices: &[u8]) -> anyhow::Result<Vec<psy_plonky2_circuits::bridge::circuits::bridge_agg_final::BridgeAggFinalEndpointWitness<F>>> {
    use psy_plonky2_circuits::bridge::{circuits::bridge_agg_final::BridgeAggFinalEndpointWitness, gadgets::slot_value_in_contract_state::SlotValueInContractStateWitnessInput};
    let mut endpoints = Vec::with_capacity(indices.len());
    for &chain_index in indices {
        let slots = [16_451 + 2 * u64::from(chain_index), 16_452 + 2 * u64::from(chain_index)];
        let deposit_root = fetch_tree_root_witness(provider, checkpoint, BRIDGE_USER_ID_U64, DEPOSIT_TREE_CONTRACT_ID, slots).await?;
        let contract = u32::try_from(deposit_root.contract_id)?;
        let slot_index = 16_386 + u64::from(chain_index) / 4;
        let deposit_count = SlotValueInContractStateWitnessInput {
            sender_user_id: BRIDGE_USER_ID_U64,
            contract_id: deposit_root.contract_id,
            slot_index,
            user_leaf: deposit_root.user_leaf,
            contract_proof: deposit_root.contract_proof.clone(),
            user_tree_proof: deposit_root.user_tree_proof.clone(),
            slot_proof: to_core_merkle_proof(provider.get_user_contract_state_tree_merkle_proof(checkpoint, BRIDGE_USER_ID_U64, contract, bridge_contract_state_tree_height(contract)?, slot_index).await?),
        };
        endpoints.push(BridgeAggFinalEndpointWitness { chain_index, deposit_root, deposit_count });
    }
    Ok(endpoints)
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

pub(crate) async fn fetch_tree_subroot_and_top_proof(
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
    let mut empty_subtree = B256::ZERO;

    let mut node = 256u64 + chain_index as u64;
    for level in 0..TOP_TREE_HEIGHT {
        let sibling = if (node & 1) == 0 { node + 1 } else { node - 1 };
        let stored_sibling =
            fetch_slot_pair_as_b256(provider, checkpoint_id, owner_user_id, contract_id, agg_slot_base + sibling * 2).await?;
        proof[level + 1] = canonical_empty_subtree(stored_sibling, empty_subtree);
        empty_subtree = keccak_pair(empty_subtree, empty_subtree);
        node >>= 1;
    }

    Ok((subtree_root, proof))
}

fn canonical_empty_subtree(stored: B256, empty_subtree: B256) -> B256 {
    if stored == B256::ZERO { empty_subtree } else { stored }
}

fn keccak_pair(left: B256, right: B256) -> B256 {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left.as_slice());
    input[32..].copy_from_slice(right.as_slice());
    keccak256(input)
}

#[derive(Serialize)]
pub struct ProveBridgeAggOutput {
    pub from_checkpoint: u64,
    pub to_checkpoint: u64,
    pub num_checkpoints_aggregated: u64,
    pub l1_chain_index: u64,
    pub bridge_agg_public_inputs_count: usize,
    pub bridge_agg_public_inputs: Vec<String>,
    pub opening_bytes: String,
    pub opening_digest: String,
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
    pub opening_digest: String,
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

pub(crate) async fn prove_checkpoint_range(
    provider: &RpcProvider,
    coordinator: &QEDCoordinatorCircuitManager<C, D>,
    start_checkpoint_id: u64,
    end_checkpoint_id: u64,
    configured_chain_indices: &[u8],
) -> anyhow::Result<(
    BridgeAggProveResult<C, D>,
    PQEDCheckpointLeaf<F, QHashOut<F>>,
    MerkleProofCore<QHashOut<F>>,
)> {
    anyhow::ensure!(
        start_checkpoint_id < end_checkpoint_id,
        "checkpoint range requires start_checkpoint_id < end_checkpoint_id"
    );
    let from_checkpoint = start_checkpoint_id.checked_add(1)
        .context("checkpoint range start overflow")?;
    let to_checkpoint = end_checkpoint_id;
    let num_checkpoints_aggregated = end_checkpoint_id - start_checkpoint_id;

    let checkpoint_common_data: &CommonCircuitData<F, D> = coordinator.checkpoint_root_transition.get_common_circuit_data_ref();
    let checkpoint_verifier_data = coordinator.checkpoint_root_transition.get_verifier_config_ref();
    let cap_height = checkpoint_verifier_data.constants_sigmas_cap.height();
    let checkpoint_state_transition_fingerprint = coordinator.checkpoint_root_transition.get_fingerprint();
    // For step_commit, use the SAME fingerprint that RCP circuit used during genesis proving.
    // This is NOT base_fingerprint or minifier fingerprint, but the cached library fingerprint
    // for GenerateRollupStateTransitionProof (circuit type 32).
    use psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library;
    let cached_lib = get_cached_circuit_library::<F>();
    let checkpoint_step_commit_fingerprint = cached_lib
        .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
        .expect("GenerateRollupStateTransitionProof not found in cached circuit library");
    tracing::info!(from_checkpoint, to_checkpoint, "pre-fetching checkpoint proofs");

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
    let leaf_felts = psy_client_common::traits::to_qfelts::ToQFelts::to_qfelts(&leaf_data);
    anyhow::ensure!(
        leaf_felts.len() == <PQEDCheckpointLeaf<F, QHashOut<F>> as parth_core::felt::QFeltSized>::q_felt_size(),
        "checkpoint leaf felt width mismatch: got {}",
        leaf_felts.len()
    );
    let full_checkpoint_leaf = <PQEDCheckpointLeaf<F, QHashOut<F>> as parth_core::felt::ToQFelts<F>>::from_qfelts(&leaf_felts);

    // start_chain_hash must be the chain hash immediately before `from_checkpoint`.
    // For from_checkpoint == 1, this is the genesis checkpoint transition PI = H(H(root_0, leaf_0), genesis_fingerprint).
    // For from_checkpoint > 1, this is checkpoint (from_checkpoint - 1)'s proof public input hash.
    let genesis_fingerprint = coordinator.genesis_checkpoint_root_transition.get_fingerprint();
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
        fetch_tree_root_witness(provider, to_checkpoint, BRIDGE_USER_ID_U64, DEPOSIT_TREE_CONTRACT_ID, [0, 1]).await?;

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

    tracing::info!(from_checkpoint, to_checkpoint, "proving bridge aggregation");

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
        CHECKPOINT_TREE_HEIGHT,
        GLOBAL_USER_TREE_HEIGHT,
        GLOBAL_CONTRACT_TREE_HEIGHT,
        DEPOSIT_CONTRACT_STATE_TREE_HEIGHT,
        configured_chain_indices,
        &fetch_finalize_endpoints(provider, to_checkpoint, configured_chain_indices).await?,
    )?;
    tracing::info!(step_count = to_checkpoint - from_checkpoint + 1, "bridge aggregation proof generated");

    anyhow::ensure!(
        result.proof.public_inputs.len() == bridge_agg_final_pi_len(configured_chain_indices.len()),
        "BridgeAgg proof public inputs width differs from 18+5*C: {}",
        result.proof.public_inputs.len()
    );
    anyhow::ensure!(
        result.proof.public_inputs[17].to_canonical_u64() == num_checkpoints_aggregated,
        "BridgeAgg public input span mismatch: pi={} expected={}",
        result.proof.public_inputs[17].to_canonical_u64(),
        num_checkpoints_aggregated
    );
    let end_checkpoint_index = result.proof.public_inputs[16].to_canonical_u64();
    anyhow::ensure!(
        end_checkpoint_index == to_checkpoint,
        "BridgeAgg public input end_checkpoint_index mismatch: pi={} expected={}",
        end_checkpoint_index,
        to_checkpoint
    );
    let final_delta = delta_merkle_proofs.pop()
        .context("positive checkpoint range requires a final append delta")?;
    let end_checkpoint_path = MerkleProofCore {
        root: final_delta.new_root,
        value: final_delta.new_value,
        index: end_checkpoint_id,
        siblings: final_delta.siblings,
    };
    Ok((result, full_checkpoint_leaf, end_checkpoint_path))
}

pub(crate) async fn prove_checkpoint_membership(
    provider: &RpcProvider,
    coordinator: &QEDCoordinatorCircuitManager<C, D>,
    checkpoint_id: u64,
    configured_chain_indices: &[u8],
    trusted_checkpoint_root: HashOut<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let cached = psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
    let checkpoint_base = cached.get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof).context("GenerateRollupStateTransitionProof not found in cached circuit library")?;
    let checkpoint = &coordinator.checkpoint_root_transition;
    let membership = psy_plonky2_circuits::bridge::circuits::bridge_agg_final::BridgeAggFinalMembershipCircuit::<C, D>::prebuild_membership_circuit(
        checkpoint.get_common_circuit_data_ref(), checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(), checkpoint.get_fingerprint(), checkpoint_base,
        CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, DEPOSIT_CONTRACT_STATE_TREE_HEIGHT, configured_chain_indices,
    );
    let leaf_data = provider.get_checkpoint_leaf_data(checkpoint_id).await?;
    let compact = leaf_data.to_compact::<psy_client_data::config::store_config::PsyHasher>();
    let leaf = PQEDCheckpointLeafCompact { global_chain_root: to_core_hash(compact.global_chain_root), stats_hash: to_core_hash(compact.stats_hash) };
    let proof = provider.get_checkpoint_tree_merkle_proof(checkpoint_id, checkpoint_id).await?;
    let path = MerkleProofCore { root: to_core_hash(proof.root), value: to_core_hash(proof.value), index: checkpoint_id, siblings: proof.siblings.into_iter().map(to_core_hash).collect() };
    anyhow::ensure!(path.root.0 == trusted_checkpoint_root, "membership path root differs from the opening end root");
    let roots = provider.get_checkpoint_global_state_roots(checkpoint_id).await?;
    let global = PQEDCheckpointGlobalStateRoots { contract_tree_root: to_core_hash(roots.contract_tree_root), deposit_tree_root: to_core_hash(roots.deposit_tree_root), user_tree_root: to_core_hash(roots.user_tree_root), withdrawal_tree_root: to_core_hash(roots.withdrawal_tree_root), user_registration_tree_root: to_core_hash(roots.user_registration_tree_root), validator_tree_root: to_core_hash(roots.validator_tree_root) };
    let proved = membership.prove(&leaf, &path, &global, &fetch_finalize_endpoints(provider, checkpoint_id, configured_chain_indices).await?, trusted_checkpoint_root)?;
    anyhow::ensure!(proved.public_inputs.len() == bridge_agg_final_pi_len(configured_chain_indices.len()) && proved.public_inputs[16].to_canonical_u64() == checkpoint_id && proved.public_inputs[17] == F::ZERO, "membership finalizer does not bind the zero span");
    Ok(proved)
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningWitness {
    pub opening: String,
    pub deposit_prefixes: Vec<crate::guardian::verify_l1::VerifiedDepositPrefix>,
    pub rewards: Vec<OpeningRewardWitness>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningRewardWitness {
    pub proof: String,
    pub anchor: String,
}


pub(crate) async fn prove_bridge_opening(
    from_checkpoint: u64,
    to_checkpoint: u64,
    rpc_config: &str,
    aggregate_config: &Path,
    opening_bytes: &[u8],
    witness: &OpeningWitness,
) -> anyhow::Result<(OpeningProof, psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningWrapper)> {
    use plonky2::plonk::config::Hasher;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    use psy_plonky2_circuits::bridge::circuits::bridge_wrap::{BridgeOpeningChain, BridgeOpeningWrapper};
    let from_checkpoint = from_checkpoint.max(1);
    anyhow::ensure!(from_checkpoint <= to_checkpoint, "from_checkpoint must be <= to_checkpoint");
    let coordinator_circuits = cached_bridge_coordinator_circuits()?;
    let provider = RpcProvider::new_with_config_path(rpc_config)?;
    let approved = psy_plonky2_circuits::bridge::aggregate_circuits::load_aggregate_setup_config(aggregate_config)?;
    let network = NetworkConfig::decode(&hex::decode(&approved.network_config)?)?;
    let indices = network.chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>();
    let circuits = build_bridge_circuits::<PsyNetworkLocalDevnetConstants>(
        coordinator_circuits, &indices, approved.withdrawal_policies.clone(), network.ethereum_index,
    )?;
    circuits.validate_config(&network)?;
    let opening = psy_client_data::bridge_aggregate::BridgeOpening::decode(opening_bytes)
        .map_err(|error| anyhow::anyhow!("bridge opening: {error:?}"))?;
    opening.validate_config(&network).map_err(|error| anyhow::anyhow!("bridge opening config: {error:?}"))?;
    let canonical = opening.encode().map_err(|error| anyhow::anyhow!("bridge opening: {error:?}"))?;
    anyhow::ensure!(canonical == opening_bytes, "bridge opening bytes are not canonical");
    let witness_opening = canonical_base64(&witness.opening).context("witness opening is not canonical standard base64")?;
    anyhow::ensure!(witness_opening == opening_bytes, "witness opening differs from the supplied opening bytes");
    anyhow::ensure!(u64::from(opening.end_checkpoint_id) == to_checkpoint, "opening end checkpoint differs from the requested checkpoint");
    anyhow::ensure!(witness.rewards.len() == opening.rewards.len(), "reward witness count differs from the opening");
    let opening_digest = opening.opening_digest().map_err(|error| anyhow::anyhow!("opening digest: {error:?}"))?;

    let mut finalizations = Vec::with_capacity(opening.chains.len());
    let mut zero_span = Vec::with_capacity(opening.chains.len());
    for row in &opening.chains {
        let start_id = u64::from(row.start_checkpoint_id);
        let span = to_checkpoint.checked_sub(start_id).context("opening start follows the end checkpoint")?;
        let proof = if span == 0 {
            prove_checkpoint_membership(&provider, coordinator_circuits, to_checkpoint, &indices, HashOut { elements: std::array::from_fn(|index| F::from_canonical_u64(row.start_checkpoint_root[index])) }).await?
        } else {
            let (proved, _, _) = prove_checkpoint_range(&provider, coordinator_circuits, start_id, to_checkpoint, &indices).await?;
            anyhow::ensure!(proved.common_data == circuits.checkpoint_final.circuit_data.common && proved.verifier_data == circuits.checkpoint_final.circuit_data.verifier_only && proved.fingerprint == circuits.checkpoint_final.fingerprint, "checkpoint source pin mismatch");
            proved.proof
        };
        let inputs = proof.public_inputs.iter().map(|field| field.to_canonical_u64()).collect::<Vec<_>>();
        anyhow::ensure!(inputs[12..16] == opening.end_checkpoint_root && inputs[16] == to_checkpoint && inputs[17] == span, "selected finalization does not bind the opening endpoint");
        if span == 0 {
            anyhow::ensure!(inputs[..4] == opening.end_checkpoint_root, "zero-span finalization changed the checkpoint root");
        } else {
            anyhow::ensure!(inputs[..4] == row.start_checkpoint_root, "positive finalization does not start at the opening cursor");
        }
        zero_span.push(span == 0);
        finalizations.push(proof);
    }
    let end_checkpoint_root = HashOut { elements: std::array::from_fn(|index| finalizations[0].public_inputs[12 + index]) };
    anyhow::ensure!(end_checkpoint_root.elements.map(|limb| limb.to_canonical_u64()) == opening.end_checkpoint_root, "selected checkpoint root differs from the opening");
    let end_gusr = HashOut { elements: std::array::from_fn(|index| finalizations[0].public_inputs[4 + index]) };
    anyhow::ensure!(end_gusr.elements.map(|limb| limb.to_canonical_u64()) == opening.end_user_root, "selected user root differs from the opening");

    let mut deposit_opening = DepositAggregateOpening {
        config_hash: opening.config_hash,
        window_id: [0; 32],
        end_checkpoint_id: to_checkpoint,
        end_checkpoint_root: opening.end_checkpoint_root,
        starts: opening.chains.iter().map(|row| psy_client_data::bridge_aggregate::ChainStart {
            chain_index: row.chain_index, start_checkpoint_id: u64::from(row.start_checkpoint_id), start_checkpoint_root: row.start_checkpoint_root,
        }).collect(),
        deposits: opening.chains.iter().map(|row| psy_client_data::bridge_aggregate::DepositTransition {
            chain_index: row.chain_index, old_root: row.old_deposit_root, new_root: row.new_deposit_root, old_count: row.old_count, new_count: row.new_count,
        }).collect(),
        deposit_leaves: opening.deposits.clone(),
    };
    deposit_opening.window_id = deposit_opening.window_id().map_err(|error| anyhow::anyhow!("deposit window: {error:?}"))?;
    let pages = build_deposit_spiderman_inputs(&network, &deposit_opening, &witness.deposit_prefixes)?;
    let deposit = build_deposit_aggregate(&network, &deposit_opening, &pages, &circuits)?;
    let policies = circuits.withdrawal_policies();
    let ordinals = withdrawal_policy_ordinals(policies, &opening.withdrawals)?;
    let mut withdrawal_claims = Vec::with_capacity(opening.withdrawals.len());
    for (record, ordinal) in opening.withdrawals.iter().zip(ordinals) {
        withdrawal_claims.push(fetch_withdrawal_claim_witness(&provider, policies, u64::from(opening.end_checkpoint_id), u64::from(record.user_id), ordinal, be_u32_words(&record.nonce), recipient_words(&record.recipient), amount_words(&record.amount)?).await?);
    }
    let withdrawal = prove_withdrawal_claims(&circuits.withdrawal_claim, &BridgeWithdrawalClaimInput {
        end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root, end_gusr,
        end_gcon: HashOut { elements: std::array::from_fn(|index| finalizations[0].public_inputs[8 + index]) },
        claims: withdrawal_claims,
    })?;

    let mut roots = Vec::with_capacity(witness.rewards.len());
    let mut claims = Vec::with_capacity(witness.rewards.len());
    for (index, reward) in witness.rewards.iter().enumerate() {
        let proof_bytes = canonical_base64(&reward.proof).context("reward root proof is not canonical standard base64")?;
        let root = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &circuits.reward_root.circuit_data.common).context("reward root proof")?;
        anyhow::ensure!(root.to_bytes() == proof_bytes && root.public_inputs.len() == REWARD_ROOT_STATEMENT_LEN, "reward root proof is not canonical");
        let statement: [u64; REWARD_ROOT_STATEMENT_LEN] = std::array::from_fn(|field| root.public_inputs[field].to_canonical_u64());
        let claim = psy_client_data::bridge_aggregate::RewardClaim::from_public_inputs(network.ethereum_index, &statement)
            .map_err(|error| anyhow::anyhow!("reward claim: {error:?}"))?;
        anyhow::ensure!(claim == opening.rewards[index], "reward root statement differs from the opening");
        let anchor = canonical_base64(&reward.anchor).context("reward anchor is not canonical standard base64")?;
        anyhow::ensure!(anchor.len() == 2696, "reward anchor width");
        let anchor_fields = decode_reward_anchor(&anchor)?;
        let statement_index = u32::try_from(index)?;
        let selected = provider.get_checkpoint_tree_merkle_proof(to_checkpoint, anchor_fields[0]).await?;
        claims.push(validate_reward_anchor(statement_index, &anchor_fields, &statement, to_checkpoint, end_checkpoint_root, &selected)?);
        roots.push(root);
    }
    let batch = if roots.is_empty() { prove_empty_reward_batch(&circuits)? } else { prove_reward_root_batch(&circuits, &roots)? };
    let reward = prove_reward_claims(&circuits, &BridgeRewardClaimInput {
        end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root, claims, batch_proof: batch,
    })?;
    let aggregate = prove_bridge_aggregate(&circuits, &deposit, &withdrawal, &reward, &finalizations, &zero_span)?;
    let bound = bind_opening_digest(&aggregate, opening_bytes, opening_digest)?;
    let chains = network.chains.iter().map(|chain| BridgeOpeningChain {
        chain_index: chain.chain_index, bootstrap_id: chain.bootstrap_id, bootstrap_root: chain.bootstrap_root,
    }).collect::<Vec<_>>();
    let wrapper = BridgeOpeningWrapper::build(
        &circuits.bridge_aggregate.circuit_data.common, &circuits.bridge_aggregate.circuit_data.verifier_only,
        &circuits.withdrawal_claim.circuit_data.common, &circuits.withdrawal_claim.circuit_data.verifier_only,
        approved.sources, network.config_hash().map_err(|error| anyhow::anyhow!("approved configuration hash: {error:?}"))?, &chains, circuits.withdrawal_policies(),
    )?;
    Ok((bound, wrapper))
}

pub async fn run_prove_bridge_agg_with_result(
    from_checkpoint: u64,
    to_checkpoint: u64,
    rpc_config: String,
    out_json: PathBuf,
    deployments_network: String,
    aggregate_config: PathBuf,
    opening_bytes: Vec<u8>,
    witness: OpeningWitness,
    artifact_dir: PathBuf,
) -> anyhow::Result<BridgeProveResult> {
    let from_checkpoint = from_checkpoint.max(1);
    anyhow::ensure!(from_checkpoint <= to_checkpoint, "from_checkpoint must be <= to_checkpoint");
    let num_checkpoints_aggregated = to_checkpoint - from_checkpoint + 1;
    let _l1_config = load_l1_deployment_config(&deployments_network)?;
    let (bound, wrapper) = prove_bridge_opening(from_checkpoint, to_checkpoint, &rpc_config, &aggregate_config, &opening_bytes, &witness).await?;
    let opening_dir = artifact_dir.join("BridgeOpening");
    crate::bridge::regen_groth16_keystore::validate_bridge_opening_setup(&opening_dir, wrapper.identity())?;
    let artifact = opening_dir.to_str().context("BridgeOpening artifact path must be UTF-8")?;
    let groth16 = wrapper.prove_groth16(&bound.proof, artifact)?;
    if let Some(parent) = out_json.parent().filter(|path| !path.as_os_str().is_empty()) { fs::create_dir_all(parent)?; }
    fs::write(&out_json, serde_json::to_vec(&groth16)?)?;
    Ok(BridgeProveResult {
        from_checkpoint, to_checkpoint, num_checkpoints_aggregated, proof_path: out_json, opening_digest: hex::encode(bound.opening_digest),
    })
}
fn canonical_base64(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(value)?;
    anyhow::ensure!(base64::engine::general_purpose::STANDARD.encode(&bytes) == value, "base64 is not canonical");
    Ok(bytes)
}

fn decode_reward_anchor(anchor: &[u8]) -> anyhow::Result<[u64; 337]> {
    anyhow::ensure!(anchor.len() == 2696, "reward anchor width");
    let mut fields = [0u64; 337];
    for (index, chunk) in anchor.chunks_exact(8).enumerate() {
        let field = u64::from_le_bytes(chunk.try_into().unwrap());
        anyhow::ensure!(field < 0xffff_ffff_0000_0001, "reward anchor field is outside Goldilocks");
        fields[index] = field;
    }
    Ok(fields)
}

fn decoded_checkpoint_leaf(fields: &[u64; 337]) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>> {
    use psy_client_common::traits::to_qfelts::{QFeltSized, ToQFelts};
    use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
    let width = PsyCheckpointLeaf::<F>::q_felt_size();
    anyhow::ensure!(width == 43 && 1 + width + 24 == 68, "checkpoint leaf and roots no longer occupy anchor fields 1..68");
    let felts = fields[1..1 + width].iter().copied().map(F::from_canonical_u64).collect::<Vec<_>>();
    Ok(PsyCheckpointLeaf::from_qfelts(&felts))
}

fn validate_reward_anchor(
    statement_index: u32,
    anchor_fields: &[u64; 337],
    statement: &[u64; REWARD_ROOT_STATEMENT_LEN],
    end_checkpoint_id: u64,
    end_checkpoint_root: HashOut<F>,
    selected: &psy_crypto::hash::merkle::core::MerkleProofCore<ClientQHashOut>,
) -> anyhow::Result<BridgeRewardClaimWitness> {
    use plonky2::plonk::config::Hasher;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    let anchor_checkpoint_id = anchor_fields[0];
    anyhow::ensure!(anchor_checkpoint_id <= u64::from(u32::MAX) && anchor_checkpoint_id <= end_checkpoint_id, "reward anchor checkpoint is outside the selected range");
    let anchor_checkpoint_id = anchor_checkpoint_id as u32;
    let anchor_leaf = decoded_checkpoint_leaf(anchor_fields)?.qfhash::<plonky2::hash::poseidon::PoseidonHash>().0;
    let admission_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT] = std::array::from_fn(|level| HashOut { elements: std::array::from_fn(|limb| F::from_canonical_u64(anchor_fields[68 + level * 4 + limb])) });
    let mut admission_root = anchor_leaf;
    let mut cursor = u64::from(anchor_checkpoint_id);
    for sibling in admission_siblings {
        admission_root = if cursor & 1 == 0 { plonky2::hash::poseidon::PoseidonHash::two_to_one(admission_root, sibling) } else { plonky2::hash::poseidon::PoseidonHash::two_to_one(sibling, admission_root) };
        cursor >>= 1;
    }
    anyhow::ensure!(admission_root.elements.map(|limb| limb.to_canonical_u64()) == statement[26..30], "reward anchor is not under its checkpoint root");
    anyhow::ensure!(selected.index == u64::from(anchor_checkpoint_id) && selected.siblings.len() == CHECKPOINT_TREE_HEIGHT, "selected anchor path does not identify the anchor checkpoint");
    anyhow::ensure!(to_core_hash(selected.value).0 == anchor_leaf, "selected anchor path authenticates another leaf");
    let selected_root = to_core_hash(selected.root);
    let selected_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT] = std::array::from_fn(|level| to_core_hash(selected.siblings[level]).0);
    anyhow::ensure!(selected_root.0 == end_checkpoint_root, "selected anchor path does not bind the end checkpoint");
    let (anchor_root, current_root) = parth_core::crypto::hash::merkle_proof::compute_historical_and_current_merkle_roots_core_gt::<HashOut<F>, plonky2::hash::poseidon::PoseidonHash>(&MerkleProofCore {
        root: end_checkpoint_root, value: anchor_leaf, index: u64::from(anchor_checkpoint_id), siblings: selected_siblings.to_vec(),
    });
    anyhow::ensure!(current_root == end_checkpoint_root, "fetched anchor path does not reach the selected end root");
    anyhow::ensure!(statement[26..30] == anchor_root.elements.map(|limb| limb.to_canonical_u64()), "reward root is not the historical root of the selected anchor");
    Ok(BridgeRewardClaimWitness { statement_index, anchor_checkpoint_id, anchor_leaf, anchor_siblings: selected_siblings })
}
#[cfg(test)]
mod withdrawal_conversion_tests {
    use super::{amount_words, be_u32_words, recipient_words, withdrawal_policy_ordinals, BridgeTokenPolicy, F};
    use plonky2::field::types::Field;
    use psy_client_data::bridge_aggregate::WithdrawalBurnRecord;
    use psy_client_data::qdata::contract::PsyContractLeaf;

    fn policy(chain: u8, contract: u32) -> BridgeTokenPolicy {
        BridgeTokenPolicy {
            chain_index: chain, token_contract_id: contract, token_address: [0; 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(1), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        }
    }
    fn record(chain: u8, contract: u32) -> WithdrawalBurnRecord {
        WithdrawalBurnRecord { chain_index: chain, user_id: 1, contract_id: contract, nonce: [0; 32], recipient: [1; 20], amount: [0; 32] }
    }

    #[test]
    fn recipient_keeps_leading_zero_words() {
        let address = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50,
        ];
        let words = recipient_words(&address);
        assert_eq!(&words[..3], &[0, 0, 0]);
        assert_eq!(&words[3..], &[0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff10, 0x20304050]);
    }

    #[test]
    fn nonce_preserves_words_above_goldilocks() {
        let mut nonce = [0u8; 32];
        nonce[0..8].copy_from_slice(&u64::MAX.to_be_bytes());
        nonce[8..16].copy_from_slice(&0xffff_ffff_0000_0001u64.to_be_bytes());
        let words = be_u32_words(&nonce);
        assert_eq!(&words[..4], &[u32::MAX, u32::MAX, u32::MAX, 1]);
        assert_eq!(&words[4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn amount_accepts_power_of_two_and_modulus_minus_one() {
        let mut power = [0u8; 32];
        power[24..32].copy_from_slice(&(1u64 << 32).to_be_bytes());
        assert_eq!(amount_words(&power).unwrap()[6..], [1, 0]);
        let mut below = [0u8; 32];
        below[24..32].copy_from_slice(&0xffff_ffff_0000_0000u64.to_be_bytes());
        assert_eq!(amount_words(&below).unwrap()[6..], [u32::MAX, 0]);
    }

    #[test]
    fn amount_rejects_zero_and_modulus() {
        assert!(amount_words(&[0; 32]).is_err());
        let mut modulus = [0u8; 32];
        modulus[24..32].copy_from_slice(&0xffff_ffff_0000_0001u64.to_be_bytes());
        assert!(amount_words(&modulus).is_err());
    }

    #[test]
    fn policy_ordinals_follow_opening_order() {
        let policies = vec![policy(1, 7), policy(2, 9)];
        let records = vec![record(2, 9), record(1, 7)];
        assert_eq!(withdrawal_policy_ordinals(&policies, &records).unwrap(), vec![1, 0]);
        let mut ambiguous = policies.clone();
        ambiguous.push(policy(2, 9));
        assert!(withdrawal_policy_ordinals(&ambiguous, &records).is_err());
        assert!(withdrawal_policy_ordinals(&policies[..1], &records).is_err());
    }
}

#[cfg(test)]
mod reward_anchor_tests {
    use super::{validate_reward_anchor, ClientQHashOut, CHECKPOINT_TREE_HEIGHT, F};
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::hash_types::HashOut;
    use psy_client_common::traits::to_qfelts::{QFeltSized, ToQFelts};
    use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
    use psy_crypto::hash::{merkle::utils::simple_merkle_tree::SimpleMerkleTree, traits::qhashable::QFieldHashable};

    fn hash(value: HashOut<F>) -> ClientQHashOut { psy_client_common::data::qhashout::QHashOut(value) }
    fn fields_from_leaf(id: u64, leaf: &PsyCheckpointLeaf<F>, siblings: &[HashOut<F>; CHECKPOINT_TREE_HEIGHT]) -> [u64; 337] {
        let mut fields = [0u64; 337];
        fields[0] = id;
        for (index, felt) in leaf.to_qfelts().into_iter().enumerate() { fields[1 + index] = felt.to_canonical_u64(); }
        for (level, sibling) in siblings.iter().enumerate() {
            for (limb, element) in sibling.elements.iter().enumerate() { fields[68 + level * 4 + limb] = element.to_canonical_u64(); }
        }
        fields
    }
    fn fixture() -> ([u64; 337], [u64; REWARD_ROOT_STATEMENT_LEN], u64, HashOut<F>, psy_crypto::hash::merkle::core::MerkleProofCore<ClientQHashOut>) {
        let mut tree = SimpleMerkleTree::<plonky2::hash::poseidon::PoseidonHash, HashOut<F>>::new(CHECKPOINT_TREE_HEIGHT as u8);
        let leaf = PsyCheckpointLeaf::<F>::default();
        tree.set_leaf(7, leaf.qfhash::<plonky2::hash::poseidon::PoseidonHash>().0);
        let admission = tree.get_leaf(7);
        tree.set_leaf(11, HashOut { elements: [F::from_canonical_u64(9), F::ZERO, F::ZERO, F::ZERO] });
        let selected = tree.get_leaf(7);
        assert_ne!(admission.siblings, selected.siblings);
        let fields = fields_from_leaf(7, &leaf, &std::array::from_fn(|level| admission.siblings[level]));
        let mut statement = [0u64; REWARD_ROOT_STATEMENT_LEN];
        statement[26..30].copy_from_slice(&admission.root.elements.map(|limb| limb.to_canonical_u64()));
        let selected = psy_crypto::hash::merkle::core::MerkleProofCore { root: hash(selected.root), value: hash(selected.value), index: selected.index, siblings: selected.siblings.into_iter().map(hash).collect() };
        (fields, statement, 11, selected.root.0, selected)
    }

    #[test]
    fn older_admission_differs_from_selected_end_siblings() {
        let (fields, statement, end_id, end_root, selected) = fixture();
        let witness = validate_reward_anchor(4, &fields, &statement, end_id, end_root, &selected).unwrap();
        assert_eq!(witness.statement_index, 4);
        assert_eq!(witness.anchor_checkpoint_id, 7);
        assert_eq!(witness.anchor_leaf, selected.value.0);
        assert_eq!(witness.anchor_siblings, std::array::from_fn(|level| selected.siblings[level].0));
    }

    #[test]
    fn altered_admission_path_is_rejected() {
        let (mut fields, statement, end_id, end_root, selected) = fixture();
        fields[68] ^= 1;
        assert!(validate_reward_anchor(0, &fields, &statement, end_id, end_root, &selected).is_err());
    }

    #[test]
    fn short_and_long_selected_paths_reject_before_indexing() {
        let (fields, statement, end_id, end_root, selected) = fixture();
        for length in [31usize, 33] {
            let mut siblings = selected.siblings.clone();
            siblings.resize(length, hash(HashOut::ZERO));
            let mut selected = selected.clone();
            selected.siblings = siblings;
            assert!(validate_reward_anchor(0, &fields, &statement, end_id, end_root, &selected).is_err());
        }
    }
}

#[cfg(test)]
mod top_tree_tests {
    use super::{canonical_empty_subtree, keccak_pair};
    use alloy_primitives::{keccak256, B256};

    #[test]
    fn unwritten_slots_expand_to_level_specific_empty_subtrees() {
        let mut empty = B256::ZERO;
        for level in 0..8 {
            assert_eq!(canonical_empty_subtree(B256::ZERO, empty), empty, "level {level}");
            let non_empty = keccak256([level as u8]);
            assert_eq!(canonical_empty_subtree(non_empty, empty), non_empty);
            empty = keccak_pair(empty, empty);
        }
    }

    #[test]
    fn empty_chain_two_proof_matches_root_when_only_chain_one_is_non_empty() {
        let chain_one = keccak256(b"chain-one-withdrawal-root");
        let level_one_left = keccak_pair(B256::ZERO, chain_one);

        let mut empty = keccak_pair(B256::ZERO, B256::ZERO);
        let mut root_from_chain_one = level_one_left;
        for _level in 1..8 {
            root_from_chain_one = keccak_pair(root_from_chain_one, empty);
            empty = keccak_pair(empty, empty);
        }

        let mut chain_two_value = B256::ZERO;
        let mut chain_two_node = 258u16;
        let mut empty = B256::ZERO;
        for level in 0..8 {
            let sibling = if level == 1 { level_one_left } else { empty };
            chain_two_value = if chain_two_node & 1 == 0 {
                keccak_pair(chain_two_value, sibling)
            } else {
                keccak_pair(sibling, chain_two_value)
            };
            chain_two_node >>= 1;
            empty = keccak_pair(empty, empty);
        }

        assert_eq!(chain_two_value, root_from_chain_one);
    }
}

#[cfg(test)]
mod deposit_frontier_tests {
    use super::{append_deposit_leaf, build_deposit_spiderman_inputs, deposit_leaf_hash};
    use parth_core::{crypto::hash::traits::MerkleZeroHasher, pgoldilocks::PoseidonHasher};
    use plonky2::field::types::PrimeField64;
    use psy_client_data::bridge_aggregate::{
        Bytes32, ChainConfig, ChainStart,
        DepositAggregateOpening, DepositLeaf, DepositTransition, NetworkConfig, BRIDGE_USER_ID,
    };

    fn word(value: u64) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn config() -> NetworkConfig {
        NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: BRIDGE_USER_ID,
            circuit_set_hash: [7; 32],
            chains: (0..2).map(|index| ChainConfig {
                chain_index: index, chain_id: word(u64::from(index) + 1),
                bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0,
                bootstrap_root: [1, 2, 3, 4],
            }).collect(),
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20],
            reward_per_claim: word(1), reward_token_decimals: 0,
            max_withdrawals: 1024, max_rewards: 1024,
        }
    }

    #[test]
    fn prior_chain_seven_then_local_thirty_to_thirty_five_uses_two_frontiers() {
        let network = config();
        let mut leaves = Vec::new();
        for (chain, absolute_index) in (0..7).map(|index| (0u8, index)).chain((30..35).map(|index| (1u8, index))) {
            leaves.push(DepositLeaf {
                chain_index: chain, absolute_index, shield_address: [9; 32], token: [0; 20],
                l2_token_contract_id: word(1), amount: word(u64::from(absolute_index) + 1),
                note_commitment: word(u64::from(chain) + 8),
            });
        }
        let mut prior = [parth_core::pgoldilocks::QHashOut::ZERO; 32];
        let mut prior_old = PoseidonHasher::get_zero_hash(32);
        let mut prior_root = prior_old;
        for (index, leaf) in leaves[..7].iter().enumerate() {
            prior_root = append_deposit_leaf(&mut prior, index as u32, deposit_leaf_hash(leaf).unwrap());
        }
        let mut second_prefix = (0..30).map(|index| DepositLeaf {
            chain_index: 1, absolute_index: index, shield_address: word(u64::from(index) + 20),
            token: [3; 20], l2_token_contract_id: word(2), amount: word(u64::from(index) + 40),
            note_commitment: word(u64::from(index) + 70),
        }).collect::<Vec<_>>();
        second_prefix.extend_from_slice(&leaves[7..]);
        let mut local = [parth_core::pgoldilocks::QHashOut::ZERO; 32];
        let mut old_root = PoseidonHasher::get_zero_hash(32);
        for (index, leaf) in second_prefix[..30].iter().enumerate() {
            old_root = append_deposit_leaf(&mut local, index as u32, deposit_leaf_hash(leaf).unwrap());
        }
        let retained_frontier = local;
        let split = {
            let mut frontier = local;
            let mut root = old_root;
            for (offset, leaf) in second_prefix[30..32].iter().enumerate() {
                root = append_deposit_leaf(&mut frontier, 30 + offset as u32, deposit_leaf_hash(leaf).unwrap());
            }
            root
        };
        let mut new_root = old_root;
        for (offset, leaf) in second_prefix[30..].iter().enumerate() {
            new_root = append_deposit_leaf(&mut local, 30 + offset as u32, deposit_leaf_hash(leaf).unwrap());
        }
        let root = |value: parth_core::pgoldilocks::QHashOut<plonky2::field::goldilocks_field::GoldilocksField>| {
            value.0.elements.map(|limb| limb.to_canonical_u64())
        };
        let mut opening = DepositAggregateOpening {
            config_hash: network.config_hash().unwrap(), window_id: [0; 32],
            end_checkpoint_id: 1, end_checkpoint_root: [5, 6, 7, 8],
            starts: network.chains.iter().map(|chain| ChainStart {
                chain_index: chain.chain_index, start_checkpoint_id: 0,
                start_checkpoint_root: chain.bootstrap_root,
            }).collect(),
            deposits: vec![
                DepositTransition { chain_index: 0, old_root: root(prior_old), new_root: root(prior_root), old_count: 0, new_count: 7 },
                DepositTransition { chain_index: 1, old_root: root(old_root), new_root: root(new_root), old_count: 30, new_count: 35 },
            ],
            deposit_leaves: leaves.clone(),
        };
        opening.window_id = opening.window_id().unwrap();
        let mut retained_second = crate::guardian::verify_l1::VerifiedDepositPrefix::empty(1);
        retained_second.count = 30;
        retained_second.frontier = retained_frontier.map(|hash| psy_client_common::data::qhashout::QHashOut(hash.0));
        retained_second.root = psy_client_common::data::qhashout::QHashOut(old_root.0);
        retained_second = retained_second.with_occupied(second_prefix[..30].iter().map(|leaf| psy_client_common::data::qhashout::QHashOut(deposit_leaf_hash(leaf).unwrap().0)).collect());
        let retained = [crate::guardian::verify_l1::VerifiedDepositPrefix::empty(0), retained_second];
        let pages = build_deposit_spiderman_inputs(&network, &opening, &retained).unwrap();
        assert_eq!(pages.len(), 3);
        assert_eq!((pages[0].chain_index, pages[0].first_leaf, pages[0].leaf_count, pages[0].old_count), (0, 0, 7, 0));
        assert_eq!(pages[0].append_proof.top_line_proof.old_root, prior_old);
        assert_eq!(pages[0].append_proof.top_line_proof.new_root, prior_root);
        assert!(pages[0].append_proof.web_proof_old_leaves.iter().all(|leaf| *leaf == parth_core::pgoldilocks::QHashOut::ZERO));
        let expected = [(1u8, 7u32, 2u32, 30u32, old_root, split), (1, 9, 3, 32, split, new_root)];
        for (page, (chain, first, width, old_count, page_old, page_new)) in pages[1..].iter().zip(expected) {
            assert_eq!((page.chain_index, page.first_leaf, page.leaf_count, page.old_count), (chain, first, width, old_count));
            assert_eq!(page.append_proof.top_line_proof.old_root, page_old);
            assert_eq!(page.append_proof.top_line_proof.new_root, page_new);
            let occupied = (old_count % 32) as usize;
            for (actual, retained) in page.append_proof.web_proof_old_leaves[..occupied].iter().zip(&retained[1].occupied_partial_page_hashes()[..occupied]) {
                assert_eq!(*actual, super::to_core_hash(*retained));
            }
            assert!(page.append_proof.web_proof_old_leaves[occupied..].iter().all(|leaf| *leaf == parth_core::pgoldilocks::QHashOut::ZERO));
        }
        assert_ne!(pages[1].append_proof.top_line_proof.old_root, pages[1].append_proof.top_line_proof.new_root);
        let mut crossed = opening.clone();
        crossed.deposits[1].old_count = 31;
        crossed.deposit_leaves.drain(8..9);
        let mut crossed_prefix = retained[1].clone(); crossed_prefix.count = 31;
        assert!(build_deposit_spiderman_inputs(&network, &crossed, &[retained[0].clone(), crossed_prefix]).is_err());
    }
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

pub(crate) fn selected_finalizer_is_membership(public_inputs: &[F], chain_count: usize) -> anyhow::Result<bool> {
    anyhow::ensure!(public_inputs.len() == bridge_agg_final_pi_len(chain_count), "finalizer width differs from 18+5*C");
    let span = public_inputs[17];

    if span == F::ZERO {
        anyhow::ensure!(public_inputs[..4] == public_inputs[12..16], "zero span changed the checkpoint root");
        anyhow::ensure!(public_inputs.len() == 18 + 5 * chain_count, "every chain publishes a deposit endpoint");
        Ok(true)
    } else {
        anyhow::ensure!(span.to_canonical_u64() > 0, "positive span is not canonical");
        Ok(false)
    }
}

#[cfg(test)]
mod opening_selection_tests {
    use super::selected_finalizer_is_membership;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;

    #[test]
    fn positive_span_uses_end_and_span_offsets() {
        let mut inputs = vec![GoldilocksField::ZERO; 28];
        inputs[16] = GoldilocksField::from_canonical_u64(11);
        inputs[17] = GoldilocksField::from_canonical_u64(4);
        assert_eq!(inputs.len(), psy_plonky2_circuits::bridge::circuits::bridge_agg_final::bridge_agg_final_pi_len(2));
        assert!(!selected_finalizer_is_membership(&inputs, 2).unwrap());
    }

    #[test]
    fn zero_span_rejects_a_changed_root() {
        let mut inputs = vec![GoldilocksField::from_canonical_u64(9); 23];
        inputs[16] = GoldilocksField::from_canonical_u64(7);
        inputs[17] = GoldilocksField::ZERO;
        for index in 0..4 { inputs[12 + index] = inputs[index]; }
        assert!(selected_finalizer_is_membership(&inputs, 1).unwrap());
        inputs[12] += GoldilocksField::ONE;
        assert!(selected_finalizer_is_membership(&inputs, 1).is_err());
    }

    #[test]
    fn noncanonical_opening_bytes_fail_before_any_proof() {
        assert!(psy_client_data::bridge_aggregate::BridgeOpening::decode(&[0, 1, 2, 3]).is_err());
        assert!(psy_client_data::bridge_aggregate::BridgeOpening::decode(&[4, 0, 0, 0, 1]).is_err());
    }
}

#[cfg(test)]
mod aggregate_proof_command_tests {
    #[test]
    fn proof_only_command_does_not_read_a_deployment_file() {
        let source = include_str!("prove_bridge.rs");
        let producer = source.split("pub(crate) async fn prove_bridge_opening").nth(1).unwrap().split("pub async fn run_prove_bridge_agg_with_result").next().unwrap();
        assert!(!producer.contains("load_l1_deployment_config"), "proof-only producer must not read deployments");
        let normal = source.split("pub async fn run_prove_bridge_agg_with_result").nth(1).unwrap();
        assert!(normal.contains("load_l1_deployment_config"), "normal prove keeps its deployment preflight");
        assert!(!normal.contains("digest_inputs"), "normal prove must not accept a two-word digest");
    }
}

