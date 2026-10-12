use std::path::Path;

use anyhow::Context;
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use parth_core::{crypto::hash::traits::ToU64x4, pgoldilocks::QHashOut, protocol::core_types::QNetworkCircuitConstants};
use psy_core::job::job_id::ProvingJobCircuitType;
use plonky2::{
    field::goldilocks_field::GoldilocksField as F,
    plonk::{
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::PoseidonGoldilocksConfig as C,
    },
};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;
use psy_client_data::bridge_aggregate::{circuit_set_hash, deposit_aggregate_pi_len, CircuitSetRegistration, NetworkConfig};
use psy_common_circuit::serialization::PsyGateSerializer;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic_q, qstandard::QStandardCircuit};
use super::circuits::{
    bridge_agg_chain::BridgeAggChainCircuit,
    bridge_agg_final::{build_shared_finalizers, BridgeAggFinalCircuit, BridgeAggFinalMembershipCircuit},
    bridge_aggregate::{bridge_aggregate_pi_len, BridgeAggregateCircuit},
    bridge_claim::{BridgeRewardClaimCircuit, BridgeTokenPolicy, BridgeWithdrawalClaimCircuit, BRIDGE_REWARD_CLAIM_STATEMENT_LEN, BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN},
    bridge_wrap::DigestBitsSources,
    deposit_aggregate::DepositAggregateCircuit,
    reward_chain::{RewardMergeCircuit, RewardRootCircuit, RewardSegmentCircuit, REWARD_MERGE_STATEMENT_LEN, REWARD_ROOT_STATEMENT_LEN, REWARD_SEGMENT_STATEMENT_LEN},
    reward_claim_batch::{RewardClaimBatchCircuit, REWARD_CLAIM_BATCH_STATEMENT_LEN},
};

pub struct AggregateCircuitHeights {
    pub deposit_state_tree: usize,
}

/// Approved setup shared by services, the local prover, setup, and the relayer.
/// `network_config` keeps its existing lowercase hex encoding of `NetworkConfig`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateSetupConfig {
    pub network_config: String,
    pub sources: DigestBitsSources,
    pub withdrawal_policies: Vec<BridgeTokenPolicy>,
}

/// The finalizer pins the ordered chain indices; remaining configuration values are witnesses.
pub struct AggregateCircuits {
    pub reward_segment: RewardSegmentCircuit,
    pub reward_merge: RewardMergeCircuit,
    pub reward_root: RewardRootCircuit,
    pub reward_batch: RewardClaimBatchCircuit,
    pub withdrawal_claim: BridgeWithdrawalClaimCircuit,
    pub reward_claim: BridgeRewardClaimCircuit,
    pub deposit_aggregate: DepositAggregateCircuit<C, 2>,
    pub checkpoint_final: BridgeAggFinalCircuit<C, 2>,
    pub checkpoint_membership: BridgeAggFinalMembershipCircuit<C, 2>,
    pub bridge_aggregate: BridgeAggregateCircuit<C>,
    withdrawal_policies: Vec<BridgeTokenPolicy>,
    circuit_set_hash: [u8; 32],
    registrations: Vec<CircuitSetRegistration>,
}

struct BuiltGraphs {
    reward_segment: RewardSegmentCircuit,
    reward_merge: RewardMergeCircuit,
    reward_root: RewardRootCircuit,
    reward_batch: RewardClaimBatchCircuit,
    withdrawal_claim: BridgeWithdrawalClaimCircuit,
    reward_claim: BridgeRewardClaimCircuit,
    deposit_aggregate: DepositAggregateCircuit<C, 2>,
    checkpoint_final: BridgeAggFinalCircuit<C, 2>,
    checkpoint_membership: BridgeAggFinalMembershipCircuit<C, 2>,
    bridge_aggregate: BridgeAggregateCircuit<C>,
}

impl AggregateCircuits {
    /// Builds the closed ten-circuit set. `withdrawal_policies` is the installed collection;
    /// `ethereum_index` comes from the decoded `NetworkConfig`, never from the first chain.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn build<N: QNetworkCircuitConstants>(configured_chain_indices: &[u8], checkpoint_common_data: &CommonCircuitData<F, 2>, checkpoint_cap_height: usize, checkpoint_fingerprint: QHashOut<F>, heights: AggregateCircuitHeights, withdrawal_policies: Vec<BridgeTokenPolicy>, ethereum_index: u8) -> anyhow::Result<Self> {
        let graphs = build_graphs::<N>(configured_chain_indices, checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint, &heights, &withdrawal_policies, ethereum_index)?;
        let mut bundle = Self {
            reward_segment: graphs.reward_segment, reward_merge: graphs.reward_merge, reward_root: graphs.reward_root, reward_batch: graphs.reward_batch,
            withdrawal_claim: graphs.withdrawal_claim, reward_claim: graphs.reward_claim, deposit_aggregate: graphs.deposit_aggregate,
            checkpoint_final: graphs.checkpoint_final, checkpoint_membership: graphs.checkpoint_membership, bridge_aggregate: graphs.bridge_aggregate,
            withdrawal_policies, registrations: Vec::new(), circuit_set_hash: [0; 32],
        };
        bundle.registrations = bundle.build_registrations()?;
        bundle.circuit_set_hash = circuit_set_hash(&bundle.registrations).map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(bundle)
    }

    pub fn registrations(&self) -> &[CircuitSetRegistration] { &self.registrations }
    pub fn circuit_set_hash(&self) -> [u8; 32] { self.circuit_set_hash }
    pub fn withdrawal_policies(&self) -> &[BridgeTokenPolicy] { &self.withdrawal_policies }
    pub fn withdrawal_claim_data(&self) -> &CircuitData<F, C, 2> { &self.withdrawal_claim.circuit_data }
    pub fn reward_claim_data(&self) -> &CircuitData<F, C, 2> { &self.reward_claim.circuit_data }

    pub fn validate_registrations(&self, expected: &[CircuitSetRegistration]) -> anyhow::Result<()> {
        circuit_set_hash(expected).map_err(|error| anyhow::anyhow!("{error}"))?;
        anyhow::ensure!(self.build_registrations()? == expected, "circuit registry differs from the complete source graph");
        Ok(())
    }

    pub fn validate_config(&self, config: &NetworkConfig) -> anyhow::Result<()> {
        config.validate().map_err(|error| anyhow::anyhow!("{error}"))?;
        let chain_count = config.chains.len();
        let deposit_width = deposit_aggregate_pi_len(chain_count);
        let final_width = 18 + 5 * chain_count;
        let top_width = bridge_aggregate_pi_len(chain_count);
        let configured = config.chains.iter().map(|chain| chain.chain_index);
        anyhow::ensure!(configured.clone().eq(self.checkpoint_final.configured_chain_indices().iter().copied()), "configuration chain indices differ from source graph");
        anyhow::ensure!(self.checkpoint_membership.configured_chain_indices() == self.checkpoint_final.configured_chain_indices(), "membership chain indices differ from positive finalizer");
        anyhow::ensure!(self.withdrawal_policies.iter().all(|policy| configured.clone().any(|index| index == policy.chain_index)), "withdrawal policy chain is not configured");
        anyhow::ensure!(self.deposit_aggregate.circuit_data.common.num_public_inputs == deposit_width, "deposit aggregate width differs from configured chain count");
        anyhow::ensure!(self.checkpoint_final.circuit_data.common.num_public_inputs == final_width && self.checkpoint_membership.circuit_data.common.num_public_inputs == final_width, "finalizer width differs from 18+5*C");
        anyhow::ensure!(self.checkpoint_final.circuit_data.common == self.checkpoint_membership.circuit_data.common, "positive and membership finalizers must share one common circuit");
        anyhow::ensure!(self.bridge_aggregate.circuit_data.common.num_public_inputs == top_width, "bridge aggregate width differs from 8316+128*C");
        let required = [
            ((11, 0, 1), deposit_width), ((14, 0, 0), cyclic_width(&self.reward_merge.circuit_data, REWARD_MERGE_STATEMENT_LEN)?),
            ((14, 0, 1), REWARD_SEGMENT_STATEMENT_LEN),
            ((15, 0, 0), REWARD_ROOT_STATEMENT_LEN), ((16, 0, 0), cyclic_width(&self.reward_batch.circuit_data, REWARD_CLAIM_BATCH_STATEMENT_LEN)?),
            ((17, 0, 0), BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN), ((18, 0, 0), BRIDGE_REWARD_CLAIM_STATEMENT_LEN),
            ((19, 0, 1), final_width), ((19, 0, 2), final_width), ((20, 0, 0), top_width),
        ];
        anyhow::ensure!(self.registrations.len() == required.len(), "source graph does not contain the closed ten-circuit set");
        for (registration, ((family, level, variant), width)) in self.registrations.iter().zip(required) {
            anyhow::ensure!((registration.family, registration.level, registration.variant) == (family, level, variant) && registration.pi_words as usize == width, "registration ({family},{level},{variant}) differs from the constructed graph");
        }
        anyhow::ensure!(config.circuit_set_hash == self.circuit_set_hash, "configuration circuit-set pin differs from source graph");
        Ok(())
    }

    fn build_registrations(&self) -> anyhow::Result<Vec<CircuitSetRegistration>> {
        let chain_count = self.checkpoint_final.configured_chain_indices().len();
        let rows = [
            ((14, 0, 0), cyclic_width(&self.reward_merge.circuit_data, REWARD_MERGE_STATEMENT_LEN)?, &self.reward_merge.circuit_data),
            ((14, 0, 1), REWARD_SEGMENT_STATEMENT_LEN, &self.reward_segment.circuit_data),
            ((15, 0, 0), REWARD_ROOT_STATEMENT_LEN, &self.reward_root.circuit_data),
            ((16, 0, 0), cyclic_width(&self.reward_batch.circuit_data, REWARD_CLAIM_BATCH_STATEMENT_LEN)?, &self.reward_batch.circuit_data),
            ((17, 0, 0), BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN, &self.withdrawal_claim.circuit_data),
            ((18, 0, 0), BRIDGE_REWARD_CLAIM_STATEMENT_LEN, &self.reward_claim.circuit_data),
            ((11, 0, 1), deposit_aggregate_pi_len(chain_count), &self.deposit_aggregate.circuit_data),
            ((19, 0, 1), 18 + 5 * chain_count, &self.checkpoint_final.circuit_data),
            ((19, 0, 2), 18 + 5 * chain_count, &self.checkpoint_membership.circuit_data),
            ((20, 0, 0), bridge_aggregate_pi_len(chain_count), &self.bridge_aggregate.circuit_data),
        ];
        let mut registrations = rows.into_iter().map(|((family, level, variant), width, data)| {
            circuit_set_registration(family, level, variant, width, data, [0; 4])
        }).collect::<anyhow::Result<Vec<_>>>()?;
        registrations.sort_by_key(|registration| (registration.family, registration.level, registration.variant));
        circuit_set_hash(&registrations).map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(registrations)
    }

    /// Sequential registration-only construction. The proving graphs are dropped after their
    /// registrations are captured. This returns the same sorted ten-entry set as `build`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn build_circuit_set_registrations<N: QNetworkCircuitConstants>(configured_chain_indices: &[u8], checkpoint_common_data: &CommonCircuitData<F, 2>, checkpoint_cap_height: usize, checkpoint_fingerprint: QHashOut<F>, heights: AggregateCircuitHeights, withdrawal_policies: Vec<BridgeTokenPolicy>, ethereum_index: u8) -> anyhow::Result<Vec<CircuitSetRegistration>> {
        let graphs = build_graphs::<N>(configured_chain_indices, checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint, &heights, &withdrawal_policies, ethereum_index)?;
        let chain_count = configured_chain_indices.len();
        let rows = [
            ((14, 0, 0), cyclic_width(&graphs.reward_merge.circuit_data, REWARD_MERGE_STATEMENT_LEN)?, &graphs.reward_merge.circuit_data),
            ((14, 0, 1), REWARD_SEGMENT_STATEMENT_LEN, &graphs.reward_segment.circuit_data),
            ((15, 0, 0), REWARD_ROOT_STATEMENT_LEN, &graphs.reward_root.circuit_data),
            ((16, 0, 0), cyclic_width(&graphs.reward_batch.circuit_data, REWARD_CLAIM_BATCH_STATEMENT_LEN)?, &graphs.reward_batch.circuit_data),
            ((17, 0, 0), BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN, &graphs.withdrawal_claim.circuit_data),
            ((18, 0, 0), BRIDGE_REWARD_CLAIM_STATEMENT_LEN, &graphs.reward_claim.circuit_data),
            ((11, 0, 1), deposit_aggregate_pi_len(chain_count), &graphs.deposit_aggregate.circuit_data),
            ((19, 0, 1), 18 + 5 * chain_count, &graphs.checkpoint_final.circuit_data),
            ((19, 0, 2), 18 + 5 * chain_count, &graphs.checkpoint_membership.circuit_data),
            ((20, 0, 0), bridge_aggregate_pi_len(chain_count), &graphs.bridge_aggregate.circuit_data),
        ];
        let mut registrations = rows.into_iter().map(|((family, level, variant), width, data)| {
            circuit_set_registration(family, level, variant, width, data, [0; 4])
        }).collect::<anyhow::Result<Vec<_>>>()?;
        drop(graphs);
        registrations.sort_by_key(|registration| (registration.family, registration.level, registration.variant));
        circuit_set_hash(&registrations).map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(registrations)
    }
}

/// Reads the one approved setup artifact. Policy validation is delegated to the claim constructor.
pub fn load_aggregate_setup_config(path: &Path) -> anyhow::Result<AggregateSetupConfig> {
    let approved: AggregateSetupConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    approved.sources.validate()?;
    let config_bytes = hex::decode(&approved.network_config)?;
    anyhow::ensure!(hex::encode(&config_bytes) == approved.network_config, "network_config must be lowercase canonical hex without 0x");
    let config = NetworkConfig::decode(&config_bytes).map_err(|error| anyhow::anyhow!("invalid approved aggregate configuration: {error:?}"))?;
    config.validate().map_err(|error| anyhow::anyhow!("{error}"))?;
    anyhow::ensure!(!approved.withdrawal_policies.is_empty(), "installed withdrawal policy collection is empty");
    anyhow::ensure!(approved.withdrawal_policies.windows(2).all(|pair| (pair[0].chain_index, pair[0].token_contract_id) < (pair[1].chain_index, pair[1].token_contract_id)), "installed withdrawal policies must be sorted and unique by (chain_index, token_contract_id)");
    anyhow::ensure!(approved.withdrawal_policies.iter().all(|policy| config.chains.iter().any(|chain| chain.chain_index == policy.chain_index)), "withdrawal policy chain is not configured");
    Ok(approved)
}

#[cfg(not(target_arch = "wasm32"))]
fn build_graphs<N: QNetworkCircuitConstants>(configured_chain_indices: &[u8], checkpoint_common_data: &CommonCircuitData<F, 2>, checkpoint_cap_height: usize, checkpoint_fingerprint: QHashOut<F>, heights: &AggregateCircuitHeights, withdrawal_policies: &[BridgeTokenPolicy], ethereum_index: u8) -> anyhow::Result<BuiltGraphs> {
    let checkpoint_base = ensure_checkpoint_pin::<N>(configured_chain_indices, checkpoint_fingerprint)?;
    let reward_segment = RewardSegmentCircuit::new();
    anyhow::ensure!(reward_segment.circuit_data.common.num_public_inputs == REWARD_SEGMENT_STATEMENT_LEN, "reward segment width differs from 22");
    let reward_merge = RewardMergeCircuit::new(&reward_segment);
    let merge_width = cyclic_width(&reward_merge.circuit_data, REWARD_MERGE_STATEMENT_LEN)?;
    anyhow::ensure!(merge_width == 90, "reward merge width differs from the measured cap-height-4 registry width");
    let reward_root = RewardRootCircuit::new(&reward_merge);
    anyhow::ensure!(reward_root.circuit_data.common.num_public_inputs == REWARD_ROOT_STATEMENT_LEN, "reward root width differs from 30");
    let (root_common, root_verifier) = verifier_inputs(&reward_root.circuit_data);
    let reward_batch = RewardClaimBatchCircuit::new(&root_common, &root_verifier);
    let batch_width = cyclic_width(&reward_batch.circuit_data, REWARD_CLAIM_BATCH_STATEMENT_LEN)?;
    anyhow::ensure!(batch_width == 1_029, "reward batch width differs from the measured cap-height-4 registry width");
    let withdrawal_claim = BridgeWithdrawalClaimCircuit::new(withdrawal_policies.to_vec())?;
    anyhow::ensure!(withdrawal_claim.circuit_data.common.num_public_inputs == BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN, "withdrawal claim width differs from 2574");
    let (batch_common, batch_verifier) = verifier_inputs(&reward_batch.circuit_data);
    let reward_claim = BridgeRewardClaimCircuit::new(&batch_common, &batch_verifier, ethereum_index);
    anyhow::ensure!(reward_claim.circuit_data.common.num_public_inputs == BRIDGE_REWARD_CLAIM_STATEMENT_LEN, "reward claim width differs from 3846");
    let deposit_aggregate = DepositAggregateCircuit::new(configured_chain_indices.len());
    let chain = BridgeAggChainCircuit::<C, 2>::new(checkpoint_base, N::CHECKPOINT_TREE_HEIGHT_USIZE);
    let (checkpoint_final, checkpoint_membership) = build_shared_finalizers::<C, 2>(
        chain.get_common_circuit_data_ref(), chain.get_verifier_config_ref().constants_sigmas_cap.height(), chain.get_fingerprint(),
        checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint, checkpoint_base,
        N::CHECKPOINT_TREE_HEIGHT_USIZE, N::GLOBAL_USER_TREE_HEIGHT_USIZE, N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
        heights.deposit_state_tree, configured_chain_indices,
    );
    let final_width = 18 + 5 * configured_chain_indices.len();
    anyhow::ensure!(checkpoint_final.circuit_data.common.num_public_inputs == final_width && checkpoint_membership.circuit_data.common.num_public_inputs == final_width, "finalizer width differs from 18+5*C");
    anyhow::ensure!(checkpoint_final.circuit_data.common == checkpoint_membership.circuit_data.common, "positive and membership finalizers must share one common circuit");
    let (deposit_common, deposit_verifier) = verifier_inputs(&deposit_aggregate.circuit_data);
    let (withdrawal_common, withdrawal_verifier) = verifier_inputs(&withdrawal_claim.circuit_data);
    let (reward_common, reward_verifier) = verifier_inputs(&reward_claim.circuit_data);
    let (positive_common, positive_verifier) = verifier_inputs(&checkpoint_final.circuit_data);
    let (membership_common, membership_verifier) = verifier_inputs(&checkpoint_membership.circuit_data);
    let bridge_aggregate = BridgeAggregateCircuit::<C>::new(
        configured_chain_indices, &deposit_common, &deposit_verifier, &withdrawal_common, &withdrawal_verifier,
        &reward_common, &reward_verifier, &positive_common, &positive_verifier, &membership_common, &membership_verifier,
    )?;
    anyhow::ensure!(bridge_aggregate.circuit_data.common.num_public_inputs == bridge_aggregate_pi_len(configured_chain_indices.len()), "bridge aggregate width differs from 8316+128*C");
    Ok(BuiltGraphs { reward_segment, reward_merge, reward_root, reward_batch, withdrawal_claim, reward_claim, deposit_aggregate, checkpoint_final, checkpoint_membership, bridge_aggregate })
}

/// Checks the genuine checkpoint state-transition pin against the cached library and
/// returns the cached `GenerateRollupStateTransitionProof` fingerprint. Callers must
/// pass a fingerprint measured on a genuinely constructed checkpoint circuit, never
/// the cached value itself.
#[cfg(not(target_arch = "wasm32"))]
fn ensure_checkpoint_pin<N: QNetworkCircuitConstants>(configured_chain_indices: &[u8], checkpoint_fingerprint: QHashOut<F>) -> anyhow::Result<QHashOut<F>> {
    let source_chain_count = configured_chain_indices.len();
    anyhow::ensure!((1..=8).contains(&source_chain_count), "source chain count must be 1..8");
    anyhow::ensure!(configured_chain_indices.windows(2).all(|pair| pair[0] < pair[1]), "configured chain indices must be strictly increasing");
    let checkpoint_base = crate::generated::cached_circuit_library::get_cached_circuit_library::<F>()
        .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
        .context("GenerateRollupStateTransitionProof not found in cached circuit library")?;
    anyhow::ensure!(checkpoint_fingerprint == checkpoint_base, "checkpoint fingerprint differs from cached GenerateRollupStateTransitionProof");
    anyhow::ensure!(N::CHECKPOINT_TREE_HEIGHT_USIZE == usize::from(CHECKPOINT_TREE_HEIGHT), "checkpoint height differs from the authoritative constant");
    Ok(checkpoint_base)
}

/// Compact common/verifier inputs a parent circuit consumes from a child graph.
fn verifier_inputs(data: &CircuitData<F, C, 2>) -> (CommonCircuitData<F, 2>, VerifierOnlyCircuitData<C, 2>) {
    (data.common.clone(), data.verifier_only.clone())
}

fn cyclic_width(data: &CircuitData<F, C, 2>, statement_len: usize) -> anyhow::Result<usize> {
    let cap_elements = data.common.config.fri_config.num_cap_elements();
    let suffix = 4 + 4 * cap_elements;
    let expected = statement_len + suffix;
    anyhow::ensure!(data.common.num_public_inputs == expected, "cyclic public width differs from statement plus constructed FRI suffix");
    Ok(expected)
}

pub fn circuit_set_registration(family: u16, level: u8, variant: u8, expected_pi_words: usize,
    data: &CircuitData<F, C, 2>, identity_fingerprint: [u64; 4]) -> anyhow::Result<CircuitSetRegistration>
{
    anyhow::ensure!(data.common.num_public_inputs == expected_pi_words, "family {family} level {level} variant {variant} PI width mismatch");
    let fingerprint = get_circuit_fingerprint_generic_q::<2, F, C>(&data.verifier_only).to_u64x4();
    anyhow::ensure!(fingerprint != [0; 4], "missing source circuit pin");
    anyhow::ensure!(identity_fingerprint == [0; 4], "source circuit identity pin must be zero");
    Ok(CircuitSetRegistration { family, level, variant, pi_words: expected_pi_words.try_into()?, fingerprint,
        common_digest: digest(&data.common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?),
        verifier_digest: digest(&data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?),
        identity_fingerprint })
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut result = [0; 32];
    hasher.finalize(&mut result);
    result
}
