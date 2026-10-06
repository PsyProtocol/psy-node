use anyhow::Context;
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use parth_core::{crypto::hash::traits::ToU64x4, protocol::core_types::QNetworkCircuitConstants};
use psy_core::job::job_id::ProvingJobCircuitType;
use plonky2::{field::goldilocks_field::GoldilocksField as F, plonk::{circuit_data::CircuitData, config::PoseidonGoldilocksConfig as C, proof::ProofWithPublicInputs}};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;
use psy_client_data::bridge_aggregate::{bind_claim_tree, circuit_set_hash, DepositAggregateOpening, CircuitSetRegistration, InclusionAggregateHeader, NetworkConfig, SourceCheckpointRewardOpening, WithdrawalAggregateOpening, INCLUSION_AGGREGATE_CAPACITIES, REWARD_SESSION_PROOF_FIELD_COUNT};
use psy_common_circuit::serialization::PsyGateSerializer;
use psy_plonky2_common_circuits::bridge::{deposit_spiderman_append::{DepositSpidermanAppendCircuit, DEPOSIT_SPIDERMAN_PI_WORDS}, withdrawal_inclusion::{WithdrawalInclusionCircuit, WITHDRAWAL_INCLUSION_PUBLIC_INPUTS}};
use tiny_keccak::{Hasher, Keccak};

use crate::{coordinator::coordinator_helper::QEDCoordinatorCircuitManager, proof_minifier::pm_core::get_circuit_fingerprint_generic_q, qstandard::QStandardCircuit};
use super::circuits::{bridge_agg_final::BridgeAggFinalCircuit, chain_aggregate::{ChainAggregateCircuit, CHAIN_PI_WORDS}, deposit_aggregate::{DepositAggregateCircuit, DEPOSIT_AGGREGATE_PI_LEN}, inclusion_aggregate::{AggregateWindow, RewardInclusionAggregateCircuit, RewardLedgerFinalProof, SourceCheckpointRewardAggregateLeaf, WithdrawalAggregateLeaf, WithdrawalInclusionAggregateCircuit, AGGREGATE_PI_LEN}, reward_session::{RewardSessionCircuit, REWARD_SESSION_STEP_CAPACITY}};

pub struct AggregateCircuitHeights {
    pub deposit_state_tree: usize,
    pub withdrawal_state_tree: usize,
}

/// The finalizer pins the ordered chain indices; remaining configuration values are witnesses.
pub struct AggregateCircuits {
    pub deposit: DepositSpidermanAppendCircuit<C, 2>,
    pub withdrawal: WithdrawalInclusionCircuit<C, 2>,
    pub reward_session: RewardSessionCircuit,
    pub checkpoint_final: BridgeAggFinalCircuit<C, 2>,
    pub withdrawal_aggregate: WithdrawalInclusionAggregateCircuit<C, 2, 1024>,
    pub reward_aggregate: RewardInclusionAggregateCircuit<1024>,
    pub chains: ChainAggregateCircuit<C, 2>,
    pub deposit_aggregate: DepositAggregateCircuit<C, 2>,
    registrations: Vec<CircuitSetRegistration>,
    circuit_set_hash: [u8; 32],
}

impl AggregateCircuits {
    pub fn build<N: QNetworkCircuitConstants>(configured_chain_indices: &[u8], coordinator: &QEDCoordinatorCircuitManager<C, 2>, heights: AggregateCircuitHeights) -> anyhow::Result<Self> {
        let source_chain_count = configured_chain_indices.len();
        anyhow::ensure!((1..=256).contains(&source_chain_count), "source chain count must be 1..256");
        anyhow::ensure!(configured_chain_indices.windows(2).all(|pair| pair[0] < pair[1]), "configured chain indices must be strictly increasing");
        let checkpoint = &coordinator.checkpoint_root_transition;
        let checkpoint_fingerprint = checkpoint.get_fingerprint();
        let checkpoint_base = crate::generated::cached_circuit_library::get_cached_circuit_library::<F>()
            .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
            .context("GenerateRollupStateTransitionProof not found in cached circuit library")?;
        anyhow::ensure!(checkpoint_fingerprint == checkpoint_base, "coordinator fingerprint differs from cached GenerateRollupStateTransitionProof");
        anyhow::ensure!(N::CHECKPOINT_TREE_HEIGHT_USIZE == usize::from(CHECKPOINT_TREE_HEIGHT), "checkpoint height differs from the authoritative constant");
        let checkpoint_final = BridgeAggFinalCircuit::prebuild_final_circuit(
            checkpoint.get_common_circuit_data_ref(),
            checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(),
            checkpoint_fingerprint, checkpoint_base,
            N::CHECKPOINT_TREE_HEIGHT_USIZE, N::GLOBAL_USER_TREE_HEIGHT_USIZE,
            N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE, heights.deposit_state_tree,
            heights.withdrawal_state_tree, configured_chain_indices,
        );
        let deposit = DepositSpidermanAppendCircuit::build();
        let withdrawal = WithdrawalInclusionCircuit::build();
        let reward_session = RewardSessionCircuit::new(REWARD_SESSION_STEP_CAPACITY, source_chain_count)?;
        let withdrawal_aggregate = WithdrawalInclusionAggregateCircuit::<C, 2, 1024>::new(&withdrawal.circuit_data, source_chain_count);
        let reward_aggregate = RewardInclusionAggregateCircuit::<1024>::new(&reward_session.circuit_data.common, &reward_session.circuit_data.verifier_only, source_chain_count);
        let chains = ChainAggregateCircuit::build(source_chain_count, &deposit)?;
        let deposit_aggregate = DepositAggregateCircuit::new(source_chain_count, &chains.circuit_data);
        let mut bundle = Self { deposit, withdrawal, reward_session, checkpoint_final, withdrawal_aggregate, reward_aggregate, chains,
            deposit_aggregate, registrations: Vec::new(), circuit_set_hash: [0; 32] };
        bundle.registrations = bundle.build_registrations()?;
        bundle.circuit_set_hash = circuit_set_hash(&bundle.registrations)?;
        Ok(bundle)
    }

    pub fn registrations(&self) -> &[CircuitSetRegistration] { &self.registrations }
    pub fn circuit_set_hash(&self) -> [u8; 32] { self.circuit_set_hash }

    pub fn validate_registrations(&self, expected: &[CircuitSetRegistration]) -> anyhow::Result<()> {
        circuit_set_hash(expected)?;
        anyhow::ensure!(self.build_registrations()? == expected, "circuit registry differs from the complete source graph");
        Ok(())
    }

    pub fn validate_config(&self, config: &NetworkConfig) -> anyhow::Result<()> {
        config.validate()?;
        anyhow::ensure!(config.chains.iter().map(|chain| chain.chain_index).eq(self.checkpoint_final.configured_chain_indices().iter().copied()), "configuration chain indices differ from source graph");
        anyhow::ensure!(config.circuit_set_hash == self.circuit_set_hash, "configuration circuit-set pin differs from source graph");
        Ok(())
    }

    pub fn prove_deposit_aggregate(&self, config: &NetworkConfig, opening: &DepositAggregateOpening, chains: &[ProofWithPublicInputs<F, C, 2>]) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.validate_config(config)?;
        self.deposit_aggregate.prove(config, opening, chains)
    }

    pub fn prove_withdrawal_aggregate(&self, config: &NetworkConfig, opening: &WithdrawalAggregateOpening, header: &InclusionAggregateHeader, leaves: &[WithdrawalAggregateLeaf<'_, C, 2>]) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.validate_config(config)?;
        opening.validate(config)?;
        header.validate()?;
        anyhow::ensure!(header.count != 0, "empty withdrawal manifests carry no proof");
        anyhow::ensure!(header.config_hash == opening.config_hash && header.window_id == opening.window_id
            && header.end_checkpoint_id == opening.end_checkpoint_id && header.end_checkpoint_root == opening.end_checkpoint_root,
            "withdrawal aggregate window differs from opening");
        anyhow::ensure!(header.total_count <= config.max_withdrawals && header.count as usize == leaves.len(), "withdrawal publication count exceeds network limit or differs from opening");
        anyhow::ensure!(header.aggregate_capacity == INCLUSION_AGGREGATE_CAPACITIES[0], "manager withdrawal publication capacity is 1024");
        anyhow::ensure!(opening.withdrawals.len() == leaves.len() && opening.withdrawals.iter().zip(leaves).all(|(leaf, aggregate_leaf)| leaf == aggregate_leaf.leaf), "withdrawal opening differs from proof leaves");
        anyhow::ensure!(header.opening_digest == opening.opening_digest(config)?, "withdrawal publication digest differs from opening");
        anyhow::ensure!(header.withdrawal_roots == opening.withdrawal_roots, "withdrawal publication roots differ from opening");
        let mut bound = header.clone();
        bind_claim_tree(&mut bound, &opening.withdrawals.iter().map(|leaf| leaf.leaf_commit()).collect::<Result<Vec<_>, _>>()?)?;
        anyhow::ensure!(header.claim_tree_root == bound.claim_tree_root, "withdrawal publication claim root differs from opening leaves");
        let window = AggregateWindow { config_hash: opening.config_hash, window_id: opening.window_id, end_id: opening.end_checkpoint_id, end_root: opening.end_checkpoint_root };
        self.withdrawal_aggregate.prove(config, &window, header, leaves)
    }

    pub fn prove_reward_aggregate(&self, config: &NetworkConfig, opening: &SourceCheckpointRewardOpening, header: &InclusionAggregateHeader,
        tip: &RewardLedgerFinalProof<'_>, leaves: &[SourceCheckpointRewardAggregateLeaf<'_>]) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>>
    {
        self.validate_config(config)?;
        opening.encode()?;
        header.validate()?;
        anyhow::ensure!(header.family == psy_client_data::bridge_aggregate::REWARD_PUBLICATION_FAMILY, "reward publication family mismatch");
        anyhow::ensure!(header.count != 0, "empty reward manifests carry no proof");
        anyhow::ensure!(header.aggregate_capacity == INCLUSION_AGGREGATE_CAPACITIES[0], "manager reward publication capacity is 1024");
        anyhow::ensure!(header.segment_index == 0 && header.segment_count == 1 && header.first_ordinal == 0, "manager reward publication is one segment");
        anyhow::ensure!(header.total_count <= config.max_rewards && header.total_count <= INCLUSION_AGGREGATE_CAPACITIES[0] && header.count == header.total_count, "reward publication exceeds the single segment");
        anyhow::ensure!(header.count as usize == leaves.len(), "reward publication count differs from payout proofs");
        anyhow::ensure!(header.config_hash == opening.config_hash && header.window_id == opening.window_id
            && header.end_checkpoint_id == opening.end_checkpoint_id && header.end_checkpoint_root == opening.end_checkpoint_root,
            "reward aggregate window differs from opening");
        anyhow::ensure!(opening.leaves.len() == leaves.len() && opening.leaves.iter().zip(leaves).all(|(leaf, payout)| leaf == payout.leaf), "reward opening differs from payout proofs");
        anyhow::ensure!(header.opening_digest == opening.opening_digest()?, "reward publication digest differs from opening");
        let commits = opening.leaves.iter().map(|leaf| leaf.leaf_commit()).collect::<Result<Vec<_>, _>>()?;
        let mut bound = header.clone();
        bind_claim_tree(&mut bound, &commits)?;
        anyhow::ensure!(header.claim_tree_root == bound.claim_tree_root, "reward publication claim root differs from opening leaves");
        let (Some(_), Some(_)) = (header.old_ledger_state_root, header.new_ledger_state_root) else { anyhow::bail!("reward publication ledger-state roots missing"); };
        self.reward_aggregate.prove(config, opening, header, tip, leaves)
    }

    pub fn into_digest_sources(self) -> (CircuitData<F, C, 2>, CircuitData<F, C, 2>, CircuitData<F, C, 2>) {
        (self.deposit_aggregate.circuit_data, self.withdrawal_aggregate.circuit_data, self.reward_aggregate.circuit_data)
    }

    fn build_registrations(&self) -> anyhow::Result<Vec<CircuitSetRegistration>> {
        let mut registrations = Vec::with_capacity(7);
        for (family, variant, width, data) in [
            (1, 0, DEPOSIT_SPIDERMAN_PI_WORDS, &self.deposit.circuit_data),
            (2, 0, WITHDRAWAL_INCLUSION_PUBLIC_INPUTS, &self.withdrawal.circuit_data),
            (3, 0, REWARD_SESSION_PROOF_FIELD_COUNT, &self.reward_session.circuit_data),
            (7, 2, AGGREGATE_PI_LEN, &self.withdrawal_aggregate.circuit_data),
            (7, 3, AGGREGATE_PI_LEN, &self.reward_aggregate.circuit_data),
            (9, 1, CHAIN_PI_WORDS, &self.chains.circuit_data),
            (11, 1, DEPOSIT_AGGREGATE_PI_LEN, &self.deposit_aggregate.circuit_data),
        ] { registrations.push(circuit_set_registration(family, 0, variant, width, data, [0; 4])?); }
        registrations.sort_by_key(|registration| (registration.family, registration.level, registration.variant));
        circuit_set_hash(&registrations)?;
        Ok(registrations)
    }
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
