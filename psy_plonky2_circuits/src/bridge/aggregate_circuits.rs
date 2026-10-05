use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use parth_core::{crypto::hash::traits::ToU64x4, protocol::core_types::QNetworkCircuitConstants};
use plonky2::{field::goldilocks_field::GoldilocksField as F, plonk::{circuit_data::CircuitData, config::PoseidonGoldilocksConfig as C, proof::ProofWithPublicInputs}};
use psy_client_data::bridge_aggregate::{circuit_set_hash, DepositAggregateOpening, CircuitSetEntry, NetworkConfig, RewardAggregateOpening, WithdrawalAggregateOpening};
use psy_common_circuit::serialization::PsyGateSerializer;
use psy_plonky2_common_circuits::bridge::{deposit_spiderman_append::DepositSpidermanAppendCircuit, withdrawal_inclusion::WithdrawalInclusionCircuit};
use tiny_keccak::{Hasher, Keccak};

use crate::{coordinator::coordinator_helper::QEDCoordinatorCircuitManager, proof_minifier::pm_core::get_circuit_fingerprint_generic_q, qstandard::QStandardCircuit};
use super::circuits::{bridge_agg_final::BridgeAggFinalCircuit, chain_aggregate::ChainAggregateCircuit, deposit_aggregate::DepositAggregateCircuit, inclusion_aggregate::{AggregateWindow, AggregateLeaves, InclusionAggregateCircuit, InclusionAggregateSource, RewardAggregateLeaf, WithdrawalAggregateLeaf}, reward_inclusion::RewardInclusionCircuit};

pub struct AggregateCircuitHeights {
    pub deposit_state_tree: usize,
    pub withdrawal_state_tree: usize,
}

/// The finalizer pins the ordered chain indices; remaining configuration values are witnesses.
pub struct AggregateCircuits {
    pub deposit: DepositSpidermanAppendCircuit<C, 2>,
    pub withdrawal: WithdrawalInclusionCircuit<C, 2>,
    pub reward: RewardInclusionCircuit,
    pub checkpoint_final: BridgeAggFinalCircuit<C, 2>,
    pub aggregates: [InclusionAggregateCircuit<C, 2>; 2],
    pub chains: ChainAggregateCircuit<C, 2>,
    pub deposit_aggregate: DepositAggregateCircuit<C, 2>,
    entries: Vec<CircuitSetEntry>,
    circuit_set_hash: [u8; 32],
}

impl AggregateCircuits {
    pub fn build<N: QNetworkCircuitConstants>(configured_chain_indices: &[u8], coordinator: &QEDCoordinatorCircuitManager<C, 2>, heights: AggregateCircuitHeights) -> anyhow::Result<Self> {
        let source_chain_count = configured_chain_indices.len();
        anyhow::ensure!((1..=256).contains(&source_chain_count), "source chain count must be 1..256");
        anyhow::ensure!(configured_chain_indices.windows(2).all(|pair| pair[0] < pair[1]), "configured chain indices must be strictly increasing");
        let checkpoint = &coordinator.checkpoint_root_transition;
        let checkpoint_fingerprint = checkpoint.get_fingerprint();
        anyhow::ensure!(N::CHECKPOINT_TREE_HEIGHT_USIZE == usize::from(CHECKPOINT_TREE_HEIGHT), "checkpoint height differs from the authoritative constant");
        let checkpoint_final = BridgeAggFinalCircuit::prebuild_final_circuit(
            checkpoint.get_common_circuit_data_ref(),
            checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(),
            checkpoint_fingerprint, checkpoint_fingerprint,
            N::CHECKPOINT_TREE_HEIGHT_USIZE, N::GLOBAL_USER_TREE_HEIGHT_USIZE,
            N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE, heights.deposit_state_tree,
            heights.withdrawal_state_tree, configured_chain_indices,
        );
        let deposit = DepositSpidermanAppendCircuit::build();
        let withdrawal = WithdrawalInclusionCircuit::build();
        let reward = RewardInclusionCircuit::new(source_chain_count)?;
        let aggregates = [
            InclusionAggregateCircuit::new(InclusionAggregateSource::Withdrawal { circuit: &withdrawal.circuit_data, chain_count: source_chain_count }),
            InclusionAggregateCircuit::new(InclusionAggregateSource::Reward { circuit: &reward.circuit_data, chain_count: source_chain_count }),
        ];
        let chains = ChainAggregateCircuit::build(source_chain_count, &deposit)?;
        let deposit_aggregate = DepositAggregateCircuit::new(source_chain_count, &chains.circuit_data);
        let mut bundle = Self { deposit, withdrawal, reward, checkpoint_final, aggregates, chains,
            deposit_aggregate, entries: Vec::new(), circuit_set_hash: [0; 32] };
        bundle.entries = bundle.build_entries()?;
        bundle.circuit_set_hash = circuit_set_hash(&bundle.entries)?;
        Ok(bundle)
    }

    pub fn entries(&self) -> &[CircuitSetEntry] { &self.entries }
    pub fn circuit_set_hash(&self) -> [u8; 32] { self.circuit_set_hash }

    pub fn validate_entries(&self, expected: &[CircuitSetEntry]) -> anyhow::Result<()> {
        circuit_set_hash(expected)?;
        anyhow::ensure!(self.build_entries()? == expected, "circuit registry differs from the complete source graph");
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

    pub fn prove_withdrawal_aggregate(&self, config: &NetworkConfig, opening: &WithdrawalAggregateOpening, leaves: &[WithdrawalAggregateLeaf<'_, C, 2>]) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.validate_config(config)?;
        opening.validate(config)?;
        anyhow::ensure!(opening.withdrawals.len() == leaves.len() && opening.withdrawals.iter().zip(leaves).all(|(leaf, aggregate_leaf)| leaf == aggregate_leaf.leaf), "withdrawal opening differs from proof leaves");
        let window = AggregateWindow { config_hash: opening.config_hash, window_id: opening.window_id, end_id: opening.end_checkpoint_id, end_root: opening.end_checkpoint_root };
        self.aggregates[0].prove(config, &window, &AggregateLeaves::Withdrawal { leaves, withdrawal_roots: &opening.withdrawal_roots })
    }

    pub fn prove_reward_aggregate(&self, config: &NetworkConfig, opening: &RewardAggregateOpening, leaves: &[RewardAggregateLeaf<'_, C, 2>]) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.validate_config(config)?;
        opening.validate(config)?;
        anyhow::ensure!(opening.rewards.len() == leaves.len() && opening.rewards.iter().zip(leaves).all(|(leaf, aggregate_leaf)| leaf == aggregate_leaf.leaf), "reward opening differs from proof leaves");
        let window = AggregateWindow { config_hash: opening.config_hash, window_id: opening.window_id, end_id: opening.end_checkpoint_id, end_root: opening.end_checkpoint_root };
        self.aggregates[1].prove(config, &window, &AggregateLeaves::Reward(leaves))
    }

    pub fn into_digest_sources(self) -> (CircuitData<F, C, 2>, CircuitData<F, C, 2>, CircuitData<F, C, 2>) {
        let [withdrawal, reward] = self.aggregates;
        (self.deposit_aggregate.circuit_data, withdrawal.circuit_data, reward.circuit_data)
    }

    fn build_entries(&self) -> anyhow::Result<Vec<CircuitSetEntry>> {
        let mut entries = self.reward.circuit_set_entries()?;
        for (family, variant, width, data) in [
            (1, 0, 40, &self.deposit.circuit_data),
            (2, 0, 32, &self.withdrawal.circuit_data),
            (7, 2, 12, &self.aggregates[0].circuit_data),
            (7, 3, 12, &self.aggregates[1].circuit_data),
            (9, 1, 37, &self.chains.circuit_data),
            (11, 1, 12, &self.deposit_aggregate.circuit_data),
        ] { entries.push(circuit_set_entry(family, 0, variant, width, data, [0; 4])?); }
        entries.sort_by_key(|entry| (entry.family, entry.level, entry.variant));
        circuit_set_hash(&entries)?;
        Ok(entries)
    }
}

pub fn circuit_set_entry(family: u16, level: u8, variant: u8, expected_pi_words: usize,
    data: &CircuitData<F, C, 2>, identity_fingerprint: [u64; 4]) -> anyhow::Result<CircuitSetEntry>
{
    anyhow::ensure!(data.common.num_public_inputs == expected_pi_words, "family {family} level {level} variant {variant} PI width mismatch");
    let fingerprint = get_circuit_fingerprint_generic_q::<2, F, C>(&data.verifier_only).to_u64x4();
    anyhow::ensure!(fingerprint != [0; 4], "missing source circuit pin");
    anyhow::ensure!((family == 4) == (identity_fingerprint != [0; 4]), "invalid source authorization identity pin");
    Ok(CircuitSetEntry { family, level, variant, pi_words: expected_pi_words.try_into()?, fingerprint,
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
