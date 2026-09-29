use std::collections::BTreeMap;

use parth_core::{crypto::hash::traits::ToU64x4, protocol::core_types::QNetworkCircuitConstants};
use plonky2::{field::goldilocks_field::GoldilocksField as F, plonk::{circuit_data::CircuitData, config::PoseidonGoldilocksConfig as C, proof::ProofWithPublicInputs}};
use psy_client_data::bridge_aggregate::{circuit_set_hash, AOpening, BOpening, CircuitSetEntry, NetworkConfig};
use psy_common_circuit::serialization::PsyGateSerializer;
use psy_plonky2_common_circuits::bridge::{deposit_spiderman_append::DepositSpidermanAppendCircuit, withdrawal_inclusion::WithdrawalInclusionCircuit};
use tiny_keccak::{Hasher, Keccak};

use crate::{coordinator::coordinator_helper::QEDCoordinatorCircuitManager, proof_minifier::pm_core::get_circuit_fingerprint_generic_q, qstandard::QStandardCircuit};
use super::circuits::{batch_reduction::BatchReductionCircuit, bridge_agg_final::BridgeAggFinalCircuit, chain_aggregate::ChainBaseCircuits, chain_reduction::ChainReductionCircuit, checkpoint_aggregate::{CheckpointAggregateCircuit, CheckpointCircuitSet}, checkpoint_end::CheckpointEndCircuit, checkpoint_identity::CheckpointIdentityCircuit, checkpoint_range::CheckpointRangeCircuit, deposit_aggregate::{BatchCircuitSet, DepositAggregateCircuit}, record_batch::{RecordBatchCircuits, RecordBatchSource}, reward_inclusion::RewardInclusionCircuit};

pub struct AggregateCircuitHeights {
    pub deposit_state_tree: usize,
    pub withdrawal_state_tree: usize,
}

/// One source-owned graph. Configuration values remain witnesses; only its chain count is fixed.
/// Public circuit objects expose their native typed witness/prove APIs, not a caller-selected VK.
pub struct AggregateCircuits {
    source_chain_count: usize,
    pub deposit: DepositSpidermanAppendCircuit<C, 2>,
    pub withdrawal: WithdrawalInclusionCircuit<C, 2>,
    pub reward: RewardInclusionCircuit,
    pub checkpoint_final: BridgeAggFinalCircuit<C, 2>,
    pub checkpoint_positive: CheckpointRangeCircuit<C, 2>,
    pub checkpoint_identity: CheckpointIdentityCircuit<C, 2>,
    pub checkpoint_end: CheckpointEndCircuit<C, 2>,
    pub batches: [RecordBatchCircuits<C, 2>; 3],
    pub batch_levels: [Vec<BatchReductionCircuit<C, 2>>; 3],
    pub chains: [ChainBaseCircuits<C, 2>; 2],
    pub chain_levels: [Vec<ChainReductionCircuit<C, 2>>; 2],
    pub deposit_aggregate: DepositAggregateCircuit<C, 2>,
    pub checkpoint_aggregate: CheckpointAggregateCircuit<C, 2>,
    entries: Vec<CircuitSetEntry>,
    circuit_set_hash: [u8; 32],
}

impl AggregateCircuits {
    /// The coordinator is the actual source manager, never an arbitrary verifier triplet.
    /// Build it for the approved network before constructing this graph; no cache is generated here.
    pub fn build<N: QNetworkCircuitConstants>(source_chain_count: usize, coordinator: &QEDCoordinatorCircuitManager<C, 2>, heights: AggregateCircuitHeights) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=256).contains(&source_chain_count), "source chain count must be 1..256");
        let checkpoint = &coordinator.checkpoint_root_transition;
        let checkpoint_fingerprint = checkpoint.get_fingerprint();
        anyhow::ensure!(checkpoint_fingerprint.to_u64x4() != [0; 4], "missing source checkpoint pin");
        // register_into_library uses this exact manager fingerprint for the step-commit pin.
        let checkpoint_final = BridgeAggFinalCircuit::prebuild_final_circuit(
            checkpoint.get_common_circuit_data_ref(),
            checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(),
            checkpoint_fingerprint, checkpoint_fingerprint,
            N::CHECKPOINT_TREE_HEIGHT_USIZE, N::GLOBAL_USER_TREE_HEIGHT_USIZE,
            N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE, heights.deposit_state_tree,
            heights.withdrawal_state_tree,
        );
        let (checkpoint_positive, checkpoint_identity) = build_checkpoints(&checkpoint_final, N::CHECKPOINT_TREE_HEIGHT_USIZE)?;
        let checkpoint_end = CheckpointEndCircuit::new(source_chain_count, N::CHECKPOINT_TREE_HEIGHT_USIZE,
            N::GLOBAL_USER_TREE_HEIGHT_USIZE, N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
            heights.deposit_state_tree, heights.withdrawal_state_tree);
        let deposit = DepositSpidermanAppendCircuit::build();
        let withdrawal = WithdrawalInclusionCircuit::build();
        let reward = RewardInclusionCircuit::new(source_chain_count)?;
        let batches = [
            RecordBatchCircuits::build(RecordBatchSource::Deposit)?,
            RecordBatchCircuits::build(RecordBatchSource::Withdrawal { circuit: &withdrawal.circuit_data, chain_count: source_chain_count })?,
            RecordBatchCircuits::build(RecordBatchSource::Reward { circuit: &reward.circuit_data })?,
        ];
        let mut batch_levels: [Vec<BatchReductionCircuit<C, 2>>; 3] = std::array::from_fn(|_| Vec::with_capacity(5));
        for (base, levels) in batches.iter().zip(&mut batch_levels) {
            ensure_common(&base.real.circuit_data, &base.empty.circuit_data)?;
            levels.push(BatchReductionCircuit::build_base(base)?);
            for _ in 1..5 { levels.push(BatchReductionCircuit::build_next(levels.last().unwrap())?); }
        }
        let chains = [ChainBaseCircuits::build_a(source_chain_count, &deposit)?, ChainBaseCircuits::build_b(source_chain_count)?];
        let root_level = source_chain_count.next_power_of_two().trailing_zeros() as usize;
        let mut chain_levels: [Vec<ChainReductionCircuit<C, 2>>; 2] = std::array::from_fn(|_| Vec::with_capacity(root_level));
        for (base, levels) in chains.iter().zip(&mut chain_levels) {
            ensure_common(&base.real.circuit_data, &base.empty.circuit_data)?;
            if root_level > 0 {
                levels.push(ChainReductionCircuit::build_base(base)?);
                for _ in 2..=root_level { levels.push(ChainReductionCircuit::build_next(levels.last().unwrap())?); }
            }
        }
        let chain_root = |variant: usize| if root_level == 0 { &chains[variant].real.circuit_data } else { &chain_levels[variant][root_level - 1].circuit_data };
        let deposit_aggregate = DepositAggregateCircuit::new(source_chain_count, batch_set(&batches[0], &batch_levels[0]), chain_root(0));
        let checkpoint_aggregate = CheckpointAggregateCircuit::new(source_chain_count,
            batch_set(&batches[1], &batch_levels[1]), batch_set(&batches[2], &batch_levels[2]), chain_root(1),
            CheckpointCircuitSet { positive: &checkpoint_positive.circuit_data, identity: &checkpoint_identity.circuit_data, end: &checkpoint_end.circuit_data });
        let mut bundle = Self { source_chain_count, deposit, withdrawal, reward, checkpoint_final, checkpoint_positive,
            checkpoint_identity, checkpoint_end, batches, batch_levels, chains, chain_levels, deposit_aggregate,
            checkpoint_aggregate, entries: Vec::new(), circuit_set_hash: [0; 32] };
        bundle.entries = bundle.build_entries()?;
        bundle.circuit_set_hash = circuit_set_hash(&bundle.entries)?;
        Ok(bundle)
    }

    pub fn entries(&self) -> &[CircuitSetEntry] { &self.entries }
    pub fn circuit_set_hash(&self) -> [u8; 32] { self.circuit_set_hash }

    /// Compare a frozen artifact registry against all actual source fingerprints and serialized pins.
    pub fn validate_entries(&self, expected: &[CircuitSetEntry]) -> anyhow::Result<()> {
        circuit_set_hash(expected)?;
        anyhow::ensure!(self.build_entries()? == expected, "circuit registry differs from the complete source graph");
        Ok(())
    }

    pub fn validate_config(&self, config: &NetworkConfig) -> anyhow::Result<()> {
        config.validate()?;
        anyhow::ensure!(config.chains.len() == self.source_chain_count, "configuration chain count differs from source graph");
        anyhow::ensure!(config.circuit_set_hash == self.circuit_set_hash, "configuration circuit-set pin differs from source graph");
        Ok(())
    }

    pub fn prove_a(&self, config: &NetworkConfig, opening: &AOpening, batch: &ProofWithPublicInputs<F, C, 2>, chain: &ProofWithPublicInputs<F, C, 2>) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.validate_config(config)?;
        self.deposit_aggregate.prove(config, opening, batch, chain)
    }

    pub fn prove_b(&self, config: &NetworkConfig, opening: &BOpening, withdrawal: &ProofWithPublicInputs<F, C, 2>, reward: &ProofWithPublicInputs<F, C, 2>, chain: &ProofWithPublicInputs<F, C, 2>, end: &ProofWithPublicInputs<F, C, 2>, ranges: &[ProofWithPublicInputs<F, C, 2>]) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.validate_config(config)?;
        self.checkpoint_aggregate.prove(config, opening, withdrawal, reward, chain, end, ranges)
    }

    /// Transfer the real family11 data to the two wrapper builders after native proving.
    pub fn into_normalizers(self) -> (CircuitData<F, C, 2>, CircuitData<F, C, 2>) {
        (self.deposit_aggregate.circuit_data, self.checkpoint_aggregate.circuit_data)
    }

    fn build_entries(&self) -> anyhow::Result<Vec<CircuitSetEntry>> {
        let mut entries = self.reward.circuit_set_entries()?;
        let mut add = |family, level, variant, width, data: &CircuitData<F, C, 2>, identity| -> anyhow::Result<()> {
            entries.push(circuit_set_entry(family, level, variant, width, data, identity)?);
            Ok(())
        };
        add(1, 0, 0, 40, &self.deposit.circuit_data, [0; 4])?;
        add(2, 0, 0, 32, &self.withdrawal.circuit_data, [0; 4])?;
        ensure_common(&self.checkpoint_positive.circuit_data, &self.checkpoint_identity.circuit_data)?;
        add(5, 0, 0, 28, &self.checkpoint_positive.circuit_data, [0; 4])?;
        add(5, 0, 1, 28, &self.checkpoint_identity.circuit_data, [0; 4])?;
        add(6, 0, 0, 30, &self.checkpoint_end.circuit_data, [0; 4])?;
        for (index, base) in self.batches.iter().enumerate() {
            ensure_common(&base.real.circuit_data, &base.empty.circuit_data)?;
            add(7, 0, index as u8 + 1, 38, &base.real.circuit_data, [0; 4])?;
            add(7, 0, index as u8 + 129, 38, &base.empty.circuit_data, [0; 4])?;
            for level in &self.batch_levels[index] { add(8, level.level, index as u8 + 1, 38, &level.circuit_data, [0; 4])?; }
        }
        for (index, base) in self.chains.iter().enumerate() {
            ensure_common(&base.real.circuit_data, &base.empty.circuit_data)?;
            add(9, 0, index as u8 + 1, 37, &base.real.circuit_data, [0; 4])?;
            add(9, 0, index as u8 + 129, 37, &base.empty.circuit_data, [0; 4])?;
            for level in &self.chain_levels[index] { add(10, level.level, index as u8 + 1, 37, &level.circuit_data, [0; 4])?; }
        }
        add(11, 0, 1, 12, &self.deposit_aggregate.circuit_data, [0; 4])?;
        add(11, 0, 2, 12, &self.checkpoint_aggregate.circuit_data, [0; 4])?;
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
        common_digest: digest(&common_bytes(data)?),
        verifier_digest: digest(&data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?),
        identity_fingerprint })
}

fn batch_set<'a>(base: &'a RecordBatchCircuits<C, 2>, levels: &'a [BatchReductionCircuit<C, 2>]) -> BatchCircuitSet<'a, C, 2> {
    BatchCircuitSet { real: std::array::from_fn(|level| if level == 0 { &base.real.circuit_data } else { &levels[level - 1].circuit_data }), empty: &base.empty.circuit_data }
}

fn common_bytes(data: &CircuitData<F, C, 2>) -> anyhow::Result<Vec<u8>> {
    data.common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))
}

fn ensure_common(left: &CircuitData<F, C, 2>, right: &CircuitData<F, C, 2>) -> anyhow::Result<()> {
    anyhow::ensure!(left.common == right.common && common_bytes(left)? == common_bytes(right)?, "selectable source common data must be byte-identical");
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut result = [0; 32];
    hasher.finalize(&mut result);
    result
}

fn build_checkpoints(final_circuit: &BridgeAggFinalCircuit<C, 2>, height: usize) -> anyhow::Result<(CheckpointRangeCircuit<C, 2>, CheckpointIdentityCircuit<C, 2>)> {
    let mut positive = CheckpointRangeCircuit::new(final_circuit, height, &[], None);
    let mut identity = CheckpointIdentityCircuit::new(height, &[], None);
    let mut gates = BTreeMap::new();
    let mut degree = 0;
    for _ in 0..8 {
        for data in [&positive.circuit_data, &identity.circuit_data] {
            degree = degree.max(data.common.degree());
            for gate in &data.common.gates { gates.insert(gate.0.id(), gate.clone()); }
        }
        let union: Vec<_> = gates.values().cloned().collect();
        positive = CheckpointRangeCircuit::new(final_circuit, height, &union, Some(degree));
        identity = CheckpointIdentityCircuit::new(height, &union, Some(degree));
        if positive.circuit_data.common == identity.circuit_data.common {
            ensure_common(&positive.circuit_data, &identity.circuit_data)?;
            return Ok((positive, identity));
        }
    }
    anyhow::bail!("checkpoint common-data harmonization did not converge in eight rebuilds")
}
