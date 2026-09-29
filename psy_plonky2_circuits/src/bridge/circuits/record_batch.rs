use std::collections::BTreeMap;

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, Field64}},
    gates::{gate::GateRef, noop::NoopGate},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{Bytes32, ChainEnd, DepositLeaf, Hash4, NetworkConfig, RewardLeaf, WithdrawalLeaf};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::bridge::{aggregate_commitment::{self as hash, Bytes32Target, ChainEndTarget, DepositLeafTarget, RecordTarget, RewardLeafTarget, WithdrawalLeafTarget}, aggregate_config::NetworkConfigTarget};

type F = GoldilocksField;
pub const BATCH_PI_LEN: usize = 38;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BatchFamily { Deposit = 1, Withdrawal = 2, Reward = 3 }

pub enum RecordBatchSource<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    Deposit,
    Withdrawal { circuit: &'a CircuitData<F, C, D>, chain_count: usize },
    Reward { circuit: &'a CircuitData<F, C, D> },
}

impl<C: GenericConfig<D, F = F>, const D: usize> RecordBatchSource<'_, C, D>
where F: Extendable<D> {
    fn family(&self) -> BatchFamily {
        match self { Self::Deposit => BatchFamily::Deposit, Self::Withdrawal { .. } => BatchFamily::Withdrawal, Self::Reward { .. } => BatchFamily::Reward }
    }
    fn circuit(&self) -> Option<&CircuitData<F, C, D>> {
        match self { Self::Deposit => None, Self::Withdrawal { circuit, .. } | Self::Reward { circuit } => Some(circuit) }
    }
}

#[derive(Clone, Debug)]
pub struct BatchContext {
    pub config_hash: Bytes32,
    pub end_id: u64,
    pub end_root: Hash4,
    pub chain_ends_hash: Bytes32,
}

#[derive(Clone, Debug)]
pub struct WithdrawalEndWitness {
    pub ordinal: u8,
    pub end: ChainEnd,
    pub siblings: [Bytes32; 8],
}

pub struct WithdrawalBatchRecord<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub record: &'a WithdrawalLeaf,
    pub proof: &'a ProofWithPublicInputs<F, C, D>,
    pub end: &'a WithdrawalEndWitness,
}

pub struct RewardBatchRecord<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub record: &'a RewardLeaf,
    pub proof: &'a ProofWithPublicInputs<F, C, D>,
}

pub enum BatchRecords<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    Deposit(&'a [DepositLeaf]),
    Withdrawal { config: &'a NetworkConfig, records: &'a [WithdrawalBatchRecord<'a, C, D>] },
    Reward(&'a [RewardBatchRecord<'a, C, D>]),
}

impl<C: GenericConfig<D, F = F>, const D: usize> BatchRecords<'_, C, D>
where F: Extendable<D> {
    fn family(&self) -> BatchFamily {
        match self { Self::Deposit(_) => BatchFamily::Deposit, Self::Withdrawal { .. } => BatchFamily::Withdrawal, Self::Reward(_) => BatchFamily::Reward }
    }
    fn len(&self) -> usize {
        match self { Self::Deposit(records) => records.len(), Self::Withdrawal { records, .. } => records.len(), Self::Reward(records) => records.len() }
    }
}

#[derive(Clone, Copy)]
pub struct BatchStatementTarget {
    pub config_hash: Bytes32Target,
    pub end_id: [Target; 2],
    pub end_root: [Target; 4],
    pub first_chunk: Target,
    pub real_chunks: Target,
    pub first_record: Target,
    pub real_records: Target,
    pub subtree_root: Bytes32Target,
    pub chain_ends_hash: Bytes32Target,
}

impl BatchStatementTarget {
    pub fn from_public_inputs(pi: &[Target]) -> Self {
        assert_eq!(pi.len(), BATCH_PI_LEN);
        Self { config_hash: pi[4..12].try_into().unwrap(), end_id: pi[12..14].try_into().unwrap(), end_root: pi[14..18].try_into().unwrap(), first_chunk: pi[18], real_chunks: pi[19], first_record: pi[20], real_records: pi[21], subtree_root: pi[22..30].try_into().unwrap(), chain_ends_hash: pi[30..38].try_into().unwrap() }
    }

    pub(crate) fn register<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, family: u8, variant: u8, level: u8)
    where F: Extendable<D> {
        for value in [1, family, variant, level] {
            let target = builder.constant(F::from_canonical_u8(value));
            builder.register_public_input(target);
        }
        builder.register_public_inputs(&self.config_hash);
        builder.register_public_inputs(&self.end_id);
        builder.register_public_inputs(&self.end_root);
        builder.register_public_inputs(&[self.first_chunk, self.real_chunks, self.first_record, self.real_records]);
        builder.register_public_inputs(&self.subtree_root);
        builder.register_public_inputs(&self.chain_ends_hash);
    }
}

struct WithdrawalEndTarget {
    ordinal: Target,
    end: ChainEndTarget,
    siblings: [Bytes32Target; 8],
}

pub struct RecordBatchCircuit<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub family: BatchFamily,
    pub empty: bool,
    pub statement: BatchStatementTarget,
    pub circuit_data: CircuitData<F, C, D>,
    record_words: Vec<Vec<Target>>,
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
    ends: Vec<WithdrawalEndTarget>,
    config: Option<NetworkConfigTarget>,
    dummy: Option<CircuitData<F, C, D>>,
}

pub struct RecordBatchCircuits<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub real: RecordBatchCircuit<C, D>,
    pub empty: RecordBatchCircuit<C, D>,
}

impl<C: GenericConfig<D, F = F>, const D: usize> RecordBatchCircuits<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn build(source: RecordBatchSource<'_, C, D>) -> anyhow::Result<Self> {
        let mut gates = BTreeMap::<String, GateRef<F, D>>::new();
        let mut pair = Self {
            real: RecordBatchCircuit::build(&source, false, &[], 0),
            empty: RecordBatchCircuit::build(&source, true, &[], 0),
        };
        let mut degree = pair.real.circuit_data.common.degree_bits().max(pair.empty.circuit_data.common.degree_bits());
        loop {
            for member in [&pair.real, &pair.empty] {
                for gate in &member.circuit_data.common.gates { gates.insert(gate.0.id(), gate.clone()); }
            }
            let union: Vec<_> = gates.values().cloned().collect();
            pair = Self {
                real: RecordBatchCircuit::build(&source, false, &union, degree),
                empty: RecordBatchCircuit::build(&source, true, &union, degree),
            };
            let next = pair.real.circuit_data.common.degree_bits().max(pair.empty.circuit_data.common.degree_bits());
            if next > degree { degree = next; continue; }
            anyhow::ensure!(pair.real.circuit_data.common == pair.empty.circuit_data.common, "batch real/empty common data disagree after gate/degree harmonization");
            return Ok(pair);
        }
    }
}

pub(crate) fn connect_if<const D: usize>(builder: &mut CircuitBuilder<F, D>, active: BoolTarget, left: Target, right: Target)
where F: Extendable<D> {
    let delta = builder.sub(left, right);
    let checked = builder.mul(active.target, delta);
    builder.assert_zero(checked);
}

pub(crate) fn connect_context<const D: usize>(builder: &mut CircuitBuilder<F, D>, left: &BatchStatementTarget, right: &BatchStatementTarget)
where F: Extendable<D> {
    for (a, b) in left.config_hash.iter().chain(&left.end_id).chain(&left.end_root).chain(&left.chain_ends_hash)
        .zip(right.config_hash.iter().chain(&right.end_id).chain(&right.end_root).chain(&right.chain_ends_hash)) { builder.connect(*a, *b); }
}

fn less_words<const D: usize>(builder: &mut CircuitBuilder<F, D>, left: &[Target], right: &[Target]) -> BoolTarget
where F: Extendable<D> {
    let mut equal = builder._true();
    let mut less = builder._false();
    for (&a, &b) in left.iter().zip(right) {
        let digit_less = builder.is_less_than(32, a, b);
        let first_less = builder.and(equal, digit_less);
        less = builder.or(less, first_less);
        let digit_equal = builder.is_equal(a, b);
        equal = builder.and(equal, digit_equal);
    }
    less
}

fn record_target<const D: usize>(builder: &mut CircuitBuilder<F, D>, family: BatchFamily) -> RecordTarget
where F: Extendable<D> {
    match family {
        BatchFamily::Deposit => RecordTarget::Deposit(DepositLeafTarget {
            chain_index: builder.add_virtual_target(), absolute_index: builder.add_virtual_target(), shield_address: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), l2_token_contract_id: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), note_commitment: builder.add_virtual_target_arr(),
        }),
        BatchFamily::Withdrawal => RecordTarget::Withdrawal(WithdrawalLeafTarget {
            chain_index: builder.add_virtual_target(), sender_user_id: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), nonce: builder.add_virtual_target_arr(),
        }),
        BatchFamily::Reward => RecordTarget::Reward(RewardLeafTarget {
            claim_checkpoint_id: builder.add_virtual_target_arr(), user_id: builder.add_virtual_target(), height: builder.add_virtual_target(), path_index: builder.add_virtual_target(), nullifier_index: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr(),
        }),
    }
}

fn record_key(record: RecordTarget) -> Vec<Target> {
    match record {
        RecordTarget::Deposit(record) => vec![record.chain_index, record.absolute_index],
        RecordTarget::Withdrawal(record) => { let mut key = vec![record.chain_index]; key.extend(record.nonce); key },
        RecordTarget::Reward(record) => vec![record.claim_checkpoint_id[1], record.claim_checkpoint_id[0], record.nullifier_index],
    }
}

impl<C: GenericConfig<D, F = F>, const D: usize> RecordBatchCircuit<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    fn build(source: &RecordBatchSource<'_, C, D>, empty: bool, gates: &[GateRef<F, D>], degree: usize) -> Self {
        let family = source.family();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        for gate in gates { builder.add_gate_to_gate_set(gate.clone()); }
        let zero = builder.zero();
        let one = builder.one();
        let config_hash = builder.add_virtual_target_arr();
        let end_id = builder.add_virtual_target_arr();
        let end_root = builder.add_virtual_target_arr();
        let chain_ends_hash = builder.add_virtual_target_arr();
        for &word in config_hash.iter().chain(&end_id).chain(&chain_ends_hash) { builder.range_check(word, 32); }
        hash::encode_hash4(&mut builder, end_root);
        if family != BatchFamily::Withdrawal { for word in chain_ends_hash { builder.assert_zero(word); } }
        let first_chunk = builder.add_virtual_target();
        builder.range_check(first_chunk, 5);
        let first_record = builder.add_virtual_target();
        builder.range_check(first_record, 11);
        let position = builder.mul_const(F::from_canonical_u32(32), first_chunk);
        let real_records = if empty { zero } else { builder.add_virtual_target() };
        let real_chunks = if empty { zero } else { one };
        if empty { builder.ensure_is_less_than_or_equal(11, first_record, position); }
        else { builder.connect(first_record, position); }
        let config = if !empty {
            if let RecordBatchSource::Withdrawal { chain_count, .. } = source {
                let config = NetworkConfigTarget::new(&mut builder, *chain_count);
                let digest = config.hash(&mut builder);
                for i in 0..8 { builder.connect(digest[i], config_hash[i]); }
                Some(config)
            } else { None }
        } else { None };
        let mut records = Vec::new();
        let mut record_words = Vec::new();
        let mut proofs = Vec::new();
        let mut ends = Vec::new();
        let dummy = if empty { None } else { source.circuit().map(|circuit| dummy_circuit::<F, C, D>(&circuit.common)) };
        let real_vk = if empty { None } else { source.circuit().map(|circuit| builder.constant_verifier_data(&circuit.verifier_only)) };
        let dummy_vk = dummy.as_ref().map(|circuit| builder.constant_verifier_data(&circuit.verifier_only));
        if !empty {
            builder.range_check(real_records, 6);
            let maximum = builder.constant(F::from_canonical_u8(32));
            builder.ensure_is_less_than_or_equal(6, real_records, maximum);
            let is_empty = builder.is_equal(real_records, zero);
            builder.assert_zero(is_empty.target);
            for i in 0..32 {
                let slot = builder.constant(F::from_canonical_usize(i));
                let active = builder.is_less_than(6, slot, real_records);
                let inactive = builder.not(active);
                let record = record_target(&mut builder, family);
                let words = record.encode(&mut builder);
                for &word in &words { connect_if(&mut builder, inactive, word, zero); }
                if let Some(previous) = records.last() {
                    let increasing = less_words(&mut builder, &record_key(*previous), &record_key(record));
                    connect_if(&mut builder, active, increasing.target, one);
                }
                if let Some(child) = source.circuit() {
                    let expected_pi = if family == BatchFamily::Withdrawal { 32 } else { 28 };
                    assert_eq!(child.common.num_public_inputs, expected_pi);
                    let proof = builder.add_virtual_proof_with_pis(&child.common);
                    builder.conditionally_verify_proof::<C>(active, &proof, real_vk.as_ref().unwrap(), &proof, dummy_vk.as_ref().unwrap(), &child.common);
                    let pi = &proof.public_inputs;
                    for &word in pi { connect_if(&mut builder, inactive, word, zero); }
                    for (target, value) in pi[..4].iter().zip([1, family as u8, 0, 0]) {
                        let expected = builder.constant(F::from_canonical_u8(value));
                        connect_if(&mut builder, active, *target, expected);
                    }
                    for (a, b) in pi[4..18].iter().zip(config_hash.iter().chain(&end_id).chain(&end_root)) { connect_if(&mut builder, active, *a, *b); }
                    let commit = record.record_commit(&mut builder);
                    let commit_start = if family == BatchFamily::Withdrawal { 24 } else { 18 };
                    for j in 0..8 { connect_if(&mut builder, active, pi[commit_start + j], commit[j]); }
                    match record {
                        RecordTarget::Withdrawal(record) => {
                            let config = config.as_ref().unwrap();
                            connect_if(&mut builder, active, pi[18], config.bridge_user_id);
                            connect_if(&mut builder, active, pi[19], record.chain_index);
                            let ordinal = builder.add_virtual_target();
                            let end = ChainEndTarget { chain_index: builder.add_virtual_target(), deposit_root: builder.add_virtual_target_arr(), deposit_count: builder.add_virtual_target(), withdrawal_root: builder.add_virtual_target_arr() };
                            let siblings: [Bytes32Target; 8] = std::array::from_fn(|_| builder.add_virtual_target_arr());
                            let bits = builder.split_le(ordinal, 8);
                            // Zero is a valid configured ordinal even for an inactive slot; only the root join is conditional.
                            let mut root = hash::chain_end_leaf(&mut builder, config.chains.len(), ordinal, &end);
                            let mut configured_index = zero;
                            for (j, chain) in config.chains.iter().enumerate() {
                                let j = builder.constant(F::from_canonical_usize(j));
                                let selected = builder.is_equal(ordinal, j);
                                configured_index = builder.mul_add(selected.target, chain.chain_index, configured_index);
                            }
                            connect_if(&mut builder, active, end.chain_index, configured_index);
                            connect_if(&mut builder, active, end.chain_index, record.chain_index);
                            for j in 0..4 { connect_if(&mut builder, active, pi[20 + j], end.withdrawal_root[j]); }
                            for level in 0..8 {
                                let sibling = siblings[level];
                                for word in sibling { builder.range_check(word, 32); connect_if(&mut builder, inactive, word, zero); }
                                let left = std::array::from_fn(|j| builder.select(bits[level], sibling[j], root[j]));
                                let right = std::array::from_fn(|j| builder.select(bits[level], root[j], sibling[j]));
                                root = hash::chain_end_node(&mut builder, level as u8 + 1, left, right);
                            }
                            for j in 0..8 { connect_if(&mut builder, active, root[j], chain_ends_hash[j]); }
                            for target in [ordinal, end.chain_index, end.deposit_count].iter().chain(&end.deposit_root).chain(&end.withdrawal_root) { connect_if(&mut builder, inactive, *target, zero); }
                            ends.push(WithdrawalEndTarget { ordinal, end, siblings });
                        }
                        RecordTarget::Reward(record) => {
                            for j in 0..2 { connect_if(&mut builder, active, pi[26 + j], record.claim_checkpoint_id[j]); }
                        }
                        RecordTarget::Deposit(_) => unreachable!(),
                    }
                    proofs.push(proof);
                }
                records.push(record);
                record_words.push(words);
            }
        }
        let subtree_root = if empty { hash::batch_empty(&mut builder, family as u32, first_chunk) }
        else {
            let batch = hash::batch_commit(&mut builder, config_hash, end_id, end_root, first_chunk, &records, real_records);
            hash::batch_leaf(&mut builder, family as u32, first_chunk, batch)
        };
        let statement = BatchStatementTarget { config_hash, end_id, end_root, first_chunk, real_chunks, first_record, real_records, subtree_root, chain_ends_hash };
        statement.register(&mut builder, 7, family as u8 | if empty { 128 } else { 0 }, 0);
        if degree > 0 {
            let before_build = (1usize << (degree - 1)) + 1;
            while builder.num_gates() < before_build { builder.add_gate(NoopGate, vec![]); }
        }
        let circuit_data = builder.build::<C>();
        Self { family, empty, statement, circuit_data, record_words, proofs, ends, config, dummy }
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<F>, context: &BatchContext, first_chunk: u32, first_record: u32, records: Option<&BatchRecords<'_, C, D>>) -> anyhow::Result<()> {
        anyhow::ensure!(self.empty == records.is_none(), "canonical empty base has no records or user proofs");
        set_bytes(witness, &self.statement.config_hash, &context.config_hash)?;
        set_u64(witness, self.statement.end_id, context.end_id)?;
        set_hash4(witness, self.statement.end_root, context.end_root)?;
        set_bytes(witness, &self.statement.chain_ends_hash, &context.chain_ends_hash)?;
        witness.set_target(self.statement.first_chunk, F::from_canonical_u32(first_chunk))?;
        witness.set_target(self.statement.first_record, F::from_canonical_u32(first_record))?;
        let Some(records) = records else { return Ok(()); };
        anyhow::ensure!(records.family() == self.family && (1..=32).contains(&records.len()), "batch record family/count mismatch");
        witness.set_target(self.statement.real_records, F::from_canonical_usize(records.len()))?;
        if let BatchRecords::Withdrawal { config, .. } = records { self.config.as_ref().unwrap().set_witness(witness, config)?; }
        let dummy = self.dummy.as_ref().map(|circuit| dummy_proof(circuit, Default::default())).transpose()?;
        for i in 0..32 {
            if i < records.len() {
                let bytes = match records {
                    BatchRecords::Deposit(records) => records[i].encode()?,
                    BatchRecords::Withdrawal { records, .. } => records[i].record.encode()?,
                    BatchRecords::Reward(records) => records[i].record.encode()?,
                };
                set_bytes(witness, &self.record_words[i], &bytes)?;
                match records {
                    BatchRecords::Withdrawal { records, .. } => {
                        witness.set_proof_with_pis_target(&self.proofs[i], records[i].proof)?;
                        self.ends[i].set_witness(witness, Some(records[i].end))?;
                    }
                    BatchRecords::Reward(records) => witness.set_proof_with_pis_target(&self.proofs[i], records[i].proof)?,
                    BatchRecords::Deposit(_) => {},
                }
            } else {
                for &word in &self.record_words[i] { witness.set_target(word, F::ZERO)?; }
                if let Some(dummy) = &dummy { witness.set_proof_with_pis_target(&self.proofs[i], dummy)?; }
                if self.family == BatchFamily::Withdrawal { self.ends[i].set_witness(witness, None)?; }
            }
        }
        Ok(())
    }

    pub fn prove(&self, context: &BatchContext, first_chunk: u32, first_record: u32, records: Option<&BatchRecords<'_, C, D>>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, context, first_chunk, first_record, records)?;
        self.circuit_data.prove(witness)
    }
}

impl WithdrawalEndTarget {
    fn set_witness(&self, witness: &mut PartialWitness<F>, input: Option<&WithdrawalEndWitness>) -> anyhow::Result<()> {
        let empty = WithdrawalEndWitness { ordinal: 0, end: ChainEnd { chain_index: 0, deposit_root: [0; 4], deposit_count: 0, withdrawal_root: [0; 4] }, siblings: [[0; 32]; 8] };
        let input = input.unwrap_or(&empty);
        witness.set_target(self.ordinal, F::from_canonical_u8(input.ordinal))?;
        witness.set_target(self.end.chain_index, F::from_canonical_u8(input.end.chain_index))?;
        witness.set_target(self.end.deposit_count, F::from_canonical_u32(input.end.deposit_count))?;
        set_hash4(witness, self.end.deposit_root, input.end.deposit_root)?;
        set_hash4(witness, self.end.withdrawal_root, input.end.withdrawal_root)?;
        for (targets, bytes) in self.siblings.iter().zip(input.siblings) { set_bytes(witness, targets, &bytes)?; }
        Ok(())
    }
}

pub(crate) fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() == targets.len() * 4, "byte/target width mismatch");
    for (&target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) { witness.set_target(target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap())))?; }
    Ok(())
}
fn set_u64(witness: &mut PartialWitness<F>, targets: [Target; 2], value: u64) -> anyhow::Result<()> {
    witness.set_target(targets[0], F::from_canonical_u32(value as u32))?;
    witness.set_target(targets[1], F::from_canonical_u32((value >> 32) as u32))
}
fn set_hash4(witness: &mut PartialWitness<F>, targets: [Target; 4], value: Hash4) -> anyhow::Result<()> {
    for (target, value) in targets.into_iter().zip(value) {
        anyhow::ensure!(value < F::ORDER, "noncanonical Hash4");
        witness.set_target(target, F::from_canonical_u64(value))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use plonky2::{field::types::PrimeField64, hash::poseidon::PoseidonHash, plonk::config::{Hasher, PoseidonGoldilocksConfig}};
    use psy_client_data::bridge_aggregate::{domain_hash, ChainConfig, Domain};
    use psy_plonky2_common_circuits::bridge::withdrawal_inclusion::{WithdrawalInclusionCircuit, WithdrawalInclusionInputs, WithdrawalWitness};
    use tiny_keccak::{Hasher as KeccakHasher, Keccak};

    pub(crate) type C = PoseidonGoldilocksConfig;

    pub(crate) fn rejected(run: impl FnOnce() -> anyhow::Result<()> ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        assert!(result.map_or(true, |result| result.is_err()));
    }

    pub(crate) fn digest(bytes: &[u8]) -> Bytes32 {
        let mut hash = Keccak::v256();
        hash.update(bytes);
        let mut result = [0; 32];
        hash.finalize(&mut result);
        result
    }

    pub(crate) fn word(value: u64) -> Bytes32 {
        let mut word = [0; 32];
        word[24..].copy_from_slice(&value.to_be_bytes());
        word
    }

    pub(crate) fn pi_digest(pi: &[F]) -> Bytes32 {
        let mut result = [0; 32];
        for (bytes, value) in result.chunks_exact_mut(4).zip(pi) { bytes.copy_from_slice(&(value.to_canonical_u64() as u32).to_be_bytes()); }
        result
    }

    pub(crate) fn context() -> BatchContext {
        BatchContext { config_hash: [0x23; 32], end_id: (1 << 32) + 51, end_root: [7, 8, 9, 10], chain_ends_hash: [0; 32] }
    }

    pub(crate) fn deposit(index: u32) -> DepositLeaf {
        DepositLeaf { chain_index: 7, absolute_index: index, shield_address: [1; 32], token: [2; 20], l2_token_contract_id: [3; 32], amount: word(10), note_commitment: [4; 32] }
    }

    #[test]
    fn deposit_batch_matches_native_and_rejects_order_count_and_padding() {
        let bases = RecordBatchCircuits::<C, 2>::build(RecordBatchSource::Deposit).unwrap();
        assert_eq!(bases.real.circuit_data.common, bases.empty.circuit_data.common);
        let context = context();
        let records = [deposit(4), deposit(5)];
        let input = BatchRecords::Deposit(&records);
        let proof = bases.real.prove(&context, 0, 0, Some(&input)).unwrap();
        let mut body = domain_hash(Domain::Batch).to_vec();
        body.extend(context.config_hash);
        body.extend(word(context.end_id));
        for limb in context.end_root { body.extend(word(limb)); }
        for value in [1, 0, 0, 2] { body.extend(word(value)); }
        for record in &records { body.extend(record.encode().unwrap()); }
        let mut leaf = domain_hash(Domain::Leaf).to_vec();
        leaf.extend(word(1)); leaf.extend(word(0)); leaf.extend(digest(&body));
        assert_eq!(pi_digest(&proof.public_inputs[22..30]), digest(&leaf));
        bases.real.circuit_data.verify(proof).unwrap();
        let empty = bases.empty.prove(&context, 1, 2, None).unwrap();
        let mut expected = domain_hash(Domain::Empty).to_vec();
        expected.extend(word(1)); expected.extend(word(1));
        assert_eq!(pi_digest(&empty.public_inputs[22..30]), digest(&expected));
        assert_eq!(empty.public_inputs[2], F::from_canonical_u8(129));
        bases.empty.circuit_data.verify(empty).unwrap();
        let reversed = [deposit(5), deposit(4)];
        rejected(|| bases.real.prove(&context, 0, 0, Some(&BatchRecords::Deposit(&reversed))).and_then(|proof| bases.real.circuit_data.verify(proof)));
        rejected(|| bases.real.prove(&context, 0, 1, Some(&input)).and_then(|proof| bases.real.circuit_data.verify(proof)));
        rejected(|| {
            let mut witness = PartialWitness::new();
            bases.real.set_witness(&mut witness, &context, 0, 0, Some(&input))?;
            // Replace assignments, rather than testing the setter's duplicate-write check.
            witness.target_values.insert(bases.real.statement.real_records, F::from_canonical_u8(33));
            bases.real.circuit_data.prove(witness).and_then(|proof| bases.real.circuit_data.verify(proof))
        });
        rejected(|| {
            let mut witness = PartialWitness::new();
            bases.real.set_witness(&mut witness, &context, 0, 0, Some(&input))?;
            let target = bases.real.record_words[2][7];
            witness.target_values.insert(target, F::ONE);
            bases.real.circuit_data.prove(witness).and_then(|proof| bases.real.circuit_data.verify(proof))
        });
    }

    fn config() -> NetworkConfig {
        NetworkConfig {
            version: 1, network_magic: 3, bridge_user_id: 524288, circuit_set_hash: [9; 32],
            chains: vec![ChainConfig { chain_index: 7, chain_id: word(1), bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [0; 4] }],
            ethereum_index: 7, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: word(10), reward_token_decimals: 18,
            reward_cutover: 0, reward_end_exclusive: 1000, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
        }
    }

    fn withdrawal_input(context: &BatchContext) -> WithdrawalInclusionInputs {
        let leaf = WithdrawalLeaf { chain_index: 7, sender_user_id: 1000, recipient: [0x55; 20], token: [0x33; 20], amount: word(100), nonce: [0x77; 32] };
        let witness = WithdrawalWitness { leaf_index: 0x8000_0005, siblings: std::array::from_fn(|level| [level as u64 + 1; 4]) };
        let mut words = vec![F::from_canonical_u32(leaf.sender_user_id)];
        for address in [&leaf.recipient, &leaf.token] {
            words.extend([F::ZERO; 3]);
            words.extend(address.chunks_exact(4).map(|bytes| F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))));
        }
        for bytes in [&leaf.amount, &leaf.nonce] { words.extend(bytes.chunks_exact(4).map(|bytes| F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap())))); }
        words.push(F::from_canonical_u8(leaf.chain_index));
        let mut root = PoseidonHash::hash_no_pad(&words).elements;
        for (level, sibling) in witness.siblings.iter().enumerate() {
            let sibling = sibling.map(F::from_canonical_u64);
            let pair = if witness.leaf_index >> level & 1 == 0 { [root, sibling] } else { [sibling, root] };
            root = PoseidonHash::hash_no_pad(&pair.concat()).elements;
        }
        WithdrawalInclusionInputs { config_hash: context.config_hash, end_checkpoint_id: context.end_id, end_checkpoint_root: context.end_root, withdrawal_root: root.map(|value| value.to_canonical_u64()), leaf, witness }
    }

    fn end_path(end: ChainEnd) -> (WithdrawalEndWitness, Bytes32) {
        let mut leaves = Vec::with_capacity(256);
        for ordinal in 0..256 {
            let mut body = domain_hash(if ordinal == 0 { Domain::Leaf } else { Domain::Empty }).to_vec();
            for value in [6, 1, ordinal] { body.extend(word(value)); }
            if ordinal == 0 { body.extend(end.encode().unwrap()); }
            leaves.push(digest(&body));
        }
        let mut siblings = [[0; 32]; 8];
        for level in 1..=8 {
            siblings[level - 1] = leaves[1];
            leaves = leaves.chunks_exact(2).map(|pair| {
                let mut body = domain_hash(Domain::Node).to_vec();
                body.extend(word(6)); body.extend(word(level as u64)); body.extend(pair[0]); body.extend(pair[1]); digest(&body)
            }).collect();
        }
        (WithdrawalEndWitness { ordinal: 0, end, siblings }, leaves[0])
    }

    #[test]
    fn withdrawal_rejects_wrong_end_record_context_ordinal_and_verifier() {
        let config = config();
        let mut context = context();
        context.config_hash = config.config_hash().unwrap();
        let input = withdrawal_input(&context);
        let leaf = WithdrawalInclusionCircuit::<C, 2>::build();
        let leaf_proof = leaf.generate_proof(&input).unwrap();
        let (end, root) = end_path(ChainEnd { chain_index: 7, deposit_root: [1; 4], deposit_count: 2, withdrawal_root: input.withdrawal_root });
        context.chain_ends_hash = root;
        assert_eq!(root, psy_client_data::bridge_aggregate::chain_ends_hash(&[end.end.clone()]).unwrap());
        let bases = RecordBatchCircuits::build(RecordBatchSource::Withdrawal { circuit: &leaf.circuit_data, chain_count: 1 }).unwrap();
        let prove = |context: &BatchContext, record: &WithdrawalLeaf, end: &WithdrawalEndWitness, proof: &ProofWithPublicInputs<F, C, 2>| {
            let records = [WithdrawalBatchRecord { record, proof, end }];
            bases.real.prove(context, 0, 0, Some(&BatchRecords::Withdrawal { config: &config, records: &records }))
                .and_then(|proof| bases.real.circuit_data.verify(proof))
        };
        prove(&context, &input.leaf, &end, &leaf_proof).unwrap();
        let mut wrong_end = end.clone(); wrong_end.end.withdrawal_root[0] += 1;
        rejected(|| prove(&context, &input.leaf, &wrong_end, &leaf_proof));
        let mut wrong_record = input.leaf.clone(); wrong_record.nonce[31] ^= 1;
        rejected(|| prove(&context, &wrong_record, &end, &leaf_proof));
        let mut wrong_context = context.clone(); wrong_context.end_id += 1;
        rejected(|| prove(&wrong_context, &input.leaf, &end, &leaf_proof));
        let mut wrong_ordinal = end.clone(); wrong_ordinal.ordinal = 1;
        rejected(|| prove(&context, &input.leaf, &wrong_ordinal, &leaf_proof));
        let mut wrong_path = end.clone(); wrong_path.siblings[7][0] ^= 1;
        rejected(|| prove(&context, &input.leaf, &wrong_path, &leaf_proof));
        let dummy = dummy_circuit::<F, C, 2>(&leaf.circuit_data.common);
        let forged = dummy_proof(&dummy, leaf_proof.public_inputs.iter().copied().enumerate().collect()).unwrap();
        rejected(|| prove(&context, &input.leaf, &end, &forged));
    }
}
