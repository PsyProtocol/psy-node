use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::{Field, Field64}},
    gates::{gate::GateRef, noop::NoopGate},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{ChainStart, DepositTransition, ChainEnd, DepositRecordRange, DepositLeaf, NetworkConfig, deposit_record_path};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::bridge::{
    aggregate_commitment::{Bytes32Target, ChainEndTarget, DepositLeafTarget, RecordTarget, chain_rows_hash, encode_hash4, verify_deposit_record_path, word, word_u64},
    aggregate_config::NetworkConfigTarget,
    deposit_spiderman_append::DepositSpidermanAppendCircuit,
};

pub const CHAIN_PI_WORDS: usize = 37;
pub const CHAIN_WEB_SLOTS: usize = 33;
pub const CHAIN_RECORD_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainVariant { A, B }
impl ChainVariant { pub fn number(self) -> u8 { match self { Self::A => 1, Self::B => 2 } } }

#[derive(Clone, Debug)]
pub struct ChainContext {
    pub config_hash: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: [u64; 4],
    pub global_deposit_record_root: [u8; 32],
    pub global_deposit_count: u32,
}

#[derive(Clone, Debug)]
pub enum ChainRow {
    A { start: ChainStart, transition: DepositTransition, range: DepositRecordRange },
    B { start: ChainStart, transition: DepositTransition, end: ChainEnd, range: DepositRecordRange },
}
impl ChainRow {
    pub fn variant(&self) -> ChainVariant { match self { Self::A { .. } => ChainVariant::A, Self::B { .. } => ChainVariant::B } }
    pub fn range(&self) -> &DepositRecordRange { match self { Self::A { range, .. } | Self::B { range, .. } => range } }
    pub fn transition(&self) -> &DepositTransition { match self { Self::A { transition, .. } | Self::B { transition, .. } => transition } }
}

#[derive(Clone, Debug)]
pub struct DepositRangeEndpoints {
    pub first_leaf: DepositLeaf,
    pub first_siblings: [[u8; 32]; 10],
    pub last_leaf: DepositLeaf,
    pub last_siblings: [[u8; 32]; 10],
}
impl DepositRangeEndpoints {
    pub fn zero() -> Self {
        let leaf = DepositLeaf { chain_index: 0, absolute_index: 0, shield_address: [0; 32], token: [0; 20], l2_token_contract_id: [0; 32], amount: [0; 32], note_commitment: [0; 32] };
        Self { first_leaf: leaf.clone(), first_siblings: [[0; 32]; 10], last_leaf: leaf, last_siblings: [[0; 32]; 10] }
    }
    pub fn from_tree(deposits: &[DepositLeaf], tree: &[[u8; 32]], range: &DepositRecordRange) -> anyhow::Result<Self> {
        anyhow::ensure!(deposits.len() <= 1024 && tree.len() == 2047, "invalid global deposit tree capacity");
        let end = range.first_record.checked_add(range.record_count).ok_or_else(|| anyhow::anyhow!("deposit interval overflow"))?;
        anyhow::ensure!(end as usize <= deposits.len(), "deposit interval exceeds opening");
        let mut endpoints = Self::zero();
        if range.record_count > 0 {
            endpoints.first_leaf = deposits[range.first_record as usize].clone();
            endpoints.first_siblings = deposit_record_path(tree, deposits.len() as u32, range.first_record)?;
        }
        if range.record_count > 1 {
            endpoints.last_leaf = deposits[end as usize - 1].clone();
            endpoints.last_siblings = deposit_record_path(tree, deposits.len() as u32, end - 1)?;
        }
        Ok(endpoints)
    }
}

struct DepositRangeEndpointsTarget {
    first_leaf: DepositLeafTarget,
    first_siblings: [Bytes32Target; 10],
    last_leaf: DepositLeafTarget,
    last_siblings: [Bytes32Target; 10],
}
impl DepositRangeEndpointsTarget {
    fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self where F: Extendable<D> {
        let mut leaf = || DepositLeafTarget { chain_index: builder.add_virtual_target(), absolute_index: builder.add_virtual_target(), shield_address: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), l2_token_contract_id: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), note_commitment: builder.add_virtual_target_arr() };
        let first_leaf = leaf();
        let last_leaf = leaf();
        Self { first_leaf, last_leaf, first_siblings: std::array::from_fn(|_| builder.add_virtual_target_arr()), last_siblings: std::array::from_fn(|_| builder.add_virtual_target_arr()) }
    }
    fn set_witness(&self, witness: &mut PartialWitness<F>, endpoints: &DepositRangeEndpoints) -> anyhow::Result<()> {
        for (target, leaf, targets, siblings) in [(&self.first_leaf, &endpoints.first_leaf, &self.first_siblings, &endpoints.first_siblings), (&self.last_leaf, &endpoints.last_leaf, &self.last_siblings, &endpoints.last_siblings)] {
            witness.set_target(target.chain_index, F::from_canonical_u8(leaf.chain_index))?;
            witness.set_target(target.absolute_index, F::from_canonical_u32(leaf.absolute_index))?;
            for (targets, bytes) in [(&target.shield_address[..], &leaf.shield_address[..]), (&target.token[..], &leaf.token[..]), (&target.l2_token_contract_id[..], &leaf.l2_token_contract_id[..]), (&target.amount[..], &leaf.amount[..]), (&target.note_commitment[..], &leaf.note_commitment[..])] { set_bytes(witness, targets, bytes)?; }
            for (target, sibling) in targets.iter().zip(siblings) { set_bytes(witness, target, sibling)?; }
        }
        Ok(())
    }
}

fn constrain_deposit_range_endpoints<const D: usize>(builder: &mut CircuitBuilder<F, D>, context: &ChainContextTarget, row: &ChainRowTarget, endpoints: &DepositRangeEndpointsTarget) where F: Extendable<D> {
    let zero = builder.zero();
    let one = builder.one();
    let first_active = builder.is_less_than(32, zero, row.record_count);
    let last_active = builder.is_less_than(32, one, row.record_count);
    let end = builder.add(row.first_record, row.record_count);
    builder.range_check(end, 32);
    let last_ordinal = builder.sub(end, one);
    let last_index = builder.sub(row.new_count, one);
    for (leaf, siblings, active, ordinal, index) in [(endpoints.first_leaf, endpoints.first_siblings, first_active, row.first_record, row.old_count), (endpoints.last_leaf, endpoints.last_siblings, last_active, last_ordinal, last_index)] {
        let inactive = builder.not(active);
        let record = RecordTarget::Deposit(leaf);
        for target in record.encode(builder) { builder.connect_zero_if_true(inactive, target); }
        builder.connect_if_true(active, leaf.chain_index, row.chain_index);
        builder.connect_if_true(active, leaf.absolute_index, index);
        let commit = record.record_commit(builder).map(|target| builder.select(active, target, zero));
        let ordinal = builder.select(active, ordinal, zero);
        verify_deposit_record_path(builder, active, context.global_deposit_record_root, context.global_deposit_count, ordinal, commit, siblings);
    }
}

#[derive(Clone)]
pub struct ChainContextTarget {
    pub config_hash: Bytes32Target,
    pub end_id: [Target; 2],
    pub end_root: [Target; 4],
    pub global_deposit_record_root: Bytes32Target,
    pub global_deposit_count: Target,
}
impl ChainContextTarget {
    pub fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self where F: Extendable<D> {
        let value = Self { config_hash: builder.add_virtual_target_arr(), end_id: builder.add_virtual_target_arr(), end_root: builder.add_virtual_target_arr(), global_deposit_record_root: builder.add_virtual_target_arr(), global_deposit_count: builder.add_virtual_target() };
        for target in value.config_hash.into_iter().chain(value.end_id).chain(value.global_deposit_record_root).chain([value.global_deposit_count]) { builder.range_check(target, 32); }
        let maximum = builder.constant(F::from_canonical_usize(CHAIN_RECORD_CAPACITY));
        builder.ensure_is_less_than_or_equal(32, value.global_deposit_count, maximum);
        value
    }
    pub fn register<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, family: u32, variant: u8, level: u8) where F: Extendable<D> {
        let prefix = [1, family, variant as u32, level as u32].map(|v| builder.constant(F::from_canonical_u32(v)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&self.config_hash);
        builder.register_public_inputs(&self.end_id);
        builder.register_public_inputs(&self.end_root);
    }
    pub fn connect_proof<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, pi: &[Target], active: BoolTarget) where F: Extendable<D> {
        for (left, right) in self.config_hash.into_iter().chain(self.end_id).chain(self.end_root).zip(&pi[4..18]) { builder.connect_if_true(active, left, *right); }
    }
    pub fn register_deposit_context<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) where F: Extendable<D> {
        builder.register_public_inputs(&self.global_deposit_record_root);
        builder.register_public_input(self.global_deposit_count);
    }
    pub fn connect_deposit_context<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, root: &[Target], count: Target, active: BoolTarget) where F: Extendable<D> {
        assert_eq!(root.len(), 8);
        for (left, right) in self.global_deposit_record_root.into_iter().zip(root) { builder.connect_if_true(active, left, *right); }
        builder.connect_if_true(active, self.global_deposit_count, count);
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, context: &ChainContext) -> anyhow::Result<()> {
        set_bytes(witness, &self.config_hash, &context.config_hash)?;
        set_u64(witness, self.end_id, context.end_checkpoint_id)?;
        set_hash(witness, self.end_root, context.end_checkpoint_root)?;
        set_bytes(witness, &self.global_deposit_record_root, &context.global_deposit_record_root)?;
        witness.set_target(self.global_deposit_count, F::from_canonical_u32(context.global_deposit_count))
    }
}

#[derive(Clone)]
pub(crate) struct ChainRowTarget {
    pub(crate) chain_index: Target,
    pub(crate) start_id: [Target; 2],
    pub(crate) start_root: [Target; 4],
    pub(crate) old_root: [Target; 4],
    pub(crate) new_root: [Target; 4],
    pub(crate) old_count: Target,
    pub(crate) new_count: Target,
    pub(crate) end: Option<ChainEndTarget>,
    pub(crate) first_record: Target,
    pub(crate) record_count: Target,
}
impl ChainRowTarget {
    pub(crate) fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>, variant: ChainVariant) -> Self where F: Extendable<D> {
        Self {
            chain_index: builder.add_virtual_target(), start_id: builder.add_virtual_target_arr(), start_root: builder.add_virtual_target_arr(),
            old_root: builder.add_virtual_target_arr(), new_root: builder.add_virtual_target_arr(), old_count: builder.add_virtual_target(), new_count: builder.add_virtual_target(),
            end: (variant == ChainVariant::B).then(|| ChainEndTarget { chain_index: builder.add_virtual_target(), deposit_root: builder.add_virtual_target_arr(), deposit_count: builder.add_virtual_target(), withdrawal_root: builder.add_virtual_target_arr() }),
            first_record: builder.add_virtual_target(), record_count: builder.add_virtual_target(),
        }
    }
    pub(crate) fn encode<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> where F: Extendable<D> {
        let mut words = word(builder, self.chain_index, 8).to_vec();
        words.extend(word_u64(builder, self.start_id));
        words.extend(encode_hash4(builder, self.start_root));
        words.extend(word(builder, self.chain_index, 8));
        words.extend(encode_hash4(builder, self.old_root));
        words.extend(encode_hash4(builder, self.new_root));
        words.extend(word(builder, self.old_count, 32));
        words.extend(word(builder, self.new_count, 32));
        if let Some(end) = &self.end { words.extend(end.encode(builder)); }
        words.extend(word(builder, self.first_record, 32));
        words.extend(word(builder, self.record_count, 32));
        words
    }
    pub(crate) fn constrain<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, config: &NetworkConfigTarget, ordinal: Target, active: BoolTarget) where F: Extendable<D> {
        let zero = builder.zero();
        let mut selected = zero;
        let mut found = zero;
        for (i, chain) in config.chains.iter().enumerate() {
            let index = builder.constant(F::from_canonical_usize(i));
            let matches = builder.is_equal(ordinal, index);
            selected = builder.mul_add(matches.target, chain.chain_index, selected);
            found = builder.add(found, matches.target);
        }
        let one = builder.one();
        builder.connect_if_true(active, found, one);
        builder.connect_if_true(active, self.chain_index, selected);
        let end = builder.add(self.old_count, self.record_count);
        builder.range_check(end, 32);
        builder.connect_if_true(active, end, self.new_count);
        let record_end = builder.add(self.first_record, self.record_count);
        builder.range_check(record_end, 32);
        let maximum = builder.constant(F::from_canonical_usize(CHAIN_RECORD_CAPACITY));
        builder.ensure_is_less_than_or_equal(32, self.record_count, maximum);
        if let Some(end) = &self.end {
            builder.connect_if_true(active, end.chain_index, self.chain_index);
            builder.connect_if_true(active, end.deposit_count, self.new_count);
            for (left, right) in end.deposit_root.into_iter().zip(self.new_root) { builder.connect_if_true(active, left, right); }
        }
        let inactive = builder.not(active);
        for target in self.encode(builder) { builder.connect_zero_if_true(inactive, target); }
    }
    pub(crate) fn set_witness(&self, witness: &mut PartialWitness<F>, row: Option<&ChainRow>) -> anyhow::Result<()> {
        let Some(row) = row else {
            for target in self.targets() { witness.set_target(target, F::ZERO)?; }
            return Ok(());
        };
        let (start, transition, range, end) = match row {
            ChainRow::A { start, transition, range } => (start, transition, range, None),
            ChainRow::B { start, transition, range, end } => (start, transition, range, Some(end)),
        };
        anyhow::ensure!(start.chain_index == transition.chain_index && self.end.is_some() == end.is_some(), "chain row type/index mismatch");
        witness.set_target(self.chain_index, F::from_canonical_u8(start.chain_index))?;
        set_u64(witness, self.start_id, start.start_checkpoint_id)?;
        set_hash(witness, self.start_root, start.start_checkpoint_root)?;
        set_hash(witness, self.old_root, transition.old_root)?;
        set_hash(witness, self.new_root, transition.new_root)?;
        for (target, value) in [(self.old_count, transition.old_count), (self.new_count, transition.new_count), (self.first_record, range.first_record), (self.record_count, range.record_count)] { witness.set_target(target, F::from_canonical_u32(value))?; }
        if let (Some(target), Some(end)) = (&self.end, end) {
            witness.set_target(target.chain_index, F::from_canonical_u8(end.chain_index))?;
            witness.set_target(target.deposit_count, F::from_canonical_u32(end.deposit_count))?;
            set_hash(witness, target.deposit_root, end.deposit_root)?;
            set_hash(witness, target.withdrawal_root, end.withdrawal_root)?;
        }
        Ok(())
    }
    fn targets(&self) -> Vec<Target> {
        let mut targets: Vec<_> = [self.chain_index, self.old_count, self.new_count, self.first_record, self.record_count].into_iter().chain(self.start_id).chain(self.start_root).chain(self.old_root).chain(self.new_root).collect();
        if let Some(end) = self.end { targets.extend([end.chain_index, end.deposit_count]); targets.extend(end.deposit_root); targets.extend(end.withdrawal_root); }
        targets
    }
}


pub struct ChainAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub circuit_data: CircuitData<F, C, D>,
    pub variant: ChainVariant,
    pub source_chain_count: usize,
    pub is_empty: bool,
    config: NetworkConfigTarget,
    context: ChainContextTarget,
    first: Target,
    row: Option<ChainRowTarget>,
    webs: Vec<ProofWithPublicInputsTarget<D>>,
    dummy: Option<CircuitData<F, C, D>>,
    endpoints: Option<DepositRangeEndpointsTarget>,
}
pub struct ChainBaseCircuits<C: GenericConfig<D, F = F>, const D: usize> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub real: ChainAggregateCircuit<C, D>,
    pub empty: ChainAggregateCircuit<C, D>,
}

impl<C: GenericConfig<D, F = F> + 'static, const D: usize> ChainBaseCircuits<C, D> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn build_a(source_chain_count: usize, web: &DepositSpidermanAppendCircuit<C, D>) -> anyhow::Result<Self> { Self::build(source_chain_count, ChainVariant::A, Some(&web.circuit_data)) }
    pub fn build_b(source_chain_count: usize) -> anyhow::Result<Self> { Self::build(source_chain_count, ChainVariant::B, None) }
    fn build(source_chain_count: usize, variant: ChainVariant, web: Option<&CircuitData<F, C, D>>) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=256).contains(&source_chain_count), "source chain count must be 1..256");
        let mut gates: Vec<GateRef<F, D>> = Vec::new();
        let mut degree = 0;
        loop {
            let real = ChainAggregateCircuit::build(source_chain_count, variant, false, web, &gates, degree);
            let empty = ChainAggregateCircuit::build(source_chain_count, variant, true, None, &gates, degree);
            if real.circuit_data.common == empty.circuit_data.common { return Ok(Self { real, empty }); }
            let next_degree = real.circuit_data.common.degree_bits().max(empty.circuit_data.common.degree_bits());
            let mut next_gates = real.circuit_data.common.gates.clone();
            next_gates.extend(empty.circuit_data.common.gates.iter().cloned());
            next_gates.sort_by_key(|gate| gate.0.id());
            next_gates.dedup_by(|left, right| left.0.id() == right.0.id());
            anyhow::ensure!(degree != next_degree || gates != next_gates, "chain common data disagree beyond gate set and degree");
            gates = next_gates;
            degree = next_degree;
        }
    }
}

impl<C: GenericConfig<D, F = F> + 'static, const D: usize> ChainAggregateCircuit<C, D> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    fn build(source_chain_count: usize, variant: ChainVariant, is_empty: bool, web: Option<&CircuitData<F, C, D>>, gates: &[GateRef<F, D>], degree: usize) -> Self {
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let context = ChainContextTarget::new(&mut builder);
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let config_hash = config.hash(&mut builder);
        for (left, right) in config_hash.into_iter().zip(context.config_hash) { builder.connect(left, right); }
        let first = builder.add_virtual_target();
        builder.range_check(first, 32);
        let count = builder.constant(F::from_bool(!is_empty));
        let active = builder.constant_bool(!is_empty);
        let row = (!is_empty).then(|| ChainRowTarget::new(&mut builder, variant));
        let mut webs = Vec::new();
        let mut dummy = None;
        let endpoints = (!is_empty && variant == ChainVariant::B).then(|| DepositRangeEndpointsTarget::new(&mut builder));
        if let Some(row) = &row {
            row.constrain(&mut builder, &config, first, active);
            if let Some(endpoints) = &endpoints { constrain_deposit_range_endpoints(&mut builder, &context, row, endpoints); }
            if let Some(web) = web {
                let web_dummy = dummy_circuit::<F, C, D>(&web.common);
                webs = constrain_webs::<C, D>(&mut builder, &context, row, web, &web_dummy);
                dummy = Some(web_dummy);
            }
        } else {
            let minimum = builder.constant(F::from_canonical_usize(source_chain_count));
            builder.ensure_is_less_than_or_equal(32, minimum, first);
            let limit = builder.constant(F::from_canonical_usize(source_chain_count.next_power_of_two()));
            builder.ensure_is_less_than(32, first, limit);
        }
        let rows: Vec<_> = row.iter().map(|row| row.encode(&mut builder)).collect();
        let hash = chain_rows_hash(&mut builder, variant.number(), first, &rows, count);
        context.register(&mut builder, 9, variant.number() | if is_empty { 128 } else { 0 }, 0);
        builder.register_public_inputs(&[first, count]);
        builder.register_public_inputs(&hash);
        context.register_deposit_context(&mut builder);
        for gate in gates { builder.add_gate_to_gate_set(gate.clone()); }
        if degree > 0 { while builder.num_gates() < (1usize << (degree - 1)) + 1 { builder.add_gate(NoopGate, vec![]); } }
        let circuit_data = builder.build::<C>();
        Self { circuit_data, variant, source_chain_count, is_empty, config, context, first, row, webs, dummy, endpoints }
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, context: &ChainContext, first_chain_ordinal: u32, row: Option<&ChainRow>, web_proofs: &[ProofWithPublicInputs<F, C, D>], endpoints: Option<&DepositRangeEndpoints>) -> anyhow::Result<()> {
        anyhow::ensure!(self.is_empty == row.is_none(), "real/empty chain row mismatch");
        anyhow::ensure!(row.is_none_or(|row| row.variant() == self.variant), "wrong chain row variant");
        anyhow::ensure!(self.endpoints.is_some() == endpoints.is_some(), "endpoint witness is required only for real B chains");
        if let (Some(target), Some(endpoints)) = (&self.endpoints, endpoints) { target.set_witness(witness, endpoints)?; }
        self.config.set_witness(witness, config)?;
        self.context.set_witness(witness, context)?;
        witness.set_target(self.first, F::from_canonical_u32(first_chain_ordinal))?;
        if let Some(target) = &self.row { target.set_witness(witness, row)?; }
        if let Some(dummy) = &self.dummy {
            let row = row.ok_or_else(|| anyhow::anyhow!("missing A row"))?;
            let expected = active_web_count(row.transition().old_count, row.range().record_count as usize);
            anyhow::ensure!(web_proofs.len() == expected, "wrong active web proof count");
            let dummy_proof = dummy_proof(dummy, Default::default())?;
            for (i, target) in self.webs.iter().enumerate() { witness.set_proof_with_pis_target(target, web_proofs.get(i).unwrap_or(&dummy_proof))?; }
        } else { anyhow::ensure!(web_proofs.is_empty(), "B/empty chain cannot carry web witnesses"); }
        Ok(())
    }
    pub fn prove(&self, config: &NetworkConfig, context: &ChainContext, first_chain_ordinal: u32, row: Option<&ChainRow>, web_proofs: &[ProofWithPublicInputs<F, C, D>], endpoints: Option<&DepositRangeEndpoints>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, config, context, first_chain_ordinal, row, web_proofs, endpoints)?;
        self.circuit_data.prove(witness)
    }
}

pub fn active_web_count(old_count: u32, records: usize) -> usize { if records == 0 { 0 } else { ((old_count as usize & 31) + records).div_ceil(32) } }

fn constrain_webs<C: GenericConfig<D, F = F>, const D: usize>(builder: &mut CircuitBuilder<F, D>, context: &ChainContextTarget, row: &ChainRowTarget, web: &CircuitData<F, C, D>, dummy: &CircuitData<F, C, D>) -> Vec<ProofWithPublicInputsTarget<D>> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    assert_eq!(web.common.num_public_inputs, 40);
    let zero = builder.zero();
    let real_vk = builder.constant_verifier_data(&web.verifier_only);
    let dummy_vk = builder.constant_verifier_data(&dummy.verifier_only);
    let old_bits = builder.split_le(row.old_count, 32);
    let offset = builder.le_sum(old_bits[..5].iter());
    let offset_count = builder.add(offset, row.record_count);
    let rounded = builder.add_const(offset_count, F::from_canonical_u32(31));
    let bits = builder.split_le(rounded, 11);
    let nonzero_count = builder.le_sum(bits[5..].iter());
    let empty = builder.is_equal(row.record_count, zero);
    let active_count = builder.select(empty, zero, nonzero_count);
    let mut consumed = zero;
    let mut rolling_count = row.old_count;
    let mut rolling_root = row.old_root;
    let mut proofs = Vec::with_capacity(CHAIN_WEB_SLOTS);
    for slot in 0..CHAIN_WEB_SLOTS {
        let ordinal = builder.constant(F::from_canonical_usize(slot));
        let active = builder.is_less_than(32, ordinal, active_count);
        let inactive = builder.not(active);
        let proof = builder.add_virtual_proof_with_pis(&web.common);
        builder.conditionally_verify_proof::<C>(active, &proof, &real_vk, &proof, &dummy_vk, &web.common);
        for &target in &proof.public_inputs { builder.connect_zero_if_true(inactive, target); }
        let pi = &proof.public_inputs;
        for (target, value) in pi[..4].iter().zip([1, 1, 0, 0]) { let expected = builder.constant(F::from_canonical_u32(value)); builder.connect_if_true(active, *target, expected); }
        context.connect_proof(builder, pi, active);
        context.connect_deposit_context(builder, &pi[31..39], pi[39], active);
        builder.connect_if_true(active, pi[18], row.chain_index);
        builder.connect_if_true(active, pi[19], rolling_count);
        for (target, expected) in pi[21..25].iter().zip(rolling_root) { builder.connect_if_true(active, *target, expected); }
        let first = builder.add(row.first_record, consumed);
        builder.range_check(first, 32);
        builder.connect_if_true(active, pi[29], first);
        let remaining = builder.sub(row.record_count, consumed);
        builder.range_check(remaining, 32);
        let rolling_bits = builder.split_le(rolling_count, 32);
        let offset = builder.le_sum(rolling_bits[..5].iter());
        let width = builder.constant(F::from_canonical_u32(32));
        let available = builder.sub(width, offset);
        let shorter = builder.is_less_than(32, remaining, available);
        let take = builder.select(shorter, remaining, available);
        let take = builder.select(active, take, zero);
        builder.connect_if_true(active, pi[30], take);
        consumed = builder.add(consumed, take);
        let next_count = builder.add(rolling_count, take);
        builder.range_check(next_count, 32);
        builder.connect_if_true(active, pi[20], next_count);
        rolling_count = next_count;
        rolling_root = std::array::from_fn(|i| builder.select(active, pi[25 + i], rolling_root[i]));
        proofs.push(proof);
    }
    builder.connect(consumed, row.record_count);
    builder.connect(rolling_count, row.new_count);
    for (left, right) in rolling_root.into_iter().zip(row.new_root) { builder.connect(left, right); }
    proofs
}

pub(crate) fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(targets.len() * 4 == bytes.len(), "byte target width mismatch");
    for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) { witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?; }
    Ok(())
}
fn set_u64(witness: &mut PartialWitness<F>, targets: [Target; 2], value: u64) -> anyhow::Result<()> {
    witness.set_target(targets[0], F::from_canonical_u32(value as u32))?;
    witness.set_target(targets[1], F::from_canonical_u32((value >> 32) as u32))
}
fn set_hash(witness: &mut PartialWitness<F>, targets: [Target; 4], values: [u64; 4]) -> anyhow::Result<()> {
    for (target, value) in targets.into_iter().zip(values) { anyhow::ensure!(value < F::ORDER, "noncanonical Hash4"); witness.set_target(target, F::from_canonical_u64(value))?; }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_client_data::bridge_aggregate::{ChainConfig, DepositLeaf, deposit_record_tree, deposit_record_path};
    pub(crate) type C = PoseidonGoldilocksConfig;

    pub(crate) fn fixture(count: usize) -> (NetworkConfig, ChainContext, Vec<ChainRow>) {
        let config = NetworkConfig {
            version: 1, network_magic: 1, bridge_user_id: 524288, circuit_set_hash: [3; 32],
            chains: (0..count).map(|i| { let mut chain_id = [0; 32]; chain_id[31] = (i + 1) as u8; ChainConfig { chain_index: i as u8, chain_id, bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [0; 4] } }).collect(),
            ethereum_index: 0, reward_payer: [4; 20], reward_token: [5; 20], reward_per_claim: [1; 32], reward_token_decimals: 18,
            reward_cutover: 1, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
        };
        let context = ChainContext { config_hash: config.config_hash().unwrap(), end_checkpoint_id: 1, end_checkpoint_root: [7; 4], global_deposit_record_root: deposit_record_tree(&[]).unwrap()[0], global_deposit_count: 0 };
        let rows = (0..count).map(|i| ChainRow::B {
            start: ChainStart { chain_index: i as u8, start_checkpoint_id: 0, start_checkpoint_root: [0; 4] },
            transition: DepositTransition { chain_index: i as u8, old_root: [9; 4], new_root: [9; 4], old_count: 3, new_count: 3 },
            end: ChainEnd { chain_index: i as u8, deposit_root: [9; 4], deposit_count: 3, withdrawal_root: [8; 4] },
            range: DepositRecordRange { first_record: 0, record_count: 0 },
        }).collect();
        (config, context, rows)
    }

    pub(crate) fn rejects<T>(prove: impl FnOnce() -> anyhow::Result<T>) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(prove));
        assert!(result.is_err() || result.unwrap().is_err(), "tampered chain statement proved");
    }

    #[test]
    fn b_base_binds_end_count_root_and_configured_ordinal() {
        let (config, context, rows) = fixture(3);
        let bases = ChainBaseCircuits::<C, 2>::build_b(3).unwrap();
        let endpoints = DepositRangeEndpoints::zero();
        let proof = bases.real.prove(&config, &context, 0, Some(&rows[0]), &[], Some(&endpoints)).unwrap();
        bases.real.circuit_data.verify(proof).unwrap();
        for root in [false, true] {
            let mut row = rows[0].clone();
            if let ChainRow::B { end, .. } = &mut row { if root { end.deposit_root[0] += 1; } else { end.deposit_count += 1; } }
            rejects(|| bases.real.prove(&config, &context, 0, Some(&row), &[], Some(&endpoints)));
        }
        rejects(|| bases.real.prove(&config, &context, 1, Some(&rows[0]), &[], Some(&endpoints)));
        let empty = bases.empty.prove(&config, &context, 3, None, &[], None).unwrap();
        bases.empty.circuit_data.verify(empty).unwrap();
        rejects(|| bases.empty.prove(&config, &context, 2, None, &[], None));
    }

    #[test]
    fn b_endpoints_authenticate_assignment_and_zero_length_boundaries() {
        let (config, mut context, rows) = fixture(1);
        let bases = ChainBaseCircuits::<C, 2>::build_b(1).unwrap();
        for count in [1u32, 3] {
            let mut row = rows[0].clone();
            if let ChainRow::B { transition, end, range, .. } = &mut row {
                transition.old_count = 20; transition.new_count = 20 + count;
                end.deposit_count = 20 + count; range.first_record = 5; range.record_count = count;
            }
            let mut deposits = vec![DepositRangeEndpoints::zero().first_leaf; 5];
            deposits.extend((0..count).map(|i| DepositLeaf { chain_index: 0, absolute_index: 20 + i, shield_address: [1; 32], token: [2; 20], l2_token_contract_id: [3; 32], amount: [4; 32], note_commitment: [5; 32] }));
            let tree = deposit_record_tree(&deposits.iter().map(|leaf| leaf.record_commit().unwrap()).collect::<Vec<_>>()).unwrap();
            context.global_deposit_record_root = tree[0]; context.global_deposit_count = deposits.len() as u32;
            let endpoints = DepositRangeEndpoints::from_tree(&deposits, &tree, row.range()).unwrap();
            let proof = bases.real.prove(&config, &context, 0, Some(&row), &[], Some(&endpoints)).unwrap();
            bases.real.circuit_data.verify(proof).unwrap();
            let mut wrong_path = endpoints.clone(); wrong_path.first_siblings[0][0] ^= 1;
            rejects(|| bases.real.prove(&config, &context, 0, Some(&row), &[], Some(&wrong_path)));
            if count == 1 {
                let mut duplicate = endpoints.clone(); duplicate.last_leaf = duplicate.first_leaf.clone(); duplicate.last_siblings = duplicate.first_siblings;
                rejects(|| bases.real.prove(&config, &context, 0, Some(&row), &[], Some(&duplicate)));
            }
            for wrong_chain in [false, true] {
                let mut wrong_records = deposits.clone();
                let position = if count == 1 { 5 } else { wrong_records.len() - 1 };
                if wrong_chain { wrong_records[position].chain_index = 255; } else { wrong_records[position].absolute_index = 42; }
                let tree = deposit_record_tree(&wrong_records.iter().map(|leaf| leaf.record_commit().unwrap()).collect::<Vec<_>>()).unwrap();
                let mut wrong_context = context.clone(); wrong_context.global_deposit_record_root = tree[0];
                let endpoints = DepositRangeEndpoints::from_tree(&wrong_records, &tree, row.range()).unwrap();
                rejects(|| bases.real.prove(&config, &wrong_context, 0, Some(&row), &[], Some(&endpoints)));
            }
        }
        let deposits = vec![DepositRangeEndpoints::zero().first_leaf; 1024];
        let tree = deposit_record_tree(&deposits.iter().map(|leaf| leaf.record_commit().unwrap()).collect::<Vec<_>>()).unwrap();
        context.global_deposit_record_root = tree[0]; context.global_deposit_count = 1024;
        let mut row = rows[0].clone();
        if let ChainRow::B { range, .. } = &mut row { range.first_record = 1024; }
        let endpoints = DepositRangeEndpoints::from_tree(&deposits, &tree, row.range()).unwrap();
        let proof = bases.real.prove(&config, &context, 0, Some(&row), &[], Some(&endpoints)).unwrap();
        bases.real.circuit_data.verify(proof).unwrap();
        let mut nonzero_padding = endpoints; nonzero_padding.last_siblings[0][0] = 1;
        rejects(|| bases.real.prove(&config, &context, 0, Some(&row), &[], Some(&nonzero_padding)));
    }

    #[test]
    fn a_zero_append_uses_only_dummy_slots_and_rejects_changed_end() {
        let (config, context, rows) = fixture(1);
        let ChainRow::B { start, transition, range, .. } = rows[0].clone() else { unreachable!() };
        let row = ChainRow::A { start, transition, range };
        let web = DepositSpidermanAppendCircuit::<C, 2>::build();
        let bases = ChainBaseCircuits::build_a(1, &web).unwrap();
        let proof = bases.real.prove(&config, &context, 0, Some(&row), &[], None).unwrap();
        bases.real.circuit_data.verify(proof).unwrap();
        let mut changed = row.clone();
        if let ChainRow::A { transition, .. } = &mut changed { transition.new_root[0] += 1; }
        rejects(|| bases.real.prove(&config, &context, 0, Some(&changed), &[], None));
        let mut changed_context = context;
        changed_context.global_deposit_count = 1025;
        rejects(|| bases.real.prove(&config, &changed_context, 0, Some(&row), &[], None));
    }

    #[test]
    fn a_real_web_binds_global_record_root_count_and_ordinal() {
        use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, spiderman::SpidermanUpdateProof, traits::{MerkleHasher, MerkleZeroHasher}}, pgoldilocks::{PoseidonHasher, QHashOut}};
        use plonky2::{field::types::PrimeField64, hash::poseidon::PoseidonHash, plonk::config::Hasher};
        use psy_plonky2_common_circuits::bridge::deposit_spiderman_append::DepositSpidermanAppendInputs;
        let (config, mut context, rows) = fixture(1);
        let deposit = DepositLeaf { chain_index: 0, absolute_index: 31, shield_address: [1; 32], token: [2; 20], l2_token_contract_id: [3; 32], amount: [4; 32], note_commitment: [5; 32] };
        let mut commits = vec![[0; 32]; 98];
        commits[97] = deposit.record_commit().unwrap();
        let tree = deposit_record_tree(&commits).unwrap();
        context.global_deposit_record_root = tree[0];
        context.global_deposit_count = 98;
        let mut bytes = Vec::new();
        bytes.extend(deposit.shield_address); bytes.extend([0; 12]); bytes.extend(deposit.token);
        bytes.extend(deposit.l2_token_contract_id); bytes.extend(deposit.amount); bytes.extend(0u32.to_be_bytes()); bytes.extend(deposit.note_commitment);
        let words: Vec<_> = bytes.chunks_exact(4).map(|word| F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap()))).collect();
        let mut old_leaves = vec![QHashOut::ZERO; 32];
        for leaf in &mut old_leaves[..31] { *leaf = QHashOut(PoseidonHash::hash_no_pad(&[F::ONE])); }
        let mut new_leaves = old_leaves.clone();
        new_leaves[31] = QHashOut(PoseidonHash::hash_no_pad(&words));
        let top = DeltaMerkleProofCore::from_params::<PoseidonHasher>(0, PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap(), PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap(), (5..32).map(PoseidonHasher::get_zero_hash).collect());
        let ChainRow::B { start, .. } = rows[0].clone() else { unreachable!() };
        let transition = DepositTransition { chain_index: 0, old_root: top.old_root.0.elements.map(|value| value.to_canonical_u64()), new_root: top.new_root.0.elements.map(|value| value.to_canonical_u64()), old_count: 31, new_count: 32 };
        let range = DepositRecordRange { first_record: 97, record_count: 1 };
        let row = ChainRow::A { start, transition, range };
        let inputs = DepositSpidermanAppendInputs { config_hash: context.config_hash, end_checkpoint_id: context.end_checkpoint_id, end_checkpoint_root: QHashOut(plonky2::hash::hash_types::HashOut { elements: context.end_checkpoint_root.map(F::from_canonical_u64) }), chain_index: 0, old_count: 31, first_record: 97, deposits: vec![deposit], global_deposit_record_root: tree[0], global_deposit_count: 98, record_paths: vec![deposit_record_path(&tree, 98, 97).unwrap()], append_proof: SpidermanUpdateProof { top_line_proof: top, web_proof_old_leaves: old_leaves, web_proof_new_leaves: new_leaves } };
        let web = DepositSpidermanAppendCircuit::<C, 2>::build();
        let proof = web.prove(&inputs).unwrap();
        let bases = ChainBaseCircuits::build_a(1, &web).unwrap();
        let aggregate = bases.real.prove(&config, &context, 0, Some(&row), &[proof.clone()], None).unwrap();
        bases.real.circuit_data.verify(aggregate).unwrap();
        let mut changed = row.clone();
        if let ChainRow::A { range, .. } = &mut changed { range.first_record += 1; }
        rejects(|| bases.real.prove(&config, &context, 0, Some(&changed), &[proof.clone()], None));
        for change_count in [false, true] {
            let mut changed_context = context.clone();
            if change_count { changed_context.global_deposit_count += 1; } else { changed_context.global_deposit_record_root[0] ^= 1; }
            rejects(|| bases.real.prove(&config, &changed_context, 0, Some(&row), &[proof.clone()], None));
        }
    }
    #[test]
    fn web_capacity_boundaries() {
        assert_eq!(active_web_count(0, 0), 0);
        assert_eq!(active_web_count(31, 0), 0);
        assert_eq!(active_web_count(31, 1), 1);
        assert_eq!(active_web_count(31, 2), 2);
        assert_eq!(active_web_count(0, 1024), 32);
        assert_eq!(active_web_count(31, 1024), 33);
    }
}
