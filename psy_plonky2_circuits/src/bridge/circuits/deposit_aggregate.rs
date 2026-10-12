use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::Field},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs},
};
use psy_client_data::bridge_aggregate::{deposit_aggregate_pi_len, DepositAggregateOpening, DepositLeaf, DepositLeafRange, NetworkConfig};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::bridge::{
    aggregate_commitment::{Bytes32Target, DepositLeafTarget, Hash4Target, deposit_accumulator_fold, deposit_accumulator_seed},
    aggregate_config::DEPOSIT_RECORD_CAPACITY,
    deposit_spiderman_append::{DepositSpidermanAppendInputs, DepositSpidermanAppendTarget, DEPOSIT_SPIDERMAN_PAGE_CAPACITY},
};
use super::{aggregate::set_bytes, chain_aggregate::{ChainContext, ChainContextTarget, ChainRow, ChainRowTarget}};


pub(crate) fn less_words<const D: usize>(builder: &mut CircuitBuilder<F, D>, left: &[Target], right: &[Target]) -> BoolTarget
where F: Extendable<D> {
    assert_eq!(left.len(), right.len());
    let mut equal = builder._true();
    let mut less = builder._false();
    for (&left_word, &right_word) in left.iter().zip(right) {
        let next = builder.is_less_than(32, left_word, right_word);
        let selected = builder.and(equal, next);
        less = builder.or(less, selected);
        let same = builder.is_equal(left_word, right_word);
        equal = builder.and(equal, same);
    }
    less
}

fn leaf_words(leaf: &DepositLeafTarget) -> Vec<Target> {
    [leaf.chain_index, leaf.absolute_index].into_iter().chain(leaf.shield_address).chain(leaf.token)
        .chain(leaf.l2_token_contract_id).chain(leaf.amount).chain(leaf.note_commitment).collect()
}

fn accumulator_at<const D: usize>(builder: &mut CircuitBuilder<F, D>, checkpoints: &[Hash4Target], index: Target) -> Hash4Target
where F: Extendable<D> {
    std::array::from_fn(|limb| {
        let mut values: Vec<_> = checkpoints.iter().map(|hash| hash[limb]).collect();
        values.resize(64, builder.zero());
        builder.random_access(index, values)
    })
}

struct DepositAggregateOpeningTarget {
    context: ChainContextTarget,
    window_id: Bytes32Target,
    rows: Vec<ChainRowTarget>,
    leaves: Vec<DepositLeafTarget>,
    pages: Vec<DepositSpidermanAppendTarget>,
    addresses: Vec<Target>,
}

impl DepositAggregateOpeningTarget {
    fn build<const D: usize>(builder: &mut CircuitBuilder<F, D>, chains: usize) -> Self where F: Extendable<D> {
        assert!((1..=8).contains(&chains));
        assert_eq!(DEPOSIT_RECORD_CAPACITY, 32);
        let context = ChainContextTarget::new(builder);
        let count = context.global_deposit_count;
        let window_id: Bytes32Target = builder.add_virtual_target_arr();
        for word in window_id { builder.range_check(word, 32); }
        let zero = builder.zero();
        let one = builder.one();
        let mut leaves = Vec::with_capacity(DEPOSIT_RECORD_CAPACITY);
        let mut hashes = Vec::with_capacity(DEPOSIT_RECORD_CAPACITY);
        let mut active_records = Vec::with_capacity(DEPOSIT_RECORD_CAPACITY);
        let seed = deposit_accumulator_seed(builder, context.config_hash, context.end_id, context.end_root, count);
        let mut checkpoints = vec![seed];
        let mut accumulator = seed;
        let mut previous_key: Option<[Target; 2]> = None;
        for index in 0..DEPOSIT_RECORD_CAPACITY {
            let leaf = DepositLeafTarget {
                chain_index: builder.add_virtual_target(), absolute_index: builder.add_virtual_target(),
                shield_address: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(),
                l2_token_contract_id: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), note_commitment: builder.add_virtual_target_arr(),
            };
            let ordinal = builder.constant(F::from_canonical_usize(index));
            let active = builder.is_less_than(6, ordinal, count);
            let inactive = builder.not(active);
            builder.range_check(leaf.chain_index, 8);
            for word in leaf_words(&leaf) {
                builder.range_check(word, 32);
                builder.connect_zero_if_true(inactive, word);
            }
            let key = [leaf.chain_index, leaf.absolute_index];
            if let Some(previous) = previous_key {
                let ordered = less_words(builder, &previous, &key);
                builder.connect_if_true(active, ordered.target, one);
            }
            previous_key = Some(key);
            let hash = leaf.poseidon_hash(builder);
            let folded = deposit_accumulator_fold(builder, accumulator, ordinal, leaf.chain_index, leaf.absolute_index, hash);
            accumulator = std::array::from_fn(|limb| builder.select(active, folded[limb], accumulator[limb]));
            checkpoints.push(accumulator);
            hashes.push(hash);
            active_records.push(active);
            leaves.push(leaf);
        }

        let pages: Vec<_> = (0..DEPOSIT_SPIDERMAN_PAGE_CAPACITY).map(|_| DepositSpidermanAppendTarget::new(builder)).collect();
        let mut page_end = zero;
        for (index, page) in pages.iter().enumerate() {
            builder.connect_if_true(page.active, page.first_leaf, page_end);
            page_end = builder.add(page_end, page.leaf_count);
            builder.range_check(page_end, 6);
            builder.ensure_is_less_than_or_equal(6, page_end, count);
            if index > 0 {
                builder.connect_if_true(page.active, pages[index - 1].active.target, one);
                let backwards = builder.is_less_than(8, page.chain_index, pages[index - 1].chain_index);
                builder.connect_zero_if_true(page.active, backwards.target);
            }
        }
        builder.connect(page_end, count);

        let mut rows = Vec::with_capacity(chains);
        let mut first = zero;
        let mut previous_chain = None;
        let mut row_accumulator = seed;
        let page_accumulators: Vec<_> = pages.iter().map(|page| {
            let end = builder.add(page.first_leaf, page.leaf_count);
            builder.range_check(end, 6);
            builder.ensure_is_less_than_or_equal(6, end, count);
            (accumulator_at(builder, &checkpoints, page.first_leaf), accumulator_at(builder, &checkpoints, end))
        }).collect();
        let mut memberships = vec![zero; pages.len()];
        for _ in 0..chains {
            let row = ChainRowTarget::new(builder);
            if let Some(previous) = previous_chain {
                let ordered = builder.is_less_than(8, previous, row.chain_index);
                builder.connect(ordered.target, one);
            }
            previous_chain = Some(row.chain_index);
            builder.connect(row.first_leaf, first);
            let next = builder.add(first, row.leaf_count);
            builder.range_check(next, 6);
            builder.ensure_is_less_than_or_equal(6, next, count);
            let after_end = less_words(builder, &[context.end_id[1], context.end_id[0]], &[row.start_id[1], row.start_id[0]]);
            builder.assert_zero(after_end.target);
            let same_low = builder.is_equal(row.start_id[0], context.end_id[0]);
            let same_high = builder.is_equal(row.start_id[1], context.end_id[1]);
            let same_id = builder.and(same_low, same_high);
            for limb in 0..4 { builder.connect_if_true(same_id, row.start_root[limb], context.end_root[limb]); }
            let start_accumulator = accumulator_at(builder, &checkpoints, first);
            for limb in 0..4 { builder.connect(row_accumulator[limb], start_accumulator[limb]); }
            let mut rolling_root = row.old_root;
            let mut rolling_count = row.old_count;
            let mut consumed = zero;
            for (index, page) in pages.iter().enumerate() {
                let same_chain = builder.is_equal(row.chain_index, page.chain_index);
                let belongs = builder.and(page.active, same_chain);
                memberships[index] = builder.add(memberships[index], belongs.target);
                builder.connect_if_true(belongs, page.old_count, rolling_count);
                let page_first = builder.add(first, consumed);
                builder.connect_if_true(belongs, page.first_leaf, page_first);
                let remaining = builder.sub(row.leaf_count, consumed);
                builder.range_check(remaining, 6);
                let width = builder.constant(F::from_canonical_u32(32));
                let available = builder.sub(width, page.offset);
                let shorter = builder.is_less_than(6, remaining, available);
                let take = builder.select(shorter, remaining, available);
                builder.connect_if_true(belongs, page.leaf_count, take);
                for limb in 0..4 {
                    builder.connect_if_true(belongs, page.append.old_root.elements[limb], rolling_root[limb]);
                    builder.connect_if_true(belongs, page_accumulators[index].0[limb], row_accumulator[limb]);
                    rolling_root[limb] = builder.select(belongs, page.append.new_root.elements[limb], rolling_root[limb]);
                    row_accumulator[limb] = builder.select(belongs, page_accumulators[index].1[limb], row_accumulator[limb]);
                }
                rolling_count = builder.select(belongs, page.new_count, rolling_count);
                let take = builder.select(belongs, page.leaf_count, zero);
                consumed = builder.add(consumed, take);
                builder.range_check(consumed, 6);
                builder.ensure_is_less_than_or_equal(6, consumed, row.leaf_count);
            }
            builder.connect(consumed, row.leaf_count);
            builder.connect(rolling_count, row.new_count);
            for limb in 0..4 { builder.connect(rolling_root[limb], row.new_root[limb]); }
            let end_accumulator = accumulator_at(builder, &checkpoints, next);
            for limb in 0..4 { builder.connect(row_accumulator[limb], end_accumulator[limb]); }
            first = next;
            rows.push(row);
        }
        builder.connect(first, count);
        for (page, matches) in pages.iter().zip(memberships) { builder.connect(matches, page.active.target); }
        for limb in 0..4 { builder.connect(row_accumulator[limb], accumulator[limb]); }

        // Exactly N distinct addresses into exactly N eligible slots gives exact coverage.
        // The lookup consumes the same hashes as the single global accumulator fold.
        let mut addresses = Vec::with_capacity(DEPOSIT_RECORD_CAPACITY);
        for index in 0..DEPOSIT_RECORD_CAPACITY {
            let address = builder.add_virtual_target();
            let bits = builder.split_le(address, 9);
            let position = builder.le_sum(bits[..5].iter());
            let page_index = builder.le_sum(bits[5..].iter());
            let active = active_records[index];
            let inactive = builder.not(active);
            builder.connect_zero_if_true(inactive, address);
            if let Some(previous) = addresses.last() {
                let ordered = builder.is_less_than(9, *previous, address);
                builder.connect_if_true(active, ordered.target, one);
            }
            let selected: Vec<_> = (0..6).map(|field| {
                let values = pages.iter().map(|page| [page.active.target, page.offset, page.leaf_count, page.first_leaf, page.chain_index, page.old_count][field]).collect();
                builder.random_access(page_index, values)
            }).collect();
            builder.connect_if_true(active, selected[0], one);
            let before = builder.is_less_than(6, position, selected[1]);
            builder.connect_zero_if_true(active, before.target);
            let end = builder.add(selected[1], selected[2]);
            let inside = builder.is_less_than(7, position, end);
            builder.connect_if_true(active, inside.target, one);
            let delta = builder.sub(position, selected[1]);
            let ordinal = builder.add(selected[3], delta);
            let expected = builder.constant(F::from_canonical_usize(index));
            builder.connect_if_true(active, ordinal, expected);
            builder.connect_if_true(active, leaves[index].chain_index, selected[4]);
            let absolute = builder.add(selected[5], delta);
            builder.connect_if_true(active, leaves[index].absolute_index, absolute);
            for limb in 0..4 {
                // Select within each full page, then select the page; a 512-item
                // RandomAccessGate cannot fit the standard 80 routed wires.
                let values = pages.iter().map(|page| {
                    let values = page.append.web_proof.new_leaves.iter().map(|hash| hash.elements[limb]).collect();
                    builder.random_access(position, values)
                }).collect();
                let selected_hash = builder.random_access(page_index, values);
                builder.connect_if_true(active, selected_hash, hashes[index][limb]);
            }
            addresses.push(address);
        }
        let prefix = [2, 11, 1, 0].map(|value| builder.constant(F::from_canonical_u32(value)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&context.config_hash);
        builder.register_public_inputs(&window_id);
        builder.register_public_inputs(&context.end_id);
        builder.register_public_inputs(&context.end_root);
        builder.register_public_input(count);
        for row in &rows { row.register(builder); }
        for leaf in &leaves { builder.register_public_inputs(&leaf_words(leaf)); }
        Self { context, window_id, rows, leaves, pages, addresses }
    }

    fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, opening: &DepositAggregateOpening, pages: &[DepositSpidermanAppendInputs]) -> anyhow::Result<()> {
        anyhow::ensure!(config.chains.len() == self.rows.len(), "source chain count mismatch");
        opening.validate(config)?;
        anyhow::ensure!(opening.deposit_leaves.len() <= DEPOSIT_RECORD_CAPACITY, "deposit capacity exceeded");
        anyhow::ensure!(pages.len() <= self.pages.len(), "deposit page capacity exceeded");
        self.context.set_witness(witness, &ChainContext { config_hash: opening.config_hash, end_checkpoint_id: opening.end_checkpoint_id,
            end_checkpoint_root: opening.end_checkpoint_root, global_deposit_count: opening.deposit_leaves.len() as u32 })?;
        set_bytes(witness, &self.window_id, &opening.window_id)?;
        let mut first = 0;
        for (index, target) in self.rows.iter().enumerate() {
            let transition = &opening.deposits[index];
            let count = transition.new_count.checked_sub(transition.old_count).ok_or_else(|| anyhow::anyhow!("deposit count decreased"))?;
            target.set_witness(witness, &ChainRow { start: opening.starts[index].clone(), transition: transition.clone(), range: DepositLeafRange { first_leaf: first, leaf_count: count } })?;
            first += count;
        }
        let padding = DepositLeaf { chain_index: 0, absolute_index: 0, shield_address: [0; 32], token: [0; 20], l2_token_contract_id: [0; 32], amount: [0; 32], note_commitment: [0; 32] };
        for (index, leaf) in self.leaves.iter().enumerate() { set_leaf(witness, leaf, opening.deposit_leaves.get(index).unwrap_or(&padding))?; }
        let mut addresses = vec![0; DEPOSIT_RECORD_CAPACITY];
        let mut consumed = 0usize;
        for (index, target) in self.pages.iter().enumerate() {
            target.set_witness(witness, pages.get(index))?;
            if let Some(page) = pages.get(index) {
                anyhow::ensure!(page.first_leaf as usize == consumed, "noncanonical page range");
                let end = consumed.checked_add(page.leaf_count as usize).ok_or_else(|| anyhow::anyhow!("page range overflow"))?;
                anyhow::ensure!(end <= opening.deposit_leaves.len(), "page range exceeds opening");
                for (offset, address) in addresses[consumed..end].iter_mut().enumerate() {
                    *address = index * 32 + (page.old_count % 32) as usize + offset;
                }
                consumed = end;
            }
        }
        anyhow::ensure!(consumed == opening.deposit_leaves.len(), "incomplete page coverage");
        for (target, address) in self.addresses.iter().zip(addresses) { witness.set_target(*target, F::from_canonical_usize(address))?; }
        Ok(())
    }
}

fn set_leaf(witness: &mut PartialWitness<F>, target: &DepositLeafTarget, leaf: &DepositLeaf) -> anyhow::Result<()> {
    witness.set_target(target.chain_index, F::from_canonical_u8(leaf.chain_index))?;
    witness.set_target(target.absolute_index, F::from_canonical_u32(leaf.absolute_index))?;
    set_bytes(witness, &target.shield_address, &leaf.shield_address)?;
    set_bytes(witness, &target.token, &leaf.token)?;
    set_bytes(witness, &target.l2_token_contract_id, &leaf.l2_token_contract_id)?;
    set_bytes(witness, &target.amount, &leaf.amount)?;
    set_bytes(witness, &target.note_commitment, &leaf.note_commitment)
}

pub struct DepositAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize> where F: Extendable<D> {
    pub circuit_data: CircuitData<F, C, D>,
    opening: DepositAggregateOpeningTarget,
}
impl<C: GenericConfig<D, F = F>, const D: usize> DepositAggregateCircuit<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn new(chain_count: usize) -> Self {
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let opening = DepositAggregateOpeningTarget::build(&mut builder, chain_count);
        #[cfg(test)]
        eprintln!("[deposit-aggregate] phase=prebuild chains={chain_count} emitted_prebuild_gates={}", builder.num_gates());
        let circuit_data = builder.build::<C>();
        assert_eq!(circuit_data.common.num_public_inputs, deposit_aggregate_pi_len(chain_count));
        Self { circuit_data, opening }
    }
    pub fn prove(&self, config: &NetworkConfig, opening: &DepositAggregateOpening, pages: &[DepositSpidermanAppendInputs]) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.opening.set_witness(&mut witness, config, opening, pages)?;
        self.circuit_data.prove(witness)
    }
    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> { self.circuit_data.verify(proof) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, spiderman::SpidermanUpdateProof, traits::MerkleLeafHasher}, pgoldilocks::{PoseidonHasher, QHashOut}};
    use plonky2::{field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::PoseidonGoldilocksConfig};
    use psy_client_data::bridge_aggregate::{ChainConfig, ChainStart, DepositTransition};

    type C = PoseidonGoldilocksConfig;

    fn hash(value: u32) -> QHashOut<F> { QHashOut(HashOut { elements: [F::from_canonical_u32(value); 4] }) }
    fn words(value: QHashOut<F>) -> [u64; 4] { value.0.elements.map(|limb| limb.to_canonical_u64()) }

    // Independent ordinary height-32 tree builds both endpoint roots and full old pages.
    fn fixture(counts: &[(u32, usize)]) -> (NetworkConfig, DepositAggregateOpening, Vec<DepositSpidermanAppendInputs>) {
        let config = NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: 524288, circuit_set_hash: [7; 32],
            chains: counts.iter().enumerate().map(|(index, _)| ChainConfig {
                chain_index: index as u8, chain_id: [index as u8 + 1; 32], bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [1, 2, 3, 4],
            }).collect(),
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: [1; 32], reward_token_decimals: 0,
            max_withdrawals: 1024, max_rewards: 1024,
        };
        let mut opening = DepositAggregateOpening {
            config_hash: config.config_hash().unwrap(), window_id: [0; 32], end_checkpoint_id: 1, end_checkpoint_root: [5, 6, 7, 8],
            starts: vec![], deposits: vec![], deposit_leaves: vec![],
        };
        let mut pages = vec![];
        for (chain, &(old_count, count)) in counts.iter().enumerate() {
            let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(32);
            for index in 0..old_count { tree.set_leaf(u64::from(index), hash(index + 1)); }
            let old_root = words(tree.get_root());
            let mut consumed = 0;
            while consumed < count {
                let current = old_count + consumed as u32;
                let offset = (current % 32) as usize;
                let take = (32 - offset).min(count - consumed);
                let base = u64::from(current - offset as u32);
                let old_leaves: Vec<_> = (0..32).map(|index| tree.get_leaf_value(base + index)).collect();
                let siblings = tree.get_leaf(u64::from(current)).siblings[5..].to_vec();
                let first_leaf = opening.deposit_leaves.len() as u32;
                for index in 0..take {
                    let leaf = DepositLeaf {
                        chain_index: chain as u8, absolute_index: current + index as u32,
                        shield_address: [11; 32], token: [12; 20], l2_token_contract_id: [13; 32], amount: [14; 32], note_commitment: [15; 32],
                    };
                    let leaf_hash = QHashOut(HashOut { elements: leaf.poseidon_hash().unwrap().map(F::from_canonical_u64) });
                    tree.set_leaf(u64::from(leaf.absolute_index), leaf_hash);
                    opening.deposit_leaves.push(leaf);
                }
                let new_leaves: Vec<_> = (0..32).map(|index| tree.get_leaf_value(base + index)).collect();
                let top_line_proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(u64::from(current / 32),
                    PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap(), PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap(), siblings);
                assert_eq!(top_line_proof.new_root, tree.get_root());
                pages.push(DepositSpidermanAppendInputs { chain_index: chain as u8, old_count: current, first_leaf, leaf_count: take as u32,
                    append_proof: SpidermanUpdateProof { top_line_proof, web_proof_old_leaves: old_leaves, web_proof_new_leaves: new_leaves } });
                consumed += take;
            }
            opening.starts.push(ChainStart { chain_index: chain as u8, start_checkpoint_id: 0, start_checkpoint_root: [1, 2, 3, 4] });
            opening.deposits.push(DepositTransition { chain_index: chain as u8, old_root, new_root: words(tree.get_root()), old_count, new_count: old_count + count as u32 });
        }
        opening.window_id = opening.window_id().unwrap();
        (config, opening, pages)
    }

    fn witness(circuit: &DepositAggregateCircuit<C, 2>, fixture: &(NetworkConfig, DepositAggregateOpening, Vec<DepositSpidermanAppendInputs>)) -> PartialWitness<F> {
        let mut witness = PartialWitness::new();
        circuit.opening.set_witness(&mut witness, &fixture.0, &fixture.1, &fixture.2).unwrap();
        witness
    }

    fn reject(circuit: &DepositAggregateCircuit<C, 2>, witness: PartialWitness<F>) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| circuit.circuit_data.prove(witness)));
        assert!(!matches!(result, Ok(Ok(_))), "malicious raw witness produced a proof");
    }

    #[test]
    fn global_pages_cover_empty_unaligned_crossing_and_maximum_pool() {
        for chain_count in [8, 1, 3, 4, 5, 6, 7] {
        let started = std::time::Instant::now();
        let circuit = DepositAggregateCircuit::<C, 2>::new(chain_count);
        eprintln!("[deposit-aggregate] phase=construction chains={chain_count} degree_bits={} rows={} elapsed_ms={}",
            circuit.circuit_data.common.degree_bits(), circuit.circuit_data.common.degree(), started.elapsed().as_millis());
        let cases = if chain_count == 8 {
            vec![vec![(0, 0); 8], vec![(31, 4); 8], vec![(30, 3), (0, 0), (1, 2), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)], vec![(0, 32), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)]]
        } else {
            let mut counts = vec![(0, 0); chain_count];
            counts[0] = (31, DEPOSIT_RECORD_CAPACITY);
            vec![counts]
        };
        for counts in cases {
            let fixture = fixture(&counts);
            if counts == vec![(31, 4); 8] { assert_eq!(fixture.2.len(), 16); }
            if chain_count != 8 {
                assert_eq!(fixture.1.deposit_leaves.len(), DEPOSIT_RECORD_CAPACITY);
                assert_eq!(fixture.2.len(), 2);
            }
            let witness = witness(&circuit, &fixture);
            let started = std::time::Instant::now();
            let proof = circuit.circuit_data.prove(witness).unwrap();
            eprintln!("[deposit-aggregate] phase=prove chains={chain_count} counts={counts:?} records={} pages={} elapsed_ms={}",
                fixture.1.deposit_leaves.len(), fixture.2.len(), started.elapsed().as_millis());
            assert_eq!(proof.public_inputs.len(), deposit_aggregate_pi_len(chain_count));
            assert_eq!(proof.public_inputs[..4], [2, 11, 1, 0].map(F::from_canonical_u32));
            assert_eq!(proof.public_inputs[26], F::from_canonical_usize(fixture.1.deposit_leaves.len()));
            let opening = &fixture.1;
            let mut expected = vec![2, 11, 1, 0];
            let bytes = |value: &[u8]| value.chunks_exact(4).map(|word| u64::from(u32::from_be_bytes(word.try_into().unwrap()))).collect::<Vec<_>>();
            expected.extend(bytes(&opening.config_hash));
            expected.extend(bytes(&opening.window_id));
            expected.extend([opening.end_checkpoint_id as u32 as u64, opening.end_checkpoint_id >> 32]);
            expected.extend(opening.end_checkpoint_root);
            expected.push(opening.deposit_leaves.len() as u64);
            for (start, transition) in opening.starts.iter().zip(&opening.deposits) {
                expected.extend([u64::from(start.chain_index), start.start_checkpoint_id as u32 as u64, start.start_checkpoint_id >> 32]);
                expected.extend(start.start_checkpoint_root);
                expected.extend(transition.old_root);
                expected.extend(transition.new_root);
                expected.extend([u64::from(transition.old_count), u64::from(transition.new_count)]);
            }
            for leaf in &opening.deposit_leaves {
                expected.extend([u64::from(leaf.chain_index), u64::from(leaf.absolute_index)]);
                for value in [&leaf.shield_address[..], &leaf.token[..], &leaf.l2_token_contract_id[..], &leaf.amount[..], &leaf.note_commitment[..]] {
                    expected.extend(bytes(value));
                }
            }
            expected.resize(deposit_aggregate_pi_len(chain_count), 0);
            assert_eq!(proof.public_inputs, expected.into_iter().map(F::from_canonical_u64).collect::<Vec<_>>());
            #[cfg(not(target_arch = "wasm32"))]
            if chain_count == 8 && fixture.2.len() == 16 {
                use crate::bridge::circuits::bridge_wrap::{BridgeOpeningChain, BridgeOpeningWrapper, DigestBitsSources};
                use psy_client_data::qdata::contract::PsyContractLeaf;
                use super::bridge_claim::BridgeTokenPolicy;
                assert_eq!(opening.deposit_leaves.len(), DEPOSIT_RECORD_CAPACITY);
                let chains: Vec<_> = fixture.0.chains.iter().map(|chain| BridgeOpeningChain {
                    chain_index: chain.chain_index, bootstrap_id: chain.bootstrap_id, bootstrap_root: chain.bootstrap_root,
                }).collect();
                // Serialization fixture labels only, not deployed source provenance.
                let sources = DigestBitsSources {
                    node_source: "1".repeat(40), native_source: "2".repeat(40),
                    plonky2_source: "3".repeat(40), wrapper_source: "4".repeat(40),
                };
                let policy = BridgeTokenPolicy {
                    chain_index: chains[0].chain_index, token_contract_id: 7, token_address: [0, 0, 0, 0x01020304, 5, 6, 7, 8],
                    approved_leaf: PsyContractLeaf { deployer: F::from_canonical_u64(9), state_tree_height: F::from_canonical_u64(32), ..PsyContractLeaf::default() },
                    map_base: 8, capacity: 4,
                };
                // A deposit source is 1411 public inputs at eight chains, not the 9340-word bridge opening (8316+128*8).
                assert!(BridgeOpeningWrapper::build(&circuit.circuit_data.common, &circuit.circuit_data.verifier_only,
                    &circuit.circuit_data.common, &circuit.circuit_data.verifier_only, sources, opening.config_hash, &chains, &[policy]).is_err());
            }
            circuit.verify(proof).unwrap();
        }
        }
    }

    #[test]
    fn raw_witness_rejects_routing_padding_roots_counts_and_changed_records() {
        let started = std::time::Instant::now();
        let circuit = DepositAggregateCircuit::<C, 2>::new(2);
        eprintln!("[deposit-aggregate] phase=construction chains=2 degree_bits={} rows={} elapsed_ms={}",
            circuit.circuit_data.common.degree_bits(), circuit.circuit_data.common.degree(), started.elapsed().as_millis());
        let fixture = fixture(&[(31, 3), (0, 1)]);
        let target = &circuit.opening;
        let mutations = [
            (target.addresses[1], 31), // duplicate address
            (target.addresses[0], 32), // wrong page and ordinal
            (target.addresses[2], 511), // inactive page
            (target.addresses[4], 1), // inactive address
            (target.leaves[0].absolute_index, 32),
            (target.leaves[1].chain_index, 1),
            (target.leaves[0].amount[0], 99), // same raw words must hash into page
            (target.leaves[4].note_commitment[0], 1),
            (target.pages[0].leaf_count, 0), // omit page
            (target.pages[0].leaf_count, 2), // crosses page boundary
            (target.pages[1].first_leaf, 2), // nonconsecutive page range
            (target.pages[1].old_count, 33),
            (target.pages[1].chain_index, 1),
            (target.pages[3].append.top_line_proof.siblings[0].elements[0], 1),
            (target.pages[3].append.web_proof.old_leaves[0].elements[0], 1),
            (target.pages[3].append.web_proof.new_leaves[0].elements[0], 1),
            (target.pages[0].append.web_proof.old_leaves[0].elements[0], 99),
            (target.pages[0].append.web_proof.new_leaves[0].elements[0], 99),
            (target.rows[0].new_root[0], 99),
            (target.rows[0].old_count, u32::MAX as u64),
            (target.rows[0].new_count, 1),
            (target.rows[1].chain_index, 0),
            (target.context.global_deposit_count, 33),
            (target.context.end_id[1], 1),
        ];
        for (target, value) in mutations {
            let mut witness = witness(&circuit, &fixture);
            witness.target_values.insert(target, F::from_canonical_u64(value));
            reject(&circuit, witness);
        }
    }

    #[test]
    fn empty_rows_preserve_endpoints_and_equal_checkpoint_roots() {
        let started = std::time::Instant::now();
        let circuit = DepositAggregateCircuit::<C, 2>::new(2);
        eprintln!("[deposit-aggregate] phase=construction chains=2 degree_bits={} rows={} elapsed_ms={}",
            circuit.circuit_data.common.degree_bits(), circuit.circuit_data.common.degree(), started.elapsed().as_millis());
        let mut fixture = fixture(&[(1, 0), (31, 0)]);
        for start in &mut fixture.1.starts {
            start.start_checkpoint_id = fixture.1.end_checkpoint_id;
            start.start_checkpoint_root = fixture.1.end_checkpoint_root;
        }
        fixture.1.window_id = fixture.1.window_id().unwrap();
        let proof_witness = witness(&circuit, &fixture);
        let started = std::time::Instant::now();
        let proof = circuit.circuit_data.prove(proof_witness).unwrap();
        eprintln!("[deposit-aggregate] phase=prove chains=2 records={} pages={} elapsed_ms={}",
            fixture.1.deposit_leaves.len(), fixture.2.len(), started.elapsed().as_millis());
        circuit.verify(proof).unwrap();
        for target in [circuit.opening.rows[0].new_root[0], circuit.opening.rows[0].new_count,
            circuit.opening.rows[1].start_root[0], circuit.opening.pages[0].append.top_line_proof.index] {
            let mut witness = witness(&circuit, &fixture);
            let value = witness.target_values.get(&target).copied().unwrap_or(F::ZERO);
            witness.target_values.insert(target, value + F::ONE);
            reject(&circuit, witness);
        }
    }
}
