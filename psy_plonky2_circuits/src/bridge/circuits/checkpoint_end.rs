use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs},
};
use psy_client_data::bridge_aggregate::NetworkConfig;
use psy_data::v1::qdata::{checkpoint::{PQEDCheckpointLeaf, PQEDCheckpointGlobalStateRoots}, user::PQEDUserLeaf};
use psy_plonky2_basic_helpers::builder::{hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers};
use psy_plonky2_common_circuits::{
    bridge::{aggregate_commitment::{chain_ends_hash, ChainEndTarget}, aggregate_config::NetworkConfigTarget},
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    traits::CreatableTarget,
};
use crate::{
    bridge::gadgets::slot_value_in_contract_state::{SlotValueInContractStateGadget, SlotValueInContractStateWitnessInput},
    gadgets::qdata::{checkpoint::QEDCheckpointLeafGadget, checkpoint_state_roots::QEDCheckpointGlobalStateRootsGadget, user::QEDUserLeafGadget},
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};

pub const CHECKPOINT_END_PI_LEN: usize = 30;

#[derive(Clone, Debug)]
pub struct CheckpointEndChainWitness {
    /// Count, first four root words, last four root words, in this order.
    pub deposit: [SlotValueInContractStateWitnessInput<GoldilocksField>; 3],
    pub withdrawal: [SlotValueInContractStateWitnessInput<GoldilocksField>; 3],
}

#[derive(Clone, Debug)]
pub struct CheckpointEndWitness {
    pub config: NetworkConfig,
    pub end_id: u64,
    pub end_root: QHashOut<GoldilocksField>,
    pub end_leaf: PQEDCheckpointLeaf<GoldilocksField, QHashOut<GoldilocksField>>,
    pub end_path: MerkleProofCore<QHashOut<GoldilocksField>>,
    pub global_state_roots: PQEDCheckpointGlobalStateRoots<QHashOut<GoldilocksField>>,
    pub user_leaf: PQEDUserLeaf<GoldilocksField, QHashOut<GoldilocksField>>,
    pub user_path: MerkleProofCore<QHashOut<GoldilocksField>>,
    pub chains: Vec<CheckpointEndChainWitness>,
}

pub struct CheckpointEndChainTarget {
    pub deposit: [SlotValueInContractStateGadget; 3],
    pub withdrawal: [SlotValueInContractStateGadget; 3],
    pub end: ChainEndTarget,
}

pub struct CheckpointEndCircuit<C: GenericConfig<D, F = GoldilocksField>, const D: usize>
where
    GoldilocksField: Extendable<D>,
{
    pub config: NetworkConfigTarget,
    pub end_id: [Target; 2],
    pub end_leaf: QEDCheckpointLeafGadget,
    pub end_path: MerkleProofGadget,
    pub global_state_roots: QEDCheckpointGlobalStateRootsGadget,
    pub user_leaf: QEDUserLeafGadget,
    pub user_path: MerkleProofGadget,
    pub chains: Vec<CheckpointEndChainTarget>,
    pub circuit_data: CircuitData<GoldilocksField, C, D>,
    pub fingerprint: QHashOut<GoldilocksField>,
}

fn root_and_count<H: AlgebraicHasher<GoldilocksField> + MerkleZeroHasher<HashOut<GoldilocksField>>, const D: usize>(
    builder: &mut CircuitBuilder<GoldilocksField, D>,
    slots: &[SlotValueInContractStateGadget; 3],
    chain_index: Target,
) -> ([Target; 4], Target)
where GoldilocksField: Extendable<D> {
    let bits = builder.split_le(chain_index, 8);
    let quotient = builder.le_sum(bits.iter().skip(2));
    let count_index = builder.add_const(quotient, GoldilocksField::from_canonical_u64(16_386));
    builder.connect(slots[0].slot_index, count_index);
    let twice_chain = builder.add(chain_index, chain_index);
    let first_index = builder.add_const(twice_chain, GoldilocksField::from_canonical_u64(16_451));
    let second_index = builder.add_const(first_index, GoldilocksField::ONE);
    builder.connect(slots[1].slot_index, first_index);
    builder.connect(slots[2].slot_index, second_index);
    let values = slots[0].slot_proof.value.elements;
    let low = builder.select(bits[0], values[1], values[0]);
    let high = builder.select(bits[0], values[3], values[2]);
    let count = builder.select(bits[1], high, low);
    builder.range_check(count, 32);
    let words: [Target; 8] = std::array::from_fn(|i| slots[1 + i / 4].slot_proof.value.elements[i % 4]);
    let zero = builder.zero();
    let mut uninitialized = builder.is_equal(count, zero);
    for word in words {
        builder.range_check(word, 32);
        let is_zero = builder.is_equal(word, zero);
        uninitialized = builder.and(uninitialized, is_zero);
    }
    let maximum = builder.constant(GoldilocksField::from_canonical_u32(u32::MAX));
    let empty = H::get_zero_hash(32);
    let root = std::array::from_fn(|i| {
        let low = words[2 * i];
        let high = words[2 * i + 1];
        let high_is_maximum = builder.is_equal(high, maximum);
        let excess = builder.mul(high_is_maximum.target, low);
        builder.assert_zero(excess);
        let decoded = builder.mul_const_add(GoldilocksField::from_canonical_u64(1u64 << 32), high, low);
        let empty_limb = builder.constant(empty.elements[i]);
        builder.select(uninitialized, empty_limb, decoded)
    });
    (root, count)
}

impl<C: GenericConfig<D, F = GoldilocksField>, const D: usize> CheckpointEndCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<GoldilocksField> + MerkleZeroHasher<HashOut<GoldilocksField>>,
    GoldilocksField: Extendable<D>,
{
    /// All sizes are source/artifact parameters, never witness values.
    pub fn new(source_chain_count: usize, checkpoint_tree_height: usize, global_user_tree_height: usize,
        global_contract_tree_height: usize, deposit_state_tree_height: usize, withdrawal_state_tree_height: usize) -> Self {
        assert!((1..=256).contains(&source_chain_count));
        assert!((1..=63).contains(&checkpoint_tree_height));
        assert!((20..=63).contains(&global_user_tree_height));
        assert!((2..=63).contains(&global_contract_tree_height));
        assert!((15..=63).contains(&deposit_state_tree_height));
        assert!((15..=63).contains(&withdrawal_state_tree_height));
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let config_hash = config.hash(&mut builder);
        let bridge_user_id = builder.constant(GoldilocksField::from_canonical_u64(524_288));
        builder.connect(config.bridge_user_id, bridge_user_id);
        let end_id = std::array::from_fn(|_| builder.add_virtual_target());
        for word in end_id { builder.range_check(word, 32); }
        let end_leaf = QEDCheckpointLeafGadget::create_virtual(&mut builder);
        let end_leaf_hash = end_leaf.to_hash::<C::Hasher, _, D>(&mut builder);
        let end_path = MerkleProofGadget::add_virtual_to::<C::Hasher, _, D>(&mut builder, checkpoint_tree_height);
        builder.connect_hashes(end_path.value, end_leaf_hash);
        let bits = builder.split_le(end_path.index, checkpoint_tree_height);
        let low = builder.le_sum(bits.iter().take(32));
        let high = builder.le_sum(bits.iter().skip(32));
        builder.connect(end_id[0], low);
        builder.connect(end_id[1], high);
        let global_state_roots = QEDCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let global_state_roots_hash = global_state_roots.to_hash::<C::Hasher, _, D>(&mut builder);
        builder.connect_hashes(end_leaf.global_chain_root, global_state_roots_hash);
        let user_leaf = QEDUserLeafGadget::create_virtual(&mut builder);
        builder.connect(user_leaf.user_id, bridge_user_id);
        let user_hash = user_leaf.to_hash::<C::Hasher, _, D>(&mut builder);
        let user_path = MerkleProofGadget::add_virtual_to::<C::Hasher, _, D>(&mut builder, global_user_tree_height);
        builder.connect(user_path.index, bridge_user_id);
        builder.connect_hashes(user_path.value, user_hash);
        builder.connect_hashes(user_path.root, global_state_roots.user_tree_root);
        let chains = config.chains.iter().map(|chain| {
            let mut create_slots = |contract_id: u64, height: usize| {
                let contract_id = builder.constant(GoldilocksField::from_canonical_u64(contract_id));
                std::array::from_fn(|_| {
                    let slot = SlotValueInContractStateGadget::add_virtual_to::<C::Hasher, _, D>(
                        &mut builder, global_user_tree_height, global_contract_tree_height, height);
                    builder.connect(slot.sender_user_id, bridge_user_id);
                    builder.connect(slot.contract_id, contract_id);
                    slot.user_leaf.connect_to_other(&mut builder, user_leaf);
                    builder.connect_hashes(slot.user_tree_root, global_state_roots.user_tree_root);
                    builder.connect_hashes(slot.user_tree_proof.value, user_hash);
                    slot
                })
            };
            let deposit = create_slots(2, deposit_state_tree_height);
            let withdrawal = create_slots(3, withdrawal_state_tree_height);
            let (deposit_root, deposit_count) = root_and_count::<C::Hasher, D>(&mut builder, &deposit, chain.chain_index);
            let (withdrawal_root, _) = root_and_count::<C::Hasher, D>(&mut builder, &withdrawal, chain.chain_index);
            CheckpointEndChainTarget { deposit, withdrawal, end: ChainEndTarget {
                chain_index: chain.chain_index, deposit_root, deposit_count, withdrawal_root,
            } }
        }).collect::<Vec<_>>();
        let ends = chains.iter().map(|chain| chain.end).collect::<Vec<_>>();
        let ends_hash = chain_ends_hash(&mut builder, &ends);
        for value in [1, 6, 0, 0] {
            let target = builder.constant(GoldilocksField::from_canonical_u64(value));
            builder.register_public_input(target);
        }
        builder.register_public_inputs(&config_hash);
        builder.register_public_inputs(&end_id);
        builder.register_public_inputs(&end_path.root.elements);
        builder.register_public_inputs(&end_leaf_hash.elements);
        builder.register_public_inputs(&ends_hash);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self { config, end_id, end_leaf, end_path, global_state_roots, user_leaf, user_path, chains, circuit_data, fingerprint }
    }

    pub fn prove(&self, input: &CheckpointEndWitness) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, C, D>> {
        anyhow::ensure!(input.chains.len() == self.chains.len(), "configured chain count mismatch");
        anyhow::ensure!(input.end_path.siblings.len() == self.end_path.siblings.len(), "checkpoint path height mismatch");
        anyhow::ensure!(input.user_path.siblings.len() == self.user_path.siblings.len(), "user path height mismatch");
        anyhow::ensure!(input.end_path.index == input.end_id, "checkpoint path index mismatch");
        anyhow::ensure!(input.user_path.index == 524_288, "bridge user path index mismatch");
        anyhow::ensure!(input.config.chains.len() == self.chains.len(), "configuration chain count mismatch");
        for (chain, config) in input.chains.iter().zip(&input.config.chains) {
            let index = u64::from(config.chain_index);
            let slots = [16_386 + index / 4, 16_451 + 2 * index, 16_452 + 2 * index];
            for (contract_id, values) in [(2, &chain.deposit), (3, &chain.withdrawal)] {
                for (value, slot_index) in values.iter().zip(slots) {
                    anyhow::ensure!(value.sender_user_id == 524_288 && value.user_tree_proof.index == 524_288,
                        "slot user path index mismatch");
                    anyhow::ensure!(value.contract_id == contract_id && value.contract_proof.index == contract_id,
                        "slot contract path index mismatch");
                    anyhow::ensure!(value.slot_index == slot_index && value.slot_proof.index == slot_index,
                        "contract state path index mismatch");
                }
            }
        }
        let mut witness = PartialWitness::new();
        self.config.set_witness(&mut witness, &input.config)?;
        witness.set_target(self.end_id[0], GoldilocksField::from_canonical_u32(input.end_id as u32))?;
        witness.set_target(self.end_id[1], GoldilocksField::from_canonical_u32((input.end_id >> 32) as u32))?;
        witness.set_hash_target(self.end_path.root, input.end_root.0)?;
        self.end_leaf.set_witness(&mut witness, &input.end_leaf)?;
        self.end_path.set_witness_core_proof_q(&mut witness, &input.end_path)?;
        self.global_state_roots.set_witness(&mut witness, &input.global_state_roots)?;
        self.user_leaf.set_witness(&mut witness, &input.user_leaf)?;
        self.user_path.set_witness_core_proof_q(&mut witness, &input.user_path)?;
        for (targets, values) in self.chains.iter().zip(&input.chains) {
            for (target, value) in targets.deposit.iter().chain(&targets.withdrawal).zip(values.deposit.iter().chain(&values.withdrawal)) {
                anyhow::ensure!(value.slot_proof.siblings.len() == target.slot_proof.siblings.len()
                    && value.contract_proof.siblings.len() == target.contract_proof.siblings.len()
                    && value.user_tree_proof.siblings.len() == target.user_tree_proof.siblings.len(), "slot path height mismatch");
                target.set_witness(&mut witness, value)?;
            }
        }
        self.circuit_data.prove(witness)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<GoldilocksField, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use parth_core::{crypto::hash::traits::{MerkleHasher, QFieldHashable}, pgoldilocks::PoseidonHasher};
    use plonky2::{field::types::PrimeField64, plonk::config::PoseidonGoldilocksConfig};
    use psy_client_data::bridge_aggregate::{ChainConfig, ChainEnd};
    use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafStats;

    fn path(leaves: &[(u64, QHashOut<GoldilocksField>)], index: u64, height: usize) -> MerkleProofCore<QHashOut<GoldilocksField>> {
        let mut nodes = leaves.iter().copied().collect::<BTreeMap<_, _>>();
        let value = nodes.get(&index).copied().unwrap_or(QHashOut::ZERO);
        let mut position = index;
        let mut siblings = Vec::new();
        for level in 0..height {
            let zero = <PoseidonHasher as MerkleZeroHasher<QHashOut<GoldilocksField>>>::get_zero_hash(level);
            siblings.push(nodes.get(&(position ^ 1)).copied().unwrap_or(zero));
            let mut parents = BTreeMap::new();
            for &child in nodes.keys() {
                let left = nodes.get(&(child & !1)).copied().unwrap_or(zero);
                let right = nodes.get(&(child | 1)).copied().unwrap_or(zero);
                parents.insert(child >> 1, PoseidonHasher::two_to_one(&left, &right));
            }
            nodes = parents;
            position >>= 1;
        }
        MerkleProofCore { root: nodes[&0], value, index, siblings }
    }

    fn fixture(chain_index: u8, deposit_count: u64, deposit_words: [u64; 8]) -> CheckpointEndWitness {
        let count_index = 16_386 + u64::from(chain_index) / 4;
        let root_index = 16_451 + 2 * u64::from(chain_index);
        let mut count = QHashOut::ZERO;
        count.0.elements[usize::from(chain_index % 4)] = GoldilocksField::from_canonical_u64(deposit_count);
        let root0 = QHashOut(HashOut { elements: std::array::from_fn(|i| GoldilocksField::from_canonical_u64(deposit_words[i])) });
        let root1 = QHashOut(HashOut { elements: std::array::from_fn(|i| GoldilocksField::from_canonical_u64(deposit_words[4 + i])) });
        let leaves = [(count_index, count), (root_index, root0), (root_index + 1, root1)];
        let withdrawal_leaves = [(count_index, count), (root_index, QHashOut(HashOut { elements: [9, 0, 8, 0].map(GoldilocksField::from_canonical_u64) })), (root_index + 1, root1)];
        let slot_paths = [leaves, withdrawal_leaves].map(|leaves| [count_index, root_index, root_index + 1].map(|index| path(&leaves, index, 15)));
        let empty_state = <PoseidonHasher as MerkleZeroHasher<QHashOut<GoldilocksField>>>::get_zero_hash(15);
        let contracts = [0, 1].map(|i| (i as u64 + 2, if slot_paths[i][0].root == empty_state { QHashOut::ZERO } else { slot_paths[i][0].root }));
        let contract_paths = [path(&contracts, 2, 2), path(&contracts, 3, 2)];
        let user_leaf = PQEDUserLeaf::new(QHashOut::ZERO, contract_paths[0].root,
            GoldilocksField::ONE, GoldilocksField::ONE, GoldilocksField::ZERO,
            GoldilocksField::ZERO, GoldilocksField::from_canonical_u64(524_288));
        let user_path = path(&[(524_288, user_leaf.qfhash::<PoseidonHasher>())], 524_288, 20);
        let global_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: QHashOut::ZERO, deposit_tree_root: QHashOut::ZERO,
            user_tree_root: user_path.root, withdrawal_tree_root: QHashOut::ZERO,
            user_registration_tree_root: QHashOut::ZERO, validator_tree_root: QHashOut::ZERO,
        };
        let end_leaf = PQEDCheckpointLeaf { global_chain_root: global_state_roots.qfhash::<PoseidonHasher>(), stats: PQEDCheckpointLeafStats::new_empty() };
        let end_path = path(&[(1, end_leaf.qfhash::<PoseidonHasher>())], 1, 4);
        let slots = |contract: usize| std::array::from_fn(|i| SlotValueInContractStateWitnessInput {
            sender_user_id: 524_288, contract_id: contract as u64 + 2, slot_index: slot_paths[contract][i].index,
            user_leaf, slot_proof: slot_paths[contract][i].clone(), contract_proof: contract_paths[contract].clone(), user_tree_proof: user_path.clone(),
        });
        CheckpointEndWitness {
            config: NetworkConfig {
                version: 1, network_magic: 0, bridge_user_id: 524_288, circuit_set_hash: [7; 32],
                chains: vec![ChainConfig { chain_index, chain_id: [1; 32], bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [0; 4] }],
                ethereum_index: chain_index, reward_payer: [3; 20], reward_token: [4; 20],
                reward_per_claim: [1; 32], reward_token_decimals: 18, reward_cutover: 0,
                reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
            },
            end_id: 1, end_root: end_path.root, end_leaf, end_path, global_state_roots,
            user_leaf, user_path: user_path.clone(), chains: vec![CheckpointEndChainWitness { deposit: slots(0), withdrawal: slots(1) }],
        }
    }

    fn prove_targets(circuit: &CheckpointEndCircuit<PoseidonGoldilocksConfig, 2>, input: &CheckpointEndWitness) -> anyhow::Result<()> {
        let mut witness = PartialWitness::new();
        circuit.config.set_witness(&mut witness, &input.config)?;
        witness.set_target(circuit.end_id[0], GoldilocksField::from_canonical_u32(input.end_id as u32))?;
        witness.set_target(circuit.end_id[1], GoldilocksField::from_canonical_u32((input.end_id >> 32) as u32))?;
        witness.set_hash_target(circuit.end_path.root, input.end_root.0)?;
        circuit.end_leaf.set_witness(&mut witness, &input.end_leaf)?;
        circuit.end_path.set_witness_core_proof_q(&mut witness, &input.end_path)?;
        circuit.global_state_roots.set_witness(&mut witness, &input.global_state_roots)?;
        circuit.user_leaf.set_witness(&mut witness, &input.user_leaf)?;
        circuit.user_path.set_witness_core_proof_q(&mut witness, &input.user_path)?;
        for (targets, values) in circuit.chains.iter().zip(&input.chains) {
            for (target, value) in targets.deposit.iter().chain(&targets.withdrawal).zip(values.deposit.iter().chain(&values.withdrawal)) {
                target.set_witness(&mut witness, value)?;
            }
        }
        let proof = circuit.circuit_data.prove(witness)?;
        circuit.circuit_data.verify(proof)
    }

    #[test]
    fn endpoint_authenticates_selectors_and_all_memberships() {
        let circuit = CheckpointEndCircuit::<PoseidonGoldilocksConfig, 2>::new(1, 4, 20, 2, 15, 15);
        let input = fixture(5, 7, [1, 0, 2, 0, 3, 0, 4, 0]);
        prove_targets(&circuit, &input).unwrap();
        let proof = circuit.prove(&input).unwrap();
        let expected = psy_client_data::bridge_aggregate::chain_ends_hash(&[ChainEnd {
            chain_index: 5, deposit_root: [1, 2, 3, 4], deposit_count: 7, withdrawal_root: [9, 8, 3, 4],
        }]).unwrap();
        let expected_words = expected.chunks_exact(4).map(|word| u32::from_be_bytes(word.try_into().unwrap()) as u64).collect::<Vec<_>>();
        assert_eq!(proof.public_inputs.len(), CHECKPOINT_END_PI_LEN);
        assert_eq!(proof.public_inputs[22..30].iter().map(|word| word.to_canonical_u64()).collect::<Vec<_>>(), expected_words);
        circuit.verify(proof).unwrap();
        for mutation in 0..6 {
            let mut wrong = input.clone();
            match mutation {
                0 => wrong.chains[0].deposit[0].slot_index += 1,
                1 => wrong.chains[0].deposit[1].slot_proof.value.0.elements[0] += GoldilocksField::ONE,
                2 => wrong.chains[0].withdrawal[0].contract_id = 2,
                3 => wrong.user_leaf.public_key.0.elements[0] = GoldilocksField::ONE,
                4 => wrong.end_id = 2,
                _ => wrong.end_leaf.stats.block_time = GoldilocksField::ONE,
            }
            assert!(circuit.prove(&wrong).is_err(), "mutation {mutation} accepted");
        }
        let mut wrong = input.clone();
        wrong.chains[0].withdrawal = wrong.chains[0].deposit.clone();
        assert!(prove_targets(&circuit, &wrong).is_err());
        let mut wrong = input.clone();
        let slots = &input.chains[0].deposit;
        let leaves = slots.iter().map(|slot| (slot.slot_index, slot.slot_proof.value)).collect::<Vec<_>>();
        wrong.chains[0].deposit[0].slot_index = 16_388;
        wrong.chains[0].deposit[0].slot_proof = path(&leaves, 16_388, 15);
        assert_eq!(wrong.chains[0].deposit[0].slot_proof.root, slots[0].slot_proof.root);
        assert!(prove_targets(&circuit, &wrong).is_err());
        for mutation in 0..5 {
            let mut wrong = input.clone();
            let index = match mutation {
                0 => &mut wrong.end_path.index,
                1 => &mut wrong.user_path.index,
                2 => &mut wrong.chains[0].deposit[0].slot_proof.index,
                3 => &mut wrong.chains[0].deposit[0].contract_proof.index,
                _ => &mut wrong.chains[0].deposit[0].user_tree_proof.index,
            };
            *index += 0xffff_ffff_0000_0001;
            assert!(circuit.prove(&wrong).is_err());
        }
    }

    #[test]
    fn endpoint_packing_and_empty_root_boundaries() {
        let circuit = CheckpointEndCircuit::<PoseidonGoldilocksConfig, 2>::new(1, 4, 20, 2, 15, 15);
        let input = fixture(255, u32::MAX as u64, [0, u32::MAX as u64, 2, 0, 3, 0, 4, 0]);
        circuit.verify(circuit.prove(&input).unwrap()).unwrap();
        let overflow = fixture(255, u32::MAX as u64 + 1, [1, 0, 2, 0, 3, 0, 4, 0]);
        assert!(circuit.prove(&overflow).is_err());
        let modulus = fixture(255, 1, [1, u32::MAX as u64, 2, 0, 3, 0, 4, 0]);
        assert!(circuit.prove(&modulus).is_err());
        let word_overflow = fixture(255, 1, [1u64 << 32, 0, 2, 0, 3, 0, 4, 0]);
        assert!(prove_targets(&circuit, &word_overflow).is_err());
        for count in [0, 1] {
            let input = fixture(255, count, [0; 8]);
            let proof = circuit.prove(&input).unwrap();
            let empty = <PoseidonHasher as MerkleZeroHasher<QHashOut<GoldilocksField>>>::get_zero_hash(32);
            let deposit_root = if count == 0 { empty.0.elements.map(|value| value.to_canonical_u64()) } else { [0; 4] };
            let expected = psy_client_data::bridge_aggregate::chain_ends_hash(&[ChainEnd {
                chain_index: 255, deposit_root, deposit_count: count as u32, withdrawal_root: [9, 8, 0, 0],
            }]).unwrap();
            let expected_words = expected.chunks_exact(4).map(|word| u32::from_be_bytes(word.try_into().unwrap()) as u64).collect::<Vec<_>>();
            assert_eq!(proof.public_inputs[22..30].iter().map(|word| word.to_canonical_u64()).collect::<Vec<_>>(), expected_words);
            circuit.verify(proof).unwrap();
        }
    }
}
