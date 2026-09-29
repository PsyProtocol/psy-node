use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    gates::gate::GateRef,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
};
use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeaf;
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore};
use psy_plonky2_common_circuits::{hash::merkle::gadgets::merkle_proof::MerkleProofGadget, traits::CreatableTarget};
use crate::{gadgets::qdata::checkpoint::QEDCheckpointLeafGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic};
use super::bridge_agg_final::{BridgeAggFinalCircuit, BRIDGE_AGG_FINAL_PI_LEN};

pub const CHECKPOINT_RANGE_PI_LEN: usize = 28;

pub struct CheckpointRangeWitness<'a, C: GenericConfig<D, F = GoldilocksField>, const D: usize>
where
    GoldilocksField: Extendable<D>,
{
    pub range_proof: &'a ProofWithPublicInputs<GoldilocksField, C, D>,
    pub config_hash: [u32; 8],
    pub start_id: u64,
    pub end_leaf: PQEDCheckpointLeaf<GoldilocksField, QHashOut<GoldilocksField>>,
    pub end_path: MerkleProofCore<QHashOut<GoldilocksField>>,
}

struct CheckpointRangeTargets {
    config_hash: [Target; 8],
    start_id: [Target; 2],
    end_leaf: QEDCheckpointLeafGadget,
    end_path: MerkleProofGadget,
}

pub struct CheckpointRangeCircuit<C: GenericConfig<D, F = GoldilocksField>, const D: usize>
where
    GoldilocksField: Extendable<D>,
{
    range_proof: ProofWithPublicInputsTarget<D>,
    targets: CheckpointRangeTargets,
    pub circuit_data: CircuitData<GoldilocksField, C, D>,
    pub fingerprint: QHashOut<GoldilocksField>,
}

impl<C: GenericConfig<D, F = GoldilocksField>, const D: usize> CheckpointRangeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<GoldilocksField> + MerkleZeroHasher<HashOut<GoldilocksField>>,
    GoldilocksField: Extendable<D>,
{
    pub fn new(
        range_circuit: &BridgeAggFinalCircuit<C, D>,
        checkpoint_tree_height: usize,
        common_gates: &[GateRef<GoldilocksField, D>],
        target_degree: Option<usize>,
    ) -> Self {
        let child = &range_circuit.circuit_data;
        assert_eq!(child.common.num_public_inputs, BRIDGE_AGG_FINAL_PI_LEN);
        assert_eq!(range_circuit.fingerprint.0, get_circuit_fingerprint_generic(&child.verifier_only));
        assert_eq!(range_circuit.checkpoint_delta_merkle_proofs[0].siblings.len(), checkpoint_tree_height);
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let range_proof = builder.add_virtual_proof_with_pis(&child.common);
        let verifier = builder.constant_verifier_data(&child.verifier_only);
        // Final owns the Chain fingerprint and cyclic-suffix checks; Final itself is acyclic.
        builder.verify_proof::<C>(&range_proof, &verifier, &child.common);
        let targets = CheckpointRangeTargets::build::<C, D>(&mut builder, &range_proof.public_inputs, checkpoint_tree_height);
        for gate in common_gates { builder.add_gate_to_gate_set(gate.clone()); }
        if let Some(degree) = target_degree {
            assert!(degree.is_power_of_two());
            let target_rows = degree.checked_sub(CHECKPOINT_RANGE_PI_LEN.div_ceil(8) + 2)
                .expect("checkpoint range degree is too small");
            assert!(builder.num_gates() <= target_rows, "checkpoint range exceeds target degree");
            while builder.num_gates() < target_rows {
                builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
            }
        }
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self { range_proof, targets, circuit_data, fingerprint }
    }

    pub fn prove(&self, input: &CheckpointRangeWitness<'_, C, D>) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, C, D>> {
        anyhow::ensure!(input.range_proof.public_inputs.len() == BRIDGE_AGG_FINAL_PI_LEN, "range proof public input width mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.range_proof, input.range_proof)?;
        self.targets.set_witness(&mut witness, input.config_hash, input.start_id, input.range_proof.public_inputs[24].to_canonical_u64(), &input.end_leaf, &input.end_path)?;
        self.circuit_data.prove(witness)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<GoldilocksField, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

impl CheckpointRangeTargets {
    fn build<C: GenericConfig<D, F = GoldilocksField>, const D: usize>(
        builder: &mut CircuitBuilder<GoldilocksField, D>,
        range: &[Target],
        checkpoint_tree_height: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<GoldilocksField>,
        GoldilocksField: Extendable<D>,
    {
        assert_eq!(range.len(), BRIDGE_AGG_FINAL_PI_LEN);
        assert!((1..=63).contains(&checkpoint_tree_height));
        let config_hash = std::array::from_fn(|_| builder.add_virtual_target());
        for word in config_hash { builder.range_check(word, 32); }
        let start_id = std::array::from_fn(|_| builder.add_virtual_target());
        for word in start_id { builder.range_check(word, 32); }
        let radix = GoldilocksField::from_canonical_u64(1 << 32);
        let start = builder.mul_const_add(radix, start_id[1], start_id[0]);
        if checkpoint_tree_height < 32 { builder.range_check(start_id[0], checkpoint_tree_height); }
        let end_bits = builder.split_le(range[24], checkpoint_tree_height);
        let end_id = [builder.le_sum(end_bits.iter().take(32)), builder.le_sum(end_bits.iter().skip(32))];
        let high_less = builder.is_less_than(32, start_id[1], end_id[1]);
        let high_equal = builder.is_equal(start_id[1], end_id[1]);
        if checkpoint_tree_height <= 32 {
            builder.assert_zero(start_id[1]);
        } else {
            builder.range_check(start_id[1], checkpoint_tree_height - 32);
        }
        let low_less = builder.is_less_than(32, start_id[0], end_id[0]);
        let same_high_less = builder.and(high_equal, low_less);
        let positive = builder.or(high_less, same_high_less);
        builder.assert_one(positive.target);
        builder.range_check(range[25], checkpoint_tree_height);
        // Both endpoints are below 2^63 and ordered: subtraction cannot wrap the field.
        let count = builder.sub(range[24], start);
        builder.connect(count, range[25]);
        let end_leaf = QEDCheckpointLeafGadget::create_virtual(builder);
        let leaf_hash = end_leaf.to_hash::<C::Hasher, _, D>(builder);
        let end_path = MerkleProofGadget::add_virtual_to::<C::Hasher, _, D>(builder, checkpoint_tree_height);
        builder.connect_hashes(end_path.value, leaf_hash);
        builder.connect(end_path.index, range[24]);
        let end_root = HashOutTarget { elements: range[20..24].try_into().unwrap() };
        builder.connect_hashes(end_path.root, end_root);
        for value in [1, 5, 0, 0] {
            let target = builder.constant(GoldilocksField::from_canonical_u64(value));
            builder.register_public_input(target);
        }
        builder.register_public_inputs(&config_hash);
        builder.register_public_inputs(&end_id);
        builder.register_public_inputs(&end_root.elements);
        builder.register_public_inputs(&start_id);
        builder.register_public_inputs(&range[..4]);
        builder.register_public_inputs(&leaf_hash.elements);
        Self { config_hash, start_id, end_leaf, end_path }
    }

    fn set_witness(
        &self,
        witness: &mut PartialWitness<GoldilocksField>,
        config_hash: [u32; 8],
        start_id: u64,
        end_id: u64,
        end_leaf: &PQEDCheckpointLeaf<GoldilocksField, QHashOut<GoldilocksField>>,
        end_path: &MerkleProofCore<QHashOut<GoldilocksField>>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(end_path.siblings.len() == self.end_path.siblings.len(), "checkpoint path height mismatch");
        anyhow::ensure!(end_path.index == end_id, "checkpoint path index mismatch");
        for (target, value) in self.config_hash.iter().zip(config_hash) {
            witness.set_target(*target, GoldilocksField::from_canonical_u32(value))?;
        }
        witness.set_target(self.start_id[0], GoldilocksField::from_canonical_u32(start_id as u32))?;
        witness.set_target(self.start_id[1], GoldilocksField::from_canonical_u32((start_id >> 32) as u32))?;
        self.end_leaf.set_witness(witness, end_leaf)?;
        self.end_path.set_witness_core_proof_q(witness, end_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{crypto::hash::{merkle_proof::compute_root_merkle_proof_generic, traits::QFieldHashable}, pgoldilocks::PoseidonHasher};
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafStats;

    // These exercise adapter constraints, not a substitute range proof or source-circuit fixture.
    #[test]
    fn positive_range_boundaries_and_full_end_leaf_are_constrained() {
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let range = builder.add_virtual_targets(BRIDGE_AGG_FINAL_PI_LEN);
        let targets = CheckpointRangeTargets::build::<C, 2>(&mut builder, &range, 4);
        let circuit = builder.build::<C>();
        let leaf = PQEDCheckpointLeaf { global_chain_root: QHashOut::ZERO, stats: PQEDCheckpointLeafStats::new_empty() };
        let value = leaf.qfhash::<PoseidonHasher>();
        let siblings = vec![QHashOut::ZERO; 4];
        let root = compute_root_merkle_proof_generic::<_, PoseidonHasher>(value, 3, &siblings);
        let path = MerkleProofCore { root, value, index: 3, siblings };
        let prove = |start: u64, count: u64, leaf: &PQEDCheckpointLeaf<F, QHashOut<F>>, path: &MerkleProofCore<QHashOut<F>>| -> anyhow::Result<_> {
            let mut witness = PartialWitness::new();
            let mut values = [F::ZERO; BRIDGE_AGG_FINAL_PI_LEN];
            values[..4].copy_from_slice(&QHashOut::<F>::ZERO.0.elements);
            values[20..24].copy_from_slice(&root.0.elements);
            values[24] = F::from_canonical_u64(3);
            values[25] = F::from_canonical_u64(count);
            for (target, value) in range.iter().zip(values) { witness.set_target(*target, value)?; }
            targets.set_witness(&mut witness, [1; 8], start, values[24].to_canonical_u64(), leaf, path)?;
            circuit.prove(witness)
        };
        let proof = prove(1, 2, &leaf, &path).unwrap();
        assert_eq!(proof.public_inputs.len(), CHECKPOINT_RANGE_PI_LEN);
        assert_eq!(&proof.public_inputs[..4], &[F::ONE, F::from_canonical_u64(5), F::ZERO, F::ZERO]);
        circuit.verify(proof).unwrap();
        assert!(prove(0, 2, &leaf, &path).is_err());
        assert!(prove(1, 1, &leaf, &path).is_err());
        assert!(prove(3, 0, &leaf, &path).is_err());
        assert!(prove(4, 1, &leaf, &path).is_err());
        let mut wrong_leaf = leaf.clone();
        wrong_leaf.stats.block_time = F::ONE;
        assert!(prove(1, 2, &wrong_leaf, &path).is_err());
        let mut wrong_path = path.clone();
        wrong_path.index = 2;
        assert!(prove(1, 2, &leaf, &wrong_path).is_err());
        let mut wrong_path = path.clone();
        wrong_path.index = 0xffff_ffff_0000_0001 + 3;
        assert!(prove(1, 2, &leaf, &wrong_path).is_err());
        let mut wrong_path = path;
        wrong_path.siblings[0] = QHashOut(HashOut { elements: [F::ONE; 4] });
        assert!(prove(1, 2, &leaf, &wrong_path).is_err());
    }
}
