use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOutTarget,
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs},
};
use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeaf;
use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;
use psy_plonky2_common_circuits::{hash::merkle::gadgets::merkle_proof::MerkleProofGadget, traits::CreatableTarget};
use crate::{gadgets::qdata::checkpoint::QEDCheckpointLeafGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic};

pub const CHECKPOINT_IDENTITY_PI_LEN: usize = 28;

#[derive(Clone, Debug)]
pub struct CheckpointIdentityWitness {
    pub config_hash: [u32; 8],
    pub end_id: u64,
    pub end_root: QHashOut<GoldilocksField>,
    pub start_id: u64,
    pub start_root: QHashOut<GoldilocksField>,
    pub end_leaf: PQEDCheckpointLeaf<GoldilocksField, QHashOut<GoldilocksField>>,
    pub end_path: MerkleProofCore<QHashOut<GoldilocksField>>,
}

pub struct CheckpointIdentityCircuit<C: GenericConfig<D, F = GoldilocksField>, const D: usize>
where
    GoldilocksField: Extendable<D>,
{
    pub config_hash: [Target; 8],
    pub end_id: [Target; 2],
    pub start_id: [Target; 2],
    pub start_root: HashOutTarget,
    pub end_leaf: QEDCheckpointLeafGadget,
    pub end_path: MerkleProofGadget,
    pub circuit_data: CircuitData<GoldilocksField, C, D>,
    pub fingerprint: QHashOut<GoldilocksField>,
}

impl<C: GenericConfig<D, F = GoldilocksField>, const D: usize> CheckpointIdentityCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<GoldilocksField>,
    GoldilocksField: Extendable<D>,
{
    pub fn new(checkpoint_tree_height: usize, common_gates: &[plonky2::gates::gate::GateRef<GoldilocksField, D>], target_degree: Option<usize>) -> Self {
        assert!((1..=63).contains(&checkpoint_tree_height));
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let config_hash = std::array::from_fn(|_| builder.add_virtual_target());
        for word in config_hash { builder.range_check(word, 32); }
        let end_id = std::array::from_fn(|_| builder.add_virtual_target());
        let start_id = std::array::from_fn(|_| builder.add_virtual_target());
        for i in 0..2 {
            builder.range_check(end_id[i], 32);
            builder.range_check(start_id[i], 32);
            builder.connect(start_id[i], end_id[i]);
        }
        let end_leaf = QEDCheckpointLeafGadget::create_virtual(&mut builder);
        let leaf_hash = end_leaf.to_hash::<C::Hasher, _, D>(&mut builder);
        let end_path = MerkleProofGadget::add_virtual_to::<C::Hasher, _, D>(&mut builder, checkpoint_tree_height);
        builder.connect_hashes(end_path.value, leaf_hash);
        let bits = builder.split_le(end_path.index, checkpoint_tree_height);
        let low = builder.le_sum(bits.iter().take(32));
        let high = builder.le_sum(bits.iter().skip(32));
        builder.connect(end_id[0], low);
        builder.connect(end_id[1], high);
        let start_root = builder.add_virtual_hash();
        builder.connect_hashes(start_root, end_path.root);
        for value in [1, 5, 1, 0] {
            let target = builder.constant(GoldilocksField::from_canonical_u64(value));
            builder.register_public_input(target);
        }
        builder.register_public_inputs(&config_hash);
        builder.register_public_inputs(&end_id);
        builder.register_public_inputs(&end_path.root.elements);
        builder.register_public_inputs(&start_id);
        builder.register_public_inputs(&start_root.elements);
        builder.register_public_inputs(&leaf_hash.elements);
        for gate in common_gates { builder.add_gate_to_gate_set(gate.clone()); }
        if let Some(degree) = target_degree {
            assert!(degree.is_power_of_two());
            let target_rows = degree.checked_sub(CHECKPOINT_IDENTITY_PI_LEN.div_ceil(8) + 2)
                .expect("checkpoint identity degree is too small");
            assert!(builder.num_gates() <= target_rows, "checkpoint identity exceeds target degree");
            while builder.num_gates() < target_rows {
                builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
            }
        }
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self { config_hash, end_id, start_id, start_root, end_leaf, end_path, circuit_data, fingerprint }
    }

    pub fn prove(&self, input: &CheckpointIdentityWitness) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, C, D>> {
        anyhow::ensure!(input.end_path.siblings.len() == self.end_path.siblings.len(), "checkpoint path height mismatch");
        anyhow::ensure!(input.end_path.index == input.end_id, "checkpoint path index mismatch");
        let mut witness = PartialWitness::new();
        for (target, word) in self.config_hash.iter().zip(input.config_hash) {
            witness.set_target(*target, GoldilocksField::from_canonical_u32(word))?;
        }
        for (targets, value) in [(self.end_id, input.end_id), (self.start_id, input.start_id)] {
            witness.set_target(targets[0], GoldilocksField::from_canonical_u32(value as u32))?;
            witness.set_target(targets[1], GoldilocksField::from_canonical_u32((value >> 32) as u32))?;
        }
        witness.set_hash_target(self.end_path.root, input.end_root.0)?;
        witness.set_hash_target(self.start_root, input.start_root.0)?;
        self.end_leaf.set_witness(&mut witness, &input.end_leaf)?;
        self.end_path.set_witness_core_proof_q(&mut witness, &input.end_path)?;
        self.circuit_data.prove(witness)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<GoldilocksField, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{crypto::hash::{merkle_proof::compute_root_merkle_proof_generic, traits::QFieldHashable}, pgoldilocks::PoseidonHasher};
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafStats;

    #[test]
    fn identity_authenticates_full_leaf_and_equal_endpoints() {
        let circuit = CheckpointIdentityCircuit::<PoseidonGoldilocksConfig, 2>::new(4, &[], None);
        let leaf = PQEDCheckpointLeaf { global_chain_root: QHashOut::ZERO, stats: PQEDCheckpointLeafStats::new_empty() };
        let value = leaf.qfhash::<PoseidonHasher>();
        let siblings = vec![QHashOut::ZERO; 4];
        let root = compute_root_merkle_proof_generic::<_, PoseidonHasher>(value, 3, &siblings);
        let input = CheckpointIdentityWitness {
            config_hash: [1; 8], end_id: 3, end_root: root, start_id: 3, start_root: root,
            end_leaf: leaf, end_path: MerkleProofCore { root, value, index: 3, siblings },
        };
        let proof = circuit.prove(&input).unwrap();
        assert_eq!(proof.public_inputs.len(), CHECKPOINT_IDENTITY_PI_LEN);
        circuit.verify(proof).unwrap();
        let mut wrong = input.clone();
        wrong.start_id = 2;
        assert!(circuit.prove(&wrong).is_err());
        let mut wrong = input.clone();
        wrong.start_root = QHashOut::ZERO;
        assert!(circuit.prove(&wrong).is_err());
        let mut wrong = input.clone();
        wrong.end_leaf.stats.block_time = GoldilocksField::ONE;
        assert!(circuit.prove(&wrong).is_err());
        let mut wrong = input.clone();
        wrong.end_path.index += 0xffff_ffff_0000_0001;
        assert!(circuit.prove(&wrong).is_err());
        let mut wrong = input;
        wrong.end_path.index = 2;
        assert!(circuit.prove(&wrong).is_err());
    }
}
