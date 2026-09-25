//! Fixed first aggregation level for two normalized user reward leaves.

use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::builder::{
    hash::core::CircuitBuilderHashCore,
    pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
};

use super::claim_rewards_l1_final::USER_REWARD_FINAL_PUBLIC_INPUTS;

pub struct UserRewardTwoLeafCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    left: ProofWithPublicInputsTarget<D>,
    right: ProofWithPublicInputsTarget<D>,
    whitelist_root: HashOutTarget,
}
impl<C: GenericConfig<D>, const D: usize> UserRewardTwoLeafCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(leaf_data: &CircuitData<C::F, C, D>) -> Self {
        assert_eq!(leaf_data.common.num_public_inputs, USER_REWARD_FINAL_PUBLIC_INPUTS);
        let mut b = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let left = b.add_virtual_proof_with_pis(&leaf_data.common);
        let right = b.add_virtual_proof_with_pis(&leaf_data.common);
        let vd = b.constant_verifier_data(&leaf_data.verifier_only);
        b.verify_proof::<C>(&left, &vd, &leaf_data.common);
        b.verify_proof::<C>(&right, &vd, &leaf_data.common);
        for i in 0..13 {
            b.connect(left.public_inputs[i], right.public_inputs[i]);
        }
        let total = b.add(left.public_inputs[13], right.public_inputs[13]);
        let count = b.add(left.public_inputs[14], right.public_inputs[14]);
        b.range_check(total, 62);
        b.range_check(count, 32);
        let left_commitment = plonky2::hash::hash_types::HashOutTarget {
            elements: left.public_inputs[15..19].try_into().unwrap(),
        };
        let right_commitment = plonky2::hash::hash_types::HashOutTarget {
            elements: right.public_inputs[15..19].try_into().unwrap(),
        };
        let pair = b.hash_two_to_one::<C::Hasher>(left_commitment, right_commitment);
        let zero = b.zero();
        let counts = plonky2::hash::hash_types::HashOutTarget {
            elements: [left.public_inputs[14], right.public_inputs[14], zero, zero],
        };
        let commitment = b.hash_two_to_one::<C::Hasher>(pair, counts);
        let header_hash = b.hash_n_to_hash_no_pad::<C::Hasher>([&left.public_inputs[0..13], &[total, count], &commitment.elements].concat());
        b.register_public_inputs(&header_hash.elements);
        let whitelist_root = b.add_virtual_hash();
        b.register_public_inputs(&whitelist_root.elements);
        b.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut b, 12);
        let data = b.build::<C>();
        Self {
            data,
            left,
            right,
            whitelist_root,
        }
    }
    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> {
        &self.data
    }
    pub fn prove(
        &self,
        left: &ProofWithPublicInputs<C::F, C, D>,
        right: &ProofWithPublicInputs<C::F, C, D>,
        whitelist_root: QHashOut<C::F>,
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(left.public_inputs.len() == USER_REWARD_FINAL_PUBLIC_INPUTS, "left leaf shape mismatch");
        ensure!(right.public_inputs.len() == USER_REWARD_FINAL_PUBLIC_INPUTS, "right leaf shape mismatch");
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.left, left)?;
        pw.set_proof_with_pis_target(&self.right, right)?;
        pw.set_hash_target(self.whitelist_root, whitelist_root.0)?;
        Ok(self.data.prove(pw)?)
    }
}
