use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{
    builder::{
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
        verify::CircuitBuilderVerifyProofHelpers,
    },
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher};

use super::claim_rewards_l1_user_header::{UserRewardHeader, UserRewardHeaderTarget};

pub const USER_REWARD_AGG_WHITELIST_HEIGHT: usize = 3;
struct AggChild<const D: usize> {
    proof: ProofWithPublicInputsTarget<D>,
    verifier: VerifierCircuitTarget,
    inclusion: MerkleProofGadget,
    header: UserRewardHeaderTarget,
}
pub struct UserRewardTwoAggregateCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    left: AggChild<D>,
    right: AggChild<D>,
}
impl<C: GenericConfig<D>, const D: usize> UserRewardTwoAggregateCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(common: &CommonCircuitData<C::F, D>, cap_height: usize) -> Self {
        assert_eq!(common.num_public_inputs, 8);
        let mut b = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let left = Self::child(&mut b, common, cap_height);
        let right = Self::child(&mut b, common, cap_height);
        b.connect_hashes(left.inclusion.root, right.inclusion.root);
        b.connect_hashes(
            left.inclusion.root,
            HashOutTarget {
                elements: left.proof.public_inputs[4..8].try_into().unwrap(),
            },
        );
        b.connect_hashes(
            right.inclusion.root,
            HashOutTarget {
                elements: right.proof.public_inputs[4..8].try_into().unwrap(),
            },
        );
        let parent = UserRewardHeaderTarget::combine::<C::Hasher, C::F, D>(&mut b, left.header, right.header);
        let hash = parent.hash::<C::Hasher, C::F, D>(&mut b);
        b.register_public_inputs(&hash.elements);
        b.register_public_inputs(&left.inclusion.root.elements);
        b.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut b, 12);
        let data = b.build::<C>();
        assert_eq!(&data.common, common, "aggregate common data mismatch");
        Self { data, left, right }
    }
    fn child(b: &mut CircuitBuilder<C::F, D>, common: &CommonCircuitData<C::F, D>, cap: usize) -> AggChild<D> {
        let proof = b.add_virtual_proof_with_pis(common);
        let verifier = b.add_virtual_verifier_data(cap);
        b.verify_proof::<C>(&proof, &verifier, common);
        let fp = b.get_circuit_fingerprint::<C::Hasher>(&verifier);
        let inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(b, USER_REWARD_AGG_WHITELIST_HEIGHT);
        b.connect_hashes(fp, inclusion.value);
        let header = UserRewardHeaderTarget::add_virtual(b);
        let expected = header.hash::<C::Hasher, C::F, D>(b);
        b.connect_hashes(
            expected,
            HashOutTarget {
                elements: proof.public_inputs[..4].try_into().unwrap(),
            },
        );
        AggChild {
            proof,
            verifier,
            inclusion,
            header,
        }
    }
    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> {
        &self.data
    }
    pub fn prove(
        &self,
        left: (
            &ProofWithPublicInputs<C::F, C, D>,
            &VerifierOnlyCircuitData<C, D>,
            &MerkleProofCore<QHashOut<C::F>>,
            &UserRewardHeader<C::F>,
        ),
        right: (
            &ProofWithPublicInputs<C::F, C, D>,
            &VerifierOnlyCircuitData<C, D>,
            &MerkleProofCore<QHashOut<C::F>>,
            &UserRewardHeader<C::F>,
        ),
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(left.2.root == right.2.root, "aggregate whitelist roots differ");
        let mut pw = PartialWitness::new();
        Self::set(&mut pw, &self.left, left)?;
        Self::set(&mut pw, &self.right, right)?;
        Ok(self.data.prove(pw)?)
    }
    fn set(
        pw: &mut PartialWitness<C::F>,
        t: &AggChild<D>,
        v: (
            &ProofWithPublicInputs<C::F, C, D>,
            &VerifierOnlyCircuitData<C, D>,
            &MerkleProofCore<QHashOut<C::F>>,
            &UserRewardHeader<C::F>,
        ),
    ) -> Result<()> {
        ensure!(v.0.public_inputs.len() == 8, "aggregate proof PI mismatch");
        pw.set_proof_with_pis_target(&t.proof, v.0)?;
        pw.set_verifier_data_target(&t.verifier, v.1)?;
        t.inclusion.set_witness_core_proof_q(pw, v.2)?;
        t.header.set_witness(pw, v.3)?;
        Ok(())
    }
}
