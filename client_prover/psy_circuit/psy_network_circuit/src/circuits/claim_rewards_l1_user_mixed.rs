use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
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

use super::{
    claim_rewards_l1_final::USER_REWARD_FINAL_PUBLIC_INPUTS,
    claim_rewards_l1_user_header::{UserRewardHeader, UserRewardHeaderTarget},
    claim_rewards_l1_user_two_aggregate::USER_REWARD_AGG_WHITELIST_HEIGHT,
};

struct Mixed<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    leaf: ProofWithPublicInputsTarget<D>,
    agg: ProofWithPublicInputsTarget<D>,
    agg_vd: VerifierCircuitTarget,
    inclusion: MerkleProofGadget,
    agg_header: UserRewardHeaderTarget,
}
impl<C: GenericConfig<D>, const D: usize> Mixed<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn new(leaf_data: &CircuitData<C::F, C, D>, agg_data: &CircuitData<C::F, C, D>, leaf_left: bool) -> Self {
        assert_eq!(leaf_data.common.num_public_inputs, USER_REWARD_FINAL_PUBLIC_INPUTS);
        assert_eq!(agg_data.common.num_public_inputs, 8);
        let mut b = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let leaf = b.add_virtual_proof_with_pis(&leaf_data.common);
        let lvd = b.constant_verifier_data(&leaf_data.verifier_only);
        b.verify_proof::<C>(&leaf, &lvd, &leaf_data.common);
        let agg = b.add_virtual_proof_with_pis(&agg_data.common);
        let agg_vd = b.add_virtual_verifier_data(agg_data.verifier_only.constants_sigmas_cap.height());
        b.verify_proof::<C>(&agg, &agg_vd, &agg_data.common);
        let fp = b.get_circuit_fingerprint::<C::Hasher>(&agg_vd);
        let inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut b, USER_REWARD_AGG_WHITELIST_HEIGHT);
        b.connect_hashes(fp, inclusion.value);
        b.connect_hashes(
            inclusion.root,
            HashOutTarget {
                elements: agg.public_inputs[4..8].try_into().unwrap(),
            },
        );
        let leaf_header = UserRewardHeaderTarget {
            fields: leaf.public_inputs[..19].try_into().unwrap(),
        };
        let agg_header = UserRewardHeaderTarget::add_virtual(&mut b);
        let expected = agg_header.hash::<C::Hasher, C::F, D>(&mut b);
        b.connect_hashes(
            expected,
            HashOutTarget {
                elements: agg.public_inputs[..4].try_into().unwrap(),
            },
        );
        let parent = if leaf_left {
            UserRewardHeaderTarget::combine::<C::Hasher, C::F, D>(&mut b, leaf_header, agg_header)
        } else {
            UserRewardHeaderTarget::combine::<C::Hasher, C::F, D>(&mut b, agg_header, leaf_header)
        };
        let out = parent.hash::<C::Hasher, C::F, D>(&mut b);
        b.register_public_inputs(&out.elements);
        b.register_public_inputs(&inclusion.root.elements);
        b.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut b, 12);
        let data = b.build::<C>();
        assert_eq!(data.common, agg_data.common, "mixed aggregate common data mismatch");
        Self {
            data,
            leaf,
            agg,
            agg_vd,
            inclusion,
            agg_header,
        }
    }
    fn prove(
        &self,
        leaf: &ProofWithPublicInputs<C::F, C, D>,
        agg: &ProofWithPublicInputs<C::F, C, D>,
        agg_vd: &VerifierOnlyCircuitData<C, D>,
        inc: &MerkleProofCore<QHashOut<C::F>>,
        header: &UserRewardHeader<C::F>,
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(leaf.public_inputs.len() == 19 && agg.public_inputs.len() == 8, "mixed child PI mismatch");
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.leaf, leaf)?;
        pw.set_proof_with_pis_target(&self.agg, agg)?;
        pw.set_verifier_data_target(&self.agg_vd, agg_vd)?;
        self.inclusion.set_witness_core_proof_q(&mut pw, inc)?;
        self.agg_header.set_witness(&mut pw, header)?;
        Ok(self.data.prove(pw)?)
    }
}
macro_rules! mixed_wrapper {
    ($name:ident,$left:expr) => {
        pub struct $name<C: GenericConfig<D>, const D: usize>
        where
            C::Hasher: AlgebraicHasher<C::F>,
        {
            inner: Mixed<C, D>,
        }
        impl<C: GenericConfig<D>, const D: usize> $name<C, D>
        where
            C::F: RichField + Extendable<D>,
            C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
        {
            pub fn new(leaf: &CircuitData<C::F, C, D>, agg: &CircuitData<C::F, C, D>) -> Self {
                Self {
                    inner: Mixed::new(leaf, agg, $left),
                }
            }
            pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> {
                &self.inner.data
            }
            pub fn prove(
                &self,
                leaf: &ProofWithPublicInputs<C::F, C, D>,
                agg: &ProofWithPublicInputs<C::F, C, D>,
                vd: &VerifierOnlyCircuitData<C, D>,
                inc: &MerkleProofCore<QHashOut<C::F>>,
                header: &UserRewardHeader<C::F>,
            ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
                self.inner.prove(leaf, agg, vd, inc, header)
            }
        }
    };
}
mixed_wrapper!(UserRewardLeftLeafRightAggregateCircuit, true);
mixed_wrapper!(UserRewardLeftAggregateRightLeafCircuit, false);
