//! Closes one user's batch job tree against that user's final reward proof.
//! The job tree verifier's fingerprint must be present in the protocol-fixed
//! batch job circuit whitelist; a self-built whitelist cannot pass.

use anyhow::{ensure, Result};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}}};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{builder::pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates}, builder::verify::CircuitBuilderVerifyProofHelpers, hash::merkle::gadgets::merkle_proof::MerkleProofGadget};
use psy_crypto::{hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher}};

use super::{claim_rewards_l1_batch_job::BATCH_JOB_PUBLIC_INPUTS, claim_rewards_l1_batch_job_tree::BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT, claim_rewards_l1_final::{REWARD_BATCH_FINAL_PUBLIC_INPUTS, USER_REWARD_FINAL_PUBLIC_INPUTS}};

pub struct RewardBatchUserCircuit<C: GenericConfig<D>, const D: usize> where C::Hasher: AlgebraicHasher<C::F> {
    data:CircuitData<C::F,C,D>, jobs:ProofWithPublicInputsTarget<D>, jobs_verifier: plonky2::plonk::circuit_data::VerifierCircuitTarget, user:ProofWithPublicInputsTarget<D>,
    jobs_inclusion: MerkleProofGadget, whitelist_root: QHashOut<C::F>, batch_whitelist_root: HashOutTarget,
}
impl<C:GenericConfig<D>,const D:usize> RewardBatchUserCircuit<C,D>
where C::F:RichField+Extendable<D>, C::Hasher:AlgebraicHasher<C::F>+MerkleZeroHasher<HashOut<C::F>> {
    /// Closes a user's job proofs against that user's final reward proof. The
    /// job-side verifier is whitelisted: either the fixed batch job leaf (one
    /// job) or the fixed batch job tree (several jobs). A self-built whitelist
    /// cannot pass.
    pub fn new(jobs_common:&CommonCircuitData<C::F,D>,jobs_cap_height:usize,user_data:&CircuitData<C::F,C,D>,whitelist_root:QHashOut<C::F>)->Self{
        assert_eq!(jobs_common.num_public_inputs,BATCH_JOB_PUBLIC_INPUTS); assert_eq!(user_data.common.num_public_inputs,USER_REWARD_FINAL_PUBLIC_INPUTS);
        let mut b=CircuitBuilder::<C::F,D>::new(CircuitConfig::standard_recursion_config());
        let jobs=b.add_virtual_proof_with_pis(jobs_common); let jvd=b.add_virtual_verifier_data(jobs_cap_height); b.verify_proof::<C>(&jobs,&jvd,jobs_common);
        let user=b.add_virtual_proof_with_pis(&user_data.common); let uvd=b.constant_verifier_data(&user_data.verifier_only); b.verify_proof::<C>(&user,&uvd,&user_data.common);
        let fingerprint=b.get_circuit_fingerprint::<C::Hasher>(&jvd);
        let jobs_inclusion=MerkleProofGadget::add_virtual_to::<C::Hasher,C::F,D>(&mut b,BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT);
        b.connect_hashes(fingerprint,jobs_inclusion.value);
        let expected_root=b.constant_hash(whitelist_root.0); b.connect_hashes(jobs_inclusion.root,expected_root);
        b.connect_hashes(HashOutTarget { elements: jobs.public_inputs[19..23].try_into().unwrap() }, expected_root);
        for i in 0..4 { b.connect(jobs.public_inputs[i],user.public_inputs[i]); }
        b.connect(jobs.public_inputs[12],user.public_inputs[4]);
        b.connect(jobs.public_inputs[13],user.public_inputs[13]); b.connect(jobs.public_inputs[14],user.public_inputs[14]);
        for i in 0..4 { b.connect(jobs.public_inputs[15+i],user.public_inputs[15+i]); }
        b.register_public_inputs(&jobs.public_inputs[0..12]);
        let reward_commitment=b.hash_n_to_hash_no_pad::<C::Hasher>(user.public_inputs[4..14].to_vec()); b.register_public_inputs(&reward_commitment.elements);
        b.register_public_inputs(&jobs.public_inputs[15..19]); b.register_public_input(user.public_inputs[13]);
        let batch_whitelist_root=b.add_virtual_hash(); b.register_public_inputs(&batch_whitelist_root.elements);
        b.add_psy_type_a_common_gates(None); pad_circuit_degree(&mut b,12); let data=b.build::<C>();
        assert_eq!(data.common.degree_bits(), 13, "batch user closing exceeds degree 13");
        assert_eq!(data.common.num_public_inputs,REWARD_BATCH_FINAL_PUBLIC_INPUTS + 4); Self{data,jobs,jobs_verifier:jvd,user,jobs_inclusion,whitelist_root,batch_whitelist_root}
    }
    pub fn circuit_data(&self)->&CircuitData<C::F,C,D>{&self.data}
    pub fn prove(&self,jobs:&ProofWithPublicInputs<C::F,C,D>,jobs_verifier:&VerifierOnlyCircuitData<C,D>,user:&ProofWithPublicInputs<C::F,C,D>,jobs_inclusion:&MerkleProofCore<QHashOut<C::F>>,batch_whitelist_root:QHashOut<C::F>)->Result<ProofWithPublicInputs<C::F,C,D>>{
        ensure!(jobs.public_inputs.len()==BATCH_JOB_PUBLIC_INPUTS,"job root shape mismatch"); ensure!(user.public_inputs.len()==USER_REWARD_FINAL_PUBLIC_INPUTS,"user final shape mismatch");
        ensure!(jobs_inclusion.root==self.whitelist_root,"job verifier not in the fixed whitelist");
        let mut pw=PartialWitness::new(); pw.set_proof_with_pis_target(&self.jobs,jobs)?; pw.set_verifier_data_target(&self.jobs_verifier,jobs_verifier)?; pw.set_proof_with_pis_target(&self.user,user)?; self.jobs_inclusion.set_witness_core_proof_q(&mut pw,jobs_inclusion)?; pw.set_hash_target(self.batch_whitelist_root,batch_whitelist_root.0)?; Ok(self.data.prove(pw)?)
    }
}
