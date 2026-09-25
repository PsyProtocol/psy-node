//! One fixed batch-processing leaf for one normalized user reward claim. It
//! consumes the user's `UserRewardFinalCircuit` proof plus the canonical job
//! witness (checkpoint upgrade and spent update) instead of any older claim
//! leaf proof, and reproduces the per-job commitment of `UserRewardLeafCircuit`.
//! The proved user anchor is already equal to the target anchor, while the
//! recipient is taken from the user final proof at batch closing. Neither is
//! duplicated in this leaf's public inputs.

use anyhow::{ensure, Result};
use plonky2::{
    field::{extension::Extendable, types::Field}, hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{builder::comparison::CircuitBuilderComparison, builder::pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates}, hash::merkle::gadgets::{delta_merkle_proof::DeltaMerkleProofGadget, merkle_proof::MerkleProofGadget}};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_crypto::hash::{merkle::core::{DeltaMerkleProofCore, MerkleProofCore}, traits::hasher::FieldQHasher};

use super::claim_rewards_l1_final::USER_REWARD_FINAL_PUBLIC_INPUTS;

/// A checkpoint tree index (32 bits), reward node level (5 bits), and node
/// index (26 bits) form an injective 63-bit spent-tree path.
pub const SPENT_TREE_HEIGHT: usize = 63;
pub const REWARD_INDEX_BITS: usize = 26;
pub const REWARD_LEVEL_BITS: usize = 5;

pub fn spent_key(checkpoint_id: u32, reward_path_info: u64) -> Result<u64> {
    let level = reward_path_info >> 56;
    let index = reward_path_info & 0x00ff_ffff_ffff_ffff;
    ensure!(level <= REWARD_INDEX_BITS as u64 && index < (1u64 << level), "invalid reward path info");
    Ok(((checkpoint_id as u64) << (REWARD_LEVEL_BITS + REWARD_INDEX_BITS)) | (level << REWARD_INDEX_BITS) | index)
}

/// target_anchor[4], spent_start[4], spent_end[4], user_id, amount, count,
/// jobs_commitment[4], whitelist_root[4].
pub const BATCH_JOB_PUBLIC_INPUTS: usize = 23;

#[derive(Clone)]
pub struct RewardBatchJobInput<F: RichField> {
    pub checkpoint_id: u32,
    pub reward_path_info: u64,
    pub amount: u64,
    pub checkpoint_upgrade: MerkleProofCore<QHashOut<F>>,
    pub spent_update: DeltaMerkleProofCore<QHashOut<F>>,
}

pub struct RewardBatchJobCircuit<C: GenericConfig<D>, const D: usize> where C::Hasher: AlgebraicHasher<C::F> {
    data: CircuitData<C::F, C, D>, user: ProofWithPublicInputsTarget<D>,
    checkpoint_id: plonky2::iop::target::Target, reward_level: plonky2::iop::target::Target,
    reward_index: plonky2::iop::target::Target, amount: plonky2::iop::target::Target,
    upgrade: MerkleProofGadget, spent: DeltaMerkleProofGadget, whitelist_root: HashOutTarget,
}

impl<C: GenericConfig<D>, const D: usize> RewardBatchJobCircuit<C, D>
where C::F: RichField + Extendable<D>, C::Hasher: AlgebraicHasher<C::F> + FieldQHasher<C::F> {
    pub fn new(user_final_data: &CircuitData<C::F, C, D>) -> Self {
        assert_eq!(user_final_data.common.num_public_inputs, USER_REWARD_FINAL_PUBLIC_INPUTS);
        let mut builder = CircuitBuilder::<C::F,D>::new(CircuitConfig::standard_recursion_config());
        let user = builder.add_virtual_proof_with_pis(&user_final_data.common);
        let vd = builder.constant_verifier_data(&user_final_data.verifier_only);
        builder.verify_proof::<C>(&user, &vd, &user_final_data.common);
        let checkpoint_id = builder.add_virtual_target(); let reward_level = builder.add_virtual_target(); let reward_index = builder.add_virtual_target(); let amount = builder.add_virtual_target();
        builder.range_check(checkpoint_id,32); builder.range_check(reward_level,REWARD_LEVEL_BITS); builder.range_check(reward_index,REWARD_INDEX_BITS);
        builder.range_check(amount,31); builder.assert_non_zero(amount);
        let upgrade = MerkleProofGadget::add_virtual_to::<C::Hasher,C::F,D>(&mut builder,CHECKPOINT_TREE_HEIGHT as usize);
        builder.connect(upgrade.index,checkpoint_id);
        // Batch anchor membership: the checkpoint upgrade must resolve against
        // the same anchor the user's final proof is bound to.
        for i in 0..4 { builder.connect(upgrade.root.elements[i], user.public_inputs[i]); }
        let spent = DeltaMerkleProofGadget::add_virtual_to::<C::Hasher,C::F,D>(&mut builder,SPENT_TREE_HEIGHT);
        let cp_scale=builder.constant(C::F::from_canonical_u64(1u64<<(REWARD_LEVEL_BITS+REWARD_INDEX_BITS)));
        let level_scale=builder.constant(C::F::from_canonical_u64(1u64<<REWARD_INDEX_BITS));
        let hi=builder.mul(checkpoint_id,cp_scale); let lv=builder.mul(reward_level,level_scale); let prefix=builder.add(hi,lv); let key=builder.add(prefix,reward_index);
        builder.connect(spent.index,key);
        let zero=builder.constant_hash(HashOut::ZERO); let one=builder.constant_hash(HashOut{elements:[C::F::ONE,C::F::ZERO,C::F::ZERO,C::F::ZERO]});
        builder.connect_hashes(spent.old_value,zero); builder.connect_hashes(spent.new_value,one);
        builder.register_public_inputs(&upgrade.root.elements); builder.register_public_inputs(&spent.old_root.elements); builder.register_public_inputs(&spent.new_root.elements);
        builder.register_public_input(user.public_inputs[4]);
        builder.register_public_input(amount);
        let one_count=builder.one(); builder.register_public_input(one_count);
        // Canonical per-job commitment, identical to `UserRewardLeafCircuit`:
        // checkpoint_id, reward_index, reward_level, amount, user_id, and the
        // checkpoint leaf hash opened by the upgrade proof.
        let commitment=builder.hash_n_to_hash_no_pad::<C::Hasher>([
            checkpoint_id,reward_index,reward_level,amount,user.public_inputs[4],
            upgrade.value.elements[0],upgrade.value.elements[1],upgrade.value.elements[2],upgrade.value.elements[3],
        ].to_vec());
        builder.register_public_inputs(&commitment.elements);
        let whitelist_root = builder.add_virtual_hash();
        builder.register_public_inputs(&whitelist_root.elements);
        builder.add_psy_type_a_common_gates(None); pad_circuit_degree(&mut builder,12);
        let data=builder.build::<C>(); assert_eq!(data.common.num_public_inputs,BATCH_JOB_PUBLIC_INPUTS);
        assert_eq!(data.common.degree_bits(), 13, "batch job leaf exceeds degree 13");
        Self{data,user,checkpoint_id,reward_level,reward_index,amount,upgrade,spent,whitelist_root}
    }
    pub fn circuit_data(&self)->&CircuitData<C::F,C,D>{&self.data}
    pub fn prove(&self, user:&ProofWithPublicInputs<C::F,C,D>, input:&RewardBatchJobInput<C::F>, whitelist_root:QHashOut<C::F>)->Result<ProofWithPublicInputs<C::F,C,D>>{
        ensure!(user.public_inputs.len()==USER_REWARD_FINAL_PUBLIC_INPUTS,"user final public-input shape mismatch");
        ensure!(input.amount>0 && input.amount<(1u64<<31),"job amount out of circuit range");
        let level=input.reward_path_info>>56; let index=input.reward_path_info&0x00ff_ffff_ffff_ffff;
        ensure!(input.spent_update.index==spent_key(input.checkpoint_id,input.reward_path_info)?,"wrong spent key");
        ensure!(input.checkpoint_upgrade.index==input.checkpoint_id as u64,"wrong checkpoint index");
        ensure!(input.checkpoint_upgrade.siblings.len()==CHECKPOINT_TREE_HEIGHT as usize,"checkpoint path height mismatch");
        ensure!(input.spent_update.siblings.len()==SPENT_TREE_HEIGHT,"spent path height mismatch");
        for i in 0..4 { ensure!(input.checkpoint_upgrade.root.0.elements[i]==user.public_inputs[i],"job upgrade root does not match user final anchor"); }
        let mut pw=PartialWitness::new(); pw.set_proof_with_pis_target(&self.user,user)?;
        pw.set_target(self.checkpoint_id,C::F::from_canonical_u32(input.checkpoint_id))?; pw.set_target(self.reward_level,C::F::from_canonical_u64(level))?; pw.set_target(self.reward_index,C::F::from_canonical_u64(index))?;
        pw.set_target(self.amount,C::F::from_canonical_u64(input.amount))?;
        self.upgrade.set_witness_core_proof_q(&mut pw,&input.checkpoint_upgrade)?; self.spent.set_witness_core_proof_q(&mut pw,&input.spent_update)?;
        pw.set_hash_target(self.whitelist_root, whitelist_root.0)?;
        Ok(self.data.prove(pw)?)
    }
}
