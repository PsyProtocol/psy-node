

use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::{FieldQHasher, QFieldHashable}}, data::serializable::QPDSerializable, felt::{QFelt, QFelt64}, impl_qpd_serialize_params, protocol::core_types::{QFHashBase, QHashBase}};
use pser::{QBytesSerialize, QBytesDeserialize};

use crate::v1::qdata::contract::PQEDContractLeaf;



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDContractInclusionProof")]
pub struct PQEDContractInclusionProof<F, Hash> {
    pub contract_leaf: PQEDContractLeaf<F, Hash>,
    pub contract_tree_merkle_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: QFHashBase<F>> PQEDContractInclusionProof<F, Hash> {
    pub fn verify<H: FieldQHasher<F, Hash>>(&self) -> bool {
        self.contract_tree_merkle_proof.value == self.contract_leaf.qfhash::<H>()
            && self.contract_tree_merkle_proof.verify::<H>()
    }
}

impl_qpd_serialize_params!(
    PQEDContractInclusionProof,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDContractFunctionInclusionProof")]
pub struct PQEDContractFunctionInclusionProof<F: Copy + PartialEq, Hash: Copy + PartialEq> {
    pub contract_inclusion_proof: PQEDContractInclusionProof<F, Hash>,
    pub contract_function_merkle_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: QFHashBase<F>> PQEDContractFunctionInclusionProof<F, Hash> {
    pub fn verify<H: FieldQHasher<F, Hash>>(&self) -> bool {
        // must have a valid contract inclusion proof and a valid merkle proof with an even index
        // (even index is because each function uses two leaves) 
        self.contract_inclusion_proof.verify::<H>()
            && self.contract_function_merkle_proof.verify::<H>()
            && (self.contract_function_merkle_proof.index&1) == 0
    }

    // note that each function has two leaves:
    // **left** is the hash of the verifier key and **right** is [method_id, (num_outputs<<32)|num_inputs, 0, 0]

    pub fn get_function_verifier_fingerprint(&self) -> Hash {
        self.contract_function_merkle_proof.value
    }
    pub fn get_method_id(&self) -> u32 {
        self.contract_function_merkle_proof.siblings[0].to_4_felts()[0].to_u64_value() as u32
    }
    pub fn get_num_inputs(&self) -> usize {
        (self.contract_function_merkle_proof.siblings[0].to_4_felts()[1].to_u64_value()
            & 0xFFFFFFFFu64) as usize
    }
    pub fn get_num_outputs(&self) -> usize {
        (self.contract_function_merkle_proof.siblings[0].to_4_felts()[1].to_u64_value() >> 32u64)
            as usize
    }
}


impl_qpd_serialize_params!(
    PQEDContractFunctionInclusionProof,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);