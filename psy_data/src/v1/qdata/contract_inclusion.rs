

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

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{
            merkle_proof::MerkleProofCore,
            traits::{FieldQHasher, FromU64x4, QFieldHashable},
        },
        data::serializable::QPDSerializable,
        pgoldilocks::PoseidonHasher,
        utils::QPGenRandom,
        PHash, PF,
    };

    use super::{PQEDContractFunctionInclusionProof, PQEDContractInclusionProof};
    use crate::v1::qdata::contract::PQEDContractLeaf;

    fn valid_contract_inclusion_proof() -> PQEDContractInclusionProof<PF, PHash> {
        let contract_leaf = PQEDContractLeaf::<PF, PHash>::qp_rand_gen();
        let leaf_hash = contract_leaf.qfhash::<PoseidonHasher>();
        let siblings = vec![PHash::qp_rand_gen(), PHash::qp_rand_gen()];
        let contract_tree_merkle_proof = MerkleProofCore::new_from_params::<PoseidonHasher>(2, leaf_hash, siblings);
        PQEDContractInclusionProof {
            contract_leaf,
            contract_tree_merkle_proof,
        }
    }

    #[test]
    fn contract_inclusion_verify_accepts_valid_and_rejects_tampered() {
        let proof = valid_contract_inclusion_proof();
        assert!(proof.verify::<PoseidonHasher>());

        // tampering the proof value breaks the leaf-hash match
        let mut wrong_value = proof.clone();
        wrong_value.contract_tree_merkle_proof.value = PHash::qp_rand_gen();
        assert!(!wrong_value.verify::<PoseidonHasher>());

        // tampering the root breaks the merkle path verification
        let mut wrong_root = proof.clone();
        wrong_root.contract_tree_merkle_proof.root = PHash::qp_rand_gen();
        assert!(!wrong_root.verify::<PoseidonHasher>());

        // tampering the leaf breaks the leaf-hash match
        let mut wrong_leaf = proof.clone();
        wrong_leaf.contract_leaf.deployer = PHash::qp_rand_gen();
        assert!(!wrong_leaf.verify::<PoseidonHasher>());
    }

    #[test]
    fn contract_inclusion_proof_qpd_serialization_round_trip() {
        let proof = valid_contract_inclusion_proof();
        let bytes = proof.to_bytes().unwrap();
        let restored = PQEDContractInclusionProof::<PF, PHash>::from_bytes(&bytes).unwrap();
        assert_eq!(restored, proof);
        assert!(PQEDContractInclusionProof::<PF, PHash>::from_bytes(&[]).is_err());
    }

    #[test]
    fn function_inclusion_verify_and_accessors() {
        let method_id: u32 = 0xDEAD_BEEF;
        let num_inputs: u64 = 3;
        let num_outputs: u64 = 7;
        // left leaf of a function pair is the verifier key hash,
        // right leaf is [method_id, (num_outputs<<32)|num_inputs, 0, 0]
        let function_sibling = PHash::from_u64x4([method_id as u64, (num_outputs << 32) | num_inputs, 0, 0]);
        let verifier_fingerprint = PHash::qp_rand_gen();

        let contract_function_merkle_proof =
            MerkleProofCore::new_from_params::<PoseidonHasher>(4, verifier_fingerprint, vec![function_sibling]);
        let proof = PQEDContractFunctionInclusionProof {
            contract_inclusion_proof: valid_contract_inclusion_proof(),
            contract_function_merkle_proof,
        };

        // even index as required for function proofs
        assert!(proof.verify::<PoseidonHasher>());
        assert_eq!(proof.get_function_verifier_fingerprint(), verifier_fingerprint);
        assert_eq!(proof.get_method_id(), method_id);
        assert_eq!(proof.get_num_inputs(), num_inputs as usize);
        assert_eq!(proof.get_num_outputs(), num_outputs as usize);
    }

    #[test]
    fn function_inclusion_verify_rejects_odd_index() {
        let function_sibling = PHash::from_u64x4([1, (2u64 << 32) | 3, 0, 0]);
        let contract_function_merkle_proof =
            MerkleProofCore::new_from_params::<PoseidonHasher>(5, PHash::qp_rand_gen(), vec![function_sibling]);
        let proof = PQEDContractFunctionInclusionProof {
            contract_inclusion_proof: valid_contract_inclusion_proof(),
            contract_function_merkle_proof,
        };
        // each function uses two leaves, so an odd index is invalid
        assert!(!proof.verify::<PoseidonHasher>());
    }

    #[test]
    fn function_inclusion_proof_qpd_serialization_round_trip() {
        let function_sibling = PHash::from_u64x4([9, (4u64 << 32) | 5, 0, 0]);
        let contract_function_merkle_proof =
            MerkleProofCore::new_from_params::<PoseidonHasher>(2, PHash::qp_rand_gen(), vec![function_sibling]);
        let proof = PQEDContractFunctionInclusionProof {
            contract_inclusion_proof: valid_contract_inclusion_proof(),
            contract_function_merkle_proof,
        };
        let bytes = proof.to_bytes().unwrap();
        let restored = PQEDContractFunctionInclusionProof::<PF, PHash>::from_bytes(&bytes).unwrap();
        assert_eq!(restored, proof);
    }
}