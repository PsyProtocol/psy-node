use serde::{de::DeserializeOwned, Serialize};
use ts_rs::TS;

use crate::{crypto::hash::traits::{FieldQHasher, FromU64x4, HashTo4Felts, QHasher, ZeroableHash}, data::{hash::merkle_node_key::SimpleMerkleNodeKey, parth::public_preimage::{QParthProofPublicInputsPreimage, QParthProofPublicInputsPreimageWithoutRewardsHash}, queue::queue_key::PCoreQueueItemBase, serializable::{QPDSerializable, QPDSerializableFixed}}, felt::QFelt64, QJobIdSerialized};

pub trait QStorableBase: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq + Eq {}
pub trait QStorableSizedBase: QStorableBase + Sized {}
impl<T: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq + Eq> QStorableBase for T {}
impl<T: QStorableBase + Sized> QStorableSizedBase for T {}
pub trait QFHasherU64<F: QFelt64, Hash: QFHashBase<F>>: FieldQHasher<F, Hash> + QHasher<Hash> {}

pub trait QHashBase: PartialEq + ZeroableHash + Copy + Serialize + DeserializeOwned + QPDSerializable + QPDSerializableFixed + Sync + Send + FromU64x4 + TS + Default {}
pub trait QFHashBase<F: QFelt64>: QHashBase + HashTo4Felts<F> {}

pub trait QProofBase: PartialEq + Clone + Serialize + DeserializeOwned + QPDSerializable {}

pub trait QHasherBase<Hash: QHashBase, Proof: QProofBase>: QHasher<Hash> {
    fn get_proof_public_input(proof: &Proof) -> Hash; // the public inputs of the proof is a hash which is the hash of the QParthProofPublicInputsPreimage
    fn hash_proof_public_inputs_preimage(preimage: &QParthProofPublicInputsPreimage<Hash>) -> Hash;
    fn hash_proof_public_inputs_preimage_with_rewards_hash(preimage: &QParthProofPublicInputsPreimageWithoutRewardsHash<Hash>, rewards_hash: &Hash) -> Hash;
}

pub trait QZKProofVerifier<Hash: QHashBase, Proof: QProofBase>: QHasherBase<Hash, Proof> {
    fn verify_zk_proof(&self, circuit_type: u32, proof: &Proof) -> bool;
    fn verify_zk_proof_and_check_public_inputs(&self, circuit_type: u32, proof: &Proof, public_inputs_preimage: &QParthProofPublicInputsPreimage<Hash>) -> bool {
        let public_inputs = Self::get_proof_public_input(proof);
        if public_inputs != Self::hash_proof_public_inputs_preimage(public_inputs_preimage) {
            return false;
        }
        self.verify_zk_proof(circuit_type, proof)
    }
}
pub trait QJobIdBase: Send + Sync + Serialize + DeserializeOwned + Clone + PartialEq + Eq + std::fmt::Debug + QPDSerializableFixed + Sized + Into<QJobIdSerialized> + TryFrom<QJobIdSerialized> + PCoreQueueItemBase {
    fn to_bytes_fixed(&self) -> QJobIdSerialized;
    fn from_bytes_fixed(bytes: &QJobIdSerialized) -> anyhow::Result<Self>;
    fn circuit_type_u32(&self) -> u32;
    fn input_witness_id(&self) -> Self;
    fn output_proof_id(&self) -> Self;
    fn group_counter_id(&self) -> Self;
    fn get_checkpoint_id(&self) -> u64;
    fn is_user_guta_proof_circuit_type(&self) -> bool;
    fn is_end_cap_proof_circuit_type(&self) -> bool;
    fn get_parth_index(&self) -> u64;
    fn get_parth_level(&self) -> u8;
    fn get_parth_merkle_node_key(&self) -> SimpleMerkleNodeKey;
    
}

pub trait QJobPlanner<JobId: QJobIdBase> {
    fn get_child_job_for_circuit_type(&self, children_circuit_types: &[u32]) -> u32;
}

pub trait QNetworkTreeConstants {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize;
    const CHECKPOINT_TREE_HEIGHT: u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const GLOBAL_USER_TREE_HEIGHT: u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8;
    
    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8;

    // the height of the global user tree stored in the coordinator (ie. the upper half of the merkle tree)
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8;
    
     // the height of the global user tree stored in each realm (ie. the height of the sub-trees stored in each realm == GLOBAL_USER_TREE_HEIGHT - COORDINATOR_GLOBAL_USER_TREE_HEIGHT)
    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8;


    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8;


    const MAX_USERS: u64; // = 2**GLOBAL_USER_TREE_HEIGHT
    const MAX_REALMS: u32; // = 2**COORDINATOR_GLOBAL_USER_TREE_HEIGHT
    const MAX_USERS_PER_REALM: u32; // = 2**REALM_GLOBAL_USER_TREE_HEIGHT
}
pub trait QNetworkHashTypes {
    type QHash: QFHashBase<Self::F>;
    type HasherBase: QFHasherU64<Self::F, Self::QHash>;
    type F: QFelt64;
}
pub trait QNetworkZKTypes: QNetworkHashTypes {
    type ZKProof: QProofBase;
    type ZKVerifier: QZKProofVerifier<Self::QHash, Self::ZKProof>;
}

pub trait QNetworkTypesConfig: QNetworkTreeConstants + QNetworkZKTypes + QJobIdBase + QJobPlanner<Self::JobId> {
    type JobId: QJobIdBase;
    type JobPlanner: QJobPlanner<Self::JobId>;
}
/*
pub trait QNetworkTypesConfigBase: QNetworkTreeConstants {
    type QHash: QHashBase;
    type ZKProof: QProofBase;
    type HasherBase: QHasherBase<Self::QHash, Self::ZKProof>;
    type JobId: QJobIdBase;
    type F: QFelt64;
}
*/