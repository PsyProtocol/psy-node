use std::fmt::Debug;

use psy_serialize::PsySerializeCanonicalAsyncSafe;
use serde::{de::DeserializeOwned, Serialize};
use ts_rs::TS;

use crate::{crypto::hash::traits::{FieldQHasher, FromU64x4, HashTo4Felts, MerkleZeroHasher, RandomHash, ZeroableHash}, data::{db::data_types::{CoreDatabaseValueDeserialize, QDatabasePrimitiveKey}, maybe_serialization::{MaybeBytemuck, MaybeSpeedy}, serializable::{QPDSerializable, QPDSerializableFixed}}, felt::QFelt64, generic_traits::QNamedType, QJobIdBase};

pub trait QStorableBase: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq + Eq {}
pub trait QStorableSizedBase: QStorableBase + Sized {}
impl<T: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq + Eq> QStorableBase for T {}
impl<T: QStorableBase + Sized> QStorableSizedBase for T {}
pub trait QFHasherU64<F: QFelt64, Hash: QFHashBase<F>>: FieldQHasher<F, Hash>  + MerkleZeroHasher<Hash> {}
pub trait Q256BitHash: FromU64x4 + Sized + Copy + MaybeBytemuck + MaybeSpeedy + Debug + Sync + Send + PartialEq {
    fn from_owned_32bytes(bytes: [u8; 32]) -> Self;
    fn into_owned_32bytes(self) -> [u8; 32];
    fn from_ref_32bytes(bytes: &[u8; 32]) -> Self;
    fn from_slice_32bytes(bytes: &[u8]) -> anyhow::Result<Self>;
    fn to_vec_32bytes(&self) -> Vec<u8>;
}
pub trait Q256BitHashTransparent: Q256BitHash {
    fn from_ref_32bytes_transparent(bytes: &[u8; 32]) -> &Self;
    fn as_ref_32bytes_transparent(&self) -> &[u8; 32];
}

pub trait Q256BitHashNonTransparent: Q256BitHash {
}
pub trait QDBHashBase: QHash256Base + Q256BitHash  {}
impl<T: QHash256Base + Q256BitHash> QDBHashBase for T {}
pub trait QHashBase: PartialEq + ZeroableHash + Copy + Clone + Serialize + DeserializeOwned + QPDSerializable + QPDSerializableFixed + Sync + Send + FromU64x4 + TS + Default + CoreDatabaseValueDeserialize + QDatabasePrimitiveKey + RandomHash + QNamedType + MaybeSpeedy + MaybeBytemuck + std::fmt::Debug  {}
pub trait QHash256Base: QHashBase + Q256BitHash {}
impl<T: QHashBase + Q256BitHash> QHash256Base for T {}
pub trait QFHashBase<F: QFelt64>: QHashBase + HashTo4Felts<F> {}
impl<T: QHashBase + HashTo4Felts<F>, F: QFelt64> QFHashBase<F> for T {}

pub trait QProofBase: PartialEq + Clone + Serialize + DeserializeOwned + QPDSerializable {}
/*
pub trait QHasherBase<Hash: QHashBase, Proof: QProofBase>: MerkleZeroHasher<Hash> {
    fn get_proof_public_inputs(proof: &Proof) -> anyhow::Result<Hash>; // the public inputs of the proof is a hash which is the hash of the QParthProofPublicInputsPreimage
    fn hash_proof_public_inputs_preimage(preimage: &QParthProofPublicInputsPreimage<Hash>) -> Hash;
    fn hash_proof_public_inputs_preimage_with_rewards_hash(preimage: &QParthProofPublicInputsPreimageWithoutRewardsHash<Hash>, rewards_hash: &Hash) -> Hash;
}
*/
pub trait QZKProofPublicInputsHasherReader<Hash, Proof> {
    fn get_proof_public_inputs_hash(proof: &Proof) -> anyhow::Result<Hash>;
    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<Proof>;
}
pub trait QZKProofVerifier<Hash: PartialEq, Proof>: QZKProofPublicInputsHasherReader<Hash, Proof> {
    fn verify_zk_proof(&self, circuit_type: u32, proof: &Proof) -> anyhow::Result<Hash>;
    fn verify_zk_proof_check_public_inputs_hash(&self, circuit_type: u32, proof: &Proof, expected_public_inputs_hash: Hash) -> anyhow::Result<()>{
        if self.verify_zk_proof(circuit_type, proof)? != expected_public_inputs_hash {
            return Err(anyhow::anyhow!("ZK Proof verification failed"));
        }
        Ok(())
    }
    fn verify_zk_proof_from_slice_check_public_inputs_hash(&self, circuit_type: u32, proof_bytes: &[u8], expected_public_inputs_hash: Hash) -> anyhow::Result<()>{
        let proof = Self::try_proof_from_slice(proof_bytes)?;
        if Self::get_proof_public_inputs_hash(&proof)? != expected_public_inputs_hash {
            return Err(anyhow::anyhow!("ZK Proof verification failed"));
        }

        if self.verify_zk_proof(circuit_type, &proof)? != expected_public_inputs_hash {
            return Err(anyhow::anyhow!("ZK Proof verification failed"));
        }
        Ok(())
    }
}
pub trait QJobPlanner<JobId: QJobIdBase> {
    fn get_child_job_for_circuit_type(&self, children_circuit_types: &[u32]) -> u32;
}

pub trait QNetworkTreeConstants: Sized + Send + Sync + Copy + Clone {
    
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


    const GROUP_REALM_HEIGHT: u8;// 1, for user ids
    const MAX_USERS: u64; // = 2**GLOBAL_USER_TREE_HEIGHT
    const MAX_REALMS: u32; // = 2**COORDINATOR_GLOBAL_USER_TREE_HEIGHT
    const MAX_USERS_PER_REALM: u32; // = 2**REALM_GLOBAL_USER_TREE_HEIGHT



}

pub trait QNetworkTreeCircuitConstants: Sized + Send + Sync + Copy + Clone {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize;
    const CHAIN_ID: u32;
}

pub trait QNetworkCircuitConstants: QNetworkTreeCircuitConstants + QNetworkTreeConstants {
}
impl<T: QNetworkTreeCircuitConstants + QNetworkTreeConstants> QNetworkCircuitConstants for T {}

pub trait QNetworkHashTypes{
    type QHash: QFHashBase<Self::F> + Q256BitHash + PsySerializeCanonicalAsyncSafe;
    type HasherBase: QFHasherU64<Self::F, Self::QHash> + Send + Sync;
    type F: QFelt64;
}
pub trait QNetworkDatabaseTypes: QNetworkTreeConstants + QNetworkHashTypes {
}
impl<T: QNetworkTreeConstants + QNetworkHashTypes> QNetworkDatabaseTypes for T {}
pub trait QNetworkZKTypes: QNetworkHashTypes {
    type ZKProof: QProofBase + Send + Sync;
    type ZKVerifier: QZKProofVerifier<Self::QHash, Self::ZKProof> + Send + Sync;
}

pub trait QNetworkTypesConfig: QNetworkDatabaseTypes + QNetworkCircuitConstants + QNetworkZKTypes + QJobIdBase + QJobPlanner<Self::JobId>  + Sized + Send + Sync + Copy + Clone + Default {
    type JobId: QJobIdBase;
    type JobPlanner: QJobPlanner<Self::JobId> + Send + Sync;
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
