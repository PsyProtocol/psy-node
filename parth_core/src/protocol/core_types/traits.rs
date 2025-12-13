use std::fmt::Debug;

use psy_serialize::PsySerializeCanonicalAsyncSafe;
use serde::{de::DeserializeOwned, Serialize};
use ts_rs::TS;

use crate::{
    QJobIdBase, crypto::hash::traits::{FieldQHasher, FromU64x4, HashTo4Felts, MerkleZeroHasher, RandomHash, ZeroableHash}, data::{
        db::data_types::{CoreDatabaseValueDeserialize, QDatabasePrimitiveKey},
        maybe_serialization::{MaybeBytemuck, MaybeSpeedy},
        serializable::{QPDSerializable, QPDSerializableFixed},
    }, felt::QFelt64, generic_traits::{QNamedType, psy_debug_printable::PsyDebugPrintable}, protocol::core_types::{QNetworkCircuitConstants, QNetworkConstants, QNetworkConstantsCopier, QNetworkTreeConstants}
};

pub trait QStorableBase: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq + Eq {}
pub trait QStorableSizedBase: QStorableBase + Sized {}
impl<T: Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq + Eq> QStorableBase for T {}
impl<T: QStorableBase + Sized> QStorableSizedBase for T {}
pub trait QFHasherU64<F: QFelt64, Hash: QFHashBase<F>>: FieldQHasher<F, Hash> + MerkleZeroHasher<Hash> {}
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

pub trait Q256BitHashNonTransparent: Q256BitHash {}
pub trait QDBHashBase: QHash256Base + Q256BitHash {}
impl<T: QHash256Base + Q256BitHash> QDBHashBase for T {}
pub trait QHashBase:
    PartialEq
    + ZeroableHash
    + Copy
    + Clone
    + Serialize
    + DeserializeOwned
    + QPDSerializable
    + QPDSerializableFixed
    + Sync
    + Send
    + FromU64x4
    + TS
    + Default
    + CoreDatabaseValueDeserialize
    + QDatabasePrimitiveKey
    + RandomHash
    + QNamedType
    + MaybeSpeedy
    + MaybeBytemuck
    + std::fmt::Debug
    + PsyDebugPrintable
{
}
pub trait QHash256Base: QHashBase + Q256BitHash {}
impl<T: QHashBase + Q256BitHash> QHash256Base for T {}
pub trait QFHashBase<F: QFelt64>: QHashBase + HashTo4Felts<F> {}
impl<T: QHashBase + HashTo4Felts<F>, F: QFelt64> QFHashBase<F> for T {}

pub trait QProofBase: PartialEq + Clone + Serialize + DeserializeOwned {}
impl<T: PartialEq + Clone + Serialize + DeserializeOwned> QProofBase for T {}
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
pub trait QZKProofVerifier<Hash: PartialEq + Debug, Proof>: QZKProofPublicInputsHasherReader<Hash, Proof> {
    fn verify_zk_proof(&self, circuit_type: u32, proof: &Proof) -> anyhow::Result<Hash>;
    fn verify_zk_proof_check_public_inputs_hash(&self, circuit_type: u32, proof: &Proof, expected_public_inputs_hash: Hash) -> anyhow::Result<()> {
        let computed_public_inputs_hash = self.verify_zk_proof(circuit_type, proof)?;
        if computed_public_inputs_hash != expected_public_inputs_hash {
            return Err(anyhow::anyhow!("ZK Proof verification failed: invalid expected public inputs hash, computed: {:?}, expected: {:?}", computed_public_inputs_hash, expected_public_inputs_hash));
        }
        Ok(())
    }
    fn verify_zk_proof_from_slice_check_public_inputs_hash(
        &self,
        circuit_type: u32,
        proof_bytes: &[u8],
        expected_public_inputs_hash: Hash,
    ) -> anyhow::Result<()> {
        let proof = Self::try_proof_from_slice(proof_bytes)?;
        let computed_public_inputs_hash = Self::get_proof_public_inputs_hash(&proof)?;
        if computed_public_inputs_hash != expected_public_inputs_hash {
            return Err(anyhow::anyhow!("ZK Proof verification failed: invalid expected public inputs hash, computed: {:?}, expected: {:?}", computed_public_inputs_hash, expected_public_inputs_hash));
        }

        if self.verify_zk_proof(circuit_type, &proof)? != expected_public_inputs_hash {
            return Err(anyhow::anyhow!("ZK Proof verification failed: invalid proof"));
        }
        Ok(())
    }
}
pub trait QJobPlanner<JobId: QJobIdBase> {
    fn get_child_job_for_circuit_type(&self, children_circuit_types: &[u32]) -> u32;
}

pub trait QNetworkHashTypes {
    type QHash: QFHashBase<Self::F> + Q256BitHash + PsySerializeCanonicalAsyncSafe;
    type HasherBase: QFHasherU64<Self::F, Self::QHash> + Clone + Send + Sync;
    type F: QFelt64;
}
pub trait QNetworkDatabaseTypes: QNetworkTreeConstants + QNetworkHashTypes {}
impl<T: QNetworkTreeConstants + QNetworkHashTypes> QNetworkDatabaseTypes for T {}
pub trait QNetworkZKTypes: QNetworkHashTypes {
    type ZKProof: QProofBase + Send + Sync;
    type ZKVerifier: QZKProofVerifier<Self::QHash, Self::ZKProof> + Send + Sync;
}

pub trait QNetworkZKTypesCopier: Sized + Send + Sync + Clone {
    type ZKTypesCopySource: QNetworkZKTypes + 'static;
}
impl<T: QNetworkZKTypesCopier> QNetworkHashTypes for T {
    type QHash = <<T as QNetworkZKTypesCopier>::ZKTypesCopySource as QNetworkHashTypes>::QHash;

    type HasherBase = <<T as QNetworkZKTypesCopier>::ZKTypesCopySource as QNetworkHashTypes>::HasherBase;

    type F = <<T as QNetworkZKTypesCopier>::ZKTypesCopySource as QNetworkHashTypes>::F;
}
impl<T: QNetworkZKTypesCopier> QNetworkZKTypes for T {
    type ZKProof = <<T as QNetworkZKTypesCopier>::ZKTypesCopySource as QNetworkZKTypes>::ZKProof;

    type ZKVerifier = <<T as QNetworkZKTypesCopier>::ZKTypesCopySource as QNetworkZKTypes>::ZKVerifier;
}
pub trait QNetworkTypesConfig: QNetworkDatabaseTypes + QNetworkCircuitConstants + QNetworkZKTypes + Sized + Send + Sync + Clone {
    type JobId: QJobIdBase;
}

#[derive(Debug, Clone, Default)]
pub struct QNetworkTypesConfigHelper<JobId: QJobIdBase, ZKTypes: QNetworkZKTypes, NetworkConstants: QNetworkConstants> {
    _marker_job_id: std::marker::PhantomData<JobId>,
    _marker_zk_types: std::marker::PhantomData<ZKTypes::F>,
    _marker_network_constants: std::marker::PhantomData<NetworkConstants>,
}

impl<
        JobId: QJobIdBase + 'static,
        ZKTypes: QNetworkZKTypes + 'static + Clone + Send + Sync,
        NetworkConstants: QNetworkConstants + 'static + Send + Sync,
    > QNetworkZKTypesCopier for QNetworkTypesConfigHelper<JobId, ZKTypes, NetworkConstants>
{
    type ZKTypesCopySource = ZKTypes;
}

impl<
        JobId: QJobIdBase + 'static,
        ZKTypes: QNetworkZKTypes + 'static + Clone + Send + Sync,
        NetworkConstants: QNetworkConstants + 'static + Clone + Send + Sync,
    > QNetworkConstantsCopier for QNetworkTypesConfigHelper<JobId, ZKTypes, NetworkConstants>
{
    type CopySource = NetworkConstants;
}

impl<
        JobId: QJobIdBase + 'static,
        ZKTypes: QNetworkZKTypes + 'static + Clone + Send + Sync,
        NetworkConstants: QNetworkConstants + 'static + Clone + Send + Sync,
    > QNetworkTypesConfig for QNetworkTypesConfigHelper<JobId, ZKTypes, NetworkConstants>
{
    type JobId = JobId;
}
