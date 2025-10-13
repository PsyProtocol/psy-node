

use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleHasher, QFieldHashable}, data::serializable::QPDSerializable, felt::QFelt64, impl_qpd_serialize_params, protocol::core_types::{QFHashBase, QHashBase}};
use pser::{QBytesDeserialize, QBytesSerialize};

#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "ZKPublicKeyInfo")]
pub struct PZKPublicKeyInfo<Hash> {
    pub fingerprint: Hash,
    pub public_key_param: Hash,
}

impl<Hash: QHashBase> PZKPublicKeyInfo<Hash> {
    pub fn to_hash<H: MerkleHasher<Hash>>( &self) -> Hash {
        H::two_to_one(&self.fingerprint, &self.public_key_param)
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PZKPublicKeyInfo<Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        H::q_two_to_one(self.fingerprint, self.public_key_param)
    }
}

impl_qpd_serialize_params!(PZKPublicKeyInfo, { Hash: QHashBase } => { Hash });