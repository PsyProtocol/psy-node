use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PublicKeyInfo<F: RichField> {
    pub zk_public_key: ZKPublicKeyInfo<F>,
    pub secp256k1_public_key_hash: QHashOut<F>,
}

impl<F: RichField> KVQSerializable for PublicKeyInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct ZKPublicKeyInfo<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub public_key_param: QHashOut<F>,
}
// impl<F: RichField> DrainQueueMetadataTagged for ZKPublicKeyInfo<F> {
//     fn get_dq_metadata(&self) -> DrainQueueMetadata {
//         let num = self.fingerprint.0.elements[0].to_canonical_u64() +
// self.public_key_param.0.elements[0].to_canonical_u64();

//         DrainQueueMetadata {
//             channel_id: COORD_API_REGISTER_USER_CHANNEL_ID,
//             checkpoint_id: 0,
//             item_id: num,
//         }
//     }
// }
impl<F: RichField> ZKPublicKeyInfo<F> {
    pub fn to_hash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_two_to_one(self.fingerprint, self.public_key_param)
    }
}

impl<F: RichField> QFieldHashable<F> for ZKPublicKeyInfo<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_two_to_one(self.fingerprint, self.public_key_param)
    }
}

impl<F: RichField> KVQSerializable for ZKPublicKeyInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
