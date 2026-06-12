use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::QFeltSized};
use psy_crypto::{hash::traits::hasher::FieldQHasher, signature::zk::data::ZKPublicKeyInfo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QBCRegisterUser<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub public_key_param: QHashOut<F>,
}

impl<F: RichField> QBCRegisterUser<F> {
    pub fn new_from_u64s(fingerprint: [u64; 4], public_key_param: [u64; 4]) -> Self {
        Self {
            fingerprint: QHashOut::from_values(fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]),
            public_key_param: QHashOut::from_values(public_key_param[0], public_key_param[1], public_key_param[2], public_key_param[3]),
        }
    }
    pub fn new(fingerprint: QHashOut<F>, public_key_param: QHashOut<F>) -> Self {
        Self {
            fingerprint,
            public_key_param,
        }
    }
    pub fn get_public_key<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_two_to_one(self.fingerprint, self.public_key_param)
    }
}

impl<F: RichField> From<ZKPublicKeyInfo<F>> for QBCRegisterUser<F> {
    fn from(value: ZKPublicKeyInfo<F>) -> Self {
        Self {
            fingerprint: value.fingerprint,
            public_key_param: value.public_key_param,
        }
    }
}

impl<F: RichField> KVQSerializable for QBCRegisterUser<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for QBCRegisterUser<F> {
    fn q_felt_size() -> usize {
        8
    }
}
