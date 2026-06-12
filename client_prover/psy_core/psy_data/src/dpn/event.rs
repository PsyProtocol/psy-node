use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField, plonk::config::AlgebraicHasher};
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::ToQFelts};
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyUserEventRecord<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
    pub method_id: F,
    pub event_index: F,
    pub data: Vec<F>,
}

impl<F: RichField> KVQSerializable for PsyUserEventRecord<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> ToQFelts<F> for PsyUserEventRecord<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![self.checkpoint_id, self.user_id, self.contract_id, self.method_id, self.event_index]
            .into_iter()
            .chain(self.data.clone().into_iter())
            .collect()
    }

    fn from_qfelts(felts: &[F]) -> Self {
        let checkpoint_id = felts[0];
        let user_id = felts[1];
        let contract_id = felts[2];
        let method_id = felts[3];
        let event_index = felts[4];
        let data = felts[5..].to_vec();
        PsyUserEventRecord {
            checkpoint_id,
            user_id,
            contract_id,
            method_id,
            event_index,
            data,
        }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyUserEventRecord<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let qfelts = self.to_qfelts();
        H::q_hash_many(&qfelts)
    }
}

impl<F: RichField> PsyUserEventRecord<F> {
    pub fn alghash<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        let qfelts = self.to_qfelts();
        QHashOut(H::hash_no_pad(&qfelts))
    }
}
