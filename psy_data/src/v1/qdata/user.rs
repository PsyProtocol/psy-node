use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, data::serializable::QPDSerializable, felt::{QFelt, QFelt64, QFeltSized, ToQFelts}, impl_qpd_serialize_params, protocol::core_types::{QFHashBase, QHashBase}};
use pser::{QBytesDeserialize, QBytesSerialize};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDUserLeaf")]
pub struct PQEDUserLeaf<F: QFelt, Hash: QHashBase> {
    pub public_key: Hash,
    pub user_state_tree_root: Hash,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}
impl<F: QFelt, Hash: QHashBase> PQEDUserLeaf<F, Hash> {
    pub fn new_user_default(user_id: F, public_key: Hash, user_state_tree_root: Hash) -> Self {
        Self {
            public_key,
            user_state_tree_root,
            balance: F::ZERO_VALUE,
            nonce: F::ZERO_VALUE,
            last_checkpoint_id: F::ZERO_VALUE,
            event_index: F::ZERO_VALUE,
            user_id,
        }
    }

}


impl_qpd_serialize_params!(
    PQEDUserLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt, Hash: QHashBase> QFeltSized for PQEDUserLeaf<F, Hash> {
    fn q_felt_size() -> usize {
        13
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDUserLeaf<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let public_key_felts = self.public_key.to_4_felts();
        let user_state_tree_root_felts = self.user_state_tree_root.to_4_felts();

        vec![
            public_key_felts[0],
            public_key_felts[1],
            public_key_felts[2],
            public_key_felts[3],
            user_state_tree_root_felts[0],
            user_state_tree_root_felts[1],
            user_state_tree_root_felts[2],
            user_state_tree_root_felts[3],
            self.balance,
            self.nonce,
            self.last_checkpoint_id,
            self.event_index,
            self.user_id,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 13 {
            panic!("Invalid number of elements for QEDUserLeaf");
        }
        let public_key = Hash::from_4_felts_slice(&felts[0..4]);
        let user_state_tree_root = Hash::from_4_felts_slice(&felts[4..8]);
        let balance = felts[8];
        let nonce = felts[9];
        let last_checkpoint_id = felts[10];
        let event_index = felts[11];
        let user_id = felts[12];
        PQEDUserLeaf {
            public_key,
            user_state_tree_root,
            balance,
            nonce,
            last_checkpoint_id,
            event_index,
            user_id,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PQEDUserLeaf<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let public_key_felts = self.public_key.to_4_felts();
        let user_state_tree_root_felts = self.user_state_tree_root.to_4_felts();
        H::q_hash_many(&[
            public_key_felts[0],
            public_key_felts[1],
            public_key_felts[2],
            public_key_felts[3],
            user_state_tree_root_felts[0],
            user_state_tree_root_felts[1],
            user_state_tree_root_felts[2],
            user_state_tree_root_felts[3],
            self.balance,
            self.nonce,
            self.last_checkpoint_id,
            self.event_index,
            self.user_id,
        ])
    }
}