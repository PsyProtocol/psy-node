use parth_core::{data::serializable::QPDSerializable, felt::QFelt, impl_qpd_serialize_params, protocol::core_types::QHashBase};
use pser::{QBytesDeserialize, QBytesSerialize};

use crate::store::test_helper::traits::CreateRandomTestDataItem;


#[pderive::serialize_copy_f_hash]
pub struct PQEDUserLeaf<F: QFelt, Hash: QHashBase> {
    pub public_key: Hash,
    pub user_state_tree_root: Hash,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}


impl_qpd_serialize_params!(
    PQEDUserLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);


impl<F: QFelt, Hash: QHashBase> CreateRandomTestDataItem for PQEDUserLeaf<F, Hash> {
    fn create_random_test_data_item() -> Self {
        Self {
            public_key: Hash::rand_hash(),
            user_state_tree_root: Hash::rand_hash(),
            balance: F::get_simple_rand(),
            nonce: F::get_simple_rand(),
            last_checkpoint_id: F::get_simple_rand(),
            event_index: F::get_simple_rand(),
            user_id: F::get_simple_rand(),
        }
    }
}




/* 
impl CreateRandomTestDataItem for PQEDUserLeaf {
    
}

*/