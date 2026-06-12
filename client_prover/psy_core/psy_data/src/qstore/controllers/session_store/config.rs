use kvq::adapters::standard::KVQStandardAdapter;
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::DEFERRED_TRANSACTION_TREE_HEIGHT;

use crate::models::kvq_merkle::{key::KVQMerkleNodeKey, model::KVQFixedConfigMerkleTreeModel};

pub const LOCAL_PROVING_SESSION_TREE_TABLE_TYPE: u16 = 0xFE01;

pub type LocalProvingSessionTreeStore<
    const TREE_ID: u8,
    const HEIGHT: u8,
    S,
    F = crate::config::store_config::PsyFelt,
    H = crate::config::store_config::PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<LOCAL_PROVING_SESSION_TREE_TABLE_TYPE>, QHashOut<F>>,
> = KVQFixedConfigMerkleTreeModel<TREE_ID, HEIGHT, 0, 0, LOCAL_PROVING_SESSION_TREE_TABLE_TYPE, false, S, IDKVA, QHashOut<F>, H>;

pub const LPS_DEFERRED_TRANSACTION_TREE_ID: u8 = 1;

pub type LPSDeferredTransactionTreeStore<
    S,
    F = crate::config::store_config::PsyFelt,
    H = crate::config::store_config::PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<LOCAL_PROVING_SESSION_TREE_TABLE_TYPE>, QHashOut<F>>,
> = LocalProvingSessionTreeStore<LPS_DEFERRED_TRANSACTION_TREE_ID, DEFERRED_TRANSACTION_TREE_HEIGHT, S, F, H, IDKVA>;
