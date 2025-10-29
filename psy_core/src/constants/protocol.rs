use parth_core::crypto::hash::traits::FromU64x4;


// Native currency configuration
pub const NATIVE_CURRENCY_DECIMAL: u8 = 9;
pub const NATIVE_CURRENCY: &str = "0";
pub const NATIVE_CURRENCY_NAME: &str = "PSY";

// Fee configuration
pub const REGISTER_USER_FEE: u64 = 0;
pub const DEPLOY_CONTRACT_FEE: u64 = 0;
pub const GUTA_FEE: u64 = 5000000000;


/*pub trait QEDTreeConfig {
    const CHECKPOINT_TREE_HEIGHT: u8;
    const GLOBAL_USER_TREE_HEIGHT: u8;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8;
    const GLOBAL_DEPOSIT_TREE_HEIGHT: u8;
    const GLOBAL_WITHDRAWAL_TREE_HEIGHT: u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT: u8;

    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8;


}

pub struct QEDTestnetTreeConfig;
impl QEDTreeConfig for QEDTestnetTreeConfig {
    const CHECKPOINT_TREE_HEIGHT: u8 = 32;
    const GLOBAL_USER_TREE_HEIGHT: u8 = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = 24;
    const GLOBAL_DEPOSIT_TREE_HEIGHT: u8 = 32;
    const GLOBAL_WITHDRAWAL_TREE_HEIGHT: u8 = 32;

    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = 16;

    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
}
*/
// Network Magic
pub const QED_NETWORK_MAGIC_MAINNET: u64 = 0x1337CF514544C069u64;
pub const QED_NETWORK_MAGIC_TESTNET: u64 = 0x1337CF514544C169u64;
pub const QED_NETWORK_MAGIC_REGTEST: u64 = 0x1337CF514544CF69u64;


// Number of blocks that a data availability mining challenge is open for
pub const DA_CHALLENGE_WINDOW: usize = 14;


pub const DEFERRED_CALL_MAGIC: u64 = 0xDEFE1212EDCA11u64;
pub const DEFERRED_TRANSACTION_TREE_HEIGHT: u8 = 16;
pub const INLINE_TRANSACTION_TREE_HEIGHT: u8 = 16;


// used for signing a transaction/contract function call 0xCA11_<ascii'TXCALL'>
pub const SIGN_SIMPLE_TRANSACTION_MAGIC: u64 = 0xCA11_545843414C4C;


pub const UPS_SESSION_PROOF_TREE_HEIGHT: u8 = 16;

pub const UPS_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 8;


pub const QED_SIG_ACTION_SIGN_UPS_END_CAP: u64 = 0x51454445434150CFu64;


pub const VM_TYPE_STANRDARD_DAPEN_V1: u32 = 1;


pub const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;



pub const DEFAULT_USER_STATE_TREE_ROOT_U64: [u64; 4] = [
    3896366420105793420,
    17410332186442776169,
    7329967984378645716,
    6310665049578686403,
];
pub const TOKEN_CONTRACT_ID: u32 = 0;
pub const TOKEN_SIMPLE_BURN_METHOD_ID: u32 = 2923993647;

// start circuit specific config
pub const BATCH_USER_REGISTRAITION_SUB_TREE_HEIGHT: usize = 8;
pub const BATCH_USER_REGISTRAITION_MAX_SUB_TREES: usize = 4;

pub const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;


// start constant channels
pub const COORD_API_REGISTER_USER_CHANNEL_ID: u64 = 0xCC524547555352;
pub const COORD_API_DEPLOY_CONTRACT_CHANNEL_ID: u64 = 0xCC444550434F4E;
pub const COORD_API_GUTA_FROM_REALMS_CHANNEL_ID: u64 = 0xCC475554414652;

pub const REALM_API_GUTA_FROM_USER_CHANNEL_ID: u64 = 0x22475554414652;
pub const REALM_API_UPDATE_CONTRACT_STATE_TREE_CHANNEL_ID: u64 = 0x22435354555044;

pub const QED_CHECKPOINT_SYNC_INFO_COMPACT_DRAIN_QUEUE_CHANNEL: u64 = 0x901337123;
pub const QED_CHECKPOINT_JOB_ID_CHANNEL: u64 = 0x901337124;
pub const CST_USER_UPDATE_CHANNEL_ID: u64 = 0x101337;

pub const COORDINATOR_TO_REALM_CHANNEL: u64 = 0xCC544F5245414C4D;
pub const REALM_TO_COORDINATOR_CHANNEL: u64 = 0x5245414C4D544F43;

pub const REALM_PROOF_SYNC_CHANNEL: u64 = 0x524C4D50524F4F46;

pub fn get_default_worker_public_key<Hash: FromU64x4>() -> Hash {
    Hash::from_u64s(1,1,1,1)
}

pub const TODO_DEPOSIT_TREE_HEIGHT: u8 = 32;
pub const TODO_WITHDRAWAL_TREE_HEIGHT: u8 = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_constants() {
        // Verify constants are generated correctly from config.json
        assert_eq!(NATIVE_CURRENCY_DECIMAL, 9);
        assert_eq!(NATIVE_CURRENCY, "0");
        assert_eq!(NATIVE_CURRENCY_NAME, "PSY");
        assert_eq!(REGISTER_USER_FEE, 0);
        assert_eq!(DEPLOY_CONTRACT_FEE, 0);
        assert_eq!(GUTA_FEE, 5000000000);
    }
}
