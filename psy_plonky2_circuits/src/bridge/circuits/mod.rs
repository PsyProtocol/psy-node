pub mod bridge_agg;
pub mod bridge_agg_chain;
pub mod bridge_agg_final;
pub mod checkpoint_identity;
pub mod checkpoint_end;
pub mod record_batch;
pub mod batch_reduction;
pub mod chain_aggregate;
pub mod chain_reduction;
pub mod reward_inclusion;
pub mod checkpoint_range;
pub mod deposit_aggregate;
pub mod checkpoint_aggregate;
#[cfg(all(feature = "gnark-wrap", not(target_arch = "wasm32")))]
pub mod bridge_wrap;

pub use bridge_agg::BridgeAggProveResult;
pub use bridge_agg_chain::{BridgeAggChainBoundary, BridgeAggChainCircuit, BridgeAggChainSlotWitness, BRIDGE_AGG_CHAIN_MAX_SLOTS, BRIDGE_AGG_CHAIN_PI_LEN};
pub use bridge_agg_final::{BridgeAggFinalCircuit, BRIDGE_AGG_FINAL_PI_LEN};
